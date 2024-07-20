use std::io::Write;

use log::{trace, warn};
use nom::{bytes::streaming::take, sequence::tuple, IResult};
use rand::Rng;
use smicro_common::LoopingBufferWriter;
use smicro_types::{error::ParsingError, serialize::SerializePacket};

use crate::{
    crypto::cipher::Cipher,
    error::Error,
    messages::Message,
    state::{SenderState, State},
};

// A tad bit above the SFTP max packet size, so that we do not have too much fragmentation
// Besides, this is the same constant as OpenSSH
pub const MAX_PKT_SIZE: usize = 4096 * 64;

pub fn write_message<
    'a,
    T: SerializePacket + Message<'a>,
    const SIZE: usize,
    S: LoopingBufferWriter<SIZE>,
>(
    sender: &mut SenderState,
    stream: &mut S,
    payload: &T,
) -> Result<(), Error> {
    trace!("Writing message {:?}", <T as Message>::get_message_type());
    let mut padding = [0u8; 256];
    let mut padding = &mut padding as &mut [u8];

    let mut crypto_mat = sender.crypto_material.as_mut();
    let cipher = crypto_mat.as_ref().map(|mat| mat.cipher.as_ref());

    let mut padding_length = 4;
    // length + padding_length + message_type + payload + random_padding, max not included
    let mut real_packet_length = 4 + 1 + 1 + payload.get_size() + padding_length;
    // BAD: probable timing oracle!
    let (offset, multiple) = if let Some(ref cipher) = cipher {
        // For AEAD mode, the packet length does not count in the modulus
        if cipher.is_aead() {
            (4, 8)
        } else {
            (0, cipher.block_size_bytes())
        }
    } else {
        (0, 8)
    };
    while real_packet_length < 16 || (real_packet_length - offset) % multiple != 0 {
        padding_length += 1;
        real_packet_length += 1;
    }

    padding = &mut padding[..padding_length];
    sender.rng.fill(padding);

    let mut cipher_is_aead = false;
    let required_space = if let Some(ref cipher) = cipher {
        cipher_is_aead = cipher.is_aead();
        cipher.required_space_to_encrypt(real_packet_length)
    } else {
        real_packet_length
    };

    let mac = crypto_mat.as_mut().map(|mat| mat.mac.as_mut());
    let mut mac_len = 0;
    // Do not add a MAC for AEAD ciphers
    if let Some(ref mac) = mac {
        if !cipher_is_aead {
            mac_len = mac.size_bytes();
        }
    }

    let underlying_buffer = stream.get_writable_buffer();
    if underlying_buffer.len() < required_space + mac_len {
        return Err(Error::IoError(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "missing space in the buffer to write the packet",
        )));
    }

    let (output_buffer, mac_buffer) = underlying_buffer.split_at_mut(required_space);

    {
        // little tricke for serialization, because the serialize() methods change the size of
        // output buffer, but we want to encrypt the whole buffer afterward
        let mut output_buffer = &mut *output_buffer;

        // the packet_length field does not count in the packet size)
        ((real_packet_length - 4) as u32).serialize(&mut output_buffer)?;
        output_buffer.write(&[padding_length as u8, T::get_message_type() as u8])?;
        payload.serialize(&mut output_buffer)?;
        padding.as_ref().serialize(&mut output_buffer)?;
    }

    // compute the MAC on the unencrypted data
    if mac_len != 0 {
        if let Some(mac) = mac {
            let mac_buffer = &mut mac_buffer[..mac_len];
            mac.compute(&output_buffer, sender.sequence_number.0, mac_buffer)?;
        }
    }

    let cipher = crypto_mat.as_mut().map(|mat| mat.cipher.as_mut());
    if let Some(cipher) = cipher {
        cipher.encrypt(output_buffer, sender.sequence_number.0)?;
    }

    stream.advance_writer_pos(required_space + mac_len);

    sender.sequence_number += 1;
    if sender.sequence_number.0 == 0 {
        return Err(Error::SequenceNumberWrapped);
    }

    trace!("Message sent!");

    Ok(())
}

fn parse_plaintext_packet<'a>(
    input: &'a [u8],
    mut cipher: Option<&mut dyn Cipher>,
) -> IResult<&'a [u8], (&'a [u8], &'a [u8]), ParsingError> {
    let original_input = input;
    let (input, (length, padding_length)) = tuple((
        nom::number::streaming::be_u32,
        nom::number::streaming::be_u8,
    ))(input)?;
    if length as usize > MAX_PKT_SIZE {
        return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
            length as usize,
        )));
    }

    if length <= padding_length as u32 + 1 {
        warn!("The packet size implies that the packet has no payload",);
        return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
            length as usize,
        )));
    }

    let multiple = if let Some(ref mut cipher) = cipher {
        // This does not apply in the AEAD case
        if cipher.is_aead() {
            1
        } else {
            cipher.block_size_bytes()
        }
    } else {
        8
    };
    if (length + 4) as usize % multiple != 0 {
        warn!(
            "The packet size is not a multiple of {}: {} bytes",
            multiple, length
        );
        return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
            length as usize,
        )));
    }

    let (input, payload) = take(length - padding_length as u32 - 1)(input)?;
    // ensure that the padding is present
    let (_, _padding) = take(padding_length)(input)?;

    let (next_data, full_pkt) = take(length + 4)(original_input)?;

    Ok((next_data, (full_pkt, payload)))
}

pub fn parse_packet<'a>(
    input: &'a mut [u8],
    state: &mut State,
) -> IResult<&'a [u8], &'a [u8], ParsingError> {
    let cipher = state
        .receiver
        .crypto_material
        .as_mut()
        .map(|mat| mat.cipher.as_mut());

    let mut is_aead = false;
    let (next_data, (full_pkt, pkt_payload)) = if let Some(cipher) = cipher {
        is_aead = cipher.is_aead();
        let (next_data, full_pkt) = cipher.decrypt(input, state.receiver.sequence_number.0)?;

        let (should_be_empty, (_, pkt_payload)) = parse_plaintext_packet(full_pkt, Some(cipher))?;
        if should_be_empty != [] {
            return Err(nom::Err::Failure(
                ParsingError::RemainingDataAfterDecryption,
            ));
        }

        (next_data, (full_pkt, pkt_payload))
    } else {
        parse_plaintext_packet(input, None)?
    };

    let mac = state
        .receiver
        .crypto_material
        .as_mut()
        .map(|mat| mat.mac.as_mut());

    // No MAC for AEAD ciphers
    let next_data = if is_aead {
        next_data
    } else if let Some(mac) = mac {
        log::trace!("doing mac");
        let (next_data, packet_mac) = take(mac.size_bytes())(next_data)?;
        log::trace!("mac={:?}", packet_mac);

        mac.verify(&full_pkt, state.receiver.sequence_number.0, packet_mac)
            .map_err(|_| nom::Err::Failure(ParsingError::InvalidMac))?;

        next_data
    } else {
        next_data
    };
    log::trace!("mac done");

    state.receiver.sequence_number += 1;
    if state.receiver.sequence_number.0 == 0 {
        return Err(nom::Err::Failure(ParsingError::SequenceNumberWrapped));
    }

    Ok((next_data, pkt_payload))
}
