use std::io::Write;

use log::{trace, warn};
use nom::{bytes::streaming::take, sequence::tuple, IResult};
use rand::Rng;
use smicro_common::{LoopingBuffer, LoopingBufferWriter};
use smicro_types::{error::ParsingError, serialize::SerializePacket};

use crate::{
    crypto::Cipher,
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
    let mut padding = [0u8; 256];
    sender.rng.fill(&mut padding);

    let cipher = sender
        .crypto_material
        .as_ref()
        .map(|mat| mat.cipher.as_ref());

    let mut padding_length = 4;
    // length + padding_length + message_type + payload + random_padding, max not included
    let mut real_packet_length = 4 + 1 + 1 + payload.get_size() + padding_length;
    // BAD: probable timing oracle!
    // For AEAD mode, the packet length does not count in the modulus
    while real_packet_length < 16
        || (real_packet_length - if cipher.is_some() { 4 } else { 0 }) % 8 != 0
    {
        padding_length += 1;
        real_packet_length += 1;
    }

    let output_buffer = stream.get_writable_buffer();
    let required_space = if let Some(cipher) = cipher {
        cipher.required_space_to_encrypt(real_packet_length)
    } else {
        real_packet_length
    };
    if output_buffer.len() < required_space {
        return Err(Error::IoError(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "missing space in the buffer to write the packet",
        )));
    }

    let mut output_buffer = &mut output_buffer[0..required_space];

    // the packet_length field does not count in the packet size)
    ((real_packet_length - 4) as u32).serialize(&mut output_buffer)?;
    output_buffer.write(&[padding_length as u8, T::get_message_type() as u8])?;
    payload.serialize(&mut output_buffer)?;
    (&padding[0..padding_length]).serialize(&mut output_buffer)?;

    if let Some(cipher) = cipher {
        cipher.encrypt(
            &mut stream.get_writable_buffer()[0..required_space],
            sender.sequence_number.0,
        )?;
    }

    stream.advance_writer_pos(required_space);

    // We only support the AEAD mode chacha20-poly1305, where MAC is disabled

    sender.sequence_number += 1;
    if sender.sequence_number.0 == 0 {
        return Err(Error::SequenceNumberWrapped);
    }

    Ok(())
}

fn parse_plaintext_packet<'a>(
    input: &'a [u8],
    cipher: Option<&dyn Cipher>,
) -> IResult<&'a [u8], &'a [u8], ParsingError> {
    let (input, (length, padding_length)) = tuple((
        nom::number::streaming::be_u32,
        nom::number::streaming::be_u8,
    ))(input)?;
    if length as usize > MAX_PKT_SIZE {
        return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
            length as usize,
        )));
    }

    if length < 12 {
        warn!("Packet too small: {} bytes", length);
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

    // This does not apply in the AEAD case, which is the only one currently supported
    //let multiple = if let Some(cipher) = cipher {
    //    cipher.block_size_bytes()
    //} else {
    //    8
    //};
    if cipher.is_none() {
        let multiple = 8;
        if (length + 4) as usize % multiple != 0 {
            warn!(
                "The packet size is not a multiple of {}: {} bytes",
                multiple, length
            );
            return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
                length as usize,
            )));
        }
    }

    let (input, payload) = take(length - padding_length as u32 - 1)(input)?;
    // TODO: check the padding
    let (input, padding) = take(padding_length)(input)?;

    Ok((input, payload))
}

pub fn parse_packet<'a>(
    input: &'a mut [u8],
    state: &mut State,
) -> IResult<&'a [u8], &'a [u8], ParsingError> {
    let cipher = state
        .receiver
        .crypto_material
        .as_ref()
        .map(|mat| mat.cipher.as_ref());

    let (next_data, res) = if let Some(cipher) = cipher {
        let (next_data, plaintext_pkt) = cipher.decrypt(input, state.receiver.sequence_number.0)?;
        let (should_be_empty, decrypted_pkt) = parse_plaintext_packet(plaintext_pkt, Some(cipher))?;
        if should_be_empty != [] {
            return Err(nom::Err::Failure(
                ParsingError::RemainingDataAfterDecryption,
            ));
        }

        (next_data, decrypted_pkt)
    } else {
        parse_plaintext_packet(input, None)?
    };

    // We only support the AEAD mode chacha20-poly1305, where MAC is disabled
    /*
    if let Some(mac) = mac {
        let (input, packet_mac) = take(mac.size_bytes())(input)?;

        mac.verify(
            &original_input[..(length + 4) as usize],
            sequence_number,
            packet_mac,
        )
        .map_err(|_| nom::Err::Failure(ParsingError::InvalidMac))?;

        res.mac = packet_mac;

        Ok((input, res))
    } else {
    */

    state.receiver.sequence_number += 1;
    if state.receiver.sequence_number.0 == 0 {
        return Err(nom::Err::Failure(ParsingError::SequenceNumberWrapped));
    }

    Ok((next_data, res))
}
