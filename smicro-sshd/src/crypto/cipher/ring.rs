use std::num::Wrapping;

use ring::aead::{chacha20_poly1305_openssh, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

use nom::bytes::streaming::take;
use nom::number::streaming::be_u32;

use smicro_macros::declare_crypto_arg;
use smicro_types::error::ParsingError;
use smicro_types::ssh::deserialize::streaming_const_take;

use crate::{
    crypto::{CryptoAlgWithKey, KeyWrapper},
    error::Error,
    packet::MAX_PKT_SIZE,
};

use super::{Aes256Gcm, Chacha20Poly1305, Cipher, AES256GCM_TAG_SIZE, POLY1305_BLOCK_SIZE};

#[declare_crypto_arg("chacha20-poly1305@openssh.com")]
pub struct Chacha20Poly1305Impl {
    inner: Chacha20Poly1305ImplRingInner,
}

impl CryptoAlgWithKey for Chacha20Poly1305Impl {
    fn new(keys: &[&[u8]]) -> Result<Self, Error> {
        let raw_key = keys[0];
        let mut fixed_raw_key = [0; 64];
        if raw_key.len() != 2 * Chacha20Poly1305::KEY_SIZE_BYTES {
            return Err(Error::InvalidPrivateKeyLength);
        }
        fixed_raw_key.copy_from_slice(raw_key);

        Ok(Self {
            inner: Chacha20Poly1305ImplRingInner {
                raw_key: fixed_raw_key,
                decrypt: chacha20_poly1305_openssh::OpeningKey::new(&fixed_raw_key),
                encrypt: chacha20_poly1305_openssh::SealingKey::new(&fixed_raw_key),
            },
        })
    }
}

struct Chacha20Poly1305ImplRingInner {
    // slight loss of space (we store the key thrice instead of once), but that's only a waste of 128
    // bytes, which I can accept as a tradeoff for not having to redesign the API to separate the
    // sender and receiver side
    raw_key: [u8; 64],
    decrypt: chacha20_poly1305_openssh::OpeningKey,
    encrypt: chacha20_poly1305_openssh::SealingKey,
}

impl Clone for Chacha20Poly1305ImplRingInner {
    fn clone(&self) -> Self {
        Self {
            raw_key: self.raw_key,
            decrypt: chacha20_poly1305_openssh::OpeningKey::new(&self.raw_key),
            encrypt: chacha20_poly1305_openssh::SealingKey::new(&self.raw_key),
        }
    }
}

impl Cipher for Chacha20Poly1305Impl {
    fn block_size_bytes(&self) -> usize {
        64
    }

    fn is_aead(&self) -> bool {
        true
    }

    fn required_space_to_encrypt(&self, data_len: usize) -> usize {
        data_len + POLY1305_BLOCK_SIZE
    }

    fn encrypt(&mut self, data: &mut [u8], sequence_number: u32) -> Result<(), Error> {
        let mut tmp_auth_block = [0; POLY1305_BLOCK_SIZE];
        let (plaintext, auth_block) = data.split_at_mut(data.len() - POLY1305_BLOCK_SIZE);
        self.inner
            .encrypt
            .seal_in_place(sequence_number, plaintext, &mut tmp_auth_block);
        auth_block.copy_from_slice(&tmp_auth_block);

        Ok(())
    }

    fn decrypt<'a>(
        &mut self,
        input: &'a mut [u8],
        sequence_number: u32,
    ) -> nom::IResult<&'a [u8], &'a [u8], ParsingError> {
        // this is a cipher with authenticated encryptions, so we need to extract the packet length
        // beforehand
        let (next_data, size_field) = streaming_const_take::<4>(input)?;
        let pkt_size_bytes = self
            .inner
            .decrypt
            .decrypt_packet_length(sequence_number, size_field);
        let pkt_size = u32::from_be_bytes(pkt_size_bytes);
        // 5 = length field + 1 byte for the packet itself
        if pkt_size < 5 || pkt_size as usize > MAX_PKT_SIZE {
            return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
                pkt_size as usize,
            )));
        }
        // ensure there is enought data in the input slice
        let _ = take(pkt_size as usize + POLY1305_BLOCK_SIZE)(next_data)?;

        let auth_block_pos = pkt_size as usize + 4;
        let next_data_pos = auth_block_pos + POLY1305_BLOCK_SIZE;

        let mut auth_block = [0; POLY1305_BLOCK_SIZE];
        auth_block.copy_from_slice(&input[auth_block_pos..next_data_pos]);

        self.inner
            .decrypt
            .open_in_place(sequence_number, &mut input[..auth_block_pos], &auth_block)
            .map_err(|_| nom::Err::Failure(ParsingError::DecipheringError))?;
        input[0..4].copy_from_slice(&pkt_size_bytes);

        Ok((&input[next_data_pos..], &input[..auth_block_pos]))
    }
}

pub type Aes256GcmImpl = KeyWrapper<Aes256GcmImplInner>;

#[declare_crypto_arg("aes256-gcm@openssh.com")]
pub struct Aes256GcmImplInner {
    key: LessSafeKey,
}

impl CryptoAlgWithKey for Aes256GcmImplInner {
    fn new(keys: &[&[u8]]) -> Result<Self, Error> {
        let raw_key = keys[0];

        Ok(Self {
            key: LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM, raw_key)
                    .map_err(|_| Error::InvalidPrivateKeyLength)?,
            ),
        })
    }
}

impl Cipher for Aes256GcmImpl {
    fn block_size_bytes(&self) -> usize {
        Aes256Gcm::BLOCK_SIZE_BYTES
    }

    fn is_aead(&self) -> bool {
        true
    }

    fn required_space_to_encrypt(&self, data_len: usize) -> usize {
        // size of the data itself + the authentication tag size
        data_len + AES256GCM_TAG_SIZE
    }

    fn encrypt(&mut self, data: &mut [u8], _sequence_number: u32) -> Result<(), Error> {
        // this is a cipher with authenticated encryptions, so we need to extract the packet length
        // beforehand
        let (_, size_field) =
            streaming_const_take::<4>(data).map_err(|_| Error::EncryptionError)?;

        // encrypt in place
        let cleartext_data_end = data.len() - AES256GCM_TAG_SIZE;

        let nonce = Nonce::try_assume_unique_for_key(&self.keys.0[1].0)
            .expect("Invalid nonce size: impossible!?");
        let tag = self
            .inner
            .key
            .seal_in_place_separate_tag(
                nonce,
                Aad::from(&size_field),
                &mut data[4..cleartext_data_end],
            )
            .map_err(|_| Error::EncryptionError)?;

        // succeeded -> let's update the nonce
        self.increment_nonce();

        data[cleartext_data_end..].copy_from_slice(tag.as_ref());

        Ok(())
    }

    fn decrypt<'a>(
        &mut self,
        input: &'a mut [u8],
        _sequence_number: u32,
    ) -> nom::IResult<&'a [u8], &'a [u8], ParsingError> {
        // this is a cipher with authenticated encryptions, so we need to extract the packet length
        // beforehand
        let (next_data, size_field) = streaming_const_take::<4>(input)?;
        let (_, pkt_size) = be_u32(size_field.as_slice())?;
        // 5 = padding_length field + 4 bytes as this is the minimum possible padding
        if pkt_size < 5 || pkt_size as usize > MAX_PKT_SIZE {
            return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
                pkt_size as usize,
            )));
        }
        // ensure there is enought data in the input slice
        let _ = take(pkt_size as usize + AES256GCM_TAG_SIZE)(next_data)?;

        let nonce = Nonce::try_assume_unique_for_key(&self.keys.0[1].0)
            .expect("Invalid nonce size: impossible!?");
        self.inner
            .key
            .open_in_place(
                nonce,
                Aad::from(&size_field),
                &mut input[4..4 + pkt_size as usize + AES256GCM_TAG_SIZE],
            )
            .map_err(|_| nom::Err::Failure(ParsingError::InvalidMac))?;

        // valid decryption: update the nonce
        self.increment_nonce();

        let next_data = &input[AES256GCM_TAG_SIZE + 4 + pkt_size as usize..];
        let cur_pkt_plaintext = &input[..4 + pkt_size as usize];

        Ok((next_data, cur_pkt_plaintext))
    }
}

impl Aes256GcmImpl {
    #[inline]
    fn increment_nonce(&mut self) {
        // TODO: is this constant-time?
        let current_nonce = &self.keys.0[1].0[4..];
        let next_invocation_counter = Wrapping(u64::from_be_bytes([
            current_nonce[0],
            current_nonce[1],
            current_nonce[2],
            current_nonce[3],
            current_nonce[4],
            current_nonce[5],
            current_nonce[6],
            current_nonce[7],
        ])) + Wrapping(1u64);
        self.keys.0[1].0[4..].clone_from_slice(&next_invocation_counter.0.to_be_bytes());
    }
}
