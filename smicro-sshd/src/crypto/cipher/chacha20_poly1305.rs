use std::fmt::Debug;

use chacha20::ChaCha20Legacy;
use cipher::{Iv, KeyIvInit, StreamCipher, StreamCipherSeek};
use elliptic_curve::subtle::ConstantTimeEq;
use hybrid_array::Array;
use nom::bytes::streaming::take;
use poly1305::Poly1305;
use smicro_macros::{declare_crypto_arg, declare_deserializable_struct, gen_serialize_impl};
use smicro_types::{
    deserialize::DeserializePacket, error::ParsingError, serialize::SerializePacket,
    ssh::deserialize::streaming_const_take,
};

use crate::crypto::{CryptoAlg, KeyWrapper};
use crate::{
    error::{CryptoOperationError, Error},
    packet::MAX_PKT_SIZE,
};

use super::{Cipher, CipherAllocator, CipherWrapper, CryptoAlgWithKey};

const POLY1305_BLOCK_SIZE: usize = 16;

#[derive(Clone, Debug)]
#[declare_crypto_arg("chacha20-poly1305@openssh.com")]
#[declare_deserializable_struct]
#[gen_serialize_impl]
pub struct Chacha20Poly1305 {}

impl CryptoAlg for Chacha20Poly1305 {
    fn new() -> Self {
        Self {}
    }
}

impl Chacha20Poly1305 {
    const KEY_SIZE_BYTES: usize = 32;
    const IV_SIZE_BYTES: usize = 8;
    const BLOCK_SIZE_BYTES: usize = 64;
}

impl CipherAllocator for Chacha20Poly1305 {
    fn key_size_bits(&self) -> usize {
        Self::KEY_SIZE_BYTES * 8
    }

    fn iv_size_bits(&self) -> usize {
        Self::IV_SIZE_BYTES * 8
    }

    fn block_size_bits(&self) -> usize {
        Self::BLOCK_SIZE_BYTES * 8
    }

    fn from_key(&self, raw_key: &[u8], raw_iv: &[u8]) -> Result<CipherWrapper, Error> {
        Ok(CipherWrapper::KeyWrapperChacha20Poly1305Impl(
            KeyWrapper::new(&[raw_key, raw_iv])?,
        ))
    }
}

#[declare_crypto_arg("chacha20-poly1305@openssh.com")]
pub struct Chacha20Poly1305Impl {
    key: Array<u8, cipher::consts::U32>,
    aad_key: Array<u8, cipher::consts::U32>,
}

impl CryptoAlgWithKey for Chacha20Poly1305Impl {
    fn new(keys: &[&[u8]]) -> Result<Self, CryptoOperationError> {
        let raw_key = keys[0];
        let key = Array::try_from(&raw_key[..Chacha20Poly1305::KEY_SIZE_BYTES])?;
        let aad_key = Array::try_from(
            &raw_key[Chacha20Poly1305::KEY_SIZE_BYTES..2 * Chacha20Poly1305::KEY_SIZE_BYTES],
        )?;

        Ok(Self { key, aad_key })
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
        // size of the data itself + the poly1305 tag size
        data_len + POLY1305_BLOCK_SIZE
    }

    fn encrypt(
        &mut self,
        data: &mut [u8],
        sequence_number: u32,
    ) -> Result<(), CryptoOperationError> {
        // this is a cipher with authenticated encryptions, so we need to extract the packet length
        // beforehand
        let (_, size_field) =
            streaming_const_take::<4>(data).map_err(|_| CryptoOperationError::EncryptionError)?;
        let pkt_size = self.get_pkt_size(size_field, sequence_number);
        data[0..4].copy_from_slice(pkt_size.to_be_bytes().as_slice());

        // encrypt in place
        let cleartext_data_end = data.len() - POLY1305_BLOCK_SIZE;
        self.cipher_main_message(&mut data[4..cleartext_data_end], sequence_number);

        let poly1305_tag = self.compute_poly1305_hash(&data[..cleartext_data_end], sequence_number);

        data[cleartext_data_end..].copy_from_slice(poly1305_tag.as_slice());

        Ok(())
    }

    fn decrypt<'a>(
        &mut self,
        input: &'a [u8],
        tmp_packet: &'a mut [u8; MAX_PKT_SIZE],
        sequence_number: u32,
    ) -> nom::IResult<&'a [u8], &'a [u8], ParsingError> {
        // this is a cipher with authenticated encryptions, so we need to extract the packet length
        // beforehand
        let (next_data, size_field) = streaming_const_take::<4>(input)?;
        let pkt_size = self.get_pkt_size(size_field, sequence_number);
        // 5 = length field + 1 byte for the packet itself
        if pkt_size < 5 || pkt_size as usize > MAX_PKT_SIZE {
            return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
                pkt_size as usize,
            )));
        }
        // ensure there is enought data in the input slice
        let (next_data, encrypted_blocks) = take(pkt_size)(next_data)?;
        let (next_data, expected_tag) = take(POLY1305_BLOCK_SIZE)(next_data)?;
        let real_tag = self.compute_poly1305_hash(&input[..pkt_size as usize + 4], sequence_number);
        if bool::from(real_tag.ct_ne(expected_tag)) {
            return Err(nom::Err::Failure(ParsingError::InvalidMac));
        }

        // decrypt in place
        tmp_packet[0..4].copy_from_slice(pkt_size.to_be_bytes().as_slice());
        tmp_packet[4..pkt_size as usize + 4].copy_from_slice(encrypted_blocks);

        self.cipher_main_message(&mut tmp_packet[4..pkt_size as usize + 4], sequence_number);

        let cur_pkt_plaintext = &tmp_packet[..pkt_size as usize + 4];

        Ok((next_data, cur_pkt_plaintext))
    }

    // Nothing to do here, the sequence number is the only nonce we use here
    fn commit(&mut self) {}
}

impl Chacha20Poly1305Impl {
    fn compute_poly1305_hash(&self, bytes: &[u8], sequence_number: u32) -> poly1305::Block {
        let sequence_number = (sequence_number as u64).to_be_bytes();
        let mut cipher = <ChaCha20Legacy as KeyIvInit>::new(
            &self.key,
            <&Iv<ChaCha20Legacy>>::from(&sequence_number),
        );

        let mut block = [0; 64];
        cipher.apply_keystream(&mut block);

        // `block` now contains the poly1305 key

        let poly =
            <Poly1305 as universal_hash::KeyInit>::new_from_slice(&block[0..poly1305::KEY_SIZE])
                .expect("Invalid poly hash");

        poly.compute_unpadded(bytes)
    }

    fn cipher_main_message(&self, bytes: &mut [u8], sequence_number: u32) {
        let sequence_number = (sequence_number as u64).to_be_bytes();
        let mut cipher = <ChaCha20Legacy as KeyIvInit>::new(
            &self.key,
            <&Iv<ChaCha20Legacy>>::from(&sequence_number),
        );
        // skip the first block, that was used to derive the poly1305 key
        cipher.seek(Chacha20Poly1305::BLOCK_SIZE_BYTES);

        cipher.apply_keystream(bytes);
    }

    fn get_pkt_size(&self, encrypted_bytes: [u8; 4], sequence_number: u32) -> u32 {
        let sequence_number = (sequence_number as u64).to_be_bytes();

        let mut block = [0; Chacha20Poly1305::BLOCK_SIZE_BYTES];
        for i in 0..4 {
            block[i] = encrypted_bytes[i];
        }

        let mut cipher = <ChaCha20Legacy as KeyIvInit>::new(
            &self.aad_key,
            <&Iv<ChaCha20Legacy>>::from(&sequence_number),
        );
        cipher.apply_keystream(&mut block);

        u32::from_be_bytes([block[0], block[1], block[2], block[3]])
    }
}
