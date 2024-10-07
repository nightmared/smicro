use std::{fmt::Debug, num::Wrapping};

use aead::{AeadMutInPlace, KeyInit};
use aes_gcm::Aes256Gcm as OfficialAes256Gcm;
use chacha20::ChaCha20Legacy;
use cipher::{Iv, KeyIvInit, StreamCipher, StreamCipherSeek};
use elliptic_curve::subtle::ConstantTimeEq;
use hybrid_array::Array;
use nom::{bytes::streaming::take, number::complete::be_u32};
use poly1305::Poly1305;
use smicro_macros::declare_crypto_arg;
use smicro_types::{
    deserialize::DeserializePacket,
    error::ParsingError,
    serialize::SerializePacket,
    ssh::{deserialize::streaming_const_take, types::SharedSSHSlice},
};

use crate::{error::Error, packet::MAX_PKT_SIZE};

use super::{
    Aes256Gcm, Chacha20Poly1305, Cipher, CryptoAlgWithKey, AES256GCM_TAG_SIZE, POLY1305_BLOCK_SIZE,
};

#[declare_crypto_arg("chacha20-poly1305@openssh.com")]
pub struct Chacha20Poly1305Impl {
    key: Array<u8, cipher::consts::U32>,
    aad_key: Array<u8, cipher::consts::U32>,
}

impl CryptoAlgWithKey for Chacha20Poly1305Impl {
    fn new(keys: &[&[u8]]) -> Result<Self, Error> {
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

    fn encrypt(&mut self, data: &mut [u8], sequence_number: u32) -> Result<(), Error> {
        // this is a cipher with authenticated encryptions, so we need to extract the packet length
        // beforehand
        let (_, size_field) =
            streaming_const_take::<4>(data).map_err(|_| Error::EncryptionError)?;
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
        input: &'a mut [u8],
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
        let (next_data, _) = take(pkt_size)(next_data)?;

        let (_, expected_tag) = take(POLY1305_BLOCK_SIZE)(next_data)?;
        let real_tag =
            self.compute_poly1305_hash(&input[0..(pkt_size + 4) as usize], sequence_number);
        if bool::from(real_tag.ct_ne(expected_tag)) {
            return Err(nom::Err::Failure(ParsingError::InvalidMac));
        }

        // decrypt in place
        input[0..4].copy_from_slice(pkt_size.to_be_bytes().as_slice());
        self.cipher_main_message(&mut input[4..4 + pkt_size as usize], sequence_number);

        let next_data = &input[poly1305::BLOCK_SIZE + 4 + pkt_size as usize..];
        let cur_pkt_plaintext = &input[..4 + pkt_size as usize];

        Ok((next_data, cur_pkt_plaintext))
    }
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

#[declare_crypto_arg("aes256-gcm@openssh.com")]
pub struct Aes256GcmImpl {
    raw_key: Array<u8, cipher::consts::U32>,
    inner: OfficialAes256Gcm,
    nonce: Array<u8, cipher::consts::U12>,
}

impl Debug for Aes256GcmImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes256GcmImpl").finish()
    }
}

impl<'a> DeserializePacket<'a> for Aes256GcmImpl {
    fn deserialize(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParsingError> {
        let (input, raw_key) = SharedSSHSlice::deserialize(input)?;
        let (input, nonce) = SharedSSHSlice::deserialize(input)?;

        Ok((
            input,
            Aes256GcmImpl::new(&[raw_key.0, nonce.0])
                .expect("Couldn't recreate a key from its serialized representation!?"),
        ))
    }
}

impl SerializePacket for Aes256GcmImpl {
    fn get_size(&self) -> usize {
        SharedSSHSlice(self.raw_key.as_slice()).get_size()
            + SharedSSHSlice(self.nonce.as_slice()).get_size()
    }

    fn serialize<W: std::io::Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        SharedSSHSlice(self.raw_key.as_slice()).serialize(&mut output)?;
        SharedSSHSlice(self.nonce.as_slice()).serialize(output)
    }
}

impl CryptoAlgWithKey for Aes256GcmImpl {
    fn new(keys: &[&[u8]]) -> Result<Self, Error> {
        let raw_key = keys[0];
        let raw_iv = keys[1];
        let key = Array::try_from(&raw_key[0..Aes256Gcm::KEY_SIZE_BYTES])?;
        let nonce = Array::try_from(&raw_iv[0..Aes256Gcm::IV_SIZE_BYTES])?;

        Ok(Self {
            raw_key: key,
            inner: OfficialAes256Gcm::new(&key),
            nonce,
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

        let tag = self
            .inner
            .encrypt_in_place_detached(&self.nonce, &size_field, &mut data[4..cleartext_data_end])
            .map_err(|_| Error::EncryptionError)?;

        // succeeded -> let's update the nonce
        self.nonce = self.get_next_nonce_value();

        data[cleartext_data_end..].copy_from_slice(tag.as_slice());

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
        let (next_data, _) = take(pkt_size)(next_data)?;

        let (_, expected_tag) = streaming_const_take::<AES256GCM_TAG_SIZE>(next_data)?;
        let expected_tag = Array::from(expected_tag);

        self.inner
            .decrypt_in_place_detached(
                &self.nonce,
                &size_field,
                &mut input[4..4 + pkt_size as usize],
                &expected_tag,
            )
            .map_err(|_| nom::Err::Failure(ParsingError::InvalidMac))?;

        // valid decryption: update the nonce
        self.nonce = self.get_next_nonce_value();

        let next_data = &input[AES256GCM_TAG_SIZE + 4 + pkt_size as usize..];
        let cur_pkt_plaintext = &input[..4 + pkt_size as usize];

        Ok((next_data, cur_pkt_plaintext))
    }
}

impl Aes256GcmImpl {
    fn get_next_nonce_value(&self) -> Array<u8, cipher::consts::U12> {
        // TODO: is this constant-time?
        let mut next_nonce = self.nonce;
        let next_invocation_counter = Wrapping(u64::from_be_bytes([
            self.nonce[4],
            self.nonce[5],
            self.nonce[6],
            self.nonce[7],
            self.nonce[8],
            self.nonce[9],
            self.nonce[10],
            self.nonce[11],
        ])) + Wrapping(1u64);
        next_nonce[4..].clone_from_slice(&next_invocation_counter.0.to_be_bytes());

        next_nonce
    }
}
