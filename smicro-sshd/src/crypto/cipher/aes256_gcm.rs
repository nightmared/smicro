use std::{fmt::Debug, num::Wrapping};

use aead::{AeadMutInPlace, KeyInit};
use aes_gcm::Aes256Gcm as OfficialAes256Gcm;
use hybrid_array::Array;
use nom::{bytes::streaming::take, number::complete::be_u32};
use smicro_macros::{declare_crypto_arg, declare_deserializable_struct, gen_serialize_impl};
use smicro_types::{
    deserialize::DeserializePacket,
    error::ParsingError,
    serialize::SerializePacket,
    ssh::{deserialize::streaming_const_take, types::SharedSSHSlice},
};

use crate::crypto::CryptoAlg;
use crate::{
    error::{CryptoOperationError, Error},
    packet::MAX_PKT_SIZE,
};

use super::{Cipher, CipherAllocator, CipherWrapper, CryptoAlgWithKey};

const AES256GCM_TAG_SIZE: usize = 16;

#[derive(Clone, Debug)]
#[declare_crypto_arg("aes256-gcm@openssh.com")]
#[declare_deserializable_struct]
#[gen_serialize_impl]
pub struct Aes256Gcm {}

impl CryptoAlg for Aes256Gcm {
    fn new() -> Self {
        Self {}
    }
}

impl Aes256Gcm {
    const KEY_SIZE_BYTES: usize = 32;
    const IV_SIZE_BYTES: usize = 12;
    const BLOCK_SIZE_BYTES: usize = 32;
}

impl CipherAllocator for Aes256Gcm {
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
        Ok(CipherWrapper::Aes256GcmImpl(Aes256GcmImpl::new(&[
            raw_key, raw_iv,
        ])?))
    }
}

#[declare_crypto_arg("aes256-gcm@openssh.com")]
#[derive(Clone)]
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
    fn new(keys: &[&[u8]]) -> Result<Self, CryptoOperationError> {
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

    fn mac_size(&self) -> usize {
        AES256GCM_TAG_SIZE
    }

    fn is_aead(&self) -> bool {
        true
    }

    fn encrypt(&mut self, data: &mut [u8], _sequence_number: u32) {
        // this is a cipher with authenticated encryptions, so we need to extract the packet length
        // beforehand
        let (_, size_field) = streaming_const_take::<4>(data)
            .map_err(|_| CryptoOperationError::EncryptionError)
            .expect("Invariant was violated: not enough data supplied");

        // encrypt in place
        let cleartext_data_end = data.len() - AES256GCM_TAG_SIZE;

        let tag = self
            .inner
            .encrypt_in_place_detached(&self.nonce, &size_field, &mut data[4..cleartext_data_end])
            .map_err(|_| CryptoOperationError::EncryptionError)
            .expect("Encryption failed: wrong data size?");

        data[cleartext_data_end..].copy_from_slice(tag.as_slice());
    }

    fn decrypt<'a>(
        &mut self,
        input: &'a [u8],
        tmp_packet: &'a mut [u8; MAX_PKT_SIZE],
        _sequence_number: u32,
    ) -> nom::IResult<&'a [u8], &'a [u8], ParsingError> {
        // this is a cipher with authenticated encryptions, so we need to extract the packet length
        // beforehand
        let (_, size_field) = streaming_const_take::<4>(input)?;
        let (_, pkt_size) = be_u32(size_field.as_slice())?;
        // 5 = padding_length field + 4 bytes as this is the minimum possible padding
        if pkt_size < 5 || pkt_size as usize > MAX_PKT_SIZE {
            return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
                pkt_size as usize,
            )));
        }
        // ensure there is enought data in the input slice
        let (next_data, packet_payload) = take(pkt_size + 4)(input)?;
        let (next_data, expected_tag) = streaming_const_take::<AES256GCM_TAG_SIZE>(next_data)?;
        let expected_tag = Array::from(expected_tag);

        tmp_packet[..pkt_size as usize + 4].copy_from_slice(packet_payload);

        self.inner
            .decrypt_in_place_detached(
                &self.nonce,
                &size_field,
                &mut tmp_packet[4..pkt_size as usize + 4],
                &expected_tag,
            )
            .map_err(|_| nom::Err::Failure(ParsingError::InvalidMac))?;

        let cur_pkt_plaintext = &tmp_packet[..pkt_size as usize + 4];

        Ok((next_data, cur_pkt_plaintext))
    }

    fn commit(&mut self) {
        // valid decryption: update the nonce
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
        self.nonce[4..].clone_from_slice(&next_invocation_counter.0.to_be_bytes());
    }
}
