use std::fmt::Debug;

use aead::KeyInit;
use cipher::BlockCipherEncrypt;
use hybrid_array::Array;
use nom::{IResult, bytes::streaming::take};
use smicro_macros::{declare_crypto_arg, declare_deserializable_struct, gen_serialize_impl};
use smicro_types::{
    deserialize::DeserializePacket, error::ParsingError, serialize::SerializePacket,
    ssh::types::SharedSSHSlice,
};

use crate::crypto::CryptoAlg;
use crate::{
    error::{CryptoOperationError, Error},
    packet::MAX_PKT_SIZE,
};

use super::{Cipher, CipherAllocator, CipherWrapper, CryptoAlgWithKey};

#[derive(Clone, Debug)]
#[declare_crypto_arg("aes256-ctr")]
#[declare_deserializable_struct]
#[gen_serialize_impl]
pub struct Aes256Ctr {}

impl CryptoAlg for Aes256Ctr {
    fn new() -> Self {
        Self {}
    }
}

impl Aes256Ctr {
    const KEY_SIZE_BYTES: usize = 32;
    const IV_SIZE_BYTES: usize = 16;
    const BLOCK_SIZE_BYTES: usize = 16;
}

impl CipherAllocator for Aes256Ctr {
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
        Ok(CipherWrapper::Aes256CtrImpl(Aes256CtrImpl::new(&[
            raw_key, raw_iv,
        ])?))
    }
}

#[derive(Debug)]
#[declare_crypto_arg("aes256-ctr")]
pub struct Aes256CtrImpl {
    raw_key: Array<u8, cipher::consts::U32>,
    key: aes::Aes256,
    base_ctr: Array<u8, cipher::consts::U16>,
    ctr: Array<u8, cipher::consts::U16>,
}

impl CryptoAlgWithKey for Aes256CtrImpl {
    fn new(keys: &[&[u8]]) -> Result<Self, CryptoOperationError> {
        let raw_key = keys[0];
        let raw_iv = keys[1];
        let raw_key = Array::try_from(&raw_key[0..Aes256Ctr::KEY_SIZE_BYTES])?;
        let key = aes::Aes256::new(&raw_key);
        let ctr = Array::try_from(&raw_iv[0..Aes256Ctr::IV_SIZE_BYTES])?;

        Ok(Self {
            raw_key,
            key,
            base_ctr: ctr,
            ctr,
        })
    }
}

impl Cipher for Aes256CtrImpl {
    fn block_size_bytes(&self) -> usize {
        Aes256Ctr::BLOCK_SIZE_BYTES
    }

    fn encrypt(&mut self, data: &mut [u8], _sequence_number: u32) {
        // reset the counter state to the last successful decryption position
        self.ctr = self.base_ctr;

        self.cipher_main_message(data);
    }

    fn decrypt<'a>(
        &mut self,
        input: &'a [u8],
        tmp_packet: &'a mut [u8; MAX_PKT_SIZE],
        _sequence_number: u32,
    ) -> IResult<&'a [u8], &'a [u8], ParsingError> {
        // reset the counter state to the last successful decryption position
        self.ctr = self.base_ctr;

        // we need to extract the packet length from the first block
        let (next_data, first_block) = take(Aes256Ctr::BLOCK_SIZE_BYTES)(input.as_ref())?;
        tmp_packet[0..Aes256Ctr::BLOCK_SIZE_BYTES].copy_from_slice(first_block);
        self.cipher_block(tmp_packet);
        let pkt_size =
            u32::from_be_bytes([tmp_packet[0], tmp_packet[1], tmp_packet[2], tmp_packet[3]]);
        // length field + packet content, rounded to the next block
        let full_pkt_size = (pkt_size as usize + 4 + (Aes256Ctr::BLOCK_SIZE_BYTES - 1))
            & !(Aes256Ctr::BLOCK_SIZE_BYTES - 1);
        if full_pkt_size < Aes256Ctr::BLOCK_SIZE_BYTES || full_pkt_size > MAX_PKT_SIZE {
            return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
                pkt_size as usize,
            )));
        }

        // ensure we have enough data
        let (next_data, next_blocks) =
            take(full_pkt_size - Aes256Ctr::BLOCK_SIZE_BYTES)(next_data)?;
        for i in 0..next_blocks.len() {
            tmp_packet[Aes256Ctr::BLOCK_SIZE_BYTES + i] = next_blocks[i];
        }

        self.cipher_main_message(&mut tmp_packet[Aes256Ctr::BLOCK_SIZE_BYTES..full_pkt_size]);

        let cur_pkt_plaintext = &tmp_packet[..full_pkt_size];

        Ok((next_data, cur_pkt_plaintext))
    }

    fn commit(&mut self) {
        self.base_ctr = self.ctr;
    }
}

impl Aes256CtrImpl {
    fn cipher_main_message(&mut self, mut bytes: &mut [u8]) {
        while !bytes.is_empty() {
            let (block, next_bytes) = bytes.split_at_mut(Aes256Ctr::BLOCK_SIZE_BYTES);
            self.cipher_block(block);
            bytes = next_bytes;
        }
    }

    fn get_and_increment_ctr(&mut self) -> Array<u8, cipher::consts::U16> {
        let original_ctr = self.ctr;

        // increment the counter in a constant-time manner: copied from openssh
        // (https://github.com/openssh/openssh-portable/blob/c276672fc0e99f0c4389988d54a84c203ce325b6/cipher-aesctr.c#L42-L52)
        let mut add = 1;
        for i in (0..Aes256Ctr::BLOCK_SIZE_BYTES).rev() {
            self.ctr[i] += add;
            let v = self.ctr[i];
            // there is a carry only if the current byte wrapped to zero
            add *= 1
                ^ (((v >> 7)
                    | (v >> 6)
                    | (v >> 5)
                    | (v >> 4)
                    | (v >> 3)
                    | (v >> 2)
                    | (v >> 1)
                    | v)
                    & 1);
        }

        original_ctr
    }

    fn cipher_block(&mut self, array: &mut [u8]) {
        let mut keystream = self.get_and_increment_ctr();

        self.key.encrypt_block(&mut keystream);

        for i in 0..Aes256Ctr::BLOCK_SIZE_BYTES {
            array[i] ^= keystream[i];
        }
    }
}

impl<'a> DeserializePacket<'a> for Aes256CtrImpl {
    fn deserialize(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParsingError> {
        let (input, raw_key) = SharedSSHSlice::deserialize(input)?;
        let (input, ctr) = SharedSSHSlice::deserialize(input)?;

        Ok((
            input,
            Self::new(&[raw_key.0, ctr.0])
                .expect("Couldn't recreate a key from its serialized representation!?"),
        ))
    }
}

impl SerializePacket for Aes256CtrImpl {
    fn get_size(&self) -> usize {
        SharedSSHSlice(self.raw_key.as_slice()).get_size()
            + SharedSSHSlice(self.ctr.as_slice()).get_size()
    }

    fn serialize<W: std::io::Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        SharedSSHSlice(self.raw_key.as_slice()).serialize(&mut output)?;
        SharedSSHSlice(self.ctr.as_slice()).serialize(output)
    }
}
