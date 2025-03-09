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
    ctr: Array<u8, cipher::consts::U16>,
}

impl CryptoAlgWithKey for Aes256CtrImpl {
    fn new(keys: &[&[u8]]) -> Result<Self, CryptoOperationError> {
        let raw_key = keys[0];
        let raw_iv = keys[1];
        let raw_key = Array::try_from(&raw_key[0..Aes256Ctr::KEY_SIZE_BYTES])?;
        let key = aes::Aes256::new(&raw_key);
        let ctr = Array::try_from(&raw_iv[0..Aes256Ctr::IV_SIZE_BYTES])?;

        Ok(Self { raw_key, key, ctr })
    }
}

impl Cipher for Aes256CtrImpl {
    fn block_size_bytes(&self) -> usize {
        Aes256Ctr::BLOCK_SIZE_BYTES
    }

    fn required_space_to_encrypt(&self, data_len: usize) -> usize {
        // size of the data itself
        data_len
    }

    fn encrypt(
        &mut self,
        data: &mut [u8],
        _sequence_number: u32,
    ) -> Result<(), CryptoOperationError> {
        self.cipher_main_message(data);

        Ok(())
    }

    fn decrypt<'a>(
        &mut self,
        input: &'a mut [u8],
        _sequence_number: u32,
    ) -> IResult<&'a [u8], &'a [u8], ParsingError> {
        // we need to extract the packet length from the first block
        let _ = take(Aes256Ctr::BLOCK_SIZE_BYTES)(input.as_ref())?;
        let pkt_size = self.get_pkt_size(&mut input[0..Aes256Ctr::BLOCK_SIZE_BYTES]);
        // 5 = length field + 1 byte for the packet itself
        if pkt_size < 5 || pkt_size as usize > MAX_PKT_SIZE {
            return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
                pkt_size as usize,
            )));
        }

        // roundup to the next block number
        let total_size = (pkt_size as usize + 4 + (Aes256Ctr::BLOCK_SIZE_BYTES - 1))
            & !(Aes256Ctr::BLOCK_SIZE_BYTES - 1);
        // ensure we have enough data
        let _ = take(total_size)(input.as_ref())?;

        if pkt_size as usize + 4 > Aes256Ctr::BLOCK_SIZE_BYTES {
            self.cipher_main_message(&mut input[Aes256Ctr::BLOCK_SIZE_BYTES..total_size]);
        }

        let next_data = &input[total_size..];
        let cur_pkt_plaintext = &input[..total_size];

        Ok((next_data, cur_pkt_plaintext))
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

    fn get_pkt_size(&mut self, arr: &mut [u8]) -> u32 {
        self.cipher_block(arr);

        u32::from_be_bytes([arr[0], arr[1], arr[2], arr[3]])
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
