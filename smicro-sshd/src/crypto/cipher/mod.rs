use std::fmt::Debug;

use cipher::{BlockCipherEncrypt, KeyInit};
use hybrid_array::Array;
use nom::{bytes::streaming::take, IResult};

use smicro_macros::{
    create_wrapper_enum_implementing_trait, declare_crypto_arg, declare_deserializable_struct,
    gen_serialize_impl,
};
use smicro_types::{
    deserialize::DeserializePacket, error::ParsingError, serialize::SerializePacket,
};

use crate::{
    crypto::{CryptoAlg, KeyWrapper},
    error::Error,
    MAX_PKT_SIZE,
};

use super::CryptoAlgWithKey;

#[cfg(not(feature = "rustcrypto"))]
pub mod ring;
#[cfg(not(feature = "rustcrypto"))]
pub use ring::{Aes256GcmImpl, Chacha20Poly1305Impl};

#[cfg(feature = "rustcrypto")]
pub mod rustcrypto;
#[cfg(feature = "rustcrypto")]
pub use rustcrypto::{Aes256GcmImpl, Chacha20Poly1305Impl};

const POLY1305_BLOCK_SIZE: usize = 16;
const AES256GCM_TAG_SIZE: usize = 16;

#[create_wrapper_enum_implementing_trait(name = CipherAllocatorWrapper, serializable = true, deserializable = true)]
#[implementors(Chacha20Poly1305, Aes256Gcm, Aes256Ctr)]
pub trait CipherAllocator {
    fn key_size_bits(&self) -> usize;
    fn iv_size_bits(&self) -> usize;
    fn block_size_bits(&self) -> usize;

    fn from_key(&self, raw_key: &[u8], raw_iv: &[u8]) -> Result<CipherWrapper, Error>;
}

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
        Ok(CipherWrapper::KeyWrapperAes256CtrImpl(KeyWrapper::new(&[
            raw_key, raw_iv,
        ])?))
    }
}

#[create_wrapper_enum_implementing_trait(name = CipherWrapper, serializable = true, deserializable = true)]
#[implementors(KeyWrapper::<Chacha20Poly1305Impl>, Aes256GcmImpl, KeyWrapper::<Aes256CtrImpl>)]
pub trait Cipher {
    fn block_size_bytes(&self) -> usize;

    fn is_aead(&self) -> bool {
        false
    }

    fn required_space_to_encrypt(&self, data_len: usize) -> usize;

    fn encrypt(&mut self, data: &mut [u8], sequence_number: u32) -> Result<(), Error>;

    fn decrypt<'a>(
        &mut self,
        input: &'a mut [u8],
        sequence_number: u32,
    ) -> IResult<&'a [u8], &'a [u8], ParsingError>;
}

impl<T: Cipher> Cipher for KeyWrapper<T> {
    fn block_size_bytes(&self) -> usize {
        self.inner.block_size_bytes()
    }

    fn is_aead(&self) -> bool {
        self.inner.is_aead()
    }

    fn required_space_to_encrypt(&self, data_len: usize) -> usize {
        self.inner.required_space_to_encrypt(data_len)
    }

    fn encrypt(&mut self, data: &mut [u8], sequence_number: u32) -> Result<(), Error> {
        self.inner.encrypt(data, sequence_number)
    }

    fn decrypt<'a>(
        &mut self,
        input: &'a mut [u8],
        sequence_number: u32,
    ) -> IResult<&'a [u8], &'a [u8], ParsingError> {
        self.inner.decrypt(input, sequence_number)
    }
}

#[declare_crypto_arg("aes256-ctr")]
pub struct Aes256CtrImpl {
    key: Array<u8, cipher::consts::U32>,
    ctr: Array<u8, cipher::consts::U16>,
}

impl CryptoAlgWithKey for Aes256CtrImpl {
    fn new(keys: &[&[u8]]) -> Result<Self, Error> {
        let raw_key = keys[0];
        let raw_iv = keys[1];
        let key = Array::try_from(&raw_key[0..Aes256Ctr::KEY_SIZE_BYTES])?;
        let ctr = Array::try_from(&raw_iv[0..Aes256Ctr::IV_SIZE_BYTES])?;

        Ok(Self { key, ctr })
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

    fn encrypt(&mut self, data: &mut [u8], _sequence_number: u32) -> Result<(), Error> {
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
        let _ = take(total_size)(input.as_ref())?;

        self.cipher_main_message(&mut input[Aes256Ctr::BLOCK_SIZE_BYTES..total_size]);

        let next_data = &input[4 + pkt_size as usize..];
        let cur_pkt_plaintext = &input[..4 + pkt_size as usize];

        Ok((next_data, cur_pkt_plaintext))
    }
}

impl Aes256CtrImpl {
    fn cipher_main_message(&mut self, mut bytes: &mut [u8]) {
        while bytes.len() > 0 {
            let (block, next_bytes) = bytes.split_at_mut(Aes256Ctr::BLOCK_SIZE_BYTES);
            self.cipher_block(block);
            bytes = next_bytes;
        }
    }

    fn get_and_increment_ctr(&mut self) -> Array<u8, cipher::consts::U16> {
        let original_ctr = self.ctr.clone();

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

        let key = aes::Aes256::new(&self.key);
        key.encrypt_block(&mut keystream);

        for i in 0..Aes256Ctr::BLOCK_SIZE_BYTES {
            array[i] ^= keystream[i];
        }
    }

    fn get_pkt_size(&mut self, arr: &mut [u8]) -> u32 {
        self.cipher_block(arr);

        u32::from_be_bytes([arr[0], arr[1], arr[2], arr[3]])
    }
}
