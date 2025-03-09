use std::fmt::Debug;

use nom::IResult;

use smicro_macros::create_wrapper_enum_implementing_trait;
use smicro_types::error::ParsingError;

use crate::{
    crypto::KeyWrapper,
    error::{CryptoOperationError, Error},
};

use super::CryptoAlgWithKey;

pub mod aes256_ctr;
pub use aes256_ctr::{Aes256Ctr, Aes256CtrImpl};

pub mod aes256_gcm;
pub use aes256_gcm::{Aes256Gcm, Aes256GcmImpl};

pub mod chacha20_poly1305;
pub use chacha20_poly1305::{Chacha20Poly1305, Chacha20Poly1305Impl};

#[create_wrapper_enum_implementing_trait(name = CipherAllocatorWrapper, serializable = true, deserializable = true)]
#[implementors(Chacha20Poly1305, Aes256Gcm, Aes256Ctr)]
pub trait CipherAllocator {
    fn key_size_bits(&self) -> usize;
    fn iv_size_bits(&self) -> usize;
    fn block_size_bits(&self) -> usize;

    fn from_key(&self, raw_key: &[u8], raw_iv: &[u8]) -> Result<CipherWrapper, Error>;
}

#[create_wrapper_enum_implementing_trait(name = CipherWrapper, serializable = true, deserializable = true, clonable = false)]
#[implementors(KeyWrapper::<Chacha20Poly1305Impl>, Aes256GcmImpl, Aes256CtrImpl)]
pub trait Cipher {
    fn block_size_bytes(&self) -> usize;

    fn is_aead(&self) -> bool {
        false
    }

    fn required_space_to_encrypt(&self, data_len: usize) -> usize;

    fn encrypt(
        &mut self,
        data: &mut [u8],
        sequence_number: u32,
    ) -> Result<(), CryptoOperationError>;

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

    fn encrypt(
        &mut self,
        data: &mut [u8],
        sequence_number: u32,
    ) -> Result<(), CryptoOperationError> {
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
