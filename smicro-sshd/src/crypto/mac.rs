use cipher::{
    consts::{U64, U256},
    typenum::{IsLess, Le, NonZero},
};
use digest::{
    DynDigest, FixedOutputReset, HashMarker, OutputSizeUser,
    block_buffer::Eager,
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
};
use hmac::Hmac;
use sha2::{Sha256, Sha512};

use smicro_macros::{
    create_wrapper_enum_implementing_trait, declare_crypto_arg, declare_deserializable_struct,
    gen_serialize_impl,
};
use smicro_types::{deserialize::DeserializePacket, serialize::SerializePacket};

use crate::{
    crypto::{CryptoAlg, KeyWrapper},
    error::CryptoOperationError,
};

use super::CryptoAlgWithKey;

#[create_wrapper_enum_implementing_trait(name = MACAllocatorWrapper, serializable = true, deserializable = true)]
#[implementors(HmacSha2256, HmacSha2512)]
pub trait MACAllocator {
    fn key_size_bites(&self) -> usize;

    fn allocate_with_key(&self, key: &[u8]) -> Result<MACWrapper, CryptoOperationError>;
}

#[derive(Clone, Debug)]
#[declare_crypto_arg("hmac-sha2-256")]
#[declare_deserializable_struct]
#[gen_serialize_impl]
pub struct HmacSha2256 {}

impl CryptoAlg for HmacSha2256 {
    fn new() -> Self {
        Self {}
    }
}

impl MACAllocator for HmacSha2256 {
    fn key_size_bites(&self) -> usize {
        256
    }

    fn allocate_with_key(&self, key: &[u8]) -> Result<MACWrapper, CryptoOperationError> {
        Ok(MACWrapper::KeyWrapperHmacSha256(KeyWrapper::new(&[key])?))
    }
}

#[derive(Clone, Debug)]
#[declare_crypto_arg("hmac-sha2-512")]
#[declare_deserializable_struct]
#[gen_serialize_impl]
pub struct HmacSha2512 {}

impl CryptoAlg for HmacSha2512 {
    fn new() -> Self {
        Self {}
    }
}

impl MACAllocator for HmacSha2512 {
    fn key_size_bites(&self) -> usize {
        512
    }

    fn allocate_with_key(&self, key: &[u8]) -> Result<MACWrapper, CryptoOperationError> {
        Ok(MACWrapper::KeyWrapperHmacSha512(KeyWrapper::new(&[key])?))
    }
}

#[create_wrapper_enum_implementing_trait(name = MACWrapper, serializable = true, deserializable = true, clonable = false)]
#[implementors(KeyWrapper::<Hmac<Sha256>>, KeyWrapper::<Hmac<Sha512>>)]
pub trait MAC {
    fn size_bytes(&self) -> usize;

    fn compute(&mut self, data: &[u8], sequence_number: u32, output: &mut [u8]);

    fn verify(
        &mut self,
        data: &[u8],
        sequence_number: u32,
        expected_mac: &[u8],
    ) -> Result<(), CryptoOperationError>;
}

impl crate::crypto::CryptoAlgName for Hmac<Sha256> {
    const NAME: &'static str = "hmac-sha2-256";

    fn name(&self) -> &'static str {
        Self::NAME
    }
}

impl crate::crypto::CryptoAlgName for Hmac<Sha512> {
    const NAME: &'static str = "hmac-sha2-512";

    fn name(&self) -> &'static str {
        Self::NAME
    }
}

impl<T> MAC for Hmac<T>
where
    T: CoreProxy + 'static,
    T::Core: Clone
        + Default
        + FixedOutputCore
        + OutputSizeUser
        + UpdateCore
        + HashMarker
        + BufferKindUser<BufferKind = Eager>,
    <T::Core as OutputSizeUser>::OutputSize: IsLess<U64>,
    <T::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<T::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn size_bytes(&self) -> usize {
        T::Core::output_size()
    }

    fn compute(&mut self, data: &[u8], sequence_number: u32, output: &mut [u8]) {
        self.update(&sequence_number.to_be_bytes());
        self.update(&data);

        FixedOutputReset::finalize_into_reset(self, digest::Output::<Self>::from_mut_slice(output));
    }

    fn verify(
        &mut self,
        data: &[u8],
        sequence_number: u32,
        expected_mac: &[u8],
    ) -> Result<(), CryptoOperationError> {
        let mut computed_mac = [0; 64];
        let computed_mac = &mut computed_mac[..self.size_bytes()];
        self.compute(data, sequence_number, computed_mac);
        // a mediocre attempt at constant-time comparison
        let mut different_byte_present = 0;
        for i in 0..self.size_bytes() {
            let diff = expected_mac[i] ^ computed_mac[i];
            different_byte_present |= ((diff >> 7)
                | (diff >> 6)
                | (diff >> 5)
                | (diff >> 4)
                | (diff >> 3)
                | (diff >> 2)
                | (diff >> 1)
                | diff)
                & 1;
        }
        if different_byte_present == 1 {
            return Err(CryptoOperationError::InvalidMAC);
        }

        Ok(())
    }
}

impl<T> MAC for KeyWrapper<T>
where
    T: MAC,
{
    fn size_bytes(&self) -> usize {
        self.inner.size_bytes()
    }

    fn compute(&mut self, data: &[u8], sequence_number: u32, output: &mut [u8]) {
        self.inner.compute(data, sequence_number, output)
    }

    fn verify(
        &mut self,
        data: &[u8],
        sequence_number: u32,
        expected_mac: &[u8],
    ) -> Result<(), CryptoOperationError> {
        self.inner.verify(data, sequence_number, expected_mac)
    }
}

impl<T: digest::Mac + digest::KeyInit> CryptoAlgWithKey for T {
    fn new(keys: &[&[u8]]) -> Result<Self, CryptoOperationError> {
        <T as digest::Mac>::new_from_slice(keys[0])
            .map_err(|_| CryptoOperationError::InvalidMACKeyLength)
    }
}
