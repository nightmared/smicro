use digest::DynDigest;
use hmac::Hmac;
use sha2::{Sha256, Sha512};
use smicro_macros::{create_wrapper_enum_implementing_trait, declare_crypto_arg};
use smicro_types::serialize::SerializePacket;

use crate::{crypto::CryptoAlg, error::Error};

#[create_wrapper_enum_implementing_trait(name = MACAllocatorWrapper, implementors = [HmacSha2256, HmacSha2512])]
pub trait MACAllocator {
    fn key_size_bites(&self) -> usize;

    fn allocate_with_key(&self, key: &[u8]) -> Result<MACWrapper, Error>;
}

#[declare_crypto_arg("hmac-sha2-256")]
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

    fn allocate_with_key(&self, key: &[u8]) -> Result<MACWrapper, Error> {
        Ok(MACWrapper::HmacSha2256Key(HmacSha2256Key {
            inner: <Hmac<Sha256> as hmac::Mac>::new_from_slice(key)
                .map_err(|_| Error::InvalidMACKeyLength)?,
        }))
    }
}

#[declare_crypto_arg("hmac-sha2-512")]
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

    fn allocate_with_key(&self, key: &[u8]) -> Result<MACWrapper, Error> {
        Ok(MACWrapper::HmacSha2512Key(HmacSha2512Key {
            inner: <Hmac<Sha512> as hmac::Mac>::new_from_slice(key)
                .map_err(|_| Error::InvalidMACKeyLength)?,
        }))
    }
}

#[create_wrapper_enum_implementing_trait(name = MACWrapper, implementors = [HmacSha2256Key, HmacSha2512Key])]
pub trait MAC {
    fn size_bytes(&self) -> usize;

    fn compute(
        &mut self,
        data: &[u8],
        sequence_number: u32,
        output: &mut [u8],
    ) -> Result<(), Error>;

    fn verify(
        &mut self,
        data: &[u8],
        sequence_number: u32,
        expected_mac: &[u8],
    ) -> Result<(), Error>;
}

#[declare_crypto_arg("hmac-sha2-512")]
pub struct HmacSha2512Key {
    inner: Hmac<Sha512>,
}

impl MAC for HmacSha2512Key {
    fn size_bytes(&self) -> usize {
        512 / 8
    }

    fn compute(
        &mut self,
        data: &[u8],
        sequence_number: u32,
        output: &mut [u8],
    ) -> Result<(), Error> {
        sequence_number.serialize(&mut self.inner)?;
        data.serialize(&mut self.inner)?;

        self.inner.finalize_into_reset(output)?;

        Ok(())
    }

    fn verify(
        &mut self,
        data: &[u8],
        sequence_number: u32,
        expected_mac: &[u8],
    ) -> Result<(), Error> {
        let mut computed_mac = [0; 64];
        self.compute(data, sequence_number, &mut computed_mac)?;
        // a mediocre attempt at constant-time comparison
        let mut identical = true;
        for i in 0..self.size_bytes() {
            identical &= expected_mac[i] == computed_mac[i];
        }
        if !identical {
            return Err(Error::InvalidMAC);
        }

        Ok(())
    }
}

#[declare_crypto_arg("hmac-sha2-256")]
pub struct HmacSha2256Key {
    inner: Hmac<Sha256>,
}

impl MAC for HmacSha2256Key {
    fn size_bytes(&self) -> usize {
        256 / 8
    }

    fn compute(
        &mut self,
        data: &[u8],
        sequence_number: u32,
        output: &mut [u8],
    ) -> Result<(), Error> {
        sequence_number.serialize(&mut self.inner)?;
        data.serialize(&mut self.inner)?;

        self.inner.finalize_into_reset(output)?;

        Ok(())
    }

    fn verify(
        &mut self,
        data: &[u8],
        sequence_number: u32,
        expected_mac: &[u8],
    ) -> Result<(), Error> {
        let mut computed_mac = [0; 32];
        self.compute(data, sequence_number, &mut computed_mac)?;
        // a mediocre attempt at constant-time comparison
        let mut identical = true;
        for i in 0..self.size_bytes() {
            identical &= expected_mac[i] == computed_mac[i];
        }
        if !identical {
            return Err(Error::InvalidMAC);
        }

        Ok(())
    }
}
