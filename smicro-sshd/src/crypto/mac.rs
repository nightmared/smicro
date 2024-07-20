use digest::{DynDigest, Mac, Reset};
use hmac::Hmac;
use sha2::{Sha256, Sha512};
use smicro_types::serialize::SerializePacket;

use crate::{crypto::CryptoAlg, error::Error};

pub trait MACAllocator {
    fn name(&self) -> &'static str;
    fn key_size_bites(&self) -> usize;

    fn allocate_with_key(&self, key: &[u8]) -> Result<Box<dyn MAC>, Error>;
}

pub trait MACIdentifier: CryptoAlg + MACAllocator {
    const NAME: &'static str;
}
#[derive(Clone)]
pub struct HmacSha2256 {}

impl CryptoAlg for HmacSha2256 {
    fn new() -> Self {
        Self {}
    }
}

impl MACIdentifier for HmacSha2256 {
    const NAME: &'static str = "hmac-sha2-256";
}

impl MACAllocator for HmacSha2256 {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn key_size_bites(&self) -> usize {
        256
    }

    fn allocate_with_key(&self, key: &[u8]) -> Result<Box<dyn MAC>, Error> {
        Ok(Box::new(HmacSha2256Key {
            inner: <Hmac<Sha256> as hmac::Mac>::new_from_slice(key)
                .map_err(|_| Error::InvalidMACKeyLength)?,
        }))
    }
}

#[derive(Clone)]
pub struct HmacSha2512 {}

impl CryptoAlg for HmacSha2512 {
    fn new() -> Self {
        Self {}
    }
}

impl MACIdentifier for HmacSha2512 {
    const NAME: &'static str = "hmac-sha2-512";
}

impl MACAllocator for HmacSha2512 {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn key_size_bites(&self) -> usize {
        512
    }

    fn allocate_with_key(&self, key: &[u8]) -> Result<Box<dyn MAC>, Error> {
        Ok(Box::new(HmacSha2512Key {
            inner: <Hmac<Sha512> as hmac::Mac>::new_from_slice(key)
                .map_err(|_| Error::InvalidMACKeyLength)?,
        }))
    }
}

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

#[derive(Clone)]
struct HmacSha2512Key {
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

#[derive(Clone)]
struct HmacSha2256Key {
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
