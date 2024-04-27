use std::io::Write;

use digest::Mac;
use hmac::Hmac;
use sha2::Sha512;
use smicro_types::serialize::SerializePacket;

use crate::{crypto::CryptoAlg, error::Error};

pub trait MACAllocator {
    fn name(&self) -> &'static str;
    fn key_size_bites(&self) -> usize;

    fn allocate_with_key(&self, key: &[u8]) -> Box<dyn MAC>;
}

pub trait MACIdentifier: CryptoAlg + MACAllocator {
    const NAME: &'static str;
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
        HmacSha2512::NAME
    }

    fn key_size_bites(&self) -> usize {
        512
    }

    fn allocate_with_key(&self, key: &[u8]) -> Box<dyn MAC> {
        Box::new(HmacSha2512Key { key: key.to_vec() })
    }
}

pub trait MAC {
    fn size_bytes(&self) -> usize;

    fn compute(
        &self,
        data: &[u8],
        sequence_number: u32,
        output: &mut dyn Write,
    ) -> Result<(), Error>;

    fn verify(&self, data: &[u8], sequence_number: u32, expected_mac: &[u8]) -> Result<(), Error>;
}

#[derive(Clone)]
struct HmacSha2512Key {
    key: Vec<u8>,
}

impl MAC for HmacSha2512Key {
    fn size_bytes(&self) -> usize {
        512 / 8
    }

    fn compute(
        &self,
        data: &[u8],
        sequence_number: u32,
        mut output: &mut dyn Write,
    ) -> Result<(), Error> {
        sequence_number.serialize(&mut output)?;

        let mut mac = <Hmac<Sha512> as hmac::Mac>::new_from_slice(&self.key)
            .map_err(|_| Error::InvalidMACKeyLength)?;

        sequence_number.serialize(&mut mac)?;
        data.serialize(&mut mac)?;

        let final_mac = mac.finalize();
        output.write_all(&final_mac.into_bytes())?;

        Ok(())
    }

    fn verify(&self, data: &[u8], sequence_number: u32, expected_mac: &[u8]) -> Result<(), Error> {
        let mut mac = <Hmac<Sha512> as hmac::Mac>::new_from_slice(&self.key)
            .map_err(|_| Error::InvalidMACKeyLength)?;

        sequence_number.serialize(&mut mac)?;
        data.serialize(&mut mac)?;

        let final_mac = mac.finalize();
        if *expected_mac != *final_mac.into_bytes() {
            return Err(Error::InvalidMAC);
        }

        Ok(())
    }
}
