use std::io::Write;

use chacha20::cipher::generic_array::GenericArray;
use chacha20::ChaCha20Legacy;
use cipher::StreamCipher;
use cipher::StreamCipherSeek;
use cipher::{Iv, KeyIvInit};
use elliptic_curve::subtle::ConstantTimeEq;
use nom::{bytes::streaming::take, IResult};
use poly1305::Poly1305;
use smicro_types::serialize::SerializePacket;
use smicro_types::{
    error::ParsingError,
    ssh::deserialize::{const_take, streaming_const_take},
};

use crate::{crypto::CryptoAlg, error::Error, MAX_PKT_SIZE};

pub trait CipherIdentifier: CryptoAlg + CipherAllocator {
    const NAME: &'static str;
}

pub trait CipherAllocator {
    fn name(&self) -> &'static str;
    fn key_size_bits(&self) -> usize;
    fn iv_size_bits(&self) -> usize;
    fn block_size_bits(&self) -> usize;

    fn from_key(&self, key: &[u8]) -> Result<Box<dyn Cipher>, Error>;
}

#[derive(Clone)]
pub struct Chacha20Poly1305 {}

impl CryptoAlg for Chacha20Poly1305 {
    fn new() -> Self {
        Self {}
    }
}

impl CipherIdentifier for Chacha20Poly1305 {
    const NAME: &'static str = "chacha20-poly1305@openssh.com";
}

impl Chacha20Poly1305 {
    const KEY_SIZE_BYTES: usize = 32;
    const IV_SIZE_BYTES: usize = 8;
    const BLOCK_SIZE_BYTES: usize = 64;
}

impl CipherAllocator for Chacha20Poly1305 {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn key_size_bits(&self) -> usize {
        Self::KEY_SIZE_BYTES * 8
    }

    fn iv_size_bits(&self) -> usize {
        Self::IV_SIZE_BYTES * 8
    }

    fn block_size_bits(&self) -> usize {
        Self::BLOCK_SIZE_BYTES * 8
    }

    fn from_key(&self, raw_key: &[u8]) -> Result<Box<dyn Cipher>, Error> {
        let key = GenericArray::from_slice(&raw_key[0..self.key_size_bits() / 8]).clone();
        let aad_key = GenericArray::from_slice(
            &raw_key[self.key_size_bits() / 8..2 * self.key_size_bits() / 8],
        )
        .clone();

        Ok(Box::new(Chacha20Poly1305Impl { key, aad_key }))
    }
}

pub trait Cipher {
    fn block_size_bytes(&self) -> usize;

    fn encrypt(
        &self,
        cleartext_data: &mut [u8],
        sequence_number: u32,
        ciphered_data: &mut dyn Write,
    ) -> Result<(), Error>;

    fn decrypt<'a>(
        &self,
        input: &'a mut [u8],
        sequence_number: u32,
    ) -> IResult<&'a [u8], &'a [u8], ParsingError>;
}

#[derive(Clone)]
pub struct Chacha20Poly1305Impl {
    key: GenericArray<u8, cipher::consts::U32>,
    aad_key: GenericArray<u8, cipher::consts::U32>,
}

impl Cipher for Chacha20Poly1305Impl {
    fn block_size_bytes(&self) -> usize {
        64
    }

    fn encrypt(
        &self,
        cleartext_data: &mut [u8],
        sequence_number: u32,
        mut ciphered_data: &mut dyn Write,
    ) -> Result<(), Error> {
        // this is a cipher with authenticated encryptions, so we need to extract the packet length
        // beforehand
        let (_, size_field) =
            const_take::<4>(cleartext_data).map_err(|_| Error::EncryptionError)?;
        let pkt_size = self.get_pkt_size(size_field, sequence_number);
        cleartext_data[0..4].copy_from_slice(pkt_size.to_be_bytes().as_slice());

        // decrypt in place
        self.cipher_main_message(&mut cleartext_data[4..], sequence_number);

        let poly1305_tag = self.compute_poly1305_hash(cleartext_data, sequence_number);

        (cleartext_data as &[u8]).serialize(&mut ciphered_data)?;
        poly1305_tag.as_slice().serialize(&mut ciphered_data)?;

        Ok(())
    }

    fn decrypt<'a>(
        &self,
        input: &'a mut [u8],
        sequence_number: u32,
    ) -> IResult<&'a [u8], &'a [u8], ParsingError> {
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

        let (_, expected_tag) = take(poly1305::BLOCK_SIZE)(next_data)?;
        let real_tag =
            self.compute_poly1305_hash(&input[0..(pkt_size + 4) as usize], sequence_number);
        if bool::from(real_tag.ct_ne(expected_tag)) {
            return Err(nom::Err::Failure(ParsingError::InvalidMac));
        }

        // decrypt in place
        input[0..4].copy_from_slice(pkt_size.to_be_bytes().as_slice());
        self.cipher_main_message(&mut input[4..], sequence_number);

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
            <Iv<ChaCha20Legacy>>::from_slice(&sequence_number),
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
            <Iv<ChaCha20Legacy>>::from_slice(&sequence_number),
        );
        // skip the first block, that was used to derive the poly1305 key
        cipher.seek(Chacha20Poly1305::BLOCK_SIZE_BYTES);

        cipher.apply_keystream(bytes);
    }

    fn get_pkt_size(&self, encrypted_bytes: [u8; 4], sequence_number: u32) -> u32 {
        let sequence_number = (sequence_number as u64).to_be_bytes();
        let mut cipher = <ChaCha20Legacy as KeyIvInit>::new(
            &self.aad_key,
            <Iv<ChaCha20Legacy>>::from_slice(&sequence_number),
        );

        let mut block = [0; 64];
        for i in 0..4 {
            block[i] = encrypted_bytes[i];
        }
        cipher.apply_keystream(&mut block);

        u32::from_be_bytes([block[0], block[1], block[2], block[3]])
    }
}
