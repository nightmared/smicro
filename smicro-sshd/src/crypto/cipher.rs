#[cfg(feature = "rustcrypto")]
use chacha20::ChaCha20Legacy;
use cipher::BlockCipherEncrypt;
#[cfg(feature = "rustcrypto")]
use cipher::{Iv, KeyIvInit, StreamCipher, StreamCipherSeek};
#[cfg(feature = "rustcrypto")]
use elliptic_curve::subtle::ConstantTimeEq;
use hybrid_array::Array;
use nom::{bytes::streaming::take, IResult};
#[cfg(feature = "rustcrypto")]
use poly1305::Poly1305;
use universal_hash::KeyInit;

use smicro_macros::{create_wrapper_enum_implementing_trait, declare_crypto_arg};
use smicro_types::{
    error::ParsingError,
    ssh::deserialize::{const_take, streaming_const_take},
};

use crate::{crypto::CryptoAlg, error::Error, MAX_PKT_SIZE};

#[cfg(all(feature = "rustcrypto", feature = "ring"))]
compile_error!("Features 'rustcrypto' and 'ring' cannot be enabled at the same time");

const POLY1305_BLOCK_SIZE: usize = 16;

#[create_wrapper_enum_implementing_trait(name = CipherAllocatorWrapper, implementors = [Chacha20Poly1305, Aes256Ctr])]
pub trait CipherAllocator {
    fn key_size_bits(&self) -> usize;
    fn iv_size_bits(&self) -> usize;
    fn block_size_bits(&self) -> usize;

    fn from_key(&self, key: &[u8], raw_iv: &[u8]) -> Result<CipherWrapper, Error>;
}

#[declare_crypto_arg("chacha20-poly1305@openssh.com")]
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

    fn from_key(&self, raw_key: &[u8], _raw_iv: &[u8]) -> Result<CipherWrapper, Error> {
        #[cfg(feature = "rustcrypto")]
        {
            let key = Array::try_from(&raw_key[0..self.key_size_bits() / 8])?;
            let aad_key =
                Array::try_from(&raw_key[self.key_size_bits() / 8..2 * self.key_size_bits() / 8])?;

            Ok(CipherWrapper::Chacha20Poly1305Impl(Chacha20Poly1305Impl {
                key,
                aad_key,
            }))
        }

        #[cfg(feature = "ring")]
        {
            let mut fixed_raw_key = [0; 64];
            if raw_key.len() != 2 * Self::KEY_SIZE_BYTES {
                return Err(Error::InvalidPrivateKeyLength);
            }
            fixed_raw_key.copy_from_slice(raw_key);

            Ok(CipherWrapper::Chacha20Poly1305Impl(Chacha20Poly1305Impl {
                decrypt: ring::aead::chacha20_poly1305_openssh::OpeningKey::new(&fixed_raw_key),
                encrypt: ring::aead::chacha20_poly1305_openssh::SealingKey::new(&fixed_raw_key),
            }))
        }
    }
}

#[declare_crypto_arg("aes256-ctr")]
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
        let key = Array::try_from(&raw_key[0..Self::KEY_SIZE_BYTES])?;
        let ctr = Array::try_from(&raw_iv[0..Self::IV_SIZE_BYTES])?;

        Ok(CipherWrapper::Aes256CtrImpl(Aes256CtrImpl { key, ctr }))
    }
}

#[create_wrapper_enum_implementing_trait(name = CipherWrapper, implementors = [Chacha20Poly1305Impl, Aes256CtrImpl])]
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

#[cfg(feature = "rustcrypto")]
#[declare_crypto_arg("chacha20-poly1305@openssh.com")]
pub struct Chacha20Poly1305Impl {
    key: Array<u8, cipher::consts::U32>,
    aad_key: Array<u8, cipher::consts::U32>,
}

#[cfg(feature = "rustcrypto")]
impl Cipher for Chacha20Poly1305Impl {
    fn block_size_bytes(&self) -> usize {
        64
    }

    fn is_aead(&self) -> bool {
        true
    }

    fn required_space_to_encrypt(&self, data_len: usize) -> usize {
        // size of the data itself + the poly1305 tag size
        data_len + POLY1305_BLOCK_SIZE
    }

    fn encrypt(&mut self, data: &mut [u8], sequence_number: u32) -> Result<(), Error> {
        // this is a cipher with authenticated encryptions, so we need to extract the packet length
        // beforehand
        let (_, size_field) = const_take::<4>(data).map_err(|_| Error::EncryptionError)?;
        let pkt_size = self.get_pkt_size(size_field, sequence_number);
        data[0..4].copy_from_slice(pkt_size.to_be_bytes().as_slice());

        // encrypt in place
        let cleartext_data_end = data.len() - POLY1305_BLOCK_SIZE;
        self.cipher_main_message(&mut data[4..cleartext_data_end], sequence_number);

        let poly1305_tag = self.compute_poly1305_hash(&data[..cleartext_data_end], sequence_number);

        data[cleartext_data_end..].copy_from_slice(poly1305_tag.as_slice());

        Ok(())
    }

    fn decrypt<'a>(
        &mut self,
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

        let (_, expected_tag) = take(POLY1305_BLOCK_SIZE)(next_data)?;
        let real_tag =
            self.compute_poly1305_hash(&input[0..(pkt_size + 4) as usize], sequence_number);
        if bool::from(real_tag.ct_ne(expected_tag)) {
            return Err(nom::Err::Failure(ParsingError::InvalidMac));
        }

        // decrypt in place
        input[0..4].copy_from_slice(pkt_size.to_be_bytes().as_slice());
        self.cipher_main_message(&mut input[4..4 + pkt_size as usize], sequence_number);

        let next_data = &input[poly1305::BLOCK_SIZE + 4 + pkt_size as usize..];
        let cur_pkt_plaintext = &input[..4 + pkt_size as usize];

        Ok((next_data, cur_pkt_plaintext))
    }
}

#[cfg(feature = "rustcrypto")]
impl Chacha20Poly1305Impl {
    fn compute_poly1305_hash(&self, bytes: &[u8], sequence_number: u32) -> poly1305::Block {
        let sequence_number = (sequence_number as u64).to_be_bytes();
        let mut cipher = <ChaCha20Legacy as KeyIvInit>::new(
            &self.key,
            <&Iv<ChaCha20Legacy>>::from(&sequence_number),
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
            <&Iv<ChaCha20Legacy>>::from(&sequence_number),
        );
        // skip the first block, that was used to derive the poly1305 key
        cipher.seek(Chacha20Poly1305::BLOCK_SIZE_BYTES);

        cipher.apply_keystream(bytes);
    }

    fn get_pkt_size(&self, encrypted_bytes: [u8; 4], sequence_number: u32) -> u32 {
        let sequence_number = (sequence_number as u64).to_be_bytes();

        let mut block = [0; Chacha20Poly1305::BLOCK_SIZE_BYTES];
        for i in 0..4 {
            block[i] = encrypted_bytes[i];
        }

        let mut cipher = <ChaCha20Legacy as KeyIvInit>::new(
            &self.aad_key,
            <&Iv<ChaCha20Legacy>>::from(&sequence_number),
        );
        cipher.apply_keystream(&mut block);

        u32::from_be_bytes([block[0], block[1], block[2], block[3]])
    }
}

#[cfg(feature = "ring")]
#[declare_crypto_arg("chacha20-poly1305@openssh.com")]
pub struct Chacha20Poly1305Impl {
    // slight loss of space (we store the key twice instead of once), but that's only a waste of 64
    // bytes, which I can accept as a tradeoff for not having to redesign the API to separate the
    // sender and receiver side
    decrypt: ring::aead::chacha20_poly1305_openssh::OpeningKey,
    encrypt: ring::aead::chacha20_poly1305_openssh::SealingKey,
}

#[cfg(feature = "ring")]
impl Cipher for Chacha20Poly1305Impl {
    fn block_size_bytes(&self) -> usize {
        64
    }

    fn is_aead(&self) -> bool {
        true
    }

    fn required_space_to_encrypt(&self, data_len: usize) -> usize {
        data_len + POLY1305_BLOCK_SIZE
    }

    fn encrypt(&mut self, data: &mut [u8], sequence_number: u32) -> Result<(), Error> {
        let mut tmp_auth_block = [0; POLY1305_BLOCK_SIZE];
        let (plaintext, auth_block) = data.split_at_mut(data.len() - POLY1305_BLOCK_SIZE);
        self.encrypt
            .seal_in_place(sequence_number, plaintext, &mut tmp_auth_block);
        auth_block.copy_from_slice(&tmp_auth_block);

        Ok(())
    }

    fn decrypt<'a>(
        &mut self,
        input: &'a mut [u8],
        sequence_number: u32,
    ) -> IResult<&'a [u8], &'a [u8], ParsingError> {
        // this is a cipher with authenticated encryptions, so we need to extract the packet length
        // beforehand
        let (next_data, size_field) = streaming_const_take::<4>(input)?;
        let pkt_size_bytes = self
            .decrypt
            .decrypt_packet_length(sequence_number, size_field);
        let pkt_size = u32::from_be_bytes(pkt_size_bytes);
        // 5 = length field + 1 byte for the packet itself
        if pkt_size < 5 || pkt_size as usize > MAX_PKT_SIZE {
            return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
                pkt_size as usize,
            )));
        }
        // ensure there is enought data in the input slice
        let _ = take(pkt_size as usize + POLY1305_BLOCK_SIZE)(next_data)?;

        let auth_block_pos = pkt_size as usize + 4;
        let next_data_pos = auth_block_pos + POLY1305_BLOCK_SIZE;

        let mut auth_block = [0; POLY1305_BLOCK_SIZE];
        auth_block.copy_from_slice(&input[auth_block_pos..next_data_pos]);

        self.decrypt
            .open_in_place(sequence_number, &mut input[..auth_block_pos], &auth_block)
            .map_err(|_| nom::Err::Failure(ParsingError::DecipheringError))?;
        input[0..4].copy_from_slice(&pkt_size_bytes);

        Ok((&input[next_data_pos..], &input[..auth_block_pos]))
    }
}

#[declare_crypto_arg("aes256-ctr")]
pub struct Aes256CtrImpl {
    key: Array<u8, cipher::consts::U32>,
    ctr: Array<u8, cipher::consts::U16>,
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
