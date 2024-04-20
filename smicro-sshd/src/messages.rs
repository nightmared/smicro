use std::cmp::max;
use std::{io::Write, net::TcpStream, ops::Mul};

use chacha20::ChaCha20Legacy;
use cipher::generic_array::GenericArray;
use cipher::{Iv, KeyIvInit, StreamCipher, StreamCipherSeek};
use ecdsa::Signature;
use elliptic_curve::subtle::ConstantTimeEq;
use elliptic_curve::Scalar;
use elliptic_curve::{
    ecdh::{EphemeralSecret as EcEphemeralSecret, SharedSecret},
    point::AffineCoordinates,
    scalar::FromUintUnchecked,
    sec1::{EncodedPoint, FromEncodedPoint},
    AffinePoint, Curve, PublicKey as EcPublicKey,
};
use hmac::{Hmac, Mac};
use log::{debug, error, info};
use nom::IResult;
use nom::{bytes::streaming::take, number::complete::be_u32, AsBytes, Parser};
use p521::NistP521;
use poly1305::Poly1305;
use rand::Rng;
use sha2::{Digest, Sha512};
use signature::{Signer, Verifier};

use smicro_macros::{declare_crypto_algs_list, declare_deserializable_struct, gen_serialize_impl};
use smicro_types::error::ParsingError;
use smicro_types::sftp::deserialize::{parse_utf8_slice, parse_utf8_string};
use smicro_types::ssh::deserialize::streaming_const_take;
use smicro_types::ssh::types::PositiveBigNum;
use smicro_types::{
    deserialize::DeserializePacket,
    serialize::SerializePacket,
    sftp::deserialize::parse_slice,
    ssh::{
        deserialize::{const_take, parse_boolean, parse_name_list},
        types::{MessageType, NameList, SSHSlice, SharedSSHSlice},
    },
};

use crate::MAX_PKT_SIZE;
use crate::{
    error::{Error, KeyLoadingError},
    state::{CryptoAlgs, ICryptoAlgs, State},
    write_message, KexReplySent, SessionStates,
};

pub trait Message<'a>: Sized {
    fn get_message_type() -> MessageType;
}

pub trait CryptoAlg {
    fn new() -> Self;
}

pub trait KeyExchangeMethods {
    fn perform_key_exchange(
        &self,
        state: &mut State,
        stream: &mut TcpStream,
        ecdh_init: &MessageKexEcdhInit,
        my_kex_message: &MessageKeyExchangeInit,
        peer_kex_message: &MessageKeyExchangeInit,
    ) -> Result<SessionStates, Error>;
}

pub trait KeyExchangeAlgorithm: CryptoAlg + KeyExchangeMethods {
    const NAME: &'static str;
}

#[derive(Clone)]
pub struct EcdhSha2Nistp521 {}

impl CryptoAlg for EcdhSha2Nistp521 {
    fn new() -> Self {
        Self {}
    }
}

struct HashAdaptor<'a>(&'a mut dyn digest::DynDigest);

impl<'a> Write for HashAdaptor<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn compute_hash<C: elliptic_curve::Curve>(
    state: &State,
    hash: &mut dyn digest::DynDigest,
    k_server: &SSHSlice<u8>,
    q_server: &SSHSlice<u8>,
    shared_secret: &SharedSecret<C>,
    ecdh_init: &MessageKexEcdhInit,
    my_kex_message: &MessageKeyExchangeInit,
    peer_kex_message: &MessageKeyExchangeInit,
) -> Result<Vec<u8>, Error> {
    let mut hash = HashAdaptor(hash);

    // Hash the identification strings
    SharedSSHSlice(
        &state
            .peer_identifier_string
            .as_ref()
            .expect("The client identifier string should have been set by now"),
    )
    .serialize(&mut hash)?;
    state.my_identifier_string.serialize(&mut hash)?;

    // Hash the SSH_MSG_KEXINIT messages
    let mut serialize_kex_msg = |kex_msg: &MessageKeyExchangeInit| -> Result<(), Error> {
        let mut tmp_buf = Vec::new();
        kex_msg.serialize(&mut tmp_buf)?;

        ((tmp_buf.len() + 1) as u32).serialize(&mut hash)?;
        (&[MessageType::KexInit as u8] as &[u8]).serialize(&mut hash)?;
        tmp_buf.serialize(&mut hash)?;
        Ok(())
    };
    serialize_kex_msg(peer_kex_message)?;
    serialize_kex_msg(my_kex_message)?;

    // Hash our public host key
    k_server.serialize(&mut hash)?;

    // Hash the ephemeral public keys
    SharedSSHSlice(ecdh_init.Q_client).serialize(&mut hash)?;
    q_server.serialize(&mut hash)?;

    // Finally, hash the shared secret
    PositiveBigNum(shared_secret.raw_secret_bytes().as_bytes()).serialize(&mut hash)?;

    let mut result = vec![0; hash.0.output_size()];
    hash.0.finalize_into_reset(&mut result).unwrap();

    Ok(result)
}

fn derive_encryption_key<C: elliptic_curve::Curve>(
    hash: &mut dyn digest::DynDigest,
    shared_secret: &SharedSecret<C>,
    exchange_hash_digest: &[u8],
    char_index: u8,
    session_id: &[u8],
    needed_bits: usize,
) -> Result<Vec<u8>, Error> {
    let mut hash = HashAdaptor(hash);

    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut total_len_bits = 0;
    while total_len_bits < needed_bits {
        PositiveBigNum(shared_secret.raw_secret_bytes().as_slice()).serialize(&mut hash)?;
        exchange_hash_digest.serialize(&mut hash)?;
        if total_len_bits == 0 {
            hash.0.update(&[char_index]);
            session_id.serialize(&mut hash)?;
        } else {
            for key in &keys {
                hash.0.update(key);
            }
        }

        let mut key = vec![0; hash.0.output_size()];
        hash.0.finalize_into_reset(&mut key).unwrap();
        total_len_bits += key.len() * 8;
        keys.push(key);
    }

    let new_key_size = keys.len() * hash.0.output_size();
    let resulting_key = keys
        .into_iter()
        .fold(Vec::with_capacity(new_key_size), |mut acc, new| {
            acc.extend(&new);
            acc.truncate(needed_bits.div_ceil(8));
            acc
        });

    Ok(resulting_key)
}

impl KeyExchangeMethods for EcdhSha2Nistp521 {
    fn perform_key_exchange(
        &self,
        state: &mut State,
        stream: &mut TcpStream,
        ecdh_init: &MessageKexEcdhInit,
        my_kex_message: &MessageKeyExchangeInit,
        peer_kex_message: &MessageKeyExchangeInit,
    ) -> Result<SessionStates, Error> {
        let crypto_algs = state
            .crypto_algs
            .as_ref()
            .ok_or(Error::MissingCryptoAlgs)?
            .clone();

        // Compute the shared secret
        let peer_pubkey: EcPublicKey<p521::NistP521> =
            EcPublicKey::from_sec1_bytes(&ecdh_init.Q_client)?;

        // Elliptic Curve Public Key Validation Primitive (see https://www.secg.org/sec1-v2.pdf)
        // `from_sec1_bytes` checks for us that the point is not "at infinity" and that the
        // point lie on the curve

        // Ensure that the order of the curve is respected
        if peer_pubkey
            .as_affine()
            .mul(p521::Scalar::from_uint_unchecked(NistP521::ORDER))
            != p521::ProjectivePoint::IDENTITY
        {
            return Err(Error::InvalidPointForEcdh);
        }

        let my_secret = EcEphemeralSecret::random(&mut state.rng);
        let shared_secret = my_secret.diffie_hellman(&peer_pubkey);
        let my_pubkey = my_secret.public_key();

        // Retrieve the host key
        let match_host_key = || {
            for host_key in state.host_keys {
                if host_key.key_name() == crypto_algs.host_key_name() {
                    return Some(host_key);
                }
            }
            None
        };
        let matching_host_key =
            match_host_key().ok_or(Error::NoGoodHostKeyFound(crypto_algs.host_key_name()))?;
        let key_name = matching_host_key.key_name();

        // Print the server host key to a byte string
        let mut k_server = Vec::new();
        KeyEcdsa {
            name: key_name,
            curve_name: matching_host_key.curve_name(),
            key: PositiveBigNum(matching_host_key.public_sec1_part().as_bytes()),
        }
        .serialize(&mut k_server)?;
        let k_server = SSHSlice(k_server);

        let q_server = SSHSlice(my_pubkey.to_sec1_bytes().to_vec());

        let exchange_hash = compute_hash(
            state,
            &mut <Sha512 as Digest>::new(),
            &k_server,
            &q_server,
            &shared_secret,
            ecdh_init,
            my_kex_message,
            peer_kex_message,
        )?;

        let mut signature = Vec::new();
        matching_host_key.sign(exchange_hash.as_bytes(), &mut signature)?;

        let mut kex_signature = Vec::new();
        SignatureWithName {
            name: key_name,
            key: SharedSSHSlice(&signature),
        }
        .serialize(&mut kex_signature)?;
        let kex_signature = SSHSlice(kex_signature);

        let res = MessageKexEcdhReply {
            K_server: k_server,
            Q_server: q_server,
            signature: kex_signature,
        };

        write_message(state, stream, &res)?;

        let derive_key = |c: u8| -> Result<Vec<u8>, Error> {
            derive_encryption_key(
                &mut <Sha512 as Digest>::new(),
                &shared_secret,
                &exchange_hash,
                c,
                &exchange_hash,
                crypto_algs.key_max_length(),
            )
        };

        let iv_c2s = derive_key(b'A')?;
        let iv_s2c = derive_key(b'B')?;
        let encryption_key_c2s = derive_key(b'C')?;
        let encryption_key_s2c = derive_key(b'D')?;
        let integrity_key_c2s = derive_key(b'E')?;
        let integrity_key_s2c = derive_key(b'F')?;

        state.session_identifier = Some(exchange_hash);

        Ok(SessionStates::KexReplySent(KexReplySent {
            iv_c2s,
            iv_s2c,
            encryption_key_c2s,
            encryption_key_s2c,
            integrity_key_c2s,
            integrity_key_s2c,
        }))
    }
}

impl KeyExchangeAlgorithm for EcdhSha2Nistp521 {
    const NAME: &'static str = "ecdh-sha2-nistp521";
}

pub trait IKeySigningAlgorithm: CryptoAlg {
    const NAME: &'static str;
    const CURVE_NAME: &'static str;
    const KEY_SIZE_BITS: usize;
    const KEY_SIZE_BYTES: usize;

    type KeyType;

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn curve_name(&self) -> &'static str {
        Self::CURVE_NAME
    }

    fn deserialize_buf_to_key<'a>(
        &self,
        buf: &'a [u8],
    ) -> Result<(&'a [u8], Self::KeyType), KeyLoadingError>;

    fn signature_is_valid(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error>;
}

#[derive(Clone)]
pub struct EcdsaSha2Nistp521 {}

impl CryptoAlg for EcdsaSha2Nistp521 {
    fn new() -> Self {
        Self {}
    }
}

impl IKeySigningAlgorithm for EcdsaSha2Nistp521 {
    const NAME: &'static str = "ecdsa-sha2-nistp521";
    const CURVE_NAME: &'static str = "nistp521";
    const KEY_SIZE_BITS: usize = 521;
    const KEY_SIZE_BYTES: usize = 66;

    type KeyType = ecdsa::SigningKey<NistP521>;

    fn deserialize_buf_to_key<'a>(
        &self,
        buf: &'a [u8],
    ) -> Result<(&'a [u8], Self::KeyType), KeyLoadingError> {
        let (next_data, point_data) = parse_slice(buf)?;

        let encoded_point = <EncodedPoint<NistP521>>::from_bytes(point_data)
            .map_err(|_| KeyLoadingError::InvalidEncodedPoint)?;
        if encoded_point.is_identity() {
            return Err(KeyLoadingError::GotIdentityPoint);
        }
        let maybe_affine_point = <AffinePoint<NistP521>>::from_encoded_point(&encoded_point);
        let affine_point = <Option<AffinePoint<NistP521>>>::from(maybe_affine_point)
            .ok_or(KeyLoadingError::NotAnAffinePoint)?;

        let (next_data, secret_key_data) = parse_slice(next_data)?;
        let secret_key = p521::SecretKey::from_slice(secret_key_data)
            .map_err(|_| KeyLoadingError::NotASecretKey)?;

        let signing_key = Self::KeyType::from(&secret_key);

        // ensure the automatically-generated verifying key match the public key provided as input
        if signing_key.verifying_key().as_affine() != &affine_point {
            return Err(KeyLoadingError::VerifyingKeyMismatch);
        }

        Ok((next_data, signing_key))
    }

    fn signature_is_valid(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        let (_, key) = KeyEcdsa::deserialize(key)?;
        let signer = <ecdsa::VerifyingKey<NistP521>>::from_sec1_bytes(key.key.0)
            .map_err(|_| Error::InvalidPublicKey)?;

        let (_, sig) = SignatureWithName::deserialize(signature)?;
        let (_, raw_ecdsa_sig) = EcdsaSignature::deserialize(sig.key.0)?;

        let expand_bignum =
            |bignum: PositiveBigNum| -> Result<p521::Scalar, elliptic_curve::Error> {
                let mut out = [0; 66];

                let slice = if bignum.0.len() < 66 {
                    out[66 - bignum.0.len()..].copy_from_slice(bignum.0);
                    &out
                } else {
                    bignum.0
                };

                p521::Scalar::from_slice(slice)
            };

        let r = expand_bignum(raw_ecdsa_sig.r)?;
        let s = expand_bignum(raw_ecdsa_sig.s)?;

        let ecdsa_sig = <ecdsa::Signature<NistP521>>::from_scalars(&r, &s)
            .map_err(|_| Error::InvalidSignature)?;

        println!("{:?}", signer.verify(message, &ecdsa_sig));
        Ok(signer.verify(message, &ecdsa_sig).is_ok())
    }
}

pub trait ISigningKey {
    fn key_name(&self) -> &'static str;
    fn curve_name(&self) -> &'static str;

    fn integer_size_bytes(&self) -> usize;

    fn sign(&self, data_to_sign: &[u8], output: &mut dyn Write) -> Result<(), Error>;

    fn public_sec1_part(&self) -> Vec<u8>;

    fn public_key_x(&self) -> Vec<u8>;
}

impl ISigningKey for <EcdsaSha2Nistp521 as IKeySigningAlgorithm>::KeyType {
    fn key_name(&self) -> &'static str {
        EcdsaSha2Nistp521::NAME
    }

    fn curve_name(&self) -> &'static str {
        EcdsaSha2Nistp521::CURVE_NAME
    }

    fn integer_size_bytes(&self) -> usize {
        EcdsaSha2Nistp521::KEY_SIZE_BYTES
    }

    fn sign(&self, data_to_sign: &[u8], mut output: &mut dyn Write) -> Result<(), Error> {
        let data = (self as &dyn Signer<Signature<NistP521>>)
            .try_sign(data_to_sign)
            .map_err(|_| Error::SigningError)?
            .to_bytes();

        let r = PositiveBigNum(&data[0..self.integer_size_bytes()]);
        let s = PositiveBigNum(&data[self.integer_size_bytes()..]);

        EcdsaSignature { r, s }.serialize(&mut output)?;

        Ok(())
    }

    fn public_sec1_part(&self) -> Vec<u8> {
        self.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    fn public_key_x(&self) -> Vec<u8> {
        self.verifying_key().as_affine().x().to_vec()
    }
}

pub trait CipherAlgorithm: CryptoAlg + DynCipherAlgorithm {
    const NAME: &'static str;
}

pub trait DynCipherAlgorithm {
    fn name(&self) -> &'static str;
    fn key_size_bits(&self) -> usize;
    fn iv_size_bits(&self) -> usize;
    fn block_size_bits(&self) -> usize;

    fn from_key(&self, key: &[u8]) -> Result<Box<dyn DynCipher>, Error>;
}

#[derive(Clone)]
pub struct Chacha20Poly1305 {}

impl CryptoAlg for Chacha20Poly1305 {
    fn new() -> Self {
        Self {}
    }
}

impl CipherAlgorithm for Chacha20Poly1305 {
    const NAME: &'static str = "chacha20-poly1305@openssh.com";
}

impl Chacha20Poly1305 {
    const KEY_SIZE_BYTES: usize = 32;
    const IV_SIZE_BYTES: usize = 8;
    const BLOCK_SIZE_BYTES: usize = 64;
}

impl DynCipherAlgorithm for Chacha20Poly1305 {
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

    fn from_key(&self, raw_key: &[u8]) -> Result<Box<dyn DynCipher>, Error> {
        let key = GenericArray::from_slice(&raw_key[0..self.key_size_bits() / 8]).clone();
        let aad_key = GenericArray::from_slice(
            &raw_key[self.key_size_bits() / 8..2 * self.key_size_bits() / 8],
        )
        .clone();

        Ok(Box::new(Chacha20Poly1305Impl { key, aad_key }))
    }
}

pub trait DynCipher {
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

impl DynCipher for Chacha20Poly1305Impl {
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

pub trait MACAlgorithm: CryptoAlg + DynMACAlgorithm {
    const NAME: &'static str;
}

pub trait DynMACAlgorithm {
    fn name(&self) -> &'static str;
    fn key_size_bites(&self) -> usize;

    fn allocate_with_key(&self, key: &[u8]) -> Box<dyn DynMAC>;
}

#[derive(Clone)]
struct HmacSha2512 {}

impl CryptoAlg for HmacSha2512 {
    fn new() -> Self {
        Self {}
    }
}

impl MACAlgorithm for HmacSha2512 {
    const NAME: &'static str = "hmac-sha2-512";
}

impl DynMACAlgorithm for HmacSha2512 {
    fn name(&self) -> &'static str {
        HmacSha2512::NAME
    }

    fn key_size_bites(&self) -> usize {
        512
    }

    fn allocate_with_key(&self, key: &[u8]) -> Box<dyn DynMAC> {
        Box::new(HmacSha2512Key { key: key.to_vec() })
    }
}

pub trait DynMAC {
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

impl DynMAC for HmacSha2512Key {
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
        if expected_mac != final_mac.into_bytes().as_bytes() {
            return Err(Error::InvalidMAC);
        }

        Ok(())
    }
}

pub fn gen_kex_initial_list(state: &mut State) -> MessageKeyExchangeInit {
    let cookie: [u8; 16] = state.rng.gen();

    // suboptimal, but only done once per session opening, so let's ignore it for now
    let kex_algorithms = NameList {
        entries: KEX_ALGORITHMS_NAMES.iter().map(|x| x.to_string()).collect(),
    };

    let server_host_key_algorithms = NameList {
        entries: HOST_KEY_ALGORITHMS_NAMES
            .iter()
            .map(|x| x.to_string())
            .collect(),
    };

    let encryption_algorithms_client_to_server = NameList {
        entries: CIPHER_ALGORITHMS_NAMES
            .iter()
            .map(|x| x.to_string())
            .collect(),
    };
    let encryption_algorithms_server_to_client = encryption_algorithms_client_to_server.clone();

    let mac_algorithms_client_to_server = NameList {
        entries: MAC_ALGORITHMS_NAMES.iter().map(|x| x.to_string()).collect(),
    };
    let mac_algorithms_server_to_client = mac_algorithms_client_to_server.clone();

    let compression_algorithms_client_to_server = NameList {
        entries: vec![String::from("none")],
    };
    let compression_algorithms_server_to_client = compression_algorithms_client_to_server.clone();

    let languages_client_to_server = NameList {
        entries: Vec::new(),
    };
    let languages_server_to_client = languages_client_to_server.clone();

    MessageKeyExchangeInit {
        cookie,
        kex_algorithms,
        server_host_key_algorithms,
        encryption_algorithms_server_to_client,
        encryption_algorithms_client_to_server,
        mac_algorithms_client_to_server,
        mac_algorithms_server_to_client,
        compression_algorithms_client_to_server,
        compression_algorithms_server_to_client,
        languages_client_to_server,
        languages_server_to_client,
        first_kex_packet_follows: false,
        reserved: 0,
    }
}

#[gen_serialize_impl]
#[declare_deserializable_struct]
#[derive(Clone)]
pub struct MessageKeyExchangeInit {
    #[field(parser = const_take::<16>)]
    cookie: [u8; 16],
    #[field(parser = parse_name_list)]
    kex_algorithms: NameList,
    #[field(parser = parse_name_list)]
    server_host_key_algorithms: NameList,
    #[field(parser = parse_name_list)]
    encryption_algorithms_client_to_server: NameList,
    #[field(parser = parse_name_list)]
    encryption_algorithms_server_to_client: NameList,
    #[field(parser = parse_name_list)]
    mac_algorithms_client_to_server: NameList,
    #[field(parser = parse_name_list)]
    mac_algorithms_server_to_client: NameList,
    #[field(parser = parse_name_list)]
    compression_algorithms_client_to_server: NameList,
    #[field(parser = parse_name_list)]
    compression_algorithms_server_to_client: NameList,
    #[field(parser = parse_name_list)]
    languages_client_to_server: NameList,
    #[field(parser = parse_name_list)]
    languages_server_to_client: NameList,
    #[field(parser = parse_boolean)]
    first_kex_packet_follows: bool,
    #[field(parser = be_u32)]
    reserved: u32,
}

#[declare_crypto_algs_list]
const HOST_KEY_ALGORITHMS: IKeySigningAlgorithm = [EcdsaSha2Nistp521];

#[declare_crypto_algs_list]
const KEX_ALGORITHMS: IKeyExchangeAlgorithm = [EcdhSha2Nistp521, EcdhSha2Nistp521];

// TODO: add aes256-gcm@openssh.com
#[declare_crypto_algs_list]
const CIPHER_ALGORITHMS: ICipherAlgorithm = [Chacha20Poly1305];

#[declare_crypto_algs_list]
pub const MAC_ALGORITHMS: IMACAlgorithm = [HmacSha2512];

impl MessageKeyExchangeInit {
    pub fn compute_crypto_algs(&self) -> Result<Box<dyn ICryptoAlgs>, Error> {
        if self.first_kex_packet_follows {
            error!("first_kex_packet_follows is not supported");
            return Err(Error::Unsupported);
        }

        let kex = negotiate_alg_kex_algorithms!(self.kex_algorithms.entries, Error::NoCommonKexAlg);
        let host_key_alg = negotiate_alg_host_key_algorithms!(
            self.server_host_key_algorithms.entries,
            Error::NoCommonHostKeyAlg
        );
        let client_to_server_cipher = negotiate_alg_cipher_algorithms!(
            self.encryption_algorithms_client_to_server.entries,
            Error::NoCommonCipher
        );
        let server_to_client_cipher = negotiate_alg_cipher_algorithms!(
            self.encryption_algorithms_server_to_client.entries,
            Error::NoCommonCipher
        );
        let client_to_server_mac = negotiate_alg_mac_algorithms!(
            self.mac_algorithms_client_to_server.entries,
            Error::NoCommonMAC
        );
        let server_to_client_mac = negotiate_alg_mac_algorithms!(
            self.mac_algorithms_server_to_client.entries,
            Error::NoCommonMAC
        );

        let cipher_max_length = |cipher: &dyn DynCipherAlgorithm| -> usize {
            max(
                cipher.iv_size_bits(),
                max(cipher.block_size_bits(), cipher.key_size_bits()),
            )
        };
        let key_max_length = max(
            max(
                client_to_server_mac.key_size_bites(),
                cipher_max_length(&client_to_server_cipher),
            ),
            max(
                server_to_client_mac.key_size_bites(),
                cipher_max_length(&server_to_client_cipher),
            ),
        );

        let crypto_algs = CryptoAlgs {
            kex,
            host_key_alg,
            client_to_server_cipher,
            server_to_client_cipher,
            client_to_server_mac,
            server_to_client_mac,
            key_max_length,
        };

        debug!("Cryptographic parameters negotiated: {:?}", crypto_algs);

        Ok(Box::new(crypto_algs))
    }
}

impl<'a> Message<'a> for MessageKeyExchangeInit {
    fn get_message_type() -> MessageType {
        MessageType::KexInit
    }
}

#[gen_serialize_impl]
#[declare_deserializable_struct]
pub struct MessageKexEcdhInit<'a> {
    #[field(parser = parse_slice)]
    Q_client: &'a [u8],
}

impl<'a> Message<'a> for MessageKexEcdhInit<'a> {
    fn get_message_type() -> MessageType {
        MessageType::KexEcdhInit
    }
}

#[gen_serialize_impl]
#[declare_deserializable_struct]
pub struct KeyEcdsa<'a> {
    #[field(parser = parse_utf8_slice)]
    name: &'a str,
    #[field(parser = parse_utf8_slice)]
    curve_name: &'a str,
    #[field(parser = parse_slice.map(|x| PositiveBigNum(x)))]
    key: PositiveBigNum<'a>,
}

#[gen_serialize_impl]
#[declare_deserializable_struct]
pub struct SignatureWithName<'a> {
    #[field(parser = parse_utf8_slice)]
    name: &'a str,
    #[field(parser = parse_slice.map(SharedSSHSlice))]
    key: SharedSSHSlice<'a, u8>,
}

#[gen_serialize_impl]
pub struct MessageKexEcdhReply {
    K_server: SSHSlice<u8>,
    Q_server: SSHSlice<u8>,
    signature: SSHSlice<u8>,
}

impl<'a> Message<'_> for MessageKexEcdhReply {
    fn get_message_type() -> MessageType {
        MessageType::KexEcdhReply
    }
}

#[gen_serialize_impl]
#[declare_deserializable_struct]
pub struct MessageNewKeys {}

impl<'a> Message<'a> for MessageNewKeys {
    fn get_message_type() -> MessageType {
        MessageType::NewKeys
    }
}

#[declare_deserializable_struct]
pub struct MessageServiceRequest<'a> {
    #[field(parser = parse_utf8_slice)]
    service_name: &'a str,
}

#[gen_serialize_impl]
pub struct MessageServiceAccept<'a> {
    pub service_name: &'a str,
}

impl<'a> Message<'a> for MessageServiceAccept<'a> {
    fn get_message_type() -> MessageType {
        MessageType::ServiceAccept
    }
}

#[repr(u32)]
#[derive(Copy, Clone)]
pub enum DisconnectReason {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    ServiceNotAvailable = 7,
}

impl SerializePacket for DisconnectReason {
    fn get_size(&self) -> usize {
        (*self as u32).get_size()
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        (*self as u32).serialize(output)
    }
}

#[gen_serialize_impl]
pub struct MessageDisconnect<'a> {
    reason: DisconnectReason,
    description: &'a str,
    language: &'a str,
}

impl<'a> Message<'a> for MessageDisconnect<'a> {
    fn get_message_type() -> MessageType {
        MessageType::Disconnect
    }
}

impl<'a> MessageDisconnect<'a> {
    pub fn new(reason: DisconnectReason) -> MessageDisconnect<'static> {
        MessageDisconnect {
            reason,
            description: "",
            language: "",
        }
    }
}

#[gen_serialize_impl]
pub struct MessageUnimplemented {
    pub sequence_number: u32,
}

impl<'a> Message<'a> for MessageUnimplemented {
    fn get_message_type() -> MessageType {
        MessageType::Unimplemented
    }
}

#[declare_deserializable_struct]
pub struct MessageUserAuthRequest<'a> {
    #[field(parser = parse_utf8_slice)]
    pub user_name: &'a str,
    #[field(parser = parse_utf8_slice)]
    pub service_name: &'a str,
    #[field(parser = parse_utf8_slice)]
    pub method_name: &'a str,
    #[field(parser = nom::combinator::rest)]
    pub method_data: &'a [u8],
}

#[gen_serialize_impl]
pub struct MessageUserAuthFailure {
    pub allowed_auth_methods: NameList,
    pub partial_success: bool,
}

impl<'a> Message<'a> for MessageUserAuthFailure {
    fn get_message_type() -> MessageType {
        MessageType::UserAuthFailure
    }
}

#[gen_serialize_impl]
pub struct MessageUserAuthSuccess {}

impl<'a> Message<'a> for MessageUserAuthSuccess {
    fn get_message_type() -> MessageType {
        MessageType::UserAuthSuccess
    }
}

#[declare_deserializable_struct]
pub struct UserAuthPublickey<'a> {
    #[field(parser = parse_boolean)]
    pub with_signature: bool,
    #[field(parser = parse_utf8_slice)]
    pub public_key_alg_name: &'a str,
    #[field(parser = parse_slice)]
    pub public_key_blob: &'a [u8],
    #[field(parser = parse_slice, optional = true)]
    pub signature: &'a [u8],
}

#[gen_serialize_impl]
pub struct MessageUserAuthPublicKeyOk<'a> {
    pub public_key_alg_name: &'a str,
    pub public_key_blob: SharedSSHSlice<'a, u8>,
}

impl<'a> Message<'a> for MessageUserAuthPublicKeyOk<'a> {
    fn get_message_type() -> MessageType {
        MessageType::UserAuthPublickKeyOk
    }
}

#[gen_serialize_impl]
#[declare_deserializable_struct]
struct EcdsaSignature<'a> {
    #[field(parser = parse_slice.map(PositiveBigNum))]
    r: PositiveBigNum<'a>,
    #[field(parser = parse_slice.map(PositiveBigNum))]
    s: PositiveBigNum<'a>,
}
