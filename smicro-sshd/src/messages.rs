use std::{io::Write, marker::PhantomData, net::TcpStream};

use ecdsa::{Signature, SignatureSize, SignatureWithOid};
use elliptic_curve::{
    ecdh::EphemeralSecret as EcEphemeralSecret,
    group::UncompressedEncoding,
    point::AffineCoordinates,
    sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint},
    subtle::CtOption,
    AffinePoint, PublicKey as EcPublicKey, ScalarPrimitive, SecretKey as EcSecretKey,
};
use log::{debug, error, info};
use nom::{combinator::rest, number::complete::be_u32, AsBytes, HexDisplay, Parser};
use p521::NistP521;
use rand::Rng;
use sha2::{Digest, Sha512};
use signature::Signer;

use smicro_macros::{declare_crypto_algs_list, declare_deserializable_struct, gen_serialize_impl};
use smicro_types::{
    deserialize::DeserializePacket,
    serialize::SerializePacket,
    sftp::deserialize::parse_slice,
    ssh::{
        deserialize::{const_take, parse_boolean, parse_message_type, parse_name_list},
        types::{MessageType, NameList, SSHSlice, SharedSSHSlice},
    },
};

use crate::{
    error::{Error, KeyLoadingError},
    state::{CryptoAlgs, ICryptoAlgs, State},
    write_message, KexReceived, KexReplySent, SessionStates,
};

pub trait Message<'a>: Sized {
    fn get_message_type() -> MessageType;
}

pub trait CryptoAlg {
    fn new() -> Self;
}

pub trait IKeyExchangeMethods {
    fn perform_key_exchange(
        &self,
        state: &mut State,
        stream: &mut TcpStream,
        ecdh_init: &MessageKexEcdhInit,
        my_kex_message: &MessageKeyExchangeInit,
        peer_kex_message: &MessageKeyExchangeInit,
    ) -> Result<SessionStates, Error>;
}

pub trait IKeyExchangeAlgorithm: CryptoAlg + IKeyExchangeMethods {
    const NAME: &'static str;
}

#[derive(Clone)]
pub struct EcdhSha2Nistp521 {}

impl CryptoAlg for EcdhSha2Nistp521 {
    fn new() -> Self {
        Self {}
    }
}

impl IKeyExchangeMethods for EcdhSha2Nistp521 {
    fn perform_key_exchange(
        &self,
        state: &mut State,
        stream: &mut TcpStream,
        ecdh_init: &MessageKexEcdhInit,
        my_kex_message: &MessageKeyExchangeInit,
        peer_kex_message: &MessageKeyExchangeInit,
    ) -> Result<SessionStates, Error> {
        // Compute the shared secret
        let peer_pubkey: EcPublicKey<p521::NistP521> =
            EcPublicKey::from_sec1_bytes(&ecdh_init.Q_client)?;
        // TODO: ensure the public key is valid
        let my_secret = EcEphemeralSecret::random(&mut state.rng);
        let shared_secret = my_secret.diffie_hellman(&peer_pubkey);
        let my_pubkey = my_secret.public_key();

        // Retrieve the host key
        // TODO: find the matching key algorithm
        let matching_host_key = &state.host_keys[0];
        let key_name = matching_host_key.get_key_name();

        // Print the server host key to a byte string
        let mut k_server = Vec::new();
        KexHostKeyEcdsa {
            name: key_name,
            curve_name: "nistp521",
            key: SharedSSHSlice(matching_host_key.public_sec1_part().as_bytes()),
        }
        .serialize(&mut k_server)?;
        let k_server = SSHSlice(k_server);
        debug!("K_server={:?}", k_server);

        let q_server = SSHSlice(my_pubkey.to_sec1_bytes().to_vec());

        let mut hash = Vec::new();

        // Hash the identification strings
        SharedSSHSlice(
            &state
                .peer_identifier_string
                .as_ref()
                .expect("The client identifier string should have been set by now"),
        )
        .serialize(&mut hash)?;
        debug!("peer_identifier_string={:?}", state.peer_identifier_string);
        state.my_identifier_string.serialize(&mut hash)?;
        debug!("my_identifier_string={:?}", state.my_identifier_string);

        // Hash the SSH_MSG_KEXINIT messages
        let mut serialize_kex_msg = |kex_msg: &MessageKeyExchangeInit| -> Result<(), Error> {
            let mut tmp_buf = Vec::new();
            kex_msg.serialize(&mut tmp_buf)?;

            debug!("len={}, Kex_msg={:?}", tmp_buf.len(), tmp_buf);

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
        debug!("q_client={:?}", ecdh_init.Q_client);
        debug!("q_server={:?}", q_server);
        SharedSSHSlice(ecdh_init.Q_client).serialize(&mut hash)?;
        q_server.serialize(&mut hash)?;

        // Finally, hash the shared secret
        SharedSSHSlice(shared_secret.raw_secret_bytes().as_bytes()).serialize(&mut hash)?;

        debug!("full_hash={:x?}", hash);

        let mut real_hash = Sha512::new();
        real_hash.update(&hash);
        let exchange_hash = real_hash.finalize();

        debug!("key_name={:?}", key_name);
        debug!(
            "len(hash)={}, hash={:?}",
            exchange_hash.len(),
            exchange_hash
        );

        let mut signature = Vec::new();
        matching_host_key.sign(exchange_hash.as_bytes(), &mut signature)?;

        debug!("signature={:?}", signature);

        let mut kex_signature = Vec::new();
        KeyWithName {
            name: key_name,
            key: SharedSSHSlice(&signature),
        }
        .serialize(&mut kex_signature)?;
        let kex_signature = SSHSlice(kex_signature);
        debug!("kex_signature={:?}", kex_signature);

        let res = MessageKexEcdhReply {
            K_server: k_server,
            Q_server: q_server,
            signature: kex_signature,
        };

        let mut out = Vec::new();
        write_message(state, &mut out, &res)?;
        println!("{:?}", out);

        write_message(state, stream, &res)?;

        Ok(SessionStates::KexReplySent(KexReplySent {}))
    }
}

impl IKeyExchangeAlgorithm for EcdhSha2Nistp521 {
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
}

pub trait ISigningKey {
    fn get_key_name(&self) -> &'static str;

    fn integer_size_bytes(&self) -> usize;

    fn sign(&self, data_to_sign: &[u8], output: &mut dyn Write) -> Result<(), Error>;

    fn public_sec1_part(&self) -> Vec<u8>;

    fn public_key_x(&self) -> Vec<u8>;
}

impl ISigningKey for <EcdsaSha2Nistp521 as IKeySigningAlgorithm>::KeyType {
    fn get_key_name(&self) -> &'static str {
        EcdsaSha2Nistp521::NAME
    }

    fn integer_size_bytes(&self) -> usize {
        EcdsaSha2Nistp521::KEY_SIZE_BYTES
    }

    fn sign(&self, data_to_sign: &[u8], mut output: &mut dyn Write) -> Result<(), Error> {
        let data = (self as &dyn Signer<Signature<NistP521>>)
            .try_sign(data_to_sign)
            .map_err(|_| Error::SigningError)?
            .to_bytes();

        //((12 + 2 * self.integer_size_bytes()) as u32).serialize(&mut output)?;
        (self.integer_size_bytes() as u32).serialize(&mut output)?;
        data[0..self.integer_size_bytes()]
            .as_ref()
            .serialize(&mut output)?;
        (self.integer_size_bytes() as u32).serialize(&mut output)?;
        data[self.integer_size_bytes()..]
            .as_ref()
            .serialize(output)?;

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

pub trait ICipherAlgorithm: CryptoAlg {
    const NAME: &'static str;
    const BLOCK_SIZE_BITS: usize;

    type KeyType;
}

#[derive(Clone)]
pub struct Chacha20Poly1305 {}

impl CryptoAlg for Chacha20Poly1305 {
    fn new() -> Self {
        Self {}
    }
}

impl ICipherAlgorithm for Chacha20Poly1305 {
    const NAME: &'static str = "chacha20-poly1305@openssh.com";
    const BLOCK_SIZE_BITS: usize = 256;

    type KeyType = [u8; Self::BLOCK_SIZE_BITS / 8];
}

pub trait IMACAlgorithm: CryptoAlg {
    const NAME: &'static str;
}

#[derive(Clone)]
struct HmacSha2512 {}

impl CryptoAlg for HmacSha2512 {
    fn new() -> Self {
        Self {}
    }
}

impl IMACAlgorithm for HmacSha2512 {
    const NAME: &'static str = "hmac-sha2-512";
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

        let crypto_algs = CryptoAlgs::new(
            kex,
            host_key_alg,
            client_to_server_cipher,
            server_to_client_cipher,
            client_to_server_mac,
            server_to_client_mac,
        );

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
pub struct KexHostKeyEcdsa<'a> {
    name: &'a str,
    curve_name: &'a str,
    key: SharedSSHSlice<'a, u8>,
}

#[gen_serialize_impl]
pub struct KeyWithName<'a> {
    name: &'a str,
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
