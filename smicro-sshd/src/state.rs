use std::{
    collections::HashMap, fmt::Debug, fs::File, io::Read, num::Wrapping, path::Path, sync::Arc,
};

use base64::engine::{general_purpose::STANDARD, Engine as _};
use log::info;
use nom::{
    bytes::complete::{tag, take_till1},
    character::complete::line_ending,
    combinator::{peek, rest},
    multi::many_till,
    number::complete::be_u32,
    sequence::{delimited, preceded, terminated},
    Parser,
};
use rand::{rngs::ThreadRng, thread_rng};
use smicro_macros::declare_deserializable_struct;
use smicro_types::sftp::deserialize::{parse_slice, parse_utf8_string};

use crate::{
    error::KeyLoadingError,
    messages::{
        negotiate_alg_host_key_algorithms, CipherAlgorithm, CryptoAlg, DynCipher,
        DynCipherAlgorithm, DynMAC, DynMACAlgorithm, IKeySigningAlgorithm, ISigningKey,
        KeyExchangeAlgorithm, KeyExchangeMethods, MACAlgorithm,
    },
    DeserializePacket,
};

pub trait ICryptoAlgs: Debug {
    fn kex(&self) -> &dyn KeyExchangeMethods;

    fn host_key_name(&self) -> &'static str;

    fn key_max_length(&self) -> usize;

    fn client_cipher(&self) -> &dyn DynCipherAlgorithm;

    fn server_cipher(&self) -> &dyn DynCipherAlgorithm;

    fn client_mac(&self) -> &dyn DynMACAlgorithm;

    fn server_mac(&self) -> &dyn DynMACAlgorithm;
}

pub struct CryptoAlgs<
    Kex: KeyExchangeAlgorithm,
    HostKey: IKeySigningAlgorithm,
    C2SCipher: CipherAlgorithm,
    S2CCipher: CipherAlgorithm,
    C2SMac: MACAlgorithm,
    S2CMac: MACAlgorithm,
> {
    pub kex: Kex,
    pub host_key_alg: HostKey,
    pub client_to_server_cipher: C2SCipher,
    pub server_to_client_cipher: S2CCipher,
    pub client_to_server_mac: C2SMac,
    pub server_to_client_mac: S2CMac,
    pub key_max_length: usize,
}

impl<
        Kex: KeyExchangeAlgorithm,
        HostKey: IKeySigningAlgorithm,
        C2SCipher: CipherAlgorithm,
        S2CCipher: CipherAlgorithm,
        C2SMac: MACAlgorithm,
        S2CMac: MACAlgorithm,
    > ICryptoAlgs for CryptoAlgs<Kex, HostKey, C2SCipher, S2CCipher, C2SMac, S2CMac>
{
    fn kex(&self) -> &dyn KeyExchangeMethods {
        &self.kex
    }

    fn host_key_name(&self) -> &'static str {
        self.host_key_alg.name()
    }

    fn key_max_length(&self) -> usize {
        self.key_max_length
    }

    fn client_cipher(&self) -> &dyn DynCipherAlgorithm {
        &self.client_to_server_cipher
    }

    fn server_cipher(&self) -> &dyn DynCipherAlgorithm {
        &self.server_to_client_cipher
    }

    fn client_mac(&self) -> &dyn DynMACAlgorithm {
        &self.client_to_server_mac
    }

    fn server_mac(&self) -> &dyn DynMACAlgorithm {
        &self.server_to_client_mac
    }
}

impl<
        Kex: KeyExchangeAlgorithm,
        HostKey: IKeySigningAlgorithm,
        C2SCipher: CipherAlgorithm,
        S2CCipher: CipherAlgorithm,
        C2SMac: MACAlgorithm,
        S2CMac: MACAlgorithm,
    > Debug for CryptoAlgs<Kex, HostKey, C2SCipher, S2CCipher, C2SMac, S2CMac>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoAlgs")
            .field("kex", &Kex::NAME)
            .field("host_key_alg", &HostKey::NAME)
            .field("client_to_server_cipher", &C2SCipher::NAME)
            .field("client_to_server_mac", &C2SMac::NAME)
            .field("server_to_client_cipher", &S2CCipher::NAME)
            .field("server_to_client_mac", &S2CMac::NAME)
            .finish()
    }
}

#[declare_deserializable_struct]
pub struct OpenSSHKeySerialized<'a> {
    #[field(parser = parse_utf8_string)]
    ciphername: String,
    #[field(parser = parse_utf8_string)]
    kdfname: String,
    #[field(parser = parse_slice)]
    kdfoptions: &'a [u8],
    #[field(parser = be_u32)]
    key_number: u32,
    #[field(parser = rest)]
    key_data: &'a [u8],
}

pub struct Channel {
    pub window_size: u32,
    pub max_pkt_size: u32,
    pub remote_channel_number: u32,
}

pub struct State<'a> {
    pub rng: ThreadRng,
    pub host_keys: &'a [&'a dyn ISigningKey],
    pub my_identifier_string: &'static str,
    pub peer_identifier_string: Option<Vec<u8>>,
    pub crypto_algs: Option<Arc<Box<dyn ICryptoAlgs>>>,
    pub crypto_material: Option<SessionCryptoMaterials>,
    pub session_identifier: Option<Vec<u8>>,
    pub authentified_user: Option<String>,
    pub channels: HashMap<u32, Channel>,
    pub num_channels: u32,
    pub sequence_number_c2s: Wrapping<u32>,
    pub sequence_number_s2c: Wrapping<u32>,
}

pub struct SessionCryptoMaterials {
    pub client_mac: Box<dyn DynMAC>,
    pub server_mac: Box<dyn DynMAC>,
    pub client_cipher: Box<dyn DynCipher>,
    pub server_cipher: Box<dyn DynCipher>,
}

impl std::fmt::Debug for SessionCryptoMaterials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionCryptoMaterials { <REDACTED> }")
    }
}

impl<'a> State<'a> {
    pub fn new(host_keys: &'a [&'a dyn ISigningKey]) -> Self {
        Self {
            rng: thread_rng(),
            host_keys,
            my_identifier_string: "SSH-2.0-smicro_ssh",
            peer_identifier_string: None,
            crypto_algs: None,
            crypto_material: None,
            session_identifier: None,
            authentified_user: None,
            channels: HashMap::new(),
            num_channels: 0,
            sequence_number_c2s: Wrapping(0),
            sequence_number_s2c: Wrapping(0),
        }
    }

    pub fn load_hostkey(hostkey_file: &Path) -> Result<Box<dyn ISigningKey>, KeyLoadingError> {
        let mut f = File::open(hostkey_file)?;
        let mut file_content = Vec::with_capacity(4096);
        f.read_to_end(&mut file_content)?;

        let mut key_parser = delimited(
            tag("-----BEGIN OPENSSH PRIVATE KEY-----\n"),
            many_till(
                terminated(take_till1(|c| c == b'\n' || c == b'\r'), line_ending),
                peek(tag(b"-")),
            )
            .map(|(delimited_list, _)| delimited_list),
            tag("-----END OPENSSH PRIVATE KEY-----"),
        )
        .map(|v| {
            let mut res = Vec::with_capacity(file_content.len());
            for substr in v {
                res.extend_from_slice(substr);
            }
            res
        });

        let key_base64encoded = key_parser.parse(file_content.as_slice())?.1;
        let key_openssh_raw = STANDARD.decode(key_base64encoded)?;

        let key_openssh_raw_data =
            preceded(tag("openssh-key-v1\0"), rest)(key_openssh_raw.as_slice())?.1;

        let key_openssh_raw_serialized = OpenSSHKeySerialized::deserialize(key_openssh_raw_data)?.1;

        let nb_keys = key_openssh_raw_serialized.key_number as usize;

        if nb_keys != 1 {
            return Err(KeyLoadingError::InvalidNumberOfKeys);
        }

        if key_openssh_raw_serialized.kdfname != "none"
            || key_openssh_raw_serialized.ciphername != "none"
            || key_openssh_raw_serialized.kdfoptions != []
        {
            return Err(KeyLoadingError::PassphraseProtectedKeyUnsupported);
        }

        let next_data = key_openssh_raw_serialized.key_data;
        let (next_data, _public_key) = parse_slice(next_data)?;

        let (_, next_data) = parse_slice(next_data)?;
        let (next_data, checkint1) = be_u32(next_data)?;
        let (next_data, checkint2) = be_u32(next_data)?;

        if checkint1 != checkint2 {
            return Err(KeyLoadingError::InvalidIntegersCheck);
        }

        let (next_data, private_key_type) = parse_utf8_string(next_data)?;
        let signing_algo = negotiate_alg_host_key_algorithms!(
            [private_key_type.clone()],
            KeyLoadingError::UnsupportedSigningAlgorithm
        );

        let (next_data, curve_name) = parse_utf8_string(next_data)?;
        // check that the EC curve name matches the key type
        if curve_name != signing_algo.curve_name() {
            return Err(KeyLoadingError::EcdsaCurveMismatch);
        }

        let (next_data, signing_key) = signing_algo.deserialize_buf_to_key(next_data)?;

        let (mut next_data, comment) = parse_utf8_string(next_data)?;
        info!("Read key '{}' of type '{}'", comment, private_key_type);

        // ensure a proper padding
        let mut pad_pos = 1;
        while next_data != [] {
            if next_data[0] != pad_pos {
                return Err(KeyLoadingError::InvalidBlockPadding);
            }

            pad_pos += 1;
            next_data = &next_data[1..];
        }

        Ok(Box::new(signing_key))
    }
}
