use std::{fmt::Debug, fs::File, io::Read, path::Path};

use base64::engine::{general_purpose::STANDARD, Engine as _};
use log::{info, trace};
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
use signature::Signer;
use smicro_macros::declare_deserializable_struct;
use smicro_types::sftp::deserialize::{parse_slice, parse_utf8_string};

use crate::{
    error::KeyLoadingError,
    messages::{
        negotiate_alg_host_key_algorithms, CryptoAlg, ICipherAlgorithm, IKeyExchangeAlgorithm,
        IKeyExchangeMethods, IKeySigningAlgorithm, IMACAlgorithm, ISigningKey,
    },
    DeserializePacket,
};

pub trait ICryptoAlgs: Debug {
    fn get_kex(&self) -> &dyn IKeyExchangeMethods;
}

pub struct CryptoAlgs<
    Kex: IKeyExchangeAlgorithm,
    HostKey: IKeySigningAlgorithm,
    C2SCipher: ICipherAlgorithm,
    S2CCipher: ICipherAlgorithm,
    C2SMac: IMACAlgorithm,
    S2CMac: IMACAlgorithm,
> {
    pub kex: Kex,
    pub host_key_alg: HostKey,
    pub client_to_server_cipher: C2SCipher,
    pub server_to_client_cipher: S2CCipher,
    pub client_to_server_mac: C2SMac,
    pub server_to_client_mac: S2CMac,
}

impl<
        Kex: IKeyExchangeAlgorithm,
        HostKey: IKeySigningAlgorithm,
        C2SCipher: ICipherAlgorithm,
        S2CCipher: ICipherAlgorithm,
        C2SMac: IMACAlgorithm,
        S2CMac: IMACAlgorithm,
    > ICryptoAlgs for CryptoAlgs<Kex, HostKey, C2SCipher, S2CCipher, C2SMac, S2CMac>
{
    fn get_kex(&self) -> &dyn IKeyExchangeMethods {
        &self.kex
    }
}

impl<
        Kex: IKeyExchangeAlgorithm,
        HostKey: IKeySigningAlgorithm,
        C2SCipher: ICipherAlgorithm,
        S2CCipher: ICipherAlgorithm,
        C2SMac: IMACAlgorithm,
        S2CMac: IMACAlgorithm,
    > CryptoAlgs<Kex, HostKey, C2SCipher, S2CCipher, C2SMac, S2CMac>
{
    pub fn new(
        kex: Kex,
        host_key_alg: HostKey,
        client_to_server_cipher: C2SCipher,
        server_to_client_cipher: S2CCipher,
        client_to_server_mac: C2SMac,
        server_to_client_mac: S2CMac,
    ) -> Self {
        Self {
            kex,
            host_key_alg,
            client_to_server_cipher,
            server_to_client_cipher,
            client_to_server_mac,
            server_to_client_mac,
        }
    }
}

impl<
        Kex: IKeyExchangeAlgorithm,
        HostKey: IKeySigningAlgorithm,
        C2SCipher: ICipherAlgorithm,
        S2CCipher: ICipherAlgorithm,
        C2SMac: IMACAlgorithm,
        S2CMac: IMACAlgorithm,
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

pub struct State {
    pub rng: ThreadRng,
    pub host_keys: Vec<Box<dyn ISigningKey>>,
    pub my_identifier_string: &'static str,
    pub peer_identifier_string: Option<Vec<u8>>,
}

impl State {
    pub fn new(host_keys: Vec<Box<dyn ISigningKey>>) -> Self {
        Self {
            rng: thread_rng(),
            host_keys,
            my_identifier_string: "SSH-2.0-smicro_ssh",
            peer_identifier_string: None,
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
        let (next_data, public_key) = parse_slice(next_data)?;

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
