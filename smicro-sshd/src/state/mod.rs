use std::{fmt::Debug, fs::File, io::Read, num::Wrapping, path::Path, sync::Arc};

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
    crypto::{Cipher, CryptoAlg, ICryptoAlgs, Signer, SignerIdentifier, MAC},
    error::KeyLoadingError,
    messages::negotiate_alg_host_key_algorithms,
    DeserializePacket,
};

pub mod channel;

use self::channel::ChannelManager;

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

pub struct SenderState {
    pub rng: ThreadRng,
    pub crypto_algs: Option<Arc<Box<dyn ICryptoAlgs>>>,
    pub crypto_material: Option<SessionCryptoMaterials>,
    pub sequence_number: Wrapping<u32>,
}

pub struct ReceiverState {
    pub rng: ThreadRng,
    pub crypto_algs: Option<Arc<Box<dyn ICryptoAlgs>>>,
    pub crypto_material: Option<SessionCryptoMaterials>,
    pub sequence_number: Wrapping<u32>,
}

pub struct State<'a> {
    pub sender: SenderState,
    pub receiver: ReceiverState,
    pub host_keys: &'a [&'a dyn Signer],
    pub my_identifier_string: &'static str,
    pub peer_identifier_string: Option<Vec<u8>>,
    pub session_identifier: Option<Vec<u8>>,
    pub authentified_user: Option<String>,
    pub channels: ChannelManager,
}

pub struct SessionCryptoMaterials {
    pub mac: Box<dyn MAC>,
    pub cipher: Box<dyn Cipher>,
}

impl std::fmt::Debug for SessionCryptoMaterials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionCryptoMaterials { <REDACTED> }")
    }
}

impl<'a> State<'a> {
    pub fn new(host_keys: &'a [&'a dyn Signer]) -> Self {
        Self {
            sender: SenderState {
                rng: thread_rng(),
                crypto_algs: None,
                crypto_material: None,
                sequence_number: Wrapping(0),
            },
            receiver: ReceiverState {
                rng: thread_rng(),
                crypto_algs: None,
                crypto_material: None,
                sequence_number: Wrapping(0),
            },
            host_keys,
            my_identifier_string: "SSH-2.0-smicro_ssh",
            peer_identifier_string: None,
            session_identifier: None,
            authentified_user: None,
            channels: ChannelManager::new(),
        }
    }

    pub fn load_hostkey(hostkey_file: &Path) -> Result<Box<dyn Signer>, KeyLoadingError> {
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
