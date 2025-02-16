use std::{
    fs::read_dir,
    num::Wrapping,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use log::info;
use nom::Parser;
use rand::{rngs::ThreadRng, thread_rng};

use smicro_macros::{declare_deserializable_struct, gen_serialize_impl};
use smicro_types::{
    deserialize::DeserializePacket,
    error::ParsingError,
    serialize::SerializePacket,
    ssh::{
        deserialize::parse_boolean,
        types::{SharedSSHSlice, SharedSlowSSHSlice, SlowSSHSlice},
    },
};

use crate::{
    crypto::{
        cipher::CipherWrapper, keys::load_hostkey, mac::MACWrapper, sign::SignerWrapper, CryptoAlgs,
    },
    error::Error,
    messages::MessageKeyExchangeInit,
};

pub mod channel;

use self::channel::ChannelManager;

pub const IDENTIFIER_STRING: &str = "SSH-2.0-smicro_ssh";

// We cannot serialize/deserialize a ThreadRng, so let's just recreate one from scratch
fn create_rng(input: &[u8]) -> nom::IResult<&[u8], ThreadRng, ParsingError> {
    Ok((input, thread_rng()))
}

#[derive(Debug)]
#[declare_deserializable_struct]
pub struct DirectionState {
    #[field(parser = create_rng)]
    pub rng: ThreadRng,
    pub crypto_algs: Option<CryptoAlgs>,
    pub crypto_material: Option<SessionCryptoMaterials>,
    #[field(parser = nom::number::streaming::be_u32.map(Wrapping))]
    pub sequence_number: Wrapping<u32>,
    #[field(parser = nom::number::streaming::be_u64)]
    pub bytes_counter: u64,
}

impl SerializePacket for DirectionState {
    fn get_size(&self) -> usize {
        self.crypto_algs.get_size()
            + self.crypto_material.get_size()
            + self.sequence_number.0.get_size()
            + self.bytes_counter.get_size()
    }

    fn serialize<W: std::io::Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        self.crypto_algs.serialize(&mut output)?;
        self.crypto_material.serialize(&mut output)?;
        self.sequence_number.0.serialize(&mut output)?;
        self.bytes_counter.serialize(&mut output)?;

        Ok(())
    }
}

// We cannot serialize/deserialize a CHannelManager, so let's just recreate one from scratch
fn create_channel_manager(input: &[u8]) -> nom::IResult<&[u8], ChannelManager, ParsingError> {
    Ok((input, ChannelManager::new()))
}

fn parse_option_string(input: &[u8]) -> nom::IResult<&[u8], Option<String>, ParsingError> {
    let (next_data, res) = <Option<SlowSSHSlice<u8>>>::deserialize(input)?;
    if let Some(res) = res {
        Ok((
            next_data,
            Some(
                String::from_utf8(res.0)
                    .map_err(ParsingError::from)
                    .map_err(nom::Err::Failure)?,
            ),
        ))
    } else {
        Ok((next_data, None))
    }
}

fn create_option_none<T>(input: &[u8]) -> nom::IResult<&[u8], Option<T>, ParsingError> {
    Ok((input, None))
}

#[derive(Debug)]
pub enum AuthMode {
    SingleUser(PathBuf),
    MultiUser,
}

fn create_auth_mode(input: &[u8]) -> nom::IResult<&[u8], AuthMode, ParsingError> {
    Ok((input, AuthMode::MultiUser))
}

#[derive(Debug)]
#[declare_deserializable_struct]
pub struct State {
    pub sender: DirectionState,
    pub receiver: DirectionState,
    #[field(parser = SlowSSHSlice::deserialize.map(|v| v.0))]
    pub host_keys: Vec<SignerWrapper>,
    #[field(parser = <Option<SlowSSHSlice<u8>>>::deserialize.map(|v| v.map(|x| x.0)))]
    pub peer_identifier_string: Option<Vec<u8>>,
    #[field(parser = <Option<SlowSSHSlice<u8>>>::deserialize.map(|v| v.map(|x| x.0)))]
    pub session_identifier: Option<Vec<u8>>,
    #[field(parser = parse_option_string)]
    pub authentified_user: Option<String>,
    #[field(parser = create_channel_manager)]
    pub channels: ChannelManager,
    #[field(parser = create_option_none)]
    pub rekeying: Option<MessageKeyExchangeInit>,
    #[field(parser = parse_boolean)]
    pub enable_interactive_shell: bool,
    // this value doesn't matter in the child
    #[field(parser = create_auth_mode)]
    pub auth_mode: AuthMode,
}

impl SerializePacket for State {
    fn get_size(&self) -> usize {
        self.sender.get_size()
            + self.receiver.get_size()
            + SharedSlowSSHSlice(&self.host_keys).get_size()
            + self.peer_identifier_string.get_size()
            + self.session_identifier.get_size()
            + self.authentified_user.get_size()
            + self.enable_interactive_shell.get_size()
    }

    fn serialize<W: std::io::Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        self.sender.serialize(&mut output)?;
        self.receiver.serialize(&mut output)?;
        SharedSlowSSHSlice(&self.host_keys).serialize(&mut output)?;
        self.peer_identifier_string
            .as_ref()
            .map(|v| SharedSSHSlice(v))
            .serialize(&mut output)?;
        self.session_identifier
            .as_ref()
            .map(|v| SharedSSHSlice(v))
            .serialize(&mut output)?;
        self.authentified_user.serialize(&mut output)?;
        self.enable_interactive_shell.serialize(&mut output)?;

        Ok(())
    }
}

#[declare_deserializable_struct]
#[gen_serialize_impl]
pub struct SessionCryptoMaterials {
    pub mac: MACWrapper,
    pub cipher: CipherWrapper,
}

impl std::fmt::Debug for SessionCryptoMaterials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionCryptoMaterials { <REDACTED> }")
    }
}

impl State {
    pub fn new(
        auth_mode: AuthMode,
        enable_interactive_shell: bool,
        host_keys_dir: &Path,
    ) -> Result<Self, Error> {
        let mut host_keys = Vec::new();
        let files = read_dir(host_keys_dir).map_err(Error::CannotOpenHostsKeyDir)?;
        for file in files {
            let file = file.map_err(Error::RetrievingFileInformationFailed)?;
            let filename = file.file_name();
            let filename = filename.as_bytes();
            if filename.starts_with(b"host_key") && !filename.ends_with(b".pub") {
                match load_hostkey(&file.path()) {
                    Ok(k) => host_keys.push(k),
                    Err(_) => info!("Could not open or parse key file {:?}", file.path()),
                }
            }
        }

        Ok(Self {
            sender: DirectionState {
                rng: thread_rng(),
                crypto_algs: None,
                crypto_material: None,
                sequence_number: Wrapping(0),
                bytes_counter: 0,
            },
            receiver: DirectionState {
                rng: thread_rng(),
                crypto_algs: None,
                crypto_material: None,
                sequence_number: Wrapping(0),
                bytes_counter: 0,
            },
            host_keys,
            peer_identifier_string: None,
            session_identifier: None,
            authentified_user: None,
            channels: ChannelManager::new(),
            rekeying: None,
            auth_mode,
            enable_interactive_shell,
        })
    }
}
