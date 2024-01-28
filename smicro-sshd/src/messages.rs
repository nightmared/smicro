use std::{io::Write, net::TcpStream};

use log::debug;
use nom::{number::complete::be_u32, Parser};

use rand::Rng;
use smicro_macros::{declare_deserializable_struct, gen_serialize_impl};
use smicro_types::{
    deserialize::DeserializePacket,
    serialize::SerializePacket,
    ssh::{
        deserialize::{const_take, parse_boolean, parse_message_type, parse_name_list},
        types::{MessageType, NameList},
    },
};

use crate::{error::Error, state::State, SessionStates};

pub trait Message<'a>: Sized {
    fn process(self, state: &mut State, stream: &mut TcpStream) -> Result<SessionStates, Error>;

    fn get_message_type() -> MessageType;
}

struct KeyExchangeAlgorithm {
    name: &'static str,
    requires_encryption_capable_host_key: bool,
    requires_signature_capable_host_key: bool,
}

const SUPPORTED_KEX_ALGORITHMS: [KeyExchangeAlgorithm; 1] = [KeyExchangeAlgorithm {
    name: "ecdh-sha2-nistp521",
    // TODO: revisit this
    requires_encryption_capable_host_key: false,
    requires_signature_capable_host_key: false,
}];

struct HostKeyAlgorithm {
    name: &'static str,
    encryption_capable: bool,
    signature_capable: bool,
}

const SUPPORTED_HOST_KEY_ALGORITHMS: [HostKeyAlgorithm; 1] = [HostKeyAlgorithm {
    name: "ecdsa-sha2-nistp521",
    // TODO: revisit this
    encryption_capable: false,
    signature_capable: false,
}];

struct Cipher {
    name: &'static str,
}

// TODO: add aes256-gcm@openssh.com
const SUPPORTED_CIPHERS: [Cipher; 1] = [Cipher {
    name: "chacha20-poly1305@openssh.com",
}];

struct MacAlgorithm {
    name: &'static str,
}

const SUPPORTED_MAC_ALGORITHMS: [MacAlgorithm; 1] = [MacAlgorithm {
    name: "hmac-sha2-512",
}];

pub fn gen_kex_initial_list(state: &mut State) -> MessageKeyExchangeInit {
    let cookie: [u8; 16] = state.rng.gen();

    // suboptimal, but only done once per session opening, so let's ignore it for now
    let kex_algorithms = NameList {
        entries: SUPPORTED_KEX_ALGORITHMS
            .iter()
            .map(|x| x.name.to_string())
            .collect(),
    };

    let server_host_key_algorithms = NameList {
        entries: SUPPORTED_HOST_KEY_ALGORITHMS
            .iter()
            .map(|x| x.name.to_string())
            .collect(),
    };

    let encryption_algorithms_client_to_server = NameList {
        entries: SUPPORTED_CIPHERS
            .iter()
            .map(|x| x.name.to_string())
            .collect(),
    };
    let encryption_algorithms_server_to_client = encryption_algorithms_client_to_server.clone();

    let mac_algorithms_client_to_server = NameList {
        entries: SUPPORTED_MAC_ALGORITHMS
            .iter()
            .map(|x| x.name.to_string())
            .collect(),
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

impl<'a> Message<'a> for MessageKeyExchangeInit {
    fn process(self, state: &mut State, stream: &mut TcpStream) -> Result<SessionStates, Error> {
        debug!("Received {:?}", self);
        unimplemented!()
        //for supported_kex in SUPPORTED_KEX_ALGORITHMS {
        //    if self.kex_algorithms.entries.contains(supported_kex) {

        //    }
        //}
    }

    fn get_message_type() -> MessageType {
        MessageType::KexInit
    }
}

macro_rules! generate_message_wrapper {
    ($($msg:ident => $ty:ty),*) => {
        pub(crate) fn message_process<'a>(state: &mut State, stream: &mut TcpStream, payload: &'a [u8]) -> Result<(&'a [u8], SessionStates), Error> {

            let (message_data, message_type) = parse_message_type(payload)?;
            match message_type {
                $( MessageType::$msg => {
                    let (remaining_input, msg) = <$ty>::deserialize(message_data)?;
                    Ok((remaining_input, msg.process(state, stream)?))
                } ),*
            }
        }
    };
}

generate_message_wrapper!(
    KexInit => MessageKeyExchangeInit
);
