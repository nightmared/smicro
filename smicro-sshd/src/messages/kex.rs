use std::cmp::max;

use log::{debug, error};
use nom::number::complete::be_u32;
use nom::Parser;
use rand::Rng;

use smicro_macros::{declare_crypto_algs_list, declare_deserializable_struct, declare_message};
use smicro_types::deserialize::DeserializePacket;
use smicro_types::serialize::SerializePacket;
use smicro_types::sftp::deserialize::parse_slice;
use smicro_types::ssh::types::{MessageType, SSHSlice};
use smicro_types::ssh::{
    deserialize::{const_take, parse_boolean, parse_name_list},
    types::NameList,
};

use crate::{
    crypto::{cipher::CipherAllocator, mac::MACAllocator, CryptoAlg, CryptoAlgs},
    error::Error,
    state::State,
};

pub fn gen_kex_initial_list(state: &mut State) -> MessageKeyExchangeInit {
    let cookie: [u8; 16] = state.receiver.rng.gen();

    // suboptimal, but only done once per session opening, so let's ignore it for now
    let mut kex_algorithms: Vec<String> =
        KEX_ALGORITHMS_NAMES.iter().map(|x| x.to_string()).collect();
    // advertise support for strict key checking
    kex_algorithms.push("kex-strict-s-v00@openssh.com".to_string());
    let kex_algorithms = NameList {
        entries: kex_algorithms,
    };

    let server_host_key_algorithms = NameList {
        entries: SIGNING_ALGORITHMS_NAMES
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

#[declare_message(KexInit)]
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

#[declare_crypto_algs_list(wrapper_name = crate::crypto::sign::SignerIdentifierWrapper, error_value = Error::NoCommonSigningAlg)]
const SIGNING_ALGORITHMS: _ = [crate::crypto::sign::EcdsaSha2Nistp521];

#[declare_crypto_algs_list(wrapper_name = crate::crypto::kex::KEXWrapper, error_value = Error::NoCommonKexAlg)]
const KEX_ALGORITHMS: _ = [crate::crypto::kex::EcdhSha2Nistp521];

#[declare_crypto_algs_list(wrapper_name = crate::crypto::cipher::CipherAllocatorWrapper, error_value = Error::NoCommonCipher)]
const CIPHER_ALGORITHMS: _ = [
    crate::crypto::cipher::Chacha20Poly1305,
    crate::crypto::cipher::Aes256Gcm,
    crate::crypto::cipher::Aes256Ctr,
];

#[declare_crypto_algs_list(wrapper_name = crate::crypto::mac::MACAllocatorWrapper, error_value = Error::NoCommonMAC)]
pub const MAC_ALGORITHMS: _ = [
    crate::crypto::mac::HmacSha2256,
    crate::crypto::mac::HmacSha2512,
];

impl MessageKeyExchangeInit {
    pub fn compute_crypto_algs(&self) -> Result<CryptoAlgs, Error> {
        if self.first_kex_packet_follows {
            error!("first_kex_packet_follows is not supported");
            return Err(Error::Unsupported);
        }

        let kex = negotiate_alg_kex_algorithms(&self.kex_algorithms.entries)?;
        let host_key_alg =
            negotiate_alg_signing_algorithms(&self.server_host_key_algorithms.entries)?;
        let client_to_server_cipher =
            negotiate_alg_cipher_algorithms(&self.encryption_algorithms_client_to_server.entries)?;
        let server_to_client_cipher =
            negotiate_alg_cipher_algorithms(&self.encryption_algorithms_server_to_client.entries)?;
        let client_to_server_mac =
            negotiate_alg_mac_algorithms(&self.mac_algorithms_client_to_server.entries)?;
        let server_to_client_mac =
            negotiate_alg_mac_algorithms(&self.mac_algorithms_server_to_client.entries)?;

        let cipher_max_length = |cipher: &dyn CipherAllocator| -> usize {
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

        Ok(crypto_algs)
    }
}

#[declare_message(KexEcdhInit)]
#[declare_deserializable_struct]
pub struct MessageKexEcdhInit<'a> {
    #[field(parser = parse_slice)]
    q_client: &'a [u8],
}

#[declare_message(KexEcdhReply)]
pub struct MessageKexEcdhReply {
    pub k_server: SSHSlice<u8>,
    pub q_server: SSHSlice<u8>,
    pub signature: SSHSlice<u8>,
}
