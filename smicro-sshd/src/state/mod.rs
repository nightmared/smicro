use std::{alloc::Allocator, num::Wrapping, path::Path};

use rand::{rngs::ThreadRng, thread_rng};
use smicro_common::BumpAllocatorOnMemfd;

use crate::{
    crypto::{
        cipher::CipherWrapper, keys::load_hostkey, mac::MACWrapper, sign::SignerWrapper, CryptoAlgs,
    },
    error::Error,
};

pub mod channel;

use self::channel::ChannelManager;

pub const IDENTIFIER_STRING: &'static str = "SSH-2.0-smicro_ssh";

pub struct SenderState {
    pub rng: ThreadRng,
    pub crypto_algs: Option<CryptoAlgs>,
    pub crypto_material: Option<SessionCryptoMaterials>,
    pub sequence_number: Wrapping<u32>,
}

pub struct ReceiverState {
    pub rng: ThreadRng,
    pub crypto_algs: Option<CryptoAlgs>,
    pub crypto_material: Option<SessionCryptoMaterials>,
    pub sequence_number: Wrapping<u32>,
}

pub struct State<A: Allocator = BumpAllocatorOnMemfd> {
    pub allocator: A,
    pub sender: SenderState,
    pub receiver: ReceiverState,
    pub host_keys: Vec<SignerWrapper>,
    pub peer_identifier_string: Option<Vec<u8, A>>,
    pub session_identifier: Option<Vec<u8, A>>,
    pub authentified_user: Option<String>,
    pub channels: ChannelManager,
}

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
    pub fn new() -> Result<Self, Error> {
        let allocator = BumpAllocatorOnMemfd::new(4096)?;

        let mut host_keys = Vec::new();
        let test_hostkey = load_hostkey(&Path::new("/home/sthoby/dev-fast/smicro/host_key"))?;
        host_keys.push(test_hostkey);

        Ok(Self {
            allocator,
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
            peer_identifier_string: None,
            session_identifier: None,
            authentified_user: None,
            channels: ChannelManager::new(),
        })
    }
}
