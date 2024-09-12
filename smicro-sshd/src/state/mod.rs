use std::{num::Wrapping, sync::Arc};

use rand::{rngs::ThreadRng, thread_rng};

use crate::crypto::{cipher::Cipher, mac::MAC, sign::Signer, ICryptoAlgs};

pub mod channel;

use self::channel::ChannelManager;

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
}
