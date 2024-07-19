use std::sync::Arc;

use log::debug;
use smicro_common::LoopingBufferWriter;
use smicro_macros::declare_session_state;
use smicro_types::deserialize::DeserializePacket;
use smicro_types::ssh::types::MessageType;

use crate::{
    crypto::{ICryptoAlgs, KexNegotiatedKeys},
    error::Error,
    messages::{gen_kex_initial_list, MessageKexEcdhInit, MessageKeyExchangeInit, MessageNewKeys},
    state::{SessionCryptoMaterials, State},
    write_message,
};

use super::SessionStateEstablished;

#[derive(Clone, Debug)]
pub(crate) enum SessionStateAllowedAfterKex {
    ExpectsServiceRequest(super::ExpectsServiceRequest),
    ExpectsUserAuthRequest(super::ExpectsUserAuthRequest),
    ExpectsChannelOpen(super::ExpectsChannelOpen),
    AcceptsChannelMessages(super::AcceptsChannelMessages),
}

impl SessionStateAllowedAfterKex {
    fn to_sessionstates(&self) -> SessionStateEstablished {
        match self {
            Self::ExpectsServiceRequest(x) => {
                SessionStateEstablished::ExpectsServiceRequest(x.clone())
            }
            Self::ExpectsUserAuthRequest(x) => {
                SessionStateEstablished::ExpectsUserAuthRequest(x.clone())
            }
            Self::ExpectsChannelOpen(x) => SessionStateEstablished::ExpectsChannelOpen(x.clone()),
            Self::AcceptsChannelMessages(x) => {
                SessionStateEstablished::AcceptsChannelMessages(x.clone())
            }
        }
    }
}

pub(crate) fn renegotiate_kex<const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
    state: &mut State,
    writer: &mut W,
) -> Result<MessageKeyExchangeInit, Error> {
    debug!("Received a key rotation message, sending a MessageKeyExchangeInit packet");
    let kex_init_msg = gen_kex_initial_list(state);
    write_message(&mut state.sender, writer, &kex_init_msg)?;

    Ok(kex_init_msg)
}

#[declare_session_state(msg_type = MessageType::KexInit, strict_kex = true)]
pub struct KexSent {
    pub my_kex_message: MessageKeyExchangeInit,
    pub(crate) next_state: SessionStateAllowedAfterKex,
}

impl KexSent {
    pub fn inner_process<const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &self,
        _state: &mut State,
        _writer: &mut W,
        _message_type: MessageType,
        message_data: &[u8],
    ) -> Result<SessionStateEstablished, Error> {
        let (_, msg) = MessageKeyExchangeInit::deserialize(message_data)?;
        debug!("Received a key exchange init message: {:?}", msg);

        let crypto_algs = msg.compute_crypto_algs()?;
        debug!("Cryptographic algorithms exchanged");

        let next_state = KexReceived {
            my_kex_message: self.my_kex_message.clone(),
            peer_kex_message: msg,
            new_crypto_algs: Arc::new(crypto_algs),
            next_state: self.next_state.clone(),
        };

        Ok(SessionStateEstablished::KexReceived(next_state))
    }
}

#[declare_session_state(msg_type = MessageType::KexEcdhInit, strict_kex = true)]
pub struct KexReceived {
    pub my_kex_message: MessageKeyExchangeInit,
    pub peer_kex_message: MessageKeyExchangeInit,
    pub new_crypto_algs: Arc<Box<dyn ICryptoAlgs>>,
    pub(crate) next_state: SessionStateAllowedAfterKex,
}

impl KexReceived {
    pub fn inner_process<const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &self,
        state: &mut State,
        writer: &mut W,
        _message_type: MessageType,
        message_data: &[u8],
    ) -> Result<SessionStateEstablished, Error> {
        let (_, msg) = MessageKexEcdhInit::deserialize(message_data)?;
        debug!("Received an ECDH key exchange request: {:?}", msg);
        let crypto_algs = self.new_crypto_algs.clone();
        let (ecdh_reply, negotiated_keys) =
            crypto_algs.kex().perform_key_exchange(state, &msg, &self)?;

        write_message(&mut state.sender, writer, &ecdh_reply)?;

        write_message(&mut state.sender, writer, &MessageNewKeys {})?;

        let server_mac = crypto_algs
            .server_mac()
            .allocate_with_key(&negotiated_keys.integrity_key_s2c);
        let server_cipher = crypto_algs
            .server_cipher()
            .from_key(&negotiated_keys.encryption_key_s2c)?;
        state.sender.crypto_algs = Some(crypto_algs.clone());
        state.sender.crypto_material = Some(SessionCryptoMaterials {
            mac: server_mac,
            cipher: server_cipher,
        });
        state.sender.sequence_number.0 = 0;

        let kex_reply_sent = KexReplySent {
            negotiated_keys,
            new_crypto_algs: crypto_algs,
            next_state: self.next_state.clone(),
        };

        Ok(SessionStateEstablished::KexReplySent(kex_reply_sent))
    }
}

#[declare_session_state(msg_type = MessageType::NewKeys, strict_kex = true)]
pub struct KexReplySent {
    pub negotiated_keys: KexNegotiatedKeys,
    pub new_crypto_algs: Arc<Box<dyn ICryptoAlgs>>,
    pub(crate) next_state: SessionStateAllowedAfterKex,
}

impl KexReplySent {
    pub fn inner_process<const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &self,
        state: &mut State,
        _writer: &mut W,
        _message_type: MessageType,
        message_data: &[u8],
    ) -> Result<SessionStateEstablished, Error> {
        if message_data != [] {
            return Err(Error::DataInNewKeysMessage);
        }

        let crypto_algs = self.new_crypto_algs.clone();
        let client_mac = crypto_algs
            .client_mac()
            .allocate_with_key(&self.negotiated_keys.integrity_key_c2s);
        let client_cipher = crypto_algs
            .client_cipher()
            .from_key(&self.negotiated_keys.encryption_key_c2s)?;

        state.receiver.crypto_algs = Some(self.new_crypto_algs.clone());
        state.receiver.crypto_material = Some(SessionCryptoMaterials {
            mac: client_mac,
            cipher: client_cipher,
        });

        state.receiver.sequence_number.0 = 0;

        debug!("Key setup/rotation done");

        Ok(self.next_state.to_sessionstates())
    }
}
