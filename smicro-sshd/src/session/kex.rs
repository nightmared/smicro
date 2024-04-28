use std::sync::Arc;

use log::debug;
use smicro_macros::declare_session_state_with_allowed_message_types;

use crate::{
    error::Error,
    messages::{MessageKexEcdhInit, MessageKeyExchangeInit, MessageNewKeys},
    session::ExpectsServiceRequest,
    state::SessionCryptoMaterials,
    write_message,
};

#[derive(Clone, Debug)]
pub struct KexSent {
    pub my_kex_message: MessageKeyExchangeInit,
}

#[declare_session_state_with_allowed_message_types(structure = KexSent, msg_type = MessageType::KexInit)]
fn process(message_data: &[u8]) {
    let (_, msg) = MessageKeyExchangeInit::deserialize(message_data)?;
    debug!("Received {:?}", msg);
    state.crypto_algs = Some(Arc::new(msg.compute_crypto_algs()?));

    let next_state = KexReceived {
        my_kex_message: self.my_kex_message.clone(),
        peer_kex_message: msg,
    };

    Ok((next, SessionStates::KexReceived(next_state)))
}

#[derive(Clone, Debug)]
pub struct KexReceived {
    my_kex_message: MessageKeyExchangeInit,
    peer_kex_message: MessageKeyExchangeInit,
}

#[declare_session_state_with_allowed_message_types(structure = KexReceived, msg_type = MessageType::KexEcdhInit)]
fn process(message_data: &[u8]) {
    let (_, msg) = MessageKexEcdhInit::deserialize(message_data)?;
    debug!("Received {:?}", msg);
    let crypto_algs = state
        .crypto_algs
        .as_ref()
        .ok_or(Error::MissingCryptoAlgs)?
        .clone();
    let next_state = crypto_algs.kex().perform_key_exchange(
        state,
        writer,
        &msg,
        &self.my_kex_message,
        &self.peer_kex_message,
    )?;

    write_message(state, writer, &MessageNewKeys {})?;

    Ok((next, next_state))
}

#[derive(Clone, Debug)]
pub struct KexReplySent {
    pub iv_c2s: Vec<u8>,
    pub iv_s2c: Vec<u8>,
    pub encryption_key_c2s: Vec<u8>,
    pub encryption_key_s2c: Vec<u8>,
    pub integrity_key_c2s: Vec<u8>,
    pub integrity_key_s2c: Vec<u8>,
}

#[declare_session_state_with_allowed_message_types(structure = KexReplySent, msg_type = MessageType::NewKeys)]
fn process(message_data: &[u8]) {
    if message_data != [] {
        return Err(Error::DataInNewKeysMessage);
    }

    let crypto_algs = state
        .crypto_algs
        .as_ref()
        .ok_or(Error::MissingCryptoAlgs)?
        .clone();
    let client_mac = crypto_algs
        .client_mac()
        .allocate_with_key(&self.integrity_key_c2s);
    let server_mac = crypto_algs
        .server_mac()
        .allocate_with_key(&self.integrity_key_s2c);
    let client_cipher = crypto_algs
        .client_cipher()
        .from_key(&self.encryption_key_c2s)?;
    let server_cipher = crypto_algs
        .server_cipher()
        .from_key(&self.encryption_key_s2c)?;
    let materials = SessionCryptoMaterials {
        client_mac,
        server_mac,
        client_cipher,
        server_cipher,
    };

    state.crypto_material = Some(materials);

    Ok((
        next,
        SessionStates::ExpectsServiceRequest(ExpectsServiceRequest {}),
    ))
}
