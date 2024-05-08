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

    let crypto_algs = Arc::new(msg.compute_crypto_algs()?);
    debug!("Cryptographic algorithms exchanged");
    state.receiver.crypto_algs = Some(crypto_algs.clone());
    state.sender.crypto_algs = Some(crypto_algs);

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
        .receiver
        .crypto_algs
        .as_ref()
        .ok_or(Error::MissingCryptoAlgs)?
        .clone();
    let (ecdh_reply, exchange_hash, kex_reply_sent) = crypto_algs.kex().perform_key_exchange(
        state,
        &msg,
        &self.my_kex_message,
        &self.peer_kex_message,
    )?;

    write_message(&mut state.sender, writer, &ecdh_reply)?;
    state.session_identifier = Some(exchange_hash);

    write_message(&mut state.sender, writer, &MessageNewKeys {})?;

    Ok((next, SessionStates::KexReplySent(kex_reply_sent)))
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
        .receiver
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
    state.receiver.crypto_material = Some(SessionCryptoMaterials {
        mac: client_mac,
        cipher: client_cipher,
    });
    state.sender.crypto_material = Some(SessionCryptoMaterials {
        mac: server_mac,
        cipher: server_cipher,
    });

    Ok((
        next,
        SessionStates::ExpectsServiceRequest(ExpectsServiceRequest {}),
    ))
}
