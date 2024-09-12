use base64::engine::{general_purpose::STANDARD, Engine as _};

use log::{debug, info};

use nix::unistd::User;
use nom::{AsBytes, AsChar};
use smicro_common::LoopingBufferWriter;
use smicro_macros::declare_session_state;
use smicro_types::deserialize::DeserializePacket;
use smicro_types::ssh::types::MessageType;
use smicro_types::{
    serialize::SerializePacket,
    ssh::types::{NameList, SharedSSHSlice},
};

use crate::{
    crypto::{
        keys::{load_public_key_list, AuthorizedKey},
        sign::{EcdsaSha2Nistp521, SignerIdentifier},
        CryptoAlg,
    },
    error::Error,
    messages::{
        get_signature_checker_from_key_type, MessageServiceAccept, MessageServiceRequest,
        MessageUserAuthFailure, MessageUserAuthPublicKeyOk, MessageUserAuthRequest,
        MessageUserAuthSuccess, UserAuthPublickey,
    },
    session::ExpectsChannelOpen,
    state::State,
    write_message,
};

use super::SessionStateEstablished;

#[declare_session_state(msg_type = MessageType::ServiceRequest)]
pub struct ExpectsServiceRequest {}

impl ExpectsServiceRequest {
    fn inner_process<const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &self,
        state: &mut State,
        writer: &mut W,
        _message_type: MessageType,
        message_data: &[u8],
    ) -> Result<SessionStateEstablished, Error> {
        let (_, msg) = MessageServiceRequest::deserialize(message_data)?;

        if msg.service_name != "ssh-userauth" {
            return Err(Error::InvalidServiceRequest);
        }

        write_message(
            &mut state.sender,
            writer,
            &MessageServiceAccept {
                service_name: msg.service_name,
            },
        )?;

        Ok(SessionStateEstablished::ExpectsUserAuthRequest(
            ExpectsUserAuthRequest {},
        ))
    }
}

#[declare_session_state(msg_type = MessageType::UserAuthRequest)]
pub struct ExpectsUserAuthRequest {}

impl ExpectsUserAuthRequest {
    fn get_authorized_keys_for_user(&self, user: &User) -> Result<Vec<AuthorizedKey>, Error> {
        // TODO: this should be customizable
        let mut key_location = user.dir.clone();
        key_location.push(".ssh");
        key_location.push("authorized_keys");

        Ok(load_public_key_list(&key_location)?)
    }

    fn reject_auth_request<const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &self,
        state: &mut State,
        writer: &mut W,
    ) -> Result<SessionStateEstablished, Error> {
        write_message(
            &mut state.sender,
            writer,
            &MessageUserAuthFailure {
                allowed_auth_methods: NameList {
                    entries: vec![String::from("publickey")],
                },
                partial_success: false,
            },
        )?;

        Ok(SessionStateEstablished::ExpectsUserAuthRequest(
            self.clone(),
        ))
    }

    fn inner_process<const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &self,
        state: &mut State,
        writer: &mut W,
        _message_type: MessageType,
        message_data: &[u8],
    ) -> Result<SessionStateEstablished, Error> {
        let (_, msg) = MessageUserAuthRequest::deserialize(message_data)?;

        if let Some(_invalid_char) = msg
            .user_name
            .bytes()
            .find(|c| !(c.is_alphanum() || *c == b'.' || *c == b'_' || *c == b'-'))
        {
            debug!("User sent an invalid user name, aborting the auth attempt");
            return self.reject_auth_request(state, writer);
        }

        if msg.method_name != "publickey" {
            return self.reject_auth_request(state, writer);
        }

        let (user_entry, authorized_keys) =
            if let Ok(Some(user_entry)) = User::from_name(msg.user_name) {
                let authorized_keys = self.get_authorized_keys_for_user(&user_entry)?;
                (user_entry, authorized_keys)
            } else {
                info!("User {} could not be found, aborting", msg.user_name);
                return Err(Error::UnknownUserName);
            };

        let (_, pk) = UserAuthPublickey::deserialize(msg.method_data)?;

        for authorized_key in authorized_keys {
            if pk.public_key_alg_name.as_bytes() == authorized_key.key_type {
                let verifier = match get_signature_checker_from_key_type(&authorized_key.key_type) {
                    Some(v) => v,
                    None => {
                        info!("Unsupported key type {}", pk.public_key_alg_name);
                        continue;
                    }
                };
                // TODO: constant-time compare
                if pk.public_key_blob == authorized_key.key_data {
                    if !pk.with_signature {
                        // The public key matches, let's ask for a signature to validate that the
                        // user owns the private key
                        write_message(
                            &mut state.sender,
                            writer,
                            &MessageUserAuthPublicKeyOk {
                                public_key_alg_name: pk.public_key_alg_name,
                                public_key_blob: SharedSSHSlice(pk.public_key_blob),
                            },
                        )?;

                        return Ok(SessionStateEstablished::ExpectsUserAuthRequest(
                            self.clone(),
                        ));
                    }

                    // We have a signature, let's check if it's valid
                    let sig = pk.signature.ok_or(Error::NoSignatureProvided)?;

                    let session_identifier = state
                        .session_identifier
                        .as_ref()
                        .ok_or(Error::MissingSessionIdentifier)?;
                    let mut message = Vec::new();
                    SharedSSHSlice(session_identifier.as_slice()).serialize(&mut message)?;
                    message.push(MessageType::UserAuthRequest as u8);
                    msg.user_name.serialize(&mut message)?;
                    msg.service_name.serialize(&mut message)?;
                    "publickey".serialize(&mut message)?;
                    true.serialize(&mut message)?;
                    pk.public_key_alg_name.serialize(&mut message)?;
                    SharedSSHSlice(pk.public_key_blob).serialize(&mut message)?;

                    if !verifier.signature_is_valid(&authorized_key.key_data, &message, sig)? {
                        info!(
                            "Attempted authentication for user {} with invalid public key",
                            msg.user_name
                        );
                        return self.reject_auth_request(state, writer);
                    }

                    write_message(&mut state.sender, writer, &MessageUserAuthSuccess {})?;

                    state.authentified_user = Some(msg.user_name.to_string());

                    return Ok(SessionStateEstablished::ExpectsChannelOpen(
                        ExpectsChannelOpen {},
                    ));
                }
            }
        }
        self.reject_auth_request(state, writer)
    }
}
