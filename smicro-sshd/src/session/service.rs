use log::{debug, info};

use nix::unistd::User;
use nom::AsChar;
use smicro_common::LoopingBufferWriter;
use smicro_macros::declare_session_state;
use smicro_types::deserialize::DeserializePacket;
use smicro_types::ssh::types::MessageType;
use smicro_types::{
    serialize::SerializePacket,
    ssh::types::{NameList, SharedSSHSlice},
};

use crate::crypto::sign::SignerIdentifier;
use crate::{
    crypto::keys::{load_public_key_list, AuthorizedKey},
    error::Error,
    messages::{
        negotiate_alg_signing_algorithms, MessageServiceAccept, MessageServiceRequest,
        MessageUserAuthFailure, MessageUserAuthPublicKeyOk, MessageUserAuthRequest,
        MessageUserAuthSuccess, UserAuthPublickey,
    },
    state::State,
    write_message,
};

use super::{PacketProcessingDecision, SessionStateEstablished};

#[declare_session_state(msg_type = MessageType::ServiceRequest)]
pub struct ExpectsServiceRequest {}

impl ExpectsServiceRequest {
    fn inner_process<const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &self,
        state: &mut State,
        writer: &mut W,
        _message_type: MessageType,
        message_data: &[u8],
    ) -> Result<PacketProcessingDecision, Error> {
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

        Ok(SessionStateEstablished::ExpectsUserAuthRequest(ExpectsUserAuthRequest {}).into())
    }
}

#[declare_session_state(msg_type = MessageType::UserAuthRequest)]
pub struct ExpectsUserAuthRequest {}

enum PubkeyAuthDecision {
    Rejected,
    WorkInProgress,
    Accepted,
}

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
    ) -> Result<PacketProcessingDecision, Error> {
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

        Ok(SessionStateEstablished::ExpectsUserAuthRequest(self.clone()).into())
    }

    fn auth_pub_key<const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &self,
        state: &mut State,
        writer: &mut W,
        authorized_key: &AuthorizedKey,
        msg: &MessageUserAuthRequest,
        req: &UserAuthPublickey,
    ) -> Result<PubkeyAuthDecision, Error> {
        if req.public_key_alg_name.as_bytes() != authorized_key.key_type {
            return Ok(PubkeyAuthDecision::Rejected);
        }

        let verifier = match negotiate_alg_signing_algorithms(&[&String::from_utf8_lossy(
            &authorized_key.key_type,
        )]) {
            Ok(v) => v[0].clone(),
            Err(_) => {
                info!("Unsupported key type {}", req.public_key_alg_name);
                return Ok(PubkeyAuthDecision::Rejected);
            }
        };

        // constant-time compare
        if req.public_key_blob.len() != authorized_key.key_data.len() {
            return Ok(PubkeyAuthDecision::Rejected);
        }
        let mut pubkey_equal = true;
        for i in 0..authorized_key.key_data.len() {
            pubkey_equal &= (req.public_key_blob[i] ^ authorized_key.key_data[i]) == 0;
        }
        if !pubkey_equal {
            return Ok(PubkeyAuthDecision::Rejected);
        }

        if !req.with_signature {
            // The public key matches, let's ask for a signature to validate that the
            // user owns the private key
            write_message(
                &mut state.sender,
                writer,
                &MessageUserAuthPublicKeyOk {
                    public_key_alg_name: req.public_key_alg_name,
                    public_key_blob: SharedSSHSlice(req.public_key_blob),
                },
            )?;

            return Ok(PubkeyAuthDecision::WorkInProgress);
        }

        // We have a signature, let's check if it's valid
        let sig = req.signature.ok_or(Error::NoSignatureProvided)?;

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
        // the signature is present
        true.serialize(&mut message)?;
        req.public_key_alg_name.serialize(&mut message)?;
        SharedSSHSlice(&authorized_key.key_data).serialize(&mut message)?;

        if !verifier.signature_is_valid(&authorized_key.key_data, &message, sig)? {
            info!(
                "Attempted authentication for user {} with invalid signature",
                msg.user_name
            );
            return Ok(PubkeyAuthDecision::Rejected);
        }

        write_message(&mut state.sender, writer, &MessageUserAuthSuccess {})?;

        state.authentified_user = Some(msg.user_name.to_string());

        Ok(PubkeyAuthDecision::Accepted)
    }

    fn inner_process<const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &self,
        state: &mut State,
        writer: &mut W,
        _message_type: MessageType,
        message_data: &[u8],
    ) -> Result<PacketProcessingDecision, Error> {
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

        let (_user_entry, authorized_keys) =
            if let Ok(Some(user_entry)) = User::from_name(msg.user_name) {
                let authorized_keys = self.get_authorized_keys_for_user(&user_entry)?;
                (user_entry, authorized_keys)
            } else {
                info!("User {} could not be found, aborting", msg.user_name);
                return Err(Error::UnknownUserName);
            };

        let (_, pk) = UserAuthPublickey::deserialize(msg.method_data)?;

        for authorized_key in authorized_keys {
            match self.auth_pub_key(state, writer, &authorized_key, &msg, &pk)? {
                PubkeyAuthDecision::Rejected => continue,
                PubkeyAuthDecision::WorkInProgress => {
                    return Ok(SessionStateEstablished::ExpectsUserAuthRequest(self.clone()).into())
                }
                PubkeyAuthDecision::Accepted => {
                    return Ok(PacketProcessingDecision::SpawnChild(
                        msg.user_name.to_string(),
                    ))
                }
            }
        }
        self.reject_auth_request(state, writer)
    }
}
