use base64::engine::{general_purpose::STANDARD, Engine as _};

use smicro_macros::declare_session_state_with_allowed_message_types;
use smicro_types::{
    serialize::SerializePacket,
    ssh::types::{NameList, SharedSSHSlice},
};

use crate::{
    crypto::{CryptoAlg, EcdsaSha2Nistp521, SignerIdentifier},
    error::Error,
    messages::{
        MessageServiceAccept, MessageServiceRequest, MessageUserAuthFailure,
        MessageUserAuthPublicKeyOk, MessageUserAuthRequest, MessageUserAuthSuccess,
        UserAuthPublickey,
    },
    session::ExpectsChannelOpen,
    write_message,
};

#[derive(Clone, Debug)]
pub struct ExpectsServiceRequest {}

#[declare_session_state_with_allowed_message_types(structure = ExpectsServiceRequest, msg_type = MessageType::ServiceRequest)]
fn process(message_data: &[u8]) {
    let (_, msg) = MessageServiceRequest::deserialize(message_data)?;

    if msg.service_name != "ssh-userauth" {
        return Err(Error::InvalidServiceRequest);
    }

    write_message(
        state,
        stream,
        &MessageServiceAccept {
            service_name: msg.service_name,
        },
    )?;

    Ok((
        next,
        SessionStates::ExpectsUserAuthRequest(ExpectsUserAuthRequest {}),
    ))
}

#[derive(Clone, Debug)]
pub struct ExpectsUserAuthRequest {}

#[declare_session_state_with_allowed_message_types(structure = ExpectsUserAuthRequest, msg_type = MessageType::UserAuthRequest)]
fn process(message_data: &[u8]) {
    let (_, msg) = MessageUserAuthRequest::deserialize(message_data)?;

    if msg.method_name == "publickey" {
        let (_, pk) = UserAuthPublickey::deserialize(msg.method_data)?;

        if pk.public_key_alg_name == <EcdsaSha2Nistp521 as SignerIdentifier>::NAME {
            let verifier = EcdsaSha2Nistp521::new();
            let allowed_key = STANDARD.decode("AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAD2J8ayINyXiTREW9oNZ/TTveKGTAPe0orWMgMJ/unT72Lo/NUA2G4LcgCrjpunTctfT88Drq5NB5uyULw3tLMI+wBvJqL7ACK5+j9c1GDx8wZ1W5AN+hYzi1fjvMICS/MCDmG2J3KaDZOci3A5DQCtaJ7COs9BzVmJQzWFpF76QxgJJQ==").unwrap();
            if pk.public_key_blob == allowed_key {
                if pk.with_signature {
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

                    if verifier.signature_is_valid(pk.public_key_blob, &message, sig)? {
                        write_message(state, stream, &MessageUserAuthSuccess {})?;

                        state.authentified_user = Some(msg.user_name.to_string());

                        return Ok((
                            next,
                            SessionStates::ExpectsChannelOpen(ExpectsChannelOpen {}),
                        ));
                    }
                } else {
                    write_message(
                        state,
                        stream,
                        &MessageUserAuthPublicKeyOk {
                            public_key_alg_name: pk.public_key_alg_name,
                            public_key_blob: SharedSSHSlice(pk.public_key_blob),
                        },
                    )?;

                    return Ok((next, SessionStates::ExpectsUserAuthRequest(self.clone())));
                }
            }
        }
    }
    write_message(
        state,
        stream,
        &MessageUserAuthFailure {
            allowed_auth_methods: NameList {
                entries: vec![String::from("publickey")],
            },
            partial_success: false,
        },
    )?;

    Ok((next, SessionStates::ExpectsUserAuthRequest(self.clone())))
}


