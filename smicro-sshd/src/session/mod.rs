use smicro_common::LoopingBufferWriter;

use crate::packet::MAX_PKT_SIZE;
use crate::{error::Error, state::State};

mod channel;
pub(crate) mod kex;
mod service;
mod session_establishment;

pub use self::channel::{AcceptsChannelMessages, ExpectsChannelOpen};
pub use self::kex::{KexReceived, KexReplySent, KexSent};
pub use self::service::{ExpectsServiceRequest, ExpectsUserAuthRequest};
pub use self::session_establishment::{
    IdentifierStringReceived, IdentifierStringSent, UninitializedSession,
};

pub enum PacketProcessingDecision {
    NewState(SessionStates),
    SpawnChild(String),
    PeerTriggeredDisconnection,
}

pub trait SessionState {
    fn process<'a, 'b: 'a, const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &mut self,
        state: &mut State,
        writer: &mut W,
        input: &'a [u8],
        tmp_packet: &'b mut [u8; MAX_PKT_SIZE],
    ) -> Result<(&'a [u8], PacketProcessingDecision), Error>;
}

macro_rules! define_state_list {
    ($struct:ident, $($name:ident),*) => {
        #[derive(Debug)]
        pub enum $struct {
            $($name(crate::session::$name)),*
        }

        impl SessionState for $struct {
            fn process<'a, 'b: 'a, const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
                &mut self,
                state: &mut State,
                writer: &mut W,
                input: &'a [u8],
                tmp_packet: &'b mut [u8; MAX_PKT_SIZE],
            ) -> Result<(&'a [u8], PacketProcessingDecision), Error> {
                match self {
                    $($struct::$name(val) => val.process(state, writer, input, tmp_packet),)*
                }
            }
        }
    };
}

define_state_list!(
    SessionStateEstablished,
    KexSent,
    KexReceived,
    KexReplySent,
    ExpectsServiceRequest,
    ExpectsUserAuthRequest,
    ExpectsChannelOpen,
    AcceptsChannelMessages
);

impl From<SessionStateEstablished> for PacketProcessingDecision {
    fn from(obj: SessionStateEstablished) -> Self {
        PacketProcessingDecision::NewState(SessionStates::SessionStateEstablished(obj))
    }
}

define_state_list!(
    SessionStates,
    UninitializedSession,
    IdentifierStringSent,
    IdentifierStringReceived,
    SessionStateEstablished
);
