use smicro_common::{LoopingBuffer, LoopingBufferWriter};

use crate::{error::Error, state::State};

mod channel;
mod kex;
mod service;
mod session_establishment;

pub use self::channel::{AcceptsChannelMessages, ExpectsChannelOpen};
pub use self::kex::{KexReceived, KexReplySent, KexSent};
pub use self::service::{ExpectsServiceRequest, ExpectsUserAuthRequest};
pub use self::session_establishment::{
    IdentifierStringReceived, IdentifierStringSent, UninitializedSession,
};

macro_rules! define_state_list {
    ($($name:ident),*) => {
        #[derive(Debug)]
        pub enum SessionStates {
            $($name(crate::session::$name)),*
        }

        impl SessionState for SessionStates {
            fn process<'a, const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
                &mut self,
                state: &mut State,
                writer: &mut W,
                input: &'a mut [u8],
            ) -> Result<(&'a [u8], SessionStates), Error> {
                match self {
                    $(SessionStates::$name(val) => val.process(state, writer, input),)*
                }
            }
        }
    };
}
define_state_list!(
    UninitializedSession,
    IdentifierStringSent,
    IdentifierStringReceived,
    KexSent,
    KexReceived,
    KexReplySent,
    ExpectsServiceRequest,
    ExpectsUserAuthRequest,
    ExpectsChannelOpen,
    AcceptsChannelMessages
);

pub trait SessionState {
    fn process<'a, const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &mut self,
        state: &mut State,
        writer: &mut W,
        input: &'a mut [u8],
    ) -> Result<(&'a [u8], SessionStates), Error>;
}
