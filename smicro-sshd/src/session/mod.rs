use std::net::TcpStream;

use crate::{error::Error, state::State};

mod channel;
mod kex;
mod service;
mod session_establishment;

pub use channel::{AcceptsChannelMessages, ExpectsChannelOpen};
pub use kex::{KexReceived, KexReplySent, KexSent};
pub use service::{ExpectsServiceRequest, ExpectsUserAuthRequest};
pub use session_establishment::{
    IdentifierStringReceived, IdentifierStringSent, UninitializedSession,
};

macro_rules! define_state_list {
    ($($name:ident),*) => {
        #[derive(Debug)]
        pub enum SessionStates {
            $($name(crate::session::$name)),*
        }

        impl SessionState for SessionStates {
            fn process<'a>(
                &mut self,
                state: &mut State,
                stream: &mut TcpStream,
                input: &'a mut [u8],
            ) -> Result<(&'a [u8], SessionStates), Error> {
                match self {
                    $(SessionStates::$name(val) => val.process(state, stream, input),)*
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
    fn process<'a>(
        &mut self,
        state: &mut State,
        stream: &mut TcpStream,
        input: &'a mut [u8],
    ) -> Result<(&'a [u8], SessionStates), Error>;
}
