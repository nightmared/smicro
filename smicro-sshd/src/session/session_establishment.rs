use log::{debug, trace};
use nom::{
    bytes::streaming::{tag, take_until, take_while1},
    combinator::{opt, peek},
    multi::many_till,
    sequence::preceded,
    AsChar,
};
use smicro_common::LoopingBufferWriter;

use crate::{
    error::Error,
    messages::gen_kex_initial_list,
    session::{
        kex::SessionStateAllowedAfterKex, ExpectsServiceRequest, KexSent, SessionState,
        SessionStateEstablished, SessionStates,
    },
    state::State,
    write_message,
};

#[derive(Debug)]
pub struct UninitializedSession {}

impl SessionState for UninitializedSession {
    fn process<'a, const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &mut self,
        state: &mut State,
        writer: &mut W,
        input: &'a mut [u8],
    ) -> Result<(&'a [u8], SessionStates), Error> {
        // Write the identification string
        writer.write(state.my_identifier_string.as_bytes())?;
        writer.write(b"\r\n")?;
        Ok((
            input,
            SessionStates::IdentifierStringSent(IdentifierStringSent {}),
        ))
    }
}

#[derive(Debug)]
pub struct IdentifierStringSent {}

impl SessionState for IdentifierStringSent {
    fn process<'a, const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &mut self,
        state: &mut State,
        _writer: &mut W,
        input: &'a mut [u8],
    ) -> Result<(&'a [u8], SessionStates), Error> {
        let input = input as &[u8];
        let consume_until_carriage = &take_until(b"\r\n" as &[u8]);
        let consume_carriage = &tag(b"\r\n");
        // consume all lines not starting by SSH-
        let (input, _unused_lines) = opt(many_till(
            preceded(consume_until_carriage, consume_carriage),
            peek(tag(b"SSH-")),
        ))(input)?;

        let (input, magic) = tag(b"SSH-2.0-")(input)?;
        let (input, softwareversion) = take_while1(|c: u8| {
            let c = c.as_char();
            c.is_ascii_graphic() && c != '-'
        })(input)?;

        let (input, comment) = opt(preceded(tag(b" "), consume_until_carriage))(input)?;

        let (input, _) = consume_carriage(input)?;

        let mut peer_identifier_string = Vec::new();
        peer_identifier_string.extend_from_slice(magic);
        peer_identifier_string.extend_from_slice(softwareversion);
        if let Some(comment) = comment {
            peer_identifier_string.extend_from_slice(comment);
        }
        state.peer_identifier_string = Some(peer_identifier_string);

        // the UTF-8 conversion should be free, because we checked that this is ascii before,
        // but we can't tell the compiler that
        if log::log_enabled!(log::Level::Trace) {
            if let Ok(software_version) = std::str::from_utf8(softwareversion) {
                trace!("Got client with software '{}'", software_version);
            }
        }
        Ok((
            input,
            SessionStates::IdentifierStringReceived(IdentifierStringReceived {}),
        ))
    }
}

#[derive(Debug)]
pub struct IdentifierStringReceived {}

impl SessionState for IdentifierStringReceived {
    fn process<'a, const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &mut self,
        state: &mut State,
        writer: &mut W,
        input: &'a mut [u8],
    ) -> Result<(&'a [u8], SessionStates), Error> {
        debug!("Sending the MessageKeyExchangeInit packet");
        let kex_init_msg = gen_kex_initial_list(state);
        write_message(&mut state.sender, writer, &kex_init_msg)?;

        Ok((
            input,
            SessionStates::SessionStateEstablished(SessionStateEstablished::KexSent(KexSent {
                my_kex_message: kex_init_msg,
                next_state: SessionStateAllowedAfterKex::ExpectsServiceRequest(
                    ExpectsServiceRequest {},
                ),
            })),
        ))
    }
}
