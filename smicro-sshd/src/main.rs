use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    thread,
};

use log::{debug, error, info, trace, warn, LevelFilter};
use messages::Message;
use nom::{
    bytes::streaming::{tag, take, take_until, take_while1},
    combinator::{opt, peek},
    multi::many_till,
    sequence::{preceded, tuple},
    AsChar, IResult,
};
use rand::Rng;
use state::State;
use syslog::{BasicLogger, Facility, Formatter3164};

use smicro_common::create_read_buffer;
use smicro_types::{
    error::ParsingError,
    serialize::SerializePacket,
    ssh::{deserialize::parse_message_type, types::MessageType},
};

mod error;
mod messages;
mod state;

use error::Error;

use crate::messages::{gen_kex_initial_list, message_process};

// A tad bit above the SFTP max packet size, so that we do not have too much fragmentation
pub const MAX_PKT_SIZE: usize = 4096 * 64;

macro_rules! define_state_list {
    ($($name:ident),*) => {
        #[derive(Debug)]
        pub enum SessionStates {
            $($name($name)),*
        }

        impl SessionState for SessionStates {
            fn process<'a>(
                &mut self,
                state: &mut State,
                stream: &mut TcpStream,
                input: &'a [u8],
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
    KexSent
);

trait SessionState {
    fn process<'a>(
        &mut self,
        state: &mut State,
        stream: &mut TcpStream,
        input: &'a [u8],
    ) -> Result<(&'a [u8], SessionStates), Error>;
}

#[derive(Debug)]
pub struct UninitializedSession {}

impl SessionState for UninitializedSession {
    fn process<'a>(
        &mut self,
        state: &mut State,
        stream: &mut TcpStream,
        input: &'a [u8],
    ) -> Result<(&'a [u8], SessionStates), Error> {
        // Write the identification string
        stream.write_all(b"SSH-2.0-smicro_ssh\r\n")?;
        Ok((
            input,
            SessionStates::IdentifierStringSent(IdentifierStringSent {}),
        ))
    }
}

#[derive(Debug)]
pub struct IdentifierStringSent {}

impl SessionState for IdentifierStringSent {
    fn process<'a>(
        &mut self,
        state: &mut State,
        stream: &mut TcpStream,
        input: &'a [u8],
    ) -> Result<(&'a [u8], SessionStates), Error> {
        let consume_until_carriage = &take_until(b"\r\n" as &[u8]);
        let consume_carriage = &tag(b"\r\n");
        // consume all lines not starting by SSH-
        let (input, _unused_lines) = opt(many_till(
            preceded(consume_until_carriage, consume_carriage),
            peek(tag(b"SSH-")),
        ))(input)?;

        let (input, _magic) = tag(b"SSH-2.0-")(input)?;
        let (input, softwareversion) = take_while1(|c: u8| {
            let c = c.as_char();
            c.is_ascii_graphic() && c != '-'
        })(input)?;

        let (input, _comment) = opt(preceded(tag(b" "), consume_until_carriage))(input)?;

        let (input, _) = consume_carriage(input)?;

        // this should be free, because we check that this is ascii before, but we can't tell the
        // compiler that
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
    fn process<'a>(
        &mut self,
        state: &mut State,
        stream: &mut TcpStream,
        input: &'a [u8],
    ) -> Result<(&'a [u8], SessionStates), Error> {
        debug!("Sending the MessageKeyExchangeInit packet");
        let kex_init_msg = gen_kex_initial_list(state);
        write_message(state, stream, &kex_init_msg)?;

        Ok((input, SessionStates::KexSent(KexSent {})))
    }
}

#[derive(Debug)]
pub struct KexSent {}

impl SessionState for KexSent {
    fn process<'a>(
        &mut self,
        state: &mut State,
        stream: &mut TcpStream,
        input: &'a [u8],
    ) -> Result<(&'a [u8], SessionStates), Error> {
        let (next_, packet) = parse_packet(input, None, None)?;
        //trace!("{packet:?}");
        let msg = message_process(state, stream, packet.payload)?;
        debug!("{msg:?}");

        unimplemented!()
    }
}

#[derive(Debug)]
struct Packet<'a> {
    length: u32,
    padding_length: u8,
    payload: &'a [u8],
    padding: &'a [u8],
    mac: &'a [u8],
}

fn write_message<'a, T: SerializePacket + Message<'a>>(
    state: &mut State,
    mut stream: &mut TcpStream,
    payload: &T,
) -> Result<(), Error> {
    let mut padding_length = 4;
    // length + padding_length + message_type + payload + random_padding, max not included
    let mut real_packet_length = 4 + 1 + 1 + payload.get_size() + padding_length;
    // BAD: probable timing oracle!
    while real_packet_length < 16 || real_packet_length % 8 != 0 {
        padding_length += 1;
        real_packet_length += 1;
    }

    let mut padding = [0u8; 256];
    state.rng.fill(&mut padding);

    // the packet_length field does not count in the packet size)
    ((real_packet_length - 4) as u32).serialize(&mut stream)?;
    stream.write_all(&[padding_length as u8, T::get_message_type() as u8])?;
    payload.serialize(&mut stream)?;
    (&padding[0..padding_length]).serialize(&mut stream)?;
    // TODO: mac
    Ok(())
}

struct MacParameters {
    length: usize,
    sequence_number: u32,
    validate: &'static dyn Fn(&Packet, &[u8]) -> bool,
}

fn parse_packet<'a>(
    input: &'a [u8],
    cipher_block_size: Option<usize>,
    mac: Option<&mut MacParameters>,
) -> IResult<&'a [u8], Packet<'a>, ParsingError> {
    let (input, (length, padding_length)) = tuple((
        nom::number::streaming::be_u32,
        nom::number::streaming::be_u8,
    ))(input)?;
    if length as usize > MAX_PKT_SIZE {
        return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
            length as usize,
        )));
    }

    if length < 12 {
        warn!("Packet too small: {} bytes", length);
        return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
            length as usize,
        )));
    }

    let multiple = cipher_block_size.unwrap_or(8);
    if (length + 4) % 8 != 0 {
        warn!(
            "The packet size is not a multiple of {}: {} bytes",
            multiple, length
        );
        return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
            length as usize,
        )));
    }

    if length <= padding_length as u32 + 1 {
        warn!("The packet size implies that the packet has no payload",);
        return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
            length as usize,
        )));
    }

    let (input, payload) = take(length - padding_length as u32 - 1)(input)?;
    let (input, padding) = take(padding_length)(input)?;
    let mut res = Packet {
        length,
        padding_length,
        payload,
        padding,
        mac: &[],
    };
    if let Some(mac) = mac {
        let (input, packet_mac) = take(mac.length)(input)?;

        if !(mac.validate)(&res, packet_mac) {
            return Err(nom::Err::Failure(ParsingError::InvalidMac));
        }

        res.mac = packet_mac;

        Ok((input, res))
    } else {
        Ok((input, res))
    }
}

fn handle_packet(stream: io::Result<TcpStream>) -> Result<(), Error> {
    let mut stream = stream?;

    let buf = create_read_buffer(MAX_PKT_SIZE)?;
    let mut data_start = 0;
    let mut cur_pos = 0;

    let mut global_state = State::new();
    let mut state = SessionStates::UninitializedSession(UninitializedSession {});

    loop {
        let res = state.process(&mut global_state, &mut stream, &buf[data_start..cur_pos]);
        match res {
            Err(Error::ParsingError(nom::Err::Incomplete(_))) => {
                trace!("Not enough data, trying to read more");
                // Read enough data to hold *at least* a packet, but without overwriting previous
                // data
                let written =
                    stream.read(&mut buf[cur_pos..cur_pos + MAX_PKT_SIZE - data_start])?;
                trace!("Read {written} bytes");
                if written == 0 {
                    info!("The client closed the connection, shutting down the thread");
                    return Ok(());
                }
                cur_pos += written;
            }
            Err(Error::ParsingError(e)) => {
                error!("Got an error while trying to parse the packet: {:?}", e);
                debug!("The data that triggered the error was: {:?}", buf);
                return Err(Error::InvalidPacket);
            }
            Err(e) => {
                error!("Got an error while processing the packet: {:?}", e);
                debug!("The data that triggered the error was: {:?}", buf);
                return Err(Error::ProcessingFailed);
            }
            Ok((next_data, new_state)) => {
                state = new_state;

                // The start of the next packet is at the beginning of the data we haven't read yet
                data_start = cur_pos - next_data.len();

                // Thanks to the properties of our doubly-mapped buffer, we can loop like this
                if data_start >= MAX_PKT_SIZE {
                    data_start %= MAX_PKT_SIZE;
                    cur_pos %= MAX_PKT_SIZE;
                }
            }
        }
    }
}

fn main() -> Result<(), Error> {
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "smicro_ssh".into(),
        pid: 0,
    };

    let logger = syslog::unix(formatter)?;
    log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
        .map(|()| log::set_max_level(LevelFilter::Trace))?;

    let listener = TcpListener::bind("127.0.0.1:2222")?;
    for stream in listener.incoming() {
        info!("Received a new connection");
        thread::spawn(move || handle_packet(stream));
    }
    Ok(())
}
