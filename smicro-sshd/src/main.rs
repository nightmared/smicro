use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    thread,
};

use log::{debug, error, info, trace, LevelFilter};
use nom::{
    branch::alt,
    bytes::{
        streaming::take_until,
        streaming::{tag, take_while1},
    },
    combinator::{opt, peek},
    multi::many_till,
    sequence::preceded,
    AsChar, IResult,
};
use syslog::{BasicLogger, Facility, Formatter3164};

use smicro_common::create_read_buffer;

mod error;

use error::Error;

// A tad bit above the SFTP max packet size, so that we do not have too mux fragmentation
pub const MAX_PKT_SIZE: usize = 4096 * 64;

macro_rules! define_state_list {
    ($($name:ident),*) => {
        enum SessionStates {
            $($name($name)),*
        }

        impl SessionState for SessionStates {
            fn process<'a>(
                &mut self,
                stream: &mut TcpStream,
                input: &'a [u8],
            ) -> Result<(&'a [u8], SessionStates), Error> {
                match self {
                    $(SessionStates::$name(val) => val.process(stream, input),)*
                }
            }
        }
    };
}
define_state_list!(UninitializedSession, IdentifiedClient);

trait SessionState {
    fn process<'a>(
        &mut self,
        stream: &mut TcpStream,
        input: &'a [u8],
    ) -> Result<(&'a [u8], SessionStates), Error>;
}

struct UninitializedSession {}

impl SessionState for UninitializedSession {
    fn process<'a>(
        &mut self,
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
        Ok((input, SessionStates::IdentifiedClient(IdentifiedClient {})))
    }
}

struct IdentifiedClient {}

impl SessionState for IdentifiedClient {
    fn process<'a>(
        &mut self,
        stream: &mut TcpStream,
        input: &'a [u8],
    ) -> Result<(&'a [u8], SessionStates), Error> {
        unimplemented!()
    }
}

fn handle_packet(stream: io::Result<TcpStream>) -> Result<(), Error> {
    let mut stream = stream?;

    // Write the identification string
    stream.write_all(b"SSH-2.0-smicro_ssh\r\n")?;

    let buf = create_read_buffer(MAX_PKT_SIZE)?;
    let mut data_start = 0;
    let mut cur_pos = 0;

    let mut state = SessionStates::UninitializedSession(UninitializedSession {});

    loop {
        let res = state.process(&mut stream, &buf[data_start..cur_pos]);
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
