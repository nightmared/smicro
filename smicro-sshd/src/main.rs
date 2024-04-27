use std::{
    io::{ErrorKind, Read},
    net::SocketAddr,
    path::Path,
    str::FromStr,
    thread,
};

use log::{debug, error, info, trace, LevelFilter};
use mio::{
    net::{TcpListener, TcpStream},
    Events, Interest, Poll, Token,
};
use syslog::{BasicLogger, Facility, Formatter3164};

use smicro_common::LoopingBuffer;
use smicro_types::{
    deserialize::DeserializePacket,
    ssh::{deserialize::parse_message_type, types::MessageType},
};

mod crypto;
mod error;
mod messages;
mod packet;
mod session;
mod state;

use crate::{
    error::Error,
    messages::{DisconnectReason, MessageDisconnect},
    packet::{write_message, MAX_PKT_SIZE},
    session::UninitializedSession,
    session::{SessionState, SessionStates},
    state::State,
};

fn handle_packet<const SIZE: usize>(
    buf: &mut LoopingBuffer<SIZE>,
    stream: &mut TcpStream,
    session: &mut SessionStates,
    state: &mut State,
) -> Result<(), Error> {
    let available_data = buf.get_readable_data();
    let available_data_len = available_data.len();
    let res = session.process(state, stream, available_data);
    match res {
        Err(Error::ParsingError(nom::Err::Incomplete(_))) => {
            trace!("Not enough data, trying to read more");
            // Read enough data to hold *at least* a packet, but without overwriting previous
            // data
            let written = stream.read(buf.get_writable_buffer())?;
            trace!("Read {written} bytes");
            if written == 0 {
                info!("The client closed the connection, shutting down the thread");
                return Ok(());
            }
            buf.advance_writer_pos(written);
        }
        Err(Error::ParsingError(e)) => {
            error!("Got an error while trying to parse the packet: {:?}", e);
            debug!("The data that triggered the error was: {:?}", buf);

            let _ = write_message(
                state,
                stream,
                &MessageDisconnect::new(DisconnectReason::ProtocolError),
            );
            return Err(Error::InvalidPacket);
        }
        Err(Error::DisallowedMessageType(MessageType::Ignore | MessageType::Debug)) => {}
        Err(e) => {
            error!("Got an error while processing the packet: {:?}", e);
            debug!("The data that triggered the error was: {:?}", buf);
            let _ = write_message(
                state,
                stream,
                &MessageDisconnect::new(DisconnectReason::ProtocolError),
            );

            return Err(Error::ProcessingFailed);
        }
        Ok((next_data, new_session)) => {
            *session = new_session;

            let read_data = available_data_len - next_data.len();
            buf.advance_reader_pos(read_data);
        }
    }

    Ok(())
}

fn handle_stream(mut stream: TcpStream) -> Result<(), Error> {
    let mut buf = <LoopingBuffer<MAX_PKT_SIZE>>::new()?;

    let mut host_keys = Vec::new();
    let test_hostkey = State::load_hostkey(&Path::new("/home/sthoby/dev-fast/smicro/host_key"))?;
    host_keys.push(test_hostkey.as_ref());
    let mut state = State::new(&host_keys);
    let mut session = SessionStates::UninitializedSession(UninitializedSession {});

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);

    let main_connection_token = Token(0);
    poll.registry()
        .register(&mut stream, main_connection_token, Interest::READABLE)?;

    loop {
        poll.poll(&mut events, None)?;

        for ev in &events {
            if ev.token() == main_connection_token {
                loop {
                    let res = handle_packet(&mut buf, &mut stream, &mut session, &mut state);
                    if let Err(e) = res {
                        if let Error::IoError(ref e) = e {
                            if e.kind() == ErrorKind::WouldBlock {
                                break;
                            }
                        }
                        return Err(e);
                    }
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

    let mut listener = TcpListener::bind(SocketAddr::from_str("127.0.0.1:2222")?)?;

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);

    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)?;

    loop {
        poll.poll(&mut events, None)?;

        for _event in events.iter() {
            loop {
                // One or more connections are ready, so we'll attempt to
                // accept them (in a loop).
                match listener.accept() {
                    Ok((stream, _address)) => {
                        info!("Received a new connection");
                        thread::spawn(move || {
                            if let Err(e) = handle_stream(stream) {
                                error!("Got an error while handling a stream: {:?}", e);
                            }
                        });
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => {
                        error!("Got an error accepting a connection: {:?}", e);
                    }
                }
            }
        }
    }
}
