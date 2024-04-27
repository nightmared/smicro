use std::{
    io::Read,
    net::{TcpListener, TcpStream},
    path::Path,
    thread,
};

use log::{debug, error, info, trace, LevelFilter};
use packet::MAX_PKT_SIZE;
use syslog::{BasicLogger, Facility, Formatter3164};

use smicro_common::create_read_buffer;
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
    packet::write_message,
    session::UninitializedSession,
    session::{SessionState, SessionStates},
    state::State,
};

fn handle_packet(mut stream: TcpStream) -> Result<(), Error> {
    let buf = create_read_buffer(MAX_PKT_SIZE)?;
    let mut data_start = 0;
    let mut cur_pos = 0;

    let mut host_keys = Vec::new();
    let test_hostkey = State::load_hostkey(&Path::new("/home/sthoby/dev-fast/smicro/host_key"))?;
    host_keys.push(test_hostkey.as_ref());
    let mut global_state = State::new(&host_keys);
    let mut state = SessionStates::UninitializedSession(UninitializedSession {});

    loop {
        let res = state.process(
            &mut global_state,
            &mut stream,
            &mut buf[data_start..cur_pos],
        );
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

                let _ = write_message(
                    &mut global_state,
                    &mut stream,
                    &MessageDisconnect::new(DisconnectReason::ProtocolError),
                );
                return Err(Error::InvalidPacket);
            }
            Err(Error::DisallowedMessageType(MessageType::Ignore | MessageType::Debug)) => {}
            Err(e) => {
                error!("Got an error while processing the packet: {:?}", e);
                debug!("The data that triggered the error was: {:?}", buf);
                let _ = write_message(
                    &mut global_state,
                    &mut stream,
                    &MessageDisconnect::new(DisconnectReason::ProtocolError),
                );

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
        if let Ok(stream) = stream {
            thread::spawn(move || {
                if let Err(e) = handle_packet(stream) {
                    error!("Got an error while handling a stream: {:?}", e);
                }
            });
        }
    }
    Ok(())
}
