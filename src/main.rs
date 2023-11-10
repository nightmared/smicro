use std::io::{stdin, stdout, ErrorKind as IOErrorKind, Read, Write};

use command::{Command, CommandType, CommandWrapper};
use deserialize::{parse_command, Packet};
use log::{debug, error, info, trace, LevelFilter};
use nom::Err;
use serialize::SerializeForSftp;
use state::GlobalState;
use syslog::{BasicLogger, Facility, Formatter3164};

mod command;
mod deserialize;
mod error;
mod extensions;
mod response;
mod serialize;
mod state;
mod types;

use error::Error;
use response::{ResponsePacket, ResponseStatus, ResponseWrapper};
use types::StatusCode;

pub const MAX_PKT_SIZE: usize = 256000;
pub const MAX_READ_LENGTH: usize = MAX_PKT_SIZE - 1000;

fn process_command(
    mut output: impl Write,
    state: &mut GlobalState,
    pkt: Packet<CommandType, CommandWrapper>,
) -> Result<(), Error> {
    let mut hdr = pkt.hdr;
    debug!("Received command {:?}", pkt.data);
    let response = match pkt.data.process(state) {
        Ok(res) => res,
        Err(Error::StatusCode(status)) => {
            debug!("Got the status code {status:?} handling a packet");
            ResponseWrapper::Status(ResponseStatus::new(status))
        }
        Err(Error::IoError(e)) => {
            let code = match e.kind() {
                IOErrorKind::NotFound => StatusCode::NoSuchFile,
                IOErrorKind::InvalidData => StatusCode::BadMessage,
                IOErrorKind::PermissionDenied => StatusCode::PermissionDenied,
                IOErrorKind::BrokenPipe => StatusCode::ConnectionLost,
                _ => StatusCode::Failure,
            };

            error!("Got an IO error handling a packet: {e:?}");
            ResponseWrapper::Status(ResponseStatus::new(code))
        }
        Err(e) => {
            error!("Got an error handling a packet: {e:?}");
            ResponseWrapper::Status(ResponseStatus::new(StatusCode::Failure))
        }
    };
    // overwrite the request_id if this is a status response, because there is some operations
    // (well, one really: init) that do not supply one, and status should always provide one
    if let ResponseWrapper::Status(_) = response {
        if hdr.request_id.is_none() {
            hdr.request_id = Some(0);
        }
    }

    debug!("Got the response {response:?}");

    let req_id_size = if hdr.request_id.is_some() { 4 } else { 0 };
    let length = response.get_size() + 1 + req_id_size;
    let mut buf = vec![0u8; 4 + length];
    (length as u32).serialize(&mut buf[0..4]);
    (response.get_type() as u8).serialize(&mut buf[4..5]);
    if let Some(req_id) = hdr.request_id {
        req_id.serialize(&mut buf[5..9]);
    }
    response.serialize(&mut buf[5 + req_id_size..]);

    trace!("Writing {buf:?}");
    output.write_all(&buf)?;
    output.flush()?;

    trace!("Response written");

    Ok(())
}

fn main() -> Result<(), Error> {
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "smicro".into(),
        pid: 0,
    };

    let logger = syslog::unix(formatter)?;
    log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
        .map(|()| log::set_max_level(LevelFilter::Info))?;

    let mut input = stdin().lock();
    let mut output = stdout().lock();

    let mut buf: Vec<u8> = Vec::with_capacity(MAX_PKT_SIZE);

    let mut state = GlobalState::new();
    loop {
        let res = parse_command(buf.as_slice());
        match res {
            Err(Err::Incomplete(_)) => {
                trace!("Not enough data, trying to read more from stdin");
                let mut tmp_buf = [0u8; 8192];
                let written = input.read(&mut tmp_buf)?;
                trace!("Read {written} bytes");
                if written == 0 {
                    info!("The client closed the connection, shutting down");
                    return Ok(());
                }
                buf.extend_from_slice(&tmp_buf[0..written]);
            }
            Err(e) => {
                error!("Got an error while trying to parse the packet: {:?}", e);
                debug!("The data that triggered the error was: {:?}", buf);
                return Err(Error::InvalidPacket);
            }

            Ok((next_data, pkt)) => {
                // TODO: do this with less overhead
                let mut new_buf = Vec::with_capacity(MAX_PKT_SIZE);
                new_buf.extend_from_slice(next_data);
                buf = new_buf;
                process_command(&mut output, &mut state, pkt)?;
            }
        }
    }
}
