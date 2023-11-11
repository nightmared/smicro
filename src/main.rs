use std::{
    fs::File,
    io::{stdin, ErrorKind as IOErrorKind, Read, Write},
    os::fd::FromRawFd,
};

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

// this is the first multiple of a page size that span more than 256 000 (the openss-sftp max
// packet size)
pub const MAX_PKT_SIZE: usize = 4096 * 63;
pub const MAX_READ_LENGTH: usize = 255000;

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
    (length as u32).serialize(&mut output)?;
    (response.get_type() as u8).serialize(&mut output)?;
    if let Some(req_id) = hdr.request_id {
        req_id.serialize(&mut output)?;
    }
    response.serialize(&mut output)?;
    output.flush()?;

    trace!("Response written");

    Ok(())
}

unsafe fn create_read_buffer() -> Result<&'static mut [u8], Error> {
    // reserve a memory map where we map twice our memory mapping, so that there is no risk of
    // overwriting an existing memory map
    let overwritable_mapping = libc::mmap(
        std::ptr::null_mut(),
        2 * MAX_PKT_SIZE,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
        -1,
        0,
    );
    if overwritable_mapping as usize == usize::MAX {
        return Err(Error::AllocationFailed(std::io::Error::last_os_error()));
    }

    // Right now, our memory looks like this:
    // <------- overwritable_mapping ------->
    // --------------------------------------
    // | MAX_PKT_SIZE    | MAX_PKT_SIZE     |
    // --------------------------------------
    //                  | |
    //            Anonymous memory

    let fd = libc::memfd_create(b"read_buffer\0".as_ptr() as *const i8, 0);
    if fd == -1 {
        return Err(Error::VirtualFileCreationFailed(
            std::io::Error::last_os_error(),
        ));
    }

    if libc::ftruncate(fd, MAX_PKT_SIZE as i64) == -1 {
        return Err(Error::VirtualFileTruncationFailed(
            std::io::Error::last_os_error(),
        ));
    }

    let first_map = libc::mmap(
        overwritable_mapping,
        MAX_PKT_SIZE,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_FIXED | libc::MAP_SHARED,
        fd,
        0,
    );
    if first_map as usize == usize::MAX {
        return Err(Error::AllocationFailed(std::io::Error::last_os_error()));
    }

    let second_map = libc::mmap(
        overwritable_mapping.offset(MAX_PKT_SIZE as isize),
        MAX_PKT_SIZE,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_FIXED | libc::MAP_SHARED,
        fd,
        0,
    );
    if second_map as usize == usize::MAX {
        return Err(Error::AllocationFailed(std::io::Error::last_os_error()));
    }

    // Our memory now looks like this:
    // <------- overwritable_mapping ------->
    // <--- first_map ---><--- second_map -->
    // --------------------------------------
    // | MAX_PKT_SIZE    | MAX_PKT_SIZE     |
    // --------------------------------------
    //         \               /
    //          \             /
    //           \           /
    //        <-- memfd file -->
    //        -------------------
    //        | MAX_PKT_SIZE    |
    //        -------------------
    // Which means both memory areas are completely aliases,
    // and the two mapping together loop, hence forming a ringbuffer

    Ok(std::slice::from_raw_parts_mut(
        overwritable_mapping as *mut u8,
        2 * MAX_PKT_SIZE,
    ))
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
    // We do not use std::io::stdout() as it uses internally a LineWriter method that consumes a lot of CPu
    // searching for newlines
    let mut output = unsafe { File::from_raw_fd(libc::STDOUT_FILENO) };

    let buf = unsafe { create_read_buffer() }?;
    let mut data_start = 0;
    let mut cur_pos = 0;

    let mut state = GlobalState::new();
    loop {
        let res = parse_command(&buf[data_start..cur_pos]);
        match res {
            Err(Err::Incomplete(_)) => {
                trace!("Not enough data, trying to read more from stdin");
                // Read enough data to hold *at least* a packet, but without overwriting previous
                // data
                let written = input.read(&mut buf[cur_pos..cur_pos + MAX_PKT_SIZE - data_start])?;
                trace!("Read {written} bytes");
                if written == 0 {
                    info!("The client closed the connection, shutting down");
                    return Ok(());
                }
                cur_pos += written;
            }
            Err(e) => {
                error!("Got an error while trying to parse the packet: {:?}", e);
                debug!("The data that triggered the error was: {:?}", buf);
                return Err(Error::InvalidPacket);
            }

            Ok((next_data, pkt)) => {
                process_command(&mut output, &mut state, pkt)?;

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
