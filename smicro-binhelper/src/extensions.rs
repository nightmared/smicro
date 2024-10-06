use std::fs::File;
use std::os::{
    fd::{AsRawFd, FromRawFd},
    unix::prelude::FileExt,
};
use std::path::PathBuf;

use log::debug;
use log::warn;
use nom::Parser;

use nom::number::complete::be_u64;
use smicro_macros::declare_deserializable_struct;
use smicro_types::{
    deserialize::DeserializePacket,
    sftp::{
        deserialize::{parse_pathbuf, parse_utf8_string},
        types::StatusCode,
    },
};

use crate::command::{Command, CommandRename};
use crate::error::Error;
use crate::response::{ResponseStatus, ResponseWrapper};
use crate::state::GlobalState;

pub trait Extension: std::fmt::Debug {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error>;
}

#[declare_deserializable_struct]
#[derive(Debug)]
pub struct ExtensionPosixRename {
    #[field(parser = parse_pathbuf)]
    old_path: PathBuf,
    #[field(parser = parse_pathbuf)]
    new_path: PathBuf,
}

impl Extension for ExtensionPosixRename {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        CommandRename {
            old_path: self.old_path,
            new_path: self.new_path,
        }
        .process(global_state)
    }
}

#[declare_deserializable_struct]
#[derive(Debug)]
pub struct ExtensionCopyData {
    #[field(parser = parse_utf8_string)]
    read_handle: String,
    #[field(parser = be_u64)]
    read_offset: u64,
    #[field(parser = be_u64)]
    copy_len: u64,
    #[field(parser = parse_utf8_string)]
    write_handle: String,
    #[field(parser = be_u64)]
    write_offset: u64,
}

impl Extension for ExtensionCopyData {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let (_name, read_file) = global_state.get_file_handle(&self.read_handle)?;
        // Safe because we only use this fd inside this method, and there is no concurrency: the fd
        // cannot be closed under our feet
        let read_file = unsafe { File::from_raw_fd(read_file.as_raw_fd()) };
        let (_name, write_file) = global_state.get_file_handle(&self.write_handle)?;

        if self.read_handle == self.write_handle || read_file.as_raw_fd() == write_file.as_raw_fd()
        {
            warn!("Requested a copy of data from a file unto itself");
            return Ok(ResponseWrapper::Status(ResponseStatus::new(
                StatusCode::Failure,
            )));
        }

        debug!(
            "Copying {} bytes from {}:{} to {}:{}",
            self.copy_len, self.read_handle, self.read_offset, self.write_handle, self.write_offset
        );

        // Special behaviour: if self.copy_len is zero, copy all the content of the file
        let full_copy = self.copy_len == 0;

        let mut read_offset = self.read_offset;
        let mut write_offset = self.write_offset;
        let mut remaining = if full_copy { u64::MAX } else { self.copy_len };
        while remaining > 0 {
            let mut buf = [0; 8192];
            let nb_read = read_file.read_at(&mut buf, read_offset)?;
            if nb_read == 0 {
                // We were copying all the file content and we are done -> stop there
                if full_copy {
                    break;
                }

                warn!(
                    "Unexpected end of file reading data, {} bytes were not processed",
                    remaining
                );
                return Ok(ResponseWrapper::Status(ResponseStatus::new(
                    StatusCode::Failure,
                )));
            }
            // WARNING: this is buggy for files opened with O_APPEND, the client should be wary of
            // calling this on files opened in append mode (see the documentation of `write_at`)
            write_file.write_all_at(&buf[..nb_read], write_offset)?;

            remaining = remaining.saturating_sub(nb_read as u64);
            read_offset = read_offset.wrapping_add(nb_read as u64);
            write_offset = write_offset.wrapping_add(nb_read as u64);
        }

        Ok(ResponseWrapper::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

pub const POSIX_RENAME_EXT: &str = "posix-rename@openssh.com";
pub const COPY_DATA_EXT: &str = "copy-data";
