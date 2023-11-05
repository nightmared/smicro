use std::{
    fs::{canonicalize, metadata, symlink_metadata, OpenOptions},
    os::unix::prelude::{FileExt, OpenOptionsExt},
    path::PathBuf,
    str::FromStr,
};

use log::debug;
use nom::{
    number::complete::{be_u32, be_u64},
    Parser,
};

use smicro_macros::declare_command_packet;

use crate::{
    deserialize::{
        parse_attrs, parse_open_modes, parse_string, parse_utf8_string, parse_version,
        DeserializeSftp,
    },
    error::Error,
    response::{
        Response, ResponseAttrs, ResponseData, ResponseHandle, ResponseName, ResponseStatus,
        ResponseVersion,
    },
    state::GlobalState,
    types::{Attrs, AttrsFlags, HandleType, OpenModes, SSHString, Stat, StatusCode},
    MAX_READ_LENGTH,
};

#[derive(Debug, Eq, PartialEq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
#[repr(u8)]
pub enum CommandType {
    Init = 1,
    Open = 3,
    Close = 4,
    Read = 5,
    Write = 6,
    Lstat = 7,
    Fstat = 8,
    //Setstat = 9,
    //Fsetstat = 10,
    Opendir = 11,
    Readdir = 12,
    //Remove = 13,
    //Mkdir = 14,
    //Rmdir = 15,
    Realpath = 16,
    Stat = 17,
    //Rename = 18,
    //Readlink = 19,
    //Link = 21,
    //Block = 22,
    //Unblock = 23,
    //Extended = 200,
    //ExtendedReply = 201,
}

pub trait Command: std::fmt::Debug {
    fn process(&self, global_state: &mut GlobalState) -> Result<Response, Error>;
}

#[derive(Debug)]
#[declare_command_packet(packet_type = CommandType::Init)]
pub struct CommandInit {
    #[field(parser = parse_version)]
    version: u32,
}

impl Command for CommandInit {
    fn process(&self, _global_state: &mut GlobalState) -> Result<Response, Error> {
        // TODO: handle properly the supported client sftp version
        Ok(Response::Version(ResponseVersion {
            version: self.version,
            extensions: Vec::new(),
        }))
    }
}

#[derive(Debug)]
#[declare_command_packet(packet_type = CommandType::Realpath)]
pub struct CommandRealpath {
    #[field(parser = parse_utf8_string)]
    original_path: String,
}

impl Command for CommandRealpath {
    fn process(&self, _global_state: &mut GlobalState) -> Result<Response, Error> {
        let canonicalized_path = canonicalize(&self.original_path)?.into_os_string();
        Ok(Response::Name(ResponseName {
            count: 1,
            names: vec![Stat {
                filename: canonicalized_path.clone(),
                long_filename: canonicalized_path,
                attrs: Attrs::new(),
            }],
            end_of_list: true,
        }))
    }
}

#[derive(Debug)]
#[declare_command_packet(packet_type = CommandType::Opendir)]
pub struct CommandOpendir {
    #[field(parser = parse_utf8_string)]
    dir_path: String,
}

impl Command for CommandOpendir {
    fn process(&self, global_state: &mut GlobalState) -> Result<Response, Error> {
        let dir_path = PathBuf::from_str(&self.dir_path)?;
        if !dir_path.is_dir() {
            return Ok(Response::Status(ResponseStatus::new(
                StatusCode::NotADirectory,
            )));
        }

        let dir_list = dir_path.read_dir()?;

        let handle = global_state.create_dir_handle(dir_path, dir_list);

        Ok(Response::Handle(ResponseHandle { handle }))
    }
}

#[derive(Debug)]
#[declare_command_packet(packet_type = CommandType::Readdir)]
pub struct CommandReaddir {
    #[field(parser = parse_utf8_string)]
    handle: String,
}

impl Command for CommandReaddir {
    fn process(&self, global_state: &mut GlobalState) -> Result<Response, Error> {
        let (_name, dir_list) = global_state.get_dir_handle(&self.handle)?;

        let mut names = ResponseName {
            count: 0,
            names: Vec::with_capacity(100),
            end_of_list: false,
        };

        // We iterate in loops of 250 entries, to try to stay being the packet size limit.
        // This doesn't looks great (and isn't), but this is acceptable for a PoC, as that's
        // what the SFTP server in OpenSSH does does too
        // (https://github.com/openssh/openssh-portable/blob/fb06f9b5a065dfbbef5916fc4accc03c0bf026dd/sftp-server.c#L1169C21-L1169C21)
        for entry in dir_list.take(100) {
            let entry = entry?;
            let metadata = entry.metadata()?;
            names
                .names
                .push(Stat::generate_from_path(entry.file_name(), metadata, true)?);
            names.count += 1;
        }

        if names.count == 0 {
            return Err(Error::StatusCode(StatusCode::Eof));
        }

        let iteration_finished = dir_list.peek().is_none();
        if iteration_finished {
            names.end_of_list = true;
        }

        Ok(Response::Name(names))
    }
}

#[derive(Debug)]
#[declare_command_packet(packet_type = CommandType::Lstat)]
pub struct CommandLstat {
    #[field(parser = parse_utf8_string)]
    filename: String,
}

impl Command for CommandLstat {
    fn process(&self, _global_state: &mut GlobalState) -> Result<Response, Error> {
        let stat = symlink_metadata(self.filename.as_str())?;
        Ok(Response::Attrs(ResponseAttrs {
            attrs: Attrs::from_metadata(&stat),
        }))
    }
}

#[derive(Debug)]
#[declare_command_packet(packet_type = CommandType::Fstat)]
pub struct CommandFstat {
    #[field(parser = parse_utf8_string)]
    handle: String,
}

impl Command for CommandFstat {
    fn process(&self, global_state: &mut GlobalState) -> Result<Response, Error> {
        let handle = match global_state.get_handle(&self.handle) {
            Some(x) => x,
            None => Err(StatusCode::InvalidHandle)?,
        };

        let meta = match &handle.ty {
            HandleType::File(fd) => fd.metadata()?,
            // unlike file where we hold a reference to the file descriptor, we must reaccess
            // the directory, hoping it didn't move under our feet
            HandleType::Directory(_) => metadata(&handle.filename)?,
        };
        Ok(Response::Attrs(ResponseAttrs {
            attrs: Attrs::from_metadata(&meta),
        }))
    }
}

#[derive(Debug)]
#[declare_command_packet(packet_type = CommandType::Stat)]
pub struct CommandStat {
    #[field(parser = parse_utf8_string)]
    filename: String,
}

impl Command for CommandStat {
    fn process(&self, _global_state: &mut GlobalState) -> Result<Response, Error> {
        let stat = metadata(self.filename.as_str())?;
        Ok(Response::Attrs(ResponseAttrs {
            attrs: Attrs::from_metadata(&stat),
        }))
    }
}

#[derive(Debug)]
#[declare_command_packet(packet_type = CommandType::Open)]
pub struct CommandOpen {
    #[field(parser = parse_utf8_string)]
    path: String,
    #[field(parser = parse_open_modes)]
    open_mode: u32,
    #[field(parser = parse_attrs)]
    attrs: Attrs,
}

impl Command for CommandOpen {
    fn process(&self, global_state: &mut GlobalState) -> Result<Response, Error> {
        let path = PathBuf::from_str(&self.path)?;
        if path.is_dir() {
            Err(StatusCode::FileIsADirectory)?;
        };

        let mut options = OpenOptions::new();
        options
            .read(self.open_mode & OpenModes::Read as u32 != 0)
            .write(self.open_mode & OpenModes::Write as u32 != 0)
            .append(self.open_mode & OpenModes::Append as u32 != 0)
            .create(self.open_mode & OpenModes::Create as u32 != 0)
            .truncate(self.open_mode & OpenModes::Truncate as u32 != 0);
        if self.attrs.attribute_flags & AttrsFlags::Permissions as u32 != 0 {
            options.mode(self.attrs.permissions.unwrap_or(0o600));
        }
        if self.open_mode & OpenModes::Exclusive as u32 != 0 {
            options.custom_flags(libc::O_EXCL);
        }
        debug!("Opening file {path:?} with options {options:?}");

        let file = options.open(&path)?;

        let handle = global_state.create_file_handle(path, file);

        Ok(Response::Handle(ResponseHandle { handle }))
    }
}

#[derive(Debug)]
#[declare_command_packet(packet_type = CommandType::Read)]
pub struct CommandRead {
    #[field(parser = parse_utf8_string)]
    handle: String,
    #[field(parser = be_u64)]
    offset: u64,
    #[field(parser = be_u32)]
    len: u32,
}

impl Command for CommandRead {
    fn process(&self, global_state: &mut GlobalState) -> Result<Response, Error> {
        let (_name, file) = global_state.get_file_handle(&self.handle)?;

        let len = if self.len as usize > MAX_READ_LENGTH {
            MAX_READ_LENGTH
        } else {
            self.len as usize
        };

        let mut buf = vec![0; len];
        let nb_read = file.read_at(&mut buf, self.offset)?;
        if nb_read == 0 {
            return Ok(Response::Status(ResponseStatus::new(StatusCode::Eof)));
        }

        buf.truncate(nb_read);

        Ok(Response::Data(ResponseData {
            data: SSHString(buf),
        }))
    }
}

#[derive(Debug)]
#[declare_command_packet(packet_type = CommandType::Write)]
pub struct CommandWrite {
    #[field(parser = parse_utf8_string)]
    handle: String,
    #[field(parser = be_u64)]
    offset: u64,
    #[field(parser = parse_string)]
    data: Vec<u8>,
}

impl Command for CommandWrite {
    fn process(&self, global_state: &mut GlobalState) -> Result<Response, Error> {
        let (_name, file) = global_state.get_file_handle(&self.handle)?;

        file.write_all_at(&self.data, self.offset)?;

        Ok(Response::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

#[derive(Debug)]
#[declare_command_packet(packet_type = CommandType::Close)]
pub struct CommandClose {
    #[field(parser = parse_utf8_string)]
    handle: String,
}

impl Command for CommandClose {
    fn process(&self, global_state: &mut GlobalState) -> Result<Response, Error> {
        global_state.close_handle(&self.handle)?;

        Ok(Response::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}
