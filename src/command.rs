use std::{
    ffi::OsString,
    fs::{
        canonicalize, metadata, read_link, remove_dir, remove_file, rename, symlink_metadata,
        DirBuilder, OpenOptions,
    },
    os::unix::{
        fs::{symlink, DirBuilderExt},
        prelude::{FileExt, OpenOptionsExt},
    },
    path::PathBuf,
    str::FromStr,
};

use log::debug;
use nom::{
    number::complete::{be_u32, be_u64},
    Parser,
};

use smicro_macros::declare_deserializable_struct;

use crate::{
    deserialize::{
        parse_attrs, parse_open_modes, parse_string, parse_utf8_string, parse_version,
        DeserializeSftp, PacketHeader,
    },
    error::{Error, ParsingError},
    extensions::{
        Extension as ExtensionTrait, ExtensionCopyData, ExtensionPosixRename, COPY_DATA_EXT,
        POSIX_RENAME_EXT,
    },
    response::{
        ResponseAttrs, ResponseData, ResponseHandle, ResponseName, ResponseStatus, ResponseVersion,
        ResponseWrapper,
    },
    state::GlobalState,
    types::{Attrs, AttrsFlags, Extension, HandleType, OpenModes, SSHString, Stat, StatusCode},
    Packet, MAX_READ_LENGTH,
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
    Remove = 13,
    Mkdir = 14,
    Rmdir = 15,
    Realpath = 16,
    Stat = 17,
    Rename = 18,
    Readlink = 19,
    Symlink = 20,
    Extended = 200,
}

pub trait Command: std::fmt::Debug {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error>;
}

#[declare_deserializable_struct]
pub struct CommandInit {
    #[field(parser = parse_version)]
    _version: u32,
}

impl Command for CommandInit {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        Ok(ResponseWrapper::Version(ResponseVersion {
            version: 3,
            extensions: vec![
                Extension {
                    name: POSIX_RENAME_EXT,
                    data: "1",
                },
                Extension {
                    name: COPY_DATA_EXT,
                    data: "1",
                },
            ],
        }))
    }
}

#[declare_deserializable_struct]
pub struct CommandRealpath {
    #[field(parser = parse_utf8_string)]
    original_path: String,
}

impl Command for CommandRealpath {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let canonicalized_path = canonicalize(self.original_path)?.into_os_string();
        Ok(ResponseWrapper::Name(ResponseName {
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

#[declare_deserializable_struct]
pub struct CommandOpendir {
    #[field(parser = parse_utf8_string)]
    dir_path: String,
}

impl Command for CommandOpendir {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let dir_path = PathBuf::from_str(&self.dir_path)?;
        if !dir_path.is_dir() {
            return Ok(ResponseWrapper::Status(ResponseStatus::new(
                StatusCode::Failure,
            )));
        }

        let dir_list = dir_path.read_dir()?;

        let handle = global_state.create_dir_handle(dir_path, dir_list);

        Ok(ResponseWrapper::Handle(ResponseHandle { handle }))
    }
}

#[declare_deserializable_struct]
pub struct CommandReaddir {
    #[field(parser = parse_utf8_string)]
    handle: String,
}

impl Command for CommandReaddir {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
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

        Ok(ResponseWrapper::Name(names))
    }
}

#[declare_deserializable_struct]
pub struct CommandLstat {
    #[field(parser = parse_utf8_string)]
    filename: String,
}

impl Command for CommandLstat {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let stat = symlink_metadata(self.filename.as_str())?;
        Ok(ResponseWrapper::Attrs(ResponseAttrs {
            attrs: Attrs::from_metadata(&stat),
        }))
    }
}

#[declare_deserializable_struct]
pub struct CommandFstat {
    #[field(parser = parse_utf8_string)]
    handle: String,
}

impl Command for CommandFstat {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let handle = match global_state.get_handle(&self.handle) {
            Some(x) => x,
            None => Err(StatusCode::Failure)?,
        };

        let meta = match &handle.ty {
            HandleType::File(fd) => fd.metadata()?,
            // unlike file where we hold a reference to the file descriptor, we must reaccess
            // the directory, hoping it didn't move under our feet
            HandleType::Directory(_) => metadata(&handle.filename)?,
        };
        Ok(ResponseWrapper::Attrs(ResponseAttrs {
            attrs: Attrs::from_metadata(&meta),
        }))
    }
}

#[declare_deserializable_struct]
pub struct CommandStat {
    #[field(parser = parse_utf8_string)]
    filename: String,
}

impl Command for CommandStat {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let stat = metadata(self.filename.as_str())?;
        Ok(ResponseWrapper::Attrs(ResponseAttrs {
            attrs: Attrs::from_metadata(&stat),
        }))
    }
}

#[declare_deserializable_struct]
pub struct CommandOpen {
    #[field(parser = parse_utf8_string)]
    path: String,
    #[field(parser = parse_open_modes)]
    open_mode: u32,
    #[field(parser = parse_attrs)]
    attrs: Attrs,
}

impl Command for CommandOpen {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let path = PathBuf::from_str(&self.path)?;
        if path.is_dir() {
            Err(StatusCode::Failure)?;
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

        Ok(ResponseWrapper::Handle(ResponseHandle { handle }))
    }
}

#[declare_deserializable_struct]
pub struct CommandRead {
    #[field(parser = parse_utf8_string)]
    handle: String,
    #[field(parser = be_u64)]
    offset: u64,
    #[field(parser = be_u32)]
    len: u32,
}

impl Command for CommandRead {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let (_name, file) = global_state.get_file_handle(&self.handle)?;

        let len = if self.len as usize > MAX_READ_LENGTH {
            MAX_READ_LENGTH
        } else {
            self.len as usize
        };

        let mut buf = vec![0; len];
        let nb_read = file.read_at(&mut buf, self.offset)?;
        if nb_read == 0 {
            return Ok(ResponseWrapper::Status(ResponseStatus::new(
                StatusCode::Eof,
            )));
        }

        buf.truncate(nb_read);

        Ok(ResponseWrapper::Data(ResponseData {
            data: SSHString(buf),
        }))
    }
}

#[declare_deserializable_struct]
pub struct CommandWrite {
    #[field(parser = parse_utf8_string)]
    handle: String,
    #[field(parser = be_u64)]
    offset: u64,
    #[field(parser = parse_string)]
    data: Vec<u8>,
}

impl Command for CommandWrite {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let (_name, file) = global_state.get_file_handle(&self.handle)?;

        file.write_all_at(&self.data, self.offset)?;

        Ok(ResponseWrapper::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

#[declare_deserializable_struct]
pub struct CommandRename {
    #[field(parser = parse_utf8_string)]
    old_path: String,
    #[field(parser = parse_utf8_string)]
    new_path: String,
}

impl Command for CommandRename {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        rename(&self.old_path, &self.new_path)?;

        Ok(ResponseWrapper::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

#[declare_deserializable_struct]
pub struct CommandReadlink {
    #[field(parser = parse_utf8_string)]
    path: String,
}

impl Command for CommandReadlink {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let path = PathBuf::from_str(&self.path)?;

        if !path.is_symlink() {
            return Ok(ResponseWrapper::Status(ResponseStatus::new(
                StatusCode::NoSuchFile,
            )));
        }

        let target: OsString = read_link(path)?.into();
        let stat = Stat {
            filename: target.clone(),
            long_filename: target,
            attrs: Attrs::new(),
        };

        Ok(ResponseWrapper::Name(ResponseName {
            count: 1,
            names: vec![stat],
            end_of_list: true,
        }))
    }
}

#[declare_deserializable_struct]
pub struct CommandSymlink {
    #[field(parser = parse_utf8_string)]
    old_path: String,
    #[field(parser = parse_utf8_string)]
    new_path: String,
}

impl Command for CommandSymlink {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        symlink(&self.old_path, &self.new_path)?;

        Ok(ResponseWrapper::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

#[declare_deserializable_struct]
pub struct CommandRemove {
    #[field(parser = parse_utf8_string)]
    path: String,
}

impl Command for CommandRemove {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        remove_file(self.path)?;

        Ok(ResponseWrapper::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

#[declare_deserializable_struct]
pub struct CommandMkdir {
    #[field(parser = parse_utf8_string)]
    path: String,
    #[field(parser = parse_attrs)]
    attrs: Attrs,
}

impl Command for CommandMkdir {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        DirBuilder::new()
            .mode(self.attrs.permissions.unwrap_or(0o777))
            .create(&self.path)?;

        Ok(ResponseWrapper::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

#[declare_deserializable_struct]
pub struct CommandRmdir {
    #[field(parser = parse_utf8_string)]
    path: String,
}

impl Command for CommandRmdir {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        remove_dir(self.path)?;

        Ok(ResponseWrapper::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

#[declare_deserializable_struct]
pub struct CommandClose {
    #[field(parser = parse_utf8_string)]
    handle: String,
}

impl Command for CommandClose {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        global_state.close_handle(&self.handle)?;

        Ok(ResponseWrapper::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

#[declare_deserializable_struct]
pub struct CommandExtended {
    #[field(parser = parse_utf8_string)]
    extension: String,
    #[field(parser = nom::combinator::rest.map(Vec::from))]
    req: Vec<u8>,
}

impl Command for CommandExtended {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        // TODO: if I find enought motivation to do so, create a dedicated macro like
        // `generate_command_wrapper!` below
        Ok(match self.extension.as_str() {
            POSIX_RENAME_EXT => {
                let (_next_data, ext) = ExtensionPosixRename::deserialize(&self.req)?;
                ext.process(global_state)?
            }
            COPY_DATA_EXT => {
                let (_next_data, ext) = ExtensionCopyData::deserialize(&self.req)?;
                ext.process(global_state)?
            }
            _ => ResponseWrapper::Status(ResponseStatus::new(StatusCode::OpUnsupported)),
        })
    }
}

macro_rules! generate_command_wrapper {
    ($($cmd:ident => $ty:ty),*) => {
        #[derive(Debug)]
        pub enum CommandWrapper {
            $($cmd($ty)),*
        }

        impl Command for CommandWrapper {
            fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
                match self {
                    $(CommandWrapper::$cmd(val) => val.process(global_state)),*
                }
            }
        }

        pub(crate) fn command_deserialize(hdr: PacketHeader<CommandType>, command_data: &[u8]) -> Result<Packet<CommandType, CommandWrapper>, nom::Err<ParsingError>> {
            match hdr.ty {
                $( CommandType::$cmd => {
                    <$ty>::deserialize(command_data).map(|(_next_data, cmd)| Packet {
                        hdr,
                        data: CommandWrapper::$cmd(cmd),
                    })
                } ),*
            }
        }
    };
}

generate_command_wrapper!(
    Init => CommandInit,
    Realpath => CommandRealpath,
    Opendir => CommandOpendir,
    Readdir => CommandReaddir,
    Close => CommandClose,
    Lstat => CommandLstat,
    Fstat => CommandFstat,
    Stat => CommandStat,
    Open => CommandOpen,
    Read => CommandRead,
    Write => CommandWrite,
    Readlink => CommandReadlink,
    Rename => CommandRename,
    Symlink => CommandSymlink,
    Extended => CommandExtended,
    Remove => CommandRemove,
    Mkdir => CommandMkdir,
    Rmdir => CommandRmdir
);
