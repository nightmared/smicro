use std::{
    cmp::min,
    ffi::{CString, OsString},
    fs::{
        canonicalize, metadata, read_link, remove_dir, remove_file, rename, set_permissions,
        symlink_metadata, DirBuilder, OpenOptions, Permissions,
    },
    os::unix::{
        fs::{chown, symlink, DirBuilderExt},
        prelude::{FileExt, OpenOptionsExt, OsStrExt, PermissionsExt},
    },
    path::PathBuf,
};

use libc::timespec;
use log::debug;
use nom::{
    number::complete::{be_u32, be_u64},
    Parser,
};

use smicro_macros::declare_deserializable_struct;
use smicro_types::{deserialize::DeserializePacket, error::ParsingError, sftp::types::StatusCode};
use smicro_types::{
    sftp::{
        deserialize::{
            parse_attrs, parse_open_modes, parse_pathbuf, parse_slice, parse_utf8_slice,
            parse_utf8_string, parse_version, PacketHeader,
        },
        types::{Attrs, AttrsFlags, CommandType, Extension, OpenModes, Stat},
    },
    ssh::types::SharedSSHSlice,
};

use crate::{
    error::Error,
    extensions::{
        Extension as ExtensionTrait, ExtensionCopyData, ExtensionPosixRename, COPY_DATA_EXT,
        POSIX_RENAME_EXT,
    },
    response::{
        ResponseAttrs, ResponseData, ResponseHandle, ResponseName, ResponseStatus, ResponseVersion,
        ResponseWrapper,
    },
    state::GlobalState,
    types::{generate_stat_from_path, HandleType},
    Packet, MAX_READ_LENGTH,
};

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
    #[field(parser = parse_pathbuf)]
    original_path: PathBuf,
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
    #[field(parser = parse_pathbuf)]
    dir_path: PathBuf,
}

impl Command for CommandOpendir {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        if !self.dir_path.is_dir() {
            return Ok(ResponseWrapper::Status(ResponseStatus::new(
                StatusCode::Failure,
            )));
        }

        let dir_list = self.dir_path.read_dir()?;

        let handle = global_state.create_dir_handle(self.dir_path, dir_list);

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
                .push(generate_stat_from_path(entry.file_name(), metadata, true)?);
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
    #[field(parser = parse_pathbuf)]
    filename: PathBuf,
}

impl Command for CommandLstat {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let stat = symlink_metadata(self.filename)?;
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
    #[field(parser = parse_pathbuf)]
    filename: PathBuf,
}

impl Command for CommandStat {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let stat = metadata(self.filename)?;

        Ok(ResponseWrapper::Attrs(ResponseAttrs {
            attrs: Attrs::from_metadata(&stat),
        }))
    }
}

#[declare_deserializable_struct]
pub struct CommandOpen {
    #[field(parser = parse_pathbuf)]
    path: PathBuf,
    #[field(parser = parse_open_modes)]
    open_mode: u32,
    #[field(parser = parse_attrs)]
    attrs: Attrs,
}

impl Command for CommandOpen {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        if self.path.is_dir() {
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
        debug!("Opening file {:?} with options {:?}", self.path, options);

        let file = options.open(&self.path)?;

        let handle = global_state.create_file_handle(self.path, file);

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

// use a static buffer so that there is no buffer allocation on each read
static mut READ_BUF: [u8; MAX_READ_LENGTH] = [0; MAX_READ_LENGTH];

impl Command for CommandRead {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let (_name, file) = global_state.get_file_handle(&self.handle)?;

        let mut buf = unsafe { &mut READ_BUF[..min(MAX_READ_LENGTH, self.len as usize)] };
        let nb_read = file.read_at(&mut buf, self.offset)?;
        if nb_read == 0 {
            return Ok(ResponseWrapper::Status(ResponseStatus::new(
                StatusCode::Eof,
            )));
        }

        Ok(ResponseWrapper::Data(ResponseData {
            data: unsafe { SharedSSHSlice(&READ_BUF[..nb_read]) },
        }))
    }
}

#[declare_deserializable_struct]
pub struct CommandWrite<'a> {
    #[field(parser = parse_utf8_slice)]
    handle: &'a str,
    #[field(parser = be_u64)]
    offset: u64,
    #[field(parser = parse_slice)]
    data: &'a [u8],
}

impl<'a> Command for CommandWrite<'a> {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let (_name, file) = global_state.get_file_handle(&self.handle)?;

        file.write_all_at(&self.data, self.offset)?;

        Ok(ResponseWrapper::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

#[declare_deserializable_struct]
pub struct CommandRename {
    #[field(parser = parse_pathbuf)]
    old_path: PathBuf,
    #[field(parser = parse_pathbuf)]
    new_path: PathBuf,
}

impl Command for CommandRename {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        rename(&self.old_path, &self.new_path)?;

        Ok(ResponseWrapper::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

#[declare_deserializable_struct]
pub struct CommandReadlink {
    #[field(parser = parse_pathbuf)]
    path: PathBuf,
}

impl Command for CommandReadlink {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        if !self.path.is_symlink() {
            return Ok(ResponseWrapper::Status(ResponseStatus::new(
                StatusCode::NoSuchFile,
            )));
        }

        let target: OsString = read_link(self.path)?.into();
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
    #[field(parser = parse_pathbuf)]
    old_path: PathBuf,
    #[field(parser = parse_pathbuf)]
    new_path: PathBuf,
}

impl Command for CommandSymlink {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        symlink(&self.old_path, &self.new_path)?;

        Ok(ResponseWrapper::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

#[declare_deserializable_struct]
pub struct CommandRemove {
    #[field(parser = parse_pathbuf)]
    path: PathBuf,
}

impl Command for CommandRemove {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        remove_file(self.path)?;

        Ok(ResponseWrapper::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

#[declare_deserializable_struct]
pub struct CommandMkdir {
    #[field(parser = parse_pathbuf)]
    path: PathBuf,
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
    #[field(parser = parse_pathbuf)]
    path: PathBuf,
}

impl Command for CommandRmdir {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        remove_dir(self.path)?;

        Ok(ResponseWrapper::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

#[declare_deserializable_struct]
pub struct CommandSetstat {
    #[field(parser = parse_pathbuf)]
    path: PathBuf,
    #[field(parser = parse_attrs)]
    attrs: Attrs,
}

impl Command for CommandSetstat {
    fn process(self, _global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        if let Some(size) = self.attrs.size {
            OpenOptions::new()
                .write(true)
                .open(&self.path)?
                .set_len(size)?;
        }

        if let Some(perms) = self.attrs.permissions {
            set_permissions(&self.path, Permissions::from_mode(perms))?;
        }

        if let Some(mtime) = self.attrs.mtime {
            let atime = self
                .attrs
                .atime
                .expect("Invariant error: atime is not set, but mtime is");
            let path = CString::new(self.path.as_os_str().as_bytes())?;
            let atime = timespec {
                tv_sec: atime as i64,
                tv_nsec: 0,
            };
            let mtime = timespec {
                tv_sec: mtime as i64,
                tv_nsec: 0,
            };
            let times = [atime, mtime];
            let res = unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0) };

            if res != 0 {
                Err(std::io::Error::last_os_error())?;
            }
        }

        if let Some(uid) = self.attrs.uid {
            let gid = self
                .attrs
                .gid
                .expect("Invariant error: gid is not set, but atime is");

            chown(&self.path, Some(uid), Some(gid))?;
        }

        Ok(ResponseWrapper::Status(ResponseStatus::new(StatusCode::Ok)))
    }
}

#[declare_deserializable_struct]
pub struct CommandFsetstat {
    #[field(parser = parse_utf8_string)]
    handle: String,
    #[field(parser = parse_attrs)]
    attrs: Attrs,
}

impl Command for CommandFsetstat {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        let path = match global_state
            .get_handle(&self.handle)
            .map(|h| h.filename.clone())
        {
            Some(x) => x,
            None => {
                return Ok(ResponseWrapper::Status(ResponseStatus::new(
                    StatusCode::NoSuchFile,
                )))
            }
        };

        // that's not quite as ideal on operating on the file descriptor directly, but that's a
        // good enough subsitute
        CommandSetstat {
            path,
            attrs: self.attrs,
        }
        .process(global_state)
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
pub struct CommandExtended<'a> {
    #[field(parser = parse_utf8_string)]
    extension: String,
    #[field(parser = nom::combinator::rest)]
    req: &'a [u8],
}

impl<'a> Command for CommandExtended<'a> {
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
        pub enum CommandWrapper<'a> {
            $($cmd($ty)),*
        }

        impl<'a> Command for CommandWrapper<'a> {
            fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
                match self {
                    $(CommandWrapper::$cmd(val) => val.process(global_state)),*
                }
            }
        }

        pub(crate) fn command_deserialize<'a>(hdr: PacketHeader<CommandType>, command_data: &'a [u8]) -> Result<Packet<CommandType, CommandWrapper<'a>>, nom::Err<ParsingError>> {
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
    Write => CommandWrite<'a>,
    Readlink => CommandReadlink,
    Rename => CommandRename,
    Symlink => CommandSymlink,
    Extended => CommandExtended<'a>,
    Remove => CommandRemove,
    Mkdir => CommandMkdir,
    Rmdir => CommandRmdir,
    Setstat => CommandSetstat,
    Fsetstat => CommandFsetstat
);
