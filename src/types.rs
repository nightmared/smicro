use std::{
    ffi::OsString,
    fs::{File, Metadata, ReadDir},
    iter::Peekable,
    os::{
        linux::fs::MetadataExt,
        unix::prelude::{FileTypeExt, PermissionsExt},
    },
    path::PathBuf,
    str::FromStr,
};

use chrono::{DateTime, Utc};
use smicro_macros::serialize_struct;

use crate::error::Error;
use crate::serialize::SerializeForSftp;

#[derive(Debug)]
pub enum HandleType {
    File(File),
    Directory(Peekable<ReadDir>),
}

#[derive(Debug)]
pub struct Handle {
    pub filename: PathBuf,
    pub ty: HandleType,
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive,
)]
#[repr(u32)]
pub enum StatusCode {
    Ok = 0,
    Eof = 1,
    NoSuchFile = 2,
    PermissionDenied = 3,
    Failure = 4,
    BadMessage = 5,
    NoConnection = 6,
    ConnectionLost = 7,
    OpUnsupported = 8,
    InvalidHandle = 9,
    NoSuchPath = 10,
    FileAlreadyExists = 11,
    WriteProtect = 12,
    NoMedia = 13,
    NoSpaceOnFilesystem = 14,
    QuotaExceeded = 15,
    LockConflict = 17,
    DirNotEmpty = 18,
    NotADirectory = 19,
    InvalidFilename = 20,
    LinkLoop = 21,
    CannotDelete = 22,
    InvalidParameter = 23,
    FileIsADirectory = 24,
    OwnerInvalid = 29,
    GroupInvalid = 30,
}

impl std::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

impl std::error::Error for StatusCode {}

#[derive(
    Debug, Copy, Clone, Eq, PartialEq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive,
)]
#[repr(u32)]
pub enum AttrsFlags {
    Size = 1,
    UidAndGid = 2,
    Permissions = 4,
    Time = 8,
}

#[derive(Debug)]
pub struct Attrs {
    pub attribute_flags: u32,
    pub size: Option<u64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub permissions: Option<u32>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
}

impl Attrs {
    pub fn new() -> Self {
        Self {
            attribute_flags: 0,
            size: None,
            uid: None,
            gid: None,
            permissions: None,
            atime: None,
            mtime: None,
        }
    }

    pub fn from_metadata(meta: &Metadata) -> Self {
        let mut res = Self::new();

        res.attribute_flags |= AttrsFlags::Permissions as u32;
        res.permissions = Some(meta.permissions().mode());

        res.attribute_flags |= AttrsFlags::Size as u32;
        res.size = Some(meta.st_size());

        res.attribute_flags |= AttrsFlags::UidAndGid as u32;
        res.uid = Some(meta.st_uid());
        res.gid = Some(meta.st_gid());

        res.attribute_flags |= AttrsFlags::Time as u32;
        // Not Y2038 proof! Alas this is how it's done in OpenSSH too...
        res.atime = Some(meta.st_atime() as u32);
        res.mtime = Some(meta.st_mtime() as u32);

        res
    }
}

#[derive(Debug)]
#[serialize_struct]
pub struct Stat {
    pub filename: OsString,
    // For most cases, long_filename holds the same entry as filename.
    // Hoewever, for readdir commands, long_filename holds the entry in the ls format
    // (e.g. "-rw-r--r--    ? 1002     1002         542B Aug  6 13:51 .bashrc")
    // The client then show the format supplied by the server (I consider this is a
    // dubious design choice, but that's the way it is :/)
    pub long_filename: OsString,
    pub attrs: Attrs,
}

fn print_perms(mode: u32) -> [u8; 9] {
    let mut perms = [b'-'; 9];
    let print = |matching_mode: u32, byte: u8| -> u8 {
        if matching_mode & mode != 0 {
            byte
        } else {
            b'-'
        }
    };

    let setuid = mode & 0o4000 != 0;
    let setgid = mode & 0o2000 != 0;
    let sticky = mode & 0o1000 != 0;
    perms[0] = print(0o400, b'r');
    perms[1] = print(0o200, b'w');
    let executable = mode & 0o100 != 0;
    perms[2] = match (executable, setuid) {
        (false, false) => b'-',
        (true, false) => b'x',
        (false, true) => b'S',
        (true, true) => b's',
    };

    perms[3] = print(0o040, b'r');
    perms[4] = print(0o020, b'w');
    let group_executable = mode & 0o010 != 0;
    perms[5] = match (group_executable, setgid) {
        (false, false) => b'-',
        (true, false) => b'x',
        (false, true) => b'S',
        (true, true) => b's',
    };

    perms[6] = print(0o004, b'r');
    perms[7] = print(0o002, b'w');
    let others_executable = mode & 0o001 != 0;
    perms[8] = match (others_executable, sticky) {
        (false, false) => b'-',
        (true, false) => b'x',
        (false, true) => b'T',
        (true, true) => b't',
    };

    perms
}

impl Stat {
    pub fn generate_from_path(
        filename: OsString,
        metadata: Metadata,
        generate_long_filename: bool,
    ) -> Result<Stat, Error> {
        let attrs = Attrs::from_metadata(&metadata);

        let long_filename = if generate_long_filename {
            let perms = print_perms(attrs.permissions.unwrap());

            let file_type = metadata.file_type();
            let prefix = if file_type.is_file() {
                '-'
            } else if file_type.is_dir() {
                'd'
            } else if file_type.is_symlink() {
                'l'
            } else if file_type.is_block_device() {
                'b'
            } else if file_type.is_fifo() {
                '|'
            } else if file_type.is_socket() {
                's'
            } else {
                '?'
            };

            let dt: Option<DateTime<Utc>> = DateTime::from_timestamp(metadata.st_mtime(), 0);
            let mtime = if let Some(dt) = dt {
                dt.to_rfc3339()
            } else {
                "?".to_string()
            };

            // safe to call unwrap(): we crafted this slice with ascii characters ourselves
            let output = format!(
                "{}{} ? {:>7} {:>7} {:>12} {} ",
                prefix,
                std::str::from_utf8(&perms).unwrap(),
                attrs.uid.unwrap(),
                attrs.gid.unwrap(),
                attrs.size.unwrap(),
                mtime
            );
            let mut long_filename = OsString::from_str(&output).unwrap();
            long_filename.push(&filename);
            long_filename
        } else {
            filename.clone()
        };

        Ok(Stat {
            filename,
            long_filename,
            attrs,
        })
    }
}

#[derive(Debug)]
#[repr(u32)]
pub enum OpenModes {
    Read = 1,
    Write = 2,
    Append = 4,
    Create = 8,
    Truncate = 16,
    Exclusive = 32,
}

#[derive(Debug)]
#[serialize_struct]
pub struct Extension {
    name: String,
    data: String,
}

#[derive(Debug)]
pub struct SSHString(pub Vec<u8>);
