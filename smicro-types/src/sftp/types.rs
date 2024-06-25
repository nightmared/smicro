use std::{
    ffi::OsString,
    fs::Metadata,
    io::Write,
    os::{linux::fs::MetadataExt, unix::prelude::PermissionsExt},
};

use crate::{serialize::SerializePacket, serializepacket_iterator_over_elements};

use smicro_macros::gen_serialize_impl;

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
#[gen_serialize_impl]
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

serializepacket_iterator_over_elements!(Vec<Stat>,);

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
    Setstat = 9,
    Fsetstat = 10,
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

#[derive(Debug, Eq, PartialEq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
#[repr(u8)]
pub enum ResponseType {
    Version = 2,
    Status = 101,
    Handle = 102,
    Data = 103,
    Name = 104,
    Attrs = 105,
    ExtendedReply = 201,
}

#[derive(Debug, Copy, Clone)]
#[gen_serialize_impl]
pub struct Extension {
    pub name: &'static str,
    pub data: &'static str,
}

serializepacket_iterator_over_elements!(Vec<Extension>,);
