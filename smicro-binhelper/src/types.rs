use std::{
    ffi::OsString,
    fs::{File, Metadata, ReadDir},
    iter::Peekable,
    os::{linux::fs::MetadataExt, unix::prelude::FileTypeExt},
    path::PathBuf,
    str::FromStr,
};

use chrono::{DateTime, Utc};
use smicro_types::sftp::types::{Attrs, Stat};

use crate::error::Error;

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

pub fn generate_stat_from_path(
    filename: OsString,
    metadata: Metadata,
    generate_long_filename: bool,
) -> Result<Stat, Error> {
    // All the subsequent unwraps inside attrs are safe because Attrs::from_metadata
    // populate all fields
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
            std::str::from_utf8(&perms)?,
            attrs.uid.unwrap(),
            attrs.gid.unwrap(),
            attrs.size.unwrap(),
            mtime
        );
        let mut long_filename = OsString::from_str(&output)?;
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
