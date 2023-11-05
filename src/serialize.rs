use std::{mem::size_of, os::unix::prelude::OsStrExt};

use crate::types::{Attrs, AttrsFlags, SSHString};

pub trait SerializeForSftp: Sized {
    fn get_size(&self) -> usize {
        size_of::<Self>()
    }

    fn serialize(&self, addr: &mut [u8]);
}

impl SerializeForSftp for bool {
    fn get_size(&self) -> usize {
        1
    }

    fn serialize(&self, addr: &mut [u8]) {
        addr[0] = if *self { 1 } else { 0 };
    }
}

impl SerializeForSftp for u8 {
    fn serialize(&self, addr: &mut [u8]) {
        addr[0] = *self;
    }
}

impl SerializeForSftp for u16 {
    fn serialize(&self, addr: &mut [u8]) {
        addr[0..size_of::<Self>()].copy_from_slice(&self.to_be_bytes());
    }
}

impl SerializeForSftp for u32 {
    fn serialize(&self, addr: &mut [u8]) {
        addr[0..size_of::<Self>()].copy_from_slice(&self.to_be_bytes());
    }
}

impl SerializeForSftp for u64 {
    fn serialize(&self, addr: &mut [u8]) {
        addr[0..size_of::<Self>()].copy_from_slice(&self.to_be_bytes());
    }
}

impl<'a> SerializeForSftp for &'a str {
    fn get_size(&self) -> usize {
        4 + self.len()
    }

    fn serialize(&self, addr: &mut [u8]) {
        (self.len() as u32).serialize(addr);
        addr[4..4 + self.len()].copy_from_slice(self.as_bytes());
    }
}

impl SerializeForSftp for String {
    fn get_size(&self) -> usize {
        4 + self.len()
    }

    fn serialize(&self, addr: &mut [u8]) {
        (self.len() as u32).serialize(addr);
        addr[4..4 + self.len()].copy_from_slice(self.as_bytes());
    }
}

impl SerializeForSftp for std::ffi::OsString {
    fn get_size(&self) -> usize {
        4 + self.len()
    }

    fn serialize(&self, addr: &mut [u8]) {
        (self.len() as u32).serialize(addr);
        addr[4..4 + self.len()].copy_from_slice(self.as_bytes());
    }
}

impl SerializeForSftp for crate::types::StatusCode {
    fn serialize(&self, addr: &mut [u8]) {
        (*self as u32).serialize(addr);
    }
}

impl<T: SerializeForSftp> SerializeForSftp for Vec<T> {
    fn get_size(&self) -> usize {
        self.as_slice().get_size()
    }

    fn serialize(&self, addr: &mut [u8]) {
        self.as_slice().serialize(addr)
    }
}

impl<'a, T: SerializeForSftp> SerializeForSftp for &'a [T] {
    fn get_size(&self) -> usize {
        self.iter().fold(0, |acc, val| acc + val.get_size())
    }

    fn serialize(&self, addr: &mut [u8]) {
        let mut size = 0;
        for val in self.iter() {
            val.serialize(&mut addr[size..]);
            size += val.get_size();
        }
    }
}

impl SerializeForSftp for SSHString {
    fn get_size(&self) -> usize {
        4 + self.0.len()
    }

    fn serialize(&self, addr: &mut [u8]) {
        (self.0.len() as u32).serialize(addr);
        addr[4..4 + self.0.len()].copy_from_slice(&self.0);
    }
}

impl SerializeForSftp for AttrsFlags {
    fn serialize(&self, addr: &mut [u8]) {
        (*self as u32).serialize(addr);
    }
}

impl SerializeForSftp for Attrs {
    fn get_size(&self) -> usize {
        let mut size = 4;
        if self.attribute_flags & AttrsFlags::Size as u32 != 0 {
            size += 8;
        }
        if self.attribute_flags & AttrsFlags::UidAndGid as u32 != 0 {
            size += 8;
        }
        if self.attribute_flags & AttrsFlags::Permissions as u32 != 0 {
            size += 4;
        }
        if self.attribute_flags & AttrsFlags::Time as u32 != 0 {
            size += 8;
        }

        size
    }

    fn serialize(&self, addr: &mut [u8]) {
        self.attribute_flags.serialize(addr);
        let mut cur_pos = 4;
        // We rely on an invariant in the code: the values are Some(_) iff the matching flag is set
        // in self.attribute_flags
        if let Some(size) = self.size {
            size.serialize(&mut addr[cur_pos..]);
            cur_pos += 8;
        }
        if let Some(uid) = self.uid {
            assert!(self.gid.is_some());
            uid.serialize(&mut addr[cur_pos..]);
            cur_pos += 4;
            self.gid.unwrap().serialize(&mut addr[cur_pos..]);
            cur_pos += 4;
        }
        if let Some(perms) = self.permissions {
            perms.serialize(&mut addr[cur_pos..]);
            cur_pos += 4;
        }
        if let Some(atime) = self.atime {
            assert!(self.mtime.is_some());
            atime.serialize(&mut addr[cur_pos..]);
            cur_pos += 4;
            self.mtime.unwrap().serialize(&mut addr[cur_pos..]);
        }
    }
}
