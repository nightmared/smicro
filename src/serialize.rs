use std::{io::Write, os::unix::prelude::OsStrExt};

use crate::types::{Attrs, AttrsFlags, SSHString};

pub trait SerializeForSftp: Sized {
    fn get_size(&self) -> usize;

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error>;
}

impl SerializeForSftp for bool {
    fn get_size(&self) -> usize {
        1
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        output.write_all(&[if *self { 1 } else { 0 }])
    }
}

impl SerializeForSftp for u8 {
    fn get_size(&self) -> usize {
        1
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        output.write_all(&[*self])
    }
}

impl SerializeForSftp for u16 {
    fn get_size(&self) -> usize {
        2
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        output.write_all(&self.to_be_bytes())
    }
}

impl SerializeForSftp for u32 {
    fn get_size(&self) -> usize {
        4
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        output.write_all(&self.to_be_bytes())
    }
}

impl SerializeForSftp for u64 {
    fn get_size(&self) -> usize {
        8
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        output.write_all(&self.to_be_bytes())
    }
}

impl<'a> SerializeForSftp for &'a str {
    fn get_size(&self) -> usize {
        4 + self.len()
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        (self.len() as u32).serialize(&mut output)?;
        output.write_all(self.as_bytes())
    }
}

impl SerializeForSftp for String {
    fn get_size(&self) -> usize {
        self.as_str().get_size()
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        self.as_str().serialize(output)
    }
}

impl SerializeForSftp for std::ffi::OsString {
    fn get_size(&self) -> usize {
        4 + self.len()
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        (self.len() as u32).serialize(&mut output)?;
        output.write_all(self.as_bytes())
    }
}

impl SerializeForSftp for SSHString {
    fn get_size(&self) -> usize {
        4 + self.0.len()
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        (self.0.len() as u32).serialize(&mut output)?;
        output.write_all(self.0.as_slice())
    }
}

impl SerializeForSftp for crate::types::StatusCode {
    fn get_size(&self) -> usize {
        4
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        (*self as u32).serialize(output)
    }
}

impl<T: SerializeForSftp> SerializeForSftp for Vec<T> {
    fn get_size(&self) -> usize {
        self.as_slice().get_size()
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        self.as_slice().serialize(output)
    }
}

impl<'a, T: SerializeForSftp> SerializeForSftp for &'a [T] {
    fn get_size(&self) -> usize {
        self.iter().fold(0, |acc, elem| acc + elem.get_size())
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        for val in self.iter() {
            val.serialize(&mut output)?;
        }

        Ok(())
    }
}

impl SerializeForSftp for AttrsFlags {
    fn get_size(&self) -> usize {
        4
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        (*self as u32).serialize(output)
    }
}

impl SerializeForSftp for Attrs {
    fn get_size(&self) -> usize {
        let mut res = self.attribute_flags.get_size();
        if let Some(size) = self.size {
            res += size.get_size();
        }
        if let Some(uid) = self.uid {
            res += 2 * uid.get_size();
        }
        if let Some(perms) = self.permissions {
            res += perms.get_size();
        }
        if let Some(atime) = self.atime {
            res += 2 * atime.get_size();
        }

        res
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        self.attribute_flags.serialize(&mut output)?;
        // We rely on an invariant in the code: the values are Some(_) iff the matching flag is set
        // in self.attribute_flags
        if let Some(size) = self.size {
            size.serialize(&mut output)?;
        }
        if let Some(uid) = self.uid {
            assert!(self.gid.is_some());
            uid.serialize(&mut output)?;
            self.gid.unwrap().serialize(&mut output)?;
        }
        if let Some(perms) = self.permissions {
            perms.serialize(&mut output)?;
        }
        if let Some(atime) = self.atime {
            assert!(self.mtime.is_some());
            atime.serialize(&mut output)?;
            self.mtime.unwrap().serialize(&mut output)?;
        }

        Ok(())
    }
}
