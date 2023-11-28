use std::io::Write;

use crate::serialize::SerializePacket;

use super::types::{Attrs, AttrsFlags, StatusCode};

impl SerializePacket for AttrsFlags {
    fn get_size(&self) -> usize {
        4
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        (*self as u32).serialize(output)
    }
}

impl SerializePacket for Attrs {
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

impl SerializePacket for StatusCode {
    fn get_size(&self) -> usize {
        4
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        (*self as u32).serialize(output)
    }
}
