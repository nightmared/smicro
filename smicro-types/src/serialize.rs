use std::{io::Write, os::unix::prelude::OsStrExt};

use crate::ssh::types::{SSHSlice, SharedSSHSlice};

pub trait SerializePacket: Sized {
    fn get_size(&self) -> usize;

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error>;
}

impl SerializePacket for bool {
    fn get_size(&self) -> usize {
        1
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        output.write_all(&[if *self { 1 } else { 0 }])
    }
}

impl SerializePacket for u8 {
    fn get_size(&self) -> usize {
        1
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        output.write_all(&[*self])
    }
}

impl SerializePacket for u16 {
    fn get_size(&self) -> usize {
        2
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        output.write_all(&self.to_be_bytes())
    }
}

impl SerializePacket for u32 {
    fn get_size(&self) -> usize {
        4
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        output.write_all(&self.to_be_bytes())
    }
}

impl SerializePacket for u64 {
    fn get_size(&self) -> usize {
        8
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        output.write_all(&self.to_be_bytes())
    }
}

impl<'a> SerializePacket for &'a str {
    fn get_size(&self) -> usize {
        4 + self.len()
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        (self.len() as u32).serialize(&mut output)?;
        output.write_all(self.as_bytes())
    }
}

impl SerializePacket for String {
    fn get_size(&self) -> usize {
        self.as_str().get_size()
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        self.as_str().serialize(output)
    }
}

impl SerializePacket for std::ffi::OsString {
    fn get_size(&self) -> usize {
        4 + self.len()
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        (self.len() as u32).serialize(&mut output)?;
        output.write_all(self.as_bytes())
    }
}

impl<T: SerializePacket> SerializePacket for Vec<T> {
    fn get_size(&self) -> usize {
        self.as_slice().get_size()
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        self.as_slice().serialize(output)
    }
}

impl<'a, T: SerializePacket, const N: usize> SerializePacket for [T; N] {
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

impl<'a, T: SerializePacket> SerializePacket for &'a [T] {
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

impl<T: SerializePacket> SerializePacket for SSHSlice<T> {
    fn get_size(&self) -> usize {
        4 + self.0.iter().fold(0, |acc, elem| acc + elem.get_size())
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        (self.0.len() as u32).serialize(&mut output)?;
        for val in self.0.iter() {
            val.serialize(&mut output)?;
        }

        Ok(())
    }
}

impl<'a, T: SerializePacket> SerializePacket for SharedSSHSlice<'a, T> {
    fn get_size(&self) -> usize {
        4 + self.0.iter().fold(0, |acc, elem| acc + elem.get_size())
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        (self.0.len() as u32).serialize(&mut output)?;
        for val in self.0.iter() {
            val.serialize(&mut output)?;
        }

        Ok(())
    }
}
