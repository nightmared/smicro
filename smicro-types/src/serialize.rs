use std::{io::Write, os::unix::prelude::OsStrExt};

use crate::ssh::types::{SSHSlice, SharedSSHSlice, SharedSlowSSHSlice, SlowSSHSlice};

pub trait SerializePacket {
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

impl SerializePacket for usize {
    fn get_size(&self) -> usize {
        8
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        if std::mem::size_of::<usize>() > 8 && self >> 8 > 0 {
            panic!("Serializing usize over 64 bytes is not supported");
        }
        output.write_all(&(*self as u64).to_be_bytes())
    }
}

impl SerializePacket for &str {
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

#[macro_export]
macro_rules! serializepacket_iterator_over_elements {
    ($t:ty, $($key:tt)*) => {
        impl<$($key)*> SerializePacket for $t {
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
    };
}

serializepacket_iterator_over_elements!([T; N], T: SerializePacket, const N: usize);

impl SerializePacket for &[u8] {
    fn get_size(&self) -> usize {
        self.len()
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        output.write_all(self)?;

        Ok(())
    }
}

impl SerializePacket for Vec<u8> {
    fn get_size(&self) -> usize {
        self.as_slice().get_size()
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        self.as_slice().serialize(output)
    }
}

impl<T: SerializePacket> SerializePacket for SSHSlice<T>
where
    for<'a> &'a [T]: SerializePacket,
{
    fn get_size(&self) -> usize {
        SharedSSHSlice(self.0.as_ref()).get_size()
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        SharedSSHSlice(self.0.as_ref()).serialize(output)
    }
}

impl<T: SerializePacket> SerializePacket for SharedSSHSlice<'_, T>
where
    for<'a> &'a [T]: SerializePacket,
{
    fn get_size(&self) -> usize {
        4 + self.0.get_size()
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        (self.0.len() as u32).serialize(&mut output)?;
        self.0.serialize(output)
    }
}

impl<T: SerializePacket> SerializePacket for SharedSlowSSHSlice<'_, T> {
    fn get_size(&self) -> usize {
        4 + self.0.iter().fold(0, |acc, elem| acc + elem.get_size())
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        (self.0.len() as u32).serialize(&mut output)?;

        for item in self.0 {
            item.serialize(&mut output)?;
        }

        Ok(())
    }
}

impl<T: SerializePacket> SerializePacket for SlowSSHSlice<T> {
    fn get_size(&self) -> usize {
        SharedSlowSSHSlice(&self.0).get_size()
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        SharedSlowSSHSlice(&self.0).serialize(output)
    }
}

impl<T: SerializePacket> SerializePacket for Option<T> {
    fn get_size(&self) -> usize {
        if let Some(obj) = self {
            1 + obj.get_size()
        } else {
            1
        }
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        if let Some(obj) = self {
            let _ = output.write(&[1])?;
            obj.serialize(output)
        } else {
            output.write(&[0]).map(|_| ())
        }
    }
}
