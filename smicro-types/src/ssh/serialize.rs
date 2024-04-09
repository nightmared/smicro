use std::io::Write;

use crate::serialize::SerializePacket;

use super::types::{NameList, PositiveBigNum};

impl SerializePacket for NameList {
    fn get_size(&self) -> usize {
        // self.entries.len() - 1 is the number of ',' characters in the output
        let comma_number = if self.entries.len() > 0 {
            self.entries.len() - 1
        } else {
            0
        };
        4 + self.entries.iter().map(|entry| entry.len()).sum::<usize>() + comma_number
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        // the header size does not count
        (self.get_size() as u32 - 4).serialize(&mut output)?;
        for (pos, entry) in self.entries.iter().enumerate() {
            if pos != 0 {
                output.write_all(&[b','])?;
            }
            output.write_all(entry.as_bytes())?;
        }
        Ok(())
    }
}

impl<'a> SerializePacket for PositiveBigNum<'a> {
    fn get_size(&self) -> usize {
        let mut number_of_zero_bytes = self.0.iter().take_while(|&&b| b == 0).count();
        // prepend a NULL byte if the MSB could indicate a negative number
        if self.0[number_of_zero_bytes] & 0x80 != 0 {
            number_of_zero_bytes -= 1;
        }

        4 + self.0.len() - number_of_zero_bytes
    }

    fn serialize<W: Write>(&self, mut output: W) -> Result<(), std::io::Error> {
        let number_of_zero_bytes = self.0.iter().take_while(|&&b| b == 0).count();
        // The MSB of the first non-zero byte is set -> we need to prepend a \x00, otherwise
        // we would be expressing a negative number instead of our number, which obviously isn't
        // great if we want tehe client to understand us
        let prepend_byte = self.0[number_of_zero_bytes] & 0x80 != 0;

        ((self.0.len() - number_of_zero_bytes + if prepend_byte { 1 } else { 0 }) as u32)
            .serialize(&mut output)?;
        if prepend_byte {
            output.write_all(&[0])?;
        }

        output.write_all(&self.0[number_of_zero_bytes..])
    }
}
