use std::io::Write;

use crate::serialize::SerializePacket;

use super::types::NameList;

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
