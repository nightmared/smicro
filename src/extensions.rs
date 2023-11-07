use nom::Parser;

use smicro_macros::declare_deserializable_struct;

use crate::command::Command;
use crate::command::CommandRename;
use crate::deserialize::parse_utf8_string;
use crate::deserialize::DeserializeSftp;
use crate::error::Error;
use crate::response::ResponseWrapper;
use crate::state::GlobalState;

pub trait Extension: std::fmt::Debug {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error>;
}

#[declare_deserializable_struct]
pub struct ExtensionPosixRename {
    #[field(parser = parse_utf8_string)]
    old_path: String,
    #[field(parser = parse_utf8_string)]
    new_path: String,
}

impl Extension for ExtensionPosixRename {
    fn process(self, global_state: &mut GlobalState) -> Result<ResponseWrapper, Error> {
        CommandRename {
            old_path: self.old_path,
            new_path: self.new_path,
        }
        .process(global_state)
    }
}

pub const POSIX_RENAME_EXT: &'static str = "posix-rename@openssh.com";
