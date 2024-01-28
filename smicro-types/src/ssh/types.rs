use crate::serialize::SerializePacket;

use smicro_macros::gen_serialize_impl;

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive,
)]
#[repr(u8)]
pub enum MessageType {
    KexInit = 20,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NameList {
    pub entries: Vec<String>,
}
