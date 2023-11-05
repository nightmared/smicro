use smicro_macros::{
    declare_response_packet, implement_responsepacket_on_enum, serialize_variants_in_enum,
};

use crate::serialize::SerializeForSftp;
use crate::types::{Attrs, Extension, SSHString, Stat, StatusCode};

#[derive(Debug, Eq, PartialEq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
#[repr(u8)]
pub enum ResponseType {
    Version = 2,
    Status = 101,
    Handle = 102,
    Data = 103,
    Name = 104,
    Attrs = 105,
}

#[derive(Debug)]
#[implement_responsepacket_on_enum]
#[serialize_variants_in_enum]
pub enum Response {
    Status(ResponseStatus),
    Version(ResponseVersion),
    Name(ResponseName),
    Handle(ResponseHandle),
    Data(ResponseData),
    Attrs(ResponseAttrs),
}

pub trait ResponsePacket {
    fn get_type(&self) -> ResponseType;
}

#[derive(Debug)]
#[declare_response_packet(packet_type = ResponseType::Name)]
pub struct ResponseName {
    pub count: u32,
    pub names: Vec<Stat>,
    pub end_of_list: bool,
}

#[derive(Debug)]
#[declare_response_packet(packet_type = ResponseType::Version)]
pub struct ResponseVersion {
    pub version: u32,
    // TODO: allow a dynamic length for that field
    pub extensions: Vec<Extension>,
}

#[derive(Debug)]
#[declare_response_packet(packet_type = ResponseType::Status)]
pub struct ResponseStatus {
    pub status_code: StatusCode,
    pub error_message: &'static str,
    pub language: &'static str,
}

impl ResponseStatus {
    pub fn new(code: StatusCode) -> Self {
        Self {
            status_code: code,
            error_message: "",
            language: "",
        }
    }
}

#[derive(Debug)]
#[declare_response_packet(packet_type = ResponseType::Handle)]
pub struct ResponseHandle {
    pub handle: String,
}

#[derive(Debug)]
#[declare_response_packet(packet_type = ResponseType::Data)]
pub struct ResponseData {
    pub data: SSHString,
}

#[derive(Debug)]
#[declare_response_packet(packet_type = ResponseType::Attrs)]
pub struct ResponseAttrs {
    pub attrs: Attrs,
}
