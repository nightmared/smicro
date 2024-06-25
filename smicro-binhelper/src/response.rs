use std::io::Write;

use smicro_macros::{
    declare_response_packet, implement_responsepacket_on_enum, serialize_variants_in_enum,
};
use smicro_types::serialize::SerializePacket;
use smicro_types::sftp::types::{Attrs, Extension, ResponseType, Stat, StatusCode};
use smicro_types::ssh::types::{SSHSlice, SharedSSHSlice};

#[derive(Debug)]
#[implement_responsepacket_on_enum]
#[serialize_variants_in_enum]
pub enum ResponseWrapper<'a> {
    Status(ResponseStatus),
    Version(ResponseVersion),
    Name(ResponseName),
    Handle(ResponseHandle),
    Data(ResponseData<'a>),
    Attrs(ResponseAttrs),
    ExtendedReply(ResponseExtendedReply),
}

pub trait ResponsePacket {
    fn get_type(&self) -> ResponseType;
}

#[declare_response_packet(packet_type = ResponseType::Name)]
pub struct ResponseName {
    pub count: u32,
    pub names: Vec<Stat>,
    pub end_of_list: bool,
}

#[declare_response_packet(packet_type = ResponseType::Version)]
pub struct ResponseVersion {
    pub version: u32,
    // TODO: allow a dynamic length for that field
    pub extensions: Vec<Extension>,
}

#[declare_response_packet(packet_type = ResponseType::Status)]
pub struct ResponseStatus {
    pub status_code: StatusCode,
    pub error_message: &'static str,
    pub language: &'static str,
}

impl ResponseStatus {
    pub fn new(code: StatusCode) -> Self {
        let error_message = match code {
            StatusCode::Ok => "Success",
            StatusCode::Eof => "End of file",
            StatusCode::NoSuchFile => "No such file",
            StatusCode::PermissionDenied => "Permission denied",
            StatusCode::Failure => "Failure",
            StatusCode::BadMessage => "Bad message",
            StatusCode::NoConnection => "No connection",
            StatusCode::ConnectionLost => "Connection lost",
            StatusCode::OpUnsupported => "Operation unsupported",
        };

        Self {
            status_code: code,
            error_message,
            language: "",
        }
    }
}

#[declare_response_packet(packet_type = ResponseType::Handle)]
pub struct ResponseHandle {
    pub handle: String,
}

#[declare_response_packet(packet_type = ResponseType::Data)]
pub struct ResponseData<'a> {
    pub data: SharedSSHSlice<'a, u8>,
}

#[declare_response_packet(packet_type = ResponseType::Attrs)]
pub struct ResponseAttrs {
    pub attrs: Attrs,
}

#[declare_response_packet(packet_type = ResponseType::ExtendedReply)]
pub struct ResponseExtendedReply {
    pub data: Vec<u8>,
}
