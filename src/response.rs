use smicro_macros::{
    declare_response_packet, implement_responsepacket_on_enum, serialize_variants_in_enum,
};

use crate::serialize::SerializeForSftp;
use crate::types::{Attrs, Extension, Stat, StatusCode};

#[derive(Debug, Eq, PartialEq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
#[repr(u8)]
pub enum ResponseType {
    Version = 2,
    Status = 101,
    Handle = 102,
    Data = 103,
    Name = 104,
    Attrs = 105,
    // Not used yet
    //ExtendedReply = 201,
}

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
    //ExtendedReply(ResponseExtendedReply),
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

#[derive(Debug)]
pub struct ResponseData<'a> {
    pub data: &'a [u8],
}

impl<'a> ResponsePacket for ResponseData<'a> {
    fn get_type(&self) -> ResponseType {
        ResponseType::Data
    }
}

#[declare_response_packet(packet_type = ResponseType::Attrs)]
pub struct ResponseAttrs {
    pub attrs: Attrs,
}

//#[declare_response_packet(packet_type = ResponseType::ExtendedReply)]
//pub struct ResponseExtendedReply {
//    pub data: Vec<u8>,
//}
