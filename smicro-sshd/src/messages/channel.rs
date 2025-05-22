use std::io::Write;

use nom::Parser;
use nom::number::complete::be_u32;

use smicro_macros::{declare_deserializable_struct, declare_message};
use smicro_types::sftp::deserialize::parse_utf8_slice;
use smicro_types::{
    deserialize::DeserializePacket,
    serialize::SerializePacket,
    sftp::deserialize::parse_slice,
    ssh::{
        deserialize::parse_boolean,
        types::{MessageType, SharedSSHSlice},
    },
};

#[declare_deserializable_struct]
pub struct MessageChannelOpen<'a> {
    #[field(parser = parse_utf8_slice)]
    pub channel_type: &'a str,
    #[field(parser = be_u32)]
    pub sender_channel: u32,
    #[field(parser = be_u32)]
    pub initial_window_size: u32,
    #[field(parser = be_u32)]
    pub max_pkt_size: u32,
    #[field(parser = nom::combinator::rest)]
    pub channel_specific_data: &'a [u8],
}

#[derive(Debug)]
#[declare_deserializable_struct]
pub struct DirectTcpIpMessagePart<'a> {
    #[field(parser = parse_utf8_slice)]
    pub remote_host: &'a str,
    #[field(parser = be_u32)]
    pub remote_port: u32,
    #[field(parser = parse_utf8_slice)]
    pub origin_host: &'a str,
    #[field(parser = be_u32)]
    pub origin_port: u32,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum ChannelOpenFailureReason {
    ConnectFailed = 2,
    UnknownChannelType = 3,
}

impl SerializePacket for ChannelOpenFailureReason {
    fn get_size(&self) -> usize {
        (*self as u32).get_size()
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        (*self as u32).serialize(output)
    }
}

#[declare_message(ChannelOpenFailure)]
pub struct MessageChannelOpenFailure<'a> {
    recipient_channel: u32,
    reason: ChannelOpenFailureReason,
    description: &'a str,
    language: &'a str,
}

impl MessageChannelOpenFailure<'_> {
    pub fn new(
        recipient_channel: u32,
        reason: ChannelOpenFailureReason,
    ) -> MessageChannelOpenFailure<'static> {
        MessageChannelOpenFailure {
            recipient_channel,
            reason,
            description: "",
            language: "",
        }
    }
}

#[declare_message(ChannelOpenConfirmation)]
pub struct MessageChannelOpenConfirmation {
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub max_pkt_size: u32,
}

#[declare_message(GlobalRequest)]
#[declare_deserializable_struct]
pub struct MessageGlobalRequest<'a> {
    #[field(parser = parse_utf8_slice)]
    pub request_name: &'a str,
    #[field(parser = parse_boolean)]
    pub want_reply: bool,
    #[field(parser = nom::combinator::rest)]
    pub channel_specific_data: &'a [u8],
}

#[declare_message(RequestFailure)]
pub struct MessageRequestFailure {}

#[declare_message(ChannelRequest)]
#[declare_deserializable_struct]
pub struct MessageChannelRequest<'a> {
    #[field(parser = be_u32)]
    pub recipient_channel: u32,
    #[field(parser = parse_utf8_slice)]
    pub requested_mode: &'a str,
    #[field(parser = parse_boolean)]
    pub want_reply: bool,
    #[field(parser = nom::combinator::rest)]
    pub channel_specific_data: &'a [u8],
}

#[derive(Debug)]
#[declare_deserializable_struct]
pub struct PtyReq<'a> {
    #[field(parser = parse_utf8_slice)]
    pub variable: &'a str,
    #[field(parser = be_u32)]
    pub width_chars: u32,
    #[field(parser = be_u32)]
    pub height_chars: u32,
    #[field(parser = be_u32)]
    pub width_pixels: u32,
    #[field(parser = be_u32)]
    pub height_pixels: u32,
    #[field(parser = parse_slice)]
    pub modes: &'a [u8],
}

#[declare_message(ChannelFailure)]
pub struct MessageChannelFailure {
    pub recipient_channel: u32,
}

#[declare_message(ChannelSuccess)]
pub struct MessageChannelSuccess {
    pub recipient_channel: u32,
}

#[declare_message(ChannelData)]
#[declare_deserializable_struct]
pub struct MessageChannelData<'a> {
    #[field(parser = be_u32)]
    pub recipient_channel: u32,
    #[field(parser = parse_slice.map(SharedSSHSlice))]
    pub data: SharedSSHSlice<'a, u8>,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum ChannelExtendedDataCode {
    Stderr = 1,
}

impl SerializePacket for ChannelExtendedDataCode {
    fn get_size(&self) -> usize {
        (*self as u32).get_size()
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        (*self as u32).serialize(output)
    }
}

#[declare_message(ChannelExtendedData)]
pub struct MessageChannelExtendedData<'a> {
    pub recipient_channel: u32,
    pub data_type: ChannelExtendedDataCode,
    pub data: SharedSSHSlice<'a, u8>,
}

#[declare_message(ChannelWindowAdjust)]
#[declare_deserializable_struct]
pub struct MessageChannelWindowAdjust {
    #[field(parser = be_u32)]
    pub recipient_channel: u32,
    #[field(parser = be_u32)]
    pub bytes_to_add: u32,
}

#[declare_message(ChannelEof)]
#[declare_deserializable_struct]
pub struct MessageChannelEof {
    #[field(parser = be_u32)]
    pub recipient_channel: u32,
}

#[declare_message(ChannelClose)]
#[declare_deserializable_struct]
pub struct MessageChannelClose {
    #[field(parser = be_u32)]
    pub recipient_channel: u32,
}
