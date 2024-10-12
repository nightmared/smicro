use std::io::Write;

use nom::{number::complete::be_u32, Parser};

use smicro_macros::{declare_deserializable_struct, declare_message};
use smicro_types::sftp::deserialize::parse_utf8_slice;
use smicro_types::{
    deserialize::DeserializePacket,
    serialize::SerializePacket,
    sftp::deserialize::parse_slice,
    ssh::{
        deserialize::parse_boolean,
        types::{MessageType, NameList, SharedSSHSlice},
    },
};

mod kex;

pub use self::kex::{
    gen_kex_initial_list, negotiate_alg_signing_algorithms, MessageKexEcdhInit,
    MessageKexEcdhReply, MessageKeyExchangeInit,
};

pub trait Message<'a>: Sized {
    fn get_message_type() -> MessageType;
}

#[declare_message(NewKeys)]
#[declare_deserializable_struct]
pub struct MessageNewKeys {}

#[declare_deserializable_struct]
pub struct MessageServiceRequest<'a> {
    #[field(parser = parse_utf8_slice)]
    service_name: &'a str,
}

#[declare_message(ServiceAccept)]
pub struct MessageServiceAccept<'a> {
    pub service_name: &'a str,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum DisconnectReason {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    ServiceNotAvailable = 7,
}

impl SerializePacket for DisconnectReason {
    fn get_size(&self) -> usize {
        (*self as u32).get_size()
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        (*self as u32).serialize(output)
    }
}

#[declare_message(Disconnect)]
pub struct MessageDisconnect<'a> {
    reason: DisconnectReason,
    description: &'a str,
    language: &'a str,
}

impl MessageDisconnect<'_> {
    pub fn new(reason: DisconnectReason) -> MessageDisconnect<'static> {
        MessageDisconnect {
            reason,
            description: "",
            language: "",
        }
    }
}

#[declare_message(Unimplemented)]
pub struct MessageUnimplemented {
    pub sequence_number: u32,
}

#[declare_deserializable_struct]
pub struct MessageUserAuthRequest<'a> {
    #[field(parser = parse_utf8_slice)]
    pub user_name: &'a str,
    #[field(parser = parse_utf8_slice)]
    pub service_name: &'a str,
    #[field(parser = parse_utf8_slice)]
    pub method_name: &'a str,
    #[field(parser = nom::combinator::rest)]
    pub method_data: &'a [u8],
}

#[declare_message(UserAuthFailure)]
pub struct MessageUserAuthFailure {
    pub allowed_auth_methods: NameList,
    pub partial_success: bool,
}

#[declare_message(UserAuthSuccess)]
pub struct MessageUserAuthSuccess {}

#[declare_deserializable_struct]
pub struct UserAuthPublickey<'a> {
    #[field(parser = parse_boolean)]
    pub with_signature: bool,
    #[field(parser = parse_utf8_slice)]
    pub public_key_alg_name: &'a str,
    #[field(parser = parse_slice)]
    pub public_key_blob: &'a [u8],
    #[field(parser = parse_slice, optional = true)]
    pub signature: &'a [u8],
}

#[declare_message(UserAuthPublickKeyOk)]
pub struct MessageUserAuthPublicKeyOk<'a> {
    pub public_key_alg_name: &'a str,
    pub public_key_blob: SharedSSHSlice<'a, u8>,
}

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
