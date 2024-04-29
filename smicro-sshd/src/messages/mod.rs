use std::io::Write;

use nom::{number::complete::be_u32, Parser};

use smicro_macros::{declare_deserializable_struct, gen_serialize_impl};
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
    gen_kex_initial_list, negotiate_alg_host_key_algorithms, MessageKexEcdhInit,
    MessageKexEcdhReply, MessageKeyExchangeInit,
};

pub trait Message<'a>: Sized {
    fn get_message_type() -> MessageType;
}

#[gen_serialize_impl]
#[declare_deserializable_struct]
pub struct MessageNewKeys {}

impl<'a> Message<'a> for MessageNewKeys {
    fn get_message_type() -> MessageType {
        MessageType::NewKeys
    }
}

#[declare_deserializable_struct]
pub struct MessageServiceRequest<'a> {
    #[field(parser = parse_utf8_slice)]
    service_name: &'a str,
}

#[gen_serialize_impl]
pub struct MessageServiceAccept<'a> {
    pub service_name: &'a str,
}

impl<'a> Message<'a> for MessageServiceAccept<'a> {
    fn get_message_type() -> MessageType {
        MessageType::ServiceAccept
    }
}

#[repr(u32)]
#[derive(Copy, Clone)]
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

#[gen_serialize_impl]
pub struct MessageDisconnect<'a> {
    reason: DisconnectReason,
    description: &'a str,
    language: &'a str,
}

impl<'a> Message<'a> for MessageDisconnect<'a> {
    fn get_message_type() -> MessageType {
        MessageType::Disconnect
    }
}

impl<'a> MessageDisconnect<'a> {
    pub fn new(reason: DisconnectReason) -> MessageDisconnect<'static> {
        MessageDisconnect {
            reason,
            description: "",
            language: "",
        }
    }
}

#[gen_serialize_impl]
pub struct MessageUnimplemented {
    pub sequence_number: u32,
}

impl<'a> Message<'a> for MessageUnimplemented {
    fn get_message_type() -> MessageType {
        MessageType::Unimplemented
    }
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

#[gen_serialize_impl]
pub struct MessageUserAuthFailure {
    pub allowed_auth_methods: NameList,
    pub partial_success: bool,
}

impl<'a> Message<'a> for MessageUserAuthFailure {
    fn get_message_type() -> MessageType {
        MessageType::UserAuthFailure
    }
}

#[gen_serialize_impl]
pub struct MessageUserAuthSuccess {}

impl<'a> Message<'a> for MessageUserAuthSuccess {
    fn get_message_type() -> MessageType {
        MessageType::UserAuthSuccess
    }
}

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

#[gen_serialize_impl]
pub struct MessageUserAuthPublicKeyOk<'a> {
    pub public_key_alg_name: &'a str,
    pub public_key_blob: SharedSSHSlice<'a, u8>,
}

impl<'a> Message<'a> for MessageUserAuthPublicKeyOk<'a> {
    fn get_message_type() -> MessageType {
        MessageType::UserAuthPublickKeyOk
    }
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
#[derive(Copy, Clone)]
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

#[gen_serialize_impl]
pub struct MessageChannelOpenFailure<'a> {
    recipient_channel: u32,
    reason: ChannelOpenFailureReason,
    description: &'a str,
    language: &'a str,
}

impl<'a> Message<'a> for MessageChannelOpenFailure<'a> {
    fn get_message_type() -> MessageType {
        MessageType::ChannelOpenFailure
    }
}

impl<'a> MessageChannelOpenFailure<'a> {
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

#[gen_serialize_impl]
pub struct MessageChannelOpenConfirmation {
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub max_pkt_size: u32,
}

impl<'a> Message<'a> for MessageChannelOpenConfirmation {
    fn get_message_type() -> MessageType {
        MessageType::ChannelOpenConfirmation
    }
}

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

#[gen_serialize_impl]
pub struct MessageChannelFailure {
    pub recipient_channel: u32,
}

impl<'a> Message<'a> for MessageChannelFailure {
    fn get_message_type() -> MessageType {
        MessageType::ChannelFailure
    }
}

#[gen_serialize_impl]
pub struct MessageChannelSuccess {
    pub recipient_channel: u32,
}

impl<'a> Message<'a> for MessageChannelSuccess {
    fn get_message_type() -> MessageType {
        MessageType::ChannelSuccess
    }
}

#[gen_serialize_impl]
#[declare_deserializable_struct]
pub struct MessageChannelData<'a> {
    #[field(parser = be_u32)]
    pub recipient_channel: u32,
    #[field(parser = parse_slice.map(SharedSSHSlice))]
    pub data: SharedSSHSlice<'a, u8>,
}

impl<'a> Message<'a> for MessageChannelData<'a> {
    fn get_message_type() -> MessageType {
        MessageType::ChannelData
    }
}
