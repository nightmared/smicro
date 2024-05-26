#[derive(
    Debug, Clone, Copy, Eq, PartialEq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive,
)]
#[repr(u8)]
pub enum MessageType {
    Disconnect = 1,
    Ignore = 2,
    Unimplemented = 3,
    Debug = 4,

    ServiceRequest = 5,
    ServiceAccept = 6,

    KexInit = 20,
    NewKeys = 21,

    KexEcdhInit = 30,
    KexEcdhReply = 31,

    UserAuthRequest = 50,
    UserAuthFailure = 51,
    UserAuthSuccess = 52,

    UserAuthPublickKeyOk = 60,

    ChannelOpen = 90,
    ChannelOpenConfirmation = 91,
    ChannelOpenFailure = 92,
    ChannelWindowAdjust = 93,
    ChannelData = 94,
    ChannelExtendedData = 95,
    ChannelEof = 96,
    ChannelClose = 97,
    ChannelRequest = 98,
    ChannelSuccess = 99,
    ChannelFailure = 100,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NameList {
    pub entries: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SSHSlice<T>(pub Vec<T>);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SharedSSHSlice<'a, T>(pub &'a [T]);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PositiveBigNum<'a>(pub &'a [u8]);
