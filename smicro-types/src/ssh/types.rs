#[derive(
    Debug, Clone, Copy, Eq, PartialEq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive,
)]
#[repr(u8)]
pub enum MessageType {
    KexInit = 20,
    NewKeys = 21,
    KexEcdhInit = 30,
    KexEcdhReply = 31,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NameList {
    pub entries: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SSHSlice<T>(pub Vec<T>);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SharedSSHSlice<'a, T>(pub &'a [T]);
