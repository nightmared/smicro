#[derive(
    Debug, Clone, Copy, Eq, PartialEq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive,
)]
#[repr(u8)]
pub enum MessageType {
    KexInit = 20,
    KexEcdhInit = 30,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NameList {
    pub entries: Vec<String>,
}
