#[derive(thiserror::Error, Debug)]
pub enum ParsingError {
    #[error("Invalid value for a command")]
    InvalidCommandType(#[from] num_enum::TryFromPrimitiveError<crate::sftp::types::CommandType>),
    #[error("Error applying nom combinators")]
    NomError,
    #[error("Received an unsupported version number form the client")]
    InvalidVersionNumber(u32),
    #[error("Invalid UTF-8 input from the client")]
    NonUTF8String(#[from] std::str::Utf8Error),
    #[error("Invalid value for the attribute flags")]
    InvalidAttrsFlags(u32),
    #[error("Invalid value for the open modes of a file")]
    InvalidOpenModes(u32),
    #[error("Invalid packet length")]
    InvalidPacketLength(usize),
}

impl<I> nom::error::ParseError<I> for ParsingError {
    fn from_error_kind(_input: I, _kind: nom::error::ErrorKind) -> Self {
        ParsingError::NomError
    }

    fn append(_: I, _: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}
