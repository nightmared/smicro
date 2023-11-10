use std::{convert::Infallible, ffi::NulError};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Building a syslog logger failed")]
    SyslogLoggerCreationFailed(#[from] syslog::Error),
    #[error("Couldn't set a logger")]
    SetLoggerFailed(#[from] log::SetLoggerError),
    #[error("An error occured during an IO operation")]
    IoError(#[from] std::io::Error),
    #[error("Received an invalid packet")]
    InvalidPacket,
    #[error("Invalid UTF-8 input from the client")]
    NonUTF8String(#[from] std::str::Utf8Error),
    #[error("Got a status code from the application")]
    StatusCode(#[from] crate::StatusCode),
    #[error(
        "An infallible error was triggered, this probably indicates a failure in our dependencies"
    )]
    Infallible(#[from] Infallible),
    #[error("An error ocurred parsing a packet")]
    ParsingError(#[from] nom::Err<ParsingError>),
    #[error("As a path contains a null byte, it cannot be converted to a CString")]
    NulError(#[from] NulError),
}

#[derive(thiserror::Error, Debug)]
pub enum ParsingError {
    #[error("Invalid value for a command")]
    InvalidCommandType(#[from] num_enum::TryFromPrimitiveError<crate::CommandType>),
    #[error("Error applying nom combinators")]
    NomError,
    #[error("Received an unsupported version number form the client")]
    InvalidVersionNumber(u32),
    #[error("Invalid UTF-8 input from the client")]
    FromUTF8Error(#[from] std::string::FromUtf8Error),
    #[error("Invalid value for the attribute flags")]
    InvalidAttrsFlags(u32),
    #[error("Invalid value for the open modes of a file")]
    InvalidOpenModes(u32),
}

impl<I> nom::error::ParseError<I> for ParsingError {
    fn from_error_kind(_input: I, _kind: nom::error::ErrorKind) -> Self {
        ParsingError::NomError
    }

    fn append(_: I, _: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}
