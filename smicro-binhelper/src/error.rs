use std::{convert::Infallible, ffi::NulError};

use smicro_types::error::ParsingError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Building a syslog logger failed")]
    SyslogLoggerCreationFailed(#[from] syslog::Error),
    #[error("Couldn't set a logger")]
    SetLoggerFailed(#[from] log::SetLoggerError),
    #[error("An error occured during an IO operation")]
    Io(#[from] std::io::Error),
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
    Parsing(#[from] nom::Err<ParsingError>),
    #[error("As a path contains a null byte, it cannot be converted to a CString")]
    Nul(#[from] NulError),
    #[error("Could not create a buffer")]
    BufferCreation(#[from] smicro_common::BufferCreationError),
}
