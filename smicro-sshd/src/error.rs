use smicro_types::error::ParsingError;

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
    #[error("Error processing the client packet")]
    ProcessingFailed,
    #[error("Invalid UTF-8 input from the client")]
    NonUTF8String(#[from] std::str::Utf8Error),
    #[error("Could not create a buffer")]
    BufferCreationError(#[from] smicro_common::BufferCreationError),
    #[error("An error ocurred parsing a packet")]
    ParsingError(#[from] nom::Err<ParsingError>),
}
