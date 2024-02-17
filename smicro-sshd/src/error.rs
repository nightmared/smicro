use smicro_types::{error::ParsingError, ssh::types::MessageType};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Unsupported feature")]
    Unsupported,
    #[error("Building a syslog logger failed")]
    SyslogLoggerCreationFailed(#[from] syslog::Error),
    #[error("Couldn't set a logger")]
    SetLoggerFailed(#[from] log::SetLoggerError),
    #[error("An error occured during an IO operation")]
    IoError(#[from] std::io::Error),
    #[error("Received an invalid packet")]
    InvalidPacket,
    #[error("No common MAC algorithm was found")]
    NoCommonMAC,
    #[error("No common cipher algorithm was found")]
    NoCommonCipher,
    #[error("No common Kex algorithm was found")]
    NoCommonKexAlg,
    #[error("No common host key algorithm was found")]
    NoCommonHostKeyAlg,
    #[error("Error processing the client packet")]
    ProcessingFailed,
    #[error("Invalid UTF-8 input from the client")]
    NonUTF8String(#[from] std::str::Utf8Error),
    #[error("Could not create a buffer")]
    BufferCreationError(#[from] smicro_common::BufferCreationError),
    #[error("An error ocurred parsing a packet")]
    ParsingError(#[from] nom::Err<ParsingError>),
    #[error("This message is not allowed in the current state")]
    DisallowedMessageType(MessageType),
    #[error("Cryptographic error while doing elliptic curve operations")]
    EllipticCurveCryptoError(#[from] elliptic_curve::Error),
    #[error("Code error: this cryptographic algorithm should be implemented")]
    MissingCryptoCodePath,
    #[error("Could not load a private key")]
    KeyLoadingError(#[from] KeyLoadingError),
    #[error("Could not sign some data")]
    SigningError,
}

#[derive(thiserror::Error, Debug)]
pub enum KeyLoadingError {
    #[error("Could not decode a base64 string")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("OpenSSH only support a single key per file, so we do too")]
    InvalidNumberOfKeys,
    #[error("Passphrase-protected keys are not supported")]
    PassphraseProtectedKeyUnsupported,
    #[error("Invalid validation integers inside the private key part")]
    InvalidIntegersCheck,
    #[error("Invalid block padding")]
    InvalidBlockPadding,
    #[error("This algorithm is unsupported")]
    UnsupportedSigningAlgorithm,
    #[error("A mismatch occured between the key type and its ecdsa curve")]
    EcdsaCurveMismatch,
    #[error("The private key encoding is invalid and the point cannot be retrieved")]
    InvalidEncodedPoint,
    #[error(
        "Got the identity point on the curve, that's not what we want from a public or private key"
    )]
    GotIdentityPoint,
    #[error("Could not convert the encoded point to an affine point")]
    NotAnAffinePoint,
    #[error("Could not deserialize to a secret key")]
    NotASecretKey,
    #[error("Mismatch between the public key embedded in the key format and the automatically derived verifying key")]
    VerifyingKeyMismatch,
    #[error("An error occured reading the key file")]
    IoError(#[from] std::io::Error),
    #[error("An error ocurred parsing the key")]
    ParsingError(#[from] nom::Err<ParsingError>),
}
