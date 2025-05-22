use std::{array::TryFromSliceError, net::AddrParseError};

use smicro_types::{error::ParsingError, ssh::types::MessageType};

use crate::state::channel::ChannelAllocationError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Unsupported feature")]
    Unsupported,
    #[error("Invalid argument")]
    InvalidArgument,
    #[error("Could not bind the socket")]
    BindFailed(#[source] std::io::Error),
    #[error("Could not setup an epoll listener")]
    MioSetupFailed(#[source] std::io::Error),
    #[error("Could not receive an epoll event")]
    MioReceiveEventFailed(#[source] std::io::Error),
    #[error("Could not register a stream to the epoll loop")]
    MioRegistrationFailed(#[source] std::io::Error),
    #[error("Building a syslog logger failed")]
    SyslogLoggerCreationFailed(#[from] syslog::Error),
    #[error("Couldn't set a logger")]
    SetLoggerFailed(#[from] log::SetLoggerError),
    #[error("An error occured during an IO operation")]
    IoError(#[source] std::io::Error),
    #[error("A generic unix error happened")]
    UnixError(#[from] nix::Error),
    #[error("Invalid listener address")]
    InvalidListenerAddress(#[from] AddrParseError),
    #[error("Received an invalid packet")]
    InvalidPacket,
    #[error("No common MAC algorithm was found")]
    NoCommonMAC,
    #[error("No common cipher algorithm was found")]
    NoCommonCipher,
    #[error("No common Kex algorithm was found")]
    NoCommonKexAlg,
    #[error("No common signing key algorithm was found")]
    NoCommonSigningAlg,
    #[error("Error processing the client packet")]
    ProcessingFailed,
    #[error("Got data in a NEWKEYS message, this shouldn't happen")]
    DataInNewKeysMessage,
    #[error("Invalid service name in SERVICE_REQUEST")]
    InvalidServiceRequest,
    #[error("Cryptographic error: invalid length")]
    InvalidLength(#[from] digest::InvalidLength),
    #[error("Invalid UTF-8 input from the client")]
    NonUTF8String(#[from] std::str::Utf8Error),
    #[error("Could not create a buffer")]
    BufferCreationError(#[from] smicro_common::BufferCreationError),
    #[error("An error ocurred parsing a packet")]
    ParsingError(#[from] nom::Err<ParsingError>),
    #[error("This message is not allowed in the current state")]
    DisallowedMessageType(MessageType),
    #[error("Code error: this cryptographic algorithm should be implemented")]
    MissingCryptoCodePath,
    #[error("Overflow: the sequence number wrapped")]
    SequenceNumberWrapped,
    #[error("No signature provided in the authentication request")]
    NoSignatureProvided,
    #[error("A session identifier should be available")]
    MissingSessionIdentifier,
    #[error("Cannot allocate a new channel")]
    ChannelAllocationError(#[from] ChannelAllocationError),
    #[error("Invalid channel message")]
    InvalidChannelMessage,
    #[error("Could not retrieve the handle of a stdin/stdout/stderr process")]
    InvalidStdioHandle,
    #[error("The client closed the connection")]
    ConnectionClosed,
    #[error("Invalid channel: no command is registered for that channel")]
    MissingCommandInChannel,
    #[error("Requested to increase the window size beyond 4GB: aborting")]
    ExceededChannelLength,
    #[error("Could not register or unregister a channel")]
    RegistrationManagementError(#[source] std::io::Error),
    #[error("This channel request type is not supported")]
    UnsupportedChannelRequestKind,
    #[error("Cannot create an eventfd notifier")]
    EventFdCreationFailed(#[source] nix::errno::Errno),
    #[error("Cannot signal an event")]
    EventFdSignalingFailed(#[source] nix::errno::Errno),
    #[error("Invalid or undetected user name")]
    UnknownUserName,
    #[error("Key type whose support is not implemented")]
    UnsupportedKeyType,
    #[error("Fork of the child process failed")]
    ForkFailed(#[source] nix::errno::Errno),
    #[error("Could not protect the child process from illegitimate accesses")]
    ChildProtectionFailed,
    #[error("Changing user failed")]
    UserChangeFailed(#[source] nix::errno::Errno),
    #[error("Could not allocate a pty")]
    PtyAllocationFailed(#[source] nix::errno::Errno),
    #[error("Trying to spawn a command inside an already in-use channel")]
    InvalidChannelReuse,
    #[error("Couldn't open the host key directory")]
    CannotOpenHostsKeyDir(#[source] std::io::Error),
    #[error("Couldn't open a host key file")]
    CannotOpenHostkeyFile(#[source] std::io::Error),
    #[error("Couldn't stat() a file")]
    RetrievingFileInformationFailed(#[source] std::io::Error),
    #[error("Couldn't serialize a public key authentication request")]
    UserPubKeySerializationFailed(#[source] std::io::Error),
    #[error("Couldn't serialize a packet")]
    PacketSerializationFailed(#[source] std::io::Error),
    #[error("Cannot set a stream, pty or file descriptor as non-blocking")]
    SetNonBlockingFailed(#[source] std::io::Error),
    #[error("Cannot execute a program")]
    ProgramExecutionFailed(#[source] std::io::Error),
    #[error("Cannot locate the current binary")]
    LocateBinaryFailed(#[source] std::io::Error),
    #[error("Cryptographic failure")]
    CryptoOperationFailed(#[from] CryptoOperationError),
    #[error("Could not send a connection to our child")]
    ConnectionTransferFailed(#[source] std::io::Error),
    #[error("Could not retrieve a connection from our parent")]
    ConnectionRetrievalFailed(#[source] std::io::Error),
    #[error("Could not create an IO wrapper")]
    IOWrapperCreationFailed(#[source] nix::Error),
    #[error("Could not handle an event")]
    HandleEventFailed(#[source] nix::Error),
    #[error("Could not resolve a hostname")]
    DnsResolutionFailure,
    #[error("Got no entry when resolving a hostname")]
    DnsResolutionReturnedNoEntry,
    #[error("Could not connect to a remote host")]
    TcpConnectFailed,
}

#[derive(thiserror::Error, Debug)]
pub enum CryptoOperationError {
    #[error("Could not perfom a read/write")]
    IoError(#[from] std::io::Error),
    #[error("Could not sign some data")]
    SigningError,
    #[error("The packet MAC is invalid")]
    InvalidMAC,
    #[error("Invalid buffer size when performing digest calculation")]
    InvalidBufferSize(#[from] digest::InvalidBufferSize),
    #[error("Cryptographic error while doing elliptic curve operations")]
    EllipticCurveCryptoError(#[from] elliptic_curve::Error),
    #[error("Invalid point on the curve")]
    InvalidPointForEcdh,
    #[error("No host key could be found for that algorithm")]
    NoGoodHostKeyFound(&'static str),
    #[error("An error ocurred parsing a cryptography-related object")]
    ParsingError(#[from] nom::Err<ParsingError>),
    #[error("This public key is not properly encoded")]
    InvalidPublicKey,
    #[error("This signature is not properly encoded")]
    InvalidSignature,
    #[error("Could not load a private key")]
    KeyLoadingError(#[from] KeyLoadingError),
    #[error("Invalid length of the private key material")]
    InvalidPrivateKeyLength,
    #[error("Invalid length of the key for the MAC")]
    InvalidMACKeyLength,
    #[error("Invalid data size for crypto operation")]
    SliceError(#[from] TryFromSliceError),
    #[error("Could not decrypt data")]
    DecryptionError,
    #[error("Could not encrypt data")]
    EncryptionError,
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
    #[error(
        "Mismatch between the public key embedded in the key format and the automatically derived verifying key"
    )]
    VerifyingKeyMismatch,
    #[error("An error occured reading the key file")]
    IoError(#[from] std::io::Error),
    #[error("An error ocurred parsing the key")]
    ParsingError(#[from] nom::Err<ParsingError>),
}

impl From<KeyLoadingError> for Error {
    fn from(value: KeyLoadingError) -> Self {
        Error::CryptoOperationFailed(CryptoOperationError::KeyLoadingError(value))
    }
}
