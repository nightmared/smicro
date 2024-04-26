use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    ops::Index,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    thread,
};

use base64::engine::{general_purpose::STANDARD, Engine as _};
use log::{debug, error, info, trace, warn, LevelFilter};
use messages::{
    ChannelOpenFailureReason, CryptoAlg, DynCipher, EcdsaSha2Nistp521, IKeySigningAlgorithm,
    Message, MessageChannelData, MessageChannelOpen, MessageChannelOpenConfirmation,
    MessageChannelOpenFailure, MessageChannelRequest, MessageKeyExchangeInit, MessageServiceAccept,
    MessageUserAuthFailure, MessageUserAuthPublicKeyOk, MessageUserAuthRequest,
    MessageUserAuthSuccess, UserAuthPublickey,
};
use nom::{
    bytes::streaming::{tag, take, take_until, take_while1},
    combinator::{opt, peek},
    multi::many_till,
    sequence::{preceded, tuple},
    AsChar, IResult,
};
use rand::Rng;
use smicro_macros::declare_session_state_with_allowed_message_types;
use state::{SessionCryptoMaterials, State};
use syslog::{BasicLogger, Facility, Formatter3164};

use smicro_common::create_read_buffer;
use smicro_types::{
    deserialize::DeserializePacket,
    error::ParsingError,
    serialize::SerializePacket,
    sftp::deserialize::parse_utf8_slice,
    ssh::{
        deserialize::parse_message_type,
        types::{MessageType, NameList, SharedSSHSlice},
    },
};

mod error;
mod messages;
mod state;

use error::Error;

use crate::messages::{
    gen_kex_initial_list, DisconnectReason, MessageDisconnect, MessageKexEcdhInit, MessageNewKeys,
    MessageServiceRequest,
};

// A tad bit above the SFTP max packet size, so that we do not have too much fragmentation
// Besides, this is the same constant as OpenSSH
pub const MAX_PKT_SIZE: usize = 4096 * 64;

macro_rules! define_state_list {
    ($($name:ident),*) => {
        #[derive(Debug)]
        pub enum SessionStates {
            $($name($name)),*
        }

        impl SessionState for SessionStates {
            fn process<'a>(
                &mut self,
                state: &mut State,
                stream: &mut TcpStream,
                input: &'a mut [u8],
            ) -> Result<(&'a [u8], SessionStates), Error> {
                match self {
                    $(SessionStates::$name(val) => val.process(state, stream, input),)*
                }
            }
        }
    };
}
define_state_list!(
    UninitializedSession,
    IdentifierStringSent,
    IdentifierStringReceived,
    KexSent,
    KexReceived,
    KexReplySent,
    ExpectsServiceRequest,
    ExpectsUserAuthRequest,
    ExpectsChannelOpen,
    AcceptsChannelMessages
);

trait SessionState {
    fn process<'a>(
        &mut self,
        state: &mut State,
        stream: &mut TcpStream,
        input: &'a mut [u8],
    ) -> Result<(&'a [u8], SessionStates), Error>;
}

#[derive(Debug)]
pub struct UninitializedSession {}

impl SessionState for UninitializedSession {
    fn process<'a>(
        &mut self,
        state: &mut State,
        stream: &mut TcpStream,
        input: &'a mut [u8],
    ) -> Result<(&'a [u8], SessionStates), Error> {
        // Write the identification string
        stream.write_all(state.my_identifier_string.as_bytes())?;
        stream.write_all(b"\r\n")?;
        Ok((
            input,
            SessionStates::IdentifierStringSent(IdentifierStringSent {}),
        ))
    }
}

#[derive(Debug)]
pub struct IdentifierStringSent {}

impl SessionState for IdentifierStringSent {
    fn process<'a>(
        &mut self,
        state: &mut State,
        _stream: &mut TcpStream,
        input: &'a mut [u8],
    ) -> Result<(&'a [u8], SessionStates), Error> {
        let input = input as &[u8];
        let consume_until_carriage = &take_until(b"\r\n" as &[u8]);
        let consume_carriage = &tag(b"\r\n");
        // consume all lines not starting by SSH-
        let (input, _unused_lines) = opt(many_till(
            preceded(consume_until_carriage, consume_carriage),
            peek(tag(b"SSH-")),
        ))(input)?;

        let (input, magic) = tag(b"SSH-2.0-")(input)?;
        let (input, softwareversion) = take_while1(|c: u8| {
            let c = c.as_char();
            c.is_ascii_graphic() && c != '-'
        })(input)?;

        let (input, comment) = opt(preceded(tag(b" "), consume_until_carriage))(input)?;

        let (input, _) = consume_carriage(input)?;

        let mut peer_identifier_string = Vec::new();
        peer_identifier_string.extend_from_slice(magic);
        peer_identifier_string.extend_from_slice(softwareversion);
        if let Some(comment) = comment {
            peer_identifier_string.extend_from_slice(comment);
        }
        state.peer_identifier_string = Some(peer_identifier_string);

        // this should be free, because we check that this is ascii before, but we can't tell the
        // compiler that
        if log::log_enabled!(log::Level::Trace) {
            if let Ok(software_version) = std::str::from_utf8(softwareversion) {
                trace!("Got client with software '{}'", software_version);
            }
        }
        Ok((
            input,
            SessionStates::IdentifierStringReceived(IdentifierStringReceived {}),
        ))
    }
}

#[derive(Debug)]
pub struct IdentifierStringReceived {}

impl SessionState for IdentifierStringReceived {
    fn process<'a>(
        &mut self,
        state: &mut State,
        stream: &mut TcpStream,
        input: &'a mut [u8],
    ) -> Result<(&'a [u8], SessionStates), Error> {
        debug!("Sending the MessageKeyExchangeInit packet");
        let kex_init_msg = gen_kex_initial_list(state);
        write_message(state, stream, &kex_init_msg)?;

        Ok((
            input,
            SessionStates::KexSent(KexSent {
                my_kex_message: kex_init_msg,
            }),
        ))
    }
}

#[derive(Clone, Debug)]
pub struct KexSent {
    my_kex_message: MessageKeyExchangeInit,
}

#[declare_session_state_with_allowed_message_types(structure = KexSent, msg_type = MessageType::KexInit)]
fn process(message_data: &[u8]) {
    let (_, msg) = MessageKeyExchangeInit::deserialize(message_data)?;
    debug!("Received {:?}", msg);
    state.crypto_algs = Some(Arc::new(msg.compute_crypto_algs()?));

    let next_state = KexReceived {
        my_kex_message: self.my_kex_message.clone(),
        peer_kex_message: msg,
    };

    Ok((next, SessionStates::KexReceived(next_state)))
}

#[derive(Clone, Debug)]
pub struct KexReceived {
    my_kex_message: MessageKeyExchangeInit,
    peer_kex_message: MessageKeyExchangeInit,
}

#[declare_session_state_with_allowed_message_types(structure = KexReceived, msg_type = MessageType::KexEcdhInit)]
fn process(message_data: &[u8]) {
    let (_, msg) = MessageKexEcdhInit::deserialize(message_data)?;
    debug!("Received {:?}", msg);
    let crypto_algs = state
        .crypto_algs
        .as_ref()
        .ok_or(Error::MissingCryptoAlgs)?
        .clone();
    let next_state = crypto_algs.kex().perform_key_exchange(
        state,
        stream,
        &msg,
        &self.my_kex_message,
        &self.peer_kex_message,
    )?;

    write_message(state, stream, &MessageNewKeys {})?;

    Ok((next, next_state))
}

#[derive(Clone, Debug)]
pub struct KexReplySent {
    pub iv_c2s: Vec<u8>,
    pub iv_s2c: Vec<u8>,
    pub encryption_key_c2s: Vec<u8>,
    pub encryption_key_s2c: Vec<u8>,
    pub integrity_key_c2s: Vec<u8>,
    pub integrity_key_s2c: Vec<u8>,
}

#[declare_session_state_with_allowed_message_types(structure = KexReplySent, msg_type = MessageType::NewKeys)]
fn process(message_data: &[u8]) {
    if message_data != [] {
        return Err(Error::DataInNewKeysMessage);
    }

    let crypto_algs = state
        .crypto_algs
        .as_ref()
        .ok_or(Error::MissingCryptoAlgs)?
        .clone();
    let client_mac = crypto_algs
        .client_mac()
        .allocate_with_key(&self.integrity_key_c2s);
    let server_mac = crypto_algs
        .server_mac()
        .allocate_with_key(&self.integrity_key_s2c);
    let client_cipher = crypto_algs
        .client_cipher()
        .from_key(&self.encryption_key_c2s)?;
    let server_cipher = crypto_algs
        .server_cipher()
        .from_key(&self.encryption_key_s2c)?;
    let materials = SessionCryptoMaterials {
        client_mac,
        server_mac,
        client_cipher,
        server_cipher,
    };

    state.crypto_material = Some(materials);

    Ok((
        next,
        SessionStates::ExpectsServiceRequest(ExpectsServiceRequest {}),
    ))
}

#[derive(Clone, Debug)]
pub struct ExpectsServiceRequest {}

#[declare_session_state_with_allowed_message_types(structure = ExpectsServiceRequest, msg_type = MessageType::ServiceRequest)]
fn process(message_data: &[u8]) {
    let (_, msg) = MessageServiceRequest::deserialize(message_data)?;

    if msg.service_name != "ssh-userauth" {
        return Err(Error::InvalidServiceRequest);
    }

    write_message(
        state,
        stream,
        &MessageServiceAccept {
            service_name: msg.service_name,
        },
    )?;

    Ok((
        next,
        SessionStates::ExpectsUserAuthRequest(ExpectsUserAuthRequest {}),
    ))
}

#[derive(Clone, Debug)]
pub struct ExpectsUserAuthRequest {}

#[declare_session_state_with_allowed_message_types(structure = ExpectsUserAuthRequest, msg_type = MessageType::UserAuthRequest)]
fn process(message_data: &[u8]) {
    let (_, msg) = MessageUserAuthRequest::deserialize(message_data)?;

    if msg.method_name == "publickey" {
        let (_, pk) = UserAuthPublickey::deserialize(msg.method_data)?;

        if pk.public_key_alg_name == <EcdsaSha2Nistp521 as IKeySigningAlgorithm>::NAME {
            let verifier = EcdsaSha2Nistp521::new();
            let allowed_key = STANDARD.decode("AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAD2J8ayINyXiTREW9oNZ/TTveKGTAPe0orWMgMJ/unT72Lo/NUA2G4LcgCrjpunTctfT88Drq5NB5uyULw3tLMI+wBvJqL7ACK5+j9c1GDx8wZ1W5AN+hYzi1fjvMICS/MCDmG2J3KaDZOci3A5DQCtaJ7COs9BzVmJQzWFpF76QxgJJQ==").unwrap();
            if pk.public_key_blob == allowed_key {
                if pk.with_signature {
                    let sig = pk.signature.ok_or(Error::NoSignatureProvided)?;

                    let session_identifier = state
                        .session_identifier
                        .as_ref()
                        .ok_or(Error::MissingSessionIdentifier)?;
                    let mut message = Vec::new();
                    SharedSSHSlice(session_identifier.as_slice()).serialize(&mut message)?;
                    message.push(MessageType::UserAuthRequest as u8);
                    msg.user_name.serialize(&mut message)?;
                    msg.service_name.serialize(&mut message)?;
                    "publickey".serialize(&mut message)?;
                    true.serialize(&mut message)?;
                    pk.public_key_alg_name.serialize(&mut message)?;
                    SharedSSHSlice(pk.public_key_blob).serialize(&mut message)?;

                    if verifier.signature_is_valid(pk.public_key_blob, &message, sig)? {
                        write_message(state, stream, &MessageUserAuthSuccess {})?;

                        state.authentified_user = Some(msg.user_name.to_string());

                        return Ok((
                            next,
                            SessionStates::ExpectsChannelOpen(ExpectsChannelOpen {}),
                        ));
                    }
                } else {
                    write_message(
                        state,
                        stream,
                        &MessageUserAuthPublicKeyOk {
                            public_key_alg_name: pk.public_key_alg_name,
                            public_key_blob: SharedSSHSlice(pk.public_key_blob),
                        },
                    )?;

                    return Ok((next, SessionStates::ExpectsUserAuthRequest(self.clone())));
                }
            }
        }
    }
    write_message(
        state,
        stream,
        &MessageUserAuthFailure {
            allowed_auth_methods: NameList {
                entries: vec![String::from("publickey")],
            },
            partial_success: false,
        },
    )?;

    Ok((next, SessionStates::ExpectsUserAuthRequest(self.clone())))
}

#[derive(Clone, Debug)]
pub struct ExpectsChannelOpen {}

#[declare_session_state_with_allowed_message_types(structure = ExpectsChannelOpen, msg_type = MessageType::ChannelOpen)]
fn process(message_data: &[u8]) {
    let (_, msg) = MessageChannelOpen::deserialize(message_data)?;

    if msg.channel_type != "session" {
        write_message(
            state,
            stream,
            &MessageChannelOpenFailure::new(
                msg.sender_channel,
                ChannelOpenFailureReason::UnknownChannelType,
            ),
        )?;

        return Err(Error::InvalidChannelMessage);
    }

    if state.num_channels == u32::MAX {
        write_message(
            state,
            stream,
            &MessageChannelOpenFailure::new(
                msg.sender_channel,
                ChannelOpenFailureReason::ConnectFailed,
            ),
        )?;

        return Err(Error::MaxChannelNumberReached);
    }

    let channel_num = state.num_channels;
    state.num_channels += 1;

    write_message(
        state,
        stream,
        &MessageChannelOpenConfirmation {
            recipient_channel: msg.sender_channel,
            sender_channel: channel_num,
            initial_window_size: msg.initial_window_size,
            max_pkt_size: msg.max_pkt_size,
        },
    )?;

    Ok((
        next,
        SessionStates::AcceptsChannelMessages(AcceptsChannelMessages {}),
    ))
}

#[derive(Clone, Debug)]
pub struct AcceptsChannelMessages {}

#[declare_session_state_with_allowed_message_types(structure = AcceptsChannelMessages, msg_type = [MessageType::ChannelRequest])]
fn process(message_data: &[u8]) {
    let (_, msg) = MessageChannelRequest::deserialize(message_data)?;

    if msg.requested_mode == "exec" {
        let (_, command) = parse_utf8_slice(msg.channel_specific_data)?;

        // Shell injection FTW!
        // More seriously though, this will be acceptable because the user was identified
        // and this will be executed with the privileges of that target user once
        // smico properly switches rights before exec.
        let mut cmd = Command::new("/usr/bin/env")
            .arg("sh")
            .arg("-c")
            .arg(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let mut stdin = cmd.stdin.take().ok_or(Error::InvalidStdioHandle)?;
        let mut stdout = cmd.stdout.take().ok_or(Error::InvalidStdioHandle)?;
        let mut stderr = cmd.stderr.take().ok_or(Error::InvalidStdioHandle)?;

        cmd.wait()?;

        let mut buf = Vec::new();
        stderr.read_to_end(&mut buf)?;
        println!("{:?}", std::str::from_utf8(&buf));
        println!("{:?}", command);

        write_message(
            state,
            stream,
            &MessageChannelData {
                recipient_channel: msg.recipient_channel,
                data: SharedSSHSlice(buf.as_slice()),
            },
        )?;
    }
    unimplemented!()
}

fn write_message<'a, T: SerializePacket + Message<'a>, W: Write>(
    state: &mut State,
    mut stream: &mut W,
    payload: &T,
) -> Result<(), Error> {
    let mut tmp_out = Vec::new();

    let mut padding = [0u8; 256];
    state.rng.fill(&mut padding);

    let cipher = state
        .crypto_material
        .as_ref()
        .map(|mat| mat.server_cipher.as_ref());

    let mut padding_length = 4;
    // length + padding_length + message_type + payload + random_padding, max not included
    let mut real_packet_length = 4 + 1 + 1 + payload.get_size() + padding_length;
    // BAD: probable timing oracle!
    // For AEAD mode, the packet length does not count in the modulus
    while real_packet_length < 16
        || (real_packet_length - if cipher.is_some() { 4 } else { 0 }) % 8 != 0
    {
        padding_length += 1;
        real_packet_length += 1;
    }

    // the packet_length field does not count in the packet size)
    ((real_packet_length - 4) as u32).serialize(&mut tmp_out)?;
    tmp_out.write_all(&[padding_length as u8, T::get_message_type() as u8])?;
    payload.serialize(&mut tmp_out)?;
    (&padding[0..padding_length]).serialize(&mut tmp_out)?;

    if let Some(cipher) = cipher {
        cipher.encrypt(
            tmp_out.as_mut_slice(),
            state.sequence_number_s2c.0,
            &mut stream,
        )?;
    } else {
        tmp_out.as_slice().serialize(&mut stream)?;
    };

    // We only support the AEAD mode chacha20-poly1305, where MAC is disabled

    state.sequence_number_s2c += 1;
    if state.sequence_number_s2c.0 == 0 {
        return Err(Error::SequenceNumberWrapped);
    }

    Ok(())
}

fn parse_plaintext_packet<'a>(
    input: &'a [u8],
    cipher: Option<&dyn DynCipher>,
) -> IResult<&'a [u8], &'a [u8], ParsingError> {
    let (input, (length, padding_length)) = tuple((
        nom::number::streaming::be_u32,
        nom::number::streaming::be_u8,
    ))(input)?;
    if length as usize > MAX_PKT_SIZE {
        return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
            length as usize,
        )));
    }

    if length < 12 {
        warn!("Packet too small: {} bytes", length);
        return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
            length as usize,
        )));
    }

    if length <= padding_length as u32 + 1 {
        warn!("The packet size implies that the packet has no payload",);
        return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
            length as usize,
        )));
    }

    // This does not apply in the AEAD case, which is the only one currently supported
    //let multiple = if let Some(cipher) = cipher {
    //    cipher.block_size_bytes()
    //} else {
    //    8
    //};
    if cipher.is_none() {
        let multiple = 8;
        if (length + 4) as usize % multiple != 0 {
            warn!(
                "The packet size is not a multiple of {}: {} bytes",
                multiple, length
            );
            return Err(nom::Err::Failure(ParsingError::InvalidPacketLength(
                length as usize,
            )));
        }
    }

    let (input, payload) = take(length - padding_length as u32 - 1)(input)?;
    // TODO: check the padding
    let (input, padding) = take(padding_length)(input)?;

    Ok((input, payload))
}

fn parse_packet<'a>(
    input: &'a mut [u8],
    state: &mut State,
) -> IResult<&'a [u8], &'a [u8], ParsingError> {
    let cipher = state
        .crypto_material
        .as_ref()
        .map(|mat| mat.client_cipher.as_ref());

    let (next_data, res) = if let Some(cipher) = cipher {
        let (next_data, plaintext_pkt) = cipher.decrypt(input, state.sequence_number_c2s.0)?;
        let (should_be_empty, decrypted_pkt) = parse_plaintext_packet(plaintext_pkt, Some(cipher))?;
        if should_be_empty != [] {
            return Err(nom::Err::Failure(
                ParsingError::RemainingDataAfterDecryption,
            ));
        }

        (next_data, decrypted_pkt)
    } else {
        parse_plaintext_packet(input, None)?
    };

    // We only support the AEAD mode chacha20-poly1305, where MAC is disabled
    /*
    if let Some(mac) = mac {
        let (input, packet_mac) = take(mac.size_bytes())(input)?;

        mac.verify(
            &original_input[..(length + 4) as usize],
            sequence_number,
            packet_mac,
        )
        .map_err(|_| nom::Err::Failure(ParsingError::InvalidMac))?;

        res.mac = packet_mac;

        Ok((input, res))
    } else {
    */

    state.sequence_number_c2s += 1;
    if state.sequence_number_c2s.0 == 0 {
        return Err(nom::Err::Failure(ParsingError::SequenceNumberWrapped));
    }

    Ok((next_data, res))
}

fn handle_packet(mut stream: TcpStream) -> Result<(), Error> {
    let buf = create_read_buffer(MAX_PKT_SIZE)?;
    let mut data_start = 0;
    let mut cur_pos = 0;

    let mut host_keys = Vec::new();
    let test_hostkey = State::load_hostkey(&Path::new("/home/sthoby/dev-fast/smicro/host_key"))?;
    host_keys.push(test_hostkey.as_ref());
    let mut global_state = State::new(&host_keys);
    let mut state = SessionStates::UninitializedSession(UninitializedSession {});

    loop {
        let res = state.process(
            &mut global_state,
            &mut stream,
            &mut buf[data_start..cur_pos],
        );
        match res {
            Err(Error::ParsingError(nom::Err::Incomplete(_))) => {
                trace!("Not enough data, trying to read more");
                // Read enough data to hold *at least* a packet, but without overwriting previous
                // data
                let written =
                    stream.read(&mut buf[cur_pos..cur_pos + MAX_PKT_SIZE - data_start])?;
                trace!("Read {written} bytes");
                if written == 0 {
                    info!("The client closed the connection, shutting down the thread");
                    return Ok(());
                }
                cur_pos += written;
            }
            Err(Error::ParsingError(e)) => {
                error!("Got an error while trying to parse the packet: {:?}", e);
                debug!("The data that triggered the error was: {:?}", buf);

                let _ = write_message(
                    &mut global_state,
                    &mut stream,
                    &MessageDisconnect::new(DisconnectReason::ProtocolError),
                );
                return Err(Error::InvalidPacket);
            }
            Err(Error::DisallowedMessageType(MessageType::Ignore | MessageType::Debug)) => {}
            Err(e) => {
                error!("Got an error while processing the packet: {:?}", e);
                debug!("The data that triggered the error was: {:?}", buf);
                let _ = write_message(
                    &mut global_state,
                    &mut stream,
                    &MessageDisconnect::new(DisconnectReason::ProtocolError),
                );

                return Err(Error::ProcessingFailed);
            }

            Ok((next_data, new_state)) => {
                state = new_state;

                // The start of the next packet is at the beginning of the data we haven't read yet
                data_start = cur_pos - next_data.len();

                // Thanks to the properties of our doubly-mapped buffer, we can loop like this
                if data_start >= MAX_PKT_SIZE {
                    data_start %= MAX_PKT_SIZE;
                    cur_pos %= MAX_PKT_SIZE;
                }
            }
        }
    }
}

fn main() -> Result<(), Error> {
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "smicro_ssh".into(),
        pid: 0,
    };

    let logger = syslog::unix(formatter)?;
    log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
        .map(|()| log::set_max_level(LevelFilter::Trace))?;

    let listener = TcpListener::bind("127.0.0.1:2222")?;
    for stream in listener.incoming() {
        info!("Received a new connection");
        if let Ok(stream) = stream {
            thread::spawn(move || {
                if let Err(e) = handle_packet(stream) {
                    error!("Got an error while handling a stream: {:?}", e);
                }
            });
        }
    }
    Ok(())
}
