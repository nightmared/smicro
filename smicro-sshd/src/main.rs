#![feature(linux_pidfd)]
#![feature(unix_socket_ancillary_data)]

use std::{
    collections::HashSet,
    io::ErrorKind,
    os::fd::{AsFd, AsRawFd},
    path::Path,
    str::FromStr,
    thread,
};

use log::{Level, debug, error, info, trace};
use mio::{
    Events, Interest, Poll, Token,
    net::{TcpListener, TcpStream},
    unix::SourceFd,
};
use nix::{
    errno::Errno,
    sys::prctl,
    unistd::{ForkResult, fork, setgid, setuid},
};
use syslog::Facility;

use smicro_common::{LoopingBuffer, LoopingBufferReader, LoopingBufferWriter, get_atomic_writer};
use smicro_types::ssh::{deserialize::parse_message_type, types::MessageType};

mod channel;
mod child;
pub mod crypto;
pub mod error;
pub mod io;
pub mod messages;
mod options;
pub mod packet;
pub mod session;
pub mod state;

use crate::{
    channel::{flush_channel, handle_channel_data, process_channel_states},
    child::{receive_connection, transfer_connection},
    error::Error,
    io::{FdStreamManager, IOOperation, ReadFromBuffer, ReadFromStream},
    messages::{DisconnectReason, MessageDisconnect},
    options::Options,
    packet::{MAX_PKT_SIZE, write_message},
    session::{
        ExpectsChannelData, PacketProcessingDecision, SessionState, SessionStateEstablished,
        SessionStates, UninitializedSession, kex::renegotiate_kex,
    },
    state::State,
    state::{AuthMode, channel::POLL_NB_PER_CHAN},
};

enum KeepProcessing {
    Continue,
    StopDisconnected,
    StopAndTransferToChild(String),
}

fn handle_packet<const SIZE: usize, R: LoopingBufferReader<SIZE>, W: LoopingBufferWriter<SIZE>>(
    buf: &mut R,
    writer: &mut W,
    session: &mut SessionStates,
    state: &mut State,
    tmp_packet: &mut [u8; MAX_PKT_SIZE],
) -> Result<KeepProcessing, Error> {
    let available_data = buf.get_readable_data();
    let available_data_len = available_data.len();
    let mut atomic_writer = get_atomic_writer(writer);
    let res = session.process(state, &mut atomic_writer, available_data, tmp_packet);

    match res {
        Err(e) => match e {
            Error::ParsingError(nom::Err::Incomplete(_)) => {
                // forward the signal that se need more data
                Err(e)
            }
            Error::ParsingError(e) => {
                error!("Got an error while trying to parse the packet: {:?}", e);
                debug!(
                    "The data that triggered the error was: {:?}",
                    buf.get_readable_data()
                );
                let _ = write_message(
                    &mut state.sender,
                    writer,
                    &MessageDisconnect::new(DisconnectReason::ProtocolError),
                );

                Err(Error::InvalidPacket)
            }
            Error::DisallowedMessageType(MessageType::Ignore | MessageType::Debug) => {
                trace!("Received an Ignore or Debug message, skipping processing of that jessage");
                Ok(KeepProcessing::Continue)
            }
            e => {
                error!("Got an error while processing the packet: {:?}", e);
                debug!(
                    "The data that triggered the error was: {:?}",
                    buf.get_readable_data()
                );
                let _ = write_message(
                    &mut state.sender,
                    writer,
                    &MessageDisconnect::new(DisconnectReason::ProtocolError),
                );

                Err(Error::ProcessingFailed)
            }
        },
        Ok((next_data, processing_decision)) => {
            // register the writes so they can be sent to the client
            let written_data = atomic_writer.commit();
            state.sender.bytes_counter += written_data;

            let read_data = available_data_len - next_data.len();
            buf.advance_reader_pos(read_data);
            state.receiver.bytes_counter += read_data as u64;

            match processing_decision {
                PacketProcessingDecision::NewState(new_session) => {
                    *session = new_session;

                    Ok(KeepProcessing::Continue)
                }
                PacketProcessingDecision::SpawnChild(username) => {
                    Ok(KeepProcessing::StopAndTransferToChild(username))
                }
                PacketProcessingDecision::PeerTriggeredDisconnection => {
                    Ok(KeepProcessing::StopDisconnected)
                }
            }
        }
    }
}

fn handle_packets<const SIZE: usize, R: LoopingBufferReader<SIZE>, W: LoopingBufferWriter<SIZE>>(
    reader_buf: &mut R,
    sender_buf: &mut W,
    session: &mut SessionStates,
    state: &mut State,
    tmp_packet: &mut [u8; MAX_PKT_SIZE],
) -> Result<KeepProcessing, Error> {
    loop {
        // rekey every two gigabytes
        let rekey_limit = 2 * 1024 * 1024 * 1024;
        if state.rekeying.is_none()
            && (state.sender.bytes_counter > rekey_limit
                || state.receiver.bytes_counter > rekey_limit)
        {
            info!("Initiating rekeying");
            match renegotiate_kex(state, sender_buf) {
                Ok(x) => state.rekeying = Some(x),
                Err(e) => debug!("Failed to trigger rekeying ({:?}, retrying later", e),
            }

            return Ok(KeepProcessing::Continue);
        }
        match handle_packet(reader_buf, sender_buf, session, state, tmp_packet) {
            Ok(KeepProcessing::Continue) => {}
            Ok(x) => return Ok(x),
            Err(Error::ParsingError(nom::Err::Incomplete(_))) => {
                trace!("Not enough data to parse the packet, trying to read more");
                return Ok(KeepProcessing::Continue);
            }
            Err(Error::IoError(e)) if e.kind() == ErrorKind::WouldBlock => {
                return Ok(KeepProcessing::Continue);
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}

fn handle_stream(
    stream: TcpStream,
    auth_mode: AuthMode,
    enable_command_execution: bool,
    host_keys_dir: &Path,
) -> Result<(), Error> {
    let reader_buf = <LoopingBuffer<MAX_PKT_SIZE>>::new()?;
    let sender_buf = <LoopingBuffer<MAX_PKT_SIZE>>::new()?;

    let state = State::new(auth_mode, enable_command_execution, host_keys_dir)?;
    let session = SessionStates::UninitializedSession(UninitializedSession {});

    handle_stream_with_preexisting_state(stream, reader_buf, sender_buf, state, session)
}

fn handle_stream_with_preexisting_state(
    stream: TcpStream,
    reader_buf: LoopingBuffer<MAX_PKT_SIZE>,
    sender_buf: LoopingBuffer<MAX_PKT_SIZE>,
    mut state: State,
    mut session: SessionStates,
) -> Result<(), Error> {
    let mut poll = Poll::new().map_err(Error::MioSetupFailed)?;
    let mut events = Events::with_capacity(128);

    let registry = poll.registry();

    let stream_token = 0;
    let stream_read_buffer_token = 1;
    let stream_write_buffer_token = 2;

    let mut registered_channels: HashSet<u32> = HashSet::new();
    let mut channels_to_remove: HashSet<u32> = HashSet::new();

    let mut stream_reader: FdStreamManager<MAX_PKT_SIZE, _, ReadFromStream> = FdStreamManager::new(
        stream.as_fd(),
        stream_token,
        reader_buf,
        stream_read_buffer_token,
    )
    .map_err(Error::IOWrapperCreationFailed)?;
    stream_reader
        .register(registry, false)
        .map_err(Error::MioRegistrationFailed)?;
    let mut stream_writer: FdStreamManager<MAX_PKT_SIZE, _, ReadFromBuffer> = FdStreamManager::new(
        stream.as_fd(),
        stream_token,
        sender_buf,
        stream_write_buffer_token,
    )
    .map_err(Error::IOWrapperCreationFailed)?;
    stream_writer
        .register(registry, false)
        .map_err(Error::MioRegistrationFailed)?;
    registry
        .register(
            &mut SourceFd(&stream.as_raw_fd()),
            Token(stream_token),
            Interest::READABLE | Interest::WRITABLE,
        )
        .map_err(Error::MioRegistrationFailed)?;

    let mut tmp_packet = [0u8; MAX_PKT_SIZE];

    loop {
        match poll.poll(&mut events, None) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::MioReceiveEventFailed(e)),
        }

        for ev in &events {
            let event_token = ev.token();
            trace!("Got token {}", event_token.0);
            if event_token.0 == stream_token
                || event_token.0 == stream_read_buffer_token
                || event_token.0 == stream_write_buffer_token
            {
                // DO not perform an if/else dance here, as events can be readavble AND
                // writable simultaneously.
                if (event_token.0 == stream_token && ev.is_readable())
                    || event_token.0 == stream_read_buffer_token
                {
                    let res = stream_reader.handle_event(event_token);
                    match res {
                        Ok(()) => {}
                        Err(Errno::EPIPE) => {
                            // the remote end shutdowned its sending window
                            stream_reader
                                .deregister(poll.registry(), false)
                                .map_err(Error::IoError)?;
                        }
                        _ => {
                            return res.map_err(Error::UnixError);
                        }
                    }
                }
                if (event_token.0 == stream_token && ev.is_writable())
                    || event_token.0 == stream_write_buffer_token
                {
                    stream_writer.handle_event(event_token)?;
                }

                match handle_packets(
                    &mut stream_reader,
                    &mut stream_writer,
                    &mut session,
                    &mut state,
                    &mut tmp_packet,
                )? {
                    KeepProcessing::Continue => {}
                    KeepProcessing::StopDisconnected => {
                        info!("Connection terminated");
                        return Ok(());
                    }
                    KeepProcessing::StopAndTransferToChild(username) => {
                        return transfer_connection(state, stream_reader, stream_writer, username)
                            .map_err(Error::ConnectionTransferFailed);
                    }
                }
            } else if event_token.0 >= POLL_NB_PER_CHAN {
                handle_channel_data(ev, &mut state)?;
            }
        }

        process_channel_states(
            &mut state,
            &mut stream_writer,
            &mut poll,
            &mut registered_channels,
            &mut channels_to_remove,
        )?;
        for (_, chan) in state.channels.channels.iter_mut() {
            flush_channel(chan, &mut state.sender, &mut stream_writer)?;
        }
    }
}

fn master_process(options: &Options) -> Result<(), Error> {
    let mut listener = TcpListener::bind(std::net::SocketAddr::from_str(&format!(
        "{}:{}",
        options.listening_address, options.port
    ))?)
    .map_err(Error::BindFailed)?;

    let mut poll = Poll::new().map_err(Error::MioSetupFailed)?;
    let mut events = Events::with_capacity(128);

    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)
        .map_err(Error::MioSetupFailed)?;

    loop {
        match poll.poll(&mut events, None) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::MioReceiveEventFailed(e)),
        }

        for _event in events.iter() {
            loop {
                // One or more connections are ready, so we'll attempt to
                // accept them (in a loop).
                match listener.accept() {
                    Ok((stream, _address)) => {
                        info!("Received a new connection");
                        let auth_mode = if options.single_user_mode {
                            AuthMode::SingleUser(options.authorized_keys_file.clone())
                        } else {
                            AuthMode::MultiUser
                        };

                        let host_keys_dir = options.host_keys_dir.clone();
                        let enable_command_execution = options.enable_command_execution;
                        thread::spawn(move || {
                            if let Err(e) = handle_stream(
                                stream,
                                auth_mode,
                                enable_command_execution,
                                &host_keys_dir,
                            ) {
                                error!("Got an error while handling a stream: {:?}", e);
                            }
                        });
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => {
                        error!("Got an error accepting a connection: {:?}", e);
                    }
                }
            }
        }
    }
}

fn protect_process() -> Result<(), Error> {
    prctl::set_dumpable(false).map_err(|_| Error::ChildProtectionFailed)?;
    prctl::set_keepcaps(false).map_err(|_| Error::ChildProtectionFailed)?;
    prctl::set_no_new_privs().map_err(|_| Error::ChildProtectionFailed)?;

    Ok(())
}

fn main() -> Result<(), Error> {
    let options: Options = argh::from_env();

    if options.single_user_mode && options.authorized_keys_file.file_name().is_none() {
        eprintln!(
            "Invalid argument: the authorized_key_file argument must be set in single user mode"
        );
        return Err(Error::InvalidArgument);
    }

    if options.master_socket {
        // detach the process from its sshd parent
        if let ForkResult::Parent { .. } = unsafe { fork() }.map_err(Error::ForkFailed)? {
            return Ok(());
        }
    }

    if !options.disable_protections {
        protect_process()?;
    }

    let log_level = options.log_level.unwrap_or(Level::Info);
    if options.log_to_syslog {
        syslog::init(
            Facility::LOG_USER,
            log_level.to_level_filter(),
            Some("smicro_ssh"),
        )?;
    } else {
        simple_logger::init_with_level(log_level)?;
    }

    if options.master_socket {
        let (user, state, reader_buf, sender_buf, stream) = receive_connection()?;

        if !options.single_user_mode {
            // switch to the user session
            setgid(user.gid).map_err(Error::UserChangeFailed)?;
            setuid(user.uid).map_err(Error::UserChangeFailed)?;
        }

        handle_stream_with_preexisting_state(
            stream,
            reader_buf,
            sender_buf,
            state,
            SessionStates::SessionStateEstablished(
                SessionStateEstablished::ExpectsChannelData(ExpectsChannelData {}).into(),
            ),
        )?;

        Ok(())
    } else {
        master_process(&options)
    }
}
