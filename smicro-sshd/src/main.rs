#![feature(linux_pidfd)]
#![feature(unix_socket_ancillary_data)]
#![feature(allocator_api)]

use std::{
    cmp::min,
    collections::HashSet,
    io::{ErrorKind, Read, Write},
    net::SocketAddr,
    ops::{BitOr, BitOrAssign},
    os::{
        fd::AsRawFd,
        linux::process::ChildExt,
        unix::net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    process::Command,
    str::FromStr,
    thread,
};

use argh::FromArgs;
use log::{debug, error, info, trace, warn, LevelFilter};
use messages::{MessageChannelClose, MessageChannelWindowAdjust};
use mio::{
    net::{TcpListener, TcpStream},
    unix::SourceFd,
    Events, Interest, Poll, Token,
};
use nix::sys::eventfd::EventFd;
use session::{ExpectsChannelOpen, PacketProcessingDecision, SessionStateEstablished};
use state::channel::{Channel, ChannelCommand, ChannelState};
use syslog::Facility;

use smicro_common::{
    receive_fd_over_socket, send_fd_over_socket, LoopingBuffer, LoopingBufferReader,
    LoopingBufferWriter,
};
use smicro_types::{
    deserialize::DeserializePacket,
    serialize::SerializePacket,
    ssh::{
        deserialize::parse_message_type,
        types::{MessageType, SharedSSHSlice},
    },
};

pub mod crypto;
pub mod error;
pub mod messages;
pub mod packet;
pub mod session;
pub mod state;

use crate::{
    error::Error,
    messages::{
        ChannelExtendedDataCode, DisconnectReason, MessageChannelData, MessageChannelExtendedData,
        MessageChannelRequest, MessageDisconnect,
    },
    packet::{write_message, MAX_PKT_SIZE},
    session::{SessionState, SessionStates, UninitializedSession},
    state::{DirectionState, State},
};

enum KeepProcessing {
    Continue,
    StopDisconnected,
    StopAndTransferToChild,
}

fn handle_packet<const SIZE: usize>(
    buf: &mut LoopingBuffer<SIZE>,
    writer: &mut LoopingBuffer<SIZE>,
    session: &mut SessionStates,
    state: &mut State,
) -> Result<KeepProcessing, Error> {
    let available_data = buf.get_readable_data();
    let available_data_len = available_data.len();
    let mut atomic_writer = writer.get_atomic_writer();
    let res = session.process(state, &mut atomic_writer, available_data);
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
            atomic_writer.commit();

            let read_data = available_data_len - next_data.len();
            buf.advance_reader_pos(read_data);

            match processing_decision {
                PacketProcessingDecision::NewState(new_session) => {
                    *session = new_session;

                    Ok(KeepProcessing::Continue)
                }
                PacketProcessingDecision::SpawnChild(new_session) => {
                    *session = new_session;

                    Ok(KeepProcessing::StopAndTransferToChild)
                }
                PacketProcessingDecision::PeerTriggeredDisconnection => {
                    Ok(KeepProcessing::StopDisconnected)
                }
            }
        }
    }
}

fn read_stream_to_buffer<const SIZE: usize, R: Read + ?Sized>(
    stream: &mut R,
    reader_buf: &mut LoopingBuffer<SIZE>,
) -> Result<NonIOProgress, Error> {
    loop {
        // Read enough data to hold *at least* a packet, but without overwriting previous
        // data
        let writeable_buffer = reader_buf.get_writable_buffer();
        if writeable_buffer.len() == 0 {
            return Ok(NonIOProgress::Continue);
        }
        match stream.read(writeable_buffer) {
            Ok(written) => {
                trace!("Read {written} bytes");
                if written == 0 {
                    info!("Connection closed while reading from stream");
                    return Err(Error::ConnectionClosed);
                }
                reader_buf.advance_writer_pos(written);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                break;
            }
            Err(e) => return Err(Error::from(e)),
        }
    }

    Ok(NonIOProgress::Done)
}

fn write_buffer_to_stream<const SIZE: usize, W: Write + ?Sized>(
    sender_buf: &mut LoopingBuffer<SIZE>,
    stream: &mut W,
) -> Result<(), Error> {
    loop {
        let read_buffer = sender_buf.get_readable_data();
        if read_buffer.len() == 0 {
            break;
        }
        match stream.write(read_buffer) {
            Ok(written) => {
                trace!("Written {written} bytes");
                if written == 0 {
                    info!("Connection closed while writing to a stream");
                    return Err(Error::ConnectionClosed);
                }
                sender_buf.advance_reader_pos(written);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                break;
            }
            Err(e) => return Err(Error::from(e)),
        }
    }

    Ok(())
}

fn handle_packets<const SIZE: usize>(
    reader_buf: &mut LoopingBuffer<SIZE>,
    sender_buf: &mut LoopingBuffer<SIZE>,
    session: &mut SessionStates,
    state: &mut State,
) -> Result<KeepProcessing, Error> {
    loop {
        match handle_packet(reader_buf, sender_buf, session, state) {
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

fn flush_data_to_channel<
    const INPUT_SIZE: usize,
    const SIZE: usize,
    R: LoopingBufferReader<INPUT_SIZE>,
    W: LoopingBufferWriter<SIZE>,
>(
    sender_buf: &mut W,
    input_buf: &mut R,
    recipient_channel: u32,
    max_chan_pkt_size: u32,
    window_size: &mut u32,
    sender: &mut DirectionState,
    is_stderr: bool,
) -> Result<(), Error> {
    let readable_data = input_buf.get_readable_data();

    // 72 is chosen arbitrarily to represent the packet overhead
    if readable_data.len() == 0 || max_chan_pkt_size <= 72 {
        return Ok(());
    }
    let max_write_size = max_chan_pkt_size - 72;
    let data_len = min(readable_data.len() as u32, max_write_size);
    if *window_size < data_len {
        // we must wait for the client to increase the windows size
        return Ok(());
    }

    trace!(
        "Data is available on {}, writing it to the output stream",
        if is_stderr { "stderr" } else { "stdout" }
    );
    let data = SharedSSHSlice(&readable_data[0..data_len as usize]);
    let res = if is_stderr {
        let channel_data = MessageChannelExtendedData {
            recipient_channel,
            data_type: ChannelExtendedDataCode::Stderr,
            data,
        };
        write_message(sender, sender_buf, &channel_data)
    } else {
        let channel_data = MessageChannelData {
            recipient_channel,
            data,
        };
        write_message(sender, sender_buf, &channel_data)
    };

    match res {
        Ok(()) => {
            input_buf.advance_reader_pos(data_len as usize);
            *window_size -= data_len;
            Ok(())
        }
        Err(Error::IoError(e)) if e.kind() == ErrorKind::WouldBlock => Ok(()),
        Err(e) => Err(e),
    }
}

fn handle_channel_message(event_token: Token, chan: &mut Channel) -> Result<NonIOProgress, Error> {
    let cmd = chan
        .command
        .as_mut()
        .ok_or(Error::MissingCommandInChannel)?;

    let mut res = NonIOProgress::Done;

    if event_token.0 % 4 == 0 {
        // stdin
        write_buffer_to_stream(&mut cmd.stdin_buffer, &mut cmd.stdin)?;
    } else if event_token.0 % 4 == 1 {
        // stdout
        res |= read_stream_to_buffer(&mut cmd.stdout, &mut cmd.stdout_buffer)?;
    } else if event_token.0 % 4 == 2 {
        // stderr
        res |= read_stream_to_buffer(&mut cmd.stderr, &mut cmd.stderr_buffer)?;
    } else if event_token.0 % 4 == 3 {
        // maybe the process exited?
        if let Ok(Some(exit_status)) = cmd.command.try_wait() {
            chan.state = ChannelState::StoppedWithStatus(exit_status.code().unwrap_or(255));
        }
    }

    Ok(res)
}

fn handle_channel_data(event_token: Token, state: &mut State) -> Result<(), Error> {
    let channel_number = (event_token.0 / 4) as u32 - 1;
    debug!(
        "Received data from the process running for channel {}",
        channel_number
    );
    if let Ok(chan) = state.channels.get_channel(channel_number) {
        match handle_channel_message(event_token, chan) {
            Ok(_) => {}
            Err(Error::ConnectionClosed) => {
                // do not change the state, we will only do that once the process exited
            }
            Err(e) => return Err(e),
        }
    } else {
        warn!(
            "Got data for a channel ({}) that does not exist",
            channel_number
        );
    }
    Ok(())
}

fn register_channel(
    poll: &mut Poll,
    chan_number: u32,
    cmd: &ChannelCommand,
) -> Result<(), std::io::Error> {
    debug!("Registering channel {}", chan_number);
    let token_base = (chan_number + 1) as usize * 4;
    poll.registry().register(
        &mut SourceFd(&cmd.stdin.as_raw_fd()),
        Token(token_base),
        Interest::WRITABLE,
    )?;
    poll.registry().register(
        &mut SourceFd(&cmd.stdout.as_raw_fd()),
        Token(token_base + 1),
        Interest::READABLE,
    )?;
    poll.registry().register(
        &mut SourceFd(&cmd.stderr.as_raw_fd()),
        Token(token_base + 2),
        Interest::READABLE,
    )?;

    poll.registry().register(
        &mut SourceFd(&cmd.command.pidfd()?.as_raw_fd()),
        Token(token_base + 3),
        Interest::READABLE,
    )?;

    Ok(())
}

fn unregister_channel(poll: &mut Poll, chan: &Channel) -> Result<(), std::io::Error> {
    if let Some(cmd) = &chan.command {
        let registry = poll.registry();
        registry.deregister(&mut SourceFd(&cmd.stdin.as_raw_fd()))?;
        registry.deregister(&mut SourceFd(&cmd.stdout.as_raw_fd()))?;
        registry.deregister(&mut SourceFd(&cmd.stderr.as_raw_fd()))?;
        registry.deregister(&mut SourceFd(&cmd.command.pidfd()?.as_raw_fd()))?;
    }

    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum NonIOProgress {
    Continue,
    Done,
}

impl BitOr for NonIOProgress {
    type Output = NonIOProgress;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == NonIOProgress::Continue {
            NonIOProgress::Continue
        } else {
            rhs
        }
    }
}

impl BitOrAssign for NonIOProgress {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

fn flush_channel<const SIZE: usize, T: LoopingBufferWriter<SIZE>>(
    chan: &mut Channel,
    sender: &mut DirectionState,
    output_buf: &mut T,
) -> Result<NonIOProgress, Error> {
    let mut res = NonIOProgress::Done;
    if let Some(ref mut cmd) = chan.command {
        // bump the receiver window size, if required
        if chan.receiver_window_size < MAX_PKT_SIZE as u32 {
            match write_message(
                sender,
                output_buf,
                &MessageChannelWindowAdjust {
                    recipient_channel: chan.remote_channel_number,
                    bytes_to_add: MAX_PKT_SIZE as u32,
                },
            ) {
                Ok(()) => {
                    chan.receiver_window_size += MAX_PKT_SIZE as u32;
                }
                // retry later if we cannot write to the output buffer now
                Err(Error::IoError(e)) if e.kind() == ErrorKind::WouldBlock => {
                    return Ok(NonIOProgress::Continue);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        if cmd.stderr_buffer.get_readable_data().len() > 0 {
            flush_data_to_channel(
                output_buf,
                &mut cmd.stderr_buffer,
                chan.remote_channel_number,
                chan.max_pkt_size,
                &mut chan.sender_window_size,
                sender,
                true,
            )?;
        }
        if cmd.stdout_buffer.get_readable_data().len() > 0 {
            flush_data_to_channel(
                output_buf,
                &mut cmd.stdout_buffer,
                chan.remote_channel_number,
                chan.max_pkt_size,
                &mut chan.sender_window_size,
                sender,
                false,
            )?;
        }

        write_buffer_to_stream(&mut cmd.stdin_buffer, &mut cmd.stdin)?;

        res |= if cmd.stdin_buffer.get_readable_data().len() > 0
            || cmd.stdout_buffer.get_readable_data().len() > 0
            || cmd.stderr_buffer.get_readable_data().len() > 0
        {
            NonIOProgress::Continue
        } else {
            NonIOProgress::Done
        };
    }
    Ok(res)
}

fn process_channel_states<const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
    state: &mut State,
    sender_buf: &mut W,
    poll: &mut Poll,
    registered_channels: &mut HashSet<u32>,
    channels_to_remove: &mut HashSet<u32>,
) -> Result<(), Error> {
    for (&chan_number, chan) in state.channels.channels.iter_mut() {
        match chan.state {
            ChannelState::Running => {
                // register newly created channels on the event loop
                if let Some(cmd) = &chan.command {
                    if registered_channels.insert(chan_number) {
                        register_channel(poll, chan_number, cmd)
                            .map_err(|e| Error::RegistrationManagementError(e))?;
                    }
                }
            }
            ChannelState::StoppedWithStatus(status) => {
                debug!("The command in channel {} terminated", chan_number);

                write_message(
                    &mut state.sender,
                    sender_buf,
                    &MessageChannelRequest {
                        recipient_channel: chan.remote_channel_number,
                        requested_mode: "exit-status",
                        want_reply: false,
                        channel_specific_data: &status.to_be_bytes(),
                    },
                )?;

                debug!("Exit status sent for channel {}", chan_number);
            }
            ChannelState::Stopped => {
                write_message(
                    &mut state.sender,
                    sender_buf,
                    &MessageChannelClose {
                        recipient_channel: chan.remote_channel_number,
                    },
                )?;

                debug!("Close order sent to channel {}", chan_number);

                chan.state = ChannelState::Shutdowned;
            }
            ChannelState::Shutdowned => {
                // stop receiving data from that end
                if registered_channels.remove(&chan_number) {
                    debug!("Unregistering channel {}", chan_number);
                    unregister_channel(poll, chan)
                        .map_err(|e| Error::RegistrationManagementError(e))?;
                } else {
                    let mut remove = true;
                    if let Some(cmd) = &mut chan.command {
                        // inhibit the removal until all data was transferred
                        remove = cmd.stdout_buffer.get_readable_data().len() == 0
                            && cmd.stderr_buffer.get_readable_data().len() == 0;
                        // ensure that the process was waited for
                        let _ = cmd.command.try_wait();
                    }
                    if remove {
                        debug!("Requesting the removal of channel {}", chan_number);
                        channels_to_remove.insert(chan_number);
                    }
                }
            }
        }
    }

    for chan_number in channels_to_remove.drain() {
        state.channels.remove_channel(chan_number)?;
        debug!("Done cleaning up channel {}", chan_number);
    }

    Ok(())
}

fn handle_stream(stream: TcpStream) -> Result<(), Error> {
    let reader_buf = <LoopingBuffer<MAX_PKT_SIZE>>::new()?;
    let sender_buf = <LoopingBuffer<MAX_PKT_SIZE>>::new()?;

    let state = State::new()?;
    let session = SessionStates::UninitializedSession(UninitializedSession {});

    handle_stream_with_preexisting_state(stream, reader_buf, sender_buf, state, session)
}

fn handle_stream_with_preexisting_state(
    mut stream: TcpStream,
    mut reader_buf: LoopingBuffer<MAX_PKT_SIZE>,
    mut sender_buf: LoopingBuffer<MAX_PKT_SIZE>,
    mut state: State,
    mut session: SessionStates,
) -> Result<(), Error> {
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);

    let registry = poll.registry();

    let stream_token = Token(0);
    registry.register(
        &mut stream,
        stream_token,
        Interest::READABLE | Interest::WRITABLE,
    )?;

    let signal_token = Token(1);
    let data_available_eventfd = EventFd::new().map_err(Error::EventFdCreationFailed)?;
    registry.register(
        &mut SourceFd(&data_available_eventfd.as_raw_fd()),
        signal_token,
        Interest::READABLE,
    )?;

    let mut registered_channels: HashSet<u32> = HashSet::new();
    let mut channels_to_remove: HashSet<u32> = HashSet::new();

    loop {
        match poll.poll(&mut events, None) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }

        let mut non_io_backed_progress = NonIOProgress::Done;

        for ev in &events {
            let event_token = ev.token();
            // Receive then processes messages from the client
            if event_token == stream_token {
                // flush whatever data we couldn't write previously
                if ev.is_writable() {
                    write_buffer_to_stream(&mut sender_buf, &mut stream)?;
                }
                if ev.is_readable() {
                    non_io_backed_progress |= read_stream_to_buffer(&mut stream, &mut reader_buf)?;
                }
            } else if event_token == signal_token {
                data_available_eventfd
                    .read()
                    .map_err(Error::EventFdSignalingFailed)?;
            } else {
                handle_channel_data(event_token, &mut state)?;
            }
        }

        if sender_buf.get_readable_data().len() > 0 {
            trace!("Data is available on the output stream, flushing it to the output stream");
            write_buffer_to_stream(&mut sender_buf, &mut stream)?;
        }

        non_io_backed_progress |= read_stream_to_buffer(&mut stream, &mut reader_buf)?;

        match handle_packets(&mut reader_buf, &mut sender_buf, &mut session, &mut state)? {
            KeepProcessing::Continue => {}
            KeepProcessing::StopDisconnected => return Ok(()),
            KeepProcessing::StopAndTransferToChild => {
                println!("Transferring!");
                let socket_path = "/tmp/wip";
                let socket = UnixListener::bind(socket_path)?;

                Command::new(
                    std::env::current_exe()?
                        .parent()
                        .unwrap()
                        .join("smicro-sshd"),
                )
                .arg("--master-socket")
                .arg(socket_path)
                .spawn()?;
                let (mut slave_stream, _) = socket.accept()?;

                unsafe {
                    reader_buf.send_over_socket(&mut slave_stream)?;
                    sender_buf.send_over_socket(&mut slave_stream)?;
                    send_fd_over_socket(&mut slave_stream, stream)?;
                };
                state.serialize(&mut slave_stream)?;
                slave_stream.shutdown(std::net::Shutdown::Both)?;

                drop(socket);

                return Ok(());
            }
        }

        for cmd in state
            .channels
            .channels
            .values_mut()
            .filter(|chan| chan.state != ChannelState::Shutdowned)
            .filter_map(|chan| chan.command.as_mut())
        {
            non_io_backed_progress |=
                read_stream_to_buffer(&mut cmd.stdout, &mut cmd.stdout_buffer)?;
            non_io_backed_progress |=
                read_stream_to_buffer(&mut cmd.stderr, &mut cmd.stderr_buffer)?;
        }

        process_channel_states(
            &mut state,
            &mut sender_buf,
            &mut poll,
            &mut registered_channels,
            &mut channels_to_remove,
        )?;

        for (_, chan) in state.channels.channels.iter_mut() {
            non_io_backed_progress |= flush_channel(chan, &mut state.sender, &mut sender_buf)?;
        }

        if sender_buf.get_readable_data().len() > 0 {
            non_io_backed_progress = NonIOProgress::Continue;
        }

        if non_io_backed_progress == NonIOProgress::Continue {
            data_available_eventfd
                .write(1)
                .map_err(Error::EventFdSignalingFailed)?;
        }
    }
}

fn master_process() -> Result<(), Error> {
    let mut listener = TcpListener::bind(SocketAddr::from_str("127.0.0.1:2222")?)?;

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);

    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)?;

    loop {
        match poll.poll(&mut events, None) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }

        for _event in events.iter() {
            loop {
                // One or more connections are ready, so we'll attempt to
                // accept them (in a loop).
                match listener.accept() {
                    Ok((stream, _address)) => {
                        info!("Received a new connection");
                        thread::spawn(move || match handle_stream(stream) {
                            Ok(()) => {
                                info!("Connection terminated");
                            }
                            Err(e) => error!("Got an error while handling a stream: {:?}", e),
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

#[derive(Debug, FromArgs)]
#[argh(description = "Smicro SSHD server")]
struct Options {
    #[argh(option, description = "level of logging")]
    log_level: Option<LevelFilter>,

    #[argh(option, description = "socket to talk to a master instance")]
    master_socket: Option<PathBuf>,
}

fn main() -> Result<(), Error> {
    let options: Options = argh::from_env();

    syslog::init(
        Facility::LOG_USER,
        options.log_level.unwrap_or(LevelFilter::Info),
        Some("smicro_ssh"),
    )?;

    if let Some(socket_path) = options.master_socket {
        let mut stream = UnixStream::connect(socket_path)?;

        unsafe {
            let reader_buf = <LoopingBuffer<MAX_PKT_SIZE>>::receive_over_socket(&mut stream)?;
            let sender_buf = <LoopingBuffer<MAX_PKT_SIZE>>::receive_over_socket(&mut stream)?;

            let client_socket = receive_fd_over_socket(&mut stream)?;

            let mut buf = Vec::new();
            stream.read_to_end(&mut buf)?;

            let state = match State::deserialize(buf.as_slice()) {
                Err(e) => {
                    println!("{:?}", e);
                    return Err(e.into());
                }
                Ok((_, state)) => state,
            };

            handle_stream_with_preexisting_state(
                client_socket,
                reader_buf,
                sender_buf,
                state,
                SessionStates::SessionStateEstablished(
                    SessionStateEstablished::ExpectsChannelOpen(ExpectsChannelOpen {}),
                ),
            )?;
        };

        Ok(())
    } else {
        master_process()
    }
}
