#![feature(linux_pidfd)]

use std::{
    cmp::min,
    collections::HashSet,
    io::{ErrorKind, Read, Write},
    net::SocketAddr,
    os::{fd::AsRawFd, linux::process::ChildExt},
    path::Path,
    process::ExitStatus,
    str::FromStr,
    thread,
};

use log::{debug, error, info, trace, warn, LevelFilter};
use mio::{
    net::{TcpListener, TcpStream},
    unix::SourceFd,
    Events, Interest, Poll, Token,
};
use state::channel::{Channel, ChannelCommand};
use syslog::{BasicLogger, Facility, Formatter3164};

use smicro_common::{
    AtomicLoopingBufferWriter, LoopingBuffer, LoopingBufferReader, LoopingBufferWriter,
};
use smicro_types::{
    deserialize::DeserializePacket,
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
        MessageDisconnect,
    },
    packet::{write_message, MAX_PKT_SIZE},
    session::{SessionState, SessionStates, UninitializedSession},
    state::{SenderState, State},
};

fn handle_packet<const SIZE: usize>(
    buf: &mut LoopingBuffer<SIZE>,
    writer: &mut LoopingBuffer<SIZE>,
    session: &mut SessionStates,
    state: &mut State,
) -> Result<(), Error> {
    let available_data = buf.get_readable_data();
    let available_data_len = available_data.len();
    let mut atomic_writer = writer.get_atomic_writer();
    let res = session.process(state, &mut atomic_writer, available_data);
    match res {
        Err(e) => match e {
            Error::ParsingError(nom::Err::Incomplete(_)) | Error::PeerTriggeredDisconnection => {
                // forward to our caller
                return Err(e);
            }
            Error::ParsingError(e) => {
                error!("Got an error while trying to parse the packet: {:?}", e);
                debug!("The data that triggered the error was: {:?}", buf);
                let _ = write_message(
                    &mut state.sender,
                    writer,
                    &MessageDisconnect::new(DisconnectReason::ProtocolError),
                );

                return Err(Error::InvalidPacket);
            }
            Error::DisallowedMessageType(MessageType::Ignore | MessageType::Debug) => {}
            e => {
                error!("Got an error while processing the packet: {:?}", e);
                debug!("The data that triggered the error was: {:?}", buf);
                let _ = write_message(
                    &mut state.sender,
                    writer,
                    &MessageDisconnect::new(DisconnectReason::ProtocolError),
                );

                return Err(Error::ProcessingFailed);
            }
        },
        Ok((next_data, new_session)) => {
            *session = new_session;

            // register the writes so they can be sent to the client
            atomic_writer.commit();

            let read_data = available_data_len - next_data.len();
            buf.advance_reader_pos(read_data);
        }
    }

    Ok(())
}

fn process_read<const SIZE: usize, R: Read + ?Sized>(
    reader_buf: &mut LoopingBuffer<SIZE>,
    stream: &mut R,
) -> Result<(), Error> {
    loop {
        // Read enough data to hold *at least* a packet, but without overwriting previous
        // data
        let writeable_buffer = reader_buf.get_writable_buffer();
        if writeable_buffer.len() == 0 {
            break;
        }
        match stream.read(writeable_buffer) {
            Ok(written) => {
                trace!("Read {written} bytes");
                if written == 0 {
                    info!("The client closed the connection, shutting down the thread");
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

    Ok(())
}

fn process_write<const SIZE: usize, W: Write + ?Sized>(
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
                    info!("The client closed the connection, shutting down the thread");
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
) -> Result<(), Error> {
    loop {
        match handle_packet(reader_buf, sender_buf, session, state) {
            Ok(_) => {}
            Err(Error::ParsingError(nom::Err::Incomplete(_))) => {
                trace!("Not enough data to parse the packet, trying to read more");
                return Ok(());
            }
            Err(Error::IoError(e)) if e.kind() == ErrorKind::WouldBlock => {
                return Ok(());
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}

fn flush_data_to_channel<const INPUT_SIZE: usize, const SIZE: usize>(
    sender_buf: &mut LoopingBuffer<SIZE>,
    input_buf: &mut LoopingBuffer<INPUT_SIZE>,
    recipient_channel: u32,
    max_pkt_size: u32,
    sender: &mut SenderState,
    is_stderr: bool,
) -> Result<(), Error> {
    let readable_data = input_buf.get_readable_data();

    // 32 is chosen arbitrarily to represent the packet overhead
    let max_write_size = max_pkt_size as usize - 32;
    let data = &readable_data[0..min(readable_data.len(), max_write_size)];
    let data_len = data.len();
    let data = SharedSSHSlice(data);
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
            input_buf.advance_reader_pos(data_len);
            Ok(())
        }
        Err(Error::IoError(e)) if e.kind() == ErrorKind::WouldBlock => Ok(()),
        Err(e) => Err(e),
    }
}

fn handle_channel_message(event_token: Token, chan: &mut Channel) -> Result<(), Error> {
    let cmd = chan
        .command
        .as_mut()
        .ok_or(Error::MissingCommandInChannel)?;

    if event_token.0 % 4 == 0 {
        // stdin
        process_write(&mut cmd.stdin_buffer, &mut cmd.stdin)?;
    } else if event_token.0 % 4 == 1 {
        // stdout
        process_read(&mut cmd.stdout_buffer, &mut cmd.stdout)?;
    } else if event_token.0 % 4 == 2 {
        // stderr
        process_read(&mut cmd.stderr_buffer, &mut cmd.stderr)?;
    } else if event_token.0 % 4 == 3 {
        // maybe the process exited?
        if let Ok(_) = cmd.command.try_wait() {
            chan.mark_closed = true;
        }
    }
    Ok(())
}

fn handle_channel_data(event_token: Token, state: &mut State) -> Result<(), Error> {
    let channel_number = (event_token.0 / 4) as u32;
    if let Ok(chan) = state.channels.get_channel(channel_number) {
        match handle_channel_message(event_token, chan) {
            Ok(()) => {}
            Err(Error::ConnectionClosed) => {
                // TODO: do something
                return Ok(());
            }
            Err(e) => {
                return Err(e);
            }
        }
    } else {
        warn!(
            "Got data for a channel ({}) that does not exist",
            channel_number
        );
    }

    Ok(())
}

fn handle_stream(mut stream: TcpStream) -> Result<(), Error> {
    let mut reader_buf = <LoopingBuffer<MAX_PKT_SIZE>>::new()?;
    let mut sender_buf = <LoopingBuffer<MAX_PKT_SIZE>>::new()?;

    let mut host_keys = Vec::new();
    let test_hostkey = State::load_hostkey(&Path::new("/home/sthoby/dev-fast/smicro/host_key"))?;
    host_keys.push(test_hostkey.as_ref());
    let mut state = State::new(&host_keys);
    let mut session = SessionStates::UninitializedSession(UninitializedSession {});

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);

    let stream_token = Token(0);
    poll.registry().register(
        &mut stream,
        stream_token,
        Interest::READABLE | Interest::WRITABLE,
    )?;

    let mut registered_channels: HashSet<u32> = HashSet::new();

    loop {
        poll.poll(&mut events, None)?;

        for ev in &events {
            let event_token = ev.token();
            // Receive then processes messages from the client
            if event_token == stream_token {
                // flush whatever data we couldn't write previously
                if ev.is_writable() {
                    process_write(&mut sender_buf, &mut stream)?;
                }
                if ev.is_readable() {
                    process_read(&mut reader_buf, &mut stream)?;
                    handle_packets(&mut reader_buf, &mut sender_buf, &mut session, &mut state)?;
                }
            } else {
                handle_channel_data(event_token, &mut state)?;
            }

            for (_, chan) in state.channels.channels.iter_mut() {
                let recipient_channel = chan.remote_channel_number;
                let max_pkt_size = chan.max_pkt_size;
                if let Some(ref mut cmd) = chan.command {
                    if cmd.stderr_buffer.get_readable_data().len() > 0 {
                        flush_data_to_channel(
                            &mut sender_buf,
                            &mut cmd.stderr_buffer,
                            recipient_channel,
                            max_pkt_size,
                            &mut state.sender,
                            true,
                        )?;
                    }
                    if cmd.stdout_buffer.get_readable_data().len() > 0 {
                        flush_data_to_channel(
                            &mut sender_buf,
                            &mut cmd.stdout_buffer,
                            recipient_channel,
                            max_pkt_size,
                            &mut state.sender,
                            false,
                        )?;
                    }
                }
            }

            if sender_buf.get_readable_data().len() > 0 {
                process_write(&mut sender_buf, &mut stream)?;
            }
        }

        for (&chan_number, chan) in state.channels.channels.iter() {
            // once a channel has stopped writting data and is closed, we can terminate it
            if let Some(cmd) = &chan.command {
                if registered_channels.insert(chan_number) {
                    debug!("Registering channel {}", chan_number);
                    let token_base = chan_number as usize * 4;
                    let stdin_fd = cmd.stdin.as_raw_fd();
                    poll.registry().register(
                        &mut SourceFd(&stdin_fd),
                        Token(token_base),
                        Interest::WRITABLE,
                    )?;
                    let stdout_fd = cmd.stdout.as_raw_fd();
                    poll.registry().register(
                        &mut SourceFd(&stdout_fd),
                        Token(token_base + 1),
                        Interest::READABLE,
                    )?;
                    let stderr_fd = cmd.stderr.as_raw_fd();
                    poll.registry().register(
                        &mut SourceFd(&stderr_fd),
                        Token(token_base + 2),
                        Interest::READABLE,
                    )?;

                    poll.registry().register(
                        &mut SourceFd(&cmd.command.pidfd()?.as_raw_fd()),
                        Token(token_base + 3),
                        Interest::READABLE,
                    )?;
                }
            }
        }
        for chan_number in registered_channels.iter() {
            if !state.channels.channels.contains_key(chan_number) {
                debug!("Unregistering channel {}", chan_number);
                let fd_base = *chan_number as i32 * 4;
                poll.registry().deregister(&mut SourceFd(&fd_base))?;
                poll.registry().deregister(&mut SourceFd(&(fd_base + 1)))?;
                poll.registry().deregister(&mut SourceFd(&(fd_base + 2)))?;
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
        .map(|()| log::set_max_level(LevelFilter::Debug))?;

    let mut listener = TcpListener::bind(SocketAddr::from_str("127.0.0.1:2222")?)?;

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);

    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)?;

    loop {
        poll.poll(&mut events, None)?;

        for _event in events.iter() {
            loop {
                // One or more connections are ready, so we'll attempt to
                // accept them (in a loop).
                match listener.accept() {
                    Ok((stream, _address)) => {
                        info!("Received a new connection");
                        thread::spawn(move || match handle_stream(stream) {
                            Ok(()) | Err(Error::PeerTriggeredDisconnection) => {
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
