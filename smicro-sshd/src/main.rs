use std::{
    cmp::min,
    collections::HashSet,
    io::{ErrorKind, Read, Write},
    net::SocketAddr,
    os::fd::AsRawFd,
    path::Path,
    str::FromStr,
    thread,
};

use log::{debug, error, info, trace, LevelFilter};
use mio::{
    net::{TcpListener, TcpStream},
    unix::SourceFd,
    Events, Interest, Poll, Token,
};
use syslog::{BasicLogger, Facility, Formatter3164};

use smicro_common::LoopingBuffer;
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
    messages::{DisconnectReason, MessageChannelData, MessageDisconnect},
    packet::{write_message, MAX_PKT_SIZE},
    session::UninitializedSession,
    session::{SessionState, SessionStates},
    state::State,
};

fn handle_packet<const SIZE: usize, W: Write>(
    buf: &mut LoopingBuffer<SIZE>,
    writer: &mut W,
    session: &mut SessionStates,
    state: &mut State,
) -> Result<(), Error> {
    let available_data = buf.get_readable_data();
    let available_data_len = available_data.len();
    let res = session.process(state, writer, available_data);
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
                    state,
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
                    state,
                    writer,
                    &MessageDisconnect::new(DisconnectReason::ProtocolError),
                );

                return Err(Error::ProcessingFailed);
            }
        },
        Ok((next_data, new_session)) => {
            *session = new_session;

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
                break;
            }
            Err(Error::IoError(e)) if e.kind() == ErrorKind::WouldBlock => {
                break;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    Ok(())
}

fn handle_channel_data<const SIZE: usize>(
    sender_buf: &mut LoopingBuffer<SIZE>,
    event_token: Token,
    state: &mut State,
) -> Result<(), Error> {
    let channel_number = (event_token.0 / 4) as u32;
    if let Some(chan) = state.channels.channels.get_mut(&channel_number) {
        let cmd = chan
            .command
            .as_mut()
            .ok_or(Error::MissingCommandInChannel)?;
        if event_token.0 % 4 == 2 {
            // stdin
            process_write(&mut cmd.stdin_buffer, &mut cmd.stdin)?;
        } else {
            // stdout/stderr
            let source: &mut dyn Read = if event_token.0 % 4 == 0 {
                &mut cmd.stdout
            } else {
                &mut cmd.stderr
            };
            process_read(&mut cmd.output_buffer, source)?;
            let readable_data =
                unsafe { std::mem::transmute::<_, &[u8]>(cmd.output_buffer.get_readable_data()) };

            // 32 is chosen arbitrarily to represent the packet overhe&d
            let max_write_size = chan.max_pkt_size as usize - 32;
            let channel_data = MessageChannelData {
                recipient_channel: chan.remote_channel_number,
                data: SharedSSHSlice(&readable_data[0..min(readable_data.len(), max_write_size)]),
            };
            // This is safe because the bump allocator does not clean memory, but we should
            // avoid this as much as possible (bumping while still using a reference).
            // Sadly, I had to do this to appease the borrow checker
            cmd.output_buffer
                .advance_reader_pos(channel_data.data.0.len());
            write_message(state, sender_buf, &channel_data)?;
        }
    } else {
        // TODO: find out the message to send here
        unimplemented!()
        //write_message(&mut state, &mut sender_buf, unimplemented!())?;
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
                if ev.is_writable() {
                    process_write(&mut sender_buf, &mut stream)?;
                }
                if ev.is_readable() {
                    process_read(&mut reader_buf, &mut stream)?;
                    handle_packets(&mut reader_buf, &mut sender_buf, &mut session, &mut state)?;
                }
            } else {
                handle_channel_data(&mut sender_buf, event_token, &mut state)?;
            }
            if sender_buf.get_readable_data().len() > 0 {
                process_write(&mut sender_buf, &mut stream)?;
            }
        }

        if state.channels.channels_changed {
            for (&chan_number, chan) in state.channels.channels.iter() {
                if let Some(cmd) = &chan.command {
                    if registered_channels.insert(chan_number) {
                        let token_base = chan_number as usize * 4;
                        let stdout_fd = cmd.stdout.as_raw_fd();
                        poll.registry().register(
                            &mut SourceFd(&stdout_fd),
                            Token(token_base),
                            Interest::READABLE,
                        )?;
                        let stderr_fd = cmd.stderr.as_raw_fd();
                        poll.registry().register(
                            &mut SourceFd(&stderr_fd),
                            Token(token_base + 1),
                            Interest::READABLE,
                        )?;
                        let stdin_fd = cmd.stdin.as_raw_fd();
                        poll.registry().register(
                            &mut SourceFd(&stdin_fd),
                            Token(token_base + 2),
                            Interest::WRITABLE,
                        )?;
                    }
                }
            }
            // TODO: deregister channels for future reuse
            for chan in registered_channels.iter() {
                if !state.channels.channels.contains_key(chan) {}
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
