use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::linux::process::CommandExt;
use std::process::{Command, Stdio};

use log::{debug, info, warn};
use smicro_common::{LoopingBuffer, LoopingBufferWriter};
use smicro_macros::declare_session_state;
use smicro_types::deserialize::DeserializePacket;
use smicro_types::sftp::deserialize::parse_utf8_slice;
use smicro_types::ssh::types::MessageType;

use crate::io::FdStreamManager;
use crate::{
    error::Error,
    messages::channel::{
        ChannelOpenFailureReason, DirectTcpIpMessagePart, MessageChannelClose, MessageChannelData,
        MessageChannelEof, MessageChannelFailure, MessageChannelOpen,
        MessageChannelOpenConfirmation, MessageChannelOpenFailure, MessageChannelRequest,
        MessageChannelSuccess, MessageChannelWindowAdjust, MessageGlobalRequest,
        MessageRequestFailure,
    },
    state::{
        DirectionState, State,
        channel::{Channel, ChannelCommand, ChannelState, ChannelTcp, ChannelType},
    },
    write_message,
};

use super::{PacketProcessingDecision, SessionStateEstablished};

fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    let value = 1 as libc::c_int;
    if unsafe { libc::ioctl(fd, libc::FIONBIO, &value) } == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn spawn_tcp(remote_host: &str, remote_port: u16) -> Result<ChannelTcp, Error> {
    let address = (remote_host, remote_port)
        .to_socket_addrs()
        .map_err(|_| Error::DnsResolutionFailure)?
        .next()
        .ok_or(Error::DnsResolutionReturnedNoEntry)?;

    info!("Establishing a TCP connection to {:?}", address);

    let stream = TcpStream::connect(address).map_err(|_| Error::TcpConnectFailed)?;
    stream
        .set_nonblocking(true)
        .map_err(|_| Error::TcpConnectFailed)?;

    let fd = unsafe { OwnedFd::from_raw_fd(stream.as_raw_fd()) };
    let in_fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    let out_fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    std::mem::forget(stream);

    Ok(ChannelTcp {
        socket: fd,
        data_in: FdStreamManager::new(in_fd, 0, LoopingBuffer::new()?, 0)?,
        data_out: FdStreamManager::new(out_fd, 0, LoopingBuffer::new()?, 0)?,
    })
}

fn spawn_command(command: &str, with_env: bool) -> Result<ChannelCommand, Error> {
    // Shell injection FTW!
    // More seriously though, this will be acceptable because the user was identified
    // and this will be executed with the privileges of that target user once
    // smico properly switches rights before exec.
    let mut inner_command = if with_env {
        Command::new("/usr/bin/env")
    } else {
        Command::new(command)
    };
    let mut cmd = if with_env {
        inner_command.arg("sh").arg("-c").arg(command)
    } else {
        &mut inner_command
    }
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .create_pidfd(true)
    .spawn()
    .map_err(Error::ProgramExecutionFailed)?;

    let stdin = cmd.stdin.take().ok_or(Error::InvalidStdioHandle)?;
    set_nonblocking(stdin.as_raw_fd()).map_err(Error::SetNonBlockingFailed)?;
    let stdout = cmd.stdout.take().ok_or(Error::InvalidStdioHandle)?;
    set_nonblocking(stdout.as_raw_fd()).map_err(Error::SetNonBlockingFailed)?;
    let stderr = cmd.stderr.take().ok_or(Error::InvalidStdioHandle)?;
    set_nonblocking(stderr.as_raw_fd()).map_err(Error::SetNonBlockingFailed)?;

    Ok(ChannelCommand {
        command: cmd,
        stdin: FdStreamManager::new(stdin, 0, LoopingBuffer::new()?, 0)?,
        stdout: FdStreamManager::new(stdout, 0, LoopingBuffer::new()?, 0)?,
        stderr: FdStreamManager::new(stderr, 0, LoopingBuffer::new()?, 0)?,
    })
}

fn handle_channel_request<const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
    sender: &mut DirectionState,
    writer: &mut W,
    msg: MessageChannelRequest,
    chan: &mut Channel,
    enable_command_execution: bool,
) -> Result<(), Error> {
    debug!("Got a channel request for mode '{}'", msg.requested_mode);

    if chan.command.is_some() {
        return Err(Error::InvalidChannelReuse);
    }

    let mut success = false;

    match msg.requested_mode {
        "exec" => {
            if enable_command_execution {
                let (_, command) = parse_utf8_slice(msg.channel_specific_data)?;

                chan.command = Some(ChannelType::ChannelCommand(spawn_command(command, true)?));
                success = true;
            }
        }
        "subsystem" => {
            let (_, requested_subsystem) = parse_utf8_slice(msg.channel_specific_data)?;
            debug!(
                "Got a request to open the subsystem '{}' on channel {}",
                requested_subsystem, chan.remote_channel_number
            );
            if requested_subsystem == "sftp" {
                let command = std::env::current_exe()
                    .map_err(Error::LocateBinaryFailed)?
                    .parent()
                    .unwrap()
                    .join("smicro_binhelper");

                chan.command = Some(ChannelType::ChannelCommand(spawn_command(
                    command.to_str().unwrap(),
                    false,
                )?));
                success = true;
            } else {
                warn!("Unsupported subsystem");
            }
        }
        _ => return Err(Error::UnsupportedChannelRequestKind),
    };
    if msg.want_reply {
        if success {
            let success = MessageChannelSuccess {
                recipient_channel: chan.remote_channel_number,
            };
            write_message(sender, writer, &success)?;
        } else {
            let failure = MessageChannelFailure {
                recipient_channel: chan.remote_channel_number,
            };
            write_message(sender, writer, &failure)?;
        }
    }

    Ok(())
}

// TODO: handle ChannelExtendedData
#[declare_session_state(
    msg_type = [MessageType::ChannelOpen, MessageType::GlobalRequest, MessageType::ChannelRequest, MessageType::ChannelData, MessageType::ChannelWindowAdjust, MessageType::ChannelEof, MessageType::ChannelClose]
)]
pub struct ExpectsChannelData {}

impl ExpectsChannelData {
    pub fn inner_process<const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
        &self,
        state: &mut State,
        writer: &mut W,
        message_type: MessageType,
        message_data: &[u8],
    ) -> Result<PacketProcessingDecision, Error> {
        match message_type {
            MessageType::ChannelOpen => {
                let (_, msg) = MessageChannelOpen::deserialize(message_data)?;

                let mut command = None;

                match msg.channel_type {
                    "session" => {}
                    "direct-tcpip" => {
                        let (_, conn) =
                            DirectTcpIpMessagePart::deserialize(msg.channel_specific_data)?;

                        match spawn_tcp(conn.remote_host, conn.remote_port as u16) {
                            Ok(cmd) => {
                                command = Some(ChannelType::ChannelTcp(cmd));
                            }
                            Err(e) => {
                                info!("TCP connection failed: {:?}", e);
                                // the TCP connection failed, let's abort
                                write_message(
                                    &mut state.sender,
                                    writer,
                                    &MessageChannelOpenFailure::new(
                                        msg.sender_channel,
                                        ChannelOpenFailureReason::UnknownChannelType,
                                    ),
                                )?;
                                return Ok(SessionStateEstablished::ExpectsChannelData(
                                    self.clone(),
                                )
                                .into());
                            }
                        }
                    }
                    _ => {
                        info!("Unsupported channel type {}", msg.channel_type);
                        write_message(
                            &mut state.sender,
                            writer,
                            &MessageChannelOpenFailure::new(
                                msg.sender_channel,
                                ChannelOpenFailureReason::UnknownChannelType,
                            ),
                        )?;

                        return Ok(SessionStateEstablished::ExpectsChannelData(self.clone()).into());
                    }
                }

                let local_chan_number = match state.channels.allocate_channel(
                    msg.sender_channel,
                    msg.max_pkt_size,
                    msg.initial_window_size,
                ) {
                    Ok(chan) => chan,
                    Err(e) => {
                        write_message(
                            &mut state.sender,
                            writer,
                            &MessageChannelOpenFailure::new(
                                msg.sender_channel,
                                ChannelOpenFailureReason::ConnectFailed,
                            ),
                        )?;

                        return Err(Error::from(e));
                    }
                };

                if command.is_some() {
                    // safe as we just allocated the channel, and there is no concurrency
                    let chan = state.channels.get_channel(local_chan_number).unwrap();
                    chan.command = command;
                }

                let confirmation = MessageChannelOpenConfirmation {
                    recipient_channel: msg.sender_channel,
                    sender_channel: local_chan_number,
                    initial_window_size: msg.initial_window_size,
                    max_pkt_size: msg.max_pkt_size,
                };
                write_message(&mut state.sender, writer, &confirmation)?;
            }
            MessageType::GlobalRequest => {
                let (_, msg) = MessageGlobalRequest::deserialize(message_data)?;

                debug!(
                    "Received a GlobalRequest ({:?}), but this is currently unsupported",
                    msg
                );

                write_message(&mut state.sender, writer, &MessageRequestFailure {})?;
            }
            MessageType::ChannelRequest => {
                let (_, msg) = MessageChannelRequest::deserialize(message_data)?;

                let chan = state.channels.get_channel(msg.recipient_channel)?;

                if handle_channel_request(
                    &mut state.sender,
                    writer,
                    msg,
                    chan,
                    state.enable_command_execution,
                )
                .is_err()
                {
                    let failure = MessageChannelFailure {
                        recipient_channel: chan.remote_channel_number,
                    };
                    write_message(&mut state.sender, writer, &failure)?;
                }
            }
            MessageType::ChannelData => {
                let (_, msg) = MessageChannelData::deserialize(message_data)?;
                let chan = state.channels.get_channel(msg.recipient_channel)?;
                debug!("Got channel data ({} bytes)", msg.data.0.len());

                if chan.state == ChannelState::Running {
                    let cmd = &mut chan
                        .command
                        .as_mut()
                        .ok_or(Error::MissingCommandInChannel)?;

                    if msg.data.0.len() > chan.receiver_window_size as usize {
                        return Err(Error::ExceededChannelLength);
                    }

                    let write_res = match cmd {
                        ChannelType::ChannelCommand(cmd) => cmd.stdin.write(msg.data.0),
                        ChannelType::ChannelTcp(cmd) => cmd.data_in.write(msg.data.0),
                    };

                    if write_res.is_err() {
                        return Err(Error::IoError(std::io::Error::new(
                            std::io::ErrorKind::WouldBlock,
                            "Could not write data to the stdin buffer",
                        )));
                    }

                    chan.receiver_window_size -= msg.data.0.len() as u32;
                }
            }
            MessageType::ChannelWindowAdjust => {
                let (_, msg) = MessageChannelWindowAdjust::deserialize(message_data)?;

                let chan = state.channels.get_channel(msg.recipient_channel)?;
                if u32::MAX - msg.bytes_to_add < chan.sender_window_size {
                    // End of channel: maximum number of writeable data reached
                    return Err(Error::ExceededChannelLength);
                }

                chan.sender_window_size += msg.bytes_to_add;
            }
            MessageType::ChannelEof => {
                let (_, msg) = MessageChannelEof::deserialize(message_data)?;

                let chan = state.channels.get_channel(msg.recipient_channel)?;

                chan.state = ChannelState::RemoteEof;
            }
            MessageType::ChannelClose => {
                let (_, msg) = MessageChannelClose::deserialize(message_data)?;

                let chan = state.channels.get_channel(msg.recipient_channel)?;

                debug!(
                    "Received a request for closing channel {}",
                    msg.recipient_channel
                );

                chan.state = ChannelState::Stopped;
            }
            _ => {
                unreachable!()
            }
        }

        Ok(SessionStateEstablished::ExpectsChannelData(self.clone()).into())
    }
}
