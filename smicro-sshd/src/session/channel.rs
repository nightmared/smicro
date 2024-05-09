use std::os::fd::{AsRawFd, RawFd};
use std::os::linux::process::CommandExt;
use std::process::{Command, Stdio};

use smicro_common::{LoopingBuffer, LoopingBufferWriter};
use smicro_macros::declare_session_state_with_allowed_message_types;
use smicro_types::sftp::deserialize::parse_utf8_slice;

use crate::{
    error::Error,
    messages::{
        ChannelOpenFailureReason, MessageChannelData, MessageChannelFailure, MessageChannelOpen,
        MessageChannelOpenConfirmation, MessageChannelOpenFailure, MessageChannelRequest,
        MessageChannelSuccess, MessageChannelWindowAdjust,
    },
    process_write,
    state::channel::ChannelCommand,
    write_message,
};

#[derive(Clone, Debug)]
pub struct ExpectsChannelOpen {}

#[declare_session_state_with_allowed_message_types(structure = ExpectsChannelOpen, msg_type = MessageType::ChannelOpen)]
fn process(message_data: &[u8]) {
    let (_, msg) = MessageChannelOpen::deserialize(message_data)?;

    if msg.channel_type != "session" {
        write_message(
            &mut state.sender,
            writer,
            &MessageChannelOpenFailure::new(
                msg.sender_channel,
                ChannelOpenFailureReason::UnknownChannelType,
            ),
        )?;

        return Err(Error::InvalidChannelMessage);
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

    let confirmation = MessageChannelOpenConfirmation {
        recipient_channel: msg.sender_channel,
        sender_channel: local_chan_number,
        initial_window_size: msg.initial_window_size,
        max_pkt_size: msg.max_pkt_size,
    };
    write_message(&mut state.sender, writer, &confirmation)?;

    Ok((
        next,
        SessionStates::AcceptsChannelMessages(AcceptsChannelMessages {}),
    ))
}

#[derive(Clone, Debug)]
pub struct AcceptsChannelMessages {}

#[declare_session_state_with_allowed_message_types(structure = AcceptsChannelMessages, msg_type = [MessageType::ChannelRequest, MessageType::ChannelData, MessageType::ChannelWindowAdjust])]
fn process(message_data: &[u8]) {
    if message_type == MessageType::ChannelRequest {
        let (_, msg) = MessageChannelRequest::deserialize(message_data)?;

        let chan = state.channels.get_channel(msg.recipient_channel)?;

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
                .create_pidfd(true)
                .spawn()?;

            let set_nonblocking = |fd: RawFd| -> std::io::Result<()> {
                let value = 1 as libc::c_int;
                if unsafe { libc::ioctl(fd, libc::FIONBIO, &value) } == -1 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            };

            let stdin = cmd.stdin.take().ok_or(Error::InvalidStdioHandle)?;
            set_nonblocking(stdin.as_raw_fd())?;
            let stdout = cmd.stdout.take().ok_or(Error::InvalidStdioHandle)?;
            set_nonblocking(stdout.as_raw_fd())?;
            let stderr = cmd.stderr.take().ok_or(Error::InvalidStdioHandle)?;
            set_nonblocking(stderr.as_raw_fd())?;
            chan.command = Some(ChannelCommand {
                command: cmd,
                stdin,
                stdout,
                stderr,
                stdin_buffer: LoopingBuffer::new()?,
                stdout_buffer: LoopingBuffer::new()?,
                stderr_buffer: LoopingBuffer::new()?,
            });

            if msg.want_reply {
                let success = MessageChannelSuccess {
                    recipient_channel: chan.remote_channel_number,
                };
                write_message(&mut state.sender, writer, &success)?;
            }
        } else {
            let failure = MessageChannelFailure {
                recipient_channel: chan.remote_channel_number,
            };
            write_message(&mut state.sender, writer, &failure)?;
        }
    } else if message_type == MessageType::ChannelData {
        let (_, msg) = MessageChannelData::deserialize(message_data)?;

        let chan = state.channels.get_channel(msg.recipient_channel)?;
        if !chan.mark_closed {
            let cmd = &mut chan
                .command
                .as_mut()
                .ok_or(Error::MissingCommandInChannel)?;

            if msg.data.0.len() > chan.receiver_window_size as usize {
                return Err(Error::ExceededChannelLength);
            }

            if let Err(_) = cmd.stdin_buffer.write(msg.data.0) {
                return Err(Error::IoError(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "Could not write data to the stdin buffer",
                )));
            }
            process_write(&mut cmd.stdin_buffer, &mut cmd.stdin)?;
        }
    } else if message_type == MessageType::ChannelWindowAdjust {
        let (_, msg) = MessageChannelWindowAdjust::deserialize(message_data)?;

        let chan = state.channels.get_channel(msg.recipient_channel)?;
        if u32::MAX - msg.bytes_to_add < chan.receiver_window_size {
            // End of channel: maximum number of writeable data reached
            return Err(Error::ExceededChannelLength);
        }

        chan.receiver_window_size += msg.bytes_to_add;
    }

    Ok((next, SessionStates::AcceptsChannelMessages(self.clone())))
}
