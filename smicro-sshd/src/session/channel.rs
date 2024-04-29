use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Command, Stdio};

use smicro_common::LoopingBuffer;
use smicro_macros::declare_session_state_with_allowed_message_types;
use smicro_types::sftp::deserialize::parse_utf8_slice;

use crate::process_write;
use crate::{
    error::Error,
    messages::{
        ChannelOpenFailureReason, MessageChannelData, MessageChannelFailure, MessageChannelOpen,
        MessageChannelOpenConfirmation, MessageChannelOpenFailure, MessageChannelRequest,
        MessageChannelSuccess,
    },
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
            state,
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
                state,
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
    write_message(state, writer, &confirmation)?;

    Ok((
        next,
        SessionStates::AcceptsChannelMessages(AcceptsChannelMessages {}),
    ))
}

#[derive(Clone, Debug)]
pub struct AcceptsChannelMessages {}

#[declare_session_state_with_allowed_message_types(structure = AcceptsChannelMessages, msg_type = [MessageType::ChannelRequest, MessageType::ChannelData])]
fn process(message_data: &[u8]) {
    if message_type == MessageType::ChannelRequest {
        let (_, msg) = MessageChannelRequest::deserialize(message_data)?;

        let chan = match state.channels.channels.get_mut(&msg.recipient_channel) {
            Some(chan) => chan,
            None => {
                write_message(
                    state,
                    writer,
                    &MessageChannelFailure {
                        // send back the provided channel, as we do not know the real 'remote'
                        // channel id in this situation
                        recipient_channel: msg.recipient_channel,
                    },
                )?;

                return Ok((next, SessionStates::AcceptsChannelMessages(self.clone())));
            }
        };

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
                output_buffer: LoopingBuffer::new()?,
            });
            state.channels.channels_changed = true;

            if msg.want_reply {
                let success = MessageChannelSuccess {
                    recipient_channel: chan.remote_channel_number,
                };
                write_message(state, writer, &success)?;
            }
        } else {
            let failure = MessageChannelFailure {
                recipient_channel: chan.remote_channel_number,
            };
            write_message(state, writer, &failure)?;
        }
    } else if message_type == MessageType::ChannelData {
        let (_, msg) = MessageChannelData::deserialize(message_data)?;

        if let Some(chan) = state.channels.channels.get_mut(&msg.recipient_channel) {
            let cmd = &mut chan
                .command
                .as_mut()
                .ok_or(Error::MissingCommandInChannel)?;
            if let Err(e) = cmd.stdin_buffer.write_all(msg.data.0) {
                let failure = MessageChannelFailure {
                    recipient_channel: chan.remote_channel_number,
                };
                write_message(state, writer, &failure)?;
                return Err(Error::from(e));
            }
            process_write(&mut cmd.stdin_buffer, &mut cmd.stdin)?;
        }
    }

    Ok((next, SessionStates::AcceptsChannelMessages(self.clone())))
}
