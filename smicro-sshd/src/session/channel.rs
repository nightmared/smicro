use std::io::Read;
use std::process::{Command, Stdio};

use smicro_macros::declare_session_state_with_allowed_message_types;
use smicro_types::{sftp::deserialize::parse_utf8_slice, ssh::types::SharedSSHSlice};

use crate::state::ChannelAllocationError;
use crate::{
    error::Error,
    messages::{
        ChannelOpenFailureReason, MessageChannelData, MessageChannelOpen,
        MessageChannelOpenConfirmation, MessageChannelOpenFailure, MessageChannelRequest,
    },
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

    let chan = match state.channels.allocate_channel(
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
        sender_channel: chan.remote_channel_number,
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

#[declare_session_state_with_allowed_message_types(structure = AcceptsChannelMessages, msg_type = [MessageType::ChannelRequest])]
fn process(message_data: &[u8]) {
    let (_, msg) = MessageChannelRequest::deserialize(message_data)?;

    println!("{:?}", msg.recipient_channel);
    let chan = state.channels.channels.get(&msg.recipient_channel);

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
            writer,
            &MessageChannelData {
                recipient_channel: msg.recipient_channel,
                data: SharedSSHSlice(buf.as_slice()),
            },
        )?;
    }
    Ok((next, SessionStates::AcceptsChannelMessages(self.clone())))
}
