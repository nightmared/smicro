use std::{cmp::min, collections::HashSet, io::ErrorKind};

use log::{debug, trace, warn};
use mio::{Poll, event::Event};
use smicro_common::{LoopingBufferReader, LoopingBufferWriter};
use smicro_types::ssh::types::SharedSSHSlice;

use crate::{
    error::Error,
    messages::channel::{
        ChannelExtendedDataCode, MessageChannelClose, MessageChannelData,
        MessageChannelExtendedData, MessageChannelRequest, MessageChannelWindowAdjust,
    },
    packet::{MAX_PKT_SIZE, write_message},
    state::channel::{Channel, ChannelState, ChannelType, DataChannel, POLL_NB_PER_CHAN},
    state::{DirectionState, State},
};

pub fn flush_data_to_channel<
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
    if readable_data.is_empty() || max_chan_pkt_size <= 72 {
        return Ok(());
    }
    let max_write_size = max_chan_pkt_size - 72;
    let data_len = min(readable_data.len() as u32, max_write_size);
    if *window_size < data_len {
        debug!("Waiting for a window size increase");
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
            sender.bytes_counter += data_len as u64;
            Ok(())
        }
        Err(Error::IoError(e)) if e.kind() == ErrorKind::WouldBlock => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn handle_channel_data(event: &Event, state: &mut State) -> Result<(), Error> {
    let channel_number = (event.token().0 / POLL_NB_PER_CHAN) as u32 - 1;
    debug!(
        "Received data from the process running for channel {}",
        channel_number
    );
    if let Ok(chan) = state.channels.get_channel(channel_number) {
        let cmd = chan
            .command
            .as_mut()
            .ok_or(Error::MissingCommandInChannel)?;

        match cmd.handle_channel_message(event, channel_number, &mut chan.state) {
            Ok(_) => {}
            Err(e) if e == nix::Error::EPIPE => {
                debug!("Got a disconnection event on channel {}", channel_number);
                chan.state = ChannelState::Stopped;
            }
            Err(e) => {
                return Err(Error::HandleEventFailed(e));
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

pub fn flush_channel<const SIZE: usize, T: LoopingBufferWriter<SIZE>>(
    chan: &mut Channel,
    sender: &mut DirectionState,
    output_buf: &mut T,
) -> Result<(), Error> {
    if let Some(ref mut cmd) = chan.command {
        // bump the receiver window size, if required
        if chan.receiver_window_size < MAX_PKT_SIZE as u32 {
            debug!("Bumping the receiver window size");
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
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        match cmd {
            ChannelType::ChannelTcp(cmd) => {
                flush_data_to_channel(
                    output_buf,
                    &mut cmd.data_out,
                    chan.remote_channel_number,
                    chan.max_pkt_size,
                    &mut chan.sender_window_size,
                    sender,
                    false,
                )?;
            }
            ChannelType::ChannelCommand(cmd) => {
                if !cmd.stderr.get_readable_data().is_empty() {
                    flush_data_to_channel(
                        output_buf,
                        &mut cmd.stderr,
                        chan.remote_channel_number,
                        chan.max_pkt_size,
                        &mut chan.sender_window_size,
                        sender,
                        true,
                    )?;
                }
                if !cmd.stdout.get_readable_data().is_empty() {
                    flush_data_to_channel(
                        output_buf,
                        &mut cmd.stdout,
                        chan.remote_channel_number,
                        chan.max_pkt_size,
                        &mut chan.sender_window_size,
                        sender,
                        false,
                    )?;
                }
            }
        }
    }

    Ok(())
}

pub fn process_channel_states<const SIZE: usize, W: LoopingBufferWriter<SIZE>>(
    state: &mut State,
    sender_buf: &mut W,
    poll: &mut Poll,
    registered_channels: &mut HashSet<u32>,
    channels_to_remove: &mut HashSet<u32>,
) -> Result<(), Error> {
    for (&chan_number, chan) in state.channels.channels.iter_mut() {
        match chan.state {
            ChannelState::Running | ChannelState::RemoteEof => {
                // register newly created channels on the event loop
                if let Some(cmd) = &mut chan.command {
                    if registered_channels.insert(chan_number) {
                        cmd.register(poll, chan_number)
                            .map_err(Error::RegistrationManagementError)?;
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
                if chan.state == ChannelState::Running || chan.state == ChannelState::RemoteEof {
                    chan.state = ChannelState::Stopped;
                }
            }
            ChannelState::Stopped => {
                if chan.state == ChannelState::Running || chan.state == ChannelState::RemoteEof {
                    write_message(
                        &mut state.sender,
                        sender_buf,
                        &MessageChannelClose {
                            recipient_channel: chan.remote_channel_number,
                        },
                    )?;
                }

                debug!("Close order sent to channel {}", chan_number);

                chan.state = ChannelState::Shutdowned;
            }
            ChannelState::Shutdowned => {
                // stop receiving data from that end
                if registered_channels.remove(&chan_number) {
                    debug!("Unregistering channel {}", chan_number);
                    if let Some(cmd) = &mut chan.command {
                        cmd.unregister(poll)
                            .map_err(Error::RegistrationManagementError)?;
                    }
                } else {
                    let mut remove = true;
                    if let Some(ChannelType::ChannelCommand(cmd)) = &mut chan.command {
                        // TODO: fix this
                        // inhibit the removal until all data was transferred
                        remove = cmd.stdout.get_readable_data().is_empty()
                            && cmd.stderr.get_readable_data().is_empty();
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
