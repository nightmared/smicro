use std::{
    collections::HashMap,
    process::{ChildStderr, ChildStdin, ChildStdout},
};

use log::trace;
use smicro_common::{BufferCreationError, LoopingBuffer};

use crate::{error::Error, packet::MAX_PKT_SIZE};

#[derive(Debug)]
pub struct ChannelCommand {
    pub command: std::process::Child,
    pub stdin: ChildStdin,
    pub stdin_buffer: LoopingBuffer<MAX_PKT_SIZE>,
    pub stdout: ChildStdout,
    pub stdout_buffer: LoopingBuffer<MAX_PKT_SIZE>,
    pub stderr: ChildStderr,
    pub stderr_buffer: LoopingBuffer<MAX_PKT_SIZE>,
}

impl Drop for ChannelCommand {
    fn drop(&mut self) {
        trace!("Dropping the command part of a channel");
        self.command
            .kill()
            .expect("Could not kill the child process");
    }
}

#[derive(PartialEq, Debug)]
pub enum ChannelState {
    Running,
    StoppedWithStatus(i32),
    Stopped,
    Shutdowned,
}

#[derive(Debug)]
pub struct Channel {
    pub remote_channel_number: u32,
    pub receiver_window_size: u32,
    pub sender_window_size: u32,
    pub max_pkt_size: u32,
    pub state: ChannelState,
    pub command: Option<ChannelCommand>,
}

#[derive(thiserror::Error, Debug)]
pub enum ChannelAllocationError {
    #[error("This channel number is already allocated")]
    AlreadyAllocated(u32),
    #[error("Maximum number of channels was reached, opening new channels is now blocked")]
    Overflow,
    #[error("Could not allocate the output buffer")]
    BufferAllocationFailed(#[from] BufferCreationError),
}

#[derive(Debug)]
pub struct ChannelManager {
    pub channels: HashMap<u32, Channel>,
    pub num_channels: u32,
}

impl ChannelManager {
    pub fn new() -> Self {
        ChannelManager {
            channels: HashMap::new(),
            num_channels: 0,
        }
    }

    pub fn allocate_channel(
        &mut self,
        remote_channel_number: u32,
        max_pkt_size: u32,
        window_size: u32,
    ) -> Result<u32, ChannelAllocationError> {
        let channel_num = self.num_channels;
        // We only allow 1024 channels per session
        if channel_num >= 1 << 10 {
            return Err(ChannelAllocationError::Overflow);
        }

        self.num_channels += 1;
        self.channels.insert(
            channel_num,
            Channel {
                remote_channel_number,
                receiver_window_size: window_size,
                sender_window_size: window_size,
                max_pkt_size,
                state: ChannelState::Running,
                command: None,
            },
        );

        Ok(channel_num)
    }

    pub fn get_channel(&mut self, chan_number: u32) -> Result<&mut Channel, Error> {
        self.channels
            .get_mut(&chan_number)
            .ok_or(Error::MissingCommandInChannel)
    }

    pub fn remove_channel(&mut self, chan_number: u32) -> Result<(), Error> {
        self.channels
            .remove(&chan_number)
            .map(|_| ())
            .ok_or(Error::MissingCommandInChannel)
    }
}
