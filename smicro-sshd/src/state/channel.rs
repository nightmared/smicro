use std::{
    collections::HashMap,
    process::{ChildStderr, ChildStdin, ChildStdout},
};

use smicro_common::{BufferCreationError, LoopingBuffer};

use crate::{error::Error, packet::MAX_PKT_SIZE};

#[derive(Debug)]
pub struct ChannelCommand {
    pub command: std::process::Child,
    pub stdin: ChildStdin,
    pub stdout: ChildStdout,
    pub stderr: ChildStderr,
    pub stdin_buffer: LoopingBuffer<MAX_PKT_SIZE>,
    pub stdout_buffer: LoopingBuffer<MAX_PKT_SIZE>,
    pub stderr_buffer: LoopingBuffer<MAX_PKT_SIZE>,
}

#[derive(Debug)]
pub struct Channel {
    pub remote_channel_number: u32,
    pub receiver_window_size: u32,
    pub sender_window_size: u32,
    pub max_pkt_size: u32,
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
    pub channels_changed: bool,
    pub num_channels: u32,
}

impl ChannelManager {
    pub fn new() -> Self {
        ChannelManager {
            channels: HashMap::new(),
            channels_changed: false,
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
}
