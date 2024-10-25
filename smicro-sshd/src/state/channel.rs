use std::{
    collections::HashMap,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    pipe::{PipeReader, PipeWriter},
    process::{ChildStderr, ChildStdin, ChildStdout},
};

use log::trace;
use nix::pty::OpenptyResult;
use smicro_common::{BufferCreationError, LoopingBuffer, LoopingBufferReader};

use crate::{
    error::Error, packet::MAX_PKT_SIZE, read_stream_to_buffer, write_buffer_to_stream,
    NonIOProgress,
};

#[derive(Debug)]
pub struct ChannelFdWithoutPty {
    pub stdin: ChildStdin,
    pub stdout: ChildStdout,
    pub stderr: ChildStderr,
}

#[derive(Debug)]
pub enum ChannelFdWrapper {
    WithPty(OwnedFd),
    WithoutPty(ChannelFdWithoutPty),
}

#[derive(Debug)]
pub struct ChannelCommand {
    pub command: std::process::Child,
    pub fds: ChannelFdWrapper,
    pub stdin_buffer: LoopingBuffer<MAX_PKT_SIZE>,
    pub stdout_buffer: LoopingBuffer<MAX_PKT_SIZE>,
    pub stderr_buffer: LoopingBuffer<MAX_PKT_SIZE>,
}

impl ChannelCommand {
    pub fn flush_readable_data(&mut self) -> Result<NonIOProgress, Error> {
        let mut non_io_backed_progress = NonIOProgress::Done;
        match &mut self.fds {
            ChannelFdWrapper::WithPty(pty) => {
                let mut pipe_reader = unsafe { PipeReader::from_raw_fd(pty.as_raw_fd()) };
                non_io_backed_progress |=
                    read_stream_to_buffer(&mut pipe_reader, &mut self.stdout_buffer)?;
                // Do not drop the raw fd, as we still need it
                std::mem::forget(pipe_reader);
            }
            ChannelFdWrapper::WithoutPty(ref mut fds) => {
                non_io_backed_progress |=
                    read_stream_to_buffer(&mut fds.stdout, &mut self.stdout_buffer)?;
                non_io_backed_progress |=
                    read_stream_to_buffer(&mut fds.stderr, &mut self.stderr_buffer)?;
            }
        }
        Ok(non_io_backed_progress)
    }

    pub fn flush_writeable_data(&mut self) -> Result<(), Error> {
        if self.stdin_buffer.get_readable_data().is_empty() {
            return Ok(());
        }

        match &mut self.fds {
            ChannelFdWrapper::WithPty(pty) => {
                let mut pipe_writer = unsafe { PipeWriter::from_raw_fd(pty.as_raw_fd()) };
                write_buffer_to_stream(&mut self.stdin_buffer, &mut pipe_writer)?;
                std::mem::forget(pipe_writer);
                Ok(())
            }
            ChannelFdWrapper::WithoutPty(ref mut fds) => Ok(write_buffer_to_stream(
                &mut self.stdin_buffer,
                &mut fds.stdin,
            )?),
        }
    }
}

impl Drop for ChannelCommand {
    fn drop(&mut self) {
        trace!("Dropping the command part of a channel");
        self.command
            .kill()
            .expect("Could not kill the child process");
        let _ = self.command.wait();
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
    pub term: Option<OpenptyResult>,
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
                term: None,
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
