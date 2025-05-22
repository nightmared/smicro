use std::{
    collections::HashMap,
    os::{
        fd::{AsRawFd, BorrowedFd, OwnedFd},
        linux::process::ChildExt,
    },
    process::{ChildStderr, ChildStdin, ChildStdout},
};

use log::{debug, trace};
use mio::{Interest, Poll, Token, event::Event, unix::SourceFd};
use smicro_common::BufferCreationError;
use smicro_macros::create_wrapper_enum_implementing_trait;

use crate::{
    error::Error,
    io::{FdStreamManager, IOOperation, ReadFromBuffer, ReadFromStream},
    packet::MAX_PKT_SIZE,
};

pub const POLL_NB_PER_CHAN: usize = 8;

#[create_wrapper_enum_implementing_trait(name = ChannelType, crypto_alg = false, clonable = false)]
#[implementors(ChannelCommand, ChannelTcp)]
pub trait DataChannel {
    fn register(&mut self, poll: &mut Poll, chan_number: u32) -> Result<(), std::io::Error>;

    fn unregister(&mut self, poll: &mut Poll) -> Result<(), std::io::Error>;

    fn handle_channel_message(
        &mut self,
        event: &Event,
        channel_number: u32,
        chan_state: &mut ChannelState,
    ) -> Result<(), nix::Error>;
}

#[derive(Debug)]
pub struct ChannelCommand {
    pub command: std::process::Child,
    pub stdin: FdStreamManager<MAX_PKT_SIZE, ChildStdin, ReadFromBuffer>,
    pub stdout: FdStreamManager<MAX_PKT_SIZE, ChildStdout, ReadFromStream>,
    pub stderr: FdStreamManager<MAX_PKT_SIZE, ChildStderr, ReadFromStream>,
}

impl DataChannel for ChannelCommand {
    fn register(&mut self, poll: &mut Poll, chan_number: u32) -> Result<(), std::io::Error> {
        debug!("Registering channel {}", chan_number);
        let token_base = (chan_number + 1) as usize * POLL_NB_PER_CHAN;
        let registry = poll.registry();

        self.stdin.fd_identifier = token_base;
        self.stdin.buffer_identifier = token_base + 1;
        self.stdin.register(registry, true)?;
        self.stdout.fd_identifier = token_base + 2;
        self.stdout.buffer_identifier = token_base + 3;
        self.stdout.register(registry, true)?;
        self.stderr.fd_identifier = token_base + 4;
        self.stderr.buffer_identifier = token_base + 5;
        self.stderr.register(registry, true)?;
        registry.register(
            &mut SourceFd(&self.command.pidfd()?.as_raw_fd()),
            Token(token_base + 6),
            Interest::READABLE,
        )?;

        Ok(())
    }

    fn unregister(&mut self, poll: &mut Poll) -> Result<(), std::io::Error> {
        let registry = poll.registry();
        self.stdin.deregister(registry, true)?;
        self.stdout.deregister(registry, true)?;
        self.stderr.deregister(registry, true)?;
        registry.deregister(&mut SourceFd(&self.command.pidfd()?.as_raw_fd()))?;

        Ok(())
    }

    fn handle_channel_message(
        &mut self,
        event: &Event,
        channel_number: u32,
        chan_state: &mut ChannelState,
    ) -> Result<(), nix::Error> {
        if event.token().0 % POLL_NB_PER_CHAN == 6 {
            debug!("Process exited on channel {}", channel_number);
            // maybe the process exited?
            if let Ok(Some(exit_status)) = self.command.try_wait() {
                *chan_state = ChannelState::StoppedWithStatus(exit_status.code().unwrap_or(255));
            }
            return Ok(());
        }

        if (event.token().0 % POLL_NB_PER_CHAN) / 2 == 0 {
            // stdin
            self.stdin.handle_event(event.token())
        } else if (event.token().0 % POLL_NB_PER_CHAN) / 2 == 1 {
            // stdout
            self.stdout.handle_event(event.token())
        } else {
            // stderr
            self.stderr.handle_event(event.token())
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

#[derive(Debug)]
pub struct ChannelTcp {
    pub socket: OwnedFd,
    // unsafe, but we know we hold the ownedFd for as long as we own the BorrowedFd
    pub data_in: FdStreamManager<MAX_PKT_SIZE, BorrowedFd<'static>, ReadFromBuffer>,
    pub data_out: FdStreamManager<MAX_PKT_SIZE, BorrowedFd<'static>, ReadFromStream>,
}

impl DataChannel for ChannelTcp {
    fn register(&mut self, poll: &mut Poll, chan_number: u32) -> Result<(), std::io::Error> {
        debug!("Registering channel {}", chan_number);
        let token_base = (chan_number + 1) as usize * POLL_NB_PER_CHAN;
        let registry = poll.registry();

        registry.register(
            &mut SourceFd(&self.socket.as_raw_fd()),
            Token(token_base),
            Interest::READABLE | Interest::WRITABLE,
        )?;

        self.data_in.fd_identifier = token_base;
        self.data_in.buffer_identifier = token_base + 1;
        self.data_in.register(registry, false)?;
        self.data_out.fd_identifier = token_base;
        self.data_out.buffer_identifier = token_base + 3;
        self.data_out.register(registry, false)?;

        Ok(())
    }

    fn unregister(&mut self, poll: &mut Poll) -> Result<(), std::io::Error> {
        let registry = poll.registry();
        registry.deregister(&mut SourceFd(&self.socket.as_raw_fd()))?;
        self.data_in.deregister(registry, false)?;
        self.data_out.deregister(registry, false)?;

        Ok(())
    }

    fn handle_channel_message(
        &mut self,
        event: &Event,
        _channel_number: u32,
        _chan_state: &mut ChannelState,
    ) -> Result<(), nix::Error> {
        if event.token().0 == self.data_in.fd_identifier {
            if event.is_readable() {
                self.data_in.handle_event(event.token())?;
            }
            if event.is_writable() {
                self.data_out.handle_event(event.token())?;
            }
            Ok(())
        } else if (event.token().0 % POLL_NB_PER_CHAN) / 2 == 0 {
            self.data_in.handle_event(event.token())
        } else {
            self.data_out.handle_event(event.token())
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum ChannelState {
    Running,
    RemoteEof,
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
    pub command: Option<ChannelType>,
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
