use std::{
    fmt::Debug,
    marker::PhantomData,
    os::fd::{AsFd, AsRawFd},
};

use log::{info, trace, warn};

use mio::{Interest, Registry, Token, unix::SourceFd};
use nix::{Error, errno::Errno, sys::eventfd::EventFd};
use smicro_common::{LoopingBuffer, LoopingBufferReader, LoopingBufferWriter};

pub trait ReadDirection {}

pub struct ReadFromStream;
impl ReadDirection for ReadFromStream {}
pub struct ReadFromBuffer;
impl ReadDirection for ReadFromBuffer {}

pub trait IOOperation {
    fn register(&self, registry: &Registry, register_fd: bool) -> Result<(), std::io::Error>;
    fn deregister(&self, registry: &Registry, unregister_fd: bool) -> Result<(), std::io::Error>;
    fn handle_event(&mut self, tok: Token) -> Result<(), Error>;
    fn notify(&mut self);
}

#[derive(PartialEq)]
enum StreamManagerStatus {
    Ready,
    Blocked,
}

pub struct FdStreamManager<const BUF_SIZE: usize, I, D: ReadDirection> {
    pub fd: I,
    pub fd_identifier: usize,
    status: StreamManagerStatus,
    pub buffer: LoopingBuffer<BUF_SIZE>,
    // token used to identify the notification eventfd in the poller
    pub buffer_identifier: usize,
    // eventfd triggered when the buffer is available
    pub buffer_notifier: EventFd,
    _direction: PhantomData<D>,
}

impl<const BUF_SIZE: usize, I, D: ReadDirection> Debug for FdStreamManager<BUF_SIZE, I, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FdStreamManager").finish()
    }
}

impl<const BUF_SIZE: usize, I, D: ReadDirection> FdStreamManager<BUF_SIZE, I, D> {
    pub fn new(
        fd: I,
        fd_identifier: usize,
        buffer: LoopingBuffer<BUF_SIZE>,
        buffer_identifier: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            fd,
            fd_identifier,
            status: StreamManagerStatus::Ready,
            buffer,
            buffer_identifier,
            buffer_notifier: EventFd::new()?,
            _direction: PhantomData,
        })
    }
}

impl<const BUF_SIZE: usize, I: AsRawFd> IOOperation
    for FdStreamManager<BUF_SIZE, I, ReadFromStream>
{
    fn register(&self, registry: &Registry, register_fd: bool) -> Result<(), std::io::Error> {
        registry.register(
            &mut SourceFd(&self.buffer_notifier.as_raw_fd()),
            Token(self.buffer_identifier),
            Interest::READABLE,
        )?;

        if register_fd {
            registry.register(
                &mut SourceFd(&self.fd.as_raw_fd()),
                Token(self.fd_identifier),
                Interest::READABLE,
            )?;
        }

        Ok(())
    }

    fn deregister(&self, registry: &Registry, unregister_fd: bool) -> Result<(), std::io::Error> {
        registry.deregister(&mut SourceFd(&self.buffer_notifier.as_raw_fd()))?;
        if unregister_fd {
            registry.deregister(&mut SourceFd(&self.fd.as_raw_fd()))
        } else {
            Ok(())
        }
    }

    fn handle_event(&mut self, tok: Token) -> Result<(), Error> {
        if tok.0 != self.fd_identifier && tok.0 != self.buffer_identifier {
            warn!("Received an invalid token event");
            return Ok(());
        }

        if tok.0 == self.buffer_identifier {
            self.buffer_notifier.read().map_err(|e| {
                warn!("EventFd signaling failed: {:?}", e);
                Error::EIO
            })?;
        }

        loop {
            let writeable_buffer = self.buffer.get_writable_buffer();
            if writeable_buffer.is_empty() {
                // cannot write: the output buffer is full
                self.status = StreamManagerStatus::Blocked;
                return Ok(());
            }
            match nix::unistd::read(self.fd.as_raw_fd(), writeable_buffer) {
                Ok(written) => {
                    trace!("Read {written} bytes");
                    if written == 0 {
                        info!("File descriptor closed while reading");
                        return Err(Error::EPIPE);
                    }
                    self.buffer.advance_writer_pos(written as usize);
                }
                Err(e) if e == Errno::EWOULDBLOCK => {
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    fn notify(&mut self) {
        if self.status == StreamManagerStatus::Blocked {
            self.buffer_notifier
                .arm()
                .expect("Could not write to the eventfd");
            self.status = StreamManagerStatus::Ready;
        }
    }
}

impl<const BUF_SIZE: usize, I: AsFd + AsRawFd> LoopingBufferWriter<BUF_SIZE>
    for FdStreamManager<BUF_SIZE, I, ReadFromStream>
{
    fn write(&mut self, buf: &[u8]) -> Result<(), std::io::Error> {
        self.buffer.write(buf)
    }

    fn advance_writer_pos(&mut self, offset: usize) {
        self.buffer.advance_writer_pos(offset);
    }

    fn get_writable_buffer(&mut self) -> &mut [u8] {
        self.buffer.get_writable_buffer()
    }
}

impl<const BUF_SIZE: usize, I: AsFd + AsRawFd> LoopingBufferReader<BUF_SIZE>
    for FdStreamManager<BUF_SIZE, I, ReadFromStream>
{
    fn get_readable_data(&mut self) -> &mut [u8] {
        self.buffer.get_readable_data()
    }

    fn advance_reader_pos(&mut self, offset: usize) {
        self.buffer.advance_reader_pos(offset);
        self.notify();
    }
}

impl<const BUF_SIZE: usize, I: AsFd + AsRawFd> IOOperation
    for FdStreamManager<BUF_SIZE, I, ReadFromBuffer>
{
    fn register(&self, registry: &Registry, register_fd: bool) -> Result<(), std::io::Error> {
        registry.register(
            &mut SourceFd(&self.buffer_notifier.as_raw_fd()),
            Token(self.buffer_identifier),
            Interest::READABLE,
        )?;

        if register_fd {
            registry.register(
                &mut SourceFd(&self.fd.as_raw_fd()),
                Token(self.fd_identifier),
                Interest::WRITABLE,
            )?;
        }

        Ok(())
    }

    fn deregister(&self, registry: &Registry, unregister_fd: bool) -> Result<(), std::io::Error> {
        registry.deregister(&mut SourceFd(&self.buffer_notifier.as_raw_fd()))?;
        if unregister_fd {
            registry.deregister(&mut SourceFd(&self.fd.as_raw_fd()))
        } else {
            Ok(())
        }
    }

    fn handle_event(&mut self, tok: Token) -> Result<(), Error> {
        match tok.0 {
            // the fd is writable again
            v if v == self.fd_identifier => {
                self.status = StreamManagerStatus::Ready;
            }
            // data is available in the buffer
            v if v == self.buffer_identifier => {}
            _ => {
                warn!("Received an invalid token event");
                return Ok(());
            }
        }

        // write as much data as possible to the fd from the buffer
        loop {
            let read_buffer = self.buffer.get_readable_data();
            if read_buffer.is_empty() {
                break;
            }
            // we cannot write yet
            if self.status == StreamManagerStatus::Blocked {
                break;
            }
            match nix::unistd::write(self.fd.as_fd(), read_buffer) {
                Ok(written) => {
                    trace!("Written {written} bytes");
                    if written == 0 {
                        info!("Connection closed while writing to a stream");
                        return Err(Error::EPIPE);
                    }
                    self.buffer.advance_reader_pos(written);
                }
                Err(e) if e == Errno::EWOULDBLOCK => {
                    // the stream is full
                    self.status = StreamManagerStatus::Blocked;
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    fn notify(&mut self) {
        self.buffer_notifier
            .arm()
            .expect("Could not write to the eventfd");
    }
}

impl<const BUF_SIZE: usize, I: AsFd + AsRawFd> LoopingBufferWriter<BUF_SIZE>
    for FdStreamManager<BUF_SIZE, I, ReadFromBuffer>
{
    fn write(&mut self, buf: &[u8]) -> Result<(), std::io::Error> {
        self.buffer.write(buf)?;
        self.notify();
        Ok(())
    }

    fn advance_writer_pos(&mut self, offset: usize) {
        self.buffer.advance_writer_pos(offset);
        self.notify();
    }

    fn get_writable_buffer(&mut self) -> &mut [u8] {
        self.buffer.get_writable_buffer()
    }
}

impl<const BUF_SIZE: usize, I: AsFd + AsRawFd> LoopingBufferReader<BUF_SIZE>
    for FdStreamManager<BUF_SIZE, I, ReadFromBuffer>
{
    fn get_readable_data(&mut self) -> &mut [u8] {
        self.buffer.get_readable_data()
    }

    fn advance_reader_pos(&mut self, offset: usize) {
        self.buffer.advance_reader_pos(offset);
    }
}
