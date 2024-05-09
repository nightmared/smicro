use std::fmt::{Debug, Display};
use std::io::{Error, ErrorKind, Write};

#[derive(thiserror::Error, Debug)]
pub enum BufferCreationError {
    #[error("A memory allocation failed")]
    AllocationFailed(std::io::Error),
    #[error("Could not create a virtual buffer with memfd_create")]
    VirtualFileCreationFailed(std::io::Error),
    #[error("Could not truncate the virtual buffer")]
    VirtualFileTruncationFailed(std::io::Error),
}

pub fn create_circular_buffer(
    max_pkt_size: usize,
) -> Result<&'static mut [u8], BufferCreationError> {
    unsafe {
        // reserve a memory map where we map twice our memory mapping, so that there is no risk of
        // overwriting an existing memory map
        let overwritable_mapping = libc::mmap(
            std::ptr::null_mut(),
            2 * max_pkt_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        );
        if overwritable_mapping as usize == usize::MAX {
            return Err(BufferCreationError::AllocationFailed(
                std::io::Error::last_os_error(),
            ));
        }

        // Right now, our memory looks like this:
        // <------- overwritable_mapping ------->
        // --------------------------------------
        // | MAX_PKT_SIZE    | MAX_PKT_SIZE     |
        // --------------------------------------
        //                  | |
        //            Anonymous memory

        let fd = libc::memfd_create(b"read_buffer\0".as_ptr() as *const i8, 0);
        if fd == -1 {
            return Err(BufferCreationError::VirtualFileCreationFailed(
                std::io::Error::last_os_error(),
            ));
        }

        if libc::ftruncate(fd, max_pkt_size as i64) == -1 {
            return Err(BufferCreationError::VirtualFileTruncationFailed(
                std::io::Error::last_os_error(),
            ));
        }

        let first_map = libc::mmap(
            overwritable_mapping,
            max_pkt_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_FIXED | libc::MAP_SHARED,
            fd,
            0,
        );
        if first_map as usize == usize::MAX {
            return Err(BufferCreationError::AllocationFailed(
                std::io::Error::last_os_error(),
            ));
        }

        let second_map = libc::mmap(
            overwritable_mapping.offset(max_pkt_size as isize),
            max_pkt_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_FIXED | libc::MAP_SHARED,
            fd,
            0,
        );
        if second_map as usize == usize::MAX {
            return Err(BufferCreationError::AllocationFailed(
                std::io::Error::last_os_error(),
            ));
        }

        // Our memory now looks like this:
        // <------- overwritable_mapping ------->
        // <--- first_map ---><--- second_map -->
        // --------------------------------------
        // | MAX_PKT_SIZE    | MAX_PKT_SIZE     |
        // --------------------------------------
        //         \               /
        //          \             /
        //           \           /
        //        <-- memfd file -->
        //        -------------------
        //        | MAX_PKT_SIZE    |
        //        -------------------
        // Which means both memory areas are completely aliases,
        // and the two mapping together loop, hence forming a ringbuffer

        Ok(std::slice::from_raw_parts_mut(
            overwritable_mapping as *mut u8,
            2 * max_pkt_size,
        ))
    }
}

pub trait LoopingBufferWriter<const SIZE: usize> {
    /// Bump the buffer length by `offset` bytes (`offset` being
    /// the number of bytes that were written in the buffer).
    fn advance_writer_pos(&mut self, offset: usize);

    /// Write data directly in the buffer
    fn write(&mut self, buf: &[u8]) -> Result<(), Error>;

    /// Return a buffer to the part that is not initialized yet
    fn get_writable_buffer(&mut self) -> &mut [u8];
}

pub trait LoopingBufferReader<const SIZE: usize> {
    /// Return a buffer that contains initialized data
    fn get_readable_data<'a>(&'a mut self) -> &'a mut [u8];

    /// Decrease the buffer length by `offset` bytes (`offset` being
    /// the number of bytes that were consumed in the buffer and can be discarded).
    fn advance_reader_pos(&mut self, offset: usize);
}

/// A mutable circular buffer
// The internal invariants at any point are:
// - end_pos >= start_pos
// - size >= end_pos - start_pos (otherwise data would be overwritten)
// - size >= start_pos (we always reduce start_pos
// - the used space is end_pos - start_pos bytes long, starting at start_pos:
//   [start_pos, end_pos[
// - the free (not initialized yet) space is size - used_space bytes long, that is size - (end_pos - start_pos),
//   starting at end_pos:
//   [end_pos, end_pos + (size - (end_pos - start_pos))[ = [end_pos, size + start_pos[
// TODO: implement Drop to properly deallocate the memory mappings and the memfd
pub struct LoopingBuffer<const SIZE: usize> {
    buf: &'static mut [u8],
    start_pos: usize,
    end_pos: usize,
}

impl<const SIZE: usize> Debug for LoopingBuffer<SIZE> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopingBuffer")
            .field("buf", &"<REDACTED>")
            .field("start_pos", &self.start_pos)
            .field("end_pos", &self.end_pos)
            .finish()
    }
}

impl<const SIZE: usize> LoopingBuffer<SIZE> {
    pub fn new() -> Result<Self, BufferCreationError> {
        let buf = create_circular_buffer(SIZE)?;
        Ok(Self {
            buf,
            start_pos: 0,
            end_pos: 0,
        })
    }

    /// Return an 'atomic' writer.
    /// By that, we mean atomic not in the sense of 'usable concurrently',
    /// but in the sense that all the writes performed against it will only be commited
    /// to the backing LoopingBuffer when calling `commit()`. This means that
    /// all writes will be registered at once, or will not be (if an error happened
    /// at some point).
    pub fn get_atomic_writer<'a>(&'a mut self) -> AtomicLoopingBufferWriter<'a, SIZE> {
        let end_pos = self.end_pos;
        AtomicLoopingBufferWriter {
            inner: self,
            end_pos,
        }
    }
}

impl<const SIZE: usize> LoopingBufferReader<SIZE> for LoopingBuffer<SIZE> {
    fn get_readable_data<'a>(&'a mut self) -> &'a mut [u8] {
        &mut self.buf[self.start_pos..self.end_pos]
    }

    /// Decrease the buffer length by `offset` bytes (`offset` being
    /// the number of bytes that were consumed in the buffer and can be discarded).
    fn advance_reader_pos(&mut self, offset: usize) {
        if self.start_pos + offset > self.end_pos {
            panic!("An impossible number of bytes were read from the buffer, possible attack?");
        }

        self.start_pos += offset;

        // Thanks to the properties of our doubly-mapped buffer, we can loop like this
        if self.start_pos >= SIZE {
            self.start_pos %= SIZE;
            self.end_pos %= SIZE;
        }
    }
}

impl<const SIZE: usize> LoopingBufferWriter<SIZE> for LoopingBuffer<SIZE> {
    fn advance_writer_pos(&mut self, offset: usize) {
        let new_size = self.end_pos + offset - self.start_pos;
        if new_size > SIZE {
            panic!("An impossible number of bytes were written in the buffer, possible attack?");
        }
        self.end_pos += offset;
    }

    fn write(&mut self, buf: &[u8]) -> Result<(), Error> {
        let write_len = buf.len();
        let new_size = self.end_pos + write_len - self.start_pos;
        if new_size > SIZE {
            return Err(Error::new(
                ErrorKind::WouldBlock,
                "Trying to write too much",
            ));
        }

        self.buf[self.end_pos..self.end_pos + write_len].copy_from_slice(buf);
        self.end_pos += write_len;
        Ok(())
    }

    fn get_writable_buffer(&mut self) -> &mut [u8] {
        &mut self.buf[self.end_pos..SIZE + self.start_pos]
    }
}

pub struct AtomicLoopingBufferWriter<'a, const SIZE: usize> {
    inner: &'a mut LoopingBuffer<SIZE>,
    end_pos: usize,
}

impl<'a, const SIZE: usize> AtomicLoopingBufferWriter<'a, SIZE> {
    pub fn commit(self) {
        self.inner
            .advance_writer_pos(self.end_pos - self.inner.end_pos);
    }
}

impl<'a, const SIZE: usize> LoopingBufferWriter<SIZE> for AtomicLoopingBufferWriter<'a, SIZE> {
    fn advance_writer_pos(&mut self, offset: usize) {
        let new_size = self.end_pos + offset - self.inner.start_pos;
        if new_size > SIZE {
            panic!("An impossible number of bytes were written in the buffer, possible attack?");
        }
        self.end_pos += offset;
    }

    fn write(&mut self, buf: &[u8]) -> Result<(), Error> {
        let write_len = buf.len();
        let new_size = self.end_pos + write_len - self.inner.start_pos;
        if new_size > SIZE {
            return Err(Error::new(
                ErrorKind::WouldBlock,
                "Trying to write too much",
            ));
        }

        self.inner.buf[self.end_pos..self.end_pos + write_len].copy_from_slice(buf);
        self.end_pos += write_len;
        Ok(())
    }

    fn get_writable_buffer(&mut self) -> &mut [u8] {
        &mut self.inner.buf[self.end_pos..SIZE + self.inner.start_pos]
    }
}
