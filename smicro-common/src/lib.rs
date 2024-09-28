#![feature(unix_socket_ancillary_data)]
#![feature(allocator_api)]

use std::alloc::Allocator;
use std::cell::UnsafeCell;
use std::fmt::Debug;
use std::io::{Error, ErrorKind};
use std::ptr::{slice_from_raw_parts_mut, NonNull};
use std::sync::Arc;
#[cfg(feature = "share_loop")]
use std::{
    io::{IoSlice, IoSliceMut},
    os::unix::net::{AncillaryData, AncillaryError, SocketAncillary, UnixStream},
};

#[derive(thiserror::Error, Debug)]
pub enum BufferCreationError {
    #[error("A memory allocation failed")]
    AllocationFailed(std::io::Error),
    #[error("Could not create a virtual buffer with memfd_create")]
    VirtualFileCreationFailed(std::io::Error),
    #[error("Could not truncate the virtual buffer")]
    VirtualFileTruncationFailed(std::io::Error),
    #[cfg(feature = "share_loop")]
    #[error("Could not read enough data to recreate a LoopingBuffer")]
    MissingDataInStream,
    #[cfg(feature = "share_loop")]
    #[error("No associated file descripto: cannot restore the LoopingBuffer")]
    MissingFdInStream,
    #[cfg(feature = "share_loop")]
    #[error("Received an incorrect length for the LoopingBuffer")]
    LengthMismatch,
    #[cfg(feature = "share_loop")]
    #[error("Could not read data from the stream")]
    StreamRecvError(std::io::Error),
    #[cfg(feature = "share_loop")]
    #[error("Could not decode ancillary data")]
    AncillaryDecodeError(AncillaryError),
}

pub fn create_circular_buffer_from_existing_fd(
    buf_size: usize,
    fd: i32,
) -> Result<&'static mut [u8], BufferCreationError> {
    unsafe {
        // reserve a memory map where we map twice our memory mapping, so that there is no risk of
        // overwriting an existing memory map
        let overwritable_mapping = libc::mmap(
            std::ptr::null_mut(),
            2 * buf_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED,
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

        let first_map = libc::mmap(
            overwritable_mapping,
            buf_size,
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
            overwritable_mapping.offset(buf_size as isize),
            buf_size,
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
        // Which means both memory areas completely aliases,
        // and the two mapping together loop, hence forming a ringbuffer

        Ok(std::slice::from_raw_parts_mut(
            overwritable_mapping as *mut u8,
            2 * buf_size,
        ))
    }
}

pub fn create_memfd(buf_size: usize) -> Result<i32, BufferCreationError> {
    unsafe {
        let fd = libc::memfd_create(b"read_buffer\0".as_ptr() as *const i8, 0);
        if fd == -1 {
            return Err(BufferCreationError::VirtualFileCreationFailed(
                std::io::Error::last_os_error(),
            ));
        }

        if libc::ftruncate(fd, buf_size as i64) == -1 {
            return Err(BufferCreationError::VirtualFileTruncationFailed(
                std::io::Error::last_os_error(),
            ));
        }

        Ok(fd)
    }
}

pub fn create_circular_buffer(
    buf_size: usize,
) -> Result<(i32, &'static mut [u8]), BufferCreationError> {
    let fd = create_memfd(buf_size)?;

    Ok((fd, create_circular_buffer_from_existing_fd(buf_size, fd)?))
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
pub struct LoopingBuffer<const SIZE: usize> {
    fd: i32,
    buf: &'static mut [u8],
    start_pos: usize,
    end_pos: usize,
}

impl<const SIZE: usize> Drop for LoopingBuffer<SIZE> {
    fn drop(&mut self) {
        unsafe {
            let mmap_ptr = self.buf.as_mut_ptr() as *mut libc::c_void;
            libc::munmap(mmap_ptr, SIZE);
            libc::munmap(mmap_ptr.byte_offset(SIZE as isize), SIZE);
            libc::close(self.fd);
        }
    }
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
        let (fd, buf) = create_circular_buffer(SIZE)?;
        Ok(Self {
            fd,
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

    #[cfg(feature = "share_loop")]
    /// Warning: unsafe as the looping buffer must not be used in the originating process after
    /// being sent (we risk concurrent use of the memory, and thus reading/writing uninitialized
    /// data)
    pub unsafe fn send_over_socket(&mut self, stream: &mut UnixStream) -> std::io::Result<()> {
        let mut buf = [0; 12];
        buf[0..4].copy_from_slice(&(SIZE as u32).to_be_bytes());
        buf[4..8].copy_from_slice(&(self.start_pos as u32).to_be_bytes());
        buf[8..12].copy_from_slice(&(self.end_pos as u32).to_be_bytes());
        let buf = IoSlice::new(&buf);

        let mut ancillary_buffer = [0; 128];
        let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);
        ancillary.add_fds(&[self.fd]);

        stream.send_vectored_with_ancillary(&mut [buf], &mut ancillary)?;

        Ok(())
    }

    #[cfg(feature = "share_loop")]
    pub unsafe fn receive_over_socket(
        stream: &mut UnixStream,
    ) -> Result<Self, BufferCreationError> {
        let mut ancillary_buffer = [0; 128];
        let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);

        let mut recv_buffer = [0; 12];

        let nb_read = stream
            .recv_vectored_with_ancillary(&mut [IoSliceMut::new(&mut recv_buffer)], &mut ancillary)
            .map_err(BufferCreationError::StreamRecvError)?;
        if nb_read != 12 {
            return Err(BufferCreationError::MissingDataInStream);
        }

        let mut buf = [0; 4];
        buf.copy_from_slice(&recv_buffer[0..4]);
        let size = u32::from_be_bytes(buf);

        if size as usize != SIZE {
            return Err(BufferCreationError::LengthMismatch);
        }

        buf.copy_from_slice(&recv_buffer[4..8]);
        let start_pos = u32::from_be_bytes(buf) as usize;

        buf.copy_from_slice(&recv_buffer[8..12]);
        let end_pos = u32::from_be_bytes(buf) as usize;

        let mut fd = None;
        for ancillary_result in ancillary.messages() {
            if let AncillaryData::ScmRights(mut scm_rights) =
                ancillary_result.map_err(BufferCreationError::AncillaryDecodeError)?
            {
                fd = scm_rights.next();
            }
        }

        match fd {
            Some(fd) => {
                let buf = create_circular_buffer_from_existing_fd(SIZE, fd)?;
                Ok(Self {
                    fd,
                    buf,
                    start_pos,
                    end_pos,
                })
            }
            None => Err(BufferCreationError::MissingFdInStream),
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

pub struct BumpAllocatorOnMemfdInner {
    fd: i32,
    buf: *mut u8,
    size: usize,
    last_alloc_end: usize,
    cur_alignment: usize,
}

#[derive(Clone)]
pub struct BumpAllocatorOnMemfd {
    inner: Arc<UnsafeCell<BumpAllocatorOnMemfdInner>>,
}

impl BumpAllocatorOnMemfd {
    pub fn new(size: usize) -> Result<Self, BufferCreationError> {
        let fd = create_memfd(size)?;

        unsafe {
            let buf = libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED,
                fd,
                0,
            );
            if fd as usize == usize::MAX {
                return Err(BufferCreationError::AllocationFailed(
                    std::io::Error::last_os_error(),
                ));
            }

            Ok(BumpAllocatorOnMemfd {
                inner: Arc::new(UnsafeCell::new(BumpAllocatorOnMemfdInner {
                    fd,
                    buf: buf as *mut u8,
                    size,
                    last_alloc_end: 0,
                    // mmap allocations are page-aligned
                    cur_alignment: libc::sysconf(libc::_SC_PAGESIZE) as usize,
                })),
            })
        }
    }
}

unsafe impl Allocator for BumpAllocatorOnMemfd {
    fn allocate(
        &self,
        layout: std::alloc::Layout,
    ) -> Result<std::ptr::NonNull<[u8]>, std::alloc::AllocError> {
        let inner = self.inner.get();
        unsafe {
            let inner = &mut *inner;
            let required_align = layout.align();
            let cur_align = inner.cur_alignment;
            let padding_alignment_bytes = if cur_align % required_align == 0 {
                0
            } else {
                let next_aligned_pos = (cur_align + required_align) & !(required_align - 1);
                next_aligned_pos - cur_align
            };

            // not enought bytes available in the allocator
            let next_end_pos = inner.last_alloc_end + padding_alignment_bytes + layout.size();
            if next_end_pos > inner.size {
                return Err(std::alloc::AllocError);
            }

            let ptr = (*inner).buf.byte_offset(inner.last_alloc_end as isize);
            let ptr = NonNull::new_unchecked(slice_from_raw_parts_mut(ptr, layout.size()));

            let mut new_align = 1;
            while next_end_pos & !((1 << (new_align + 1)) - 1) == 0 {
                new_align += 1;
            }

            inner.last_alloc_end = next_end_pos;
            inner.cur_alignment = new_align;

            Ok(ptr)
        }
    }

    unsafe fn deallocate(&self, ptr: std::ptr::NonNull<u8>, layout: std::alloc::Layout) {
        // deallocating is a no-op, but we zero out the memory in case it was sensitive
        for i in 0..(layout.size() as isize) {
            ptr.byte_offset(i).write(0);
        }
    }
}
