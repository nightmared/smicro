#[derive(thiserror::Error, Debug)]
pub enum BufferCreationError {
    #[error("A memory allocation failed")]
    AllocationFailed(std::io::Error),
    #[error("Could not create a virtual buffer with memfd_create")]
    VirtualFileCreationFailed(std::io::Error),
    #[error("Could not truncate the virtual buffer")]
    VirtualFileTruncationFailed(std::io::Error),
}

pub fn create_read_buffer(max_pkt_size: usize) -> Result<&'static mut [u8], BufferCreationError> {
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

/// A mutable circular buffer
// The internal invariants at any point are:
// - end_pos >= start_pos
// - size >= end_pos - start_pos (otherwise data would be overwritten)
// - size >= start_pos (we always reduce start_pos
// - the used space is end_pos - start_pos bytes long, starting at start_pos:
//   [start_pos, end_pos[
// - the free (not initialized yet) space is size - start_pos bytes long, starting at end_pos:
//   [end_pos, end_pos + (size - start_pos)[
// TODO: implement Drop to properly deallocate the memory mappings and the memfd
#[derive(Debug)]
pub struct LoopingBuffer<const SIZE: usize> {
    buf: &'static mut [u8],
    start_pos: usize,
    end_pos: usize,
}

impl<const SIZE: usize> LoopingBuffer<SIZE> {
    pub fn new() -> Result<Self, BufferCreationError> {
        let buf = create_read_buffer(SIZE)?;
        Ok(Self {
            buf,
            start_pos: 0,
            end_pos: 0,
        })
    }

    /// Return a buffer that contains initialized data
    pub fn get_readable_data<'a>(&'a mut self) -> &'a mut [u8] {
        &mut self.buf[self.start_pos..self.end_pos]
    }

    /// Return a buffer to the part that is not initiliazed yet
    pub fn get_writable_buffer<'a>(&'a mut self) -> &'a mut [u8] {
        &mut self.buf[self.end_pos..self.end_pos + SIZE - self.start_pos]
    }

    /// Bump the buffer length by `offset` bytes (`offset` being
    /// the number of bytes that were written in the buffer).
    pub fn advance_writer_pos(&mut self, offset: usize) {
        if offset > SIZE - self.start_pos {
            panic!("An impossible number of bytes were written in the buffer, possible attack?");
        }
        self.end_pos += offset;
    }

    /// Decrease the buffer length by `offset` bytes (`offset` being
    /// the number of bytes that were consumed in the buffer and can be discarded).
    pub fn advance_reader_pos(&mut self, offset: usize) {
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
