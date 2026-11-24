use std::{io, mem, task::Poll};

use tokio::io::{AsyncRead, ReadBuf};

use crate::transport::Transport;

/// Capacity of the ciphertext read buffer, enough for a record header plus the largest
/// ciphertext `BoringSSL` accepts (`SSL3_RT_MAX_ENCRYPTED_LENGTH`).
///
/// `BoringSSL` may request record headers and bodies in separate BIO reads. Buffering lets these
/// reads share data from one underlying read. Larger bursts may require multiple refills.
const READ_BUF_CAPACITY: usize = 17 * 1024;

/// Ciphertext read from the transport but not yet taken by `BoringSSL`.
#[derive(Default)]
pub struct ReadBuffer {
    bytes: Vec<u8>,
    // The next byte to hand out is `bytes[pos]`.
    pos: usize,
}

impl ReadBuffer {
    /// Whether no ciphertext is waiting; a drained buffer is released at once.
    #[inline]
    pub(crate) const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Copies buffered ciphertext into `buf`, first refilling an empty buffer from `transport`.
    #[inline]
    pub(crate) fn read<S, R>(
        &mut self,
        transport: &mut Transport<S>,
        capacity: usize,
        copy: impl FnOnce(&[u8]) -> R,
    ) -> io::Result<R>
    where
        S: AsyncRead,
    {
        if capacity == 0 {
            return Ok(copy(&[]));
        }
        if self.bytes.is_empty() {
            self.fill(transport)?;
        }

        let buffered = &self.bytes[self.pos..];
        let n = buffered.len().min(capacity);
        let result = copy(&buffered[..n]);
        self.pos += n;

        // Release the buffer as soon as it is drained, so a connection that stops reading here,
        // such as one returned to a pool, does not keep it.
        if self.pos == self.bytes.len() {
            self.bytes = Vec::new();
            self.pos = 0;
        }
        Ok(result)
    }

    /// Fills the empty buffer with a single read of `transport`.
    ///
    /// Maps the stream's `Poll::Pending` to `WouldBlock`; the stream registers the waker. On
    /// failure the buffer stays empty and unallocated.
    fn fill<S>(&mut self, transport: &mut Transport<S>) -> io::Result<()>
    where
        S: AsyncRead,
    {
        let (stream, cx) = transport.parts()?;
        let mut bytes = mem::take(&mut self.bytes);
        bytes.reserve(READ_BUF_CAPACITY);
        self.pos = 0;

        let mut buf = ReadBuf::uninit(bytes.spare_capacity_mut());
        match stream.poll_read(cx, &mut buf)? {
            Poll::Ready(()) => {
                let filled = buf.filled().len();
                // SAFETY: `ReadBuf` guarantees its first `filled` bytes are initialized.
                unsafe { bytes.set_len(filled) };
                if filled != 0 {
                    self.bytes = bytes;
                }
                Ok(())
            }
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Read, pin::Pin, task::Context};

    use super::*;
    use crate::bio::StreamWrapper;

    /// Yields the given bytes in one read, then stays pending.
    struct Once(Vec<u8>);

    impl AsyncRead for Once {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.0.is_empty() {
                return Poll::Pending;
            }
            buf.put_slice(&mem::take(&mut self.0));
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn read_buf_released_when_drained() {
        let mut wrapper = StreamWrapper::new(Once(vec![1; 100]));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        // SAFETY: The context is local to this test and never otherwise used;
        // the stream is Unpin and the transport stays on this thread.
        unsafe { wrapper.transport.set_context(&mut cx) };

        let mut buf = [0; 60];
        assert_eq!(wrapper.read(&mut buf).unwrap(), 60);
        assert_eq!(wrapper.read_buf.bytes.capacity(), READ_BUF_CAPACITY);

        assert_eq!(wrapper.read(&mut buf).unwrap(), 40);
        assert_eq!(wrapper.read_buf.bytes.capacity(), 0);

        let err = wrapper.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(wrapper.read_buf.bytes.capacity(), 0);
        wrapper.transport.clear_context();
    }

    #[test]
    fn empty_read_and_eof_do_not_allocate_or_poll_unnecessarily() {
        let mut wrapper = StreamWrapper::new(tokio::io::empty());
        // Without an installed context, any transport poll would fail.
        assert_eq!(wrapper.read(&mut []).unwrap(), 0);
        assert_eq!(wrapper.read_buf.bytes.capacity(), 0);

        let mut cx = Context::from_waker(std::task::Waker::noop());
        // SAFETY: The context is local to this test and never otherwise used;
        // the stream is Unpin and the transport stays on this thread.
        unsafe { wrapper.transport.set_context(&mut cx) };
        assert_eq!(wrapper.read(&mut [0]).unwrap(), 0);
        assert_eq!(wrapper.read_buf.bytes.capacity(), 0);
        wrapper.transport.clear_context();
    }
}
