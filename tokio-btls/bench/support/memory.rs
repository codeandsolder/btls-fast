//! In-memory transport and the tokio-btls server driven over it between timed batches.

use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Poll, Waker},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_btls::SslStream;

use super::{BoxError, Direction, case::Tls};

/// Bytes written to one direction of the transport and not yet read.
#[derive(Default)]
struct Pipe {
    bytes: Vec<u8>,
    // The next byte to read is `bytes[pos]`.
    pos: usize,
    // Woken by the next write while a handshake read waits on this pipe.
    reader: Option<Waker>,
}

/// State both ends of one transport share.
struct Shared {
    pipes: [Pipe; 2],
    // Cleared once both handshakes are done: an empty read then fails instead of waiting.
    handshake: bool,
}

/// One end of an in-memory duplex transport, shared safely across threads.
///
/// Writes never block and are kept until read. During the handshake a read of an empty pipe
/// waits for the other end; afterwards it fails with `UnexpectedEof`, so a stray poll fails at
/// once instead of hanging the only task.
pub(super) struct MemoryStream {
    shared: Arc<Mutex<Shared>>,
    // This end reads `pipes[rx]` and writes the other pipe.
    rx: usize,
}

/// The tokio-btls server end of a memory transport, which seals or opens bodies between timed
/// batches.
pub(super) struct MemoryPeer {
    stream: SslStream<MemoryStream>,
    // One received body; empty when the peer only sends.
    buf: Vec<u8>,
}

/// Creates the two connected ends of a transport in its handshake phase.
pub(super) fn pair() -> (MemoryStream, MemoryStream) {
    let shared = Arc::new(Mutex::new(Shared {
        pipes: Default::default(),
        handshake: true,
    }));
    let client = MemoryStream {
        shared: shared.clone(),
        rx: 0,
    };
    (client, MemoryStream { shared, rx: 1 })
}

// ===== impl MemoryStream =====

impl MemoryStream {
    // The shared in-memory pipes can also be moved to another executor thread.
    // Recover poisoning after a benchmark panic so a subsequent integrity
    // check can report any incomplete record rather than panic again.
    fn lock_shared(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Bytes waiting for this end to read.
    fn unread(&self) -> usize {
        let shared = self.lock_shared();
        let pipe = &shared.pipes[self.rx];
        let unread = pipe.bytes.len() - pipe.pos;
        drop(shared);
        unread
    }

    /// Bytes this end wrote that the other end has not read.
    fn in_flight(&self) -> usize {
        let shared = self.lock_shared();
        let pipe = &shared.pipes[1 - self.rx];
        let queued = pipe.bytes.len() - pipe.pos;
        drop(shared);
        queued
    }

    /// Appends `bufs` to the pipe the other end reads.
    fn append(&self, bufs: &[IoSlice<'_>]) -> usize {
        let (written, reader) = {
            let mut shared = self.lock_shared();
            let pipe = &mut shared.pipes[1 - self.rx];
            let start = pipe.bytes.len();
            for buf in bufs {
                pipe.bytes.extend_from_slice(buf);
            }
            let written = pipe.bytes.len() - start;
            let reader = if written == 0 {
                None
            } else {
                pipe.reader.take()
            };
            drop(shared);
            (written, reader)
        };
        if let Some(reader) = reader {
            reader.wake();
        }
        written
    }
}

impl AsyncRead for MemoryStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut shared = self.lock_shared();
        let handshake = shared.handshake;
        let pipe = &mut shared.pipes[self.rx];
        let available = &pipe.bytes[pipe.pos..];
        if available.is_empty() {
            if handshake {
                pipe.reader = Some(cx.waker().clone());
                return Poll::Pending;
            }
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read past the ciphertext of the current batch",
            )));
        }

        let n = available.len().min(buf.remaining());
        buf.put_slice(&available[..n]);
        pipe.pos += n;
        if pipe.pos == pipe.bytes.len() {
            // Keep the capacity: the next batch refills the same buffer.
            pipe.bytes.clear();
            pipe.pos = 0;
        }
        drop(shared);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MemoryStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(self.append(&[IoSlice::new(buf)])))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(self.append(bufs)))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ===== impl MemoryPeer =====

impl MemoryPeer {
    /// Takes a server stream whose handshake has completed and ends the transport's handshake
    /// phase.
    ///
    /// Returns an error if the server already sent data the client never asked for.
    pub(super) fn new(
        stream: SslStream<MemoryStream>,
        direction: Direction,
        len: usize,
    ) -> Result<Self, BoxError> {
        let transport = stream.get_ref();
        let queued = {
            let mut shared = transport.lock_shared();
            shared.handshake = false;
            shared.pipes.iter().any(|pipe| pipe.pos != pipe.bytes.len())
        };
        if queued {
            return Err("memory transport holds data after the handshake".into());
        }
        let buf = match direction {
            Direction::Read => Vec::new(),
            Direction::Write => vec![0; len],
        };
        Ok(Self { stream, buf })
    }

    /// Ciphertext the client wrote that the peer has not read.
    pub(super) fn unread(&self) -> usize {
        self.stream.get_ref().unread()
    }

    /// Ciphertext the peer wrote that the client has not read.
    pub(super) fn in_flight(&self) -> usize {
        self.stream.get_ref().in_flight()
    }

    /// Seals `copies` of `part` into the transport.
    pub(super) async fn send(&mut self, part: &[u8], copies: usize) -> io::Result<()> {
        for _ in 0..copies {
            self.stream.write_all(part).await?;
        }
        self.stream.flush().await
    }

    /// Opens `copies` of `part` and compares each with it.
    ///
    /// The client's ciphertext must cover them, and nothing may follow. Only a lower bound holds
    /// for its length, since `rustls` adds a `KeyUpdate` record every 2^24 records.
    pub(super) async fn receive(&mut self, part: &[u8], copies: usize) -> Result<(), BoxError> {
        let sealed = Tls::Enabled.wire_len(part.len()) * copies;
        if self.unread() < sealed {
            return Err(format!("client wrote {} bytes, expected {sealed}", self.unread()).into());
        }
        let buf = &mut self.buf[..part.len()];
        for _ in 0..copies {
            self.stream.read_exact(buf).await?;
            if *buf != *part {
                return Err("server received a different body".into());
            }
        }
        match self.unread() {
            0 => Ok(()),
            left => Err(format!("client wrote {left} bytes beyond its bodies").into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn empty_reads_complete_without_registering_a_waker_or_requiring_ciphertext() {
        let (mut writer, mut reader) = pair();
        let counter = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let mut empty = [];
        let mut buf = ReadBuf::new(&mut empty);
        assert!(matches!(
            Pin::new(&mut reader).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, &[42]),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);

        // After the handshake, an empty buffer succeeds even when the pipe is empty,
        // but a nonempty buffer must still report an incomplete batch.
        writer.lock_shared().handshake = false;
        let mut byte = [0];
        let mut nonempty = ReadBuf::new(&mut byte);
        assert!(matches!(
            Pin::new(&mut reader).poll_read(&mut cx, &mut nonempty),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(nonempty.filled(), &[42]);
        let mut nonempty = ReadBuf::new(&mut byte);
        assert!(matches!(
            Pin::new(&mut reader).poll_read(&mut cx, &mut nonempty),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
        assert!(matches!(
            Pin::new(&mut reader).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
    }

    #[test]
    fn zero_byte_write_does_not_wake_waiting_reader() {
        let (mut writer, mut reader) = pair();
        let counter = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let mut byte = [0];
        let mut buf = ReadBuf::new(&mut byte);
        assert!(
            Pin::new(&mut reader)
                .poll_read(&mut cx, &mut buf)
                .is_pending()
        );
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, &[]),
            Poll::Ready(Ok(0))
        ));
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);

        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, &[42]),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
        assert!(matches!(
            Pin::new(&mut reader).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), &[42]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplex_memory_transport_is_send_and_wakes_cross_thread_reader() -> Result<(), BoxError>
    {
        let (mut writer, mut reader) = pair();
        let body: Vec<u8> = (0u8..=250).cycle().take(2048).collect();
        let expected = body.clone();
        let sender = tokio::spawn(async move {
            for _ in 0..128 {
                writer.write_all(&body).await?;
            }
            Ok::<(), io::Error>(())
        });
        let receiver = tokio::spawn(async move {
            let mut output = vec![0; expected.len()];
            for _ in 0..128 {
                reader.read_exact(&mut output).await?;
                assert_eq!(output, expected);
            }
            Ok::<(), io::Error>(())
        });
        sender.await??;
        receiver.await??;
        Ok(())
    }
}
