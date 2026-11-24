use std::{io, pin::Pin, ptr, task::Context};

/// An erased pointer to the exclusively borrowed context of a synchronous poll.
struct PollContext(*mut ());

// SAFETY: The pointer is installed only for a synchronous poll on its owning
// thread, and cleared before the stream can leave that poll. It is never
// accessed from a shared reference. No live context can cross threads.
unsafe impl Send for PollContext {}
// SAFETY: Access to the pointer requires exclusive access to the transport.
unsafe impl Sync for PollContext {}

/// The underlying stream and the task context of the poll driving it.
///
/// Each poll installs its context for the transport I/O it drives and clears it afterwards.
pub struct Transport<S> {
    pub(crate) stream: S,
    context: PollContext,
}

impl<S> Transport<S> {
    pub(crate) const fn new(stream: S) -> Self {
        Self {
            stream,
            context: PollContext(ptr::null_mut()),
        }
    }

    /// Installs `cx` as the context of later [`parts`](Self::parts) calls.
    ///
    /// # Safety
    ///
    /// `cx` and the waker it borrows must stay valid on the calling thread, and
    /// `cx` must otherwise remain unused, until [`clear_context`](Self::clear_context)
    /// runs. The transport must not be transferred to another thread while the
    /// context is installed. Unless `S: Unpin`, `stream` must not move from the
    /// first `parts` call until it is dropped.
    #[inline]
    pub(crate) unsafe fn set_context(&mut self, cx: &mut Context<'_>) {
        self.context.0 = ptr::from_mut(cx).cast();
    }

    #[inline]
    pub(crate) const fn clear_context(&mut self) {
        self.context.0 = ptr::null_mut();
    }

    /// Returns the pinned stream and the installed context; fails outside a poll.
    #[inline]
    pub(crate) fn parts(&mut self) -> io::Result<(Pin<&mut S>, &mut Context<'_>)> {
        if self.context.0.is_null() {
            return Err(io::Error::other("TLS transport used outside a poll"));
        }
        // SAFETY: a non-null context comes from `set_context`, whose caller keeps the context
        // valid until `clear_context` and keeps the stream pinned.
        unsafe {
            Ok((
                Pin::new_unchecked(&mut self.stream),
                &mut *self.context.0.cast::<Context<'_>>(),
            ))
        }
    }
}
