//! Context-aware encoding of native TLS sessions.

use std::{
    fmt,
    ops::Deref,
    ptr::{self, NonNull},
    slice,
};

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;

use super::{SslContextRef, SslSession, SslSessionRef};
use crate::{
    cvt, cvt_p,
    error::ErrorStack,
    ffi,
    util::{NativeBuffer, cleanse},
};

/// An encoded resumable session, containing secret key material.
///
/// This owns the original native allocation without copying it. The bytes
/// are cleansed before release; debugging never exposes the contents.
/// Applications persisting these bytes must protect their confidentiality
/// and integrity, including any copies they make.
pub struct SessionEncoding {
    data: NonNull<u8>,
    len: usize,
}

// SAFETY: the exclusively owned allocation contains only immutable bytes;
// BoringSSL allocations can be read and freed on another thread.
unsafe impl Send for SessionEncoding {}
// SAFETY: shared access can only read the initialized immutable bytes.
unsafe impl Sync for SessionEncoding {}

impl SessionEncoding {
    /// Borrows the encoded secret session data.
    #[must_use = "Protect the returned secret bytes when persisting or importing the session."]
    pub const fn as_bytes(&self) -> &[u8] {
        // SAFETY: the owner was constructed with the exact initialized
        // allocation length, and the allocation lives for this borrow.
        unsafe { slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }
}

impl Deref for SessionEncoding {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for SessionEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionEncoding")
            .field("len", &self.len)
            .field("data", &"[redacted]")
            .finish()
    }
}

impl Drop for SessionEncoding {
    fn drop(&mut self) {
        // SAFETY: the allocation is exclusively owned, and exactly len
        // initialized bytes must be erased even with a custom allocator.
        unsafe {
            ffi::OPENSSL_cleanse(self.data.as_ptr().cast(), self.len);
            ffi::OPENSSL_free(self.data.as_ptr().cast());
        }
    }
}

impl SslSession {
    /// Decodes a complete native session with the destination context's
    /// certificate method and buffer pool.
    ///
    /// Decoding does not authenticate the bytes or establish the identity of
    /// the peer. Import only authenticated data from trusted session storage;
    /// the caller must still establish the resumption authentication policy.
    ///
    /// # Errors
    /// The input is malformed, contains trailing bytes, is not resumable,
    /// or native allocation fails.
    #[corresponds(SSL_SESSION_from_bytes)]
    pub fn from_bytes(context: &SslContextRef, bytes: &[u8]) -> Result<Self, ErrorStack> {
        // SAFETY: the destination context and all input bytes remain live
        // during parsing; native returns a new owned session or null.
        let session = unsafe {
            Self::from_ptr(cvt_p(ffi::SSL_SESSION_from_bytes(
                bytes.as_ptr(),
                bytes.len(),
                context.as_ptr(),
            ))?)
        };
        session.require_resumable()?;
        Ok(session)
    }
}

impl SslSessionRef {
    /// Returns whether this session is complete and has a resumption identity.
    ///
    /// This does not establish that the server will accept it or that its
    /// authentication and lifetime are valid for another connection.
    #[corresponds(SSL_SESSION_is_resumable)]
    #[must_use = "Check this predicate before attempting to cache a session."]
    pub fn is_resumable(&self) -> bool {
        // SAFETY: the native session remains live for the read-only query.
        unsafe { ffi::SSL_SESSION_is_resumable(self.as_ptr()) != 0 }
    }

    fn require_resumable(&self) -> Result<(), ErrorStack> {
        if self.is_resumable() {
            Ok(())
        } else {
            Err(ErrorStack::internal_error_str("session is not resumable"))
        }
    }

    /// Encodes the complete resumable session in its native format.
    ///
    /// # Errors
    /// The session is not resumable or native encoding fails.
    #[corresponds(SSL_SESSION_to_bytes)]
    pub fn to_bytes(&self) -> Result<SessionEncoding, ErrorStack> {
        self.require_resumable()?;
        let mut output = NativeBuffer::new();
        let mut len = 0;
        // SAFETY: the session is live; native encoding transfers a new
        // allocation and its exact initialized length into the output slots.
        unsafe {
            cvt(ffi::SSL_SESSION_to_bytes(
                self.as_ptr(),
                output.output(),
                &raw mut len,
            ))?;
        }
        if len == 0 || len > isize::MAX.unsigned_abs() {
            return Err(ErrorStack::internal_error_str(
                "invalid native session encoding length",
            ));
        }
        let data = NonNull::new(output.into_ptr())
            .ok_or_else(|| ErrorStack::internal_error_str("missing native session encoding"))?;
        Ok(SessionEncoding { data, len })
    }

    /// Returns the length of the native session secret.
    ///
    /// This is the master secret for TLS 1.2 and earlier, or the native
    /// resumption secret for TLS 1.3.
    #[corresponds(SSL_SESSION_get_master_key)]
    #[must_use = "Use the exact secret length to size the output buffer."]
    pub fn secret_len(&self) -> usize {
        // SAFETY: a null output and zero capacity query the secret length.
        unsafe { ffi::SSL_SESSION_get_master_key(self.as_ptr(), ptr::null_mut(), 0) }
    }

    /// Copies the complete session secret into the output prefix.
    ///
    /// The caller must protect and erase the returned secret. Bytes beyond
    /// the secret length are untouched.
    ///
    /// # Errors
    /// The session has no secret, the output is too short, or native copying
    /// reports an inconsistent length.
    #[corresponds(SSL_SESSION_get_master_key)]
    pub fn copy_secret<'a>(&self, output: &'a mut [u8]) -> Result<&'a mut [u8], ErrorStack> {
        let len = self.secret_len();
        if len == 0 {
            return Err(ErrorStack::internal_error_str(
                "session secret is unavailable",
            ));
        }
        let secret = output
            .get_mut(..len)
            .ok_or_else(|| ErrorStack::internal_error_str("session secret buffer is too short"))?;
        // SAFETY: the exact output prefix is writable and the live session
        // is immutably borrowed throughout the native call.
        let written =
            unsafe { ffi::SSL_SESSION_get_master_key(self.as_ptr(), secret.as_mut_ptr(), len) };
        if written != len {
            cleanse(secret);
            return Err(ErrorStack::internal_error_str(
                "inconsistent native session secret length",
            ));
        }
        Ok(secret)
    }
}
