use crate::ffi;
use crate::x509::X509VerifyError;
use libc::c_int;
use openssl_macros::corresponds;
use std::error;
use std::error::Error as StdError;
use std::ffi::CStr;
use std::fmt;
use std::io;

use crate::error::ErrorStack;
use crate::ssl::MidHandshakeSslStream;

/// `SSL_ERROR_*` error code returned from SSL functions.
///
/// This is different than [packed error codes](crate::error::Error).
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ErrorCode(c_int);

impl ErrorCode {
    native_constants! {
        /// No error.
        NONE = ffi::SSL_ERROR_NONE;

        /// The SSL session has been closed.
        ZERO_RETURN = ffi::SSL_ERROR_ZERO_RETURN;

        /// An attempt to read data from the underlying socket returned `WouldBlock`.
        ///
        /// Wait for read readiness and retry the operation.
        WANT_READ = ffi::SSL_ERROR_WANT_READ;

        /// An attempt to write data to the underlying socket returned `WouldBlock`.
        ///
        /// Wait for write readiness and retry the operation.
        WANT_WRITE = ffi::SSL_ERROR_WANT_WRITE;

        WANT_X509_LOOKUP = ffi::SSL_ERROR_WANT_X509_LOOKUP;

        PENDING_SESSION = ffi::SSL_ERROR_PENDING_SESSION;

        PENDING_CERTIFICATE = ffi::SSL_ERROR_PENDING_CERTIFICATE;

        WANT_CERTIFICATE_VERIFY = ffi::SSL_ERROR_WANT_CERTIFICATE_VERIFY;

        WANT_PRIVATE_KEY_OPERATION = ffi::SSL_ERROR_WANT_PRIVATE_KEY_OPERATION;

        PENDING_TICKET = ffi::SSL_ERROR_PENDING_TICKET;

        /// The server rejected the early data of this client. Call
        /// [`SslRef::reset_early_data_reject`](super::SslRef::reset_early_data_reject) to continue
        /// the handshake without it.
        EARLY_DATA_REJECTED = ffi::SSL_ERROR_EARLY_DATA_REJECTED;

        /// A non-recoverable IO error occurred.
        SYSCALL = ffi::SSL_ERROR_SYSCALL;

        /// An error occurred in the SSL library.
        SSL = ffi::SSL_ERROR_SSL;
    }

    /// Wrap an `SSL_ERROR_*` error code.
    ///
    /// This is different than [packed error codes](crate::error::Error).
    #[must_use]
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    pub fn from_raw(raw: c_int) -> Self {
        let code = Self(raw);
        debug_assert!(
            raw < 64 || code.description().is_some(),
            "{raw} is not an SSL_ERROR_* code"
        );
        code
    }

    /// An `SSL_ERROR_*` error code.
    ///
    /// This is different than [packed error codes](crate::error::Error).
    #[must_use = "The returned native representation is needed by the caller."]
    pub const fn as_raw(self) -> c_int {
        self.0
    }

    #[corresponds(SSL_error_description)]
    #[must_use]
    pub fn description(self) -> Option<&'static str> {
        unsafe {
            let msg = ffi::SSL_error_description(self.0);
            if msg.is_null() {
                return None;
            }
            CStr::from_ptr(msg).to_str().ok()
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.description().unwrap_or("error"), self.0)
    }
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Debug)]
pub(crate) enum InnerError {
    Io(io::Error),
    Ssl(ErrorStack),
}

/// A general SSL error, based on [`SSL_ERROR_*` error codes](ErrorCode).
#[derive(Debug)]
pub struct Error {
    pub(crate) code: ErrorCode,
    pub(crate) cause: Option<InnerError>,
}

impl Error {
    /// An `SSL_ERROR_*` error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    #[must_use]
    pub const fn io_error(&self) -> Option<&io::Error> {
        match self.cause {
            Some(InnerError::Io(ref e)) => Some(e),
            _ => None,
        }
    }

    pub fn into_io_error(self) -> Result<io::Error, Self> {
        match self.cause {
            Some(InnerError::Io(e)) => Ok(e),
            _ => Err(self),
        }
    }

    /// Stack of [library-specific errors](crate::error::Error), if available.
    #[must_use]
    pub const fn ssl_error(&self) -> Option<&ErrorStack> {
        match self.cause {
            Some(InnerError::Ssl(ref e)) => Some(e),
            _ => None,
        }
    }

    #[must_use]
    pub const fn would_block(&self) -> bool {
        matches!(
            self.code,
            ErrorCode::WANT_READ
                | ErrorCode::WANT_WRITE
                | ErrorCode::WANT_X509_LOOKUP
                | ErrorCode::PENDING_SESSION
                | ErrorCode::PENDING_CERTIFICATE
                | ErrorCode::WANT_PRIVATE_KEY_OPERATION
                | ErrorCode::WANT_CERTIFICATE_VERIFY
                | ErrorCode::PENDING_TICKET
        )
    }
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Self {
        Self {
            code: ErrorCode::SSL,
            cause: Some(InnerError::Ssl(e)),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self.code {
            ErrorCode::ZERO_RETURN => "the SSL session has been shut down",
            ErrorCode::WANT_READ => match self.io_error() {
                Some(_) => "a nonblocking read call would have blocked",
                None => "the operation should be retried",
            },
            ErrorCode::WANT_WRITE => match self.io_error() {
                Some(_) => "a nonblocking write call would have blocked",
                None => "the operation should be retried",
            },
            ErrorCode::SYSCALL => match self.io_error() {
                Some(err) => return err.fmt(fmt),
                None => "unexpected EOF",
            },
            ErrorCode::SSL => match self.ssl_error() {
                Some(err) => return err.fmt(fmt),
                None => "unknown BoringSSL error",
            },
            ErrorCode(code) => return code.fmt(fmt),
        };
        fmt.write_str(msg)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self.cause {
            Some(InnerError::Io(ref e)) => Some(e),
            Some(InnerError::Ssl(ref e)) => Some(e),
            None => None,
        }
    }
}

/// An error or intermediate state after a TLS handshake attempt.
// FIXME overhaul
#[derive(Debug)]
pub enum HandshakeError<S> {
    /// Setup failed.
    SetupFailure(ErrorStack),
    /// The handshake failed.
    Failure(MidHandshakeSslStream<S>),
    /// The handshake encountered a `WouldBlock` error midway through.
    ///
    /// This error will never be returned for blocking streams.
    WouldBlock(MidHandshakeSslStream<S>),
}

impl<S: fmt::Debug> StdError for HandshakeError<S> {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match *self {
            Self::SetupFailure(ref e) => Some(e),
            Self::Failure(ref s) | Self::WouldBlock(ref s) => Some(s.error()),
        }
    }
}

impl<S> fmt::Display for HandshakeError<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::SetupFailure(ref e) => {
                write!(f, "TLS stream setup failed {e}")
            }
            Self::Failure(ref s) => fmt_mid_handshake_error(s, f, "TLS handshake failed"),
            Self::WouldBlock(ref s) => fmt_mid_handshake_error(s, f, "TLS handshake interrupted"),
        }
    }
}

fn fmt_mid_handshake_error(
    s: &MidHandshakeSslStream<impl Sized>,
    f: &mut fmt::Formatter,
    prefix: &str,
) -> fmt::Result {
    if !s.ssl().ssl_context().has_x509_support() {
        write!(f, "{prefix}")?;
        return write!(f, " {}", s.error());
    }

    match s.ssl().verify_result() {
        // INVALID_CALL is returned if no verification took place,
        // such as before a cert is sent.
        Ok(()) | Err(X509VerifyError::INVALID_CALL) => write!(f, "{prefix}")?,
        Err(verify) => write!(f, "{prefix}: cert verification failed - {verify}")?,
    }

    write!(f, " {}", s.error())
}

impl<S> From<ErrorStack> for HandshakeError<S> {
    fn from(e: ErrorStack) -> Self {
        Self::SetupFailure(e)
    }
}
