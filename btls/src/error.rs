//! Errors returned by OpenSSL library.
//!
//! OpenSSL errors are stored in an `ErrorStack`.  Most methods in the crate
//! returns a `Result<T, ErrorStack>` type.
//!
//! # Examples
//!
//! ```
//! use btls::error::ErrorStack;
//! use btls::bn::BigNum;
//!
//! let an_error = BigNum::from_dec_str("Cannot parse letters");
//! match an_error {
//!     Ok(_)  => (),
//!     Err(e) => println!("Parsing Error: {:?}", e),
//! }
//! ```
use libc::{c_char, c_int, c_uint};
use openssl_macros::corresponds;
use std::borrow::Cow;
use std::error;
use std::ffi::CStr;
use std::ffi::CString;
use std::fmt;
use std::io;
use std::ptr;
use std::str;

use crate::ffi;

pub use crate::ffi::ErrLib;

/// Collection of [`Error`]s from OpenSSL.
///
/// [`Error`]: struct.Error.html
#[derive(Debug, Clone)]
pub struct ErrorStack(Vec<Error>);

impl ErrorStack {
    /// Pops the contents of the OpenSSL error stack, and returns it.
    ///
    /// This should be used only immediately after calling Boring FFI functions,
    /// otherwise the stack may be empty or a leftover from unrelated calls.
    #[corresponds(ERR_get_error_line_data)]
    #[must_use = "Use ErrorStack::clear() to drop the error stack"]
    pub fn get() -> Self {
        let mut vec = vec![];
        while let Some(err) = Error::get() {
            vec.push(err);
        }
        Self(vec)
    }

    /// Pushes the errors back onto the OpenSSL error stack.
    #[corresponds(ERR_put_error)]
    pub fn put(&self) {
        for error in self.errors() {
            error.put();
        }
    }

    /// Used to report errors from the Rust crate
    #[cold]
    pub(crate) fn internal_error(err: impl error::Error) -> Self {
        Self(vec![Error::new_internal(Data::String(err.to_string()))])
    }

    /// Used to report errors from the Rust crate
    #[cold]
    pub(crate) fn internal_error_str(message: &'static str) -> Self {
        Self(vec![Error::new_internal(Data::Static(message))])
    }

    /// Empties the current thread's error queue.
    #[corresponds(ERR_clear_error)]
    pub(crate) fn clear() {
        // SAFETY: clears only the calling thread's BoringSSL error queue.
        unsafe {
            ffi::ERR_clear_error();
        }
    }
}

impl ErrorStack {
    /// Returns the errors in the stack.
    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    pub fn errors(&self) -> &[Error] {
        &self.0
    }
}

impl fmt::Display for ErrorStack {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        if self.0.is_empty() {
            return fmt.write_str("unknown BoringSSL error");
        }

        let mut first = true;
        for err in &self.0 {
            if !first {
                fmt.write_str(" ")?;
            }
            first = false;
            write!(
                fmt,
                "[{}]",
                err.reason()
                    .or_else(|| err.library())
                    .unwrap_or("unknown reason")
            )?;
        }
        Ok(())
    }
}

impl error::Error for ErrorStack {}

impl From<ErrorStack> for io::Error {
    fn from(e: ErrorStack) -> Self {
        Self::other(e)
    }
}

impl From<ErrorStack> for fmt::Error {
    fn from(_: ErrorStack) -> Self {
        Self
    }
}

/// A detailed error reported as part of an [`ErrorStack`].
#[derive(Clone)]
pub struct Error {
    code: c_uint,
    file: *const c_char,
    line: c_uint,
    data: Data,
}

#[derive(Clone)]
enum Data {
    None,
    CString(CString),
    String(String),
    Static(&'static str),
}

// SAFETY: `file` points to a static native source filename, and the other
// fields contain owned values, integer codes, or static strings.
unsafe impl Sync for Error {}
// SAFETY: moving the descriptor does not affect native error-queue ownership.
unsafe impl Send for Error {}

static BORING_INTERNAL: &CStr = c"btls-rust";

impl Error {
    /// Pops the first error off the OpenSSL error stack.
    #[must_use = "Use ErrorStack::clear() to drop the error stack"]
    #[corresponds(ERR_get_error_line_data)]
    pub fn get() -> Option<Self> {
        // SAFETY: the output pointers are writable local slots; BoringSSL
        // provides stable source filenames and copies of dynamic error data
        // are taken before the thread-local error slot can be overwritten.
        unsafe {
            ffi::init();

            let mut file = ptr::null();
            let mut line = 0;
            let mut data = ptr::null();
            let mut flags = 0;
            match ffi::ERR_get_error_line_data(
                &raw mut file,
                &raw mut line,
                &raw mut data,
                &raw mut flags,
            ) {
                0 => None,
                code => {
                    // The memory referenced by data is only valid until that slot is overwritten
                    // in the error stack, so we'll need to copy it off if it's dynamic
                    let data = if flags & ffi::ERR_FLAG_STRING != 0 {
                        Data::CString(CStr::from_ptr(data.cast()).to_owned())
                    } else {
                        Data::None
                    };
                    Some(Self {
                        code,
                        file,
                        line: c_uint::try_from(line).unwrap_or_default(),
                        data,
                    })
                }
            }
        }
    }

    /// Pushes the error back onto the OpenSSL error stack.
    #[corresponds(ERR_put_error)]
    pub fn put(&self) {
        // SAFETY: BoringSSL accepts these decoded error fields; the borrowed
        // C-string, when present, is valid for the duration of the call.
        unsafe {
            ffi::ERR_put_error(
                ffi::ERR_GET_LIB(self.code),
                0,
                ffi::ERR_GET_REASON(self.code),
                self.file,
                self.line,
            );
            if let Some(cstr) = self.data_cstr() {
                ffi::ERR_add_error_data(1, cstr.as_ptr().cast_mut());
            }
        }
    }

    /// Get `{lib}_R_{reason}` reason code for the given library, or `None` if the error is from a different library.
    ///
    /// Libraries are identified by `ERR_LIB_*` constants (for example `ffi::ERR_LIB_SSL`).
    #[inline]
    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    #[track_caller]
    pub fn library_reason(&self, library_code: ErrLib) -> Option<c_int> {
        debug_assert!(library_code.0 < ffi::ERR_NUM_LIBS.0);
        let native_code = c_int::try_from(library_code.0).ok()?;
        (self.library_code() == native_code).then_some(self.reason_code())
    }

    /// Returns the name of the library reporting the error, if available.
    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    pub fn library(&self) -> Option<&'static str> {
        if self.is_internal() {
            return None;
        }
        // SAFETY: the native lookup returns a null or static NUL-terminated
        // error-string pointer, which is checked before creating a `CStr`.
        unsafe {
            let cstr = ffi::ERR_lib_error_string(self.code);
            if cstr.is_null() {
                return None;
            }
            CStr::from_ptr(cstr.cast())
                .to_str()
                .ok()
                .filter(|&msg| msg != "unknown library")
        }
    }

    /// Returns the raw OpenSSL error constant for the library reporting the error (`ERR_LIB_{name}`).
    ///
    /// Error [reason codes](Error::library_reason) are not globally unique, but scoped to each library.
    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    pub const fn library_code(&self) -> c_int {
        ffi::ERR_GET_LIB(self.code)
    }

    /// Returns the reason for the error.
    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    pub fn reason(&self) -> Option<&str> {
        if self.is_internal() {
            return self.data();
        }
        // SAFETY: native error-reason strings are static and NUL-terminated;
        // a null result is checked before building the borrowed `CStr`.
        unsafe {
            let cstr = ffi::ERR_reason_error_string(self.code);
            if cstr.is_null() {
                return None;
            }
            CStr::from_ptr(cstr.cast()).to_str().ok()
        }
    }

    /// Returns [library-specific](Error::library_code) reason code corresponding to some of the `{lib}_R_{reason}` constants.
    ///
    /// Reason codes are ambiguous, and different libraries reuse the same numeric values for different errors.
    /// Use [`Error::library_reason`] to compare error codes.
    ///
    /// For `ERR_LIB_SYS` the reason code is `errno`. `ERR_LIB_USER` can use any values.
    /// Other libraries may use [`ERR_R_*`](ffi::ERR_R_FATAL) or their own codes.
    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    pub const fn reason_code(&self) -> c_int {
        ffi::ERR_GET_REASON(self.code)
    }

    /// Returns the name of the source file which encountered the error.
    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    pub fn file(&self) -> &'static str {
        // SAFETY: `file` is a static native source filename supplied by the
        // error queue, or null, which we check before reading the string.
        unsafe {
            if self.file.is_null() {
                return "";
            }
            CStr::from_ptr(self.file.cast())
                .to_str()
                .unwrap_or_default()
        }
    }

    /// Returns the line in the source file which encountered the error.
    ///
    /// 0 if unknown
    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    pub const fn line(&self) -> u32 {
        self.line
    }

    /// Returns additional data describing the error.
    #[must_use = "Use the returned supplementary native error information when reporting the failure."]
    pub fn data(&self) -> Option<&str> {
        match &self.data {
            Data::None => None,
            Data::CString(cstring) => cstring.to_str().ok(),
            Data::String(s) => Some(s),
            Data::Static(s) => Some(s),
        }
    }

    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    fn data_cstr(&self) -> Option<Cow<'_, CStr>> {
        let s = match &self.data {
            Data::None => return None,
            Data::CString(cstr) => return Some(Cow::Borrowed(cstr)),
            Data::String(s) => s.as_str(),
            Data::Static(s) => s,
        };
        CString::new(s).ok().map(Cow::Owned)
    }

    fn new_internal(msg: Data) -> Self {
        Self {
            code: ffi::ERR_PACK(ffi::ERR_LIB_NONE.0, 0),
            file: BORING_INTERNAL.as_ptr(),
            line: 0,
            data: msg,
        }
    }

    fn is_internal(&self) -> bool {
        ptr::eq(self.file, BORING_INTERNAL.as_ptr())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = fmt.debug_struct("Error");
        builder.field("code", &self.code);
        if !self.is_internal() {
            if let Some(library) = self.library() {
                builder.field("library", &library);
            }
            builder.field("library_code", &self.library_code());
            if let Some(reason) = self.reason() {
                builder.field("reason", &reason);
            }
            builder.field("reason_code", &self.reason_code());
            builder.field("file", &self.file());
            builder.field("line", &self.line());
        }
        if let Some(data) = self.data() {
            builder.field("data", &data);
        }
        builder.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "{}\n\nCode: {:08X}\nLoc: {}:{}",
            self.reason().unwrap_or("unknown TLS error"),
            &self.code,
            self.file(),
            self.line()
        )
    }
}

impl error::Error for Error {}

#[test]
fn internal_err() {
    let e = ErrorStack::internal_error(io::Error::other("hello, btls"));
    assert_eq!(1, e.errors().len());
    assert!(e.to_string().contains("hello, btls"), "{e} {e:?}");

    e.put();
    let e = ErrorStack::get();
    assert!(e.to_string().contains("hello, btls"), "{e} {e:?}");
}
