use crate::error::ErrorStack;
use foreign_types::ForeignTypeRef;
use libc::{c_char, c_int, c_void};
use std::any::Any;
use std::panic::{self, AssertUnwindSafe};
use std::slice;

// Native callbacks cannot unwind into C. Arbitrary panic payloads may have
// panicking destructors, so they must not be dropped on the native stack.
pub fn catch_native<T>(callback: impl FnOnce() -> T) -> Option<T> {
    match panic::catch_unwind(AssertUnwindSafe(callback)) {
        Ok(value) => Some(value),
        Err(payload) => {
            std::mem::forget(payload);
            None
        }
    }
}

/// Captures a single-use password callback's failure until native frames are gone.
pub struct CallbackState<F> {
    cb: Option<F>,
    failure: Option<CallbackFailure>,
}

enum CallbackFailure {
    Error(ErrorStack),
    Panic(Box<dyn Any + Send + 'static>),
}

impl<F> CallbackState<F> {
    pub const fn new(callback: F) -> Self {
        Self {
            cb: Some(callback),
            failure: None,
        }
    }

    /// The caller must pass the owned result of the completed native operation.
    /// A callback failure takes precedence over that result.
    pub fn finish<T>(self, result: Result<T, ErrorStack>) -> Result<T, ErrorStack> {
        match self.failure {
            None => result,
            Some(CallbackFailure::Error(error)) => Err(error),
            Some(CallbackFailure::Panic(payload)) => panic::resume_unwind(payload),
        }
    }
}

/// Copies a length-delimited passphrase into a native callback buffer.
pub fn copy_passphrase(password: &[u8], out: &mut [u8]) -> Result<usize, ErrorStack> {
    let dst = out.get_mut(..password.len()).ok_or_else(|| {
        ErrorStack::internal_error_str("passphrase exceeds native callback capacity")
    })?;
    dst.copy_from_slice(password);
    Ok(password.len())
}

/// Clears exclusively borrowed sensitive storage.
pub(crate) fn cleanse(bytes: &mut [u8]) {
    if !bytes.is_empty() {
        // SAFETY: the slice describes exactly the writable bytes.
        unsafe { crate::ffi::OPENSSL_cleanse(bytes.as_mut_ptr().cast(), bytes.len()) };
    }
}

/// Fixed-length initialized heap storage for sensitive intermediate data.
/// Cleanses the initialized allocation on every exit path. Ownership may be
/// transferred explicitly after a successful operation.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub(crate) fn zeroed(len: usize) -> Result<Self, ErrorStack> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(ErrorStack::internal_error)?;
        bytes.resize(len, 0);
        Ok(Self(bytes))
    }

    pub(crate) fn into_vec(mut self, len: usize) -> Result<Vec<u8>, ErrorStack> {
        let tail = self
            .0
            .get_mut(len..)
            .ok_or_else(|| ErrorStack::internal_error_str("invalid native secret output length"))?;
        cleanse(tail);
        self.0.truncate(len);
        Ok(std::mem::take(&mut self.0))
    }
}

impl std::ops::Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        cleanse(&mut self.0);
    }
}

/// A NUL-terminated password for native interfaces that lack an explicit length.
pub struct SecretCString(SecretBytes);

impl SecretCString {
    pub(crate) fn new(password: &[u8]) -> Result<Self, ErrorStack> {
        if password.contains(&0) {
            return Err(ErrorStack::internal_error_str(
                "password contains an embedded NUL",
            ));
        }
        let len = password
            .len()
            .checked_add(1)
            .ok_or_else(|| ErrorStack::internal_error_str("password length overflow"))?;
        let mut bytes = SecretBytes::zeroed(len)?;
        bytes[..password.len()].copy_from_slice(password);
        Ok(Self(bytes))
    }

    pub(crate) fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr().cast()
    }
}

/// Password callback function, passed to private key loading functions.
/// A nonnegative return is the password length (including zero); -1 is failure.
/// # Safety
///
/// For a positive size, the non-null buffer must point to that many writable
/// bytes. The non-null state must point to an exclusively borrowed live
/// `CallbackState<F>` installed by the key-reading operation.
pub unsafe extern "C" fn invoke_passwd_cb<F>(
    buf: *mut c_char,
    size: c_int,
    _rwflag: c_int,
    cb_state: *mut c_void,
) -> c_int
where
    F: FnOnce(&mut [u8]) -> Result<usize, ErrorStack>,
{
    let Ok(capacity) = usize::try_from(size) else {
        return -1;
    };
    if cb_state.is_null() || buf.is_null() {
        return -1;
    }

    // SAFETY: the synchronous native call passes its live exclusive state.
    let callback = unsafe { &mut *cb_state.cast::<CallbackState<F>>() };
    let Some(cb) = callback.cb.take() else {
        if callback.failure.is_none() {
            callback.failure = Some(CallbackFailure::Error(ErrorStack::internal_error_str(
                "password callback invoked more than once",
            )));
        }
        return -1;
    };

    // SAFETY: native supplies capacity writable bytes, potentially uninitialized.
    // Initialize them before creating a Rust slice.
    let password = unsafe {
        buf.cast::<u8>().write_bytes(0, capacity);
        slice::from_raw_parts_mut(buf.cast::<u8>(), capacity)
    };
    let result = panic::catch_unwind(AssertUnwindSafe(|| cb(password)));
    let failure = match result {
        Ok(Ok(len)) if len <= capacity => {
            if let Ok(native_len) = c_int::try_from(len) {
                cleanse(&mut password[len..]);
                return native_len;
            }
            CallbackFailure::Error(ErrorStack::internal_error_str(
                "password length cannot be represented",
            ))
        }
        Ok(Ok(_)) => CallbackFailure::Error(ErrorStack::internal_error_str(
            "password callback returned a length exceeding its buffer",
        )),
        Ok(Err(error)) => CallbackFailure::Error(error),
        Err(payload) => CallbackFailure::Panic(payload),
    };
    // Native is not required to clear the output on callback failure.
    cleanse(password);
    callback.failure = Some(failure);
    -1
}

/// Returns a borrowed byte slice only when the native pointer/length pair is
/// structurally valid. A zero-length buffer can have a null pointer.
///
/// # Safety
///
/// For every non-null pointer whose positive length fits in `isize`, the
/// caller must guarantee that many readable bytes remain live and immutable
/// for the returned lifetime. Invalid pairs are rejected before dereference.
pub const unsafe fn native_input<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() || len > isize::MAX.unsigned_abs() {
        return None;
    }
    // SAFETY: the caller supplies the readable allocation for this lifetime.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Owns an allocation transferred by a native OpenSSL output-pointer API.
pub struct NativeBuffer(*mut u8);

impl NativeBuffer {
    pub const fn new() -> Self {
        Self(std::ptr::null_mut())
    }

    pub const fn output(&mut self) -> *mut *mut u8 {
        &raw mut self.0
    }

    /// Copy a fully initialized native output.
    ///
    /// # Safety
    /// The native call must have initialized exactly len readable bytes in this allocation.
    pub unsafe fn copy(&self, len: usize) -> Result<Vec<u8>, ErrorStack> {
        if len == 0 {
            return Ok(Vec::new());
        }
        if self.0.is_null() || len > isize::MAX.unsigned_abs() {
            return Err(ErrorStack::internal_error_str(
                "invalid native output buffer",
            ));
        }
        // SAFETY: The caller supplies the initialized size; the native allocation
        // remains owned by self until after copying.
        Ok(unsafe { slice::from_raw_parts(self.0, len) }.to_vec())
    }
}

impl Drop for NativeBuffer {
    fn drop(&mut self) {
        // SAFETY: The pointer is either null or an owned OPENSSL allocation.
        unsafe { crate::ffi::OPENSSL_free(self.0.cast()) };
    }
}

pub trait ForeignTypeRefExt: ForeignTypeRef {
    unsafe fn from_const_ptr<'a>(ptr: *const Self::CType) -> &'a Self {
        // SAFETY: the caller must provide a live, immutable native object
        // for the returned lifetime; the reference does not modify it.
        unsafe { Self::from_ptr(ptr.cast_mut()) }
    }

    unsafe fn from_const_ptr_opt<'a>(ptr: *const Self::CType) -> Option<&'a Self> {
        if ptr.is_null() {
            None
        } else {
            // SAFETY: the caller provides a live immutable object for non-null input.
            Some(unsafe { Self::from_const_ptr(ptr) })
        }
    }
}
impl<FT: ForeignTypeRef> ForeignTypeRefExt for FT {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    fn invoke<F>(state: &mut CallbackState<F>, buf: &mut [u8]) -> c_int
    where
        F: FnOnce(&mut [u8]) -> Result<usize, ErrorStack>,
    {
        // SAFETY: Both pointers refer to disjoint live objects with the
        // required lengths and exclusive access.
        unsafe {
            invoke_passwd_cb::<F>(
                buf.as_mut_ptr().cast(),
                c_int::try_from(buf.len()).unwrap(),
                0,
                ptr::from_mut(state).cast(),
            )
        }
    }

    #[test]
    fn secret_buffer_release_cleans_discarded_tail() {
        let mut secret = SecretBytes::zeroed(8).unwrap();
        secret.copy_from_slice(b"oksecret");
        let mut bytes = secret.into_vec(2).unwrap();
        assert_eq!(bytes, b"ok");
        // SAFETY: this allocation previously contained eight initialized bytes
        // and into_vec only truncated it, without reallocating.
        unsafe { bytes.set_len(8) };
        assert_eq!(bytes, b"ok\0\0\0\0\0\0");
    }

    #[test]
    fn secret_c_string_is_terminated_and_rejects_embedded_nul() {
        let pass = SecretCString::new(b"abc").unwrap();
        // SAFETY: the wrapper owns a valid NUL-terminated byte string.
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(pass.as_ptr()) }.to_bytes(),
            b"abc"
        );
        assert!(SecretCString::new(b"a\0b").is_err());
    }

    #[test]
    fn native_input_guards_empty_and_invalid_native_buffers() {
        let input = [0x12, 0x34];
        // SAFETY: null or impossible-length pairs are rejected before access;
        // the valid pair borrows `input` for this lexical scope.
        unsafe {
            assert_eq!(native_input(ptr::null(), 0), Some(&[][..]));
            assert_eq!(native_input(ptr::null(), 1), None);
            assert_eq!(native_input(input.as_ptr(), input.len()), Some(&input[..]));
            assert_eq!(native_input(input.as_ptr(), usize::MAX), None);
        }
    }

    #[test]
    fn callback_initializes_buffer_and_is_single_use() {
        let mut state = CallbackState::new(|out: &mut [u8]| {
            assert_eq!(out, &[0; 4]);
            out[..2].copy_from_slice(b"pw");
            Ok(2)
        });
        let mut buf = [255; 4];
        assert_eq!(invoke(&mut state, &mut buf), 2);
        assert_eq!(buf, *b"pw\0\0");
        assert_eq!(invoke(&mut state, &mut buf), -1);
        assert!(state.finish(Ok(())).is_err());
    }

    #[test]
    fn callback_rejects_impossible_length() {
        let mut state = CallbackState::new(|out: &mut [u8]| {
            out.fill(0x55);
            Ok(out.len() + 1)
        });
        let mut buf = [0; 4];
        assert_eq!(invoke(&mut state, &mut buf), -1);
        assert_eq!(buf, [0; 4]);
        assert!(state.finish(Ok(())).is_err());
    }

    #[test]
    fn callback_preserves_empty_password_and_cleans_unused_output() {
        let mut state = CallbackState::new(|out: &mut [u8]| {
            out.fill(0x55);
            Ok(0)
        });
        let mut buf = [0; 4];
        assert_eq!(invoke(&mut state, &mut buf), 0);
        assert_eq!(buf, [0; 4]);
        state.finish(Ok(())).unwrap();
    }

    #[test]
    fn callback_preserves_original_error_and_wipes_partial_password() {
        let mut state = CallbackState::new(|out: &mut [u8]| {
            out.fill(0x55);
            Err(ErrorStack::internal_error_str("password unavailable"))
        });
        let mut buf = [0; 4];
        assert_eq!(invoke(&mut state, &mut buf), -1);
        assert_eq!(buf, [0; 4]);
        let error = state.finish(Ok(())).unwrap_err();
        assert_eq!(error.to_string(), "[password unavailable]");
    }
}
