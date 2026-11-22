use crate::error::ErrorStack;
use foreign_types::ForeignTypeRef;
use libc::{c_char, c_int, c_void};
use std::any::Any;
use std::panic::{self, AssertUnwindSafe};
use std::slice;

/// Wraps a user-supplied callback and a slot for panics thrown inside the callback (while FFI
/// frames are on the stack).
///
/// When dropped, checks if the callback has panicked, and resumes unwinding if so.
pub struct CallbackState<F> {
    /// The user callback. Taken out of the `Option` when called.
    cb: Option<F>,
    /// If the callback panics, we place the panic object here, to be re-thrown once OpenSSL
    /// returns.
    panic: Option<Box<dyn Any + Send + 'static>>,
}

impl<F> CallbackState<F> {
    pub fn new(callback: F) -> Self {
        Self {
            cb: Some(callback),
            panic: None,
        }
    }
}

impl<F> Drop for CallbackState<F> {
    fn drop(&mut self) {
        if let Some(panic) = self.panic.take() {
            panic::resume_unwind(panic);
        }
    }
}

/// Password callback function, passed to private key loading functions.
///
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
    let Ok(size) = usize::try_from(size) else {
        return 0;
    };
    if cb_state.is_null() || buf.is_null() || size == 0 {
        return 0;
    }

    // SAFETY: BoringSSL supplies the exclusive callback state installed by the
    // synchronous key-loading call. The state outlives this invocation.
    let callback = unsafe { &mut *cb_state.cast::<CallbackState<F>>() };
    let Some(cb) = callback.cb.take() else {
        // This API accepts a single-use callback; a second invocation fails
        // without overwriting a previously captured panic.
        return 0;
    };
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: BoringSSL provides size writable bytes, potentially
        // uninitialized. Initialize them before making a safe byte slice.
        let pass_slice = unsafe {
            buf.cast::<u8>().write_bytes(0, size);
            slice::from_raw_parts_mut(buf.cast::<u8>(), size)
        };
        match cb(pass_slice) {
            Ok(len) if len <= size => c_int::try_from(len).unwrap_or(0),
            Ok(_) => 0,
            Err(err) => {
                err.put();
                0
            }
        }
    }));

    match result {
        Ok(len) => len,
        Err(err) => {
            callback.panic = Some(err);
            0
        }
    }
}

/// Owns an allocation transferred by a native OpenSSL output-pointer API.
pub(crate) struct NativeBuffer(*mut u8);

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
    fn callback_initializes_buffer_and_is_single_use() {
        let mut state = CallbackState::new(|out: &mut [u8]| {
            assert_eq!(out, &[0; 4]);
            out[..2].copy_from_slice(b"pw");
            Ok(2)
        });
        let mut buf = [255; 4];
        assert_eq!(invoke(&mut state, &mut buf), 2);
        assert_eq!(buf, *b"pw\0\0");
        assert_eq!(invoke(&mut state, &mut buf), 0);
    }

    #[test]
    fn callback_rejects_impossible_length() {
        let mut state = CallbackState::new(|out: &mut [u8]| Ok(out.len() + 1));
        assert_eq!(invoke(&mut state, &mut [0; 4]), 0);
    }
}
