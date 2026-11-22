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

pub trait ForeignTypeRefExt: ForeignTypeRef {
    unsafe fn from_const_ptr<'a>(ptr: *const Self::CType) -> &'a Self {
        unsafe { Self::from_ptr(ptr.cast_mut()) }
    }

    unsafe fn from_const_ptr_opt<'a>(ptr: *const Self::CType) -> Option<&'a Self> {
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { Self::from_const_ptr(ptr.cast_mut()) })
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
