use crate::ffi::{
    self, BIO_clear_retry_flags, BIO_new, BIO_set_retry_read, BIO_set_retry_write, BIO,
    BIO_CTRL_DGRAM_QUERY_MTU, BIO_CTRL_FLUSH,
};
use libc::{c_char, c_int, c_long, c_void, strlen};
use std::any::Any;
use std::io;
use std::io::prelude::*;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use crate::error::ErrorStack;
use crate::{cvt, cvt_p};

pub struct StreamState<S> {
    pub stream: S,
    pub error: Option<io::Error>,
    pub panic: Option<Box<dyn Any + Send>>,
    pub dtls_mtu_size: c_long,
}

/// Owns the immutable native BIO method until all associated BIOs have been freed.
pub struct BioMethod(*mut ffi::BIO_METHOD);

// SAFETY: After construction the native method is immutable, and its owner frees
// it only after the last associated BIO is destroyed.
unsafe impl Sync for BioMethod {}
// SAFETY: The native method is not thread-affine.
unsafe impl Send for BioMethod {}

impl BioMethod {
    fn new<S: Read + Write>() -> Result<Self, ErrorStack> {
        // SAFETY: The returned method is uniquely owned, and each callback matches
        // the StreamState<S> attached to BIOs constructed with this method.
        unsafe {
            let ptr = cvt_p(ffi::BIO_meth_new(ffi::BIO_TYPE_NONE, c"rust".as_ptr()))?;
            let method = Self(ptr);
            cvt(ffi::BIO_meth_set_write(ptr, Some(bwrite::<S>)))?;
            cvt(ffi::BIO_meth_set_read(ptr, Some(bread::<S>)))?;
            cvt(ffi::BIO_meth_set_puts(ptr, Some(bputs::<S>)))?;
            cvt(ffi::BIO_meth_set_ctrl(ptr, Some(ctrl::<S>)))?;
            cvt(ffi::BIO_meth_set_create(ptr, Some(create)))?;
            cvt(ffi::BIO_meth_set_destroy(ptr, Some(destroy::<S>)))?;
            Ok(method)
        }
    }
}

impl Drop for BioMethod {
    fn drop(&mut self) {
        // SAFETY: This value owns the method; the associated BIOs have already
        // been freed (or construction failed before any BIO was created).
        unsafe { ffi::BIO_meth_free(self.0) };
    }
}

pub fn new<S: Read + Write>(stream: S) -> Result<(*mut BIO, BioMethod), ErrorStack> {
    let method = BioMethod::new::<S>()?;

    let state = Box::new(StreamState {
        stream,
        error: None,
        panic: None,
        dtls_mtu_size: 0,
    });

    // SAFETY: A new BIO receives exactly one owned StreamState<S>; method outlives it.
    unsafe {
        let bio = cvt_p(BIO_new(method.0))?;
        BIO_set_data(bio, Box::into_raw(state).cast());
        BIO_set_init(bio, 1);

        Ok((bio, method))
    }
}

pub unsafe fn take_error<S>(bio: *mut BIO) -> Option<io::Error> {
    // SAFETY: The caller uniquely borrows the initialized owning SslStream<S>.
    unsafe {
        let state = state::<S>(bio);
        state.error.take()
    }
}

pub unsafe fn take_panic<S>(bio: *mut BIO) -> Option<Box<dyn Any + Send>> {
    // SAFETY: The caller uniquely borrows the initialized owning SslStream<S>.
    unsafe {
        let state = state::<S>(bio);
        state.panic.take()
    }
}

pub unsafe fn get_ref<'a, S: 'a>(bio: *mut BIO) -> &'a S {
    // SAFETY: The caller guarantees the data is a live StreamState<S> and
    // its stream is shared-borrowable for 'a. Never manufacture an exclusive
    // borrow here: multiple safe SslStream::get_ref calls can coexist.
    unsafe { &(*state_ptr::<S>(bio)).stream }
}

pub unsafe fn get_mut<'a, S: 'a>(bio: *mut BIO) -> &'a mut S {
    // SAFETY: The caller guarantees unique access to the initialized state for 'a.
    unsafe { &mut state::<S>(bio).stream }
}

pub unsafe fn take_stream<S>(bio: *mut BIO) -> S {
    assert!(!bio.is_null());
    // SAFETY: The caller consumes the stream, so its boxed state can be taken once.
    unsafe {
        let data = BIO_get_data(bio);

        assert!(!data.is_null());

        let state = Box::<StreamState<S>>::from_raw(data.cast());

        BIO_set_data(bio, ptr::null_mut());

        state.stream
    }
}

pub unsafe fn set_dtls_mtu_size<S>(bio: *mut BIO, mtu_size: usize) {
    // SAFETY: The caller exclusively owns the initialized state for this operation.
    unsafe {
        if mtu_size as u64 > c_long::MAX as u64 {
            panic!("Given MTU size {mtu_size} can't be represented in a positive `c_long` range")
        }
        state::<S>(bio).dtls_mtu_size = mtu_size as c_long;
    }
}

// Returns a raw pointer without manufacturing a reference at the FFI boundary.
unsafe fn state_ptr<S>(bio: *mut BIO) -> *mut StreamState<S> {
    // SAFETY: The caller supplies a valid BIO constructed by new::<S>.
    unsafe { BIO_get_data(bio).cast() }
}

unsafe fn state<'a, S>(bio: *mut BIO) -> &'a mut StreamState<S> {
    // SAFETY: The caller supplies a live BIO with initialized state of this type
    // and exclusive access for the returned lifetime.
    unsafe { &mut *state_ptr::<S>(bio) }
}

unsafe extern "C" fn bwrite<S: Write>(bio: *mut BIO, buf: *const c_char, len: c_int) -> c_int {
    // SAFETY: BIO_meth_set_write's callback contract provides an initialized BIO
    // and a readable buffer of len bytes for the duration of this call.
    unsafe {
        BIO_clear_retry_flags(bio);

        let Ok(len) = usize::try_from(len) else {
            return -1;
        };

        if len == 0 {
            return 0;
        }
        if buf.is_null() {
            return -1;
        }

        let state = state::<S>(bio);
        let buf = slice::from_raw_parts(buf.cast(), len);

        match catch_unwind(AssertUnwindSafe(|| state.stream.write(buf))) {
            Ok(Ok(count)) => checked_count(state, count, len),
            Ok(Err(err)) => {
                if retriable_error(&err) {
                    BIO_set_retry_write(bio);
                }
                state.error = Some(err);
                -1
            }
            Err(err) => {
                state.panic = Some(err);
                -1
            }
        }
    }
}

unsafe extern "C" fn bread<S: Read>(bio: *mut BIO, buf: *mut c_char, len: c_int) -> c_int {
    // SAFETY: BIO_meth_set_read's contract provides an initialized BIO and an
    // exclusive writable buffer of len bytes. We initialize it before borrowing.
    unsafe {
        BIO_clear_retry_flags(bio);

        let Ok(len) = usize::try_from(len) else {
            return -1;
        };

        if len == 0 {
            return 0;
        }
        if buf.is_null() {
            return -1;
        }

        let state = state::<S>(bio);
        // Native BIO output buffers may be uninitialized. Read::read accepts
        // an initialized byte slice and may inspect its initial contents, so
        // initialize the buffer before creating the Rust reference.
        buf.cast::<u8>().write_bytes(0, len);
        let buf = slice::from_raw_parts_mut(buf.cast(), len);

        match catch_unwind(AssertUnwindSafe(|| state.stream.read(buf))) {
            Ok(Ok(count)) => checked_count(state, count, len),
            Ok(Err(err)) => {
                if retriable_error(&err) {
                    BIO_set_retry_read(bio);
                }
                state.error = Some(err);
                -1
            }
            Err(err) => {
                state.panic = Some(err);
                -1
            }
        }
    }
}

fn checked_count<S>(state: &mut StreamState<S>, count: usize, limit: usize) -> c_int {
    if count <= limit {
        if let Ok(count) = c_int::try_from(count) {
            return count;
        }
    }
    state.error = Some(io::Error::new(
        io::ErrorKind::InvalidData,
        "BIO stream reported more bytes than supplied",
    ));
    -1
}

fn retriable_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::NotConnected
    )
}

unsafe extern "C" fn bputs<S: Write>(bio: *mut BIO, s: *const c_char) -> c_int {
    if s.is_null() {
        return -1;
    }
    // SAFETY: The BIO callback contract supplies a NUL-terminated C string.
    let Ok(len) = c_int::try_from(unsafe { strlen(s) }) else {
        return -1;
    };
    // SAFETY: The same callback contract guarantees a valid initialized BIO and string.
    unsafe { bwrite::<S>(bio, s, len) }
}

unsafe extern "C" fn ctrl<S: Write>(
    bio: *mut BIO,
    cmd: c_int,
    _num: c_long,
    _ptr: *mut c_void,
) -> c_long {
    // SAFETY: The registered control callback receives the BIO's live state
    // for this call; flush and MTU query operate on that same state.
    unsafe {
        let state = state::<S>(bio);

        if cmd == BIO_CTRL_FLUSH {
            BIO_clear_retry_flags(bio);
            match catch_unwind(AssertUnwindSafe(|| state.stream.flush())) {
                Ok(Ok(())) => 1,
                Ok(Err(err)) => {
                    if retriable_error(&err) {
                        BIO_set_retry_write(bio);
                    }
                    state.error = Some(err);
                    0
                }
                Err(err) => {
                    state.panic = Some(err);
                    0
                }
            }
        } else if cmd == BIO_CTRL_DGRAM_QUERY_MTU {
            state.dtls_mtu_size
        } else {
            0
        }
    }
}

unsafe extern "C" fn create(bio: *mut BIO) -> c_int {
    // SAFETY: BIO_new calls this once on the newly allocated BIO.
    unsafe {
        BIO_set_init(bio, 0);
        BIO_set_data(bio, ptr::null_mut());
        BIO_set_flags(bio, 0);
        1
    }
}

unsafe extern "C" fn destroy<S>(bio: *mut BIO) -> c_int {
    if bio.is_null() {
        return 0;
    }

    // SAFETY: The final BIO destructor owns the attached allocation, if any.
    unsafe {
        let data = BIO_get_data(bio);

        if !data.is_null() {
            drop(Box::<StreamState<S>>::from_raw(data.cast()));
            BIO_set_data(bio, ptr::null_mut());
        }

        BIO_set_init(bio, 0);
        1
    }
}

use crate::ffi::{BIO_get_data, BIO_set_data, BIO_set_flags, BIO_set_init};

#[cfg(test)]
mod tests {
    use super::*;

    struct InvalidCount;

    impl Read for InvalidCount {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(buf.iter().all(|&byte| byte == 0));
            Ok(buf.len() + 1)
        }
    }

    impl Write for InvalidCount {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len() + 1)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn native_callbacks_reject_invalid_rust_counts() -> Result<(), ErrorStack> {
        let (bio, method) = new(InvalidCount)?;
        let mut buf = [0x55_u8; 8];
        // SAFETY: new() created the matching BIO, the buffers are valid for
        // the supplied lengths, and all calls are exclusively sequenced.
        unsafe {
            assert_eq!(ffi::BIO_read(bio, buf.as_mut_ptr().cast(), 8), -1);
            assert_eq!(
                take_error::<InvalidCount>(bio).map(|error| error.kind()),
                Some(io::ErrorKind::InvalidData)
            );
            assert_eq!(buf, [0; 8]);
            assert_eq!(ffi::BIO_write(bio, buf.as_ptr().cast(), 8), -1);
            assert_eq!(
                take_error::<InvalidCount>(bio).map(|error| error.kind()),
                Some(io::ErrorKind::InvalidData)
            );
            ffi::BIO_free(bio);
        }
        drop(method);
        Ok(())
    }

    #[test]
    fn shared_bio_stream_borrows_can_coexist() -> Result<(), ErrorStack> {
        let (bio, method) = new(io::Cursor::new(vec![1_u8, 2, 3]))?;
        // SAFETY: This is the matching initialized BIO; both references are
        // shared and released before the BIO is freed.
        unsafe {
            let first = get_ref::<io::Cursor<Vec<u8>>>(bio);
            let second = get_ref::<io::Cursor<Vec<u8>>>(bio);
            assert_eq!(first.get_ref(), &[1, 2, 3]);
            assert!(ptr::eq(first, second));
            ffi::BIO_free(bio);
        }
        drop(method);
        Ok(())
    }
}
