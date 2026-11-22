use std::marker::PhantomData;
use std::ptr;
use std::slice;

use crate::error::ErrorStack;
use crate::ffi;
use crate::ffi::BIO_new_mem_buf;
use crate::try_int;
use crate::{cvt, cvt_p};

pub struct MemBioSlice<'a>(*mut ffi::BIO, PhantomData<&'a [u8]>);

impl Drop for MemBioSlice<'_> {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the BIO and releases it exactly once.
        unsafe {
            ffi::BIO_free_all(self.0);
        }
    }
}

impl<'a> MemBioSlice<'a> {
    pub fn new(buf: &'a [u8]) -> Result<Self, ErrorStack> {
        ffi::init();

        // SAFETY: the input slice remains alive through the wrapper's lifetime;
        // the native BIO borrows those bytes without modifying them.
        let bio = unsafe { cvt_p(BIO_new_mem_buf(buf.as_ptr().cast(), try_int(buf.len())?))? };

        Ok(MemBioSlice(bio, PhantomData))
    }

    pub const fn as_ptr(&self) -> *mut ffi::BIO {
        self.0
    }
}

pub struct MemBio(*mut ffi::BIO);

impl Drop for MemBio {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the BIO and releases it exactly once.
        unsafe {
            ffi::BIO_free_all(self.0);
        }
    }
}

impl MemBio {
    pub fn new() -> Result<Self, ErrorStack> {
        ffi::init();

        // SAFETY: the native memory-BIO method is static and BIO_new returns
        // an owned allocation or null.
        let bio = unsafe { cvt_p(ffi::BIO_new(ffi::BIO_s_mem()))? };
        Ok(Self(bio))
    }

    pub const fn as_ptr(&self) -> *mut ffi::BIO {
        self.0
    }

    pub fn get_buf(&self) -> Result<&[u8], ErrorStack> {
        let mut ptr: *const u8 = ptr::null();
        let mut len = 0;
        // SAFETY: this wrapper owns a live memory BIO. The result and length
        // slots are writable and the native buffer stays alive while borrowed.
        unsafe { cvt(ffi::BIO_mem_contents(self.0, &raw mut ptr, &raw mut len))? };
        if len == 0 {
            return Ok(&[]);
        }
        if ptr.is_null() || len > isize::MAX.unsigned_abs() {
            return Err(ErrorStack::internal_error_str(
                "invalid native BIO contents",
            ));
        }
        // SAFETY: BIO_mem_contents describes initialized, readable bytes
        // in the owned BIO; the caller may not mutate it during this borrow.
        Ok(unsafe { slice::from_raw_parts(ptr, len) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_bio_contents_are_length_delimited() {
        let bio = MemBio::new().unwrap();
        assert!(bio.get_buf().unwrap().is_empty());
        let input = b"first\0second";
        // SAFETY: this BIO is owned by the test and input describes its
        // initialized readable bytes for the duration of the native write.
        unsafe {
            cvt(ffi::BIO_write_all(
                bio.as_ptr(),
                input.as_ptr().cast(),
                input.len(),
            ))
            .unwrap()
        };
        assert_eq!(bio.get_buf().unwrap(), input);
    }
}
