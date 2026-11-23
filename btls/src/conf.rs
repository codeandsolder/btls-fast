//! Interface for processing OpenSSL configuration files.
use crate::ffi;
use foreign_types::ForeignType;
use libc::c_void;

use crate::cvt_p;
use crate::error::ErrorStack;

#[derive(Clone, Copy)]
pub struct ConfMethod(*mut c_void);

impl ConfMethod {
    /// Construct from raw pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the pointer is valid.
    pub const unsafe fn from_ptr(ptr: *mut c_void) -> Self {
        Self(ptr)
    }

    /// Convert to raw pointer.
    #[must_use = "Use the returned native representation when crossing the native API boundary."]
    pub const fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::CONF;
    fn drop = ffi::NCONF_free;

    pub struct Conf;
}

impl Conf {
    /// Create a configuration parser.
    ///
    /// # Errors
    ///
    /// Returns the native error stack if BoringSSL cannot allocate a parser.
    pub fn new(method: ConfMethod) -> Result<Self, ErrorStack> {
        // SAFETY: the configuration method is a native handle supplied by the caller.
        // `NCONF_new` returns an owned `CONF` or a null pointer, checked by `cvt_p`.
        unsafe { cvt_p(ffi::NCONF_new(method.as_ptr())).map(|p| Self::from_ptr(p)) }
    }
}
