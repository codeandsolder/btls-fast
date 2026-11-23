use crate::ffi;
use crate::stack::Stackable;
use foreign_types::ForeignTypeRef;
use libc::c_ulong;
use std::ffi::CStr;
use std::str;

use crate::error::ErrorStack;

/// fake free method, since `SRTP_PROTECTION_PROFILE` is static
const unsafe fn free(_profile: *mut ffi::SRTP_PROTECTION_PROFILE) {}

foreign_type_and_impl_send_sync! {
    type CType = ffi::SRTP_PROTECTION_PROFILE;
    fn drop = free;

    pub struct SrtpProtectionProfile;
}

// SAFETY: the native stack type matches static native SRTP profile descriptors; ownership release is a no-op.
unsafe impl Stackable for SrtpProtectionProfile {
    type StackType = ffi::stack_st_SRTP_PROTECTION_PROFILE;
}

impl SrtpProtectionProfileRef {
    #[must_use = "Use the returned algorithm or parameter identity when selecting or reporting cryptographic settings."]
    pub fn id(&self) -> SrtpProfileId {
        // SAFETY: a foreign-type reference points to a live native profile.
        SrtpProfileId::from_raw(unsafe { (*self.as_ptr()).id })
    }

    #[must_use = "Use the returned name for reporting or selecting the native identifier."]
    ///
    /// # Errors
    ///
    /// The native profile has no name or its name is not valid UTF-8.
    pub fn name(&self) -> Result<&'static str, ErrorStack> {
        // SAFETY: the live native profile exposes a static name pointer.
        let name = unsafe { (*self.as_ptr()).name };
        if name.is_null() {
            return Err(ErrorStack::internal_error_str("missing SRTP profile name"));
        }
        // SAFETY: a non-null native profile name is a static NUL-terminated string.
        unsafe { CStr::from_ptr(name.cast()) }
            .to_str()
            .map_err(ErrorStack::internal_error)
    }
}

/// An identifier of an SRTP protection profile.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SrtpProfileId(c_ulong);

impl SrtpProfileId {
    pub const SRTP_AES128_CM_SHA1_80: Self = Self(ffi::SRTP_AES128_CM_SHA1_80 as _);
    pub const SRTP_AES128_CM_SHA1_32: Self = Self(ffi::SRTP_AES128_CM_SHA1_32 as _);
    pub const SRTP_AES128_F8_SHA1_80: Self = Self(ffi::SRTP_AES128_F8_SHA1_80 as _);
    pub const SRTP_AES128_F8_SHA1_32: Self = Self(ffi::SRTP_AES128_F8_SHA1_32 as _);
    pub const SRTP_NULL_SHA1_80: Self = Self(ffi::SRTP_NULL_SHA1_80 as _);
    pub const SRTP_NULL_SHA1_32: Self = Self(ffi::SRTP_NULL_SHA1_32 as _);
    pub const SRTP_AEAD_AES_128_GCM: Self = Self(ffi::SRTP_AEAD_AES_128_GCM as _);
    pub const SRTP_AEAD_AES_256_GCM: Self = Self(ffi::SRTP_AEAD_AES_256_GCM as _);

    /// Creates a `SrtpProfileId` from an integer representation.
    #[must_use = "Use the wrapper returned for the supplied native representation."]
    pub const fn from_raw(value: c_ulong) -> Self {
        Self(value)
    }

    /// Returns the integer representation of `SrtpProfileId`.
    #[must_use = "The returned native representation is needed by the caller."]
    pub const fn as_raw(self) -> c_ulong {
        self.0
    }
}
