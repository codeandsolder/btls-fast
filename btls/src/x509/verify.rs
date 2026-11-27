use crate::ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_uint, c_ulong};
use openssl_macros::corresponds;
use std::net::IpAddr;

use crate::error::ErrorStack;
use crate::{cvt, cvt_p};

/// Extended key usage and key usage policy for X.509 path validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum X509Purpose {
    /// TLS client authentication.
    TlsClient = ffi::X509_PURPOSE_SSL_CLIENT,
    /// TLS server authentication.
    TlsServer = ffi::X509_PURPOSE_SSL_SERVER,
    /// S/MIME signing.
    SmimeSign = ffi::X509_PURPOSE_SMIME_SIGN,
    /// S/MIME encryption.
    SmimeEncrypt = ffi::X509_PURPOSE_SMIME_ENCRYPT,
    /// CRL signing.
    CrlSign = ffi::X509_PURPOSE_CRL_SIGN,
    /// RFC 3161 timestamp signing.
    TimestampSign = ffi::X509_PURPOSE_TIMESTAMP_SIGN,
}

bitflags! {
    /// Flags used to check an `X509` certificate.
    #[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
    #[repr(transparent)]
    pub struct X509CheckFlags: c_uint {
        const NO_WILDCARDS = ffi::X509_CHECK_FLAG_NO_WILDCARDS as _;
        const NEVER_CHECK_SUBJECT = ffi::X509_CHECK_FLAG_NEVER_CHECK_SUBJECT as _;
        #[cfg(feature = "underscore-wildcards")]
        const UNDERSCORE_WILDCARDS = ffi::X509_CHECK_FLAG_UNDERSCORE_WILDCARDS as _;
    }
}

bitflags! {
    /// Flags used to check an `X509` certificate.
    #[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
    #[repr(transparent)]
    #[doc(alias = "X509Flags")]
    pub struct X509VerifyFlags: c_ulong {
        const CB_ISSUER_CHECK = ffi::X509_V_FLAG_CB_ISSUER_CHECK as _;
        const USE_CHECK_TIME = ffi::X509_V_FLAG_USE_CHECK_TIME as _;
        const CRL_CHECK = ffi::X509_V_FLAG_CRL_CHECK as _;
        const CRL_CHECK_ALL = ffi::X509_V_FLAG_CRL_CHECK_ALL as _;
        const IGNORE_CRITICAL = ffi::X509_V_FLAG_IGNORE_CRITICAL as _;
        const EXPLICIT_POLICY = ffi::X509_V_FLAG_EXPLICIT_POLICY as _;
        const INHIBIT_ANY = ffi::X509_V_FLAG_INHIBIT_ANY as _;
        const INHIBIT_MAP = ffi::X509_V_FLAG_INHIBIT_MAP as _;
        const CHECK_SS_SIGNATURE = ffi::X509_V_FLAG_CHECK_SS_SIGNATURE as _;
        const PARTIAL_CHAIN = ffi::X509_V_FLAG_PARTIAL_CHAIN as _;
        /// Disables validity-period checks. Use only with an explicit alternative time policy.
        const NO_CHECK_TIME = ffi::X509_V_FLAG_NO_CHECK_TIME as _;
        /// Accepts timezone offsets in certificate validity fields.
        const ALLOW_TIMEZONE_OFFSET = ffi::X509_V_FLAG_ALLOW_TIMEZONE_OFFSET as _;
        /// Enables the native draft-05 Merkle Tree Certificates verifier.
        const USE_MTC_DRAFT_PLANTS_05 = ffi::X509_V_FLAG_USE_MTC_DRAFT_PLANTS_05 as _;
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_VERIFY_PARAM;
    fn drop = ffi::X509_VERIFY_PARAM_free;

    /// Adjust parameters associated with certificate verification.
    pub struct X509VerifyParam;
}

impl X509VerifyParam {
    /// Create an X509VerifyParam
    #[corresponds(X509_VERIFY_PARAM_new)]
    pub fn new() -> Result<Self, ErrorStack> {
        // SAFETY: the native constructor returns a distinct owned verification
        // parameter object, or null if allocation fails.
        unsafe {
            ffi::init();
            let handle = cvt_p(ffi::X509_VERIFY_PARAM_new())?;
            Ok(Self::from_ptr(handle))
        }
    }
}

impl X509VerifyParamRef {
    /// Enables the supplied certificate-verification flags.
    ///
    /// # Errors
    ///
    /// Returns an error if the native parameter object rejects the flags.
    #[corresponds(X509_VERIFY_PARAM_set_flags)]
    pub fn set_flags(&mut self, flags: X509VerifyFlags) -> Result<(), ErrorStack> {
        // SAFETY: the native verification parameters are uniquely borrowed.
        unsafe {
            cvt(ffi::X509_VERIFY_PARAM_set_flags(
                self.as_ptr(),
                flags.bits(),
            ))
        }
    }

    /// Disables the supplied certificate-verification flags.
    ///
    /// # Errors
    ///
    /// Returns an error if the native parameter object rejects the update.
    #[corresponds(X509_VERIFY_PARAM_clear_flags)]
    pub fn clear_flags(&mut self, flags: X509VerifyFlags) -> Result<(), ErrorStack> {
        // SAFETY: the native verification parameters are uniquely borrowed.
        unsafe {
            cvt(ffi::X509_VERIFY_PARAM_clear_flags(
                self.as_ptr(),
                flags.bits(),
            ))
        }
    }

    /// Require the indicated certificate usage when validating a chain.
    ///
    /// # Errors
    /// The native verification parameters reject the purpose.
    #[corresponds(X509_VERIFY_PARAM_set_purpose)]
    pub fn set_purpose(&mut self, purpose: X509Purpose) -> Result<(), ErrorStack> {
        // SAFETY: the parameter object is exclusively borrowed, and every
        // enum value corresponds to a supported native purpose.
        unsafe {
            cvt(ffi::X509_VERIFY_PARAM_set_purpose(
                self.as_ptr(),
                purpose as c_int,
            ))
        }
    }

    /// Set the host flags.
    #[corresponds(X509_VERIFY_PARAM_set_hostflags)]
    pub fn set_hostflags(&mut self, hostflags: X509CheckFlags) {
        // SAFETY: the borrowed native parameter object is uniquely writable.
        unsafe {
            ffi::X509_VERIFY_PARAM_set_hostflags(self.as_ptr(), hostflags.bits());
        }
    }

    /// Gets verification flags.
    #[corresponds(X509_VERIFY_PARAM_get_flags)]
    #[must_use = "Use the returned flags to inspect current configuration."]
    pub fn flags(&self) -> X509VerifyFlags {
        // SAFETY: the native parameter object stays live for this flag query.
        let bits = unsafe { ffi::X509_VERIFY_PARAM_get_flags(self.as_ptr()) };
        X509VerifyFlags::from_bits_retain(bits)
    }

    /// Sets the expected DNS hostname. An empty name or embedded NUL is invalid.
    /// A failed native update poisons this parameter object so verification fails closed.
    #[corresponds(X509_VERIFY_PARAM_set1_host)]
    pub fn set_host(&mut self, host: &str) -> Result<(), ErrorStack> {
        // SAFETY: the exclusively borrowed native object copies this
        // readable hostname, with the exact length even for an empty slice.
        unsafe {
            cvt(ffi::X509_VERIFY_PARAM_set1_host(
                self.as_ptr(),
                host.as_ptr().cast(),
                host.len(),
            ))
        }
    }

    /// Sets the expected email address. An empty address or embedded NUL is invalid.
    /// A failed native update poisons this parameter object so verification fails closed.
    #[corresponds(X509_VERIFY_PARAM_set1_email)]
    pub fn set_email(&mut self, email: &str) -> Result<(), ErrorStack> {
        // SAFETY: the exclusively borrowed native object copies this
        // readable address, with the exact length even for an empty slice.
        unsafe {
            cvt(ffi::X509_VERIFY_PARAM_set1_email(
                self.as_ptr(),
                email.as_ptr().cast(),
                email.len(),
            ))
        }
    }

    /// Set the expected IPv4 or IPv6 address.
    #[corresponds(X509_VERIFY_PARAM_set1_ip)]
    pub fn set_ip(&mut self, ip: IpAddr) -> Result<(), ErrorStack> {
        // SAFETY: the native verifier copies a correctly sized 4- or
        // 16-byte IP address while the parameter object is exclusively borrowed.
        unsafe {
            let mut buf = [0; 16];
            let len = match ip {
                IpAddr::V4(addr) => {
                    buf[..4].copy_from_slice(&addr.octets());
                    4
                }
                IpAddr::V6(addr) => {
                    buf.copy_from_slice(&addr.octets());
                    16
                }
            };
            cvt(ffi::X509_VERIFY_PARAM_set1_ip(
                self.as_ptr(),
                buf.as_ptr().cast(),
                len,
            ))
        }
    }

    /// Set the verification time in seconds since the Unix epoch.
    #[corresponds(X509_VERIFY_PARAM_set_time_posix)]
    pub fn set_time(&mut self, time: i64) {
        // SAFETY: The parameter object is live and uniquely borrowed; the
        // POSIX API takes a fixed-width timestamp on every target.
        unsafe { ffi::X509_VERIFY_PARAM_set_time_posix(self.as_ptr(), time) }
    }

    /// Set the verification depth
    #[corresponds(X509_VERIFY_PARAM_set_depth)]
    pub fn set_depth(&mut self, depth: c_int) {
        // SAFETY: the native verification parameters are uniquely borrowed.
        unsafe { ffi::X509_VERIFY_PARAM_set_depth(self.as_ptr(), depth) }
    }

    /// Copies parameters from `src`.
    ///
    /// If a parameter is unset in `src`, the existing value in `self` is preserved. Verification flags are combined;
    /// the first explicitly configured verification time takes precedence.
    #[corresponds(X509_VERIFY_PARAM_set1)]
    pub fn copy_from(&mut self, src: &Self) -> Result<(), ErrorStack> {
        // SAFETY: the destination is exclusively borrowed, the source remains
        // live and immutably borrowed while native copies its parameters.
        unsafe { cvt(ffi::X509_VERIFY_PARAM_set1(self.as_ptr(), src.as_ptr())) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_roundtrip_without_panicking_wrappers() -> Result<(), ErrorStack> {
        let mut params = X509VerifyParam::new()?;
        params.set_flags(X509VerifyFlags::CRL_CHECK)?;
        assert!(params.flags().contains(X509VerifyFlags::CRL_CHECK));
        params.clear_flags(X509VerifyFlags::CRL_CHECK)?;
        assert!(!params.flags().contains(X509VerifyFlags::CRL_CHECK));
        Ok(())
    }
}
