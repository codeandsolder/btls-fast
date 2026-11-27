//! Native FIPS mode query.
//!
//! See [OpenSSL's documentation] for details.
//!
//! [OpenSSL's documentation]: https://www.openssl.org/docs/fips/UserGuide-2.0.pdf
use crate::ffi;
use openssl_macros::corresponds;

/// Returns whether the native library reports FIPS mode. This is not a certification check.
#[corresponds(FIPS_mode)]
#[must_use = "Use this predicate to decide how to handle the current value or connection."]
pub fn enabled() -> bool {
    // SAFETY: this global BoringSSL query takes no pointers or caller-owned state.
    unsafe { ffi::FIPS_mode() != 0 }
}

#[test]
fn is_enabled() {
    #[cfg(feature = "fips")]
    assert!(enabled());
    #[cfg(not(feature = "fips"))]
    assert!(!enabled());
}
