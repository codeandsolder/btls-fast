use crate::error::ErrorStack;
use crate::{cvt_0i, cvt_p, ffi};

use foreign_types::ForeignType;

foreign_type_and_impl_send_sync! {
    type CType = ffi::EVP_HPKE_KEY;
    fn drop = ffi::EVP_HPKE_KEY_free;

    pub struct HpkeKey;
}

impl HpkeKey {
    /// Allocates and initializes a key with the `EVP_HPKE_KEY` type using the
    /// `EVP_hpke_x25519_hkdf_sha256` KEM algorithm.
    ///
    /// # Errors
    ///
    /// Returns the native error stack if allocation or key initialization fails.
    pub fn dhkem_p256_sha256(pkey: &[u8]) -> Result<Self, ErrorStack> {
        // SAFETY: the returned native key is owned immediately; the borrowed input
        // slice stays valid during `EVP_HPKE_KEY_init` and is passed with its length.
        unsafe {
            ffi::init();
            let hpke = cvt_p(ffi::EVP_HPKE_KEY_new()).map(|p| Self::from_ptr(p))?;

            cvt_0i(ffi::EVP_HPKE_KEY_init(
                hpke.as_ptr(),
                ffi::EVP_hpke_x25519_hkdf_sha256(),
                pkey.as_ptr(),
                pkey.len(),
            ))?;

            Ok(hpke)
        }
    }
}
