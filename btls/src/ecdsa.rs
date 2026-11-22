//! Low level Elliptic Curve Digital Signature Algorithm (ECDSA) functions.

use crate::ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;

use crate::bn::{BigNum, BigNumRef};
use crate::ec::EcKeyRef;
use crate::error::ErrorStack;
use crate::pkey::{HasPrivate, HasPublic};
use crate::{cvt, cvt_p};
use std::mem;

foreign_type_and_impl_send_sync! {
    type CType = ffi::ECDSA_SIG;
    fn drop = ffi::ECDSA_SIG_free;

    /// A low level interface to ECDSA
    ///
    /// OpenSSL documentation at [`ECDSA_sign`]
    ///
    /// [`ECDSA_sign`]: https://www.openssl.org/docs/man1.1.0/crypto/ECDSA_sign.html
    pub struct EcdsaSig;
}

impl EcdsaSig {
    /// Signs an already-computed cryptographic message digest with a private EC key.
    ///
    /// Do not pass unhashed message data.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is unsuitable, signing fails, or allocation fails.
    #[corresponds(ECDSA_do_sign)]
    pub fn sign_digest<T>(digest: &[u8], key: &EcKeyRef<T>) -> Result<Self, ErrorStack>
    where
        T: HasPrivate,
    {
        // SAFETY: The private-key capability guarantees the required component.
        // The native function reads the full size_t length and returns an owned signature.
        unsafe {
            cvt_p(ffi::ECDSA_do_sign(
                digest.as_ptr(),
                digest.len(),
                key.as_ptr(),
            ))
            .map(|sig| Self::from_ptr(sig))
        }
    }

    /// Constructs a signature from its two integer components.
    ///
    /// The components are not validated against a curve until verification.
    ///
    /// # Errors
    ///
    /// Returns an error if native allocation or component installation fails.
    #[corresponds(ECDSA_SIG_set0)]
    pub fn from_components(r: BigNum, s: BigNum) -> Result<Self, ErrorStack> {
        // SAFETY: The new signature is owned before installation. Native only
        // takes ownership of r and s on success; Rust retains them on failure.
        unsafe {
            let sig = Self::from_ptr(cvt_p(ffi::ECDSA_SIG_new())?);
            cvt(ffi::ECDSA_SIG_set0(sig.as_ptr(), r.as_ptr(), s.as_ptr()))?;
            mem::forget((r, s));
            Ok(sig)
        }
    }

    from_der! {
        /// Decodes a DER-encoded ECDSA signature.
        #[corresponds(d2i_ECDSA_SIG)]
        from_der,
        EcdsaSig,
        ffi::d2i_ECDSA_SIG,
        ::libc::c_long
    }
}

impl EcdsaSigRef {
    to_der! {
        /// Serializes the ECDSA signature into a DER-encoded ECDSASignature structure.
        #[corresponds(i2d_ECDSA_SIG)]
        to_der,
        ffi::i2d_ECDSA_SIG
    }

    /// Checks this signature against an already-computed cryptographic message digest.
    ///
    /// Do not pass unhashed message data.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or native verification
    /// fails. The native operation does not distinguish those outcomes.
    #[corresponds(ECDSA_do_verify)]
    pub fn verify_digest<T>(&self, digest: &[u8], key: &EcKeyRef<T>) -> Result<(), ErrorStack>
    where
        T: HasPublic,
    {
        // SAFETY: The key has a public component, the signature stays live,
        // and native receives the exact readable size_t digest length.
        unsafe {
            cvt(ffi::ECDSA_do_verify(
                digest.as_ptr(),
                digest.len(),
                self.as_ptr(),
                key.as_ptr(),
            ))
        }
    }

    /// Borrows the r component of this signature.
    #[corresponds(ECDSA_SIG_get0_r)]
    #[must_use = "Use the returned signature component."]
    pub fn r(&self) -> &BigNumRef {
        // SAFETY: every successfully constructed signature owns both components.
        unsafe { BigNumRef::from_ptr(ffi::ECDSA_SIG_get0_r(self.as_ptr()).cast_mut()) }
    }

    /// Borrows the s component of this signature.
    #[corresponds(ECDSA_SIG_get0_s)]
    #[must_use = "Use the returned signature component."]
    pub fn s(&self) -> &BigNumRef {
        // SAFETY: every successfully constructed signature owns both components.
        unsafe { BigNumRef::from_ptr(ffi::ECDSA_SIG_get0_s(self.as_ptr()).cast_mut()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::{EcGroup, EcKey};
    use crate::nid::Nid;
    use crate::sha::sha256;

    #[test]
    fn sign_verify_and_reconstruct_components() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let digest = sha256(b"message");
        let sig = EcdsaSig::sign_digest(&digest, &key).unwrap();
        sig.verify_digest(&digest, &key).unwrap();
        assert!(sig.verify_digest(&sha256(b"other message"), &key).is_err());
        let reconstructed =
            EcdsaSig::from_components(sig.r().to_owned().unwrap(), sig.s().to_owned().unwrap())
                .unwrap();
        assert_eq!(sig.to_der().unwrap(), reconstructed.to_der().unwrap());
        reconstructed.verify_digest(&digest, &key).unwrap();
    }
}
