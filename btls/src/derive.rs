//! Shared secret derivation.
use crate::ffi;
use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;
use std::marker::PhantomData;
use std::ptr;

use crate::error::ErrorStack;
use crate::pkey::{HasPrivate, HasPublic, PKeyRef};
use crate::{cvt, cvt_p, util::SecretBytes};

/// A type used to derive a shared secret between two keys.
pub struct Deriver<'a>(*mut ffi::EVP_PKEY_CTX, PhantomData<&'a ()>);

// SAFETY: the context is uniquely owned; native key references outlive it
// and are immutable during derivation. The context is not thread-affine.
unsafe impl Send for Deriver<'_> {}

impl Drop for Deriver<'_> {
    fn drop(&mut self) {
        // SAFETY: self owns exactly one native context reference.
        unsafe { ffi::EVP_PKEY_CTX_free(self.0) };
    }
}

impl<'a> Deriver<'a> {
    /// Creates a new deriver using the provided private key.
    ///
    /// # Errors
    ///
    /// Native allocation or derivation initialization fails.
    #[corresponds(EVP_PKEY_derive_init)]
    pub fn new<T>(key: &'a PKeyRef<T>) -> Result<Self, ErrorStack>
    where
        T: HasPrivate,
    {
        // SAFETY: the live private key outlives the context. The new context
        // is owned before initialization, including on error.
        unsafe {
            cvt_p(ffi::EVP_PKEY_CTX_new(key.as_ptr(), ptr::null_mut()))
                .map(|p| Self(p, PhantomData))
                .and_then(|ctx| cvt(ffi::EVP_PKEY_derive_init(ctx.0)).map(|()| ctx))
        }
    }

    /// Sets the peer key used for secret derivation.
    ///
    /// # Errors
    ///
    /// The peer key is incompatible with the derivation algorithm.
    #[corresponds(EVP_PKEY_derive_set_peer)]
    pub fn set_peer<T>(&mut self, key: &'a PKeyRef<T>) -> Result<(), ErrorStack>
    where
        T: HasPublic,
    {
        // SAFETY: the live peer key outlives this exclusively borrowed context.
        unsafe { cvt(ffi::EVP_PKEY_derive_set_peer(self.0, key.as_ptr())) }
    }

    /// Returns the size of the shared secret.
    ///
    /// It can be used to size the buffer passed to [`Deriver::derive`].
    ///
    /// # Errors
    ///
    /// The context cannot determine a shared secret length.
    #[corresponds(EVP_PKEY_derive)]
    pub fn secret_len(&mut self) -> Result<usize, ErrorStack> {
        // SAFETY: null output requests only the length from the live context.
        unsafe {
            let mut len = 0;
            cvt(ffi::EVP_PKEY_derive(self.0, ptr::null_mut(), &raw mut len)).map(|()| len)
        }
    }

    /// Derives a shared secret between the two keys, writing it into the buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// The peer key is missing or invalid, or the output buffer is too small.
    #[corresponds(EVP_PKEY_derive)]
    pub fn derive(&mut self, buf: &mut [u8]) -> Result<usize, ErrorStack> {
        let mut len = buf.len();
        // SAFETY: the exclusive output buffer and its capacity are provided
        // to the live, exclusively borrowed native derivation context.
        unsafe { cvt(ffi::EVP_PKEY_derive(self.0, buf.as_mut_ptr(), &raw mut len))? };
        if len > buf.len() {
            return Err(ErrorStack::internal_error_str(
                "invalid native secret length",
            ));
        }
        Ok(len)
    }

    /// A convenience function which derives a shared secret and returns it in a new buffer.
    ///
    /// This simply wraps [`Deriver::secret_len`] and [`Deriver::derive`].
    ///
    /// [`Deriver::secret_len`]: #method.secret_len
    /// [`Deriver::derive`]: #method.derive
    ///
    /// # Errors
    ///
    /// The native length query or derivation fails.
    pub fn derive_to_vec(&mut self) -> Result<Vec<u8>, ErrorStack> {
        let len = self.secret_len()?;
        let mut buf = SecretBytes::zeroed(len)?;
        let len = self.derive(&mut buf)?;
        buf.into_vec(len)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::ec::{EcGroup, EcKey};
    use crate::nid::Nid;
    use crate::pkey::PKey;

    #[test]
    fn derive_without_peer() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        let mut deriver = Deriver::new(&pkey).unwrap();
        deriver.derive_to_vec().unwrap_err();
    }

    #[test]
    fn test_ec_key_derive() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let ec_key2 = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        let pkey2 = PKey::from_ec_key(ec_key2).unwrap();
        let mut deriver = Deriver::new(&pkey).unwrap();
        deriver.set_peer(&pkey2).unwrap();
        let shared = deriver.derive_to_vec().unwrap();
        let mut reverse = Deriver::new(&pkey2).unwrap();
        reverse.set_peer(&pkey).unwrap();
        assert_eq!(shared, reverse.derive_to_vec().unwrap());
        assert!(!shared.is_empty());
    }
}
