//! Shared secret derivation.
use crate::ffi;
use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;
use std::marker::PhantomData;
use std::ptr;

use crate::error::ErrorStack;
use crate::pkey::{HasPrivate, HasPublic, Id, PKeyRef};
use crate::util::{SecretBytes, cleanse};
use crate::{cvt, cvt_p};

/// A fixed-width shared-secret derivation operation with an immutable key pair.
/// Construct a new operation to change either key.
pub struct Deriver<'a> {
    ctx: *mut ffi::EVP_PKEY_CTX,
    secret_len: usize,
    _keys: PhantomData<&'a ()>,
}

// SAFETY: the context is uniquely owned; native key references outlive it
// and are immutable during derivation. The context is not thread-affine.
unsafe impl Send for Deriver<'_> {}

impl Drop for Deriver<'_> {
    fn drop(&mut self) {
        // SAFETY: self owns exactly one native context reference.
        unsafe { ffi::EVP_PKEY_CTX_free(self.ctx) };
    }
}

impl<'a> Deriver<'a> {
    /// Binds the private key and peer public key for shared-secret derivation.
    /// Finite-field DH retains leading zeros, avoiding variable-length secrets.
    /// Both keys must remain valid for the lifetime of the operation.
    /// # Errors
    /// Native allocation, derivation initialization, peer binding, or length query fails.
    #[corresponds(EVP_PKEY_derive_init)]
    pub fn new<T: HasPrivate, P: HasPublic>(
        key: &'a PKeyRef<T>,
        peer: &'a PKeyRef<P>,
    ) -> Result<Self, ErrorStack> {
        // SAFETY: the live keys outlive the context. Own the native context
        // before any fallible initialization; both key setters retain references.
        let mut operation = unsafe {
            Self {
                ctx: cvt_p(ffi::EVP_PKEY_CTX_new(key.as_ptr(), ptr::null_mut()))?,
                secret_len: 0,
                _keys: PhantomData,
            }
        };
        // SAFETY: uniquely owned initialized context and a borrowed live peer.
        unsafe {
            cvt(ffi::EVP_PKEY_derive_init(operation.ctx))?;
            cvt(ffi::EVP_PKEY_derive_set_peer(operation.ctx, peer.as_ptr()))?;
            if key.id() == Id::DH {
                cvt(ffi::EVP_PKEY_CTX_set_dh_pad(operation.ctx, 1))?;
            }
            cvt(ffi::EVP_PKEY_derive(
                operation.ctx,
                ptr::null_mut(),
                &raw mut operation.secret_len,
            ))?;
        }
        if operation.secret_len == 0 {
            return Err(ErrorStack::internal_error_str("empty shared secret"));
        }
        Ok(operation)
    }

    /// Returns the exact byte width of the shared secret.
    #[must_use = "Use the secret width when allocating the derivation output."]
    pub const fn secret_len(&self) -> usize {
        self.secret_len
    }

    /// Derives the complete shared secret into the start of the supplied buffer.
    /// Returns the exact prefix written; bytes beyond that prefix are unchanged.
    /// If native derivation fails, the output prefix is cleansed.
    /// # Errors
    /// The output buffer is too small, the peer is invalid, or native derivation fails.
    #[corresponds(EVP_PKEY_derive)]
    pub fn derive<'b>(&mut self, buf: &'b mut [u8]) -> Result<&'b mut [u8], ErrorStack> {
        let output = buf
            .get_mut(..self.secret_len)
            .ok_or_else(|| ErrorStack::internal_error_str("shared secret buffer too small"))?;
        let mut len = output.len();
        // SAFETY: the exclusive output prefix and its exact width are supplied
        // to the live context. A short buffer never reaches native ECDH.
        let result = unsafe {
            cvt(ffi::EVP_PKEY_derive(
                self.ctx,
                output.as_mut_ptr(),
                &raw mut len,
            ))
        };
        if let Err(error) = result {
            cleanse(output);
            return Err(error);
        }
        if len != output.len() {
            cleanse(output);
            return Err(ErrorStack::internal_error_str(
                "invalid native shared secret width",
            ));
        }
        Ok(output)
    }

    /// Derives the complete shared secret in a new buffer.
    /// # Errors
    /// Allocation or native derivation fails.
    pub fn derive_to_vec(&mut self) -> Result<Vec<u8>, ErrorStack> {
        let mut buf = SecretBytes::zeroed(self.secret_len)?;
        self.derive(&mut buf)?;
        buf.into_vec(self.secret_len)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::ec::{EcGroup, EcKey};
    use crate::nid::Nid;
    use crate::pkey::PKey;

    #[test]
    fn incompatible_keys_cannot_be_bound() {
        let ec = PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap();
        let other = PKey::generate(Id::X25519).unwrap();
        assert!(Deriver::new(&ec, &other).is_err());
        assert!(Deriver::new(&other, &ec).is_err());
        let different_curve = PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap(),
        )
        .unwrap();
        assert!(Deriver::new(&ec, &different_curve).is_err());
    }

    #[test]
    fn test_ec_key_derive() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let ec_key2 = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        let pkey2 = PKey::from_ec_key(ec_key2).unwrap();
        let mut deriver = Deriver::new(&pkey, &pkey2).unwrap();
        let shared = deriver.derive_to_vec().unwrap();
        let mut reverse = Deriver::new(&pkey2, &pkey).unwrap();
        assert_eq!(shared, reverse.derive_to_vec().unwrap());
        assert_eq!(shared.len(), 32);
        assert_eq!(deriver.secret_len(), 32);
        let mut short = [0xAA; 31];
        assert!(deriver.derive(&mut short).is_err());
        assert_eq!(short, [0xAA; 31]);
        let mut long = [0xAA; 33];
        assert_eq!(deriver.derive(&mut long).unwrap(), shared);
        assert_eq!(long[32], 0xAA);
    }

    #[test]
    fn x25519_invalid_peer_cleanses_output() {
        let key = PKey::generate(Id::X25519).unwrap();
        let peer = PKey::public_key_from_raw_bytes(&[0; 32], Id::X25519).unwrap();
        let mut deriver = Deriver::new(&key, &peer).unwrap();
        let mut output = [0xAA; 33];
        assert!(deriver.derive(&mut output).is_err());
        assert_eq!(output[..32], [0; 32]);
        assert_eq!(output[32], 0xAA);
    }

    #[test]
    fn finite_field_dh_preserves_leading_zeroes() {
        use crate::bn::BigNum;
        use crate::dh::Dh;
        use crate::pkey::Private;
        use foreign_types::ForeignType;

        fn key() -> PKey<Private> {
            // SAFETY: allocate the known ffdhe2048 group and install the
            // matching private exponent 2 and public element 4. Small fixed
            // test-only exponents deliberately produce leading zeroes.
            unsafe {
                let dh = Dh::<Private>::from_ptr(cvt_p(ffi::DH_get_rfc7919_2048()).unwrap());
                let public = BigNum::from_u32(4).unwrap();
                let private = BigNum::from_u32(2).unwrap();
                cvt(ffi::DH_set0_key(
                    dh.as_ptr(),
                    public.as_ptr(),
                    private.as_ptr(),
                ))
                .unwrap();
                std::mem::forget((public, private));
                let key = PKey::from_ptr(cvt_p(ffi::EVP_PKEY_new()).unwrap());
                cvt(ffi::EVP_PKEY_set1_DH(key.as_ptr(), dh.as_ptr())).unwrap();
                key
            }
        }
        let alice = key();
        let bob = key();
        let mut deriver = Deriver::new(&alice, &bob).unwrap();
        let secret = deriver.derive_to_vec().unwrap();
        let mut expected = [0; 256];
        expected[255] = 16;
        assert_eq!(secret, expected);
        assert_eq!(deriver.secret_len(), expected.len());
    }
}
