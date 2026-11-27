//! Private keys for Hybrid Public Key Encryption (HPKE).

use crate::error::ErrorStack;
use crate::{cvt, cvt_p, ffi};
use foreign_types::{ForeignType, ForeignTypeRef};

/// Key encapsulation mechanism used by an HPKE key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kem {
    DhkemP256HkdfSha256,
    DhkemX25519HkdfSha256,
    XWing,
    MlKem768,
    MlKem1024,
}

impl Kem {
    fn as_ptr(self) -> *const ffi::EVP_HPKE_KEM {
        // SAFETY: each function returns the static descriptor for its named KEM.
        unsafe {
            match self {
                Self::DhkemP256HkdfSha256 => ffi::EVP_hpke_p256_hkdf_sha256(),
                Self::DhkemX25519HkdfSha256 => ffi::EVP_hpke_x25519_hkdf_sha256(),
                Self::XWing => ffi::EVP_hpke_xwing(),
                Self::MlKem768 => ffi::EVP_hpke_mlkem768(),
                Self::MlKem1024 => ffi::EVP_hpke_mlkem1024(),
            }
        }
    }

    /// The encoded private-key length required by this mechanism.
    #[must_use = "Use the returned length when sizing an encoded private key."]
    pub fn private_key_len(self) -> usize {
        // SAFETY: as_ptr returns a valid static descriptor.
        unsafe { ffi::EVP_HPKE_KEM_private_key_len(self.as_ptr()) }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::EVP_HPKE_KEY;
    fn drop = ffi::EVP_HPKE_KEY_free;

    pub struct HpkeKey;
}

impl HpkeKey {
    /// Imports an encoded private key for the explicitly selected KEM.
    ///
    /// # Errors
    ///
    /// Native allocation fails or the private-key encoding is invalid for the KEM.
    pub fn from_private_key(kem: Kem, private_key: &[u8]) -> Result<Self, ErrorStack> {
        ffi::init();
        // SAFETY: the allocator returns a unique key or null. The descriptor
        // is static and the input remains readable for the synchronous call.
        unsafe {
            let key = Self::from_ptr(cvt_p(ffi::EVP_HPKE_KEY_new())?);
            cvt(ffi::EVP_HPKE_KEY_init(
                key.as_ptr(),
                kem.as_ptr(),
                private_key.as_ptr(),
                private_key.len(),
            ))?;
            Ok(key)
        }
    }
}

impl HpkeKeyRef {
    /// Encodes the public key for the selected KEM.
    ///
    /// # Errors
    ///
    /// Native serialization fails or reports an inconsistent length.
    pub fn public_key(&self) -> Result<Vec<u8>, ErrorStack> {
        // SAFETY: an initialized HPKE key has a live static KEM descriptor.
        let len = unsafe { ffi::EVP_HPKE_KEM_public_key_len(ffi::EVP_HPKE_KEY_kem(self.as_ptr())) };
        let mut out = vec![0; len];
        let mut written = 0;
        // SAFETY: the key stays live, the output has its exact native capacity,
        // and written is a writable local.
        unsafe {
            cvt(ffi::EVP_HPKE_KEY_public_key(
                self.as_ptr(),
                out.as_mut_ptr(),
                &raw mut written,
                len,
            ))?;
        }
        if written != len {
            return Err(ErrorStack::internal_error_str(
                "invalid native HPKE public key length",
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p256_scalar_one_is_generator() {
        let mut scalar = [0; 32];
        scalar[31] = 1;
        let key = HpkeKey::from_private_key(Kem::DhkemP256HkdfSha256, &scalar).unwrap();
        // SEC 2 secp256r1 generator, uncompressed SEC 1 encoding.
        assert_eq!(
            hex::encode(key.public_key().unwrap()),
            concat!(
                "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
            )
        );
        assert!(HpkeKey::from_private_key(Kem::DhkemP256HkdfSha256, &[0; 32]).is_err());
    }

    #[test]
    fn x25519_rfc7748_alice_public_key() {
        let private =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap();
        let key = HpkeKey::from_private_key(Kem::DhkemX25519HkdfSha256, &private).unwrap();
        assert_eq!(
            hex::encode(key.public_key().unwrap()),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
    }

    #[test]
    fn every_kem_selects_its_native_descriptor() {
        for (kem, id, public_len) in [
            (Kem::DhkemP256HkdfSha256, 0x0010, 65),
            (Kem::DhkemX25519HkdfSha256, 0x0020, 32),
            (Kem::XWing, 0x647a, 1216),
            (Kem::MlKem768, 0x0041, 1184),
            (Kem::MlKem1024, 0x0042, 1568),
        ] {
            // SAFETY: the descriptor is valid and static.
            assert_eq!(unsafe { ffi::EVP_HPKE_KEM_id(kem.as_ptr()) }, id);
            let key = HpkeKey::from_private_key(kem, &vec![1; kem.private_key_len()]).unwrap();
            assert_eq!(key.public_key().unwrap().len(), public_len);
            assert!(HpkeKey::from_private_key(kem, &vec![0; kem.private_key_len() - 1]).is_err());
        }
    }
}
