//! ML-KEM (FIPS 203) post-quantum key encapsulation.
//!
//! ML-KEM is a low-level cryptographic primitive. For most applications,
//! using higher-level constructions like HPKE is preferred.
//! Note that it's also enabled in TLS by default, in the X25519MLKEM768 exchange.
//!
//! Provides ML-KEM-768 (recommended) and ML-KEM-1024 variants via [`Algorithm`].
//!
//! ```
//! use btls::mlkem::{Algorithm, MlKemPrivateKey};
//!
//! let (public_key, private_key) = MlKemPrivateKey::generate(Algorithm::MlKem768).unwrap();
//! let (ciphertext, shared_secret) = public_key.encapsulate().unwrap();
//! let decrypted = private_key.decapsulate(&ciphertext).unwrap();
//! assert_eq!(shared_secret, decrypted);
//! ```

use std::fmt;
use std::mem::MaybeUninit;
use std::sync::Arc;

use crate::cvt;
use crate::error::ErrorStack;
use crate::ffi;
use crate::ffi::cbs_init;

/// Private key seed size (64 bytes).
pub const PRIVATE_KEY_SEED_BYTES: usize = ffi::MLKEM_SEED_BYTES as usize;

/// Shared secret size (32 bytes).
pub const SHARED_SECRET_BYTES: usize = ffi::MLKEM_SHARED_SECRET_BYTES as usize;

/// Raw bytes of the private key seed ([`PRIVATE_KEY_SEED_BYTES`] long)
pub type MlKemPrivateKeySeed = [u8; PRIVATE_KEY_SEED_BYTES];

/// Raw bytes of the shared secret ([`SHARED_SECRET_BYTES`] long)
pub type MlKemSharedSecret = [u8; SHARED_SECRET_BYTES];

/// ML-KEM runtime algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Recommended. AES-192 equivalent security.
    MlKem768,
    /// AES-256 equivalent security.
    MlKem1024,
}

impl Algorithm {
    /// Returns 1184 for ML-KEM-768, 1568 for ML-KEM-1024.
    #[must_use]
    pub const fn public_key_bytes(self) -> usize {
        match self {
            Self::MlKem768 => MlKem768PublicKey::PUBLIC_KEY_BYTES,
            Self::MlKem1024 => MlKem1024PublicKey::PUBLIC_KEY_BYTES,
        }
    }

    /// Returns 1088 for ML-KEM-768, 1568 for ML-KEM-1024.
    #[must_use]
    pub const fn ciphertext_bytes(self) -> usize {
        match self {
            Self::MlKem768 => MlKem768PrivateKey::CIPHERTEXT_BYTES,
            Self::MlKem1024 => MlKem1024PrivateKey::CIPHERTEXT_BYTES,
        }
    }
}

#[derive(Clone)]
pub struct MlKemPublicKey(Either<Arc<MlKem768PublicKey>, Arc<MlKem1024PublicKey>>);

#[derive(Clone)]
pub struct MlKemPrivateKey(Either<Arc<MlKem768PrivateKey>, Arc<MlKem1024PrivateKey>>);

#[derive(Clone)]
enum Either<T768, T1024> {
    MlKem768(T768),
    MlKem1024(T1024),
}

impl MlKemPrivateKey {
    /// Generates a new key pair, returning `(public_key, private_key)`.
    ///
    /// The private key is a 64-byte seed. Keep it secret.
    pub fn generate(algorithm: Algorithm) -> Result<(MlKemPublicKey, Self), ErrorStack> {
        match algorithm {
            Algorithm::MlKem768 => {
                let (pk, sk) = MlKem768PrivateKey::generate()?;
                Ok((
                    MlKemPublicKey(Either::MlKem768(pk)),
                    Self(Either::MlKem768(sk)),
                ))
            }
            Algorithm::MlKem1024 => {
                let (pk, sk) = MlKem1024PrivateKey::generate()?;
                Ok((
                    MlKemPublicKey(Either::MlKem1024(pk)),
                    Self(Either::MlKem1024(sk)),
                ))
            }
        }
    }
}

impl MlKemPublicKey {
    pub fn from_slice(algorithm: Algorithm, public_key: &[u8]) -> Result<Self, ErrorStack> {
        match algorithm {
            Algorithm::MlKem768 => Ok(Self(Either::MlKem768(Arc::new(
                MlKem768PublicKey::from_slice(public_key)?,
            )))),
            Algorithm::MlKem1024 => Ok(Self(Either::MlKem1024(Arc::new(
                MlKem1024PublicKey::from_slice(public_key)?,
            )))),
        }
    }

    /// Serialized bytes of the public key
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            Either::MlKem768(pk) => &pk.bytes,
            Either::MlKem1024(pk) => &pk.bytes,
        }
    }

    /// Encapsulates a shared secret to the given public key, returning
    /// `(ciphertext, shared_secret)`.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, MlKemSharedSecret), ErrorStack> {
        match &self.0 {
            Either::MlKem768(pk) => {
                let (ct, ss) = pk.encapsulate();
                Ok((ct.to_vec(), ss))
            }
            Either::MlKem1024(pk) => {
                let (ct, ss) = pk.encapsulate();
                Ok((ct.to_vec(), ss))
            }
        }
    }

    /// Query public key and ciphertext length
    pub const fn algorithm(&self) -> Algorithm {
        match self.0 {
            Either::MlKem768(_) => Algorithm::MlKem768,
            Either::MlKem1024(_) => Algorithm::MlKem1024,
        }
    }
}

impl MlKemPrivateKey {
    /// Expand private key from the seed bytes
    pub fn from_seed(
        algorithm: Algorithm,
        private_seed: &MlKemPrivateKeySeed,
    ) -> Result<Self, ErrorStack> {
        match algorithm {
            Algorithm::MlKem768 => Ok(Self(Either::MlKem768(Arc::new(
                MlKem768PrivateKey::from_seed(private_seed)?,
            )))),
            Algorithm::MlKem1024 => Ok(Self(Either::MlKem1024(Arc::new(
                MlKem1024PrivateKey::from_seed(private_seed)?,
            )))),
        }
    }

    /// Secret seed bytes of this private key
    pub fn seed_bytes(&self) -> &MlKemPrivateKeySeed {
        match &self.0 {
            Either::MlKem768(sk) => &sk.seed,
            Either::MlKem1024(sk) => &sk.seed,
        }
    }

    /// Decapsulates a shared secret from a ciphertext using the private key.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<MlKemSharedSecret, ErrorStack> {
        match &self.0 {
            Either::MlKem768(sk) => {
                let ct: &[u8; MlKem768PrivateKey::CIPHERTEXT_BYTES] = ciphertext
                    .try_into()
                    .map_err(|_| ErrorStack::internal_error_str("invalid ciphertext length"))?;
                Ok(sk.decapsulate(ct))
            }
            Either::MlKem1024(sk) => {
                let ct: &[u8; MlKem1024PrivateKey::CIPHERTEXT_BYTES] = ciphertext
                    .try_into()
                    .map_err(|_| ErrorStack::internal_error_str("invalid ciphertext length"))?;
                Ok(sk.decapsulate(ct))
            }
        }
    }

    /// Query public key and ciphertext length
    pub const fn algorithm(&self) -> Algorithm {
        match self.0 {
            Either::MlKem768(_) => Algorithm::MlKem768,
            Either::MlKem1024(_) => Algorithm::MlKem1024,
        }
    }
}

// All sizes, native types and entrypoints belong to the same parameter set.
// Shared handles keep one immutable native key representation per generated
// or restored key. The last private owner cleanses the secret.
macro_rules! define_mlkem {
    (
        $private:ident, $public:ident, $native_private:ident, $native_public:ident,
        $ciphertext_bytes:ident, $public_bytes:ident,
        $generate:ident, $restore:ident, $derive_public:ident, $marshal:ident,
        $decap:ident, $parse:ident, $encap:ident
    ) => {
        /// Native expanded ML-KEM private key.
        ///
        /// Caches the expanded key for fast decapsulation.
        struct $private {
            seed: MlKemPrivateKeySeed,
            expanded: ffi::$native_private,
        }

        impl $private {
            pub const CIPHERTEXT_BYTES: usize = ffi::$ciphertext_bytes as usize;

            /// Generate a new key pair.
            fn generate() -> Result<(Arc<$public>, Arc<Self>), ErrorStack> {
                // SAFETY: all buffers are out parameters, correctly sized
                unsafe {
                    ffi::init();
                    let mut bytes = [0; $public::PUBLIC_KEY_BYTES];
                    let mut seed = [0; PRIVATE_KEY_SEED_BYTES];
                    let mut expanded: MaybeUninit<ffi::$native_private> = MaybeUninit::zeroed();

                    ffi::$generate(
                        bytes.as_mut_ptr().cast(),
                        seed.as_mut_ptr(),
                        expanded.as_mut_ptr(),
                    );

                    let private = Arc::new(Self {
                        seed,
                        expanded: expanded.assume_init(),
                    });
                    Ok((Arc::new($public::from_slice(&bytes)?), private))
                }
            }

            /// Restore private key from seed.
            fn from_seed(seed: &MlKemPrivateKeySeed) -> Result<Self, ErrorStack> {
                // SAFETY: seed is 64 bytes, out parameter correctly sized
                unsafe {
                    ffi::init();
                    let mut expanded: MaybeUninit<ffi::$native_private> = MaybeUninit::zeroed();
                    cvt(ffi::$restore(
                        expanded.as_mut_ptr(),
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    Ok(Self {
                        seed: *seed,
                        expanded: expanded.assume_init(),
                    })
                }
            }

            /// Derive the public key.
            #[cfg(test)]
            fn public_key(&self) -> Result<$public, ErrorStack> {
                // SAFETY: expanded key is valid, buffers correctly sized
                unsafe {
                    ffi::init();
                    let mut parsed: MaybeUninit<ffi::$native_public> = MaybeUninit::zeroed();
                    ffi::$derive_public(parsed.as_mut_ptr(), &self.expanded);

                    let mut bytes = [0u8; $public::PUBLIC_KEY_BYTES];
                    let mut cbb: MaybeUninit<ffi::CBB> = MaybeUninit::zeroed();
                    cvt(ffi::CBB_init_fixed(
                        cbb.as_mut_ptr(),
                        bytes.as_mut_ptr(),
                        bytes.len(),
                    ))?;
                    let result = cvt(ffi::$marshal(cbb.as_mut_ptr(), parsed.as_ptr()));
                    ffi::CBB_cleanup(cbb.as_mut_ptr());
                    result?;

                    Ok($public {
                        bytes,
                        parsed: parsed.assume_init(),
                    })
                }
            }

            /// Decapsulate to get the shared secret.
            fn decapsulate(&self, ciphertext: &[u8; Self::CIPHERTEXT_BYTES]) -> MlKemSharedSecret {
                // SAFETY: expanded key is valid, ciphertext is correctly sized
                unsafe {
                    ffi::init();
                    let mut shared_secret = [0u8; SHARED_SECRET_BYTES];

                    ffi::$decap(
                        shared_secret.as_mut_ptr(),
                        ciphertext.as_ptr(),
                        ciphertext.len(),
                        &raw const self.expanded,
                    );

                    shared_secret
                }
            }
        }

        impl fmt::Debug for $private {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($private))
                    .field("key", &"[redacted]")
                    .finish()
            }
        }

        impl Drop for $private {
            fn drop(&mut self) {
                // SAFETY: pointers and lengths are valid
                unsafe {
                    ffi::OPENSSL_cleanse(self.seed.as_mut_ptr().cast(), self.seed.len());
                    ffi::OPENSSL_cleanse(
                        self.expanded.opaque.bytes.as_mut_ptr().cast(),
                        self.expanded.opaque.bytes.len(),
                    );
                }
            }
        }

        /// Parsed native ML-KEM public key.
        struct $public {
            bytes: [u8; Self::PUBLIC_KEY_BYTES],
            parsed: ffi::$native_public,
        }

        impl $public {
            pub const PUBLIC_KEY_BYTES: usize = ffi::$public_bytes as usize;

            /// Parse and validate a public key.
            ///
            /// The slice must be [`Self::PUBLIC_KEY_BYTES`] long.
            fn from_slice(slice: &[u8]) -> Result<Self, ErrorStack> {
                if slice.len() != Self::PUBLIC_KEY_BYTES {
                    return Err(ErrorStack::internal_error_str("invalid public key length"));
                }

                // SAFETY: CBS correctly initialized, length already checked
                unsafe {
                    ffi::init();
                    let mut cbs = cbs_init(slice);
                    let mut parsed: MaybeUninit<ffi::$native_public> = MaybeUninit::zeroed();

                    cvt(ffi::$parse(parsed.as_mut_ptr(), &raw mut cbs))?;
                    if cbs.len != 0 {
                        return Err(ErrorStack::internal_error_str(
                            "trailing bytes after public key",
                        ));
                    }

                    let mut bytes = [0u8; Self::PUBLIC_KEY_BYTES];
                    bytes.copy_from_slice(slice);
                    Ok(Self {
                        bytes,
                        parsed: parsed.assume_init(),
                    })
                }
            }

            /// Encapsulate: returns (ciphertext, shared_secret).
            fn encapsulate(&self) -> ([u8; $private::CIPHERTEXT_BYTES], MlKemSharedSecret) {
                // SAFETY: buffers correctly sized, parsed key is valid
                unsafe {
                    ffi::init();
                    let mut ciphertext = [0u8; $private::CIPHERTEXT_BYTES];
                    let mut shared_secret = [0u8; SHARED_SECRET_BYTES];

                    ffi::$encap(
                        ciphertext.as_mut_ptr(),
                        shared_secret.as_mut_ptr(),
                        &raw const self.parsed,
                    );

                    (ciphertext, shared_secret)
                }
            }
        }

        impl fmt::Debug for $public {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($public))
                    .field("bytes", &format_args!("[{}]", self.bytes.len()))
                    .finish()
            }
        }
    };
}

define_mlkem!(
    MlKem768PrivateKey,
    MlKem768PublicKey,
    MLKEM768_private_key,
    MLKEM768_public_key,
    MLKEM768_CIPHERTEXT_BYTES,
    MLKEM768_PUBLIC_KEY_BYTES,
    MLKEM768_generate_key,
    MLKEM768_private_key_from_seed,
    MLKEM768_public_from_private,
    MLKEM768_marshal_public_key,
    MLKEM768_decap,
    MLKEM768_parse_public_key,
    MLKEM768_encap
);

define_mlkem!(
    MlKem1024PrivateKey,
    MlKem1024PublicKey,
    MLKEM1024_private_key,
    MLKEM1024_public_key,
    MLKEM1024_CIPHERTEXT_BYTES,
    MLKEM1024_PUBLIC_KEY_BYTES,
    MLKEM1024_generate_key,
    MLKEM1024_private_key_from_seed,
    MLKEM1024_public_from_private,
    MLKEM1024_marshal_public_key,
    MLKEM1024_decap,
    MLKEM1024_parse_public_key,
    MLKEM1024_encap
);

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! mlkem_tests {
        ($name:ident, $priv:ty, $pub:ty, $ct_len:expr) => {
            mod $name {
                use super::*;

                #[test]
                fn roundtrip() {
                    let (pk, sk) = <$priv>::generate().unwrap();
                    let (ct, ss1) = pk.encapsulate();
                    let ss2 = sk.decapsulate(&ct);
                    assert_eq!(ss1, ss2);
                }

                #[test]
                fn seed_roundtrip() {
                    let (pk, sk) = <$priv>::generate().unwrap();
                    let sk2 = <$priv>::from_seed(&sk.seed).unwrap();
                    let (ct, ss1) = pk.encapsulate();
                    let ss2 = sk2.decapsulate(&ct);
                    assert_eq!(ss1, ss2);
                }

                #[test]
                fn derive_pubkey() {
                    let (pk, sk) = <$priv>::generate().unwrap();
                    assert_eq!(pk.bytes, sk.public_key().unwrap().bytes);
                }

                #[test]
                fn from_slice_rejects_bad_len() {
                    assert!(<$pub>::from_slice(&[0u8; 100]).is_err());
                    assert!(<$pub>::from_slice(&[]).is_err());
                }

                #[test]
                fn from_slice_roundtrip() {
                    let (pk, _) = <$priv>::generate().unwrap();
                    let pk2 = <$pub>::from_slice(&pk.bytes).unwrap();
                    assert_eq!(pk.bytes, pk2.bytes);
                }

                #[test]
                fn implicit_rejection() {
                    let (_, sk) = <$priv>::generate().unwrap();
                    let bad_ct = [0x42u8; $ct_len];
                    // bad ciphertext still "works", just returns deterministic garbage
                    let ss1 = sk.decapsulate(&bad_ct);
                    let ss2 = sk.decapsulate(&bad_ct);
                    assert_eq!(ss1, ss2);
                }

                #[test]
                fn debug_redacts_seed() {
                    let (_, sk) = <$priv>::generate().unwrap();
                    let dbg = format!("{:?}", sk);
                    assert!(dbg.contains("redacted"));
                }
            }
        };
    }

    mlkem_tests!(mlkem768, MlKem768PrivateKey, MlKem768PublicKey, 1088);
    mlkem_tests!(mlkem1024, MlKem1024PrivateKey, MlKem1024PublicKey, 1568);

    // Tests for unified API (MlKem struct)
    mod unified_api {
        use super::*;

        macro_rules! unified_tests {
            ($name:ident, $algorithm:expr, $pk_len:expr, $ct_len:expr) => {
                mod $name {
                    use super::*;

                    #[test]
                    fn roundtrip() {
                        let (pk, sk) = MlKemPrivateKey::generate($algorithm).unwrap();
                        let (ct, ss1) = pk.encapsulate().unwrap();
                        let ss2 = sk.decapsulate(&ct).unwrap();
                        let ss3 = sk.clone().decapsulate(&ct).unwrap();
                        let cloned = sk.clone();
                        drop(sk);
                        let ss4 = cloned.decapsulate(&ct).unwrap();
                        assert_eq!(ss1, ss2);
                        assert_eq!(ss1, ss3);
                        assert_eq!(ss1, ss4);
                    }

                    #[test]
                    fn key_sizes() {
                        assert_eq!($algorithm.public_key_bytes(), $pk_len);
                        assert_eq!($algorithm.ciphertext_bytes(), $ct_len);

                        let (pk, private_key) = MlKemPrivateKey::generate($algorithm).unwrap();
                        assert_eq!(pk.as_bytes().len(), $pk_len);
                        assert_eq!(private_key.seed_bytes().len(), PRIVATE_KEY_SEED_BYTES);

                        let (ct, ss) = pk.encapsulate().unwrap();
                        assert_eq!(ct.len(), $ct_len);
                        assert_eq!(ss.len(), SHARED_SECRET_BYTES);
                    }

                    #[test]
                    fn invalid_public_key_length() {
                        let result = MlKemPublicKey::from_slice($algorithm, &[0u8; 100]);
                        assert!(result.is_err());
                    }

                    #[test]
                    fn invalid_ciphertext_length() {
                        let (_, sk) = MlKemPrivateKey::generate($algorithm).unwrap();
                        let result = sk.decapsulate(&[0u8; 100]);
                        assert!(result.is_err());
                    }
                }
            };
        }

        unified_tests!(mlkem768, Algorithm::MlKem768, 1184, 1088);
        unified_tests!(mlkem1024, Algorithm::MlKem1024, 1568, 1568);

        #[test]
        fn params_constants() {
            assert_eq!(Algorithm::MlKem768.public_key_bytes(), 1184);
            assert_eq!(Algorithm::MlKem768.ciphertext_bytes(), 1088);
            assert_eq!(Algorithm::MlKem1024.public_key_bytes(), 1568);
            assert_eq!(Algorithm::MlKem1024.ciphertext_bytes(), 1568);
        }
    }
}
