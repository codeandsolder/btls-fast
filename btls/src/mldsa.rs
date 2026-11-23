//! ML-DSA (FIPS 204) post-quantum digital signature.
//!
//! ```
//! use btls::mldsa::{Algorithm, MlDsaPrivateKey};
//!
//! // Generate a key pair.
//! let (public_key, private_key) = MlDsaPrivateKey::generate(Algorithm::MlDsa65).unwrap();
//!
//! // Sign a message.
//! let message = b"hello post-quantum world";
//! let signature = private_key.sign(message).unwrap();
//!
//! // Verify the signature.
//! assert!(public_key.verify(message, &signature).is_ok());
//! ```

use std::fmt;
use std::mem::{self, MaybeUninit};
use std::sync::Arc;

use crate::cvt;
use crate::error::ErrorStack;
use crate::ffi;
use crate::ffi::cbs_init;

/// Seed size (32 bytes, shared across all ML-DSA parameter sets).
pub const PRIVATE_KEY_SEED_BYTES: usize = ffi::MLDSA_SEED_BYTES as usize;

/// Raw bytes of a private key seed ([`PRIVATE_KEY_SEED_BYTES`] long).
pub type MlDsaPrivateKeySeed = [u8; PRIVATE_KEY_SEED_BYTES];

/// ML-DSA parameter set selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// NIST security level 2 (AES-128 equivalent).
    MlDsa44,
    /// NIST security level 3 (AES-192 equivalent).
    MlDsa65,
    /// NIST security level 5 (AES-256 equivalent).
    MlDsa87,
}

impl Algorithm {
    /// Returns the encoded public key size in bytes.
    #[must_use = "Use the returned length or capacity to size buffers or validate input."]
    pub const fn public_key_bytes(self) -> usize {
        match self {
            Self::MlDsa44 => ffi::MLDSA44_PUBLIC_KEY_BYTES as usize,
            Self::MlDsa65 => ffi::MLDSA65_PUBLIC_KEY_BYTES as usize,
            Self::MlDsa87 => ffi::MLDSA87_PUBLIC_KEY_BYTES as usize,
        }
    }

    /// Returns the signature size in bytes.
    #[must_use = "Use the returned length or capacity to size buffers or validate input."]
    pub const fn signature_bytes(self) -> usize {
        match self {
            Self::MlDsa44 => ffi::MLDSA44_SIGNATURE_BYTES as usize,
            Self::MlDsa65 => ffi::MLDSA65_SIGNATURE_BYTES as usize,
            Self::MlDsa87 => ffi::MLDSA87_SIGNATURE_BYTES as usize,
        }
    }
}

/// An ML-DSA public key (any parameter set).
#[derive(Clone)]
pub struct MlDsaPublicKey {
    algorithm: Algorithm,
    inner: PublicKeyInner,
}

#[derive(Clone)]
enum PublicKeyInner {
    MlDsa44(Box<ffi::MLDSA44_public_key>),
    MlDsa65(Box<ffi::MLDSA65_public_key>),
    MlDsa87(Box<ffi::MLDSA87_public_key>),
}

/// A shared ML-DSA private key. Clones reuse the immutable expanded key.
#[derive(Clone)]
pub struct MlDsaPrivateKey {
    algorithm: Algorithm,
    inner: PrivateKeyInner,
}

#[derive(Clone)]
enum PrivateKeyInner {
    MlDsa44(Arc<SecretMaterial<ffi::MLDSA44_private_key>>),
    MlDsa65(Arc<SecretMaterial<ffi::MLDSA65_private_key>>),
    MlDsa87(Arc<SecretMaterial<ffi::MLDSA87_private_key>>),
}

// Only opaque, plain-old-data native key structures instantiate T.
// Their full representation, as well as the seed, is erased on final drop.
struct SecretMaterial<T: Copy> {
    seed: MlDsaPrivateKeySeed,
    expanded: T,
}

impl<T: Copy> Drop for SecretMaterial<T> {
    fn drop(&mut self) {
        // SAFETY: these exclusively owned initialized byte regions remain
        // writable until the last Arc reference is released. T is Copy (no Drop).
        unsafe {
            ffi::OPENSSL_cleanse(self.seed.as_mut_ptr().cast(), self.seed.len());
            ffi::OPENSSL_cleanse((&raw mut self.expanded).cast(), mem::size_of::<T>());
        }
    }
}

// The native APIs write large secret structures through out-parameters.
// Keep a zero-initialized temporary and cleanse it even on native failure,
// then transfer an initialized copy to the shared owner's allocation.
struct SecretBuilder<T: Copy> {
    seed: MlDsaPrivateKeySeed,
    expanded: MaybeUninit<T>,
}

impl<T: Copy> SecretBuilder<T> {
    fn new(seed: MlDsaPrivateKeySeed) -> Self {
        Self {
            seed,
            expanded: MaybeUninit::zeroed(),
        }
    }

    fn into_shared(self) -> Arc<SecretMaterial<T>> {
        // SAFETY: the only instantiations are native opaque byte-array unions.
        // They are fully valid when zeroed, and native success filled the key.
        let expanded = unsafe { self.expanded.assume_init_read() };
        Arc::new(SecretMaterial {
            seed: self.seed,
            expanded,
        })
        // self's Drop cleanses the original temporary copy.
    }
}

impl<T: Copy> Drop for SecretBuilder<T> {
    fn drop(&mut self) {
        // SAFETY: the temporary's seed and its zeroed/native-written opaque
        // storage are exclusively writable, including after a failed call.
        unsafe {
            ffi::OPENSSL_cleanse(self.seed.as_mut_ptr().cast(), self.seed.len());
            ffi::OPENSSL_cleanse(self.expanded.as_mut_ptr().cast(), mem::size_of::<T>());
        }
    }
}

impl MlDsaPrivateKey {
    /// Generates a random ML-DSA key pair.
    ///
    /// Returns `(public_key, private_key)`.
    ///
    /// # Errors
    ///
    /// Native key generation or public-key reconstruction fails.
    pub fn generate(algorithm: Algorithm) -> Result<(MlDsaPublicKey, Self), ErrorStack> {
        unsafe {
            ffi::init();
            match algorithm {
                Algorithm::MlDsa44 => {
                    let mut pub_bytes = [0u8; ffi::MLDSA44_PUBLIC_KEY_BYTES as usize];
                    let mut secret =
                        SecretBuilder::<ffi::MLDSA44_private_key>::new([0; PRIVATE_KEY_SEED_BYTES]);
                    cvt(ffi::MLDSA44_generate_key(
                        pub_bytes.as_mut_ptr(),
                        secret.seed.as_mut_ptr(),
                        secret.expanded.as_mut_ptr(),
                    ))?;
                    let public_key = MlDsaPublicKey::from_slice(algorithm, &pub_bytes)?;
                    Ok((
                        public_key,
                        Self {
                            algorithm,
                            inner: PrivateKeyInner::MlDsa44(secret.into_shared()),
                        },
                    ))
                }
                Algorithm::MlDsa65 => {
                    let mut pub_bytes = [0u8; ffi::MLDSA65_PUBLIC_KEY_BYTES as usize];
                    let mut secret =
                        SecretBuilder::<ffi::MLDSA65_private_key>::new([0; PRIVATE_KEY_SEED_BYTES]);
                    cvt(ffi::MLDSA65_generate_key(
                        pub_bytes.as_mut_ptr(),
                        secret.seed.as_mut_ptr(),
                        secret.expanded.as_mut_ptr(),
                    ))?;
                    let public_key = MlDsaPublicKey::from_slice(algorithm, &pub_bytes)?;
                    Ok((
                        public_key,
                        Self {
                            algorithm,
                            inner: PrivateKeyInner::MlDsa65(secret.into_shared()),
                        },
                    ))
                }
                Algorithm::MlDsa87 => {
                    let mut pub_bytes = [0u8; ffi::MLDSA87_PUBLIC_KEY_BYTES as usize];
                    let mut secret =
                        SecretBuilder::<ffi::MLDSA87_private_key>::new([0; PRIVATE_KEY_SEED_BYTES]);
                    cvt(ffi::MLDSA87_generate_key(
                        pub_bytes.as_mut_ptr(),
                        secret.seed.as_mut_ptr(),
                        secret.expanded.as_mut_ptr(),
                    ))?;
                    let public_key = MlDsaPublicKey::from_slice(algorithm, &pub_bytes)?;
                    Ok((
                        public_key,
                        Self {
                            algorithm,
                            inner: PrivateKeyInner::MlDsa87(secret.into_shared()),
                        },
                    ))
                }
            }
        }
    }

    /// Regenerates a private key from a seed value.
    ///
    /// # Errors
    ///
    /// The seed cannot be expanded or native allocation fails.
    pub fn from_seed(algorithm: Algorithm, seed: &MlDsaPrivateKeySeed) -> Result<Self, ErrorStack> {
        unsafe {
            ffi::init();
            match algorithm {
                Algorithm::MlDsa44 => {
                    let mut secret = SecretBuilder::<ffi::MLDSA44_private_key>::new(*seed);
                    cvt(ffi::MLDSA44_private_key_from_seed(
                        secret.expanded.as_mut_ptr(),
                        secret.seed.as_ptr(),
                        secret.seed.len(),
                    ))?;
                    Ok(Self {
                        algorithm,
                        inner: PrivateKeyInner::MlDsa44(secret.into_shared()),
                    })
                }
                Algorithm::MlDsa65 => {
                    let mut secret = SecretBuilder::<ffi::MLDSA65_private_key>::new(*seed);
                    cvt(ffi::MLDSA65_private_key_from_seed(
                        secret.expanded.as_mut_ptr(),
                        secret.seed.as_ptr(),
                        secret.seed.len(),
                    ))?;
                    Ok(Self {
                        algorithm,
                        inner: PrivateKeyInner::MlDsa65(secret.into_shared()),
                    })
                }
                Algorithm::MlDsa87 => {
                    let mut secret = SecretBuilder::<ffi::MLDSA87_private_key>::new(*seed);
                    cvt(ffi::MLDSA87_private_key_from_seed(
                        secret.expanded.as_mut_ptr(),
                        secret.seed.as_ptr(),
                        secret.seed.len(),
                    ))?;
                    Ok(Self {
                        algorithm,
                        inner: PrivateKeyInner::MlDsa87(secret.into_shared()),
                    })
                }
            }
        }
    }

    /// Returns the algorithm for this key.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the seed bytes for this private key.
    pub fn seed_bytes(&self) -> &MlDsaPrivateKeySeed {
        match &self.inner {
            PrivateKeyInner::MlDsa44(key) => &key.seed,
            PrivateKeyInner::MlDsa65(key) => &key.seed,
            PrivateKeyInner::MlDsa87(key) => &key.seed,
        }
    }

    /// Returns the public key corresponding to this private key.
    ///
    /// # Errors
    ///
    /// The native public-key derivation fails.
    pub fn public_key(&self) -> Result<MlDsaPublicKey, ErrorStack> {
        unsafe {
            ffi::init();
            match &self.inner {
                PrivateKeyInner::MlDsa44(key) => {
                    let mut pub_key: MaybeUninit<ffi::MLDSA44_public_key> = MaybeUninit::zeroed();
                    cvt(ffi::MLDSA44_public_from_private(
                        pub_key.as_mut_ptr(),
                        &key.expanded,
                    ))?;
                    Ok(MlDsaPublicKey {
                        algorithm: self.algorithm,
                        inner: PublicKeyInner::MlDsa44(Box::new(pub_key.assume_init())),
                    })
                }
                PrivateKeyInner::MlDsa65(key) => {
                    let mut pub_key: MaybeUninit<ffi::MLDSA65_public_key> = MaybeUninit::zeroed();
                    cvt(ffi::MLDSA65_public_from_private(
                        pub_key.as_mut_ptr(),
                        &key.expanded,
                    ))?;
                    Ok(MlDsaPublicKey {
                        algorithm: self.algorithm,
                        inner: PublicKeyInner::MlDsa65(Box::new(pub_key.assume_init())),
                    })
                }
                PrivateKeyInner::MlDsa87(key) => {
                    let mut pub_key: MaybeUninit<ffi::MLDSA87_public_key> = MaybeUninit::zeroed();
                    cvt(ffi::MLDSA87_public_from_private(
                        pub_key.as_mut_ptr(),
                        &key.expanded,
                    ))?;
                    Ok(MlDsaPublicKey {
                        algorithm: self.algorithm,
                        inner: PublicKeyInner::MlDsa87(Box::new(pub_key.assume_init())),
                    })
                }
            }
        }
    }

    /// Signs `msg` and returns the signature bytes.
    ///
    /// # Errors
    ///
    /// Native randomized signature generation fails.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            ffi::init();
            match &self.inner {
                PrivateKeyInner::MlDsa44(key) => {
                    let mut sig = vec![0u8; ffi::MLDSA44_SIGNATURE_BYTES as usize];
                    cvt(ffi::MLDSA44_sign(
                        sig.as_mut_ptr(),
                        &key.expanded,
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    ))?;
                    Ok(sig)
                }
                PrivateKeyInner::MlDsa65(key) => {
                    let mut sig = vec![0u8; ffi::MLDSA65_SIGNATURE_BYTES as usize];
                    cvt(ffi::MLDSA65_sign(
                        sig.as_mut_ptr(),
                        &key.expanded,
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    ))?;
                    Ok(sig)
                }
                PrivateKeyInner::MlDsa87(key) => {
                    let mut sig = vec![0u8; ffi::MLDSA87_SIGNATURE_BYTES as usize];
                    cvt(ffi::MLDSA87_sign(
                        sig.as_mut_ptr(),
                        &key.expanded,
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    ))?;
                    Ok(sig)
                }
            }
        }
    }
}

impl MlDsaPublicKey {
    /// Parses a public key from its serialized form.
    ///
    /// # Errors
    ///
    /// The wire representation has an invalid length or malformed encoding.
    pub fn from_slice(
        algorithm: Algorithm,
        serialized_public_key: &[u8],
    ) -> Result<Self, ErrorStack> {
        ffi::init();

        if serialized_public_key.len() != algorithm.public_key_bytes() {
            return Err(ErrorStack::internal_error_str("invalid public key length"));
        }
        let mut cbs = cbs_init(serialized_public_key);

        unsafe {
            match algorithm {
                Algorithm::MlDsa44 => {
                    let mut key: MaybeUninit<ffi::MLDSA44_public_key> = MaybeUninit::zeroed();
                    cvt(ffi::MLDSA44_parse_public_key(
                        key.as_mut_ptr(),
                        &raw mut cbs,
                    ))?;
                    if cbs.len != 0 {
                        return Err(ErrorStack::internal_error_str(
                            "trailing bytes after ML-DSA-44 public key",
                        ));
                    }
                    Ok(Self {
                        algorithm,
                        inner: PublicKeyInner::MlDsa44(Box::new(key.assume_init())),
                    })
                }
                Algorithm::MlDsa65 => {
                    let mut key: MaybeUninit<ffi::MLDSA65_public_key> = MaybeUninit::zeroed();
                    cvt(ffi::MLDSA65_parse_public_key(
                        key.as_mut_ptr(),
                        &raw mut cbs,
                    ))?;
                    if cbs.len != 0 {
                        return Err(ErrorStack::internal_error_str(
                            "trailing bytes after ML-DSA-65 public key",
                        ));
                    }
                    Ok(Self {
                        algorithm,
                        inner: PublicKeyInner::MlDsa65(Box::new(key.assume_init())),
                    })
                }
                Algorithm::MlDsa87 => {
                    let mut key: MaybeUninit<ffi::MLDSA87_public_key> = MaybeUninit::zeroed();
                    cvt(ffi::MLDSA87_parse_public_key(
                        key.as_mut_ptr(),
                        &raw mut cbs,
                    ))?;
                    if cbs.len != 0 {
                        return Err(ErrorStack::internal_error_str(
                            "trailing bytes after ML-DSA-87 public key",
                        ));
                    }
                    Ok(Self {
                        algorithm,
                        inner: PublicKeyInner::MlDsa87(Box::new(key.assume_init())),
                    })
                }
            }
        }
    }

    /// Returns the algorithm for this key.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Serializes the public key to its fixed-length wire representation.
    ///
    /// # Errors
    ///
    /// Returns an error if native encoding or its length validation fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ErrorStack> {
        ffi::init();
        let mut bytes = vec![0u8; self.algorithm.public_key_bytes()];
        let mut cbb: MaybeUninit<ffi::CBB> = MaybeUninit::zeroed();
        // SAFETY: the fixed output allocation remains exclusively writable;
        // native sets up the builder in the initialized temporary.
        unsafe {
            cvt(ffi::CBB_init_fixed(
                cbb.as_mut_ptr(),
                bytes.as_mut_ptr(),
                bytes.len(),
            ))?
        };
        // SAFETY: every variant owns a live matching native public key. The
        // builder is initialized and exclusively borrowed until cleanup.
        let result = unsafe {
            match &self.inner {
                PublicKeyInner::MlDsa44(key) => {
                    ffi::MLDSA44_marshal_public_key(cbb.as_mut_ptr(), key.as_ref())
                }
                PublicKeyInner::MlDsa65(key) => {
                    ffi::MLDSA65_marshal_public_key(cbb.as_mut_ptr(), key.as_ref())
                }
                PublicKeyInner::MlDsa87(key) => {
                    ffi::MLDSA87_marshal_public_key(cbb.as_mut_ptr(), key.as_ref())
                }
            }
        };
        // SAFETY: CBB was initialized. Flush and capture the written size,
        // then unconditionally release its internal state before errors escape.
        let (flushed, written) = unsafe {
            let flushed = if result == 1 {
                ffi::CBB_flush(cbb.as_mut_ptr())
            } else {
                0
            };
            let written = if flushed == 1 {
                ffi::CBB_len(cbb.as_ptr())
            } else {
                0
            };
            ffi::CBB_cleanup(cbb.as_mut_ptr());
            (flushed, written)
        };
        cvt(result)?;
        cvt(flushed)?;
        if written != bytes.len() {
            return Err(ErrorStack::internal_error_str(
                "invalid encoded ML-DSA public key length",
            ));
        }
        Ok(bytes)
    }

    /// Verifies `signature` over `msg` using this public key.
    ///
    /// # Errors
    ///
    /// The signature or context is invalid or the native verification fails.
    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            ffi::init();
            match &self.inner {
                PublicKeyInner::MlDsa44(key) => {
                    cvt(ffi::MLDSA44_verify(
                        key.as_ref(),
                        signature.as_ptr(),
                        signature.len(),
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    ))?;
                }
                PublicKeyInner::MlDsa65(key) => {
                    cvt(ffi::MLDSA65_verify(
                        key.as_ref(),
                        signature.as_ptr(),
                        signature.len(),
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    ))?;
                }
                PublicKeyInner::MlDsa87(key) => {
                    cvt(ffi::MLDSA87_verify(
                        key.as_ref(),
                        signature.as_ptr(),
                        signature.len(),
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    ))?;
                }
            }
            Ok(())
        }
    }
}

impl fmt::Debug for MlDsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaPrivateKey")
            .field("algorithm", &self.algorithm)
            .field("seed", &"[redacted]")
            .finish()
    }
}

impl fmt::Debug for MlDsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaPublicKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! mldsa_tests {
        ($name:ident, $alg:expr) => {
            mod $name {
                use super::*;

                #[test]
                fn clone_retains_expanded_private_key_without_regeneration() {
                    let (pk, sk) = MlDsaPrivateKey::generate($alg).unwrap();
                    let copy = sk.clone();
                    match (&sk.inner, &copy.inner) {
                        (PrivateKeyInner::MlDsa44(a), PrivateKeyInner::MlDsa44(b)) => {
                            assert!(Arc::ptr_eq(a, b))
                        }
                        (PrivateKeyInner::MlDsa65(a), PrivateKeyInner::MlDsa65(b)) => {
                            assert!(Arc::ptr_eq(a, b))
                        }
                        (PrivateKeyInner::MlDsa87(a), PrivateKeyInner::MlDsa87(b)) => {
                            assert!(Arc::ptr_eq(a, b))
                        }
                        _ => panic!("mismatched parameter set"),
                    }
                    drop(sk);
                    assert!(pk
                        .verify(b"after drop", &copy.sign(b"after drop").unwrap())
                        .is_ok());
                }

                #[test]
                fn sign_and_verify() {
                    let (pk, sk) = MlDsaPrivateKey::generate($alg).unwrap();
                    let msg = b"test message";
                    let sig1 = sk.sign(msg).unwrap();
                    let sig2 = sk.clone().sign(msg).unwrap();
                    assert_eq!(sig1.len(), $alg.signature_bytes());
                    assert!(pk.verify(msg, &sig1).is_ok());
                    assert!(pk.verify(msg, &sig2).is_ok());
                    assert!(pk.clone().verify(msg, &sig1).is_ok());
                }

                #[test]
                fn bad_signature_fails() {
                    let (pk, sk) = MlDsaPrivateKey::generate($alg).unwrap();
                    let msg = b"test message";
                    let mut sig = sk.sign(msg).unwrap();
                    sig[5] ^= 1;
                    assert!(pk.verify(msg, &sig).is_err());
                }

                #[test]
                fn wrong_message_fails() {
                    let (pk, sk) = MlDsaPrivateKey::generate($alg).unwrap();
                    let sig = sk.sign(b"correct").unwrap();
                    assert!(pk.verify(b"wrong", &sig).is_err());
                }

                #[test]
                fn seed_roundtrip() {
                    let (pk, sk) = MlDsaPrivateKey::generate($alg).unwrap();
                    let sk2 = MlDsaPrivateKey::from_seed($alg, sk.seed_bytes()).unwrap();
                    let msg = b"seed roundtrip";
                    let sig1 = sk2.sign(msg).unwrap();
                    let sig2 = sk2.clone().sign(msg).unwrap();
                    assert!(pk.verify(msg, &sig1).is_ok());
                    assert!(pk.verify(msg, &sig2).is_ok());
                }

                #[test]
                fn public_key_roundtrip() {
                    let (pk, sk) = MlDsaPrivateKey::generate($alg).unwrap();
                    let bytes = pk.to_bytes().unwrap();
                    assert_eq!(bytes.len(), $alg.public_key_bytes());
                    let pk2 = MlDsaPublicKey::from_slice($alg, &bytes).unwrap();
                    assert_eq!(pk2.to_bytes().unwrap(), bytes);
                    let msg = b"public key roundtrip";
                    let sig = sk.sign(msg).unwrap();
                    assert!(pk2.verify(msg, &sig).is_ok());
                }

                #[test]
                fn public_from_private() {
                    let (pk, sk) = MlDsaPrivateKey::generate($alg).unwrap();
                    let derived = sk.public_key().unwrap();
                    assert_eq!(derived.algorithm(), $alg);
                    assert_eq!(derived.to_bytes().unwrap(), pk.to_bytes().unwrap());
                }

                #[test]
                fn debug_redacts_seed() {
                    let (_, sk) = MlDsaPrivateKey::generate($alg).unwrap();
                    let dbg = format!("{:?}", sk);
                    assert!(dbg.contains("redacted"));
                    assert!(!dbg.contains(&format!("{:?}", sk.seed_bytes())));
                }
            }
        };
    }

    mldsa_tests!(mldsa44, Algorithm::MlDsa44);
    mldsa_tests!(mldsa65, Algorithm::MlDsa65);
    mldsa_tests!(mldsa87, Algorithm::MlDsa87);
}
