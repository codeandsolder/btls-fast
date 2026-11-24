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

use std::ffi::c_int;
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
pub struct MlDsaPublicKey(PublicKeyInner);

#[derive(Clone)]
enum PublicKeyInner {
    MlDsa44(Box<ffi::MLDSA44_public_key>),
    MlDsa65(Box<ffi::MLDSA65_public_key>),
    MlDsa87(Box<ffi::MLDSA87_public_key>),
}

/// A shared ML-DSA private key. Clones reuse the immutable expanded key.
#[derive(Clone)]
pub struct MlDsaPrivateKey(PrivateKeyInner);

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
    const fn new(seed: MlDsaPrivateKeySeed) -> Self {
        Self {
            seed,
            expanded: MaybeUninit::zeroed(),
        }
    }

    fn generate<const PUBLIC_BYTES: usize>(
        native: unsafe extern "C" fn(*mut u8, *mut u8, *mut T) -> c_int,
    ) -> Result<([u8; PUBLIC_BYTES], Arc<SecretMaterial<T>>), ErrorStack> {
        let mut public = [0; PUBLIC_BYTES];
        let mut secret = Self::new([0; PRIVATE_KEY_SEED_BYTES]);
        // SAFETY: the public buffer and seed have their native fixed widths;
        // the expanded out-parameter is zeroed and uniquely writable.
        cvt(unsafe {
            native(
                public.as_mut_ptr(),
                secret.seed.as_mut_ptr(),
                secret.expanded.as_mut_ptr(),
            )
        })?;
        Ok((public, secret.into_shared()))
    }

    fn from_seed(
        seed: &MlDsaPrivateKeySeed,
        native: unsafe extern "C" fn(*mut T, *const u8, usize) -> c_int,
    ) -> Result<Arc<SecretMaterial<T>>, ErrorStack> {
        let mut secret = Self::new(*seed);
        // SAFETY: the native input is exactly MLDSA_SEED_BYTES, and the
        // zeroed expanded output is exclusively writable.
        cvt(unsafe {
            native(
                secret.expanded.as_mut_ptr(),
                secret.seed.as_ptr(),
                secret.seed.len(),
            )
        })?;
        Ok(secret.into_shared())
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

// The native ML-DSA parameter sets deliberately use different opaque key types
// and entrypoints. Describe each set once, and generate the same checked
// operations without erasing native types or moving secrets out of their owner.
macro_rules! define_mldsa_suite {
    (
        $suite:ident, $variant:ident, $label:literal, $private:ty, $public:ty,
        $public_bytes:expr, $signature_bytes:expr,
        $generate:path, $seed_fn:path, $derive:path, $sign:path,
        $parse:path, $marshal:path, $verify:path
    ) => {
        struct $suite;

        impl $suite {
            fn generate() -> Result<(MlDsaPublicKey, MlDsaPrivateKey), ErrorStack> {
                let (bytes, key) = SecretBuilder::<$private>::generate::<$public_bytes>($generate)?;
                let public = MlDsaPublicKey::from_slice(Algorithm::$variant, &bytes)?;
                Ok((public, MlDsaPrivateKey(PrivateKeyInner::$variant(key))))
            }

            fn from_seed(seed: &MlDsaPrivateKeySeed) -> Result<PrivateKeyInner, ErrorStack> {
                Ok(PrivateKeyInner::$variant(
                    SecretBuilder::<$private>::from_seed(seed, $seed_fn)?,
                ))
            }

            fn public_from_private(
                secret: &SecretMaterial<$private>,
            ) -> Result<PublicKeyInner, ErrorStack> {
                let mut public = MaybeUninit::<$public>::zeroed();
                // SAFETY: The input is live and immutable. The zeroed output
                // matches the native public key type for this parameter set.
                cvt(unsafe { $derive(public.as_mut_ptr(), &raw const secret.expanded) })?;
                // SAFETY: Success initializes the whole opaque native public key.
                let public = unsafe { public.assume_init() };
                Ok(PublicKeyInner::$variant(Box::new(public)))
            }

            fn sign(secret: &SecretMaterial<$private>, msg: &[u8]) -> Result<Vec<u8>, ErrorStack> {
                let mut sig = vec![0u8; $signature_bytes];
                // SAFETY: The output has the native signature size; the expanded
                // key is immutable and the message is borrowed for this call.
                cvt(unsafe {
                    $sign(
                        sig.as_mut_ptr(),
                        &raw const secret.expanded,
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    )
                })?;
                Ok(sig)
            }

            fn parse(cbs: &mut ffi::CBS) -> Result<PublicKeyInner, ErrorStack> {
                let mut key = MaybeUninit::<$public>::zeroed();
                // SAFETY: The initialized CBS borrows the checked input slice,
                // and native writes the matching opaque public-key structure.
                cvt(unsafe { $parse(key.as_mut_ptr(), cbs) })?;
                if cbs.len != 0 {
                    return Err(ErrorStack::internal_error_str(concat!(
                        "trailing bytes after ",
                        $label,
                        " public key"
                    )));
                }
                // SAFETY: Native success wrote an initialized public key.
                let key = unsafe { key.assume_init() };
                Ok(PublicKeyInner::$variant(Box::new(key)))
            }

            /// # Safety
            /// `cbb` must point to a live, initialized native builder, and the
            /// borrowed key must remain valid until encoding completes.
            unsafe fn marshal(cbb: *mut ffi::CBB, key: &$public) -> c_int {
                // SAFETY: The caller guarantees the builder lifetime, and the
                // concrete type matches this parameter set's native encoder.
                unsafe { $marshal(cbb, key) }
            }

            fn verify(key: &$public, msg: &[u8], signature: &[u8]) -> Result<(), ErrorStack> {
                // SAFETY: The public key and borrowed byte slices are live and
                // this verifier matches their selected native parameter set.
                cvt(unsafe {
                    $verify(
                        key,
                        signature.as_ptr(),
                        signature.len(),
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    )
                })
            }
        }
    };
}

define_mldsa_suite!(
    MlDsa44Suite,
    MlDsa44,
    "ML-DSA-44",
    ffi::MLDSA44_private_key,
    ffi::MLDSA44_public_key,
    { ffi::MLDSA44_PUBLIC_KEY_BYTES as usize },
    ffi::MLDSA44_SIGNATURE_BYTES as usize,
    ffi::MLDSA44_generate_key,
    ffi::MLDSA44_private_key_from_seed,
    ffi::MLDSA44_public_from_private,
    ffi::MLDSA44_sign,
    ffi::MLDSA44_parse_public_key,
    ffi::MLDSA44_marshal_public_key,
    ffi::MLDSA44_verify
);
define_mldsa_suite!(
    MlDsa65Suite,
    MlDsa65,
    "ML-DSA-65",
    ffi::MLDSA65_private_key,
    ffi::MLDSA65_public_key,
    { ffi::MLDSA65_PUBLIC_KEY_BYTES as usize },
    ffi::MLDSA65_SIGNATURE_BYTES as usize,
    ffi::MLDSA65_generate_key,
    ffi::MLDSA65_private_key_from_seed,
    ffi::MLDSA65_public_from_private,
    ffi::MLDSA65_sign,
    ffi::MLDSA65_parse_public_key,
    ffi::MLDSA65_marshal_public_key,
    ffi::MLDSA65_verify
);
define_mldsa_suite!(
    MlDsa87Suite,
    MlDsa87,
    "ML-DSA-87",
    ffi::MLDSA87_private_key,
    ffi::MLDSA87_public_key,
    { ffi::MLDSA87_PUBLIC_KEY_BYTES as usize },
    ffi::MLDSA87_SIGNATURE_BYTES as usize,
    ffi::MLDSA87_generate_key,
    ffi::MLDSA87_private_key_from_seed,
    ffi::MLDSA87_public_from_private,
    ffi::MLDSA87_sign,
    ffi::MLDSA87_parse_public_key,
    ffi::MLDSA87_marshal_public_key,
    ffi::MLDSA87_verify
);

impl MlDsaPrivateKey {
    /// Generates a random ML-DSA key pair.
    ///
    /// Returns `(public_key, private_key)`.
    ///
    /// # Errors
    ///
    /// Native key generation or public-key reconstruction fails.
    pub fn generate(algorithm: Algorithm) -> Result<(MlDsaPublicKey, Self), ErrorStack> {
        ffi::init();
        match algorithm {
            Algorithm::MlDsa44 => MlDsa44Suite::generate(),
            Algorithm::MlDsa65 => MlDsa65Suite::generate(),
            Algorithm::MlDsa87 => MlDsa87Suite::generate(),
        }
    }

    /// Regenerates a private key from a seed value.
    ///
    /// # Errors
    ///
    /// The seed cannot be expanded or native allocation fails.
    pub fn from_seed(algorithm: Algorithm, seed: &MlDsaPrivateKeySeed) -> Result<Self, ErrorStack> {
        ffi::init();
        let inner = match algorithm {
            Algorithm::MlDsa44 => MlDsa44Suite::from_seed(seed)?,
            Algorithm::MlDsa65 => MlDsa65Suite::from_seed(seed)?,
            Algorithm::MlDsa87 => MlDsa87Suite::from_seed(seed)?,
        };
        Ok(Self(inner))
    }

    /// Returns the algorithm for this key.
    #[must_use = "Use the selected ML-DSA parameter set when encoding or validating the key."]
    pub const fn algorithm(&self) -> Algorithm {
        match &self.0 {
            PrivateKeyInner::MlDsa44(_) => Algorithm::MlDsa44,
            PrivateKeyInner::MlDsa65(_) => Algorithm::MlDsa65,
            PrivateKeyInner::MlDsa87(_) => Algorithm::MlDsa87,
        }
    }

    /// Returns the seed bytes for this private key.
    #[must_use = "Protect and persist the private seed only through the intended key export path."]
    pub fn seed_bytes(&self) -> &MlDsaPrivateKeySeed {
        match &self.0 {
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
        ffi::init();
        let inner = match &self.0 {
            PrivateKeyInner::MlDsa44(key) => MlDsa44Suite::public_from_private(key)?,
            PrivateKeyInner::MlDsa65(key) => MlDsa65Suite::public_from_private(key)?,
            PrivateKeyInner::MlDsa87(key) => MlDsa87Suite::public_from_private(key)?,
        };
        Ok(MlDsaPublicKey(inner))
    }

    /// Signs `msg` and returns the signature bytes.
    ///
    /// # Errors
    ///
    /// Native randomized signature generation fails.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        ffi::init();
        match &self.0 {
            PrivateKeyInner::MlDsa44(key) => MlDsa44Suite::sign(key, msg),
            PrivateKeyInner::MlDsa65(key) => MlDsa65Suite::sign(key, msg),
            PrivateKeyInner::MlDsa87(key) => MlDsa87Suite::sign(key, msg),
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

        let inner = match algorithm {
            Algorithm::MlDsa44 => MlDsa44Suite::parse(&mut cbs)?,
            Algorithm::MlDsa65 => MlDsa65Suite::parse(&mut cbs)?,
            Algorithm::MlDsa87 => MlDsa87Suite::parse(&mut cbs)?,
        };
        Ok(Self(inner))
    }

    /// Returns the algorithm for this key.
    #[must_use = "Use the selected ML-DSA parameter set when encoding or validating the key."]
    pub const fn algorithm(&self) -> Algorithm {
        match &self.0 {
            PublicKeyInner::MlDsa44(_) => Algorithm::MlDsa44,
            PublicKeyInner::MlDsa65(_) => Algorithm::MlDsa65,
            PublicKeyInner::MlDsa87(_) => Algorithm::MlDsa87,
        }
    }

    /// Serializes the public key to its fixed-length wire representation.
    ///
    /// # Errors
    ///
    /// Returns an error if native encoding or its length validation fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ErrorStack> {
        ffi::init();
        let mut bytes = vec![0u8; self.algorithm().public_key_bytes()];
        let mut cbb: MaybeUninit<ffi::CBB> = MaybeUninit::zeroed();
        // SAFETY: the fixed output allocation remains exclusively writable;
        // native sets up the builder in the initialized temporary.
        unsafe {
            cvt(ffi::CBB_init_fixed(
                cbb.as_mut_ptr(),
                bytes.as_mut_ptr(),
                bytes.len(),
            ))?;
        }
        // SAFETY: every variant owns a live matching native public key. The
        // builder is initialized and exclusively borrowed until cleanup.
        let result = unsafe {
            match &self.0 {
                PublicKeyInner::MlDsa44(key) => {
                    MlDsa44Suite::marshal(cbb.as_mut_ptr(), key.as_ref())
                }
                PublicKeyInner::MlDsa65(key) => {
                    MlDsa65Suite::marshal(cbb.as_mut_ptr(), key.as_ref())
                }
                PublicKeyInner::MlDsa87(key) => {
                    MlDsa87Suite::marshal(cbb.as_mut_ptr(), key.as_ref())
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
        ffi::init();
        match &self.0 {
            PublicKeyInner::MlDsa44(key) => MlDsa44Suite::verify(key, msg, signature),
            PublicKeyInner::MlDsa65(key) => MlDsa65Suite::verify(key, msg, signature),
            PublicKeyInner::MlDsa87(key) => MlDsa87Suite::verify(key, msg, signature),
        }
    }
}

impl fmt::Debug for MlDsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaPrivateKey")
            .field("algorithm", &self.algorithm())
            .field("inner", &"[redacted]")
            .finish()
    }
}

impl fmt::Debug for MlDsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaPublicKey")
            .field("algorithm", &self.algorithm())
            .field("inner", &"[opaque public key]")
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
                    match (&sk.0, &copy.0) {
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
                fn public_key_parsing_checks_exact_length() {
                    let (pk, _) = MlDsaPrivateKey::generate($alg).unwrap();
                    let bytes = pk.to_bytes().unwrap();
                    assert!(MlDsaPublicKey::from_slice($alg, &bytes[..bytes.len() - 1]).is_err());
                    let mut oversized = bytes;
                    oversized.push(0);
                    assert!(MlDsaPublicKey::from_slice($alg, &oversized).is_err());
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
