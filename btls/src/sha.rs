//! The SHA family of hashes.
//!
//! SHA, or Secure Hash Algorithms, are a family of cryptographic hashing algorithms published by
//! the National Institute of Standards and Technology (NIST).  Hash algorithms such as those in
//! the SHA family are used to map data of an arbitrary size to a fixed-size string of bytes.
//! As cryptographic hashing algorithms, these mappings have the property of being irreversable.
//! This property makes hash algorithms like these excellent for uses such as verifying the
//! contents of a file- if you know the hash you expect beforehand, then you can verify that the
//! data you have is correct if it hashes to the same value.
//!
//! # Examples
//!
//! When dealing with data that becomes available in chunks, such as while buffering data from IO,
//! you can create a hasher that you can repeatedly update to add bytes to.
//!
//! ```rust
//! extern crate hex;
//!
//! use btls::sha;
//!
//! fn main() {
//!     let mut hasher = sha::Sha256::new();
//!
//!     hasher.update(b"Hello, ");
//!     hasher.update(b"world");
//!
//!     let hash = hasher.finish();
//!     println!("Hashed \"Hello, world\" to {}", hex::encode(hash));
//! }
//! ```
//!
//! On the other hand, if you already have access to all of the data you woud like to hash, you
//! may prefer to use the slightly simpler method of simply calling the hash function corresponding
//! to the algorithm you want to use.
//!
//! ```rust
//! extern crate hex;
//!
//! use btls::sha::sha256;
//!
//! fn main() {
//!     let hash = sha256(b"your data or message");
//!     println!("Hash = {}", hex::encode(hash));
//! }
//! ```
use crate::ffi;
use libc::c_void;
use std::mem::MaybeUninit;

// Every invocation pairs a context with the native functions for exactly
// one algorithm. The storage mode records whether the native constructor
// initializes every context field; the SHA512 family does not.
macro_rules! define_sha {
    (
        $(#[$function_doc:meta])*
        $function:ident,
        $(#[$struct_doc:meta])*
        $hasher:ident, $context:ident, $size:literal,
        $storage:ident, $native_hash:ident, $init:ident, $update:ident, $finalize:ident
    ) => {
        $(#[$function_doc])*
        #[inline]
        #[must_use = "The computed digest is the result of hashing the input."]
        pub fn $function(data: &[u8]) -> [u8; $size] {
            let mut digest = MaybeUninit::<[u8; $size]>::uninit();
            // SAFETY: The input is readable for data.len() bytes. The paired
            // native function writes the entire fixed-size digest.
            unsafe {
                ffi::$native_hash(data.as_ptr(), data.len(), digest.as_mut_ptr().cast());
                digest.assume_init()
            }
        }

        $(#[$struct_doc])*
        #[derive(Clone)]
        pub struct $hasher(ffi::$context);

        impl Default for $hasher {
            #[inline]
            fn default() -> Self {
                Self::new()
            }
        }

        impl $hasher {
            /// Creates a new hasher.
            #[inline]
            #[must_use = "The returned hasher owns the initialized state for subsequent updates."]
            pub fn new() -> Self {
                let mut ctx = MaybeUninit::<ffi::$context>::$storage();
                // SAFETY: The selected storage mode and native constructor
                // together initialize every field. SHA1/224/256 clear the
                // complete integer-only context; the SHA512 family sets its
                // chaining state and counters, leaving the pre-zeroed buffer.
                unsafe {
                    ffi::$init(ctx.as_mut_ptr());
                    Self(ctx.assume_init())
                }
            }

            /// Feeds more data into the hasher.
            #[inline]
            pub fn update(&mut self, buf: &[u8]) {
                // SAFETY: The context is initialized and uniquely borrowed.
                // The native update reads at most buf.len() bytes.
                unsafe {
                    ffi::$update(&mut self.0, buf.as_ptr().cast::<c_void>(), buf.len());
                }
            }

            /// Returns the hash of the data.
            #[inline]
            #[must_use = "The computed digest is the result of consuming this hasher."]
            pub fn finish(mut self) -> [u8; $size] {
                let mut digest = MaybeUninit::<[u8; $size]>::uninit();
                // SAFETY: The private context was initialized by its matching
                // constructor; finalization writes the complete digest.
                unsafe {
                    ffi::$finalize(digest.as_mut_ptr().cast(), &mut self.0);
                    digest.assume_init()
                }
            }
        }
    };
}

define_sha!(
    /// Computes the SHA-1 hash of some data.
    ///
    /// # Warning
    /// SHA-1 is insecure and should not be used except for existing systems.
    sha1,
    /// Incremental SHA-1 hasher.
    ///
    /// # Warning
    /// SHA-1 is insecure and should not be used except for existing systems.
    Sha1,
    SHA_CTX,
    20,
    uninit,
    SHA1,
    SHA1_Init,
    SHA1_Update,
    SHA1_Final
);
define_sha!(
    /// Computes the SHA-224 hash of some data.
    sha224,
    /// Incremental SHA-224 hasher.
    Sha224,
    SHA256_CTX,
    28,
    uninit,
    SHA224,
    SHA224_Init,
    SHA224_Update,
    SHA224_Final
);
define_sha!(
    /// Computes the SHA-256 hash of some data.
    sha256,
    /// Incremental SHA-256 hasher.
    Sha256,
    SHA256_CTX,
    32,
    uninit,
    SHA256,
    SHA256_Init,
    SHA256_Update,
    SHA256_Final
);
define_sha!(
    /// Computes the SHA-384 hash of some data.
    sha384,
    /// Incremental SHA-384 hasher.
    Sha384,
    SHA512_CTX,
    48,
    zeroed,
    SHA384,
    SHA384_Init,
    SHA384_Update,
    SHA384_Final
);
define_sha!(
    /// Computes the SHA-512 hash of some data.
    sha512,
    /// Incremental SHA-512 hasher.
    Sha512,
    SHA512_CTX,
    64,
    zeroed,
    SHA512,
    SHA512_Init,
    SHA512_Update,
    SHA512_Final
);
define_sha!(
    /// Computes the SHA-512/256 hash of some data.
    sha512_256,
    /// Incremental SHA-512/256 hasher.
    Sha512_256,
    SHA512_CTX,
    32,
    zeroed,
    SHA512_256,
    SHA512_256_Init,
    SHA512_256_Update,
    SHA512_256_Final
);

#[cfg(test)]
mod test {
    use hex;

    use super::*;

    #[test]
    fn wide_hash_contexts_have_initialized_block_storage() {
        let sha384 = Sha384::new();
        let sha512 = Sha512::new();
        let sha512_256 = Sha512_256::new();
        assert_eq!(sha384.0.p, [0; 128]);
        assert_eq!(sha512.0.p, [0; 128]);
        assert_eq!(sha512_256.0.p, [0; 128]);
    }

    #[test]
    fn wide_hash_clones_are_independent_at_block_boundaries() {
        macro_rules! check {
            ($hasher:ty, $one_shot:ident) => {{
                for len in [0, 1, 127, 128, 129, 255, 256] {
                    let prefix = vec![42; len];
                    let mut original = <$hasher>::new();
                    original.update(&prefix);
                    let mut clone = original.clone();
                    clone.update(b"second");
                    original.update(b"first");
                    assert_eq!(
                        clone.finish(),
                        $one_shot(&[prefix.as_slice(), b"second"].concat())
                    );
                    assert_eq!(
                        original.finish(),
                        $one_shot(&[prefix.as_slice(), b"first"].concat())
                    );
                }
            }};
        }
        check!(Sha384, sha384);
        check!(Sha512, sha512);
        check!(Sha512_256, sha512_256);
    }

    #[test]
    fn standalone_1() {
        let data = b"abc";
        let expected = "a9993e364706816aba3e25717850c26c9cd0d89d";

        assert_eq!(hex::encode(sha1(data)), expected);
    }

    #[test]
    fn struct_1() {
        let expected = "a9993e364706816aba3e25717850c26c9cd0d89d";

        let mut hasher = Sha1::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hex::encode(hasher.finish()), expected);
    }

    #[test]
    fn cloning_allows_incremental_hashing() {
        let expected = "a9993e364706816aba3e25717850c26c9cd0d89d";

        let mut hasher = Sha1::new();
        hasher.update(b"a");

        let mut incr_hasher = hasher.clone();
        incr_hasher.update(b"bc");

        assert_eq!(hex::encode(incr_hasher.finish()), expected);
        assert_ne!(hex::encode(hasher.finish()), expected);
    }

    #[test]
    fn standalone_224() {
        let data = b"abc";
        let expected = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";

        assert_eq!(hex::encode(sha224(data)), expected);
    }

    #[test]
    fn struct_224() {
        let expected = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";

        let mut hasher = Sha224::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hex::encode(hasher.finish()), expected);
    }

    #[test]
    fn standalone_256() {
        let data = b"abc";
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        assert_eq!(hex::encode(sha256(data)), expected);
    }

    #[test]
    fn struct_256() {
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        let mut hasher = Sha256::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hex::encode(hasher.finish()), expected);
    }

    #[test]
    fn standalone_384() {
        let data = b"abc";
        let expected =
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e\
             7cc2358baeca134c825a7";

        assert_eq!(hex::encode(&sha384(data)[..]), expected);
    }

    #[test]
    fn struct_384() {
        let expected =
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e\
             7cc2358baeca134c825a7";

        let mut hasher = Sha384::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hex::encode(&hasher.finish()[..]), expected);
    }

    #[test]
    fn standalone_512() {
        let data = b"abc";
        let expected =
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274\
             fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

        assert_eq!(hex::encode(&sha512(data)[..]), expected);
    }

    #[test]
    fn struct_512() {
        let expected =
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274\
             fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

        let mut hasher = Sha512::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hex::encode(&hasher.finish()[..]), expected);
    }

    #[test]
    fn standalone_512_256() {
        let data = b"abc";
        let expected = "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23";

        assert_eq!(hex::encode(&sha512_256(data)[..]), expected);
    }

    #[test]
    fn struct_512_256() {
        let expected = "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23";

        let mut hasher = Sha512_256::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hex::encode(&hasher.finish()[..]), expected);
    }
}
