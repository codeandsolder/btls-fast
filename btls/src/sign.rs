//! Message signatures.
//!
//! The `Signer` allows for the computation of cryptographic signatures of
//! data given a private key. The `Verifier` can then be used with the
//! corresponding public key to verify the integrity and authenticity of that
//! data given the signature.
//!
//! # Examples
//!
//! Sign and verify data given an RSA keypair:
//!
//! ```rust
//! use btls::sign::{Signer, Verifier};
//! use btls::rsa::Rsa;
//! use btls::pkey::PKey;
//! use btls::hash::MessageDigest;
//!
//! // Generate a keypair
//! let keypair = Rsa::generate(2048).unwrap();
//! let keypair = PKey::from_rsa(keypair).unwrap();
//!
//! let data = b"hello, world!";
//! let data2 = b"hola, mundo!";
//!
//! // Sign the data
//! let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
//! signer.update(data).unwrap();
//! signer.update(data2).unwrap();
//! let signature = signer.sign_to_vec().unwrap();
//!
//! // Verify the data
//! let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
//! verifier.update(data).unwrap();
//! verifier.update(data2).unwrap();
//! assert!(verifier.verify(&signature).unwrap());
//! ```
use crate::ffi;
use foreign_types::ForeignTypeRef;
use libc::c_int;
use openssl_macros::corresponds;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::ptr;

use crate::error::ErrorStack;
use crate::hash::MessageDigest;
use crate::pkey::{HasPrivate, HasPublic, PKeyRef};
use crate::rsa::Padding;
use crate::{cvt, cvt_p};

use crate::ffi::{EVP_MD_CTX_free, EVP_MD_CTX_new};

/// Salt lengths that must be used with `set_rsa_pss_saltlen`.
pub struct RsaPssSaltlen(c_int);

impl RsaPssSaltlen {
    /// Returns the integer representation of `RsaPssSaltlen`.
    const fn as_raw(&self) -> c_int {
        self.0
    }

    /// Sets the salt length to the given value.
    #[must_use = "Use the returned salt-length setting when configuring RSA-PSS."]
    pub const fn custom(val: c_int) -> Self {
        Self(val)
    }

    /// The salt length is set to the digest length.
    /// Corresponds to the special value `-1`.
    pub const DIGEST_LENGTH: Self = Self(-1);
    /// The salt length is set to the maximum permissible value.
    /// Corresponds to the special value `-2`.
    pub const MAXIMUM_LENGTH: Self = Self(-2);
}

// The two operation types differ only in native initialization/update and
// their key capability bound. Both own a native digest context and borrow
// its associated key context.
macro_rules! signature_operation {
    ($(#[$doc:meta])* $kind:ident, $bound:ident, $init:ident, $update:ident) => {
        $(#[$doc])*
        pub struct $kind<'a> {
            md_ctx: *mut ffi::EVP_MD_CTX,
            pctx: *mut ffi::EVP_PKEY_CTX,
            _p: PhantomData<&'a ()>,
        }

        // SAFETY: A native operation context is not thread-affine. Moving the
        // unique Rust owner between threads preserves the key's borrowed lifetime.
        unsafe impl Send for $kind<'_> {}

        impl Drop for $kind<'_> {
            fn drop(&mut self) {
                // SAFETY: This value owns md_ctx; pctx is released by the same call.
                unsafe { EVP_MD_CTX_free(self.md_ctx) };
            }
        }

        impl<'a> $kind<'a> {
            /// Creates a new signature operation.
            ///
            /// This cannot be used with Ed25519 or Ed448 keys. Please refer to
            /// `new_without_digest`.
            ///
            /// # Errors
            ///
            /// The native context cannot be allocated or the digest/key combination is unsupported.
            #[corresponds($init)]
            pub fn new<T>(type_: MessageDigest, pkey: &'a PKeyRef<T>) -> Result<Self, ErrorStack>
            where
                T: $bound,
            {
                Self::new_intern(Some(type_), pkey)
            }

            /// Creates a new signature operation without a digest.
            ///
            /// Use this constructor for Ed25519 and other algorithms without a prehash.
            ///
            /// # Errors
            ///
            /// The native context cannot be allocated or this key requires an explicit digest.
            #[corresponds($init)]
            pub fn new_without_digest<T>(pkey: &'a PKeyRef<T>) -> Result<Self, ErrorStack>
            where
                T: $bound,
            {
                Self::new_intern(None, pkey)
            }

            fn new_intern<T>(type_: Option<MessageDigest>, pkey: &'a PKeyRef<T>) -> Result<Self, ErrorStack>
            where
                T: $bound,
            {
                ffi::init();
                // SAFETY: EVP_MD_CTX_new allocates a fresh native context.
                let ctx = unsafe { cvt_p(EVP_MD_CTX_new())? };
                let mut operation = Self {
                    md_ctx: ctx,
                    pctx: ptr::null_mut(),
                    _p: PhantomData,
                };
                // SAFETY: operation owns ctx and borrows a live key for 'a.
                // The result stores a borrowed pkey context owned by the digest context.
                unsafe {
                    cvt(ffi::$init(
                        ctx,
                        &raw mut operation.pctx,
                        type_.map_or(ptr::null(), MessageDigest::as_ptr),
                        ptr::null_mut(),
                        pkey.as_ptr(),
                    ))?;
                }
                if operation.pctx.is_null() {
                    return Err(ErrorStack::internal_error_str("native signature context missing"));
                }
                Ok(operation)
            }

            /// Returns the RSA padding mode in use.
            ///
            /// This is only useful for RSA keys.
            ///
            /// # Errors
            ///
            /// The key type does not support querying RSA padding.
            #[corresponds(EVP_PKEY_CTX_get_rsa_padding)]
            pub fn rsa_padding(&self) -> Result<Padding, ErrorStack> {
                // SAFETY: The live context is initialized by the matching native constructor;
                // pad is writable for the duration of the query.
                unsafe {
                    let mut pad = 0;
                    cvt(ffi::EVP_PKEY_CTX_get_rsa_padding(self.pctx, &raw mut pad))
                        .map(|_| Padding::from_raw(pad))
                }
            }

            /// Sets the RSA padding mode.
            ///
            /// This is only useful for RSA keys.
            ///
            /// # Errors
            ///
            /// The key type or requested padding mode is unsupported.
            #[corresponds(EVP_PKEY_CTX_set_rsa_padding)]
            pub fn set_rsa_padding(&mut self, padding: Padding) -> Result<(), ErrorStack> {
                // SAFETY: The signature context is initialized and exclusively borrowed.
                unsafe {
                    cvt(ffi::EVP_PKEY_CTX_set_rsa_padding(
                        self.pctx,
                        padding.as_raw(),
                    ))
                }
            }

            /// Sets the RSA PSS salt length.
            ///
            /// This is only useful for RSA keys.
            ///
            /// # Errors
            ///
            /// The key type, padding mode or salt length is unsupported.
            #[corresponds(EVP_PKEY_CTX_set_rsa_pss_saltlen)]
            pub fn set_rsa_pss_saltlen(&mut self, len: RsaPssSaltlen) -> Result<(), ErrorStack> {
                // SAFETY: The signature context is initialized and exclusively borrowed.
                unsafe {
                    cvt(ffi::EVP_PKEY_CTX_set_rsa_pss_saltlen(
                        self.pctx,
                        len.as_raw(),
                    ))
                }
            }

            /// Sets the RSA MGF1 algorithm.
            ///
            /// This is only useful for RSA keys.
            ///
            /// # Errors
            ///
            /// The MGF1 digest or key configuration is unsupported.
            #[corresponds(EVP_PKEY_CTX_set_rsa_mgf1_md)]
            pub fn set_rsa_mgf1_md(&mut self, md: MessageDigest) -> Result<(), ErrorStack> {
                // SAFETY: The signature context is initialized and exclusively borrowed.
                unsafe {
                    cvt(ffi::EVP_PKEY_CTX_set_rsa_mgf1_md(
                        self.pctx,
                        md.as_ptr().cast_mut(),
                    ))
                }
            }

            /// Feeds more data into the signature operation.
            ///
            /// Please note that PureEdDSA (Ed25519 and Ed448 keys) do not support streaming.
            /// Use the one-shot operation instead.
            ///
            /// # Errors
            ///
            /// The algorithm does not support streaming or native digest processing fails.
            #[corresponds($update)]
            pub fn update(&mut self, buf: &[u8]) -> Result<(), ErrorStack> {
                // SAFETY: The live context is exclusively borrowed and buf is readable
                // for buf.len() bytes throughout the native call.
                unsafe {
                    cvt(ffi::$update(
                        self.md_ctx,
                        buf.as_ptr().cast(),
                        buf.len(),
                    ))
                }
            }
        }

        impl Write for $kind<'_> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.update(buf)?;
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
    };
}

signature_operation!(
    /// A type which computes cryptographic signatures of data.
    Signer,
    HasPrivate,
    EVP_DigestSignInit,
    EVP_DigestSignUpdate
);
signature_operation!(
    /// A type which verifies cryptographic signatures of data.
    Verifier,
    HasPublic,
    EVP_DigestVerifyInit,
    EVP_DigestVerifyUpdate
);

impl Signer<'_> {
    /// Computes an upper bound on the signature length.
    ///
    /// The actual signature may be shorter than this value. Check the return value of
    /// `sign` to get the exact length.
    #[corresponds(EVP_DigestSignFinal)]
    pub fn signature_capacity(&mut self) -> Result<usize, ErrorStack> {
        unsafe {
            let mut len = 0;
            cvt(ffi::EVP_DigestSign(
                self.md_ctx,
                ptr::null_mut(),
                &raw mut len,
                ptr::null(),
                0,
            ))?;
            Ok(len)
        }
    }

    /// Writes the signature into the provided buffer, returning the number of bytes written.
    ///
    /// This method will fail if the buffer is not large enough for the signature. Use `signature_capacity`
    /// method to get an upper bound on the required size.
    #[corresponds(EVP_DigestSignFinal)]
    pub fn sign(&mut self, buf: &mut [u8]) -> Result<usize, ErrorStack> {
        unsafe {
            let mut len = buf.len();
            cvt(ffi::EVP_DigestSignFinal(
                self.md_ctx,
                buf.as_mut_ptr().cast(),
                &raw mut len,
            ))?;
            Ok(len)
        }
    }

    /// Returns the signature.
    ///
    /// This is a simple convenience wrapper over `signature_capacity` and `sign`.
    pub fn sign_to_vec(&mut self) -> Result<Vec<u8>, ErrorStack> {
        let mut buf = vec![0; self.signature_capacity()?];
        let len = self.sign(&mut buf)?;
        // The advertised length is not always equal to the real length for things like DSA
        buf.truncate(len);
        Ok(buf)
    }

    /// Signs the data in data_buf and writes the signature into the buffer sig_buf, returning the
    /// number of bytes written.
    ///
    /// For PureEdDSA (Ed25519 and Ed448 keys) this is the only way to sign data.
    ///
    /// This method will fail if the buffer is not large enough for the signature. Use `signature_capacity`
    /// method to get an upper bound on the required size.
    #[corresponds(EVP_DigestSign)]
    pub fn sign_oneshot(
        &mut self,
        sig_buf: &mut [u8],
        data_buf: &[u8],
    ) -> Result<usize, ErrorStack> {
        unsafe {
            let mut sig_len = sig_buf.len();
            cvt(ffi::EVP_DigestSign(
                self.md_ctx,
                sig_buf.as_mut_ptr(),
                &raw mut sig_len,
                data_buf.as_ptr(),
                data_buf.len(),
            ))?;
            Ok(sig_len)
        }
    }

    /// Returns the signature.
    ///
    /// This is a simple convenience wrapper over `signature_capacity` and `sign_oneshot`.
    pub fn sign_oneshot_to_vec(&mut self, data_buf: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let mut sig_buf = vec![0; self.signature_capacity()?];
        let len = self.sign_oneshot(&mut sig_buf, data_buf)?;
        // The advertised length is not always equal to the real length for things like DSA
        sig_buf.truncate(len);
        Ok(sig_buf)
    }
}

impl Verifier<'_> {
    /// Determines if the data fed into the `Verifier` matches the provided signature.
    #[corresponds(EVP_DigestVerifyFinal)]
    pub fn verify(&mut self, signature: &[u8]) -> Result<bool, ErrorStack> {
        unsafe {
            let r = ffi::EVP_DigestVerifyFinal(self.md_ctx, signature.as_ptr(), signature.len());
            match r {
                1 => Ok(true),
                0 => {
                    ErrorStack::clear(); // discard error stack
                    Ok(false)
                }
                _ => Err(ErrorStack::get()),
            }
        }
    }

    /// Determines if the data given in buf matches the provided signature.
    #[corresponds(EVP_DigestVerify)]
    pub fn verify_oneshot(&mut self, signature: &[u8], buf: &[u8]) -> Result<bool, ErrorStack> {
        unsafe {
            let r = ffi::EVP_DigestVerify(
                self.md_ctx,
                signature.as_ptr().cast(),
                signature.len(),
                buf.as_ptr().cast(),
                buf.len(),
            );
            match r {
                1 => Ok(true),
                0 => {
                    ErrorStack::clear();
                    Ok(false)
                }
                _ => Err(ErrorStack::get()),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::RsaPssSaltlen;
    use hex::{self, FromHex};

    use crate::ec::{EcGroup, EcKey};
    use crate::hash::MessageDigest;
    use crate::nid::Nid;
    use crate::pkey::PKey;
    use crate::rsa::{Padding, Rsa};
    use crate::sign::{Signer, Verifier};

    const INPUT: &str =
        "65794a68624763694f694a53557a49314e694a392e65794a7063334d694f694a71623255694c41304b49434a6c\
         654841694f6a457a4d4441344d546b7a4f44417344516f67496d6830644841364c79396c654746746347786c4c\
         6d4e76625339706331397962323930496a7030636e566c6651";

    const SIGNATURE: &str =
        "702e218943e88fd11eb5d82dbf7845f34106ae1b81fff7731116add1717d83656d420afd3c96eedd73a2663e51\
         66687b000b87226e0187ed1073f945e582adfcef16d85a798ee8c66ddb3db8975b17d09402beedd5d9d9700710\
         8db28160d5f8040ca7445762b81fbe7ff9d92e0ae76f24f25b33bbe6f44ae61eb1040acb20044d3ef9128ed401\
         30795bd4bd3b41eecad066ab651981fde48df77f372dc38b9fafdd3befb18b5da3cc3c2eb02f9e3a41d612caad\
         15911273a05f23b9e838faaf849d698429ef5a1e88798236c3d40e604522a544c8f27a7a2db80663d16cf7caea\
         56de405cb2215a45b2c25566b55ac1a748a070dfc8a32a469543d019eefb47";

    #[test]
    fn rsa_sign() {
        let key = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
        assert_eq!(signer.rsa_padding().unwrap(), Padding::PKCS1);
        signer.set_rsa_padding(Padding::PKCS1).unwrap();
        signer.update(&Vec::from_hex(INPUT).unwrap()).unwrap();
        let result = signer.sign_to_vec().unwrap();

        assert_eq!(hex::encode(result), SIGNATURE);
    }

    #[test]
    fn rsa_verify_ok() {
        let key = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        assert_eq!(verifier.rsa_padding().unwrap(), Padding::PKCS1);
        verifier.update(&Vec::from_hex(INPUT).unwrap()).unwrap();
        assert!(verifier.verify(&Vec::from_hex(SIGNATURE).unwrap()).unwrap());
    }

    #[test]
    fn rsa_verify_invalid() {
        let key = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        verifier.update(&Vec::from_hex(INPUT).unwrap()).unwrap();
        verifier.update(b"foobar").unwrap();
        assert!(!verifier.verify(&Vec::from_hex(SIGNATURE).unwrap()).unwrap());
    }

    #[test]
    fn ec() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let key = PKey::from_ec_key(key).unwrap();

        let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
        signer.update(b"hello world").unwrap();
        let signature = signer.sign_to_vec().unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha256(), &key).unwrap();
        verifier.update(b"hello world").unwrap();
        assert!(verifier.verify(&signature).unwrap());
    }

    #[test]
    fn rsa_sign_verify() {
        let key = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
        signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
        assert_eq!(signer.rsa_padding().unwrap(), Padding::PKCS1_PSS);
        signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .unwrap();
        signer.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
        signer.update(&Vec::from_hex(INPUT).unwrap()).unwrap();
        let signature = signer.sign_to_vec().unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
        verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .unwrap();
        verifier.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
        verifier.update(&Vec::from_hex(INPUT).unwrap()).unwrap();
        assert!(verifier.verify(&signature).unwrap());
    }
}
