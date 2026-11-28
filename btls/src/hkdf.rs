//! HMAC-based Extract-and-Expand Key Derivation Function (HKDF) as specified by
//! [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).

use crate::error::ErrorStack;
use crate::hash::MessageDigest;
use crate::{cvt, ffi};
use std::fmt;

/// An owned pseudorandom key bound to its HKDF digest. Its storage is
/// cleansed on drop, and its debug representation never exposes key material.
///
/// Expansion never accepts a separate digest, so equal-width hash algorithms
/// cannot be accidentally interchanged.
///
/// ```compile_fail
/// use btls::{hash::MessageDigest, hkdf::HkdfSuite};
/// let a = HkdfSuite::new(MessageDigest::sha256());
/// let b = HkdfSuite::new(MessageDigest::sha512_256());
/// let prk = a.extract(b"salt", b"ikm").unwrap();
/// b.expand(&prk, b"info", &mut [0; 32]).unwrap();
/// ```
pub struct HkdfPrk {
    buf: [u8; ffi::EVP_MAX_MD_SIZE as usize],
    len: usize,
    suite: HkdfSuite,
}

impl HkdfPrk {
    /// Borrows the pseudorandom key without losing its digest identity.
    #[must_use = "Use the borrowed key to expand or inspect its metadata."]
    pub fn as_prk(&self) -> HkdfPrkRef<'_> {
        HkdfPrkRef {
            bytes: &self.buf[..self.len],
            suite: self.suite,
        }
    }

    /// Expands the key with the same digest used to extract it.
    ///
    /// # Errors
    /// The output exceeds the RFC limit or the native operation fails.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), ErrorStack> {
        self.as_prk().expand(info, okm)
    }
}

impl fmt::Debug for HkdfPrk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HkdfPrk")
            .field("len", &self.len)
            .field("digest", &self.suite.digest.type_())
            .finish_non_exhaustive()
    }
}

/// A borrowed pseudorandom key with the digest needed for expansion. The
/// caller owns and is responsible for cleansing externally supplied storage.
#[derive(Clone, Copy)]
pub struct HkdfPrkRef<'a> {
    bytes: &'a [u8],
    suite: HkdfSuite,
}

impl<'a> HkdfPrkRef<'a> {
    /// Explicitly exposes the raw PRK for protocol serialization or storage.
    #[must_use = "Use the returned secret bytes only where raw key material is required."]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// The digest associated with this pseudorandom key.
    #[must_use = "Use the digest to inspect the key's algorithm identity."]
    pub const fn digest(self) -> MessageDigest {
        self.suite.digest
    }

    /// Computes HKDF-Expand with the key's bound digest.
    /// `info` and `okm` may be empty. Output is limited to 255 times the
    /// digest width, as specified by RFC 5869.
    ///
    /// # Errors
    /// The output exceeds the RFC limit or the native operation fails.
    pub fn expand(self, info: &[u8], okm: &mut [u8]) -> Result<(), ErrorStack> {
        self.suite.expand_prk(self.bytes, info, okm)
    }
}

impl fmt::Debug for HkdfPrkRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HkdfPrkRef")
            .field("len", &self.bytes.len())
            .field("digest", &self.suite.digest.type_())
            .finish_non_exhaustive()
    }
}

impl Drop for HkdfPrk {
    fn drop(&mut self) {
        // SAFETY: the full owned byte array is writable throughout destruction.
        unsafe { ffi::OPENSSL_cleanse(self.buf.as_mut_ptr().cast(), self.buf.len()) };
    }
}

/// HKDF for a given hash function.
///
/// The digest determines `HashLen`, the length of the pseudorandom key (PRK)
/// returned by [`HkdfSuite::extract`]. HKDF-Expand limits output to
/// `255 * HashLen` bytes, as specified by [RFC 5869, Section
/// 2.3](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.3).
#[derive(Copy, Clone)]
pub struct HkdfSuite {
    digest: MessageDigest,
}

impl HkdfSuite {
    /// Creates an HKDF suite using `digest`.
    #[must_use = "Use the returned HKDF instance configured for the selected digest."]
    pub const fn new(digest: MessageDigest) -> Self {
        Self { digest }
    }

    /// Returns `HashLen`, the digest output size in bytes.
    #[must_use = "Use the returned length or capacity to size buffers or validate input."]
    pub fn prk_size(self) -> usize {
        self.digest.size()
    }

    fn checked_width(self) -> Result<usize, ErrorStack> {
        let width = self.prk_size();
        if width == 0 || width > ffi::EVP_MAX_MD_SIZE as usize {
            return Err(ErrorStack::internal_error_str("invalid HKDF digest width"));
        }
        Ok(width)
    }

    /// Computes HKDF-Extract as specified in [RFC 5869, Section
    /// 2.2](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.2).
    ///
    /// `salt` is an optional salt value. An empty `salt` is treated as an
    /// omitted salt and is equivalent to a string of `HashLen` zero octets.
    /// `ikm` is the input keying material. The returned pseudorandom key (PRK)
    /// has length [`HkdfSuite::prk_size`].
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid digest width or native HMAC failure.
    pub fn extract(self, salt: &[u8], ikm: &[u8]) -> Result<HkdfPrk, ErrorStack> {
        let mut prk = HkdfPrk {
            buf: [0; ffi::EVP_MAX_MD_SIZE as usize],
            len: 0,
            suite: self,
        };
        prk.len = self.extract_into(salt, ikm, &mut prk.buf)?.as_bytes().len();
        Ok(prk)
    }

    /// Like [`HkdfSuite::extract`], but writes the pseudorandom key into `out`
    /// and returns a digest-bound borrow of exactly the initialized prefix.
    /// The caller retains responsibility for cleansing the backing storage.
    /// `out` must hold at least [`HkdfSuite::prk_size`] bytes; its suffix is unchanged.
    ///
    /// ```compile_fail
    /// use btls::{hash::MessageDigest, hkdf::HkdfSuite};
    /// let suite = HkdfSuite::new(MessageDigest::sha256());
    /// let mut backing = [0; 32];
    /// let prk = suite.extract_into(b"salt", b"ikm", &mut backing).unwrap();
    /// backing.fill(0);
    /// prk.expand(b"info", &mut [0; 32]).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid digest width, insufficient output capacity,
    /// or native HMAC failure.
    pub fn extract_into<'a>(
        self,
        salt: &[u8],
        ikm: &[u8],
        out: &'a mut [u8],
    ) -> Result<HkdfPrkRef<'a>, ErrorStack> {
        let width = self.checked_width()?;
        let out = out.get_mut(..width).ok_or_else(|| {
            ErrorStack::internal_error_str("HKDF PRK buffer is shorter than the digest output")
        })?;
        ffi::init();
        let mut len = 0;
        // SAFETY: the digest's fixed output width fits the exclusive output
        // slice, length is a writable local, and inputs remain readable.
        // Native orders the input keying material before the salt.
        let result = unsafe {
            ffi::HKDF_extract(
                out.as_mut_ptr(),
                &raw mut len,
                self.digest.as_ptr(),
                ikm.as_ptr(),
                ikm.len(),
                salt.as_ptr(),
                salt.len(),
            )
        };
        if result <= 0 || len != width {
            // SAFETY: the exclusive output prefix is writable, including on failure.
            unsafe { ffi::OPENSSL_cleanse(out.as_mut_ptr().cast(), out.len()) };
            cvt(result)?;
            return Err(ErrorStack::internal_error_str("invalid HKDF PRK length"));
        }
        Ok(HkdfPrkRef {
            bytes: out,
            suite: self,
        })
    }

    /// Imports an externally supplied PRK and explicitly associates it with
    /// this digest. The caller must know the PRK's original algorithm; length
    /// alone cannot establish that identity. PRKs longer than `HashLen` are valid.
    ///
    /// # Errors
    /// The digest width is invalid or the PRK is shorter than `HashLen`.
    pub fn import_prk(self, bytes: &[u8]) -> Result<HkdfPrkRef<'_>, ErrorStack> {
        let width = self.checked_width()?;
        if bytes.len() < width {
            return Err(ErrorStack::internal_error_str(
                "HKDF PRK is shorter than the digest output",
            ));
        }
        Ok(HkdfPrkRef { bytes, suite: self })
    }

    // Only validated digest-bound PRKs can reach this operation.
    fn expand_prk(self, prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), ErrorStack> {
        ffi::init();

        // SAFETY: the descriptor has a supported nonzero width; all inputs
        // and exclusive output are live, with exact lengths. Native checks the
        // RFC output limit before writing.
        unsafe {
            cvt(ffi::HKDF_expand(
                okm.as_mut_ptr(),
                okm.len(),
                self.digest.as_ptr(),
                prk.as_ptr(),
                prk.len(),
                info.as_ptr(),
                info.len(),
            ))
        }
    }
}
