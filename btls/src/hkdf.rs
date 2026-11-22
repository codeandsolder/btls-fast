//! HMAC-based Extract-and-Expand Key Derivation Function (HKDF) as specified by
//! [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).

use crate::error::ErrorStack;
use crate::hash::MessageDigest;
use crate::{cvt, ffi};
use std::{fmt, ops::Deref};

/// An owned pseudorandom key. Its storage is cleansed on drop, and the
/// debug representation does not expose key material.
pub struct HkdfPrk {
    buf: [u8; ffi::EVP_MAX_MD_SIZE as usize],
    len: usize,
}

impl Deref for HkdfPrk {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl AsRef<[u8]> for HkdfPrk {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl fmt::Debug for HkdfPrk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HkdfPrk")
            .field("len", &self.len)
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
        };
        prk.len = self.extract_into(salt, ikm, &mut prk.buf)?;
        Ok(prk)
    }

    /// Like [`HkdfSuite::extract`], but writes the pseudorandom key into `out` and returns its
    /// length, so that the caller controls the memory holding it, for example to zero it.
    ///
    /// `out` must hold at least [`HkdfSuite::prk_size`] bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid digest width, insufficient output capacity,
    /// or native HMAC failure.
    pub fn extract_into(
        self,
        salt: &[u8],
        ikm: &[u8],
        out: &mut [u8],
    ) -> Result<usize, ErrorStack> {
        let width = self.prk_size();
        if width == 0 || width > ffi::EVP_MAX_MD_SIZE as usize {
            return Err(ErrorStack::internal_error_str("invalid HKDF digest width"));
        }
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
        Ok(len)
    }

    /// Computes HKDF-Expand as specified in [RFC 5869, Section
    /// 2.3](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.3).
    ///
    /// `prk` must be a pseudorandom key of at least `HashLen` bytes, usually
    /// the output of [`HkdfSuite::extract`]. Shorter PRKs are rejected.
    /// `info` is optional context and application-specific information and may
    /// be empty. The function writes `L` bytes of output keying material into
    /// `okm`, where `L` is its length. `okm` may be empty. HKDF limits `L` to
    /// `255 * HashLen`; output-limit errors are returned as [`ErrorStack`].
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid digest width, short PRK, output beyond
    /// the RFC limit, or native HMAC failure.
    pub fn expand(self, prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), ErrorStack> {
        let width = self.prk_size();
        if width == 0 || width > ffi::EVP_MAX_MD_SIZE as usize {
            return Err(ErrorStack::internal_error_str("invalid HKDF digest width"));
        }
        if prk.len() < width {
            return Err(ErrorStack::internal_error_str(
                "HKDF PRK is shorter than the digest output",
            ));
        }

        if okm.len() > 255 * width {
            return Err(ErrorStack::internal_error_str(
                "HKDF output exceeds RFC limit",
            ));
        }
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
