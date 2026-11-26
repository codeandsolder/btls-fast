use openssl_macros::corresponds;
use std::ffi::c_uint;
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::ops::{Deref, DerefMut};
use std::ptr;

use crate::error::ErrorStack;
use crate::ffi;
use crate::ffi::{EVP_MD_CTX_free, EVP_MD_CTX_new};
use crate::nid::Nid;
use crate::{cvt, cvt_p};

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct MessageDigest(*const ffi::EVP_MD);

impl MessageDigest {
    /// Creates a `MessageDigest` from a raw OpenSSL pointer.
    ///
    /// # Safety
    ///
    /// The pointer must reference an immutable native digest descriptor that
    /// remains valid for the lifetime of the process.
    #[must_use = "Use the wrapper returned for the supplied native representation."]
    pub const unsafe fn from_ptr(x: *const ffi::EVP_MD) -> Self {
        Self(x)
    }

    /// Returns the `MessageDigest` corresponding to an `Nid`.
    #[corresponds(EVP_get_digestbynid)]
    #[must_use = "Use the returned algorithm descriptor to configure the cryptographic operation."]
    pub fn from_nid(type_: Nid) -> Option<Self> {
        // SAFETY: the native lookup returns a static descriptor or null.
        unsafe {
            let ptr = ffi::EVP_get_digestbynid(type_.as_raw());
            if ptr.is_null() { None } else { Some(Self(ptr)) }
        }
    }

    #[must_use = "Use the returned digest descriptor for the intended hash operation."]
    pub fn md5() -> Self {
        // SAFETY: the native getter returns an immutable static descriptor.
        unsafe { Self(ffi::EVP_md5()) }
    }

    #[must_use = "Use the returned digest descriptor for the intended hash operation."]
    pub fn sha1() -> Self {
        // SAFETY: the native getter returns an immutable static descriptor.
        unsafe { Self(ffi::EVP_sha1()) }
    }

    #[must_use = "Use the returned digest descriptor for the intended hash operation."]
    pub fn sha224() -> Self {
        // SAFETY: the native getter returns an immutable static descriptor.
        unsafe { Self(ffi::EVP_sha224()) }
    }

    #[must_use = "Use the returned digest descriptor for the intended hash operation."]
    pub fn sha256() -> Self {
        // SAFETY: the native getter returns an immutable static descriptor.
        unsafe { Self(ffi::EVP_sha256()) }
    }

    #[must_use = "Use the returned digest descriptor for the intended hash operation."]
    pub fn sha384() -> Self {
        // SAFETY: the native getter returns an immutable static descriptor.
        unsafe { Self(ffi::EVP_sha384()) }
    }

    #[must_use = "Use the returned digest descriptor for the intended hash operation."]
    pub fn sha512() -> Self {
        // SAFETY: the native getter returns an immutable static descriptor.
        unsafe { Self(ffi::EVP_sha512()) }
    }

    #[must_use = "Use the returned digest descriptor for the intended hash operation."]
    pub fn sha512_256() -> Self {
        // SAFETY: the native getter returns an immutable static descriptor.
        unsafe { Self(ffi::EVP_sha512_256()) }
    }

    #[must_use = "The returned native representation is needed by the caller."]
    pub const fn as_ptr(self) -> *const ffi::EVP_MD {
        self.0
    }

    /// The size of the digest in bytes.
    #[must_use = "Use the returned size when allocating or validating cryptographic buffers."]
    pub fn size(self) -> usize {
        // SAFETY: the descriptor remains valid for the process lifetime.
        unsafe { ffi::EVP_MD_size(self.0) }
    }

    /// The name of the digest.
    #[must_use = "The returned identifier is the result of this query."]
    pub fn type_(self) -> Nid {
        // SAFETY: the descriptor remains valid for the process lifetime.
        Nid::from_raw(unsafe { ffi::EVP_MD_type(self.0) })
    }
}

// SAFETY: descriptor pointers always reference immutable process-lifetime data.
unsafe impl Sync for MessageDigest {}
// SAFETY: native digest descriptors are static and not thread-affine.
unsafe impl Send for MessageDigest {}

/// Provides message digest (hash) computation.
///
/// # Examples
///
/// Calculate a hash in one go:
///
/// ```
/// use btls::hash::{hash, MessageDigest};
///
/// let data = b"\x42\xF4\x97\xE0";
/// let spec = b"\x7c\x43\x0f\x17\x8a\xef\xdf\x14\x87\xfe\xe7\x14\x4e\x96\x41\xe2";
/// let res = hash(MessageDigest::md5(), data).unwrap();
/// assert_eq!(&*res, spec);
/// ```
///
/// Supply the input in chunks:
///
/// ```
/// use btls::hash::{Hasher, MessageDigest};
///
/// let data = [b"\x42\xF4", b"\x97\xE0"];
/// let spec = b"\x7c\x43\x0f\x17\x8a\xef\xdf\x14\x87\xfe\xe7\x14\x4e\x96\x41\xe2";
/// let mut h = Hasher::new(MessageDigest::md5()).unwrap();
/// h.update(data[0]).unwrap();
/// h.update(data[1]).unwrap();
/// let res = h.finish().unwrap();
/// assert_eq!(&*res, spec);
/// ```
///
/// # Warning
///
/// Don't actually use MD5 and SHA-1 hashes, they're not secure anymore.
///
/// Don't ever hash passwords, use the functions in the `pkcs5` module or bcrypt/scrypt instead.
///
pub struct Hasher {
    ctx: *mut ffi::EVP_MD_CTX,
    digest: MessageDigest,
    finalized: bool,
}

// SAFETY: the unique context owner is movable between threads; mutation
// requires an exclusive borrow. Its digest descriptor is immutable.
unsafe impl Send for Hasher {}

impl Hasher {
    /// Creates a new hasher for the selected native digest.
    ///
    /// # Errors
    ///
    /// The context allocation fails or the digest cannot be initialized.
    pub fn new(digest: MessageDigest) -> Result<Self, ErrorStack> {
        ffi::init();
        // SAFETY: the allocator returns a fresh native context or null.
        let ctx = unsafe { cvt_p(EVP_MD_CTX_new())? };
        let mut hasher = Self {
            ctx,
            digest,
            finalized: true,
        };
        hasher.ensure_active()?;
        Ok(hasher)
    }

    fn ensure_active(&mut self) -> Result<(), ErrorStack> {
        if self.finalized {
            // SAFETY: self owns the initialized native allocation; digest
            // identifies an immutable live descriptor.
            unsafe {
                cvt(ffi::EVP_DigestInit_ex(
                    self.ctx,
                    self.digest.as_ptr(),
                    ptr::null_mut(),
                ))?;
            };
            self.finalized = false;
        }
        Ok(())
    }

    /// Feeds data into the hasher.
    ///
    /// # Errors
    ///
    /// The native digest initialization or update fails.
    pub fn update(&mut self, data: &[u8]) -> Result<(), ErrorStack> {
        self.ensure_active()?;
        // SAFETY: the native digest is active and exclusively borrowed, with
        // a readable input slice of the supplied length.
        unsafe {
            cvt(ffi::EVP_DigestUpdate(
                self.ctx,
                data.as_ptr().cast(),
                data.len(),
            ))
        }
    }

    /// Returns the hash of the data written and resets the hasher.
    ///
    /// # Errors
    ///
    /// The native digest operation fails or reports an invalid output length.
    pub fn finish(&mut self) -> Result<DigestBytes, ErrorStack> {
        self.ensure_active()?;
        let mut len: c_uint = 0;
        let mut buf = [0; ffi::EVP_MAX_MD_SIZE as usize];
        // SAFETY: the active context writes at most EVP_MAX_MD_SIZE bytes to
        // this exclusive output buffer, and reports the actual byte count.
        let result = unsafe {
            cvt(ffi::EVP_DigestFinal_ex(
                self.ctx,
                buf.as_mut_ptr(),
                &raw mut len,
            ))
        };
        self.finalized = true;
        result?;
        let len = usize::try_from(len).map_err(ErrorStack::internal_error)?;
        if len > buf.len() || len != self.digest.size() {
            return Err(ErrorStack::internal_error_str(
                "invalid native digest output length",
            ));
        }
        Ok(DigestBytes { buf, len })
    }

    /// Copies the current digest state into an independently owned context.
    ///
    /// # Errors
    ///
    /// Native allocation or copying the digest state fails.
    pub fn try_clone(&self) -> Result<Self, ErrorStack> {
        // SAFETY: the allocator returns a fresh native context or null.
        let ctx = unsafe { cvt_p(EVP_MD_CTX_new())? };
        let copy = Self {
            ctx,
            digest: self.digest,
            finalized: self.finalized,
        };
        if !self.finalized {
            // SAFETY: source is live and immutably borrowed; the destination
            // is initialized and owned by copy even if copying fails.
            unsafe { cvt(ffi::EVP_MD_CTX_copy_ex(copy.ctx, self.ctx))? };
        }
        Ok(copy)
    }
}

impl Write for Hasher {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        // SAFETY: this is the uniquely owned native allocation, and free
        // performs the context cleanup without finalizing the digest.
        unsafe { EVP_MD_CTX_free(self.ctx) };
    }
}

/// The resulting bytes of a digest.
///
/// This type derefs to a byte slice - it exists to avoid allocating memory to
/// store the digest data.
#[derive(Clone, Copy)]
pub struct DigestBytes {
    pub(crate) buf: [u8; ffi::EVP_MAX_MD_SIZE as usize],
    pub(crate) len: usize,
}

impl Deref for DigestBytes {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl DerefMut for DigestBytes {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }
}

impl AsRef<[u8]> for DigestBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl fmt::Debug for DigestBytes {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, fmt)
    }
}

/// Computes the hash of the input using the selected digest.
///
/// # Errors
///
/// Native allocation, initialization or digest computation fails.
pub fn hash(t: MessageDigest, data: &[u8]) -> Result<DigestBytes, ErrorStack> {
    let mut h = Hasher::new(t)?;
    h.update(data)?;
    h.finish()
}

/// Computes HMAC with SHA-256 digest.
///
/// # Errors
///
/// Native HMAC initialization or computation fails.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], ErrorStack> {
    hmac(MessageDigest::sha256(), key, data)
}

/// Computes HMAC with SHA-384 digest.
///
/// # Errors
/// Native HMAC initialization or computation fails.
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> Result<[u8; 48], ErrorStack> {
    hmac(MessageDigest::sha384(), key, data)
}

/// Computes HMAC with SHA-512 digest.
///
/// # Errors
///
/// Native HMAC initialization or computation fails.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<[u8; 64], ErrorStack> {
    hmac(MessageDigest::sha512(), key, data)
}

/// Computes HMAC with SHA-1 digest.
///
/// # Errors
///
/// Native HMAC initialization or computation fails.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<[u8; 20], ErrorStack> {
    hmac(MessageDigest::sha1(), key, data)
}

pub(crate) fn hmac<const N: usize>(
    digest: MessageDigest,
    key: &[u8],
    data: &[u8],
) -> Result<[u8; N], ErrorStack> {
    if digest.size() != N || N == 0 || N > ffi::EVP_MAX_MD_SIZE as usize {
        return Err(ErrorStack::internal_error_str(
            "HMAC output width does not match digest",
        ));
    }
    let mut out = [0u8; N];
    let mut out_len: c_uint = 0;

    // SAFETY: the digest's exact native output size matches N, and all
    // input/output pointers describe their readable/writable buffers.
    cvt_p(unsafe {
        ffi::HMAC(
            digest.as_ptr(),
            key.as_ptr().cast(),
            key.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            &raw mut out_len,
        )
    })?;

    if usize::try_from(out_len).map_err(ErrorStack::internal_error)? != N {
        return Err(ErrorStack::internal_error_str(
            "invalid native HMAC output length",
        ));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use hex::{self, FromHex};

    use super::*;

    #[test]
    fn rejects_mismatched_hmac_output_width() {
        assert!(hmac::<1>(MessageDigest::sha256(), b"key", b"message").is_err());
        assert!(hmac::<64>(MessageDigest::sha256(), b"key", b"message").is_err());
    }

    fn hash_test(hashtype: MessageDigest, hashtest: &(&str, &str)) {
        let res = hash(hashtype, &Vec::from_hex(hashtest.0).unwrap()).unwrap();
        assert_eq!(hex::encode(res), hashtest.1);
    }

    fn hash_recycle_test(h: &mut Hasher, hashtest: &(&str, &str)) {
        h.write_all(&Vec::from_hex(hashtest.0).unwrap()).unwrap();
        let res = h.finish().unwrap();
        assert_eq!(hex::encode(res), hashtest.1);
    }

    // Test vectors from http://www.nsrl.nist.gov/testdata/
    const MD5_TESTS: [(&str, &str); 13] = [
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("7F", "83acb6e67e50e31db6ed341dd2de1595"),
        ("EC9C", "0b07f0d4ca797d8ac58874f887cb0b68"),
        ("FEE57A", "e0d583171eb06d56198fc0ef22173907"),
        ("42F497E0", "7c430f178aefdf1487fee7144e9641e2"),
        ("C53B777F1C", "75ef141d64cb37ec423da2d9d440c925"),
        ("89D5B576327B", "ebbaf15eb0ed784c6faa9dc32831bf33"),
        ("5D4CCE781EB190", "ce175c4b08172019f05e6b5279889f2c"),
        ("81901FE94932D7B9", "cd4d2f62b8cdb3a0cf968a735a239281"),
        ("C9FFDEE7788EFB4EC9", "e0841a231ab698db30c6c0f3f246c014"),
        ("66AC4B7EBA95E53DC10B", "a3b3cea71910d9af56742aa0bb2fe329"),
        ("A510CD18F7A56852EB0319", "577e216843dd11573574d3fb209b97d8"),
        (
            "AAED18DBE8938C19ED734A8D",
            "6f80fb775f27e0a4ce5c2f42fc72c5f1",
        ),
    ];

    #[test]
    fn test_hmac_sha256() {
        let hmac = hmac_sha256(b"That's a secret".as_slice(), b"Hello world!".as_slice()).unwrap();

        assert_eq!(
            hmac,
            [
                0x50, 0xbb, 0x7d, 0xd2, 0xb8, 0xd2, 0x51, 0x5d, 0xb4, 0x2b, 0x70, 0xc3, 0x0b, 0xfd,
                0xf5, 0x4c, 0x38, 0xa7, 0xae, 0x99, 0x07, 0xe5, 0x80, 0x0f, 0x8b, 0xe8, 0x34, 0x83,
                0x55, 0x5f, 0xd0, 0xd4
            ]
        );
    }

    #[test]
    fn test_hmac_sha512() {
        let hmac = hmac_sha512(b"That's a secret".as_slice(), b"Hello world!".as_slice()).unwrap();

        assert_eq!(
            hmac,
            [
                0xc2, 0x7a, 0x7f, 0x7c, 0x17, 0x4c, 0x87, 0x70, 0x7f, 0x8c, 0xb7, 0x90, 0x01, 0xba,
                0x23, 0x0e, 0xb7, 0xd6, 0x1a, 0xfd, 0x50, 0xea, 0x40, 0x43, 0x5f, 0x03, 0x25, 0x5a,
                0x22, 0xb7, 0x8d, 0x0e, 0xba, 0x0d, 0x47, 0xb8, 0xef, 0xaa, 0xbf, 0xb1, 0xe7, 0xad,
                0xc5, 0xd1, 0xe5, 0xba, 0x4d, 0xa5, 0xd1, 0xbb, 0x5e, 0xe3, 0xc7, 0x27, 0x0c, 0x57,
                0x76, 0xd4, 0x2f, 0xb6, 0x5c, 0x21, 0xb7, 0x3a
            ]
        );
    }

    #[test]
    fn test_hmac_sha1() {
        let hmac = hmac_sha1(b"That's a secret".as_slice(), b"Hello world!".as_slice()).unwrap();

        assert_eq!(
            hmac,
            [
                0xe1, 0x06, 0x76, 0x46, 0x3b, 0x82, 0x67, 0xa1, 0xae, 0xe5, 0x1c, 0xfa, 0xee, 0x36,
                0x1d, 0x4b, 0xd4, 0x41, 0x6e, 0x37
            ]
        );
    }

    #[test]
    fn test_md5() {
        for test in &MD5_TESTS {
            hash_test(MessageDigest::md5(), test);
        }
    }

    #[test]
    fn test_md5_recycle() {
        let mut h = Hasher::new(MessageDigest::md5()).unwrap();
        for test in &MD5_TESTS {
            hash_recycle_test(&mut h, test);
        }
    }

    #[test]
    fn test_finish_twice() {
        let mut h = Hasher::new(MessageDigest::md5()).unwrap();
        h.write_all(&Vec::from_hex(MD5_TESTS[6].0).unwrap())
            .unwrap();
        h.finish().unwrap();
        let res = h.finish().unwrap();
        let null = hash(MessageDigest::md5(), &[]).unwrap();
        assert_eq!(&*res, &*null);
    }

    #[test]
    fn test_clone() {
        let i = 7;
        let inp = Vec::from_hex(MD5_TESTS[i].0).unwrap();
        assert!(inp.len() > 2);
        let p = inp.len() / 2;
        let mut h0 = Hasher::new(MessageDigest::md5()).unwrap();

        println!("Clone a new hasher");
        let mut h1 = h0.try_clone().unwrap();
        assert_eq!(
            &*h0.finish().unwrap(),
            &*hash(MessageDigest::md5(), &[]).unwrap()
        );
        h1.write_all(&inp[..p]).unwrap();
        {
            println!("Clone an updated hasher");
            let mut h2 = h1.try_clone().unwrap();
            h2.write_all(&inp[p..]).unwrap();
            let res = h2.finish().unwrap();
            assert_eq!(hex::encode(res), MD5_TESTS[i].1);
        }
        h1.write_all(&inp[p..]).unwrap();
        let res = h1.finish().unwrap();
        assert_eq!(hex::encode(res), MD5_TESTS[i].1);

        println!("Clone a finished hasher");
        let mut h3 = h1.try_clone().unwrap();
        assert_eq!(
            &*h1.finish().unwrap(),
            &*hash(MessageDigest::md5(), &[]).unwrap()
        );
        h3.write_all(&Vec::from_hex(MD5_TESTS[i + 1].0).unwrap())
            .unwrap();
        let res = h3.finish().unwrap();
        assert_eq!(hex::encode(res), MD5_TESTS[i + 1].1);
    }

    #[test]
    fn test_sha1() {
        let tests = [("616263", "a9993e364706816aba3e25717850c26c9cd0d89d")];

        for test in &tests {
            hash_test(MessageDigest::sha1(), test);
        }
    }

    #[test]
    fn test_sha224() {
        let tests = [(
            "616263",
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        )];

        for test in &tests {
            hash_test(MessageDigest::sha224(), test);
        }
    }

    #[test]
    fn test_sha256() {
        let tests = [(
            "616263",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )];

        for test in &tests {
            hash_test(MessageDigest::sha256(), test);
        }
    }

    #[test]
    fn test_sha512() {
        let tests = [(
            "616263",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2\
             192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        )];

        for test in &tests {
            hash_test(MessageDigest::sha512(), test);
        }
    }

    #[test]
    fn test_sha512_256() {
        let tests = [(
            "616263",
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
        )];

        for test in &tests {
            hash_test(MessageDigest::sha512_256(), test);
        }
    }

    #[test]
    fn from_nid() {
        assert_eq!(
            MessageDigest::from_nid(Nid::SHA256).unwrap().as_ptr(),
            MessageDigest::sha256().as_ptr()
        );
    }
}
