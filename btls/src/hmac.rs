use crate::error::ErrorStack;
use crate::hash::MessageDigest;
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::ffi::c_uint;
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::HMAC_CTX;
    fn drop = ffi::HMAC_CTX_free;

    pub struct HmacCtx;
}

impl HmacCtxRef {
    /// Configures the HMAC context for the requested digest and key.
    ///
    /// # Errors
    ///
    /// The digest is unsupported or native initialization fails.
    #[corresponds(HMAC_Init_ex)]
    pub fn init(&mut self, key: &[u8], md: &MessageDigest) -> Result<(), ErrorStack> {
        ffi::init();

        // SAFETY: self is an exclusively borrowed live HMAC context, digest
        // is a static descriptor and key describes a readable byte slice.
        unsafe {
            cvt(ffi::HMAC_Init_ex(
                self.as_ptr(),
                key.as_ptr().cast(),
                key.len(),
                md.as_ptr(),
                ptr::null_mut(),
            ))
        }
    }
}

/// Provides an init-update-finalize API for HMAC.
pub struct Hmac(HmacCtx);

impl Hmac {
    /// Creates a new HMAC object with the given key and hash algorithm.
    ///
    /// # Errors
    ///
    /// The native context allocation or initialization fails.
    pub fn init(key: &[u8], md: &MessageDigest) -> Result<Self, ErrorStack> {
        ffi::init();
        // SAFETY: the native allocator returns a uniquely owned context or null.
        let mut ctx = unsafe { HmacCtx::from_ptr(cvt_p(ffi::HMAC_CTX_new())?) };
        ctx.init(key, md)?;
        Ok(Self(ctx))
    }

    /// Updates the HMAC input.
    ///
    /// # Errors
    ///
    /// The native HMAC update fails.
    pub fn update(&mut self, data: &[u8]) -> Result<(), ErrorStack> {
        // SAFETY: the initialized context is exclusively borrowed and the
        // input describes a readable byte slice.
        unsafe { cvt(ffi::HMAC_Update(self.0.as_ptr(), data.as_ptr(), data.len())) }
    }

    /// Finalizes the HMAC and returns its initialized output.
    ///
    /// # Errors
    ///
    /// Finalization fails or the native output length is inconsistent.
    pub fn finalize(self) -> Result<Vec<u8>, ErrorStack> {
        // SAFETY: the context was successfully initialized in the constructor.
        let expected = unsafe { ffi::HMAC_size(self.0.as_ptr()) };
        if expected == 0 || expected > ffi::EVP_MAX_MD_SIZE as usize {
            return Err(ErrorStack::internal_error_str("invalid native HMAC size"));
        }
        let mut out = vec![0; expected];
        let mut len: c_uint = 0;
        // SAFETY: self owns the context, and HMAC_Final requires an output
        // buffer at least HMAC_size bytes long, as allocated above.
        unsafe {
            cvt(ffi::HMAC_Final(
                self.0.as_ptr(),
                out.as_mut_ptr(),
                &raw mut len,
            ))?;
        };
        if usize::try_from(len).map_err(ErrorStack::internal_error)? != expected {
            return Err(ErrorStack::internal_error_str(
                "invalid native HMAC output length",
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use crate::hash;

    use super::*;

    fn test<const N: usize>(md: MessageDigest) {
        assert_eq!(N, md.size());
        let key = vec![0; N];
        let message_parts = [
            b"hello".to_vec(),
            b"world!".to_vec(),
            b"".to_vec(),
            vec![0; 23],
            b"fella guy".to_vec(),
        ];
        let message = message_parts.concat();

        let mut hmac = Hmac::init(&key, &md).unwrap();
        for part in &message_parts {
            hmac.update(part).unwrap();
        }
        let res = hmac.finalize().unwrap();
        assert_eq!(res, hash::hmac::<N>(md, &key, &message).unwrap());
    }

    #[test]
    fn test_sha1() {
        test::<20>(MessageDigest::sha1());
    }

    #[test]
    fn test_sha256() {
        test::<32>(MessageDigest::sha256());
    }

    #[test]
    fn test_sha384() {
        test::<48>(MessageDigest::sha384());
    }

    #[test]
    fn test_sha512() {
        test::<64>(MessageDigest::sha512());
    }
}
