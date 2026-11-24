//! Low-level AES block encryption and RFC 3394 key wrapping.
//!
//! Use the higher-level symmetric cipher or AEAD interfaces for ordinary messages.
//! Encryption and decryption schedules are distinct types.
use crate::ffi;
use libc::{c_int, c_uint};
use openssl_macros::corresponds;
use std::{fmt, mem, ptr};

/// Provides Error handling for parsing keys.
#[derive(Debug)]
pub struct KeyError(());

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid AES key or key wrap input")
    }
}

impl std::error::Error for KeyError {}

struct AesSchedule(ffi::AES_KEY);

impl AesSchedule {
    /// A zeroed key. AES-128 and AES-192 schedules fill only part of it, and the rest must still
    /// be initialized.
    const fn zeroed() -> Self {
        Self(ffi::AES_KEY {
            rd_key: [0; 60],
            rounds: 0,
        })
    }

    fn new_schedule(
        key: &[u8],
        initialize: unsafe extern "C" fn(*const u8, c_uint, *mut ffi::AES_KEY) -> c_int,
    ) -> Result<Self, KeyError> {
        let bits = match key.len() {
            16 => 128,
            24 => 192,
            32 => 256,
            _ => return Err(KeyError(())),
        };
        let mut schedule = Self::zeroed();
        // SAFETY: The selected native initializer reads exactly the matching
        // key length and writes the initialized, exclusively owned schedule.
        let result = unsafe { initialize(key.as_ptr(), bits, &raw mut schedule.0) };
        if result == 0 {
            Ok(schedule)
        } else {
            Err(KeyError(()))
        }
    }
}

impl Drop for AesSchedule {
    fn drop(&mut self) {
        // SAFETY: The entire owned schedule is initialized and writable.
        unsafe {
            ffi::OPENSSL_cleanse(
                ptr::from_mut(&mut self.0).cast(),
                mem::size_of::<ffi::AES_KEY>(),
            );
        }
    }
}

macro_rules! aes_schedule {
    ($key:ident, $init:ident, $block:ident, $native_block:ident, $kind:literal, $operation:literal) => {
        #[doc = $kind]
        pub struct $key(AesSchedule);

        impl $key {
            /// Prepares the corresponding AES key schedule.
            ///
            /// # Errors
            ///
            /// Returns an error unless the key is 128, 192, or 256 bits.
            #[corresponds($init)]
            pub fn new(key: &[u8]) -> Result<Self, KeyError> {
                AesSchedule::new_schedule(key, ffi::$init).map(Self)
            }

            #[doc = $operation]
            #[corresponds($native_block)]
            pub fn $block(&self, input: &[u8; 16], out: &mut [u8; 16]) {
                // SAFETY: Both blocks are exactly 16 bytes. The constructor
                // initializes the schedule for the matching native operation.
                unsafe { ffi::$native_block(input.as_ptr(), out.as_mut_ptr(), &raw const self.0.0) }
            }
        }
    };
}

aes_schedule!(
    AesEncryptKey,
    AES_set_encrypt_key,
    encrypt_block,
    AES_encrypt,
    "An AES encryption schedule, cleansed on drop.",
    "Encrypts one block."
);
aes_schedule!(
    AesDecryptKey,
    AES_set_decrypt_key,
    decrypt_block,
    AES_decrypt,
    "An AES decryption schedule, cleansed on drop.",
    "Decrypts one block."
);

impl AesEncryptKey {
    /// Wraps key material according to RFC 3394, returning the written length.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input length, insufficient output capacity,
    /// or native failure. Input must contain at least two eight-byte blocks.
    #[corresponds(AES_wrap_key)]
    pub fn wrap_key(
        &self,
        iv: Option<[u8; 8]>,
        out: &mut [u8],
        input: &[u8],
    ) -> Result<usize, KeyError> {
        let len = input.len().checked_add(8).ok_or(KeyError(()))?;
        let expected = c_int::try_from(len).map_err(|_| KeyError(()))?;
        if input.len() < 16 || !input.len().is_multiple_of(8) {
            return Err(KeyError(()));
        }
        let dest = out.get_mut(..len).ok_or(KeyError(()))?;
        // SAFETY: The length checks establish the native routine's input and output
        // contracts; its optional IV is eight bytes and the schedule is for encryption.
        let written = unsafe {
            ffi::AES_wrap_key(
                &raw const self.0.0,
                iv.as_ref().map_or(ptr::null(), |iv| iv.as_ptr()),
                dest.as_mut_ptr(),
                input.as_ptr(),
                input.len(),
            )
        };
        if written != expected {
            return Err(KeyError(()));
        }
        Ok(len)
    }
}

impl AesDecryptKey {
    /// Unwraps and authenticates RFC 3394 key material.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input length, insufficient output capacity,
    /// or failed authentication. On native failure, the intended output prefix
    /// is cleansed; bytes beyond that prefix are untouched.
    #[corresponds(AES_unwrap_key)]
    pub fn unwrap_key(
        &self,
        iv: Option<[u8; 8]>,
        out: &mut [u8],
        input: &[u8],
    ) -> Result<usize, KeyError> {
        if input.len() < 24 || !input.len().is_multiple_of(8) {
            return Err(KeyError(()));
        }
        c_int::try_from(input.len()).map_err(|_| KeyError(()))?;
        let len = input.len() - 8;
        let expected = c_int::try_from(len).map_err(|_| KeyError(()))?;
        let dest = out.get_mut(..len).ok_or(KeyError(()))?;
        // SAFETY: The native API writes exactly input.len() - 8 bytes even
        // before authenticity is established. dest has that capacity, the
        // IV is eight bytes if supplied, and the schedule is for decryption.
        let written = unsafe {
            ffi::AES_unwrap_key(
                &raw const self.0.0,
                iv.as_ref().map_or(ptr::null(), |iv| iv.as_ptr()),
                dest.as_mut_ptr(),
                input.as_ptr(),
                input.len(),
            )
        };
        if written != expected {
            // SAFETY: dest is an exclusively borrowed, initialized writable slice.
            unsafe { ffi::OPENSSL_cleanse(dest.as_mut_ptr().cast(), dest.len()) };
            return Err(KeyError(()));
        }
        Ok(len)
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    use super::*;

    /// The AES-128 example of FIPS-197, Appendix C.1.
    #[test]
    fn test_block() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let plaintext: [u8; 16] = hex::decode("00112233445566778899aabbccddeeff")
            .unwrap()
            .try_into()
            .unwrap();
        let mut ciphertext = [0; 16];
        AesEncryptKey::new(&key)
            .unwrap()
            .encrypt_block(&plaintext, &mut ciphertext);
        assert_eq!(hex::encode(ciphertext), "69c4e0d86a7b0430d8cdb78070b4c55a");

        let mut decrypted = [0; 16];
        AesDecryptKey::new(&key)
            .unwrap()
            .decrypt_block(&ciphertext, &mut decrypted);
        assert_eq!(decrypted, plaintext);
    }

    // from the RFC https://tools.ietf.org/html/rfc3394#section-2.2.3
    #[test]
    fn test_wrap_unwrap() {
        let raw_key = Vec::from_hex("000102030405060708090A0B0C0D0E0F").unwrap();
        let key_data = Vec::from_hex("00112233445566778899AABBCCDDEEFF").unwrap();
        let expected_ciphertext =
            Vec::from_hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").unwrap();

        let enc_key = AesEncryptKey::new(&raw_key).unwrap();
        let mut wrapped = [0; 24];
        assert_eq!(enc_key.wrap_key(None, &mut wrapped, &key_data).unwrap(), 24);
        assert_eq!(&wrapped[..], &expected_ciphertext[..]);

        let dec_key = AesDecryptKey::new(&raw_key).unwrap();
        let mut unwrapped = [0; 16];
        assert_eq!(
            dec_key.unwrap_key(None, &mut unwrapped, &wrapped).unwrap(),
            16
        );
        assert_eq!(&unwrapped[..], &key_data[..]);
    }
    #[test]
    fn wrap_capacity_and_authentication() {
        let enc = AesEncryptKey::new(&[0; 16]).unwrap();
        let dec = AesDecryptKey::new(&[0; 16]).unwrap();
        let input = [42; 16];
        let mut wrapped = [0xa5; 31];
        assert!(enc.wrap_key(None, &mut wrapped[..23], &input).is_err());
        assert_eq!(wrapped, [0xa5; 31]);
        assert_eq!(enc.wrap_key(None, &mut wrapped, &input).unwrap(), 24);
        assert_eq!(wrapped[24..], [0xa5; 7]);
        let mut out = [0xa5; 23];
        assert!(
            dec.unwrap_key(None, &mut out[..15], &wrapped[..24])
                .is_err()
        );
        assert_eq!(out, [0xa5; 23]);
        assert_eq!(dec.unwrap_key(None, &mut out, &wrapped[..24]).unwrap(), 16);
        assert_eq!(out[..16], input);
        assert_eq!(out[16..], [0xa5; 7]);
        assert!(
            dec.unwrap_key(Some([0; 8]), &mut out, &wrapped[..24])
                .is_err()
        );
        assert_eq!(out[..16], [0; 16]);
        assert_eq!(out[16..], [0xa5; 7]);
        assert!(enc.wrap_key(None, &mut wrapped, &input[..8]).is_err());
        assert!(dec.unwrap_key(None, &mut out, &wrapped[..23]).is_err());
    }
}
