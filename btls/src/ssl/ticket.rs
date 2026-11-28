//! Server-side session-ticket key selection with library-owned cryptography.

use std::{ffi::c_int, fmt, sync::Arc};

use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;

use super::{SslContext, SslContextBuilder, SslRef};
use crate::{
    cvt,
    error::ErrorStack,
    ex_data::IndexSlot,
    ffi,
    hash::MessageDigest,
    hmac::HmacCtxRef,
    rand::rand_bytes,
    symm::{Cipher, CipherCtxRef, Mode},
    util::{SecretBytes, catch_native},
};

/// A named AES-CBC and HMAC-SHA256 session-ticket key.
///
/// Clones share immutable secret storage, which is erased on final release.
/// Use independently generated encryption and authentication keys. Rotate
/// keys regularly and retire expired keys from the provider's lookup.
#[derive(Clone)]
pub struct TicketKey {
    name: [u8; 16],
    cipher: Cipher,
    keys: Arc<SecretBytes>,
}

impl TicketKey {
    /// Imports a key for sharing between ticket-issuing servers.
    ///
    /// The AES key must contain 16, 24 or 32 bytes. The independent HMAC
    /// key must contain at least 16 bytes of high-entropy secret material.
    /// The caller retains responsibility for erasing its input buffers.
    ///
    /// # Errors
    /// The key lengths are invalid or secret storage cannot be allocated.
    pub fn from_keys(
        name: [u8; 16],
        encryption_key: &[u8],
        authentication_key: &[u8],
    ) -> Result<Self, ErrorStack> {
        let cipher = match encryption_key.len() {
            16 => Cipher::aes_128_cbc(),
            24 => Cipher::aes_192_cbc(),
            32 => Cipher::aes_256_cbc(),
            _ => {
                return Err(ErrorStack::internal_error_str(
                    "invalid AES ticket key length",
                ));
            }
        };
        if authentication_key.len() < 16 {
            return Err(ErrorStack::internal_error_str(
                "ticket authentication key is too short",
            ));
        }
        let len = encryption_key
            .len()
            .checked_add(authentication_key.len())
            .ok_or_else(|| ErrorStack::internal_error_str("ticket key length overflow"))?;
        let mut keys = SecretBytes::zeroed(len)?;
        let (encryption, authentication) = keys.split_at_mut(encryption_key.len());
        encryption.copy_from_slice(encryption_key);
        authentication.copy_from_slice(authentication_key);
        Ok(Self {
            name,
            cipher,
            keys: Arc::new(keys),
        })
    }

    /// Generates a random key name and independent 256-bit AES and HMAC keys.
    ///
    /// # Errors
    /// Allocation or secure random generation fails.
    pub fn generate() -> Result<Self, ErrorStack> {
        let mut name = [0; 16];
        let mut keys = SecretBytes::zeroed(64)?;
        rand_bytes(&mut name)?;
        rand_bytes(&mut keys)?;
        Ok(Self {
            name,
            cipher: Cipher::aes_256_cbc(),
            keys: Arc::new(keys),
        })
    }

    /// Returns the public ticket key identifier.
    #[must_use = "Use the identifier to select a key for an incoming ticket."]
    pub const fn name(&self) -> &[u8; 16] {
        &self.name
    }

    fn configure(
        &self,
        cipher: &mut CipherCtxRef,
        hmac: &mut HmacCtxRef,
        mode: Mode,
        iv: &[u8; 16],
    ) -> Result<(), ErrorStack> {
        let (encryption, authentication) = self.keys.split_at(self.cipher.key_len());
        cipher.init(self.cipher, mode, encryption, Some(iv))?;
        hmac.init(authentication, &MessageDigest::sha256())
    }
}

impl fmt::Debug for TicketKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketKey")
            .field("name", &self.name)
            .field("cipher", &self.cipher)
            .field("keys", &"[redacted]")
            .finish()
    }
}

/// Whether a successfully decrypted ticket should be renewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketRenewal {
    /// Resume without explicitly requesting renewal.
    Keep,
    /// Resume and request a replacement ticket with the current issuing key.
    Renew,
}

/// Selects ticket keys, without access to native cipher or MAC contexts.
///
/// Providers may share keys across contexts and servers and use synchronized
/// application state to rotate them. The library generates a fresh random IV
/// for every issued ticket and performs authenticated ticket processing.
pub trait TicketKeyProvider: Send + Sync {
    /// Returns the current issuing key, or `None` to skip ticket issuance.
    ///
    /// # Errors
    /// An error aborts ticket processing.
    fn issuing_key(&self, ssl: &SslRef) -> Result<Option<TicketKey>, ErrorStack>;

    /// Looks up a key by its public ticket identifier.
    ///
    /// Return `None` for unknown or retired keys to request a full handshake.
    /// A returned key must have the requested identifier.
    ///
    /// # Errors
    /// An error aborts ticket processing.
    fn decryption_key(
        &self,
        ssl: &SslRef,
        name: &[u8; 16],
    ) -> Result<Option<(TicketKey, TicketRenewal)>, ErrorStack>;
}

static TICKET_KEYS: IndexSlot<SslContext, Option<Box<dyn TicketKeyProvider>>> =
    IndexSlot::new(SslContext::new_ex_index);

impl SslContextBuilder {
    /// Installs a server-side session-ticket key provider.
    ///
    /// Replaces the previous provider. Rotate keys to bound the consequences
    /// of key compromise. If no provider is installed, `BoringSSL` manages its
    /// own ticket keys.
    ///
    /// # Errors
    /// Native callback registration or storage allocation fails.
    #[corresponds(SSL_CTX_set_tlsext_ticket_key_cb)]
    pub fn set_ticket_key_provider(
        &mut self,
        provider: impl TicketKeyProvider + 'static,
    ) -> Result<(), ErrorStack> {
        self.set_ex_data(TICKET_KEYS.register()?, Some(Box::new(provider)))?;
        // SAFETY: the exclusively owned context retains its provider and a
        // process-lifetime trampoline. The native setter always succeeds.
        unsafe {
            cvt(ffi::SSL_CTX_set_tlsext_ticket_key_cb(
                self.as_ptr(),
                Some(raw_ticket_key),
            ))
        }
    }

    /// Restores native ticket-key management and releases the previous provider.
    ///
    /// # Errors
    /// Native callback registration or storage allocation fails.
    #[corresponds(SSL_CTX_set_tlsext_ticket_key_cb)]
    pub fn clear_ticket_key_provider(&mut self) -> Result<(), ErrorStack> {
        self.set_ex_data(TICKET_KEYS.register()?, None)?;
        // SAFETY: the context is exclusively owned by the builder.
        unsafe { cvt(ffi::SSL_CTX_set_tlsext_ticket_key_cb(self.as_ptr(), None)) }
    }
}

unsafe extern "C" fn raw_ticket_key(
    ssl: *mut ffi::SSL,
    name: *mut u8,
    iv: *mut u8,
    cipher: *mut ffi::EVP_CIPHER_CTX,
    hmac: *mut ffi::HMAC_CTX,
    encrypt: c_int,
) -> c_int {
    if ssl.is_null() || name.is_null() || iv.is_null() || cipher.is_null() || hmac.is_null() {
        return -1;
    }
    catch_native(|| {
        // SAFETY: native ticket processing borrows the live SSL and exclusively
        // supplies initialized, disjoint cipher and HMAC context allocations.
        let (ssl, cipher, hmac) = unsafe {
            (
                SslRef::from_ptr(ssl),
                CipherCtxRef::from_ptr_mut(cipher),
                HmacCtxRef::from_ptr_mut(hmac),
            )
        };
        let result = (|| {
            let provider = ssl
                .session_context()
                .slot_data(&TICKET_KEYS)
                .and_then(Option::as_deref)
                .ok_or_else(|| ErrorStack::internal_error_str("missing ticket key provider"))?;
            match encrypt {
                1 => {
                    let Some(key) = provider.issuing_key(ssl)? else {
                        return Ok(0);
                    };
                    let mut nonce = [0; 16];
                    rand_bytes(&mut nonce)?;
                    key.configure(cipher, hmac, Mode::Encrypt, &nonce)?;
                    // SAFETY: native issuance provides writable arrays of at
                    // least 16 bytes. Write initialized bytes without reading
                    // or borrowing the uninitialized destination.
                    unsafe {
                        name.cast::<[u8; 16]>().write(*key.name());
                        iv.cast::<[u8; 16]>().write(nonce);
                    }
                    Ok(1)
                }
                0 => {
                    // SAFETY: native decryption provides immutable ticket input
                    // with a complete name and at least EVP_MAX_IV_LENGTH bytes
                    // of IV storage. All supported AES-CBC IVs are 16 bytes.
                    let (name, iv) =
                        unsafe { (&*name.cast::<[u8; 16]>(), &*iv.cast::<[u8; 16]>()) };
                    let Some((key, renewal)) = provider.decryption_key(ssl, name)? else {
                        return Ok(0);
                    };
                    if key.name() != name {
                        return Err(ErrorStack::internal_error_str(
                            "ticket provider returned a different key name",
                        ));
                    }
                    key.configure(cipher, hmac, Mode::Decrypt, iv)?;
                    Ok(match renewal {
                        TicketRenewal::Keep => 1,
                        TicketRenewal::Renew => 2,
                    })
                }
                _ => Err(ErrorStack::internal_error_str(
                    "invalid native ticket callback mode",
                )),
            }
        })();
        match result {
            Ok(status) => status,
            Err(error) => {
                error.put();
                -1
            }
        }
    })
    .unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_key_lengths_and_shared_secret_ownership() {
        for len in [16, 24, 32] {
            let key = TicketKey::from_keys([1; 16], &[2; 32][..len], &[3; 32]).unwrap();
            assert_eq!(key.name(), &[1; 16]);
            assert_eq!(key.cipher.key_len(), len);
            let clone = key.clone();
            assert!(Arc::ptr_eq(&key.keys, &clone.keys));
            assert!(format!("{key:?}").contains("[redacted]"));
        }
        for len in [0, 15, 17, 23, 25, 31, 33] {
            assert!(TicketKey::from_keys([0; 16], &vec![0; len], &[0; 32]).is_err());
        }
        assert!(TicketKey::from_keys([0; 16], &[0; 32], &[0; 15]).is_err());
        let generated = TicketKey::generate().unwrap();
        assert_eq!(generated.cipher.key_len(), 32);
        assert_eq!(generated.keys.len(), 64);
    }
}
