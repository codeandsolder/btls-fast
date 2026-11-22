#[cfg(feature = "rpk")]
use crate::cvt_p;
use crate::error::ErrorStack;
use crate::ex_data::Index;
use crate::pkey::{PKeyRef, Private};
use crate::ssl::callbacks;
use crate::ssl::PrivateKeyMethod;
use crate::{cvt_0i, cvt_n};
use crate::{ffi, free_data_box};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::any::TypeId;
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::mem;
use std::ptr;
use std::sync::{Arc, LazyLock, Mutex};

static SSL_CREDENTIAL_INDEXES: LazyLock<Mutex<HashMap<TypeId, c_int>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

foreign_type_and_impl_send_sync! {
    type CType = ffi::SSL_CREDENTIAL;
    fn drop = ffi::SSL_CREDENTIAL_free;

    /// A credential.
    pub struct SslCredential;
}

impl SslCredential {
    /// Create a credential suitable for a handshake using a raw public key.
    #[corresponds(SSL_CREDENTIAL_new_raw_public_key_empty)]
    #[cfg(feature = "rpk")]
    pub fn new_raw_public_key() -> Result<SslCredentialBuilder, ErrorStack> {
        unsafe {
            Ok(SslCredentialBuilder(Self::from_ptr(cvt_p(
                ffi::SSL_CREDENTIAL_new_raw_public_key_empty(),
            )?)))
        }
    }

    /// Returns a new extra data index.
    ///
    /// Each invocation of this function is guaranteed to return a distinct index. These can be used
    /// to store data in the context that can be retrieved later by callbacks, for example.
    #[corresponds(SSL_C_get_ex_new_index)]
    pub fn new_ex_index<T>() -> Result<Index<Self, T>, ErrorStack>
    where
        T: 'static + Sync + Send,
    {
        unsafe {
            ffi::init();
            let idx = cvt_n(get_new_ssl_credential_idx(Some(free_data_box::<T>)))?;
            Ok(Index::from_raw(idx))
        }
    }

    pub(crate) fn cached_ex_index<T>() -> Result<Index<Self, T>, ErrorStack>
    where
        T: 'static + Sync + Send,
    {
        use std::collections::hash_map::Entry;
        let mut indexes = SSL_CREDENTIAL_INDEXES
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let idx = match indexes.entry(TypeId::of::<T>()) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => *entry.insert(Self::new_ex_index::<T>()?.as_raw()),
        };
        // SAFETY: each type ID is associated only with an index allocated for T.
        Ok(unsafe { Index::from_raw(idx) })
    }

    pub(crate) fn registered_ex_index<T: 'static>() -> Option<Index<Self, T>> {
        let indexes = SSL_CREDENTIAL_INDEXES
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let &idx = indexes.get(&TypeId::of::<T>())?;
        // SAFETY: only cached_ex_index can insert a slot for T.
        Some(unsafe { Index::from_raw(idx) })
    }
}

impl SslCredentialRef {
    /// Returns a reference to the extra data at the specified index.
    #[corresponds(SSL_CREDENTIAL_get_ex_data)]
    #[must_use = "Use the returned application data, or handle an empty slot."]
    pub fn ex_data<T>(&self, index: Index<SslCredential, T>) -> Option<&T> {
        unsafe {
            let data = ffi::SSL_CREDENTIAL_get_ex_data(self.as_ptr(), index.as_raw());
            if data.is_null() {
                None
            } else {
                Some(&*(data as *const T))
            }
        }
    }

    // Unsafe because SSL contexts are not guaranteed to be unique, we call
    // this only from SslCredentialBuilder.
    #[corresponds(SSL_CREDENTIAL_get_ex_data)]
    pub(crate) unsafe fn ex_data_mut<T>(
        &mut self,
        index: Index<SslCredential, T>,
    ) -> Option<&mut T> {
        // SAFETY: the caller guarantees unique access to the credential and
        // the typed index identifies the allocation of T.
        unsafe {
            ffi::SSL_CREDENTIAL_get_ex_data(self.as_ptr(), index.as_raw())
                .cast::<T>()
                .as_mut()
        }
    }

    // Unsafe because SSL contexts are not guaranteed to be unique, we call
    // this only from SslCredentialBuilder.
    #[corresponds(SSL_CREDENTIAL_set_ex_data)]
    pub(crate) unsafe fn replace_ex_data<T>(
        &mut self,
        index: Index<SslCredential, T>,
        data: T,
    ) -> Result<Option<T>, ErrorStack> {
        // SAFETY: the caller holds exclusive access to this credential.
        if let Some(old) = unsafe { self.ex_data_mut(index) } {
            return Ok(Some(mem::replace(old, data)));
        }

        // Keep ownership until the native setter has accepted the pointer.
        let mut data = Box::new(data);
        // SAFETY: the pointer identifies the owned value of T; the registered
        // native free callback takes ownership only after a successful setter.
        unsafe {
            cvt_0i(ffi::SSL_CREDENTIAL_set_ex_data(
                self.as_ptr(),
                index.as_raw(),
                ptr::from_mut(&mut *data).cast::<c_void>(),
            ))?;
        }
        let _ = Box::into_raw(data);
        Ok(None)
    }
}

/// A builder for [`SslCredential`]
pub struct SslCredentialBuilder(SslCredential);

impl SslCredentialBuilder {
    /// Sets or overwrites the extra data at the specified index.
    ///
    /// This can be used to provide data to callbacks registered with the context. Use the
    /// `SslCredential::new_ex_index` method to create an `Index`.
    ///
    /// Any previous value will be returned and replaced by the new one.
    #[corresponds(SSL_CREDENTIAL_set_ex_data)]
    pub fn replace_ex_data<T>(
        &mut self,
        index: Index<SslCredential, T>,
        data: T,
    ) -> Result<Option<T>, ErrorStack> {
        // SAFETY: only the builder owns the credential before publication.
        unsafe { self.0.replace_ex_data(index, data) }
    }

    // Sets the private key of the credential.
    #[corresponds(SSL_CREDENTIAL_set1_private_key)]
    pub fn set_private_key(&mut self, private_key: &PKeyRef<Private>) -> Result<(), ErrorStack> {
        unsafe {
            cvt_0i(ffi::SSL_CREDENTIAL_set1_private_key(
                self.0.as_ptr(),
                private_key.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Configures a custom private key method on the credential.
    ///
    /// See [`PrivateKeyMethod`] for more details.
    #[corresponds(SSL_CREDENTIAL_set_private_key_method)]
    pub fn set_private_key_method<M>(&mut self, method: M) -> Result<(), ErrorStack>
    where
        M: PrivateKeyMethod,
    {
        unsafe {
            self.replace_ex_data(
                SslCredential::cached_ex_index::<Arc<M>>()?,
                Arc::new(method),
            )?;

            cvt_0i(ffi::SSL_CREDENTIAL_set_private_key_method(
                self.0.as_ptr(),
                &ffi::SSL_PRIVATE_KEY_METHOD {
                    sign: Some(callbacks::raw_sign::<M, true>),
                    decrypt: Some(callbacks::raw_decrypt::<M, true>),
                    complete: Some(callbacks::raw_complete::<M, true>),
                },
            ))
            .map(|_| ())
        }
    }

    /// Sets the SPKI of the raw public key credential.
    ///
    /// If `spki` is `None`, the SPKI is extracted from the credential's private key.
    #[corresponds(SSL_CREDENTIAL_set1_spki)]
    #[cfg(feature = "rpk")]
    pub fn set_spki_bytes(&mut self, spki: Option<&[u8]>) -> Result<(), ErrorStack> {
        unsafe {
            let spki = spki
                .map(|spki| {
                    cvt_p(ffi::CRYPTO_BUFFER_new(
                        spki.as_ptr(),
                        spki.len(),
                        ptr::null_mut(),
                    ))
                })
                .transpose()?
                .unwrap_or(ptr::null_mut());

            let ret = cvt_0i(ffi::SSL_CREDENTIAL_set1_spki(self.0.as_ptr(), spki)).map(|_| ());

            if !spki.is_null() {
                ffi::CRYPTO_BUFFER_free(spki);
            }

            ret
        }
    }

    #[must_use = "The returned owned value is the result of consuming the original owner."]
    pub fn build(self) -> SslCredential {
        self.0
    }
}

unsafe fn get_new_ssl_credential_idx(f: ffi::CRYPTO_EX_free) -> c_int {
    // SAFETY: the free callback matches the type attached to the new slot.
    unsafe { ffi::SSL_CREDENTIAL_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, f) }
}

#[cfg(all(test, feature = "rpk"))]
mod tests {
    use super::*;
    use crate::ec::{EcGroup, EcKey};
    use crate::nid::Nid;
    use crate::pkey::PKey;

    fn generate_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        PKey::from_ec_key(ec_key).unwrap()
    }

    fn spki_from_pkey(pkey: &PKey<Private>) -> Vec<u8> {
        pkey.public_key_to_der().unwrap()
    }

    #[test]
    fn set_spki_bytes_none_derives_from_private_key() {
        let key = generate_key();

        let mut cred = SslCredential::new_raw_public_key().unwrap();
        cred.set_private_key(&key).unwrap();
        // With a private key set, passing `None` should succeed and derive the
        // SPKI from the private key.
        cred.set_spki_bytes(None).unwrap();
    }

    #[test]
    fn set_spki_bytes_none_without_private_key_fails() {
        let mut cred = SslCredential::new_raw_public_key().unwrap();
        // Without a private key, passing `None` should return an error.
        let err = cred.set_spki_bytes(None).unwrap_err();
        assert!(!err.errors().is_empty());
    }

    #[test]
    fn set_spki_bytes_some_matching_private_key_succeeds() {
        let key = generate_key();
        let spki = spki_from_pkey(&key);

        let mut cred = SslCredential::new_raw_public_key().unwrap();
        cred.set_private_key(&key).unwrap();
        cred.set_spki_bytes(Some(&spki)).unwrap();
    }

    #[test]
    fn set_spki_bytes_some_mismatched_private_key_fails() {
        let key = generate_key();
        let other_key = generate_key();
        let wrong_spki = spki_from_pkey(&other_key);

        let mut cred = SslCredential::new_raw_public_key().unwrap();
        cred.set_private_key(&key).unwrap();
        // The public key derived from `wrong_spki` does not match the
        // configured private key, so this must fail.
        let err = cred.set_spki_bytes(Some(&wrong_spki)).unwrap_err();
        assert!(!err.errors().is_empty());
    }
}
