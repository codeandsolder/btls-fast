#[cfg(feature = "rpk")]
use crate::cvt_p;
use crate::error::ErrorStack;
use crate::ex_data::{Index, IndexRegistry};
use crate::pkey::{PKeyRef, Private};
use crate::ssl::PrivateKeyMethod;
use crate::ssl::callbacks;
use crate::{cvt_0i, cvt_n};
use crate::{ffi, free_data_box};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::ffi::c_int;
use std::ptr;
use std::sync::{Arc, LazyLock};

static SSL_CREDENTIAL_INDEXES: LazyLock<IndexRegistry<SslCredential, ()>> =
    LazyLock::new(IndexRegistry::new);

foreign_type_and_impl_send_sync! {
    type CType = ffi::SSL_CREDENTIAL;
    fn drop = ffi::SSL_CREDENTIAL_free;

    /// A credential.
    pub struct SslCredential;
}

impl SslCredential {
    /// Creates a credential for a raw-public-key handshake.
    ///
    /// # Errors
    ///
    /// Native credential allocation fails.
    #[corresponds(SSL_CREDENTIAL_new_raw_public_key_empty)]
    #[cfg(feature = "rpk")]
    pub fn new_raw_public_key() -> Result<SslCredentialBuilder, ErrorStack> {
        // SAFETY: the native constructor returns an owned credential or null;
        // `cvt_p` rejects null before ownership passes to the builder.
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
    ///
    /// # Errors
    ///
    /// Native extra-data index allocation fails.
    #[corresponds(SSL_C_get_ex_new_index)]
    pub fn new_ex_index<T>() -> Result<Index<Self, T>, ErrorStack>
    where
        T: 'static + Sync + Send,
    {
        // SAFETY: the registered free callback matches `T`; the native index
        // is checked before being wrapped in its typed Rust representation.
        unsafe {
            ffi::init();
            let idx = cvt_n(get_new_ssl_credential_idx(Some(free_data_box::<T>)))?;
            Ok(Index::from_raw(idx))
        }
    }

    pub(super) fn register_callback<T: 'static + Send + Sync>() -> Result<Index<Self, T>, ErrorStack>
    {
        SSL_CREDENTIAL_INDEXES.register((), Self::new_ex_index)
    }

    pub(super) fn registered_ex_index<T: 'static + Send + Sync>() -> Option<Index<Self, T>> {
        SSL_CREDENTIAL_INDEXES.get(())
    }
}

impl SslCredentialRef {
    /// Returns a reference to the extra data at the specified index.
    #[corresponds(SSL_CREDENTIAL_get_ex_data)]
    #[must_use = "Use the returned application data, or handle an empty slot."]
    pub fn ex_data<T: 'static + Send + Sync>(&self, index: Index<SslCredential, T>) -> Option<&T> {
        // SAFETY: `index` identifies a typed, registered native slot. The
        // borrowed credential owns any non-null allocation for this lifetime.
        unsafe {
            let data = ffi::SSL_CREDENTIAL_get_ex_data(self.as_ptr(), index.as_raw());
            if data.is_null() {
                None
            } else {
                Some(&*(data as *const T))
            }
        }
    }

    // Only an unpublished, uniquely owned credential builder may mutate data.
    #[corresponds(SSL_CREDENTIAL_set_ex_data)]
    unsafe fn replace_ex_data<T: 'static + Send + Sync>(
        &mut self,
        index: Index<SslCredential, T>,
        data: T,
    ) -> Result<Option<T>, ErrorStack> {
        let cred = self.as_ptr();
        // SAFETY: the caller establishes exclusive ownership and the typed
        // slot; the native setter accepts ownership only on success.
        unsafe {
            crate::ex_data::replace_boxed(
                ffi::SSL_CREDENTIAL_get_ex_data(cred, index.as_raw()),
                data,
                |ptr| {
                    cvt_0i(ffi::SSL_CREDENTIAL_set_ex_data(cred, index.as_raw(), ptr)).map(|_| ())
                },
            )
        }
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
    ///
    /// # Errors
    ///
    /// Native extra-data allocation or replacement fails.
    #[corresponds(SSL_CREDENTIAL_set_ex_data)]
    pub fn replace_ex_data<T: 'static + Send + Sync>(
        &mut self,
        index: Index<SslCredential, T>,
        data: T,
    ) -> Result<Option<T>, ErrorStack> {
        // SAFETY: only the builder owns the credential before publication.
        unsafe { self.0.replace_ex_data(index, data) }
    }

    /// Sets the credential's private key.
    ///
    /// # Errors
    ///
    /// BoringSSL rejects the key or cannot retain its reference.
    #[corresponds(SSL_CREDENTIAL_set1_private_key)]
    pub fn set_private_key(&mut self, private_key: &PKeyRef<Private>) -> Result<(), ErrorStack> {
        // SAFETY: the builder owns its credential uniquely and the borrowed
        // private key remains live while BoringSSL retains its own reference.
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
    ///
    /// # Errors
    ///
    /// Typed callback storage allocation or native registration fails.
    #[corresponds(SSL_CREDENTIAL_set_private_key_method)]
    pub fn set_private_key_method<M>(&mut self, method: M) -> Result<(), ErrorStack>
    where
        M: PrivateKeyMethod,
    {
        // SAFETY: the unpublished credential exclusively owns its callback
        // state. BoringSSL retains the monomorphized static method descriptor,
        // not a temporary stack allocation.
        unsafe {
            self.replace_ex_data(
                SslCredential::register_callback::<Arc<M>>()?,
                Arc::new(method),
            )?;

            cvt_0i(ffi::SSL_CREDENTIAL_set_private_key_method(
                self.0.as_ptr(),
                callbacks::PrivateKeyMethodDescriptor::<M, true>::descriptor(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the SPKI of the raw public key credential.
    ///
    /// If `spki` is `None`, the SPKI is extracted from the credential's private key.
    ///
    /// # Errors
    ///
    /// Native SPKI-buffer creation or credential configuration fails.
    #[corresponds(SSL_CREDENTIAL_set1_spki)]
    #[cfg(feature = "rpk")]
    pub fn set_spki_bytes(&mut self, spki: Option<&[u8]>) -> Result<(), ErrorStack> {
        // SAFETY: the source slice remains live during native buffer creation;
        // the native setter retains its own reference if successful. The
        // temporary CRYPTO_BUFFER is freed exactly once on either result.
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
