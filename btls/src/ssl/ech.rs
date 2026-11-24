use crate::ffi;
use foreign_types::ForeignType;
use libc::c_int;

use crate::error::ErrorStack;
use crate::hpke::HpkeKey;
use crate::{cvt_0i, cvt_p};

pub struct SslEchKeysBuilder {
    keys: SslEchKeys,
}

impl SslEchKeysBuilder {
    /// Creates a native ECH key-set builder.
    ///
    /// # Errors
    ///
    /// Native ECH key-set allocation fails.
    pub fn new() -> Result<Self, ErrorStack> {
        // SAFETY: `SSL_ECH_KEYS_new` returns a newly owned key set or null;
        // `cvt_p` checks allocation before ownership moves into `SslEchKeys`.
        unsafe {
            ffi::init();
            let keys = cvt_p(ffi::SSL_ECH_KEYS_new())?;

            Ok(Self {
                keys: SslEchKeys::from_ptr(keys),
            })
        }
    }

    /// Adds an ECH configuration paired with its HPKE private key.
    ///
    /// # Errors
    ///
    /// Native ECH configuration decoding or key registration fails.
    pub fn add_key(
        &mut self,
        is_retry_config: bool,
        ech_config: &[u8],
        key: &HpkeKey,
    ) -> Result<(), ErrorStack> {
        // SAFETY: the builder exclusively owns an unpublished key set. Both
        // borrowed inputs are valid through this synchronous native call;
        // BoringSSL copies the configuration and retains the private key.
        unsafe {
            cvt_0i(ffi::SSL_ECH_KEYS_add(
                self.keys.as_ptr(),
                c_int::from(is_retry_config),
                ech_config.as_ptr(),
                ech_config.len(),
                key.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    pub fn build(self) -> SslEchKeys {
        self.keys
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::SSL_ECH_KEYS;
    fn drop = ffi::SSL_ECH_KEYS_free;

    pub struct SslEchKeys;
}

impl SslEchKeys {
    /// Creates a builder for the native ECH key set.
    ///
    /// # Errors
    ///
    /// Native key-set allocation fails.
    pub fn builder() -> Result<SslEchKeysBuilder, ErrorStack> {
        SslEchKeysBuilder::new()
    }
}
