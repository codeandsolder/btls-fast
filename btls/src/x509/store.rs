//! Describe a context in which to verify an `X509` certificate.
//!
//! The `X509` certificate store holds trusted CA certificates used to verify
//! peer certificates.
//!
//! # Example
//!
//! ```rust
//! use btls::x509::store::{X509StoreBuilder, X509Store};
//! use btls::x509::{X509, X509Name};
//! use btls::asn1::Asn1Time;
//! use btls::pkey::PKey;
//! use btls::hash::MessageDigest;
//! use btls::rsa::Rsa;
//! use btls::nid::Nid;
//!
//! let rsa = Rsa::generate(2048).unwrap();
//! let pkey = PKey::from_rsa(rsa).unwrap();
//! let mut name = X509Name::builder().unwrap();
//!
//! name.append_entry_by_nid(Nid::COMMONNAME, "foobar.com").unwrap();
//!
//! let name = name.build().unwrap();
//! let mut builder = X509::builder().unwrap();
//!
//! // Sep 27th, 2016
//! let sample_time = Asn1Time::from_unix(1474934400).unwrap();
//!
//! builder.set_version(2).unwrap();
//! builder.set_subject_name(&name).unwrap();
//! builder.set_issuer_name(&name).unwrap();
//! builder.set_pubkey(&pkey).unwrap();
//! builder.set_not_before(&sample_time);
//! builder.set_not_after(&sample_time);
//! builder.sign(&pkey, MessageDigest::sha256()).unwrap();
//!
//! let certificate: X509 = builder.build();
//! let mut builder = X509StoreBuilder::new().unwrap();
//! let _ = builder.add_cert(&certificate);
//! let store: X509Store = builder.build();
//! ```

use crate::error::ErrorStack;
use crate::ffi;
use crate::stack::Stack;
use crate::x509::verify::{X509VerifyFlags, X509VerifyParamRef};
use crate::x509::{X509Object, X509Ref};
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::mem::ManuallyDrop;

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_STORE;
    fn drop = ffi::X509_STORE_free;

    /// A builder type used to construct an `X509Store`.
    pub struct X509StoreBuilder;
}

impl X509StoreBuilder {
    /// Returns a builder for a certificate store.
    ///
    /// The store is initially empty.
    ///
    /// # Errors
    ///
    /// Native certificate-store allocation fails.
    pub fn new() -> Result<Self, ErrorStack> {
        // SAFETY: the native constructor returns an owned store pointer or
        // null; `cvt_p` checks the allocation before ownership transfer.
        unsafe {
            ffi::init();

            cvt_p(ffi::X509_STORE_new()).map(|p| Self::from_ptr(p))
        }
    }

    /// Constructs the `X509Store`.
    #[must_use = "The returned owned value is the result of consuming the original owner."]
    pub fn build(self) -> X509Store {
        X509Store(ManuallyDrop::new(self).0)
    }
}

impl X509StoreBuilderRef {
    /// Adds a certificate to the certificate store.
    ///
    /// # Errors
    ///
    /// The native store cannot retain the certificate (including duplicates).
    #[corresponds(X509_STORE_add_cert)]
    pub fn add_cert(&mut self, cert: impl AsRef<X509Ref>) -> Result<(), ErrorStack> {
        let cert = cert.as_ref();
        // SAFETY: both the exclusively borrowed store and the certificate are
        // live; native insertion retains its own certificate reference.
        unsafe { cvt(ffi::X509_STORE_add_cert(self.as_ptr(), cert.as_ptr())) }
    }

    /// Load certificates from their default locations.
    ///
    /// These locations are read from the `SSL_CERT_FILE` and `SSL_CERT_DIR`
    /// environment variables if present, or defaults specified at OpenSSL
    /// build time otherwise.
    ///
    /// # Errors
    ///
    /// Native trust-path initialization fails.
    #[corresponds(X509_STORE_set_default_paths)]
    pub fn set_default_paths(&mut self) -> Result<(), ErrorStack> {
        // SAFETY: the native store is exclusively borrowed while its trust
        // path configuration is updated synchronously.
        unsafe { cvt(ffi::X509_STORE_set_default_paths(self.as_ptr())) }
    }

    /// Sets certificate chain validation flags on this store.
    ///
    /// # Errors
    ///
    /// Returns an error if native certificate-store configuration fails.
    #[corresponds(X509_STORE_set_flags)]
    pub fn set_flags(&mut self, flags: X509VerifyFlags) -> Result<(), ErrorStack> {
        // SAFETY: the native certificate store is exclusively borrowed.
        unsafe { cvt(ffi::X509_STORE_set_flags(self.as_ptr(), flags.bits())) }
    }

    /// Returns a mutable reference to the X509 verification configuration.
    #[corresponds(X509_STORE_get0_param)]
    pub fn verify_param_mut(&mut self) -> &mut X509VerifyParamRef {
        // SAFETY: the owned store keeps an initialized verification parameter
        // alive, and the mutable store borrow guarantees exclusive access.
        unsafe { X509VerifyParamRef::from_ptr_mut(ffi::X509_STORE_get0_param(self.as_ptr())) }
    }

    /// Sets certificate chain validation related parameters.
    ///
    /// # Errors
    ///
    /// Native verification-parameter copying fails.
    #[corresponds(X509_STORE_set1_param)]
    pub fn set_param(&mut self, param: &X509VerifyParamRef) -> Result<(), ErrorStack> {
        // SAFETY: the native store and borrowed parameters remain live while
        // the native setter takes its own copy.
        unsafe { cvt(ffi::X509_STORE_set1_param(self.as_ptr(), param.as_ptr())) }
    }

    /// Returns an owned snapshot of the certificates and CRLs currently cached.
    /// Subsequent native cache mutations do not invalidate this snapshot.
    ///
    /// # Errors
    ///
    /// The native store cannot allocate the owned snapshot.
    pub fn objects(&self) -> Result<Stack<X509Object>, ErrorStack> {
        snapshot_objects(self.as_ptr())
    }

    #[cfg(test)]
    pub fn objects_len(&self) -> usize {
        self.objects().unwrap().len()
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_STORE;
    fn drop = ffi::X509_STORE_free;

    /// A certificate store to hold trusted `X509` certificates.
    pub struct X509Store;
}

impl ToOwned for X509StoreRef {
    type Owned = X509Store;

    fn to_owned(&self) -> X509Store {
        // SAFETY: the borrowed store remains live; increment the native
        // reference count before creating another owning wrapper.
        unsafe {
            ffi::X509_STORE_up_ref(self.as_ptr());
            X509Store::from_ptr(self.as_ptr())
        }
    }
}

impl Clone for X509Store {
    fn clone(&self) -> Self {
        (**self).to_owned()
    }
}

impl X509StoreRef {
    /// Returns an owned snapshot of the certificates and CRLs currently cached.
    /// The snapshot is independent of later native cache mutations and store destruction.
    ///
    /// # Errors
    ///
    /// The native store cannot allocate the owned snapshot.
    #[corresponds(X509_STORE_get1_objects)]
    pub fn objects(&self) -> Result<Stack<X509Object>, ErrorStack> {
        snapshot_objects(self.as_ptr())
    }

    #[cfg(test)]
    pub fn objects_len(&self) -> usize {
        self.objects().unwrap().len()
    }
}

// SAFETY: callers pass a live store pointer for the duration of the call.
// The native function takes the cache lock and transfers ownership of the
// returned stack and its elements, or returns null on failure.
fn snapshot_objects(store: *mut ffi::X509_STORE) -> Result<Stack<X509Object>, ErrorStack> {
    // SAFETY: The two private call sites borrow live owned store wrappers.
    unsafe { cvt_p(ffi::X509_STORE_get1_objects(store)).map(|p| Stack::from_ptr(p)) }
}

#[test]
fn owned_store_snapshot_survives_mutation_and_destruction() -> Result<(), ErrorStack> {
    use crate::x509::X509;

    let mut store = X509StoreBuilder::new()?;
    let cert = X509::from_pem(include_bytes!("../../test/cert.pem"))?;
    let second = X509::from_pem(include_bytes!("../../test/root-ca.pem"))?;
    store.add_cert(&cert)?;
    let snapshot = store.objects()?;
    store.add_cert(second)?;
    assert_eq!(store.objects()?.len(), 2);
    drop(store);
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].x509().unwrap().to_der()?, cert.to_der()?);
    Ok(())
}

#[test]
#[should_panic(expected = "Shared X509Store can't be mutated")]
fn set_cert_store_prevents_mutability() {
    use crate::ssl::*;

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let store = X509StoreBuilder::new().unwrap().build();

    ctx.set_cert_store_ref(&store);
    assert!(std::ptr::eq(ctx.cert_store().as_ptr(), store.as_ptr()));
    let _aliased_store = ctx.cert_store_mut();
}
