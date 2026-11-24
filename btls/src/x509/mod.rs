//! The standard defining the format of public key certificates.
//!
//! An `X509` certificate binds an identity to a public key, and is either
//! signed by a certificate authority (CA) or self-signed. An entity that gets
//! a hold of a certificate can both verify your identity (via a CA) and encrypt
//! data with the included public key. `X509` certificates are used in many
//! Internet protocols, including SSL/TLS, which is the basis for HTTPS,
//! the secure protocol for browsing the web.

use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_long, c_void};
use openssl_macros::corresponds;
use std::convert::TryInto;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::net::IpAddr;
use std::path::Path;
use std::ptr;
use std::str;

use crate::asn1::{
    Asn1BitStringRef, Asn1IntegerRef, Asn1Object, Asn1ObjectRef, Asn1StringRef, Asn1TimeRef,
    Asn1Type,
};
use crate::bio::{MemBio, MemBioSlice};
use crate::conf::ConfRef;
use crate::error::ErrorStack;
use crate::ex_data::{Index, IndexSlot, replace_boxed};
use crate::hash::{DigestBytes, MessageDigest};
use crate::nid::Nid;
use crate::pkey::{HasPrivate, HasPublic, PKey, PKeyRef, Public};
use crate::ssl::SslRef;
use crate::stack::{Stack, StackRef, Stackable};
use crate::string::OpensslString;
use crate::try_int;
use crate::util::ForeignTypeRefExt;
use crate::x509::verify::{X509CheckFlags, X509VerifyParam, X509VerifyParamRef};
use crate::{cvt, cvt_n, cvt_p};
use crate::{ffi, free_data_box};

// Both certificate builders expose the same native version-setting contract.
macro_rules! version_setter {
    ($(#[$attr:meta])* $setter:ident) => {
        $(#[$attr])*
        #[corresponds($setter)]
        pub fn set_version(&mut self, version: c_long) -> Result<(), ErrorStack> {
            // SAFETY: The builder owns a live native object and is exclusively borrowed.
            unsafe { cvt(ffi::$setter(self.0.as_ptr(), version)) }
        }
    };
}

pub mod extension;
pub mod store;
pub mod verify;

#[cfg(test)]
mod tests;

struct ContextInputs {
    trust: store::X509Store,
    cert: X509,
    chain: Stack<X509>,
}

static CONTEXT_INPUTS_INDEX: IndexSlot<X509StoreContext, ContextInputs> =
    IndexSlot::new(X509StoreContext::new_ex_index);

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_STORE_CTX;
    fn drop = ffi::X509_STORE_CTX_free;

    /// An `X509` certificate store context.
    pub struct X509StoreContext;
}

impl X509StoreContext {
    /// Creates a new `X509StoreContext` instance.
    #[corresponds(X509_STORE_CTX_new)]
    pub fn new() -> Result<Self, ErrorStack> {
        // SAFETY: The native initializer returns an owned context or null; `cvt_p` rejects null before wrapping ownership.
        unsafe {
            ffi::init();
            cvt_p(ffi::X509_STORE_CTX_new()).map(|p| Self::from_ptr(p))
        }
    }

    /// Returns a new extra data index.
    ///
    /// Each invocation of this function is guaranteed to return a distinct index. These can be used
    /// to store data in the context that can be retrieved later by callbacks, for example.
    #[corresponds(SSL_CTX_get_ex_new_index)]
    pub fn new_ex_index<T>() -> Result<Index<Self, T>, ErrorStack>
    where
        T: 'static + Sync + Send,
    {
        // SAFETY: The global index allocator receives a matching typed free callback and yields a validated nonnegative slot.
        unsafe {
            ffi::init();
            let idx = cvt_n(get_new_x509_store_ctx_idx(Some(free_data_box::<T>)))?;
            Ok(Index::from_raw(idx))
        }
    }
}

impl X509StoreContextRef {
    /// Returns the SSL connection associated with a native certificate
    /// verification callback, if present.
    ///
    /// The native reserved slot borrows the connection and does not own a
    /// boxed application value; it must never expose mutable SSL access.
    #[must_use = "Use the associated connection to inspect verification context."]
    pub fn ssl(&self) -> Option<&SslRef> {
        // SAFETY: BoringSSL reserves this index for a borrowed live SSL
        // during certificate verification; no safe setter can access it.
        unsafe {
            let ptr = ffi::X509_STORE_CTX_get_ex_data(
                self.as_ptr(),
                ffi::SSL_get_ex_data_X509_STORE_CTX_idx(),
            );
            SslRef::from_const_ptr_opt(ptr.cast())
        }
    }

    /// Returns application data pertaining to this certificate store context.
    #[corresponds(X509_STORE_CTX_get_ex_data)]
    #[must_use = "Use the returned application data, or handle an empty slot."]
    pub fn ex_data<T: 'static + Send + Sync>(
        &self,
        index: Index<X509StoreContext, T>,
    ) -> Option<&T> {
        // SAFETY: index identifies a registered boxed T; the native object
        // keeps the allocation alive throughout the shared borrow.
        unsafe {
            ffi::X509_STORE_CTX_get_ex_data(self.as_ptr(), index.as_raw())
                .cast::<T>()
                .as_ref()
        }
    }

    /// Returns a mutable reference to registered application data.
    #[corresponds(X509_STORE_CTX_get_ex_data)]
    pub fn ex_data_mut<T: 'static + Send + Sync>(
        &mut self,
        index: Index<X509StoreContext, T>,
    ) -> Option<&mut T> {
        // SAFETY: exclusive context access guarantees exclusive application
        // data access; reserved native borrowed-pointer slots are excluded.
        unsafe {
            ffi::X509_STORE_CTX_get_ex_data(self.as_ptr(), index.as_raw())
                .cast::<T>()
                .as_mut()
        }
    }

    /// Sets or overwrites application data at a registered extra-data index.
    ///
    /// # Errors
    ///
    /// The native container cannot allocate the slot.
    #[corresponds(X509_STORE_CTX_set_ex_data)]
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "the native extra-data setter mutates the context; exclusive access is required"
    )]
    pub fn set_ex_data<T: 'static + Send + Sync>(
        &mut self,
        index: Index<X509StoreContext, T>,
        data: T,
    ) -> Result<(), ErrorStack> {
        let ctx = self.as_ptr();
        // SAFETY: the exclusive context and typed owned index establish the
        // matching boxed slot; the native setter accepts ownership on success.
        unsafe {
            replace_boxed(
                ffi::X509_STORE_CTX_get_ex_data(ctx, index.as_raw()),
                data,
                |ptr| cvt(ffi::X509_STORE_CTX_set_ex_data(ctx, index.as_raw(), ptr)),
            )?;
        }
        Ok(())
    }

    /// Returns the verify result of the context.
    #[corresponds(X509_STORE_CTX_get_error)]
    pub fn verify_result(&self) -> X509VerifyResult {
        // SAFETY: The live store context returns an integer error code; decoding it does not borrow native storage.
        unsafe { X509VerifyError::from_raw(ffi::X509_STORE_CTX_get_error(self.as_ptr())) }
    }
}

impl X509StoreContext {
    /// Initializes this context with the given certificate, certificates chain and certificate
    /// store. After initializing the context, the `with_context` closure is called with the prepared
    /// context. As long as the closure is running, the context stays initialized and can be used
    /// to e.g. verify a certificate. The context will be cleaned up, after the closure finished.
    ///
    /// * `trust` - The certificate store with the trusted certificates.
    /// * `cert` - The certificate that should be verified.
    /// * `cert_chain` - The certificates chain.
    /// * `with_context` - The closure that is called with the initialized context.
    ///
    /// Calls [`X509_STORE_CTX_cleanup`] after calling `with_context`.
    ///
    /// [`X509_STORE_CTX_cleanup`]:  https://www.openssl.org/docs/man1.0.2/crypto/X509_STORE_CTX_cleanup.html
    #[corresponds(X509_STORE_CTX_init)]
    pub fn init<F, T>(
        &mut self,
        trust: &store::X509StoreRef,
        cert: &X509Ref,
        cert_chain: &StackRef<X509>,
        with_context: F,
    ) -> Result<T, ErrorStack>
    where
        F: FnOnce(&mut X509StoreContextRef) -> Result<T, ErrorStack>,
    {
        struct Cleanup<'a>(&'a mut X509StoreContextRef);

        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                // SAFETY: The guard owns the initialized store context; native cleanup runs exactly once on scope exit.
                unsafe {
                    ffi::X509_STORE_CTX_cleanup(self.0.as_ptr());
                }
            }
        }

        // SAFETY: The borrowed trust store, certificate and chain remain live throughout the callback and the scoped cleanup guard.
        unsafe {
            let cleanup = Cleanup(self);

            cvt(ffi::X509_STORE_CTX_init(
                cleanup.0.as_ptr(),
                trust.as_ptr(),
                cert.as_ptr(),
                cert_chain.as_ptr(),
            ))?;

            with_context(cleanup.0)
        }
    }

    /// Initializes this context with the given certificate, certificates chain and certificate
    /// store.
    ///
    /// * `trust` - The certificate store with the trusted certificates.
    /// * `cert` - The certificate that should be verified.
    /// * `cert_chain` - The certificates chain.
    #[corresponds(X509_STORE_CTX_init)]
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "the native context is reinitialized in place and must be exclusively borrowed"
    )]
    pub fn reset_with_context_data(
        &mut self,
        trust: store::X509Store,
        cert: X509,
        cert_chain: Stack<X509>,
    ) -> Result<(), ErrorStack> {
        // Allocate the typed slot and owner before modifying native context.
        let index = CONTEXT_INPUTS_INDEX.register()?;
        let inputs = Box::new(ContextInputs {
            trust,
            cert,
            chain: cert_chain,
        });
        let ctx = self.as_ptr();
        // SAFETY: self owns the context; inputs remain alive until the
        // native initialization and installation both succeed or are cleaned up.
        unsafe {
            cvt(ffi::X509_STORE_CTX_init(
                ctx,
                inputs.trust.as_ptr(),
                inputs.cert.as_ptr(),
                inputs.chain.as_ptr(),
            ))?;
            let owner = Box::into_raw(inputs);
            if let Err(error) = cvt(ffi::X509_STORE_CTX_set_ex_data(
                ctx,
                index.as_raw(),
                owner.cast(),
            )) {
                ffi::X509_STORE_CTX_cleanup(ctx);
                drop(Box::from_raw(owner));
                return Err(error);
            }
        }
        Ok(())
    }
}

impl X509StoreContextRef {
    /// Returns a reference to the X509 verification configuration.
    #[corresponds(X509_STORE_CTX_get0_param)]
    #[must_use = "Inspect or retain the borrowed verification parameters."]
    pub fn verify_param(&self) -> Option<&X509VerifyParamRef> {
        // SAFETY: the parameter, if initialized, is owned by this context.
        unsafe {
            X509VerifyParamRef::from_const_ptr_opt(ffi::X509_STORE_CTX_get0_param(self.as_ptr()))
        }
    }

    /// Returns a mutable reference to the X509 verification configuration.
    #[corresponds(X509_STORE_CTX_get0_param)]
    pub fn verify_param_mut(&mut self) -> Option<&mut X509VerifyParamRef> {
        // SAFETY: the parameter, if initialized, is uniquely borrowed
        // through this exclusive context reference.
        let ptr = unsafe { ffi::X509_STORE_CTX_get0_param(self.as_ptr()) };
        if ptr.is_null() {
            None
        } else {
            // SAFETY: non-null parameter remains owned by the borrowed context.
            Some(unsafe { X509VerifyParamRef::from_ptr_mut(ptr) })
        }
    }

    /// Sets the X509 verification configuration.
    #[corresponds(X509_STORE_CTX_set0_param)]
    pub fn set_verify_param(&mut self, param: X509VerifyParam) {
        // SAFETY: The native setter takes ownership of the consumed verification parameter; the context is exclusively borrowed.
        unsafe { ffi::X509_STORE_CTX_set0_param(self.as_ptr(), param.into_ptr()) }
    }

    /// Verifies the stored certificate.
    ///
    /// Returns `true` if verification succeeds. The `error` method will return the specific
    /// validation error if the certificate was not valid.
    ///
    /// This will only work inside of a call to `init`.
    #[corresponds(X509_verify_cert)]
    pub fn verify_cert(&mut self) -> Result<bool, ErrorStack> {
        if self.verify_param().is_none() {
            return Err(ErrorStack::internal_error_str(
                "certificate context is uninitialized",
            ));
        }
        // SAFETY: the live native context has initialized verification parameters.
        unsafe { cvt_n(ffi::X509_verify_cert(self.as_ptr())).map(|n| n != 0) }
    }

    /// Set the verify result of the context.
    #[corresponds(X509_STORE_CTX_set_error)]
    pub fn set_error(&mut self, result: X509VerifyResult) {
        // SAFETY: The context remains live while updating its native verification result with an encoded error constant.
        unsafe {
            ffi::X509_STORE_CTX_set_error(
                self.as_ptr(),
                result.err().map_or(ffi::X509_V_OK, X509VerifyError::as_raw),
            );
        }
    }

    /// Returns a reference to the certificate which caused the error or None if
    /// no certificate is relevant to the error.
    #[corresponds(X509_STORE_CTX_get_current_cert)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn current_cert(&self) -> Option<&X509Ref> {
        // SAFETY: The native getter returns a borrowed certificate (or null) whose lifetime is bounded by this context.
        unsafe {
            let ptr = ffi::X509_STORE_CTX_get_current_cert(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(X509Ref::from_ptr(ptr))
            }
        }
    }

    /// Returns a non-negative integer representing the depth in the certificate
    /// chain where the error occurred. If it is zero it occurred in the end
    /// entity certificate, one if it is the certificate which signed the end
    /// entity certificate and so on.
    #[corresponds(X509_STORE_CTX_get_error_depth)]
    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    pub fn error_depth(&self) -> Option<u32> {
        // SAFETY: the live context returns an integer depth; a negative native
        // value is not a valid depth and must not wrap to an unsigned value.
        u32::try_from(unsafe { ffi::X509_STORE_CTX_get_error_depth(self.as_ptr()) }).ok()
    }

    /// Returns a reference to a complete valid `X509` certificate chain.
    #[corresponds(X509_STORE_CTX_get0_chain)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn chain(&self) -> Option<&StackRef<X509>> {
        // SAFETY: The returned native chain is borrowed from this context, checked for null and not freed independently.
        unsafe {
            let chain = X509_STORE_CTX_get0_chain(self.as_ptr());

            if chain.is_null() {
                None
            } else {
                Some(StackRef::from_ptr(chain))
            }
        }
    }

    /// Returns a reference to the `X509` certificates used to initialize the
    /// [`X509StoreContextRef`].
    #[corresponds(X509_STORE_CTX_get0_untrusted)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn untrusted(&self) -> Option<&StackRef<X509>> {
        // SAFETY: The untrusted certificate stack belongs to the live context; null is checked before creating a shared reference.
        unsafe {
            let certs = ffi::X509_STORE_CTX_get0_untrusted(self.as_ptr());

            if certs.is_null() {
                None
            } else {
                Some(StackRef::from_ptr(certs))
            }
        }
    }

    /// Returns a reference to the certificate being verified.
    /// May return None if a raw public key is being verified.
    #[corresponds(X509_STORE_CTX_get0_cert)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn cert(&self) -> Option<&X509Ref> {
        // SAFETY: The native context retains the certificate; a non-null pointer is borrowed only for the context lifetime.
        unsafe {
            let ptr = ffi::X509_STORE_CTX_get0_cert(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(X509Ref::from_ptr(ptr))
            }
        }
    }
}

/// A builder used to construct an `X509`.
pub struct X509Builder(X509);

impl X509Builder {
    /// Creates a new builder.
    #[corresponds(X509_new)]
    pub fn new() -> Result<Self, ErrorStack> {
        // SAFETY: Native allocation returns an owned certificate or null; the checked pointer transfers to `X509`.
        unsafe {
            ffi::init();
            cvt_p(ffi::X509_new()).map(|p| Self(X509::from_ptr(p)))
        }
    }

    /// Sets the notAfter constraint on the certificate.
    #[corresponds(X509_set1_notAfter)]
    pub fn set_not_after(&mut self, not_after: &Asn1TimeRef) -> Result<(), ErrorStack> {
        // SAFETY: The builder uniquely owns the certificate, and the borrowed ASN.1 timestamp remains valid during copying.
        unsafe { cvt(X509_set1_notAfter(self.0.as_ptr(), not_after.as_ptr())) }
    }

    /// Sets the notBefore constraint on the certificate.
    #[corresponds(X509_set1_notBefore)]
    pub fn set_not_before(&mut self, not_before: &Asn1TimeRef) -> Result<(), ErrorStack> {
        // SAFETY: The builder uniquely owns the certificate, and the borrowed ASN.1 timestamp remains valid during copying.
        unsafe { cvt(X509_set1_notBefore(self.0.as_ptr(), not_before.as_ptr())) }
    }

    version_setter!(
        /// Sets the zero-indexed version of the certificate (2 for X.509 v3).
        X509_set_version
    );

    /// Sets the serial number of the certificate.
    #[corresponds(X509_set_serialNumber)]
    pub fn set_serial_number(&mut self, serial_number: &Asn1IntegerRef) -> Result<(), ErrorStack> {
        // SAFETY: Both the owned certificate builder and borrowed ASN.1 serial are live through the native setter.
        unsafe {
            cvt(ffi::X509_set_serialNumber(
                self.0.as_ptr(),
                serial_number.as_ptr(),
            ))
        }
    }

    /// Sets the issuer name of the certificate.
    #[corresponds(X509_set_issuer_name)]
    pub fn set_issuer_name(&mut self, issuer_name: &X509NameRef) -> Result<(), ErrorStack> {
        // SAFETY: The issuer-name reference remains live while the native setter copies it into the owned certificate.
        unsafe {
            cvt(ffi::X509_set_issuer_name(
                self.0.as_ptr(),
                issuer_name.as_ptr(),
            ))
        }
    }

    /// Sets the subject name of the certificate.
    ///
    /// When building certificates, the `C`, `ST`, and `O` options are common when using the openssl command line tools.
    /// The `CN` field is used for the common name, such as a DNS name.
    ///
    /// ```
    /// use btls::x509::{X509, X509NameBuilder};
    ///
    /// let mut x509_name = btls::x509::X509NameBuilder::new().unwrap();
    /// x509_name.append_entry_by_text("C", "US").unwrap();
    /// x509_name.append_entry_by_text("ST", "CA").unwrap();
    /// x509_name.append_entry_by_text("O", "Some organization").unwrap();
    /// x509_name.append_entry_by_text("CN", "www.example.com").unwrap();
    /// let x509_name = x509_name.build().unwrap();
    ///
    /// let mut x509 = btls::x509::X509::builder().unwrap();
    /// x509.set_subject_name(&x509_name).unwrap();
    /// ```
    #[corresponds(X509_set_subject_name)]
    pub fn set_subject_name(&mut self, subject_name: &X509NameRef) -> Result<(), ErrorStack> {
        // SAFETY: The subject-name reference remains live while the native setter copies it into the owned certificate.
        unsafe {
            cvt(ffi::X509_set_subject_name(
                self.0.as_ptr(),
                subject_name.as_ptr(),
            ))
        }
    }

    /// Sets the public key associated with the certificate.
    #[corresponds(X509_set_pubkey)]
    pub fn set_pubkey<T>(&mut self, key: &PKeyRef<T>) -> Result<(), ErrorStack>
    where
        T: HasPublic,
    {
        // SAFETY: The public-key reference remains valid while the native setter takes its own reference.
        unsafe { cvt(ffi::X509_set_pubkey(self.0.as_ptr(), key.as_ptr())) }
    }

    /// Returns a context object which is needed to create certain X509 extension values.
    ///
    /// Set `issuer` to `None` if the certificate will be self-signed.
    #[corresponds(X509V3_set_ctx)]
    #[must_use = "Use the returned context when constructing certificate extensions."]
    pub fn x509v3_context<'a>(
        &'a self,
        issuer: Option<&'a X509Ref>,
        conf: Option<&'a ConfRef>,
    ) -> X509v3Context<'a> {
        // SAFETY: The local native context is initialized in place; all issuer, subject and config pointers are borrowed for the returned context lifetime.
        unsafe {
            let mut ctx = mem::zeroed();

            let issuer = issuer.map_or_else(|| self.0.as_ptr(), ForeignTypeRef::as_ptr);
            let subject = self.0.as_ptr();
            ffi::X509V3_set_ctx(
                &raw mut ctx,
                issuer,
                subject,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            );

            // nodb case taken care of since we zeroed ctx above
            if let Some(conf) = conf {
                ffi::X509V3_set_nconf(&raw mut ctx, conf.as_ptr());
            }

            X509v3Context(ctx, PhantomData)
        }
    }

    /// Adds an X509 extension value to the certificate.
    #[corresponds(X509_add_ext)]
    pub fn append_extension(&mut self, extension: &X509ExtensionRef) -> Result<(), ErrorStack> {
        // SAFETY: The builder exclusively owns its certificate and the input extension stays live during native copying.
        unsafe {
            cvt(ffi::X509_add_ext(self.0.as_ptr(), extension.as_ptr(), -1))?;
            Ok(())
        }
    }

    /// Signs the certificate with a private key.
    #[corresponds(X509_sign)]
    pub fn sign<T>(&mut self, key: &PKeyRef<T>, hash: MessageDigest) -> Result<(), ErrorStack>
    where
        T: HasPrivate,
    {
        // SAFETY: The private key and digest handles remain live for the synchronous native signature operation.
        unsafe { cvt(ffi::X509_sign(self.0.as_ptr(), key.as_ptr(), hash.as_ptr())) }
    }

    /// Consumes the builder, returning the certificate.
    #[must_use = "The returned owned value is the result of consuming the original owner."]
    pub fn build(self) -> X509 {
        self.0
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509;
    fn drop = ffi::X509_free;

    /// An `X509` public key certificate.
    pub struct X509;
}

impl X509Ref {
    /// Returns this certificate's subject name.
    #[corresponds(X509_get_subject_name)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn subject_name(&self) -> Option<&X509NameRef> {
        // SAFETY: the name, when present, is borrowed from this live certificate.
        unsafe { X509NameRef::from_const_ptr_opt(ffi::X509_get_subject_name(self.as_ptr())) }
    }

    /// Returns the hash of the certificates subject
    #[corresponds(X509_subject_name_hash)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn subject_name_hash(&self) -> u32 {
        // SAFETY: The native hash is a scalar computed from the live certificate and does not expose a pointer.
        unsafe { ffi::X509_subject_name_hash(self.as_ptr()) as u32 }
    }

    /// Returns this certificate's subject alternative name entries, if they exist.
    #[corresponds(X509_get_ext_d2i)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn subject_alt_names(&self) -> Option<Stack<GeneralName>> {
        self.alt_names(ffi::NID_subject_alt_name)
    }

    /// Returns this certificate's issuer name.
    #[corresponds(X509_get_issuer_name)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn issuer_name(&self) -> Option<&X509NameRef> {
        // SAFETY: the issuer name, when present, is borrowed from this live certificate.
        unsafe { X509NameRef::from_const_ptr_opt(ffi::X509_get_issuer_name(self.as_ptr())) }
    }

    /// Returns this certificate's issuer alternative name entries, if they exist.
    #[corresponds(X509_get_ext_d2i)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn issuer_alt_names(&self) -> Option<Stack<GeneralName>> {
        self.alt_names(ffi::NID_issuer_alt_name)
    }

    fn alt_names(&self, nid: c_int) -> Option<Stack<GeneralName>> {
        // SAFETY: Both call sites supply a native GENERAL_NAMES extension NID,
        // and the decoder transfers ownership of the stack and its elements.
        unsafe {
            let stack = ffi::X509_get_ext_d2i(self.as_ptr(), nid, ptr::null_mut(), ptr::null_mut());
            if stack.is_null() {
                None
            } else {
                Some(Stack::from_ptr(stack.cast()))
            }
        }
    }

    /// Returns this certificate's subject key id, if it exists.
    #[corresponds(X509_get0_subject_key_id)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn subject_key_id(&self) -> Option<&Asn1StringRef> {
        // SAFETY: The returned subject key identifier is a borrowed embedded ASN.1 string, checked for null.
        unsafe {
            let data = ffi::X509_get0_subject_key_id(self.as_ptr());
            Asn1StringRef::from_const_ptr_opt(data)
        }
    }

    /// Returns this certificate's authority key id, if it exists.
    #[corresponds(X509_get0_authority_key_id)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn authority_key_id(&self) -> Option<&Asn1StringRef> {
        // SAFETY: The returned authority key identifier is borrowed from the certificate and checked for null.
        unsafe {
            let data = ffi::X509_get0_authority_key_id(self.as_ptr());
            Asn1StringRef::from_const_ptr_opt(data)
        }
    }

    #[corresponds(X509_get_pubkey)]
    pub fn public_key(&self) -> Result<PKey<Public>, ErrorStack> {
        // SAFETY: The native public-key getter transfers a reference to the caller, checked for null before taking ownership.
        unsafe {
            let pkey = cvt_p(ffi::X509_get_pubkey(self.as_ptr()))?;
            Ok(PKey::from_ptr(pkey))
        }
    }

    /// Returns a digest of the DER representation of the certificate.
    #[corresponds(X509_digest)]
    pub fn digest(&self, hash_type: MessageDigest) -> Result<DigestBytes, ErrorStack> {
        // SAFETY: The digest buffer is fully allocated and the writable output-length slot is valid for the synchronous native call.
        unsafe {
            let mut digest = DigestBytes {
                buf: [0; ffi::EVP_MAX_MD_SIZE as usize],
                len: ffi::EVP_MAX_MD_SIZE as usize,
            };
            let mut len = try_int(ffi::EVP_MAX_MD_SIZE)?;
            cvt(ffi::X509_digest(
                self.as_ptr(),
                hash_type.as_ptr(),
                digest.buf.as_mut_ptr(),
                &raw mut len,
            ))?;
            digest.len = try_int(len)?;

            Ok(digest)
        }
    }

    /// Returns the certificate's Not After validity period.
    #[corresponds(X509_getm_notAfter)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn not_after(&self) -> &Asn1TimeRef {
        // SAFETY: The native timestamp pointer is embedded in this live certificate and validated before borrowing.
        unsafe {
            let date = X509_getm_notAfter(self.as_ptr());
            assert!(!date.is_null());
            Asn1TimeRef::from_ptr(date)
        }
    }

    /// Returns the certificate's Not Before validity period.
    #[corresponds(X509_getm_notBefore)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn not_before(&self) -> &Asn1TimeRef {
        // SAFETY: The native timestamp pointer is embedded in this live certificate and validated before borrowing.
        unsafe {
            let date = X509_getm_notBefore(self.as_ptr());
            assert!(!date.is_null());
            Asn1TimeRef::from_ptr(date)
        }
    }

    /// Returns the certificate's signature
    #[corresponds(X509_get0_signature)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn signature(&self) -> &Asn1BitStringRef {
        // SAFETY: The native call writes to an initialized output pointer slot and borrows the embedded signature from this certificate.
        unsafe {
            let mut signature = ptr::null();
            X509_get0_signature(&raw mut signature, ptr::null_mut(), self.as_ptr());
            assert!(!signature.is_null());
            Asn1BitStringRef::from_ptr(signature.cast_mut())
        }
    }

    /// Returns the certificate's signature algorithm.
    #[corresponds(X509_get0_signature)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn signature_algorithm(&self) -> &X509AlgorithmRef {
        // SAFETY: The native call writes to an initialized output pointer slot and borrows the embedded signature algorithm.
        unsafe {
            let mut algor = ptr::null();
            X509_get0_signature(ptr::null_mut(), &raw mut algor, self.as_ptr());
            assert!(!algor.is_null());
            X509AlgorithmRef::from_ptr(algor.cast_mut())
        }
    }

    /// Returns the list of OCSP responder URLs specified in the certificate's Authority Information
    /// Access field.
    #[corresponds(X509_get1_ocsp)]
    pub fn ocsp_responders(&self) -> Result<Stack<OpensslString>, ErrorStack> {
        // SAFETY: The native API transfers ownership of the stack and each
        // NUL-terminated string. Validate UTF-8 before exposing OpensslString.
        let strings: Stack<OpensslString> =
            unsafe { Stack::from_ptr(cvt_p(ffi::X509_get1_ocsp(self.as_ptr()))?) };
        for string in &strings {
            // SAFETY: Each native element is a live, allocated C string.
            unsafe { CStr::from_ptr(string.as_ptr()) }
                .to_str()
                .map_err(ErrorStack::internal_error)?;
        }
        Ok(strings)
    }

    /// Checks that this certificate issued `subject`.
    #[corresponds(X509_check_issued)]
    pub fn issued(&self, subject: &Self) -> X509VerifyResult {
        // SAFETY: Both certificate references remain live throughout the native issuer/subject compatibility query.
        unsafe {
            let r = ffi::X509_check_issued(self.as_ptr(), subject.as_ptr());
            X509VerifyError::from_raw(r)
        }
    }

    /// Check if the certificate is signed using the given public key.
    ///
    /// Only the signature is checked: no other checks (such as certificate chain validity)
    /// are performed.
    ///
    /// Returns `true` if verification succeeds.
    #[corresponds(X509_verify)]
    pub fn verify<T>(&self, key: &PKeyRef<T>) -> Result<bool, ErrorStack>
    where
        T: HasPublic,
    {
        // SAFETY: The certificate and public key references remain live during signature verification; the integer result is checked.
        unsafe { cvt_n(ffi::X509_verify(self.as_ptr(), key.as_ptr())).map(|n| n != 0) }
    }

    /// Returns this certificate's serial number.
    #[corresponds(X509_get_serialNumber)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn serial_number(&self) -> &Asn1IntegerRef {
        // SAFETY: The serial-number pointer is embedded in this live certificate and checked before borrowing.
        unsafe {
            let r = ffi::X509_get_serialNumber(self.as_ptr());
            assert!(!r.is_null());
            Asn1IntegerRef::from_ptr(r)
        }
    }

    /// Checks whether the certificate matches the given hostname.
    ///
    /// This uses the default hostname matching behavior. Use
    /// [`X509Ref::check_host_with_flags`] to customize it.
    ///
    /// # Errors
    ///
    /// Returns a native error for an invalid host string or certificate matcher failure.
    pub fn check_host(&self, host: &str) -> Result<bool, ErrorStack> {
        self.check_host_with_flags(host, X509CheckFlags::empty())
    }

    /// Checks whether the certificate matches the given hostname using the supplied flags.
    #[corresponds(X509_check_host)]
    pub fn check_host_with_flags(
        &self,
        host: &str,
        flags: X509CheckFlags,
    ) -> Result<bool, ErrorStack> {
        // SAFETY: The host byte slice and certificate stay live for the call; BoringSSL receives the exact host length.
        unsafe {
            cvt_n(ffi::X509_check_host(
                self.as_ptr(),
                host.as_ptr().cast(),
                host.len(),
                flags.bits(),
                ptr::null_mut(),
            ))
            .map(|n| n == 1)
        }
    }

    #[corresponds(X509_check_ip_asc)]
    pub fn check_ip_asc(&self, address: &str) -> Result<bool, ErrorStack> {
        let c_str = CString::new(address).map_err(ErrorStack::internal_error)?;

        // SAFETY: The address is a valid NUL-terminated C string for the duration of the native IP matcher.
        unsafe { cvt_n(ffi::X509_check_ip_asc(self.as_ptr(), c_str.as_ptr(), 0)).map(|n| n == 1) }
    }

    to_pem! {
        /// Serializes the certificate into a PEM-encoded X509 structure.
        ///
        /// The output will have a header of `-----BEGIN CERTIFICATE-----`.
        #[corresponds(PEM_write_bio_X509)]
        to_pem,
        ffi::PEM_write_bio_X509
    }

    to_der! {
        /// Serializes the certificate into a DER-encoded X509 structure.
        #[corresponds(i2d_X509)]
        to_der,
        ffi::i2d_X509
    }
}

impl ToOwned for X509Ref {
    type Owned = X509;

    fn to_owned(&self) -> X509 {
        // SAFETY: The native certificate increments its reference count before the new owner is constructed.
        unsafe {
            X509_up_ref(self.as_ptr());
            X509::from_ptr(self.as_ptr())
        }
    }
}

impl X509 {
    /// Returns a new builder.
    ///
    /// # Errors
    ///
    /// The native certificate object cannot be allocated.
    pub fn builder() -> Result<X509Builder, ErrorStack> {
        X509Builder::new()
    }

    from_pem! {
        /// Deserializes a PEM-encoded X509 structure.
        ///
        /// The input should have a header of `-----BEGIN CERTIFICATE-----`.
        #[corresponds(PEM_read_bio_X509)]
        from_pem,
        X509,
        ffi::PEM_read_bio_X509
    }

    from_der! {
        /// Deserializes a DER-encoded X509 structure.
        #[corresponds(d2i_X509)]
        from_der,
        X509,
        ffi::d2i_X509,
        ::libc::c_long
    }

    /// Deserializes a list of PEM-formatted certificates.
    #[corresponds(PEM_read_bio_X509)]
    pub fn stack_from_pem(pem: &[u8]) -> Result<Vec<Self>, ErrorStack> {
        // SAFETY: The memory BIO borrows the input bytes for the parser lifetime; every successful PEM result transfers one owned certificate.
        unsafe {
            ffi::init();
            let bio = MemBioSlice::new(pem)?;

            let mut certs = vec![];
            loop {
                let r =
                    ffi::PEM_read_bio_X509(bio.as_ptr(), ptr::null_mut(), None, ptr::null_mut());
                if r.is_null() {
                    let err = ffi::ERR_peek_last_error();

                    if u32::try_from(ffi::ERR_GET_LIB(err)).ok() == Some(ffi::ERR_LIB_PEM.0)
                        && ffi::ERR_GET_REASON(err) == ffi::PEM_R_NO_START_LINE
                    {
                        ErrorStack::clear();
                        break;
                    }

                    return Err(ErrorStack::get());
                }
                certs.push(Self::from_ptr(r));
            }

            Ok(certs)
        }
    }
}

impl Clone for X509 {
    fn clone(&self) -> Self {
        X509Ref::to_owned(self)
    }
}

impl fmt::Debug for X509 {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let serial = self
            .serial_number()
            .to_bn()
            .and_then(|bn| bn.to_hex_str())
            .map_or_else(|_| String::new(), |hex| hex.to_string());
        let mut debug_struct = formatter.debug_struct("X509");
        debug_struct.field("serial_number", &serial);
        if let Some(oid) = self.signature_algorithm().object() {
            debug_struct.field("signature_algorithm", &oid);
        } else {
            debug_struct.field("signature_algorithm", &None::<&Asn1ObjectRef>);
        }
        debug_struct.field("issuer", &self.issuer_name());
        debug_struct.field("subject", &self.subject_name());
        if let Some(subject_alt_names) = &self.subject_alt_names() {
            debug_struct.field("subject_alt_names", subject_alt_names);
        }
        debug_struct.field("not_before", &self.not_before());
        debug_struct.field("not_after", &self.not_after());

        if let Ok(public_key) = &self.public_key() {
            debug_struct.field("public_key", public_key);
        }
        // TODO: Print extensions once they are supported on the X509 struct.

        debug_struct.finish()
    }
}

impl AsRef<Self> for X509Ref {
    fn as_ref(&self) -> &Self {
        self
    }
}

// SAFETY: the native stack type matches reference-counted native X509 objects.
unsafe impl Stackable for X509 {
    type StackType = ffi::stack_st_X509;
}

/// A context object required to construct certain `X509` extension values.
pub struct X509v3Context<'a>(ffi::X509V3_CTX, PhantomData<(&'a X509Ref, &'a ConfRef)>);

impl X509v3Context<'_> {
    #[must_use = "Use the returned native representation when crossing the native API boundary."]
    pub const fn as_ptr(&self) -> *mut ffi::X509V3_CTX {
        std::ptr::addr_of!(self.0).cast_mut()
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_EXTENSION;
    fn drop = ffi::X509_EXTENSION_free;

    /// Permit additional fields to be added to an `X509` v3 certificate.
    pub struct X509Extension;
}

// SAFETY: the native stack type matches owned native X509_EXTENSION objects.
unsafe impl Stackable for X509Extension {
    type StackType = ffi::stack_st_X509_EXTENSION;
}

// Native extension constructors synchronously consume their context. Keep the
// fallback native context on this stack and return only an owned extension so
// neither the fallback nor a borrowed caller context can escape.
fn with_extension_context(
    conf: Option<&ConfRef>,
    context: Option<&X509v3Context<'_>>,
    build: impl FnOnce(*mut ffi::CONF, *mut ffi::X509V3_CTX) -> Result<X509Extension, ErrorStack>,
) -> Result<X509Extension, ErrorStack> {
    // SAFETY: BoringSSL initializes the zeroed fallback context when needed;
    // both native context variants remain live until build returns.
    unsafe {
        let mut fallback: ffi::X509V3_CTX = mem::zeroed();
        let native_context = context.map_or_else(
            || {
                ffi::X509V3_set_ctx(
                    &raw mut fallback,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                );
                &raw mut fallback
            },
            X509v3Context::as_ptr,
        );
        build(
            conf.map_or(ptr::null_mut(), ConfRef::as_ptr),
            native_context,
        )
    }
}

impl X509Extension {
    /// Constructs an X509 extension value. See `man x509v3_config` for information on supported
    /// names and their value formats.
    ///
    /// Some extension types, such as `subjectAlternativeName`, require an `X509v3Context` to be
    /// provided.
    ///
    /// DO NOT CALL THIS WITH UNTRUSTED `value`: `value` is an OpenSSL
    /// mini-language that can read arbitrary files.
    ///
    /// See the extension module for builder types which will construct certain common extensions.
    ///
    /// # Errors
    ///
    /// The name or value contains NUL, or native extension parsing fails.
    pub fn new(
        conf: Option<&ConfRef>,
        context: Option<&X509v3Context>,
        name: &str,
        value: &str,
    ) -> Result<Self, ErrorStack> {
        let name = CString::new(name).map_err(ErrorStack::internal_error)?;
        let value = CString::new(value).map_err(ErrorStack::internal_error)?;
        ffi::init();
        with_extension_context(conf, context, |native_conf, native_context| {
            // SAFETY: Both NUL-terminated strings remain live through this synchronous
            // native call; the context helper keeps all native contexts alive.
            unsafe {
                cvt_p(ffi::X509V3_EXT_nconf(
                    native_conf,
                    native_context,
                    name.as_ptr().cast_mut(),
                    value.as_ptr().cast_mut(),
                ))
                .map(|p| Self::from_ptr(p))
            }
        })
    }

    /// Constructs an X509 extension value. See `man x509v3_config` for information on supported
    /// extensions and their value formats.
    ///
    /// Some extension types, such as `nid::SUBJECT_ALTERNATIVE_NAME`, require an `X509v3Context` to
    /// be provided.
    ///
    /// DO NOT CALL THIS WITH UNTRUSTED `value`: `value` is an OpenSSL
    /// mini-language that can read arbitrary files.
    ///
    /// See the extension module for builder types which will construct certain common extensions.
    ///
    /// # Errors
    ///
    /// The value contains NUL, or native extension parsing fails.
    pub fn new_nid(
        conf: Option<&ConfRef>,
        context: Option<&X509v3Context>,
        name: Nid,
        value: &str,
    ) -> Result<Self, ErrorStack> {
        let value = CString::new(value).map_err(ErrorStack::internal_error)?;
        ffi::init();
        with_extension_context(conf, context, |native_conf, native_context| {
            // SAFETY: The NUL-terminated value remains live through this synchronous
            // native call; the context helper keeps all native contexts alive.
            unsafe {
                cvt_p(ffi::X509V3_EXT_nconf_nid(
                    native_conf,
                    native_context,
                    name.as_raw(),
                    value.as_ptr().cast_mut(),
                ))
                .map(|p| Self::from_ptr(p))
            }
        })
    }

    pub(crate) unsafe fn new_internal(
        nid: Nid,
        critical: bool,
        value: *mut c_void,
    ) -> Result<Self, ErrorStack> {
        ffi::init();
        // SAFETY: The internal caller supplies a valid ASN.1 extension payload; the decoder owns its resulting checked pointer.
        unsafe {
            cvt_p(ffi::X509V3_EXT_i2d(
                nid.as_raw(),
                c_int::from(critical),
                value,
            ))
            .map(|p| Self::from_ptr(p))
        }
    }
}

impl X509ExtensionRef {
    to_der! {
        /// Serializes the Extension to its standard DER encoding.
        to_der,
        ffi::i2d_X509_EXTENSION
    }
}

/// A builder used to construct an `X509Name`.
pub struct X509NameBuilder(X509Name);

impl X509NameBuilder {
    /// Creates a new builder.
    ///
    /// # Errors
    ///
    /// Native X.509 name allocation fails.
    pub fn new() -> Result<Self, ErrorStack> {
        // SAFETY: Native allocation returns a newly owned name or null, checked before wrapping ownership.
        unsafe {
            ffi::init();
            cvt_p(ffi::X509_NAME_new()).map(|p| Self(X509Name::from_ptr(p)))
        }
    }

    /// Add a field entry by str.
    #[corresponds(X509_NAME_add_entry_by_txt)]
    pub fn append_entry_by_text(&mut self, field: &str, value: &str) -> Result<(), ErrorStack> {
        // SAFETY: The owned name builder and both borrowed bytes are live; native length conversion is checked.
        unsafe {
            let field = CString::new(field).map_err(ErrorStack::internal_error)?;
            cvt(ffi::X509_NAME_add_entry_by_txt(
                self.0.as_ptr(),
                field.as_ptr().cast_mut(),
                ffi::MBSTRING_UTF8,
                value.as_ptr(),
                try_int(value.len())?,
                -1,
                0,
            ))
        }
    }

    /// Add a field entry by str with a specific type.
    #[corresponds(X509_NAME_add_entry_by_txt)]
    pub fn append_entry_by_text_with_type(
        &mut self,
        field: &str,
        value: &str,
        ty: Asn1Type,
    ) -> Result<(), ErrorStack> {
        // SAFETY: The owned name builder and byte slices are live while BoringSSL copies the typed field.
        unsafe {
            let field = CString::new(field).map_err(ErrorStack::internal_error)?;
            cvt(ffi::X509_NAME_add_entry_by_txt(
                self.0.as_ptr(),
                field.as_ptr().cast_mut(),
                ty.as_raw(),
                value.as_ptr(),
                try_int(value.len())?,
                -1,
                0,
            ))
        }
    }

    /// Add a field entry by NID.
    #[corresponds(X509_NAME_add_entry_by_NID)]
    pub fn append_entry_by_nid(&mut self, field: Nid, value: &str) -> Result<(), ErrorStack> {
        // SAFETY: The owned name builder and the borrowed UTF-8 bytes remain live through native insertion.
        unsafe {
            cvt(ffi::X509_NAME_add_entry_by_NID(
                self.0.as_ptr(),
                field.as_raw(),
                ffi::MBSTRING_UTF8,
                value.as_ptr().cast_mut(),
                try_int(value.len())?,
                -1,
                0,
            ))
        }
    }

    /// Add a field entry by NID with a specific type.
    #[corresponds(X509_NAME_add_entry_by_NID)]
    pub fn append_entry_by_nid_with_type(
        &mut self,
        field: Nid,
        value: &str,
        ty: Asn1Type,
    ) -> Result<(), ErrorStack> {
        // SAFETY: The owned name builder and the borrowed typed bytes remain valid during native copying.
        unsafe {
            cvt(ffi::X509_NAME_add_entry_by_NID(
                self.0.as_ptr(),
                field.as_raw(),
                ty.as_raw(),
                value.as_ptr().cast_mut(),
                try_int(value.len())?,
                -1,
                0,
            ))
        }
    }

    /// Return an owned `X509Name` with all lazy native fields initialized.
    ///
    /// # Errors
    ///
    /// Encoding or decoding the native X.509 name fails.
    pub fn build(self) -> Result<X509Name, ErrorStack> {
        // Re-encoding initializes the name's lazily computed native fields
        // before it is published across threads.
        X509Name::from_der(&self.0.to_der()?)
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_NAME;
    fn drop = ffi::X509_NAME_free;

    /// The names of an `X509` certificate.
    pub struct X509Name;
}

impl X509Name {
    /// Returns a new builder.
    ///
    /// # Errors
    ///
    /// Native X.509 name allocation fails.
    pub fn builder() -> Result<X509NameBuilder, ErrorStack> {
        X509NameBuilder::new()
    }

    /// Loads subject names from a file containing PEM-formatted certificates.
    ///
    /// This is commonly used in conjunction with `SslContextBuilder::set_client_ca_list`.
    ///
    /// # Errors
    ///
    /// The path contains NUL or the CA file cannot be loaded or decoded.
    pub fn load_client_ca_file<P: AsRef<Path>>(file: P) -> Result<Stack<Self>, ErrorStack> {
        let file = CString::new(file.as_ref().as_os_str().as_encoded_bytes())
            .map_err(ErrorStack::internal_error)?;
        // SAFETY: The filename is a valid NUL-terminated buffer; a non-null result transfers the owned CA stack.
        unsafe { cvt_p(ffi::SSL_load_client_CA_file(file.as_ptr())).map(|p| Stack::from_ptr(p)) }
    }

    from_der! {
        /// Deserializes a DER-encoded X509 name structure.
        #[corresponds(d2i_X509_NAME)]
        from_der,
        X509Name,
        ffi::d2i_X509_NAME,
        ::libc::c_long
    }
}

// SAFETY: the native stack type matches owned native X509_NAME objects.
unsafe impl Stackable for X509Name {
    type StackType = ffi::stack_st_X509_NAME;
}

impl X509NameRef {
    /// Returns the name entries by the nid.
    #[must_use = "Use the returned iterator or element to inspect the collection."]
    pub const fn entries_by_nid(&self, nid: Nid) -> X509NameEntries<'_> {
        X509NameEntries {
            name: self,
            nid: Some(nid),
            loc: -1,
        }
    }

    /// Returns an iterator over all `X509NameEntry` values
    #[must_use = "Use the returned iterator or element to inspect the collection."]
    pub const fn entries(&self) -> X509NameEntries<'_> {
        X509NameEntries {
            name: self,
            nid: None,
            loc: -1,
        }
    }

    /// Returns an owned String representing the X509 name configurable via incoming flags.
    ///
    /// This function will return `None` if the underlying string contains invalid utf-8.
    #[corresponds(X509_NAME_print_ex)]
    #[must_use = "Use the returned certificate attribute or encoded description."]
    pub fn print_ex(&self, flags: i32) -> Option<String> {
        // SAFETY: The native output BIO is live while the name printer writes into it; negative return is checked.
        unsafe {
            let bio = MemBio::new().ok()?;
            if ffi::X509_NAME_print_ex(bio.as_ptr(), self.as_ptr(), 0, flags.try_into().ok()?) < 0 {
                return None;
            }
            let buf = bio.get_buf().ok()?.to_vec();
            let res = String::from_utf8(buf);
            res.ok()
        }
    }

    to_der! {
        /// Serializes the certificate into a DER-encoded X509 name structure.
        #[corresponds(i2d_X509_NAME)]
        to_der,
        ffi::i2d_X509_NAME
    }

    /// Compares `self` and `other`'s canonicalized forms.
    #[corresponds(X509_NAME_cmp)]
    pub fn try_cmp(&self, other: &Self) -> Result<std::cmp::Ordering, ErrorStack> {
        // SAFETY: The two native names are borrowed for the comparison call, and the error sentinel is checked.
        let r = unsafe { ffi::X509_NAME_cmp(self.as_ptr(), other.as_ptr()) };
        if r == -2 {
            return Err(ErrorStack::get());
        }
        Ok(r.cmp(&0))
    }
}

impl fmt::Debug for X509NameRef {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.debug_list().entries(self.entries()).finish()
    }
}

/// A type to destructure and examine an `X509Name`.
pub struct X509NameEntries<'a> {
    name: &'a X509NameRef,
    nid: Option<Nid>,
    loc: c_int,
}

impl<'a> Iterator for X509NameEntries<'a> {
    type Item = &'a X509NameEntryRef;

    fn next(&mut self) -> Option<&'a X509NameEntryRef> {
        // SAFETY: The iterator borrows the name for its full lifetime; native index lookups yield borrowed embedded entries.
        unsafe {
            if let Some(nid) = self.nid {
                self.loc =
                    ffi::X509_NAME_get_index_by_NID(self.name.as_ptr(), nid.as_raw(), self.loc);
                if self.loc < 0 {
                    return None;
                }
            } else {
                self.loc += 1;
                if self.loc >= ffi::X509_NAME_entry_count(self.name.as_ptr()) {
                    return None;
                }
            }

            let entry = ffi::X509_NAME_get_entry(self.name.as_ptr(), self.loc);
            X509NameEntryRef::from_const_ptr_opt(entry)
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_NAME_ENTRY;
    fn drop = ffi::X509_NAME_ENTRY_free;

    /// A name entry associated with a `X509Name`.
    pub struct X509NameEntry;
}

impl X509NameEntryRef {
    /// Returns the field value of an `X509NameEntry`.
    #[corresponds(X509_NAME_ENTRY_get_data)]
    #[must_use = "Use the returned extension bytes when inspecting the certificate."]
    pub fn data(&self) -> &Asn1StringRef {
        // SAFETY: The entry owns a live embedded ASN.1 data field; the returned reference cannot outlive its entry.
        unsafe {
            let data = ffi::X509_NAME_ENTRY_get_data(self.as_ptr());
            Asn1StringRef::from_ptr(data)
        }
    }

    /// Returns the `Asn1Object` value of an `X509NameEntry`.
    /// This is useful for finding out about the actual `Nid` when iterating over all `X509NameEntries`.
    #[corresponds(X509_NAME_ENTRY_get_object)]
    #[must_use = "Use the returned certificate attribute or encoded description."]
    pub fn object(&self) -> &Asn1ObjectRef {
        // SAFETY: The entry owns a live embedded ASN.1 object; the returned reference cannot outlive its entry.
        unsafe {
            let object = ffi::X509_NAME_ENTRY_get_object(self.as_ptr());
            Asn1ObjectRef::from_ptr(object)
        }
    }
}

impl fmt::Debug for X509NameEntryRef {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_fmt(format_args!("{:?} = {:?}", self.object(), self.data()))
    }
}

/// A builder used to construct an `X509Req`.
pub struct X509ReqBuilder(X509Req);

impl X509ReqBuilder {
    /// Returns a builder for a certificate request.
    #[corresponds(X509_REQ_new)]
    pub fn new() -> Result<Self, ErrorStack> {
        // SAFETY: Native allocation returns a new request or null; ownership transfers only after null-checking.
        unsafe {
            ffi::init();
            cvt_p(ffi::X509_REQ_new()).map(|p| Self(X509Req::from_ptr(p)))
        }
    }

    version_setter!(
        /// Sets the numerical value of the request version field.
        X509_REQ_set_version
    );

    /// Set the issuer name.
    #[corresponds(X509_REQ_set_subject_name)]
    pub fn set_subject_name(&mut self, subject_name: &X509NameRef) -> Result<(), ErrorStack> {
        // SAFETY: The owned request and borrowed subject name stay live while BoringSSL copies the latter.
        unsafe {
            cvt(ffi::X509_REQ_set_subject_name(
                self.0.as_ptr(),
                subject_name.as_ptr(),
            ))
        }
    }

    /// Set the public key.
    #[corresponds(X509_REQ_set_pubkey)]
    pub fn set_pubkey<T>(&mut self, key: &PKeyRef<T>) -> Result<(), ErrorStack>
    where
        T: HasPublic,
    {
        // SAFETY: The native key setter receives a live request and public-key handle and copies the key reference.
        unsafe { cvt(ffi::X509_REQ_set_pubkey(self.0.as_ptr(), key.as_ptr())) }
    }

    /// Return an `X509v3Context`. This context object can be used to construct
    /// certain `X509` extensions.
    #[must_use = "Use the returned context when constructing certificate extensions."]
    pub fn x509v3_context<'a>(&'a self, conf: Option<&'a ConfRef>) -> X509v3Context<'a> {
        // SAFETY: The native context is initialized locally; the request and optional configuration are borrowed for the context lifetime.
        unsafe {
            let mut ctx = mem::zeroed();

            ffi::X509V3_set_ctx(
                &raw mut ctx,
                ptr::null_mut(),
                ptr::null_mut(),
                self.0.as_ptr(),
                ptr::null_mut(),
                0,
            );

            // nodb case taken care of since we zeroed ctx above
            if let Some(conf) = conf {
                ffi::X509V3_set_nconf(&raw mut ctx, conf.as_ptr());
            }

            X509v3Context(ctx, PhantomData)
        }
    }

    /// Permits any number of extension fields to be added to the certificate.
    ///
    /// # Errors
    ///
    /// Native allocation or extension attachment fails.
    pub fn add_extensions(
        &mut self,
        extensions: &StackRef<X509Extension>,
    ) -> Result<(), ErrorStack> {
        // SAFETY: The extensions stack remains live while the native request copies it.
        unsafe {
            cvt(ffi::X509_REQ_add_extensions(
                self.0.as_ptr(),
                extensions.as_ptr(),
            ))
        }
    }

    /// Sign the request using a private key.
    #[corresponds(X509_REQ_sign)]
    pub fn sign<T>(&mut self, key: &PKeyRef<T>, hash: MessageDigest) -> Result<(), ErrorStack>
    where
        T: HasPrivate,
    {
        // SAFETY: The request, private key and digest handles stay live for the synchronous signature operation.
        unsafe {
            cvt(ffi::X509_REQ_sign(
                self.0.as_ptr(),
                key.as_ptr(),
                hash.as_ptr(),
            ))
        }
    }

    /// Returns the `X509Req`.
    #[must_use = "The returned owned value is the result of consuming the original owner."]
    pub fn build(self) -> X509Req {
        self.0
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_REQ;
    fn drop = ffi::X509_REQ_free;

    /// An `X509` certificate request.
    pub struct X509Req;
}

impl X509Req {
    /// A builder for `X509Req`.
    ///
    /// # Errors
    ///
    /// Native certificate-request allocation fails.
    pub fn builder() -> Result<X509ReqBuilder, ErrorStack> {
        X509ReqBuilder::new()
    }

    from_pem! {
        /// Deserializes a PEM-encoded PKCS#10 certificate request structure.
        ///
        /// The input should have a header of `-----BEGIN CERTIFICATE REQUEST-----`.
        #[corresponds(PEM_read_bio_X509_REQ)]
        from_pem,
        X509Req,
        ffi::PEM_read_bio_X509_REQ
    }

    from_der! {
        /// Deserializes a DER-encoded PKCS#10 certificate request structure.
        #[corresponds(d2i_X509_REQ)]
        from_der,
        X509Req,
        ffi::d2i_X509_REQ,
        ::libc::c_long
    }
}

impl X509ReqRef {
    to_pem! {
        /// Serializes the certificate request to a PEM-encoded PKCS#10 structure.
        ///
        /// The output will have a header of `-----BEGIN CERTIFICATE REQUEST-----`.
        #[corresponds(PEM_write_bio_X509_REQ)]
        to_pem,
        ffi::PEM_write_bio_X509_REQ
    }

    to_der! {
        /// Serializes the certificate request to a DER-encoded PKCS#10 structure.
        #[corresponds(i2d_X509_REQ)]
        to_der,
        ffi::i2d_X509_REQ
    }

    /// Returns the numerical value of the version field of the certificate request.
    #[corresponds(X509_REQ_get_version)]
    #[must_use = "Use the returned certificate version when inspecting its encoding."]
    pub fn version(&self) -> c_long {
        // SAFETY: the native request is live and provides a scalar version;
        // retain its full native width rather than truncating to `i32`.
        unsafe { X509_REQ_get_version(self.as_ptr()) }
    }

    /// Returns the subject name of the certificate request.
    #[corresponds(X509_REQ_get_subject_name)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn subject_name(&self) -> &X509NameRef {
        // SAFETY: The subject name is owned by the live request and its returned pointer is checked before borrowing.
        unsafe {
            let name = X509_REQ_get_subject_name(self.as_ptr());
            assert!(!name.is_null());
            X509NameRef::from_ptr(name)
        }
    }

    /// Returns the public key of the certificate request.
    #[corresponds(X509_REQ_get_pubkey)]
    pub fn public_key(&self) -> Result<PKey<Public>, ErrorStack> {
        // SAFETY: The native getter transfers a public-key reference, checked before wrapping ownership.
        unsafe {
            let key = cvt_p(ffi::X509_REQ_get_pubkey(self.as_ptr()))?;
            Ok(PKey::from_ptr(key))
        }
    }

    /// Check if the certificate request is signed using the given public key.
    ///
    /// Returns `true` if verification succeeds.
    #[corresponds(X509_REQ_verify)]
    pub fn verify<T>(&self, key: &PKeyRef<T>) -> Result<bool, ErrorStack>
    where
        T: HasPublic,
    {
        // SAFETY: Both request and public-key references remain live through the native verification call.
        unsafe { cvt_n(ffi::X509_REQ_verify(self.as_ptr(), key.as_ptr())).map(|n| n != 0) }
    }

    /// Returns the extensions of the certificate request.
    #[corresponds(X509_REQ_get_extensions)]
    pub fn extensions(&self) -> Result<Stack<X509Extension>, ErrorStack> {
        // SAFETY: The native getter yields a new owned extension stack, checked before transferring ownership.
        unsafe {
            let extensions = cvt_p(ffi::X509_REQ_get_extensions(self.as_ptr()))?;
            Ok(Stack::from_ptr(extensions))
        }
    }
}

/// The result of peer certificate verification.
pub type X509VerifyResult = Result<(), X509VerifyError>;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct X509VerifyError(c_int);

impl fmt::Debug for X509VerifyError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("X509VerifyError")
            .field("code", &self.0)
            .field("error", &self.error_string())
            .finish()
    }
}

impl fmt::Display for X509VerifyError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(self.error_string())
    }
}

impl Error for X509VerifyError {}

impl X509VerifyError {
    /// Creates an [`X509VerifyResult`] from a raw error number.
    ///
    /// # Safety
    ///
    /// Some methods on [`X509VerifyError`] are not thread safe if the error
    /// number is invalid.
    ///
    /// # Errors
    ///
    /// Returns a verification error for any native code except `X509_V_OK`.
    pub const unsafe fn from_raw(err: c_int) -> X509VerifyResult {
        if err == ffi::X509_V_OK {
            Ok(())
        } else {
            Err(Self(err))
        }
    }

    /// Return the integer representation of an [`X509VerifyError`].
    #[must_use = "The returned native representation is needed by the caller."]
    pub const fn as_raw(self) -> c_int {
        self.0
    }

    /// Return a human readable error string from the verification error.
    ///
    /// Returns empty string if the message was not UTF-8.
    #[corresponds(X509_verify_cert_error_string)]
    #[must_use = "The returned description is needed to report verification failure."]
    pub fn error_string(self) -> &'static str {
        ffi::init();

        // SAFETY: The native error lookup returns a static NUL-terminated message for the supplied scalar code.
        unsafe {
            let s = ffi::X509_verify_cert_error_string(c_long::from(self.0));
            CStr::from_ptr(s).to_str().unwrap_or_default()
        }
    }
}

impl X509VerifyError {
    /// Native verification failure `X509_V_ERR_UNSPECIFIED`.
    pub const UNSPECIFIED: Self = Self(ffi::X509_V_ERR_UNSPECIFIED);
    /// Native verification failure `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT`.
    pub const UNABLE_TO_GET_ISSUER_CERT: Self = Self(ffi::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT);
    /// Native verification failure `X509_V_ERR_UNABLE_TO_GET_CRL`.
    pub const UNABLE_TO_GET_CRL: Self = Self(ffi::X509_V_ERR_UNABLE_TO_GET_CRL);
    /// Native verification failure `X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE`.
    pub const UNABLE_TO_DECRYPT_CERT_SIGNATURE: Self =
        Self(ffi::X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE);
    /// Native verification failure `X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE`.
    pub const UNABLE_TO_DECRYPT_CRL_SIGNATURE: Self =
        Self(ffi::X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE);
    /// Native verification failure `X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY`.
    pub const UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: Self =
        Self(ffi::X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY);
    /// Native verification failure `X509_V_ERR_CERT_SIGNATURE_FAILURE`.
    pub const CERT_SIGNATURE_FAILURE: Self = Self(ffi::X509_V_ERR_CERT_SIGNATURE_FAILURE);
    /// Native verification failure `X509_V_ERR_CRL_SIGNATURE_FAILURE`.
    pub const CRL_SIGNATURE_FAILURE: Self = Self(ffi::X509_V_ERR_CRL_SIGNATURE_FAILURE);
    /// Native verification failure `X509_V_ERR_CERT_NOT_YET_VALID`.
    pub const CERT_NOT_YET_VALID: Self = Self(ffi::X509_V_ERR_CERT_NOT_YET_VALID);
    /// Native verification failure `X509_V_ERR_CERT_HAS_EXPIRED`.
    pub const CERT_HAS_EXPIRED: Self = Self(ffi::X509_V_ERR_CERT_HAS_EXPIRED);
    /// Native verification failure `X509_V_ERR_CRL_NOT_YET_VALID`.
    pub const CRL_NOT_YET_VALID: Self = Self(ffi::X509_V_ERR_CRL_NOT_YET_VALID);
    /// Native verification failure `X509_V_ERR_CRL_HAS_EXPIRED`.
    pub const CRL_HAS_EXPIRED: Self = Self(ffi::X509_V_ERR_CRL_HAS_EXPIRED);
    /// Native verification failure `X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD`.
    pub const ERROR_IN_CERT_NOT_BEFORE_FIELD: Self =
        Self(ffi::X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD);
    /// Native verification failure `X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD`.
    pub const ERROR_IN_CERT_NOT_AFTER_FIELD: Self =
        Self(ffi::X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD);
    /// Native verification failure `X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD`.
    pub const ERROR_IN_CRL_LAST_UPDATE_FIELD: Self =
        Self(ffi::X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD);
    /// Native verification failure `X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD`.
    pub const ERROR_IN_CRL_NEXT_UPDATE_FIELD: Self =
        Self(ffi::X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
    /// Native verification failure `X509_V_ERR_OUT_OF_MEM`.
    pub const OUT_OF_MEM: Self = Self(ffi::X509_V_ERR_OUT_OF_MEM);
    /// Native verification failure `X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT`.
    pub const DEPTH_ZERO_SELF_SIGNED_CERT: Self = Self(ffi::X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);
    /// Native verification failure `X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN`.
    pub const SELF_SIGNED_CERT_IN_CHAIN: Self = Self(ffi::X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN);
    /// Native verification failure `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY`.
    pub const UNABLE_TO_GET_ISSUER_CERT_LOCALLY: Self =
        Self(ffi::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    /// Native verification failure `X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE`.
    pub const UNABLE_TO_VERIFY_LEAF_SIGNATURE: Self =
        Self(ffi::X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE);
    /// Native verification failure `X509_V_ERR_CERT_CHAIN_TOO_LONG`.
    pub const CERT_CHAIN_TOO_LONG: Self = Self(ffi::X509_V_ERR_CERT_CHAIN_TOO_LONG);
    /// Native verification failure `X509_V_ERR_CERT_REVOKED`.
    pub const CERT_REVOKED: Self = Self(ffi::X509_V_ERR_CERT_REVOKED);
    /// Native verification failure `X509_V_ERR_INVALID_CA`.
    pub const INVALID_CA: Self = Self(ffi::X509_V_ERR_INVALID_CA);
    /// Native verification failure `X509_V_ERR_PATH_LENGTH_EXCEEDED`.
    pub const PATH_LENGTH_EXCEEDED: Self = Self(ffi::X509_V_ERR_PATH_LENGTH_EXCEEDED);
    /// Native verification failure `X509_V_ERR_INVALID_PURPOSE`.
    pub const INVALID_PURPOSE: Self = Self(ffi::X509_V_ERR_INVALID_PURPOSE);
    /// Native verification failure `X509_V_ERR_CERT_UNTRUSTED`.
    pub const CERT_UNTRUSTED: Self = Self(ffi::X509_V_ERR_CERT_UNTRUSTED);
    /// Native verification failure `X509_V_ERR_CERT_REJECTED`.
    pub const CERT_REJECTED: Self = Self(ffi::X509_V_ERR_CERT_REJECTED);
    /// Native verification failure `X509_V_ERR_SUBJECT_ISSUER_MISMATCH`.
    pub const SUBJECT_ISSUER_MISMATCH: Self = Self(ffi::X509_V_ERR_SUBJECT_ISSUER_MISMATCH);
    /// Native verification failure `X509_V_ERR_AKID_SKID_MISMATCH`.
    pub const AKID_SKID_MISMATCH: Self = Self(ffi::X509_V_ERR_AKID_SKID_MISMATCH);
    /// Native verification failure `X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH`.
    pub const AKID_ISSUER_SERIAL_MISMATCH: Self = Self(ffi::X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH);
    /// Native verification failure `X509_V_ERR_KEYUSAGE_NO_CERTSIGN`.
    pub const KEYUSAGE_NO_CERTSIGN: Self = Self(ffi::X509_V_ERR_KEYUSAGE_NO_CERTSIGN);
    /// Native verification failure `X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER`.
    pub const UNABLE_TO_GET_CRL_ISSUER: Self = Self(ffi::X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER);
    /// Native verification failure `X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION`.
    pub const UNHANDLED_CRITICAL_EXTENSION: Self =
        Self(ffi::X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION);
    /// Native verification failure `X509_V_ERR_KEYUSAGE_NO_CRL_SIGN`.
    pub const KEYUSAGE_NO_CRL_SIGN: Self = Self(ffi::X509_V_ERR_KEYUSAGE_NO_CRL_SIGN);
    /// Native verification failure `X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION`.
    pub const UNHANDLED_CRITICAL_CRL_EXTENSION: Self =
        Self(ffi::X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION);
    /// Native verification failure `X509_V_ERR_INVALID_NON_CA`.
    pub const INVALID_NON_CA: Self = Self(ffi::X509_V_ERR_INVALID_NON_CA);
    /// Native verification failure `X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED`.
    pub const PROXY_PATH_LENGTH_EXCEEDED: Self = Self(ffi::X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED);
    /// Native verification failure `X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE`.
    pub const KEYUSAGE_NO_DIGITAL_SIGNATURE: Self =
        Self(ffi::X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE);
    /// Native verification failure `X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED`.
    pub const PROXY_CERTIFICATES_NOT_ALLOWED: Self =
        Self(ffi::X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED);
    /// Native verification failure `X509_V_ERR_INVALID_EXTENSION`.
    pub const INVALID_EXTENSION: Self = Self(ffi::X509_V_ERR_INVALID_EXTENSION);
    /// Native verification failure `X509_V_ERR_INVALID_POLICY_EXTENSION`.
    pub const INVALID_POLICY_EXTENSION: Self = Self(ffi::X509_V_ERR_INVALID_POLICY_EXTENSION);
    /// Native verification failure `X509_V_ERR_NO_EXPLICIT_POLICY`.
    pub const NO_EXPLICIT_POLICY: Self = Self(ffi::X509_V_ERR_NO_EXPLICIT_POLICY);
    /// Native verification failure `X509_V_ERR_DIFFERENT_CRL_SCOPE`.
    pub const DIFFERENT_CRL_SCOPE: Self = Self(ffi::X509_V_ERR_DIFFERENT_CRL_SCOPE);
    /// Native verification failure `X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE`.
    pub const UNSUPPORTED_EXTENSION_FEATURE: Self =
        Self(ffi::X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE);
    /// Native verification failure `X509_V_ERR_UNNESTED_RESOURCE`.
    pub const UNNESTED_RESOURCE: Self = Self(ffi::X509_V_ERR_UNNESTED_RESOURCE);
    /// Native verification failure `X509_V_ERR_PERMITTED_VIOLATION`.
    pub const PERMITTED_VIOLATION: Self = Self(ffi::X509_V_ERR_PERMITTED_VIOLATION);
    /// Native verification failure `X509_V_ERR_EXCLUDED_VIOLATION`.
    pub const EXCLUDED_VIOLATION: Self = Self(ffi::X509_V_ERR_EXCLUDED_VIOLATION);
    /// Native verification failure `X509_V_ERR_SUBTREE_MINMAX`.
    pub const SUBTREE_MINMAX: Self = Self(ffi::X509_V_ERR_SUBTREE_MINMAX);
    /// Native verification failure `X509_V_ERR_APPLICATION_VERIFICATION`.
    pub const APPLICATION_VERIFICATION: Self = Self(ffi::X509_V_ERR_APPLICATION_VERIFICATION);
    /// Native verification failure `X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE`.
    pub const UNSUPPORTED_CONSTRAINT_TYPE: Self = Self(ffi::X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE);
    /// Native verification failure `X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX`.
    pub const UNSUPPORTED_CONSTRAINT_SYNTAX: Self =
        Self(ffi::X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX);
    /// Native verification failure `X509_V_ERR_UNSUPPORTED_NAME_SYNTAX`.
    pub const UNSUPPORTED_NAME_SYNTAX: Self = Self(ffi::X509_V_ERR_UNSUPPORTED_NAME_SYNTAX);
    /// Native verification failure `X509_V_ERR_CRL_PATH_VALIDATION_ERROR`.
    pub const CRL_PATH_VALIDATION_ERROR: Self = Self(ffi::X509_V_ERR_CRL_PATH_VALIDATION_ERROR);
    /// Native verification failure `X509_V_ERR_HOSTNAME_MISMATCH`.
    pub const HOSTNAME_MISMATCH: Self = Self(ffi::X509_V_ERR_HOSTNAME_MISMATCH);
    /// Native verification failure `X509_V_ERR_EMAIL_MISMATCH`.
    pub const EMAIL_MISMATCH: Self = Self(ffi::X509_V_ERR_EMAIL_MISMATCH);
    /// Native verification failure `X509_V_ERR_IP_ADDRESS_MISMATCH`.
    pub const IP_ADDRESS_MISMATCH: Self = Self(ffi::X509_V_ERR_IP_ADDRESS_MISMATCH);
    /// Native verification failure `X509_V_ERR_INVALID_CALL`.
    pub const INVALID_CALL: Self = Self(ffi::X509_V_ERR_INVALID_CALL);
    /// Native verification failure `X509_V_ERR_STORE_LOOKUP`.
    pub const STORE_LOOKUP: Self = Self(ffi::X509_V_ERR_STORE_LOOKUP);
    /// Native verification failure `X509_V_ERR_NAME_CONSTRAINTS_WITHOUT_SANS`.
    pub const NAME_CONSTRAINTS_WITHOUT_SANS: Self =
        Self(ffi::X509_V_ERR_NAME_CONSTRAINTS_WITHOUT_SANS);
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::GENERAL_NAME;
    fn drop = ffi::GENERAL_NAME_free;

    /// An `X509` certificate alternative names.
    pub struct GeneralName;
}

impl GeneralName {
    fn new(type_: c_int, asn1_type: Asn1Type, value: &[u8]) -> Result<Self, ErrorStack> {
        ffi::init();
        let len = try_int(value.len())?;
        // SAFETY: both allocations are checked. Once the native ASN.1 string
        // is linked into the GENERAL_NAME union with its matching tag, the
        // owning wrapper frees it even when filling the payload fails.
        unsafe {
            let gn = Self::from_ptr(cvt_p(ffi::GENERAL_NAME_new())?);
            let string = cvt_p(ffi::ASN1_STRING_type_new(asn1_type.as_raw()))?;
            (*gn.as_ptr()).type_ = type_;
            (*gn.as_ptr()).d.ptr = string.cast();
            cvt(ffi::ASN1_STRING_set(string, value.as_ptr().cast(), len))?;
            Ok(gn)
        }
    }

    pub(crate) fn new_email(email: &[u8]) -> Result<Self, ErrorStack> {
        Self::new(ffi::GEN_EMAIL, Asn1Type::IA5STRING, email)
    }

    pub(crate) fn new_dns(dns: &[u8]) -> Result<Self, ErrorStack> {
        Self::new(ffi::GEN_DNS, Asn1Type::IA5STRING, dns)
    }

    pub(crate) fn new_uri(uri: &[u8]) -> Result<Self, ErrorStack> {
        Self::new(ffi::GEN_URI, Asn1Type::IA5STRING, uri)
    }

    pub(crate) fn new_ip(ip: IpAddr) -> Result<Self, ErrorStack> {
        match ip {
            IpAddr::V4(addr) => Self::new(ffi::GEN_IPADD, Asn1Type::OCTET_STRING, &addr.octets()),
            IpAddr::V6(addr) => Self::new(ffi::GEN_IPADD, Asn1Type::OCTET_STRING, &addr.octets()),
        }
    }

    pub(crate) fn new_rid(oid: Asn1Object) -> Result<Self, ErrorStack> {
        // SAFETY: The newly allocated general name takes ownership of the consumed registered-ID object.
        unsafe {
            ffi::init();
            let gn = cvt_p(ffi::GENERAL_NAME_new())?;
            (*gn).type_ = ffi::GEN_RID;
            (*gn).d.registeredID = oid.into_ptr();

            Ok(Self::from_ptr(gn))
        }
    }
}

impl GeneralNameRef {
    fn ia5_string(&self, ffi_type: c_int) -> Option<&str> {
        // SAFETY: The type discriminant is checked before accessing the matching IA5 union member; its bytes belong to the live name.
        unsafe {
            if (*self.as_ptr()).type_ != ffi_type {
                return None;
            }

            let asn = Asn1BitStringRef::from_ptr((*self.as_ptr()).d.ia5);

            // IA5Strings are stated to be ASCII (specifically IA5). Hopefully
            // OpenSSL checks that when loading a certificate but if not we'll
            // use this instead of from_utf8_unchecked just in case.
            asn.to_str()
        }
    }

    /// Returns the contents of this `GeneralName` if it is an `rfc822Name`.
    #[must_use = "Use the returned certificate attribute or encoded description."]
    pub fn email(&self) -> Option<&str> {
        self.ia5_string(ffi::GEN_EMAIL)
    }

    /// Returns the contents of this `GeneralName` if it is a `dNSName`.
    #[must_use = "Use the returned certificate attribute or encoded description."]
    pub fn dnsname(&self) -> Option<&str> {
        self.ia5_string(ffi::GEN_DNS)
    }

    /// Returns the contents of this `GeneralName` if it is an `uniformResourceIdentifier`.
    #[must_use = "Use the returned certificate attribute or encoded description."]
    pub fn uri(&self) -> Option<&str> {
        self.ia5_string(ffi::GEN_URI)
    }

    /// Returns the contents of this `GeneralName` if it is an `iPAddress`.
    #[must_use = "Use the returned certificate attribute or encoded description."]
    pub fn ipaddress(&self) -> Option<&[u8]> {
        // SAFETY: The type discriminant is checked before accessing the matching IP union member, borrowed from the live name.
        unsafe {
            if (*self.as_ptr()).type_ != ffi::GEN_IPADD {
                return None;
            }

            Some(Asn1BitStringRef::from_ptr((*self.as_ptr()).d.ip).as_slice())
        }
    }
}

impl fmt::Debug for GeneralNameRef {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        if let Some(email) = self.email() {
            formatter.write_str(email)
        } else if let Some(dnsname) = self.dnsname() {
            formatter.write_str(dnsname)
        } else if let Some(uri) = self.uri() {
            formatter.write_str(uri)
        } else if let Some(ipaddress) = self.ipaddress() {
            let result = String::from_utf8_lossy(ipaddress);
            formatter.write_str(&result)
        } else {
            formatter.write_str("(empty)")
        }
    }
}

// SAFETY: the native stack type matches owned native GENERAL_NAME objects.
unsafe impl Stackable for GeneralName {
    type StackType = ffi::stack_st_GENERAL_NAME;
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_ALGOR;
    fn drop = ffi::X509_ALGOR_free;

    /// An `X509` certificate signature algorithm.
    pub struct X509Algorithm;
}

impl X509AlgorithmRef {
    /// Returns the ASN.1 OID of this algorithm.
    #[must_use = "Use the returned certificate attribute or encoded description."]
    pub fn object(&self) -> Option<&Asn1ObjectRef> {
        // SAFETY: the native call fills the initialized output pointer with
        // an OID borrowed from the live algorithm; absent OIDs remain null.
        unsafe {
            let mut oid = ptr::null();
            X509_ALGOR_get0(
                &raw mut oid,
                ptr::null_mut(),
                ptr::null_mut(),
                self.as_ptr(),
            );
            Asn1ObjectRef::from_const_ptr_opt(oid)
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_OBJECT;
    fn drop = ffi::X509_OBJECT_free;

    /// An `X509` or an X509 certificate revocation list.
    pub struct X509Object;
}

impl X509ObjectRef {
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn x509(&self) -> Option<&X509Ref> {
        // SAFETY: The object owns the returned certificate pointer; null is checked before creating a borrowed reference.
        unsafe {
            let ptr = X509_OBJECT_get0_X509(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(X509Ref::from_ptr(ptr))
            }
        }
    }
}

// SAFETY: the native stack type matches owned native X509_OBJECT references.
unsafe impl Stackable for X509Object {
    type StackType = ffi::stack_st_X509_OBJECT;
}

use crate::ffi::{X509_get0_signature, X509_getm_notAfter, X509_getm_notBefore, X509_up_ref};

use crate::ffi::{
    X509_ALGOR_get0, X509_REQ_get_subject_name, X509_REQ_get_version, X509_STORE_CTX_get0_chain,
    X509_set1_notAfter, X509_set1_notBefore,
};

use crate::ffi::X509_OBJECT_get0_X509;

unsafe fn get_new_x509_store_ctx_idx(f: ffi::CRYPTO_EX_free) -> c_int {
    // SAFETY: The native index allocator stores a matching destructor callback and receives only null auxiliary arguments.
    unsafe { ffi::X509_STORE_CTX_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, f) }
}
