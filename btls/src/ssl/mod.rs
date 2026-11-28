//! SSL/TLS support.
//!
//! `SslConnector` and `SslAcceptor` should be used in most cases - they handle
//! configuration of the OpenSSL primitives for you.
//!
//! # Examples
//!
//! To connect as a client to a remote server:
//!
//! ```no_run
//! use btls::ssl::{SslMethod, SslConnector};
//! use std::io::{Read, Write};
//! use std::net::TcpStream;
//!
//! let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
//!
//! let stream = TcpStream::connect("google.com:443").unwrap();
//! let mut stream = connector.connect("google.com", stream).unwrap();
//!
//! stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
//! let mut res = vec![];
//! stream.read_to_end(&mut res).unwrap();
//! println!("{}", String::from_utf8_lossy(&res));
//! ```
//!
//! To accept connections as a server from remote clients:
//!
//! ```no_run
//! use btls::ssl::{SslMethod, SslAcceptor, SslStream, SslFiletype};
//! use std::net::{TcpListener, TcpStream};
//! use std::sync::Arc;
//! use std::thread;
//!
//!
//! let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
//! acceptor.set_private_key_file("key.pem", SslFiletype::PEM).unwrap();
//! acceptor.set_certificate_chain_file("certs.pem").unwrap();
//! acceptor.check_private_key().unwrap();
//! let acceptor = Arc::new(acceptor.build());
//!
//! let listener = TcpListener::bind("0.0.0.0:8443").unwrap();
//!
//! fn handle_client(stream: SslStream<TcpStream>) {
//!     // ...
//! }
//!
//! for stream in listener.incoming() {
//!     match stream {
//!         Ok(stream) => {
//!             let acceptor = acceptor.clone();
//!             thread::spawn(move || {
//!                 let stream = acceptor.accept(stream).unwrap();
//!                 handle_client(stream);
//!             });
//!         }
//!         Err(e) => { /* connection failed */ }
//!     }
//! }
//! ```
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use openssl_macros::corresponds;
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong};
use std::fmt;
use std::io::prelude::*;
use std::io::{self, IoSlice};
use std::marker::PhantomData;
use std::mem::{self, ManuallyDrop, MaybeUninit};
use std::ops::Deref;
use std::panic::resume_unwind;
use std::path::Path;
use std::ptr::{self, NonNull};
use std::slice;
use std::str;
use std::sync::{Arc, LazyLock};

use crate::error::ErrorStack;
use crate::ex_data::{Index, IndexRegistry, IndexSlot, replace_boxed};
use crate::hmac::HmacCtxRef;
use crate::nid::Nid;
#[cfg(feature = "rpk")]
use crate::pkey::Public;
use crate::pkey::{HasPrivate, PKeyRef, Private};
use crate::srtp::{SrtpProtectionProfile, SrtpProtectionProfileRef};
use crate::ssl::bio::BioMethod;
use crate::ssl::callbacks::{
    raw_cert_verify, raw_client_psk, raw_custom_verify, raw_server_psk, raw_sni, raw_ticket_key,
    raw_tlsext_status, raw_verify, ssl_raw_custom_verify, ssl_raw_verify,
};
use crate::ssl::ech::SslEchKeys;
use crate::ssl::error::InnerError;
use crate::stack::{Stack, StackRef, Stackable};
use crate::symm::CipherCtxRef;
use crate::try_int;
use crate::util::native_input;
use crate::x509::store::{X509Store, X509StoreBuilder, X509StoreBuilderRef, X509StoreRef};
use crate::x509::verify::X509VerifyParamRef;
use crate::x509::{
    X509, X509Name, X509Ref, X509StoreContextRef, X509VerifyError, X509VerifyResult,
};
use crate::{cvt, cvt_0i, cvt_n, cvt_p, init};
use crate::{ffi, free_data_box};

pub use self::async_callbacks::{
    AsyncPrivateKeyMethod, AsyncPrivateKeyMethodError, AsyncSelectCertError, BoxCustomVerifyFinish,
    BoxCustomVerifyFuture, BoxGetSessionFinish, BoxGetSessionFuture, BoxPrivateKeyMethodFinish,
    BoxPrivateKeyMethodFuture, BoxSelectCertActionFinish, BoxSelectCertActionFuture,
    BoxSelectCertFinish, BoxSelectCertFuture, ExDataFuture,
};
pub use self::connector::{
    ClientSession, ConnectConfiguration, SslAcceptor, SslAcceptorBuilder, SslConnector,
    SslConnectorBuilder,
};
#[cfg(feature = "credential")]
pub use self::credential::{SslCredential, SslCredentialBuilder, SslCredentialRef};
pub use self::early_data::EarlyDataReason;
pub use self::ech::SslEchKeysRef;
#[cfg(not(feature = "fips"))]
pub use self::ech_grease::{
    EchGreaseAead, EchGreaseParameters, EchGreaseRounding, EchGreaseSizeInfo,
};
pub use self::error::{Error, ErrorCode, HandshakeError};
pub use self::quic::{QuicEncryptionLevel, QuicMethod, QuicMethodError};

use self::connector::earliest_not_after;

mod async_callbacks;
mod bio;
pub use self::bio::{BioReadBuf, ReadUninit};
mod callbacks;
mod connector;
#[cfg(feature = "credential")]
mod credential;
mod early_data;
mod ech;
#[cfg(not(feature = "fips"))]
mod ech_grease;
mod error;
mod mut_only;
mod quic;
#[cfg(test)]
mod test;

bitflags! {
    /// Options controlling the behavior of an `SslContext`.
    #[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
    pub struct SslOptions: c_uint {

        /// `BoringSSL`'s enabled-by-default options, including compatibility
        /// with legacy servers without the renegotiation-info extension.
        const ALL = ffi::SSL_OP_ALL as _;

        /// Do not query the MTU.
        ///
        /// Only affects DTLS connections.
        const NO_QUERY_MTU = ffi::SSL_OP_NO_QUERY_MTU as _;

        /// Disables the use of session tickets for session resumption.
        const NO_TICKET = ffi::SSL_OP_NO_TICKET as _;






        /// Use the server's preferences rather than the client's when selecting a cipher.
        ///
        /// This has no effect on the client side.
        const CIPHER_SERVER_PREFERENCE = ffi::SSL_OP_CIPHER_SERVER_PREFERENCE as _;




        /// Disables the use of TLSv1.0.
        const NO_TLSV1 = ffi::SSL_OP_NO_TLSv1 as _;

        /// Disables the use of TLSv1.1.
        const NO_TLSV1_1 = ffi::SSL_OP_NO_TLSv1_1 as _;

        /// Disables the use of TLSv1.2.
        const NO_TLSV1_2 = ffi::SSL_OP_NO_TLSv1_2 as _;

        /// Disables the use of TLSv1.3.
        const NO_TLSV1_3 = ffi::SSL_OP_NO_TLSv1_3 as _;

        /// Disables the use of DTLSv1.0
        const NO_DTLSV1 = ffi::SSL_OP_NO_DTLSv1 as _;

        /// Disables the use of DTLSv1.2.
        const NO_DTLSV1_2 = ffi::SSL_OP_NO_DTLSv1_2 as _;


        /// Disables TLS 1.3 PSK resumption and 0-RTT by omitting PSK-DHE-KE.
        ///
        /// `BoringSSL` does not implement PSK-KE, so disabling PSK-DHE-KE also prevents the client
        /// from offering a pre-shared key. See [RFC 8446 section 4.2.9].
        ///
        /// [RFC 8446 section 4.2.9]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.9
        #[cfg(not(feature = "fips"))]
        const NO_PSK_DHE_KE = ffi::SSL_OP_NO_PSK_DHE_KE as _;
    }
}

bitflags! {
    /// Options controlling the behavior of an `SslContext`.
    #[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
    pub struct SslMode: c_uint {
        /// Enables "short writes".
        ///
        /// Normally, a write in OpenSSL will always write out all of the requested data, even if it
        /// requires more than one TLS record or write to the underlying stream. This option will
        /// cause a write to return after writing a single TLS record instead.
        const ENABLE_PARTIAL_WRITE = ffi::SSL_MODE_ENABLE_PARTIAL_WRITE as _;

        /// Disables a check that the data buffer has not moved between calls when operating in a
        /// nonblocking context.
        const ACCEPT_MOVING_WRITE_BUFFER = ffi::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER as _;


        /// Disables automatic chain building when verifying a peer's certificate.
        ///
        /// TLS peers are responsible for sending the entire certificate chain from the leaf to a
        /// trusted root, but some will incorrectly not do so. OpenSSL will try to build the chain
        /// out of certificates it knows of, and this option will disable that behavior.
        const NO_AUTO_CHAIN = ffi::SSL_MODE_NO_AUTO_CHAIN as _;


        /// Sends the fake `TLS_FALLBACK_SCSV` cipher suite in the `ClientHello` message of a
        /// handshake.
        ///
        /// This should only be enabled if a client has failed to connect to a server which
        /// attempted to downgrade the protocol version of the session.
        ///
        /// Do not use this unless you know what you're doing!
        const SEND_FALLBACK_SCSV = ffi::SSL_MODE_SEND_FALLBACK_SCSV as _;
    }
}

/// A type specifying the kind of protocol an `SslContext` will speak.
#[derive(Copy, Clone)]
pub struct SslMethod {
    ptr: *const ffi::SSL_METHOD,
    is_x509_method: bool,
}

impl SslMethod {
    /// Support all versions of the TLS protocol.
    #[corresponds(TLS_method)]
    #[must_use = "Use the selected protocol method to construct the TLS context."]
    pub fn tls() -> Self {
        // SAFETY: The TLS method is a process-lifetime immutable native descriptor returned by BoringSSL.
        unsafe {
            Self {
                ptr: ffi::TLS_method(),
                is_x509_method: true,
            }
        }
    }

    /// TLS without native X.509 parsing.
    ///
    /// Client handshakes fail unless a custom certificate verifier is installed
    /// using [`SslContextBuilder::set_custom_verify_callback`] or
    /// [`SslRef::set_custom_verify_callback`].
    ///
    /// # Safety
    /// The caller must install an appropriate custom certificate verifier
    /// before using this method for authenticated TLS connections and must
    /// not use native X.509 operations on the resulting non-X.509 context.
    #[must_use = "Use the selected protocol method to construct the TLS context."]
    pub unsafe fn tls_with_buffer() -> Self {
        // SAFETY: The explicitly requested no-X509 TLS method is a process-lifetime immutable native descriptor.
        unsafe {
            Self {
                ptr: ffi::TLS_with_buffers_method(),
                is_x509_method: false,
            }
        }
    }

    /// Support all versions of the DTLS protocol.
    #[corresponds(DTLS_method)]
    #[must_use = "Use the selected protocol method to construct the TLS context."]
    pub fn dtls() -> Self {
        // SAFETY: The DTLS method is a process-lifetime immutable native descriptor returned by BoringSSL.
        unsafe {
            Self {
                ptr: ffi::DTLS_method(),
                is_x509_method: true,
            }
        }
    }

    /// Constructs an `SslMethod` from a pointer to the underlying OpenSSL value.
    ///
    /// This method assumes that the `SslMethod` is not configured for X.509
    /// certificates. The user can call `SslMethod::assume_x509_method`
    /// to change that.
    ///
    /// # Safety
    ///
    /// The caller must ensure the pointer is valid.
    #[corresponds(TLS_server_method)]
    #[must_use = "The returned builder assumes ownership of the supplied native context."]
    pub const unsafe fn from_ptr(ptr: *const ffi::SSL_METHOD) -> Self {
        Self {
            ptr,
            is_x509_method: false,
        }
    }

    /// Assumes that this `SslMethod` is configured for X.509 certificates.
    ///
    /// # Safety
    ///
    /// The native context must use the X.509 certificate method and be exclusively owned.
    /// No other reference may access its extra-data slots during this operation.
    pub const unsafe fn assume_x509(&mut self) {
        self.is_x509_method = true;
    }

    /// Returns a pointer to the underlying OpenSSL value.
    #[must_use = "The returned native representation is needed by the caller."]
    pub const fn as_ptr(self) -> *const ffi::SSL_METHOD {
        self.ptr
    }
}

// SAFETY: native TLS method pointers are immutable process-lifetime descriptors;
// the Rust wrapper owns no mutable state behind the pointer.
unsafe impl Sync for SslMethod {}
// SAFETY: transferring this descriptor cannot invalidate its static storage.
unsafe impl Send for SslMethod {}

bitflags! {
    /// Options controlling the behavior of certificate verification.
    #[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
    pub struct SslVerifyMode: i32 {
        /// Verifies that the peer's certificate is trusted.
        ///
        /// On the server side, this will cause OpenSSL to request a certificate from the client.
        const PEER = ffi::SSL_VERIFY_PEER;

        /// Disables verification of the peer's certificate.
        ///
        /// On the server side, this will cause OpenSSL to not request a certificate from the
        /// client. On the client side, the certificate will be checked for validity, but the
        /// negotiation will continue regardless of the result of that check.
        const NONE = ffi::SSL_VERIFY_NONE;

        /// On the server side, abort the handshake if the client did not send a certificate.
        ///
        /// This should be paired with `SSL_VERIFY_PEER`. It has no effect on the client side.
        const FAIL_IF_NO_PEER_CERT = ffi::SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SslVerifyError {
    Invalid(SslAlert),
    Retry,
}

// Sends the alert BoringSSL's built-in verifier sends for the same result.
impl From<X509VerifyError> for SslVerifyError {
    fn from(err: X509VerifyError) -> Self {
        // SAFETY: only maps an integer.
        let alert = unsafe { ffi::SSL_alert_from_verify_result(c_long::from(err.as_raw())) };
        Self::Invalid(SslAlert(alert))
    }
}

bitflags! {
    /// Options controlling the behavior of session caching.
    #[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
    pub struct SslSessionCacheMode: c_int {
        /// No session caching for the client or server takes place.
        const OFF = ffi::SSL_SESS_CACHE_OFF;

        /// Enable session caching on the client side.
        ///
        /// OpenSSL has no way of identifying the proper session to reuse automatically, so the
        /// application is responsible for setting it explicitly via
        /// [`ConnectConfiguration::set_client_session`] or [`SslRef::set_session`].
        const CLIENT = ffi::SSL_SESS_CACHE_CLIENT;

        /// Enable session caching on the server side.
        ///
        /// This is the default mode.
        const SERVER = ffi::SSL_SESS_CACHE_SERVER;

        /// Enable session caching on both the client and server side.
        const BOTH = ffi::SSL_SESS_CACHE_BOTH;

        /// Disable automatic removal of expired sessions from the session cache.
        const NO_AUTO_CLEAR = ffi::SSL_SESS_CACHE_NO_AUTO_CLEAR;

        /// Disable use of the internal session cache for session lookups.
        const NO_INTERNAL_LOOKUP = ffi::SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;

        /// Disable use of the internal session cache for session storage.
        const NO_INTERNAL_STORE = ffi::SSL_SESS_CACHE_NO_INTERNAL_STORE;

        /// Disable use of the internal session cache for storage and lookup.
        const NO_INTERNAL = ffi::SSL_SESS_CACHE_NO_INTERNAL;
    }
}

/// An identifier of the format of a certificate or key file.
#[derive(Copy, Clone)]
pub struct SslFiletype(c_int);

impl SslFiletype {
    /// The PEM format.
    ///
    /// This corresponds to `SSL_FILETYPE_PEM`.
    pub const PEM: Self = Self(ffi::SSL_FILETYPE_PEM);

    /// The ASN1 format.
    ///
    /// This corresponds to `SSL_FILETYPE_ASN1`.
    pub const ASN1: Self = Self(ffi::SSL_FILETYPE_ASN1);

    /// Constructs an `SslFiletype` from a raw OpenSSL value.
    #[must_use = "Use the wrapper returned for the supplied native representation."]
    pub const fn from_raw(raw: c_int) -> Self {
        Self(raw)
    }

    /// Returns the raw OpenSSL value represented by this type.
    #[must_use = "The returned native representation is needed by the caller."]
    pub const fn as_raw(self) -> c_int {
        self.0
    }
}

/// An identifier of a certificate status type.
#[derive(Copy, Clone)]
pub struct StatusType(c_int);

impl StatusType {
    /// An OSCP status.
    pub const OCSP: Self = Self(ffi::TLSEXT_STATUSTYPE_ocsp);

    /// Constructs a `StatusType` from a raw OpenSSL value.
    #[must_use = "Use the wrapper returned for the supplied native representation."]
    pub const fn from_raw(raw: c_int) -> Self {
        Self(raw)
    }

    /// Returns the raw OpenSSL value represented by this type.
    #[must_use = "The returned native representation is needed by the caller."]
    pub const fn as_raw(self) -> c_int {
        self.0
    }
}

/// An identifier of a session name type.
#[derive(Copy, Clone)]
pub struct NameType(c_int);

impl NameType {
    /// A host name.
    pub const HOST_NAME: Self = Self(ffi::TLSEXT_NAMETYPE_host_name);

    /// Constructs a `NameType` from a raw OpenSSL value.
    #[must_use = "Use the wrapper returned for the supplied native representation."]
    pub const fn from_raw(raw: c_int) -> Self {
        Self(raw)
    }

    /// Returns the raw OpenSSL value represented by this type.
    #[must_use = "The returned native representation is needed by the caller."]
    pub const fn as_raw(self) -> c_int {
        self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum CallbackRole {
    ServerName,
    TicketKey,
    Alpn,
    SelectCert,
    PrivateKey,
    Status,
    PskClient,
    PskServer,
    NewSession,
    RemoveSession,
    GetSession,
    Keylog,
    Info,
    Quic,
    #[cfg(not(feature = "fips"))]
    EchGrease,
}

static CONTEXT_CALLBACKS: LazyLock<IndexRegistry<SslContext, CallbackRole>> =
    LazyLock::new(IndexRegistry::new);
#[cfg(not(feature = "fips"))]
static SSL_CALLBACKS: LazyLock<IndexRegistry<Ssl, CallbackRole>> =
    LazyLock::new(IndexRegistry::new);

// One slot per verification callback, independent of the closure's concrete type.
// Context callbacks are immutable after publication; connection callbacks may
// replace themselves, so the trampoline retains its own Arc across invocation.
type VerifyCallback = Arc<dyn Fn(bool, &mut X509StoreContextRef) -> bool + Send + Sync>;
type CertVerifyCallback = Arc<dyn Fn(&mut X509StoreContextRef) -> bool + Send + Sync>;
type CustomVerifyCallback = Arc<dyn Fn(&mut SslRef) -> Result<(), SslVerifyError> + Send + Sync>;
static CTX_VERIFY_INDEX: IndexSlot<SslContext, Option<VerifyCallback>> =
    IndexSlot::new(SslContext::new_ex_index);
static CTX_CERT_VERIFY_INDEX: IndexSlot<SslContext, Option<CertVerifyCallback>> =
    IndexSlot::new(SslContext::new_ex_index);
static CTX_CUSTOM_VERIFY_INDEX: IndexSlot<SslContext, Option<CustomVerifyCallback>> =
    IndexSlot::new(SslContext::new_ex_index);
static SSL_VERIFY_INDEX: IndexSlot<Ssl, Option<VerifyCallback>> = IndexSlot::new(Ssl::new_ex_index);
static SSL_CUSTOM_VERIFY_INDEX: IndexSlot<Ssl, Option<CustomVerifyCallback>> =
    IndexSlot::new(Ssl::new_ex_index);

static SESSION_CTX_INDEX: IndexSlot<Ssl, SslContext> = IndexSlot::new(Ssl::new_ex_index);
static X509_FLAG_INDEX: IndexSlot<SslContext, bool> = IndexSlot::new(SslContext::new_ex_index);

/// An error returned from the SNI callback.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SniError(c_int);

impl SniError {
    /// Abort the handshake with a fatal alert.
    pub const ALERT_FATAL: Self = Self(ffi::SSL_TLSEXT_ERR_ALERT_FATAL);

    /// Send a warning alert to the client and continue the handshake.
    pub const ALERT_WARNING: Self = Self(ffi::SSL_TLSEXT_ERR_ALERT_WARNING);

    pub const NOACK: Self = Self(ffi::SSL_TLSEXT_ERR_NOACK);
}

/// An SSL/TLS alert.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SslAlert(c_int);

impl SslAlert {
    native_constants! {
        CLOSE_NOTIFY = ffi::SSL_AD_CLOSE_NOTIFY;
        UNEXPECTED_MESSAGE = ffi::SSL_AD_UNEXPECTED_MESSAGE;
        BAD_RECORD_MAC = ffi::SSL_AD_BAD_RECORD_MAC;
        DECRYPTION_FAILED = ffi::SSL_AD_DECRYPTION_FAILED;
        RECORD_OVERFLOW = ffi::SSL_AD_RECORD_OVERFLOW;
        DECOMPRESSION_FAILURE = ffi::SSL_AD_DECOMPRESSION_FAILURE;
        HANDSHAKE_FAILURE = ffi::SSL_AD_HANDSHAKE_FAILURE;
        NO_CERTIFICATE = ffi::SSL_AD_NO_CERTIFICATE;
        BAD_CERTIFICATE = ffi::SSL_AD_BAD_CERTIFICATE;
        UNSUPPORTED_CERTIFICATE = ffi::SSL_AD_UNSUPPORTED_CERTIFICATE;
        CERTIFICATE_REVOKED = ffi::SSL_AD_CERTIFICATE_REVOKED;
        CERTIFICATE_EXPIRED = ffi::SSL_AD_CERTIFICATE_EXPIRED;
        CERTIFICATE_UNKNOWN = ffi::SSL_AD_CERTIFICATE_UNKNOWN;
        ILLEGAL_PARAMETER = ffi::SSL_AD_ILLEGAL_PARAMETER;
        UNKNOWN_CA = ffi::SSL_AD_UNKNOWN_CA;
        ACCESS_DENIED = ffi::SSL_AD_ACCESS_DENIED;
        DECODE_ERROR = ffi::SSL_AD_DECODE_ERROR;
        DECRYPT_ERROR = ffi::SSL_AD_DECRYPT_ERROR;
        EXPORT_RESTRICTION = ffi::SSL_AD_EXPORT_RESTRICTION;
        PROTOCOL_VERSION = ffi::SSL_AD_PROTOCOL_VERSION;
        INSUFFICIENT_SECURITY = ffi::SSL_AD_INSUFFICIENT_SECURITY;
        INTERNAL_ERROR = ffi::SSL_AD_INTERNAL_ERROR;
        INAPPROPRIATE_FALLBACK = ffi::SSL_AD_INAPPROPRIATE_FALLBACK;
        USER_CANCELLED = ffi::SSL_AD_USER_CANCELLED;
        NO_RENEGOTIATION = ffi::SSL_AD_NO_RENEGOTIATION;
        MISSING_EXTENSION = ffi::SSL_AD_MISSING_EXTENSION;
        UNSUPPORTED_EXTENSION = ffi::SSL_AD_UNSUPPORTED_EXTENSION;
        CERTIFICATE_UNOBTAINABLE = ffi::SSL_AD_CERTIFICATE_UNOBTAINABLE;
        UNRECOGNIZED_NAME = ffi::SSL_AD_UNRECOGNIZED_NAME;
        BAD_CERTIFICATE_STATUS_RESPONSE = ffi::SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE;
        BAD_CERTIFICATE_HASH_VALUE = ffi::SSL_AD_BAD_CERTIFICATE_HASH_VALUE;
        UNKNOWN_PSK_IDENTITY = ffi::SSL_AD_UNKNOWN_PSK_IDENTITY;
        CERTIFICATE_REQUIRED = ffi::SSL_AD_CERTIFICATE_REQUIRED;
        NO_APPLICATION_PROTOCOL = ffi::SSL_AD_NO_APPLICATION_PROTOCOL;
    }

    /// Returns the alert's description code.
    #[must_use = "Use the returned native representation when crossing the native API boundary."]
    pub const fn as_raw(self) -> c_int {
        self.0
    }

    /// Returns a readable name of the alert, or "unknown".
    #[corresponds(SSL_alert_desc_string_long)]
    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    pub fn description(&self) -> &'static str {
        // SAFETY: The alert description lookup returns a static NUL-terminated native string.
        unsafe {
            CStr::from_ptr(ffi::SSL_alert_desc_string_long(self.0))
                .to_str()
                .unwrap_or("unknown")
        }
    }
}

/// An error returned from an ALPN selection callback.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AlpnError(c_int);

impl AlpnError {
    /// Terminate the handshake with a fatal alert.
    pub const ALERT_FATAL: Self = Self(ffi::SSL_TLSEXT_ERR_ALERT_FATAL);

    /// Do not select a protocol, but continue the handshake.
    pub const NOACK: Self = Self(ffi::SSL_TLSEXT_ERR_NOACK);
}

/// An error returned from a certificate selection callback.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SelectCertError(ffi::ssl_select_cert_result_t);

impl SelectCertError {
    /// A fatal error occurred and the handshake should be terminated.
    pub const ERROR: Self = Self(ffi::ssl_select_cert_result_t::ssl_select_cert_error);

    /// The operation could not be completed and should be retried later.
    pub const RETRY: Self = Self(ffi::ssl_select_cert_result_t::ssl_select_cert_retry);
}

/// An action returned from a certificate selection callback.
#[non_exhaustive]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SelectCertAction {
    /// Complete certificate selection normally.
    Success,
    /// Discard `ClientHelloInner` and continue with `ClientHelloOuter`.
    ///
    /// `BoringSSL` calls the callback again with `ClientHelloOuter` and continues the handshake
    /// without retry configs. This action is only valid when [`SslRef::ech_accepted`] is true;
    /// otherwise the handshake fails.
    /// Changes made to the connection while processing `ClientHelloInner` carry over to the outer
    /// `ClientHello`.
    DisableEch,
}

/// Extension types, to be used with `ClientHello::get_extension`.
///
/// Unrecognized wire identifiers are represented without loss.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct ExtensionType(u16);

impl ExtensionType {
    native_constants! {
        SERVER_NAME = crate::native_u16(ffi::TLSEXT_TYPE_server_name);
        STATUS_REQUEST = crate::native_u16(ffi::TLSEXT_TYPE_status_request);
        EC_POINT_FORMATS = crate::native_u16(ffi::TLSEXT_TYPE_ec_point_formats);
        SIGNATURE_ALGORITHMS = crate::native_u16(ffi::TLSEXT_TYPE_signature_algorithms);
        TRUST_ANCHORS = crate::native_u16(ffi::TLSEXT_TYPE_trust_anchors);
        SRTP = crate::native_u16(ffi::TLSEXT_TYPE_srtp);
        APPLICATION_LAYER_PROTOCOL_NEGOTIATION = crate::native_u16(ffi::TLSEXT_TYPE_application_layer_protocol_negotiation);
        PADDING = crate::native_u16(ffi::TLSEXT_TYPE_padding);
        EXTENDED_MASTER_SECRET = crate::native_u16(ffi::TLSEXT_TYPE_extended_master_secret);
        QUIC_TRANSPORT_PARAMETERS_LEGACY = crate::native_u16(ffi::TLSEXT_TYPE_quic_transport_parameters_legacy);
        QUIC_TRANSPORT_PARAMETERS_STANDARD = crate::native_u16(ffi::TLSEXT_TYPE_quic_transport_parameters_standard);
        CERT_COMPRESSION = crate::native_u16(ffi::TLSEXT_TYPE_cert_compression);
        SESSION_TICKET = crate::native_u16(ffi::TLSEXT_TYPE_session_ticket);
        SUPPORTED_GROUPS = crate::native_u16(ffi::TLSEXT_TYPE_supported_groups);
        PRE_SHARED_KEY = crate::native_u16(ffi::TLSEXT_TYPE_pre_shared_key);
        EARLY_DATA = crate::native_u16(ffi::TLSEXT_TYPE_early_data);
        SUPPORTED_VERSIONS = crate::native_u16(ffi::TLSEXT_TYPE_supported_versions);
        COOKIE = crate::native_u16(ffi::TLSEXT_TYPE_cookie);
        PSK_KEY_EXCHANGE_MODES = crate::native_u16(ffi::TLSEXT_TYPE_psk_key_exchange_modes);
        CERTIFICATE_AUTHORITIES = crate::native_u16(ffi::TLSEXT_TYPE_certificate_authorities);
        SIGNATURE_ALGORITHMS_CERT = crate::native_u16(ffi::TLSEXT_TYPE_signature_algorithms_cert);
        KEY_SHARE = crate::native_u16(ffi::TLSEXT_TYPE_key_share);
        RENEGOTIATE = crate::native_u16(ffi::TLSEXT_TYPE_renegotiate);
        DELEGATED_CREDENTIAL = crate::native_u16(ffi::TLSEXT_TYPE_delegated_credential);
        APPLICATION_SETTINGS = crate::native_u16(ffi::TLSEXT_TYPE_application_settings);
        APPLICATION_SETTINGS_OLD = crate::native_u16(ffi::TLSEXT_TYPE_application_settings_old);
        ENCRYPTED_CLIENT_HELLO = crate::native_u16(ffi::TLSEXT_TYPE_encrypted_client_hello);
        CERTIFICATE_TIMESTAMP = crate::native_u16(ffi::TLSEXT_TYPE_certificate_timestamp);
        NEXT_PROTO_NEG = crate::native_u16(ffi::TLSEXT_TYPE_next_proto_neg);
        CHANNEL_ID = crate::native_u16(ffi::TLSEXT_TYPE_channel_id);
        #[cfg(not(feature = "fips"))]
        RECORD_SIZE_LIMIT = crate::native_u16(ffi::TLSEXT_TYPE_record_size_limit);
        SERVER_PADDING = crate::native_u16(ffi::TLSEXT_TYPE_server_padding);
    }

    /// Returns the wire extension type.
    #[must_use = "Use the returned native representation when crossing the native API boundary."]
    pub const fn as_raw(self) -> u16 {
        self.0
    }

    /// Whether this is an [RFC 8701] GREASE value.
    ///
    /// [RFC 8701]: https://www.rfc-editor.org/rfc/rfc8701.html
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub const fn is_grease(self) -> bool {
        self.0 & 0x0f0f == 0x0a0a && self.0 >> 8 == self.0 & 0xff
    }
}

impl From<u16> for ExtensionType {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

/// An SSL/TLS/DTLS protocol version.
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub struct SslVersion(u16);

impl SslVersion {
    native_constants! {
        /// `SSLv3`
        SSL3 = crate::native_u16(ffi::SSL3_VERSION);

        /// TLSv1.0
        TLS1 = crate::native_u16(ffi::TLS1_VERSION);

        /// TLSv1.1
        TLS1_1 = crate::native_u16(ffi::TLS1_1_VERSION);

        /// TLSv1.2
        TLS1_2 = crate::native_u16(ffi::TLS1_2_VERSION);

        /// TLSv1.3
        TLS1_3 = crate::native_u16(ffi::TLS1_3_VERSION);

        /// DTLSv1.0
        DTLS1 = crate::native_u16(ffi::DTLS1_VERSION);

        /// DTLSv1.2
        DTLS1_2 = crate::native_u16(ffi::DTLS1_2_VERSION);

        /// DTLSv1.3
        DTLS1_3 = crate::native_u16(ffi::DTLS1_3_VERSION);
    }
}

impl TryFrom<u16> for SslVersion {
    type Error = &'static str;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match i32::from(value) {
            ffi::SSL3_VERSION
            | ffi::TLS1_VERSION
            | ffi::TLS1_1_VERSION
            | ffi::TLS1_2_VERSION
            | ffi::TLS1_3_VERSION
            | ffi::DTLS1_VERSION
            | ffi::DTLS1_2_VERSION
            | ffi::DTLS1_3_VERSION => Ok(Self(value)),
            _ => Err("Unknown SslVersion"),
        }
    }
}

impl fmt::Debug for SslVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Self::SSL3 => "SSL3",
            Self::TLS1 => "TLS1",
            Self::TLS1_1 => "TLS1_1",
            Self::TLS1_2 => "TLS1_2",
            Self::TLS1_3 => "TLS1_3",
            Self::DTLS1 => "DTLS1",
            Self::DTLS1_2 => "DTLS1_2",
            Self::DTLS1_3 => "DTLS1_3",
            _ => return write!(f, "{:#06x}", self.0),
        })
    }
}

impl fmt::Display for SslVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Self::SSL3 => "SSLv3",
            Self::TLS1 => "TLSv1",
            Self::TLS1_1 => "TLSv1.1",
            Self::TLS1_2 => "TLSv1.2",
            Self::TLS1_3 => "TLSv1.3",
            Self::DTLS1 => "DTLSv1.0",
            Self::DTLS1_2 => "DTLSv1.2",
            Self::DTLS1_3 => "DTLSv1.3",
            _ => return write!(f, "unknown ({:#06x})", self.0),
        })
    }
}

/// A signature verification algorithm.
///
/// Unrecognized wire identifiers are represented without loss.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SslSignatureAlgorithm(u16);

impl SslSignatureAlgorithm {
    native_constants! {
        RSA_PKCS1_SHA1 = crate::native_u16(ffi::SSL_SIGN_RSA_PKCS1_SHA1);

        RSA_PKCS1_SHA256 = crate::native_u16(ffi::SSL_SIGN_RSA_PKCS1_SHA256);

        RSA_PKCS1_SHA384 = crate::native_u16(ffi::SSL_SIGN_RSA_PKCS1_SHA384);

        RSA_PKCS1_SHA512 = crate::native_u16(ffi::SSL_SIGN_RSA_PKCS1_SHA512);

        RSA_PKCS1_MD5_SHA1 = crate::native_u16(ffi::SSL_SIGN_RSA_PKCS1_MD5_SHA1);

        ECDSA_SHA1 = crate::native_u16(ffi::SSL_SIGN_ECDSA_SHA1);

        ECDSA_SECP256R1_SHA256 = crate::native_u16(ffi::SSL_SIGN_ECDSA_SECP256R1_SHA256);

        ECDSA_SECP384R1_SHA384 = crate::native_u16(ffi::SSL_SIGN_ECDSA_SECP384R1_SHA384);

        ECDSA_SECP521R1_SHA512 = crate::native_u16(ffi::SSL_SIGN_ECDSA_SECP521R1_SHA512);

        RSA_PSS_RSAE_SHA256 = crate::native_u16(ffi::SSL_SIGN_RSA_PSS_RSAE_SHA256);

        RSA_PSS_RSAE_SHA384 = crate::native_u16(ffi::SSL_SIGN_RSA_PSS_RSAE_SHA384);

        RSA_PSS_RSAE_SHA512 = crate::native_u16(ffi::SSL_SIGN_RSA_PSS_RSAE_SHA512);

        ED25519 = crate::native_u16(ffi::SSL_SIGN_ED25519);

        ML_DSA_44 = crate::native_u16(ffi::SSL_SIGN_ML_DSA_44);

        ML_DSA_65 = crate::native_u16(ffi::SSL_SIGN_ML_DSA_65);

        ML_DSA_87 = crate::native_u16(ffi::SSL_SIGN_ML_DSA_87);
    }

    /// Returns the name of this signature algorithm, or `None` if unknown.
    ///
    /// For ECDSA algorithms the TLS 1.3 form is returned
    /// (e.g. `ecdsa_secp256r1_sha256`), not the TLS 1.2 form (`ecdsa_sha256`).
    #[corresponds(SSL_get_signature_algorithm_name)]
    #[must_use = "Use the returned name for reporting or selecting the native identifier."]
    pub fn name(&self) -> Option<&'static str> {
        // SAFETY: The signature-algorithm name is either null or a static NUL-terminated native string.
        unsafe {
            // Pass `include_curve = 1` to get the TLS 1.3 form for ECDSA algorithms
            // (e.g. `ecdsa_secp256r1_sha256` rather than the TLS 1.2 `ecdsa_sha256`).
            let ptr = ffi::SSL_get_signature_algorithm_name(self.0, 1);
            if ptr.is_null() {
                None
            } else {
                CStr::from_ptr(ptr).to_str().ok()
            }
        }
    }
}

impl fmt::Display for SslSignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "unknown ({:#06x})", self.0),
        }
    }
}

impl From<u16> for SslSignatureAlgorithm {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

/// A TLS key share group.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct KeyShare(u16);

impl KeyShare {
    native_constants! {
        P256 = crate::native_u16(ffi::SSL_GROUP_SECP256R1);

        P384 = crate::native_u16(ffi::SSL_GROUP_SECP384R1);

        P521 = crate::native_u16(ffi::SSL_GROUP_SECP521R1);

        X25519 = crate::native_u16(ffi::SSL_GROUP_X25519);

        X25519_MLKEM768 = crate::native_u16(ffi::SSL_GROUP_X25519_MLKEM768);

        X25519_KYBER768_DRAFT00 = crate::native_u16(ffi::SSL_GROUP_X25519_KYBER768_DRAFT00);

        P256_KYBER768_DRAFT00 = crate::native_u16(ffi::SSL_GROUP_P256_KYBER768_DRAFT00);

        MLKEM1024 = crate::native_u16(ffi::SSL_GROUP_MLKEM1024);

        #[cfg(not(feature = "fips"))]
        FFDHE2048 = crate::native_u16(ffi::SSL_GROUP_FFDHE2048);

        #[cfg(not(feature = "fips"))]
        FFDHE3072 = crate::native_u16(ffi::SSL_GROUP_FFDHE3072);
    }
}

/// A TLS 1.3 cipher suite.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Tls13Cipher(u16);

impl Tls13Cipher {
    native_constants! {
        AES_128_GCM_SHA256 = crate::native_u16(ffi::SSL_CIPHER_AES_128_GCM_SHA256);

        AES_256_GCM_SHA384 = crate::native_u16(ffi::SSL_CIPHER_AES_256_GCM_SHA384);

        CHACHA20_POLY1305_SHA256 = crate::native_u16(ffi::SSL_CIPHER_CHACHA20_POLY1305_SHA256);
    }
}

/// A compliance policy.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CompliancePolicy(ffi::ssl_compliance_policy_t);

impl CompliancePolicy {
    /// Does nothing, however setting this does not undo other policies, so trying to set this is an error.
    pub const NONE: Self = Self(ffi::ssl_compliance_policy_t::ssl_compliance_policy_none);

    /// Configures a TLS connection to try and be compliant with NIST requirements, but does not guarantee success.
    /// This policy can be called even if Boring is not built with FIPS.
    pub const FIPS_202205: Self =
        Self(ffi::ssl_compliance_policy_t::ssl_compliance_policy_fips_202205);

    /// Partially configures a TLS connection to be compliant with WPA3. Callers must enforce certificate chain requirements themselves.
    /// Use of this policy is less secure than the default and not recommended.
    pub const WPA3_192_202304: Self =
        Self(ffi::ssl_compliance_policy_t::ssl_compliance_policy_wpa3_192_202304);
}

// IANA assigned identifier of compression algorithm. See https://www.rfc-editor.org/rfc/rfc8879.html#name-compression-algorithms
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct CertificateCompressionAlgorithm(u16);

impl CertificateCompressionAlgorithm {
    native_constants! {
        ZLIB = crate::native_u16(ffi::TLSEXT_cert_compression_zlib);

        BROTLI = crate::native_u16(ffi::TLSEXT_cert_compression_brotli);

        #[cfg(not(feature = "fips"))]
        ZSTD = crate::native_u16(ffi::TLSEXT_cert_compression_zstd);
    }
}

/// A standard implementation of protocol selection for Application Layer Protocol Negotiation
/// (ALPN).
///
/// `server` should contain the server's list of supported protocols and `client` the client's. They
/// must both be in the ALPN wire format. See the documentation for
/// [`SslContextBuilder::set_alpn_protos`] for details.
///
/// It will select the first protocol supported by the server which is also supported by the client.
///
/// [`SslContextBuilder::set_alpn_protos`]: struct.SslContextBuilder.html#method.set_alpn_protos
#[corresponds(SSL_select_next_proto)]
#[must_use = "Use the negotiated protocol to dispatch the application connection."]
pub fn select_next_proto<'a>(server: &'a [u8], client: &'a [u8]) -> Option<&'a [u8]> {
    if server.is_empty() || client.is_empty() {
        return None;
    }

    // SAFETY: The input protocol lists remain live; output pointer/length slots are writable and point into the inputs.
    unsafe {
        let mut out = ptr::null_mut();
        let mut outlen = 0;
        let r = ffi::SSL_select_next_proto(
            &raw mut out,
            &raw mut outlen,
            server.as_ptr(),
            try_int(server.len()).ok()?,
            client.as_ptr(),
            try_int(client.len()).ok()?,
        );

        if r == ffi::OPENSSL_NPN_NEGOTIATED {
            Some(slice::from_raw_parts(out.cast_const(), outlen as usize))
        } else {
            None
        }
    }
}

/// Options controlling the behavior of the info callback.
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
pub struct SslInfoCallbackMode(i32);

impl SslInfoCallbackMode {
    /// Signaled for each alert received, warning or fatal.
    pub const READ_ALERT: Self = Self(ffi::SSL_CB_READ_ALERT);

    /// Signaled for each alert sent, warning or fatal.
    pub const WRITE_ALERT: Self = Self(ffi::SSL_CB_WRITE_ALERT);

    /// Signaled when a handshake begins.
    pub const HANDSHAKE_START: Self = Self(ffi::SSL_CB_HANDSHAKE_START);

    /// Signaled when a handshake completes successfully.
    pub const HANDSHAKE_DONE: Self = Self(ffi::SSL_CB_HANDSHAKE_DONE);

    /// Signaled when a handshake progresses to a new state.
    pub const ACCEPT_LOOP: Self = Self(ffi::SSL_CB_ACCEPT_LOOP);

    /// Signaled when a client-side handshake progresses to a new state.
    pub const CONNECT_LOOP: Self = Self(ffi::SSL_CB_CONNECT_LOOP);

    /// Signaled when the current iteration of the server-side handshake state machine completes.
    pub const ACCEPT_EXIT: Self = Self(ffi::SSL_CB_ACCEPT_EXIT);

    /// Signaled when the current iteration of the client-side handshake state machine completes.
    pub const CONNECT_EXIT: Self = Self(ffi::SSL_CB_CONNECT_EXIT);
}

/// The `value` argument to an info callback. The most-significant byte is the alert level, while
/// the least significant byte is the alert itself.
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
pub enum SslInfoCallbackValue {
    /// The unit value (1). Some `BoringSSL` info callback modes, like `ACCEPT_LOOP`, always call the
    /// callback with `value` set to the unit value. If the [`SslInfoCallbackValue`] is a
    /// `Unit`, it can safely be disregarded.
    Unit,
    /// An alert. See [`SslInfoCallbackAlert`] for details on how to manipulate the alert. This
    /// variant should only be present if the info callback was called with a `READ_ALERT` or
    /// `WRITE_ALERT` mode.
    Alert(SslInfoCallbackAlert),
}

/// Session-ticket key callback mode and the corresponding ticket header buffers.
pub enum TicketKeyMode<'a> {
    /// Populate the key name and IV for a new ticket.
    Encrypt {
        key_name: &'a mut [u8; 16],
        iv: &'a mut [u8; ffi::EVP_MAX_IV_LENGTH as usize],
    },
    /// Inspect the immutable key name and IV supplied by the peer.
    Decrypt {
        key_name: &'a [u8; 16],
        iv: &'a [u8; ffi::EVP_MAX_IV_LENGTH as usize],
    },
}

/// Ticket key callback status.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TicketKeyCallbackResult {
    /// Abort the handshake.
    Error,

    /// Continue with a full handshake.
    ///
    /// When in decryption mode, this indicates that the peer supplied session ticket was not
    /// recognized. When in encryption mode, this instructs btls to not send a session ticket.
    ///
    /// # Note
    ///
    /// This is a decryption specific status code when using the submoduled `BoringSSL`.
    Noop,

    /// Resumption callback was successful.
    ///
    /// When in decryption mode, attempt an abbreviated handshake via session resumption. When in
    /// encryption mode, provide a new ticket to the client.
    Success,

    /// Resumption callback was successful. Attempt an abbreviated handshake, and additionally
    /// provide new session tickets to the peer.
    ///
    /// Session resumption short-circuits some security checks of a full-handshake, in exchange for
    /// potential performance gains. For this reason, a session ticket should only be valid for a
    /// limited time. Providing the peer with renewed session tickets allows them to continue
    /// session resumption with the new tickets.
    ///
    /// # Note
    ///
    /// This is a decryption specific status code.
    DecryptSuccessRenew,
}

impl From<TicketKeyCallbackResult> for c_int {
    fn from(value: TicketKeyCallbackResult) -> Self {
        match value {
            TicketKeyCallbackResult::Error => -1,
            TicketKeyCallbackResult::Noop => 0,
            TicketKeyCallbackResult::Success => 1,
            TicketKeyCallbackResult::DecryptSuccessRenew => 2,
        }
    }
}

#[derive(Hash, Copy, Clone, PartialOrd, Ord, Eq, PartialEq, Debug)]
pub struct SslInfoCallbackAlert(c_int);

impl SslInfoCallbackAlert {
    /// The level of the SSL alert.
    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    pub const fn alert_level(self) -> Ssl3AlertLevel {
        let value = self.0 >> 8;
        Ssl3AlertLevel(value)
    }

    /// The value of the SSL alert.
    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    pub fn alert(self) -> SslAlert {
        let value = self.0 & i32::from(u8::MAX);
        SslAlert(value)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Ssl3AlertLevel(c_int);

impl Ssl3AlertLevel {
    pub const WARNING: Self = Self(ffi::SSL3_AL_WARNING);
    pub const FATAL: Self = Self(ffi::SSL3_AL_FATAL);
}

/// A builder for `SslContext`s.
pub struct SslContextBuilder {
    ctx: SslContext,
    /// If it's not shared, it can be exposed as mutable
    has_shared_cert_store: bool,
}

impl SslContextBuilder {
    /// Creates a new `SslContextBuilder`.
    #[corresponds(SSL_CTX_new)]
    pub fn new(method: SslMethod) -> Result<Self, ErrorStack> {
        // SAFETY: The returned context pointer is checked for null and then transferred to its exclusive builder.
        unsafe {
            init();
            let ctx = cvt_p(ffi::SSL_CTX_new(method.as_ptr()))?;
            let mut builder = Self::from_ptr(ctx);

            if method.is_x509_method {
                builder.ctx.assume_x509()?;
            }

            Ok(builder)
        }
    }

    /// Creates an `SslContextBuilder` from a pointer to a raw OpenSSL value.
    ///
    /// This method can find out whether `ctx` is configured for X.509 certificates
    /// if `ctx` was itself a context created by this crate. If it was created by
    /// other means and it supports X.509 certificates, the use can call
    /// `SslContextBuilder::assume_x509`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the pointer is valid and uniquely owned by the builder.
    /// The context must own its cert store exclusively.
    pub unsafe fn from_ptr(ctx: *mut ffi::SSL_CTX) -> Self {
        Self {
            // SAFETY: The caller provides an owned, initialized native SSL context and transfers ownership once.
            ctx: unsafe { SslContext::from_ptr(ctx) },
            has_shared_cert_store: false,
        }
    }

    /// Assumes that this `SslContextBuilder` is configured for X.509 certificates.
    ///
    /// # Safety
    ///
    /// The native context must use the X.509 certificate method and be exclusively owned.
    /// No other reference may access its extra-data slots during this operation.
    ///
    /// # Errors
    ///
    /// Registration or replacement of the native X.509 marker fails.
    pub unsafe fn assume_x509(&mut self) -> Result<(), ErrorStack> {
        // SAFETY: The caller established that this uniquely owned context really uses the X509 method.
        unsafe { self.ctx.assume_x509() }
    }

    /// Returns a pointer to the raw OpenSSL value.
    #[must_use = "Use the returned native representation when crossing the native API boundary."]
    pub fn as_ptr(&self) -> *mut ffi::SSL_CTX {
        self.ctx.as_ptr()
    }

    /// Registers a certificate verification callback that replaces the default verification
    /// process.
    ///
    /// The callback returns true if the certificate chain is valid, and false if not.
    /// A viable verification result value (either `Ok(())` or an `Err(X509VerifyError)`) must be
    /// reflected in the error member of `X509StoreContextRef`, which can be done by calling
    /// `X509StoreContextRef::set_error`. However, the callback's return value determines
    /// whether the chain is accepted or not.
    ///
    /// *Warning*: Providing a complete verification procedure is a complex task. See
    /// [`SSL_CTX_set_cert_verify_callback`](https://docs.openssl.org/master/man3/SSL_CTX_set_cert_verify_callback/#notes)
    /// for more information.
    ///
    /// # Errors
    /// The context does not support X.509 certificates.
    ///
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_set_cert_verify_callback)]
    pub fn set_cert_verify_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&mut X509StoreContextRef) -> bool + 'static + Sync + Send,
    {
        self.ctx.check_x509()?;

        self.set_ex_data(CTX_CERT_VERIFY_INDEX.register()?, Some(Arc::new(callback)))?;
        // SAFETY: the live context owns the registered callback state.
        unsafe {
            ffi::SSL_CTX_set_cert_verify_callback(
                self.as_ptr(),
                Some(raw_cert_verify),
                ptr::null_mut(),
            );
        }
        Ok(())
    }

    /// Removes the whole-chain X.509 verification callback. Any separately
    /// configured per-certificate or custom TLS verifier remains installed.
    /// # Errors
    /// The context does not support X.509 certificates.
    #[corresponds(SSL_CTX_set_cert_verify_callback)]
    pub fn clear_cert_verify_callback(&mut self) -> Result<(), ErrorStack> {
        self.ctx.check_x509()?;
        // SAFETY: the builder has exclusive native context access.
        unsafe { ffi::SSL_CTX_set_cert_verify_callback(self.as_ptr(), None, ptr::null_mut()) };
        self.clear_verifier_slot(&CTX_CERT_VERIFY_INDEX)
    }

    /// Changes only the certificate verification mode, preserving all callbacks.
    /// # Errors
    /// The context does not support X.509 certificates.
    #[corresponds(SSL_CTX_set_verify)]
    pub fn set_verify_mode(&mut self, mode: SslVerifyMode) -> Result<(), ErrorStack> {
        self.ctx.check_x509()?;
        // SAFETY: exclusive X.509 context; preserve the currently installed callback.
        unsafe {
            let callback = ffi::SSL_CTX_get_verify_callback(self.as_ptr());
            ffi::SSL_CTX_set_verify(self.as_ptr(), c_int::from(mode.bits()), callback);
        }
        Ok(())
    }

    fn clear_verifier_slot<T: 'static + Send + Sync>(
        &mut self,
        slot: &IndexSlot<SslContext, Option<T>>,
    ) -> Result<(), ErrorStack> {
        if let Some(index) = slot.get()
            && self.ctx.ex_data(index).is_some()
        {
            self.set_ex_data(index, None)?;
        }
        Ok(())
    }

    /// Returns the verify mode set by [`Self::set_verify_mode`] or one of the verify callbacks.
    ///
    /// An explicit [`SslVerifyMode::NONE`] reads the same as the default.
    ///
    /// # Errors
    /// The context is not configured for X.509 certificates.
    #[corresponds(SSL_CTX_get_verify_mode)]
    #[must_use = "Use the returned flags to inspect current configuration."]
    pub fn verify_mode(&self) -> Result<SslVerifyMode, ErrorStack> {
        self.ctx.verify_mode()
    }

    /// Configures the certificate verification method for new connections and
    /// registers a verification callback.
    ///
    /// *Warning*: This callback does not replace the default certificate verification
    /// process and is, instead, called multiple times in the course of that process.
    /// It is very difficult to implement this callback correctly, without inadvertently
    /// relying on implementation details or making incorrect assumptions about when the
    /// callback is called.
    ///
    /// Instead, use [`SslContextBuilder::set_custom_verify_callback`] to customize certificate verification.
    /// Those callbacks can inspect the peer-sent chain, call [`X509StoreContextRef::verify_cert`]
    /// and inspect the result, or perform other operations more straightforwardly.
    ///
    /// # Errors
    /// The context does not support X.509 certificates.
    ///
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_set_verify)]
    pub fn set_verify_callback<F>(
        &mut self,
        mode: SslVerifyMode,
        callback: F,
    ) -> Result<(), ErrorStack>
    where
        F: Fn(bool, &mut X509StoreContextRef) -> bool + 'static + Sync + Send,
    {
        self.ctx.check_x509()?;

        self.set_ex_data(CTX_VERIFY_INDEX.register()?, Some(Arc::new(callback)))?;
        // SAFETY: the live context owns the registered callback state.
        unsafe {
            ffi::SSL_CTX_set_verify(self.as_ptr(), c_int::from(mode.bits()), Some(raw_verify));
        }
        Ok(())
    }

    /// Removes the per-certificate X.509 verification callback and sets the mode.
    /// The custom TLS and whole-chain X.509 callbacks remain unchanged.
    /// # Errors
    /// The context does not support X.509 certificates.
    #[corresponds(SSL_CTX_set_verify)]
    pub fn clear_verify_callback(&mut self, mode: SslVerifyMode) -> Result<(), ErrorStack> {
        self.ctx.check_x509()?;
        // SAFETY: exclusive X.509 context; null explicitly clears this callback.
        unsafe { ffi::SSL_CTX_set_verify(self.as_ptr(), c_int::from(mode.bits()), None) };
        self.clear_verifier_slot(&CTX_VERIFY_INDEX)
    }

    /// Configures certificate verification.
    ///
    /// The callback should return `Ok(())` if the certificate is valid.
    /// If the certificate is invalid, the callback should return `SslVerifyError::Invalid(alert)`.
    /// Some useful alerts include [`SslAlert::CERTIFICATE_EXPIRED`], [`SslAlert::CERTIFICATE_REVOKED`],
    /// [`SslAlert::UNKNOWN_CA`], [`SslAlert::BAD_CERTIFICATE`], [`SslAlert::CERTIFICATE_UNKNOWN`],
    /// and [`SslAlert::INTERNAL_ERROR`]. See RFC 5246 section 7.2.2 for their precise meanings.
    ///
    /// To verify a certificate asynchronously, the callback may return `Err(SslVerifyError::Retry)`.
    /// The handshake will then pause with an error with code [`ErrorCode::WANT_CERTIFICATE_VERIFY`].
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_set_custom_verify)]
    pub fn set_custom_verify_callback<F>(
        &mut self,
        mode: SslVerifyMode,
        callback: F,
    ) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef) -> Result<(), SslVerifyError> + 'static + Sync + Send,
    {
        self.set_ex_data(
            CTX_CUSTOM_VERIFY_INDEX.register()?,
            Some(Arc::new(callback)),
        )?;
        // SAFETY: the live context owns the registered callback state.
        unsafe {
            ffi::SSL_CTX_set_custom_verify(
                self.as_ptr(),
                c_int::from(mode.bits()),
                Some(raw_custom_verify),
            );
        }
        Ok(())
    }

    /// Removes the custom TLS verifier and sets the verification mode. The
    /// native certificate verifier (including any X.509 callbacks) is used instead.
    /// # Errors
    /// Native callback storage cannot be updated.
    #[corresponds(SSL_CTX_set_custom_verify)]
    pub fn clear_custom_verify_callback(&mut self, mode: SslVerifyMode) -> Result<(), ErrorStack> {
        // SAFETY: exclusive native context; null clears the custom TLS callback.
        unsafe { ffi::SSL_CTX_set_custom_verify(self.as_ptr(), c_int::from(mode.bits()), None) };
        self.clear_verifier_slot(&CTX_CUSTOM_VERIFY_INDEX)
    }

    /// Configures whether resumed client sessions use the custom verification callback.
    ///
    /// Without [`Self::set_custom_verify_callback`] every resumption fails verification; call
    /// [`SslRef::verify_peer_cert_chain`] from it to keep the built-in X.509 checks. Incompatible
    /// with [`SslVerifyMode::NONE`], including a mode set on one connection.
    /// A resumption with verification disabled fails the handshake without invoking the callback.
    #[corresponds(SSL_CTX_set_reverify_on_resume)]
    pub fn set_reverify_on_resume(&mut self, enabled: bool) {
        // SAFETY: The context is live and exclusively borrowed; the reverify flag is a native scalar setting.
        unsafe { ffi::SSL_CTX_set_reverify_on_resume(self.as_ptr(), c_int::from(enabled)) }
    }

    /// Configures the server name indication (SNI) callback for new connections.
    ///
    /// SNI is used to allow a single server to handle requests for multiple domains, each of which
    /// has its own certificate chain and configuration.
    ///
    /// Obtain the server name with the `servername` method and then set the corresponding context
    /// with `set_ssl_context`
    ///
    // FIXME tlsext prefix?
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_set_tlsext_servername_callback)]
    pub fn set_servername_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef, &mut SslAlert) -> Result<(), SniError> + 'static + Sync + Send,
    {
        // SAFETY: The callback pointer refers to an allocation owned by the context extra-data registry, which outlives native callbacks.
        unsafe {
            // The SNI callback is somewhat unique in that the callback associated with the original
            // context associated with an SSL can be used even if the SSL's context has been swapped
            // out. When that happens, we wouldn't be able to look up the callback's state in the
            // context's ex data. Instead, pass the pointer directly as the servername arg. It's
            // still stored in ex data to manage the lifetime.

            let callback_index = SslContext::register_callback::<F>(CallbackRole::ServerName)?;

            self.ctx.replace_ex_data(callback_index, callback)?;
            let callback = self
                .ctx
                .ex_data(callback_index)
                .ok_or_else(|| ErrorStack::internal_error_str("missing SNI callback"))?;

            let arg = ptr::from_ref(callback).cast_mut().cast();
            cvt(ffi::SSL_CTX_set_tlsext_servername_arg(self.as_ptr(), arg))?;
            cvt(ffi::SSL_CTX_set_tlsext_servername_callback(
                self.as_ptr(),
                Some(raw_sni::<F>),
            ))?;
        }
        Ok(())
    }

    /// Configures a custom session ticket key callback for session resumption.
    ///
    /// Session Resumption uses the security context (aka. session tickets) of a previous
    /// connection to establish a new connection via an abbreviated handshake. Skipping portions of
    /// a handshake can potentially yield performance gains.
    ///
    /// An attacker that compromises a server's session ticket key can impersonate the server and,
    /// prior to TLS 1.3, retroactively decrypt all application traffic from sessions using that
    /// ticket key. Thus ticket keys must be regularly rotated for forward secrecy.
    ///
    /// CipherCtx and HmacCtx are guaranteed to be initialized.
    ///
    /// # Safety
    ///
    /// The application is responsible for correctly setting the key_name, iv, encryption context
    /// and hmac context. See the [`SSL_CTX_set_tlsext_ticket_key_cb`] docs for additional info.
    ///
    /// [`SSL_CTX_set_tlsext_ticket_key_cb`]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CTX_set_tlsext_ticket_key_cb
    ///
    /// # Errors
    /// The context does not support X.509 certificates.
    ///
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_set_tlsext_ticket_key_cb)]
    pub unsafe fn set_ticket_key_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(
                &SslRef,
                TicketKeyMode<'_>,
                &mut CipherCtxRef,
                &mut HmacCtxRef,
            ) -> TicketKeyCallbackResult
            + 'static
            + Sync
            + Send,
    {
        self.ctx.check_x509()?;

        // SAFETY: The registered ticket callback is owned in context extra data before the native callback hooks are installed.
        unsafe {
            self.replace_ex_data(
                SslContext::register_callback::<F>(CallbackRole::TicketKey)?,
                callback,
            )?;
            cvt(ffi::SSL_CTX_set_tlsext_ticket_key_cb(
                self.as_ptr(),
                Some(raw_ticket_key::<F>),
            ))?;
        };
        Ok(())
    }

    /// Sets the certificate verification depth.
    ///
    /// If the peer's certificate chain is longer than this value, verification will fail.
    ///
    /// # Errors
    /// The context does not support X.509 certificates or the depth exceeds the signed native integer range.
    #[corresponds(SSL_CTX_set_verify_depth)]
    pub fn set_verify_depth(&mut self, depth: u32) -> Result<(), ErrorStack> {
        let depth = c_int::try_from(depth).map_err(ErrorStack::internal_error)?;
        self.ctx.check_x509()?;

        // SAFETY: the live context is exclusively borrowed, and the depth is
        // checked against the full native signed integer range.
        unsafe { ffi::SSL_CTX_set_verify_depth(self.as_ptr(), depth) };
        Ok(())
    }

    /// Returns the verification parameters inherited by new connections.
    ///
    /// # Errors
    /// The context does not support X.509 certificates.
    #[corresponds(SSL_CTX_get0_param)]
    pub fn verify_param_mut(&mut self) -> Result<&mut X509VerifyParamRef, ErrorStack> {
        self.ctx.check_x509()?;
        // SAFETY: the exclusively owned X.509 context retains its initialized parameters.
        unsafe {
            cvt_p(ffi::SSL_CTX_get0_param(self.as_ptr()))
                .map(|param| X509VerifyParamRef::from_ptr_mut(param))
        }
    }

    /// Sets a custom certificate store for verifying peer certificates.
    ///
    /// # Errors
    /// The context does not support X.509 certificates or native store installation fails.
    #[corresponds(SSL_CTX_set1_verify_cert_store)]
    pub fn set_verify_cert_store(&mut self, cert_store: &X509StoreRef) -> Result<(), ErrorStack> {
        self.ctx.check_x509()?;
        // SAFETY: live native objects; BoringSSL takes its own store reference.
        unsafe {
            cvt(ffi::SSL_CTX_set1_verify_cert_store(
                self.as_ptr(),
                cert_store.as_ptr(),
            ))
        }
    }

    /// Replaces the context's certificate store, and keeps it immutable.
    ///
    /// This method allows sharing the `X509Store`, but calls to `cert_store_mut` will return an error.
    ///
    /// Use [`set_cert_store_builder`] to set a mutable cert store
    /// (there's no way to have both sharing and mutability).
    ///
    /// # Errors
    /// The context does not support X.509 certificates.
    #[corresponds(SSL_CTX_set_cert_store)]
    pub fn set_cert_store(&mut self, cert_store: X509Store) -> Result<(), ErrorStack> {
        self.ctx.check_x509()?;

        self.has_shared_cert_store = true;
        // SAFETY: The builder transfers ownership of this certificate store to its live native context exactly once.
        unsafe {
            ffi::SSL_CTX_set_cert_store(self.as_ptr(), cert_store.into_ptr());
        };
        Ok(())
    }

    /// Replaces the context's certificate store, and allows mutating the store afterwards.
    ///
    /// # Errors
    /// The context does not support X.509 certificates.
    #[corresponds(SSL_CTX_set_cert_store)]
    pub fn set_cert_store_builder(
        &mut self,
        cert_store: X509StoreBuilder,
    ) -> Result<(), ErrorStack> {
        self.ctx.check_x509()?;

        self.has_shared_cert_store = false;
        // SAFETY: The builder transfers ownership of the replacement store to its native context exactly once.
        unsafe {
            ffi::SSL_CTX_set_cert_store(self.as_ptr(), cert_store.into_ptr());
        };
        Ok(())
    }

    /// Sets the mode used by the context, returning the new bit-mask after adding mode.
    #[corresponds(SSL_CTX_set_mode)]
    pub fn set_mode(&mut self, mode: SslMode) -> SslMode {
        // SAFETY: The mutable context is live while the native mode bitmask is updated and returned.
        let bits = unsafe { ffi::SSL_CTX_set_mode(self.as_ptr(), mode.bits()) };
        SslMode::from_bits_retain(bits)
    }

    /// Use the default locations of trusted certificates for verification.
    ///
    /// These locations are read from the `SSL_CERT_FILE` and `SSL_CERT_DIR` environment variables
    /// if present, or defaults specified at OpenSSL build time otherwise.
    ///
    /// # Errors
    /// The store is shared, the context does not support X.509 certificates, or native initialization fails.
    #[corresponds(SSL_CTX_set_default_verify_paths)]
    pub fn set_default_verify_paths(&mut self) -> Result<(), ErrorStack> {
        self.cert_store_mut()?.set_default_paths()
    }

    /// Loads trusted root certificates from a file.
    ///
    /// The file should contain a sequence of PEM-formatted CA certificates.
    #[corresponds(SSL_CTX_load_verify_locations)]
    pub fn set_ca_file<P: AsRef<Path>>(&mut self, file: P) -> Result<(), ErrorStack> {
        self.load_verify_locations(Some(file.as_ref()), None)
    }

    /// Loads trusted root certificates from a file and/or a directory.
    ///
    /// # Errors
    /// The store is shared, the context does not support X.509 certificates, a path contains a NUL byte, or native loading fails.
    #[corresponds(SSL_CTX_load_verify_locations)]
    pub fn load_verify_locations(
        &mut self,
        ca_file: Option<&Path>,
        ca_path: Option<&Path>,
    ) -> Result<(), ErrorStack> {
        let store = self.cert_store_mut()?;
        let ca_file = ca_file.map(path_to_cstring).transpose()?;
        let ca_path = ca_path.map(path_to_cstring).transpose()?;

        // SAFETY: Both optional C strings remain live through the native call and null pointers represent missing paths.
        unsafe {
            cvt(ffi::X509_STORE_load_locations(
                store.as_ptr(),
                ca_file.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                ca_path.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            ))
        }
    }

    /// Sets the list of CA names sent to the client.
    ///
    /// The CA certificates must still be added to the trust root - they are not automatically set
    /// as trusted by this method.
    ///
    /// # Errors
    /// The context does not support X.509 certificates.
    #[corresponds(SSL_CTX_set_client_CA_list)]
    pub fn set_client_ca_list(&mut self, list: Stack<X509Name>) -> Result<(), ErrorStack> {
        self.ctx.check_x509()?;

        // SAFETY: The native context takes ownership of the client CA stack; `mem::forget` prevents double-free.
        unsafe {
            ffi::SSL_CTX_set_client_CA_list(self.as_ptr(), list.as_ptr());
            mem::forget(list);
        };
        Ok(())
    }

    /// Add the provided CA certificate to the list sent by the server to the client when
    /// requesting client-side TLS authentication.
    ///
    /// # Errors
    /// The context does not support X.509 certificates. Native insertion of the CA name fails.
    #[corresponds(SSL_CTX_add_client_CA)]
    pub fn add_client_ca(&mut self, cacert: &X509Ref) -> Result<(), ErrorStack> {
        self.ctx.check_x509()?;

        // SAFETY: The CA certificate is borrowed while the live context adds its own retained reference.
        unsafe { cvt(ffi::SSL_CTX_add_client_CA(self.as_ptr(), cacert.as_ptr())) }
    }

    /// Sets the application-defined context identifier for sessions.
    ///
    /// A session is only used by a connection with the same identifier. Clients can use it to
    /// isolate compatible contexts in an external cache; servers must set it when peer
    /// verification is enabled. A [`ClientSession`] is offered to any context sharing a non-empty
    /// identifier, so share one only between contexts with the same trust, verification, client
    /// identity, protocol, and cipher configuration.
    ///
    /// # Errors
    ///
    /// The session context is too large, or the native setter rejects it.
    #[corresponds(SSL_CTX_set_session_id_context)]
    pub fn set_session_id_context(&mut self, sid_ctx: &[u8]) -> Result<(), ErrorStack> {
        c_uint::try_from(sid_ctx.len()).map_err(ErrorStack::internal_error)?;
        // SAFETY: the session ID bytes are borrowed for synchronous copying;
        // its length fits the native unsigned integer parameter.
        unsafe {
            cvt(ffi::SSL_CTX_set_session_id_context(
                self.as_ptr(),
                sid_ctx.as_ptr(),
                sid_ctx.len(),
            ))
        }
    }

    /// Loads a leaf certificate from a file.
    ///
    /// Only a single certificate will be loaded - use `add_extra_chain_cert` to add the remainder
    /// of the certificate chain, or `set_certificate_chain_file` to load the entire chain from a
    /// single file.
    ///
    /// # Errors
    /// The context does not support X.509 certificates, or loading the certificate fails.
    #[corresponds(SSL_CTX_use_certificate_file)]
    pub fn set_certificate_file<P: AsRef<Path>>(
        &mut self,
        file: P,
        file_type: SslFiletype,
    ) -> Result<(), ErrorStack> {
        self.ctx.check_x509()?;

        let file = path_to_cstring(file.as_ref())?;
        // SAFETY: The checked NUL-terminated file path remains live while the native context loads the certificate.
        unsafe {
            cvt(ffi::SSL_CTX_use_certificate_file(
                self.as_ptr(),
                file.as_ptr(),
                file_type.as_raw(),
            ))
        }
    }

    /// Loads a certificate chain from a file.
    ///
    /// The file should contain a sequence of PEM-formatted certificates, the first being the leaf
    /// certificate, and the remainder forming the chain of certificates up to and including the
    /// trusted root certificate.
    #[corresponds(SSL_CTX_use_certificate_chain_file)]
    pub fn set_certificate_chain_file<P: AsRef<Path>>(
        &mut self,
        file: P,
    ) -> Result<(), ErrorStack> {
        let file = path_to_cstring(file.as_ref())?;
        // SAFETY: The checked NUL-terminated file path remains live while the native context loads the chain.
        unsafe {
            cvt(ffi::SSL_CTX_use_certificate_chain_file(
                self.as_ptr(),
                file.as_ptr(),
            ))
        }
    }

    /// Sets the leaf certificate.
    ///
    /// Use `add_extra_chain_cert` to add the remainder of the certificate chain.
    #[corresponds(SSL_CTX_use_certificate)]
    pub fn set_certificate(&mut self, cert: &X509Ref) -> Result<(), ErrorStack> {
        // SAFETY: The borrowed certificate remains live while the context installs its own reference.
        unsafe { cvt(ffi::SSL_CTX_use_certificate(self.as_ptr(), cert.as_ptr())) }
    }

    /// Appends a certificate to the certificate chain.
    ///
    /// This chain should contain all certificates necessary to go from the certificate specified by
    /// `set_certificate` to a trusted root.
    ///
    /// # Errors
    /// The context does not support X.509 certificates. Native insertion of the certificate fails.
    #[corresponds(SSL_CTX_add_extra_chain_cert)]
    pub fn add_extra_chain_cert(&mut self, cert: X509) -> Result<(), ErrorStack> {
        self.ctx.check_x509()?;

        // SAFETY: The owned certificate pointer is consumed by the native context, with no second Rust owner.
        unsafe {
            cvt(ffi::SSL_CTX_add_extra_chain_cert(
                self.as_ptr(),
                cert.into_ptr(),
            ))
        }
    }

    /// Loads the private key from a file.
    #[corresponds(SSL_CTX_use_PrivateKey_file)]
    pub fn set_private_key_file<P: AsRef<Path>>(
        &mut self,
        file: P,
        file_type: SslFiletype,
    ) -> Result<(), ErrorStack> {
        let file = path_to_cstring(file.as_ref())?;
        // SAFETY: The path is an owned NUL-terminated string that remains live
        // during the synchronous key import into the uniquely borrowed context.
        unsafe {
            cvt(ffi::SSL_CTX_use_PrivateKey_file(
                self.as_ptr(),
                file.as_ptr(),
                file_type.as_raw(),
            ))
        }
    }

    /// Sets the private key.
    #[corresponds(SSL_CTX_use_PrivateKey)]
    pub fn set_private_key<T>(&mut self, key: &PKeyRef<T>) -> Result<(), ErrorStack>
    where
        T: HasPrivate,
    {
        // SAFETY: The referenced private key remains live during this call; BoringSSL
        // retains its own key reference in the exclusively borrowed context.
        unsafe { cvt(ffi::SSL_CTX_use_PrivateKey(self.as_ptr(), key.as_ptr())) }
    }

    /// Sets the list of supported ciphers for protocols before TLSv1.3, ignoring meaningless entries.
    ///
    /// See [`SslContextBuilder::set_strict_cipher_list()`].
    ///
    /// The `set_ciphersuites` method controls the cipher suites for TLSv1.3 in OpenSSL.
    /// BoringSSL doesn't implement `set_ciphersuites`; use [`Self::set_tls13_ciphers`] instead.
    /// See [ssl.h](https://github.com/google/boringssl/blob/master/include/openssl/ssl.h#L1542-L1544).
    ///
    /// See [`ciphers`] for details on the format.
    ///
    /// [`ciphers`]: https://www.openssl.org/docs/manmaster/apps/ciphers.html
    #[corresponds(SSL_CTX_set_cipher_list)]
    pub fn set_cipher_list(&mut self, cipher_list: &str) -> Result<(), ErrorStack> {
        let cipher_list = CString::new(cipher_list).map_err(ErrorStack::internal_error)?;
        // SAFETY: The validated NUL-terminated cipher rule is borrowed for a
        // synchronous native configuration of this exclusively borrowed context.
        unsafe {
            cvt(ffi::SSL_CTX_set_cipher_list(
                self.as_ptr(),
                cipher_list.as_ptr(),
            ))
        }
    }

    /// Sets the list of supported ciphers for protocols before TLSv1.3 but do not
    /// tolerate anything meaningless in the cipher list.
    ///
    /// The `set_ciphersuites` method controls the cipher suites for TLSv1.3 in OpenSSL.
    /// BoringSSL doesn't implement `set_ciphersuites`; use [`Self::set_tls13_ciphers`] instead.
    /// See <https://github.com/google/boringssl/blob/main/include/openssl/ssl.h#L1685>
    ///
    /// See [`ciphers`] for details on the format.
    ///
    /// [`ciphers`]: <https://docs.openssl.org/master/man1/openssl-ciphers/>.
    #[corresponds(SSL_CTX_set_strict_cipher_list)]
    pub fn set_strict_cipher_list(&mut self, cipher_list: &str) -> Result<(), ErrorStack> {
        let cipher_list = CString::new(cipher_list).map_err(ErrorStack::internal_error)?;
        // SAFETY: The NUL-terminated cipher rule remains valid for the
        // synchronous setter, which updates this uniquely borrowed context.
        unsafe {
            cvt(ffi::SSL_CTX_set_strict_cipher_list(
                self.as_ptr(),
                cipher_list.as_ptr(),
            ))
        }
    }

    /// Gets the list of supported ciphers for protocols before TLSv1.3.
    ///
    /// See [`ciphers`] for details on the format
    ///
    /// [`ciphers`]: https://www.openssl.org/docs/manmaster/man1/ciphers.html
    #[corresponds(SSL_CTX_get_ciphers)]
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn ciphers(&self) -> Option<&StackRef<SslCipher>> {
        self.ctx.ciphers()
    }

    /// Sets the options used by the context, returning the old set.
    ///
    /// # Note
    ///
    /// This *enables* the specified options, but does not disable unspecified options. Use
    /// `clear_options` for that.
    #[corresponds(SSL_CTX_set_options)]
    pub fn set_options(&mut self, option: SslOptions) -> SslOptions {
        // SAFETY: The live context is borrowed mutably and receives only a native
        // option bitset; no Rust storage is passed to BoringSSL.
        let bits = unsafe { ffi::SSL_CTX_set_options(self.as_ptr(), option.bits()) };
        SslOptions::from_bits_retain(bits)
    }

    /// Returns the options used by the context.
    #[corresponds(SSL_CTX_get_options)]
    #[must_use = "Use the returned flags to inspect current configuration."]
    pub fn options(&self) -> SslOptions {
        // SAFETY: The native getter only reads an option bitset from the live context.
        let bits = unsafe { ffi::SSL_CTX_get_options(self.as_ptr()) };
        SslOptions::from_bits_retain(bits)
    }

    /// Clears the options used by the context, returning the old set.
    #[corresponds(SSL_CTX_clear_options)]
    pub fn clear_options(&mut self, option: SslOptions) -> SslOptions {
        // SAFETY: The live context is borrowed mutably and the native function
        // updates only its option bitset.
        let bits = unsafe { ffi::SSL_CTX_clear_options(self.as_ptr(), option.bits()) };
        SslOptions::from_bits_retain(bits)
    }

    /// Sets the minimum supported protocol version.
    ///
    /// If version is `None`, the default minimum version is used. For BoringSSL this defaults to
    /// TLS 1.0.
    #[corresponds(SSL_CTX_set_min_proto_version)]
    pub fn set_min_proto_version(&mut self, version: Option<SslVersion>) -> Result<(), ErrorStack> {
        // SAFETY: The live context is exclusively borrowed and the protocol
        // version is a scalar value (zero selects the native default).
        unsafe {
            cvt(ffi::SSL_CTX_set_min_proto_version(
                self.as_ptr(),
                version.map_or(0, |v| v.0 as _),
            ))
        }
    }

    /// Sets the maximum supported protocol version.
    ///
    /// If version is `None`, the default maximum version is used. For BoringSSL this is TLS 1.3.
    #[corresponds(SSL_CTX_set_max_proto_version)]
    pub fn set_max_proto_version(&mut self, version: Option<SslVersion>) -> Result<(), ErrorStack> {
        // SAFETY: The live context is exclusively borrowed and the protocol
        // version is a scalar value (zero selects the native default).
        unsafe {
            cvt(ffi::SSL_CTX_set_max_proto_version(
                self.as_ptr(),
                version.map_or(0, |v| v.0 as _),
            ))
        }
    }

    /// Gets the minimum supported protocol version.
    #[corresponds(SSL_CTX_get_min_proto_version)]
    pub fn min_proto_version(&mut self) -> Option<SslVersion> {
        // SAFETY: The getter reads a native scalar from the live context.
        unsafe {
            let r = ffi::SSL_CTX_get_min_proto_version(self.as_ptr());
            if r == 0 { None } else { Some(SslVersion(r)) }
        }
    }

    /// Gets the maximum supported protocol version.
    #[corresponds(SSL_CTX_get_max_proto_version)]
    pub fn max_proto_version(&mut self) -> Option<SslVersion> {
        // SAFETY: The getter reads a native scalar from the live context.
        unsafe {
            let r = ffi::SSL_CTX_get_max_proto_version(self.as_ptr());
            if r == 0 { None } else { Some(SslVersion(r)) }
        }
    }

    /// Sets the protocols to sent to the server for Application Layer Protocol Negotiation (ALPN).
    ///
    /// The input must be in ALPN "wire format". It consists of a sequence of supported protocol
    /// names prefixed by their byte length. For example, the protocol list consisting of `spdy/1`
    /// and `http/1.1` is encoded as `b"\x06spdy/1\x08http/1.1"`. The protocols are ordered by
    /// preference.
    #[corresponds(SSL_CTX_set_alpn_protos)]
    pub fn set_alpn_protos(&mut self, protocols: &[u8]) -> Result<(), ErrorStack> {
        // SAFETY: The ALPN wire-format bytes are borrowed for the duration of the
        // native call. Its length is checked before narrowing to a native integer.
        unsafe {
            let r = ffi::SSL_CTX_set_alpn_protos(
                self.as_ptr(),
                protocols.as_ptr(),
                try_int(protocols.len())?,
            );
            // fun fact, SSL_CTX_set_alpn_protos has a reversed return code D:
            if r == 0 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// Enables the DTLS extension "use_srtp" as defined in RFC5764.
    #[corresponds(SSL_CTX_set_tlsext_use_srtp)]
    pub fn set_tlsext_use_srtp(&mut self, protocols: &str) -> Result<(), ErrorStack> {
        // SAFETY: The NUL-terminated SRTP profile list remains valid during the
        // native setter; the context is exclusively borrowed for this update.
        unsafe {
            let cstr = CString::new(protocols).map_err(ErrorStack::internal_error)?;

            let r = ffi::SSL_CTX_set_tlsext_use_srtp(self.as_ptr(), cstr.as_ptr());
            // fun fact, set_tlsext_use_srtp has a reversed return code D:
            if r == 0 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// Sets the callback used by a server to select a protocol for Application Layer Protocol
    /// Negotiation (ALPN).
    ///
    /// The callback is provided with the client's protocol list in ALPN wire format. See the
    /// documentation for [`SslContextBuilder::set_alpn_protos`] for details. It should return one
    /// of those protocols on success. The [`select_next_proto`] function implements the standard
    /// protocol selection algorithm.
    ///
    /// [`SslContextBuilder::set_alpn_protos`]: struct.SslContextBuilder.html#method.set_alpn_protos
    /// [`select_next_proto`]: fn.select_next_proto.html
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_set_alpn_select_cb)]
    pub fn set_alpn_select_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: for<'a> Fn(&mut SslRef, &'a [u8]) -> Result<&'a [u8], AlpnError> + 'static + Sync + Send,
    {
        // SAFETY: The closure is stored in typed context extra-data before the
        // static callback entrypoint is registered. No temporary pointer escapes.
        unsafe {
            self.replace_ex_data(
                SslContext::register_callback::<F>(CallbackRole::Alpn)?,
                callback,
            )?;
            ffi::SSL_CTX_set_alpn_select_cb(
                self.as_ptr(),
                Some(callbacks::raw_alpn_select::<F>),
                ptr::null_mut(),
            );
        }
        Ok(())
    }

    /// Sets a callback that is called before most ClientHello processing and before the decision whether
    /// to resume a session is made. The callback may inspect the ClientHello and configure the
    /// connection.
    ///
    /// A context has a single certificate selection callback. Calling this method replaces the
    /// callback set by any of [`SslContextBuilder::set_select_certificate_callback`],
    /// [`SslContextBuilder::set_select_certificate_callback_with_action`],
    /// [`SslContextBuilder::set_async_select_certificate_callback`], or
    /// [`SslContextBuilder::set_async_select_certificate_callback_with_action`].
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_set_select_certificate_cb)]
    pub fn set_select_certificate_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(ClientHello<'_>) -> Result<(), SelectCertError> + Sync + Send + 'static,
    {
        self.set_select_certificate_callback_with_action(move |client_hello| {
            callback(client_hello).map(|()| SelectCertAction::Success)
        })
    }

    /// Sets an action-aware callback that is called before most ClientHello processing and before
    /// the decision whether to resume a session is made. The callback may inspect the ClientHello
    /// and configure the connection.
    ///
    /// [`SelectCertAction::DisableEch`] causes BoringSSL to discard an inner ClientHello, call
    /// this callback again with the outer ClientHello, and continue without retry configs.
    /// It is only valid when ECH has been accepted; returning it otherwise fails the handshake.
    ///
    /// A context has a single certificate selection callback. Calling this method replaces the
    /// callback set by any of [`SslContextBuilder::set_select_certificate_callback`],
    /// [`SslContextBuilder::set_select_certificate_callback_with_action`],
    /// [`SslContextBuilder::set_async_select_certificate_callback`], or
    /// [`SslContextBuilder::set_async_select_certificate_callback_with_action`].
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_set_select_certificate_cb)]
    pub fn set_select_certificate_callback_with_action<F>(
        &mut self,
        callback: F,
    ) -> Result<(), ErrorStack>
    where
        F: Fn(ClientHello<'_>) -> Result<SelectCertAction, SelectCertError> + Sync + Send + 'static,
    {
        // SAFETY: The callback is registered only after its typed extra-data
        // slot is populated; the native function stores the static entrypoint.
        unsafe {
            self.replace_ex_data(
                SslContext::register_callback::<F>(CallbackRole::SelectCert)?,
                callback,
            )?;
            ffi::SSL_CTX_set_select_certificate_cb(
                self.as_ptr(),
                Some(callbacks::raw_select_cert::<F>),
            );
        }
        Ok(())
    }

    /// Registers a certificate compression algorithm.
    ///
    /// [`SSL_CTX_add_cert_compression_alg`]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CTX_add_cert_compression_alg
    ///
    /// # Errors
    ///
    /// Returns an error if callback storage cannot be allocated or the algorithm cannot be registered.
    #[corresponds(SSL_CTX_add_cert_compression_alg_with_data)]
    pub fn add_certificate_compression_algorithm<C>(
        &mut self,
        compressor: C,
    ) -> Result<(), ErrorStack>
    where
        C: CertificateCompressor,
    {
        const {
            assert!(
                C::CAN_COMPRESS || C::CAN_DECOMPRESS,
                "Either compression or decompression must be supported for algorithm to be registered"
            );
        };
        callbacks::install_certificate_compressor(self, compressor)
    }

    /// Configures a custom private key method on the context.
    ///
    /// See [`PrivateKeyMethod`] for more details.
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_set_private_key_method)]
    pub fn set_private_key_method<M>(&mut self, method: M) -> Result<(), ErrorStack>
    where
        M: PrivateKeyMethod,
    {
        // SAFETY: The context retains a static method table associated with
        // the callback type, while its Rust callback state lives in extra-data.
        unsafe {
            self.replace_ex_data(
                SslContext::register_callback::<Arc<M>>(CallbackRole::PrivateKey)?,
                Arc::new(method),
            )?;

            ffi::SSL_CTX_set_private_key_method(
                self.as_ptr(),
                callbacks::PrivateKeyMethodDescriptor::<M, false>::descriptor(),
            );
        }
        Ok(())
    }

    /// Checks for consistency between the private key and certificate.
    #[corresponds(SSL_CTX_check_private_key)]
    pub fn check_private_key(&self) -> Result<(), ErrorStack> {
        // SAFETY: The native checker borrows the live context, installed
        // certificate, and private key without transferring any Rust ownership.
        unsafe { cvt(ffi::SSL_CTX_check_private_key(self.as_ptr())) }
    }

    /// Returns a shared reference to the context's certificate store.
    ///
    /// # Errors
    /// The context does not support X.509 certificates.
    #[corresponds(SSL_CTX_get_cert_store)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn cert_store(&self) -> Result<&X509StoreBuilderRef, ErrorStack> {
        self.ctx.check_x509()?;

        // SAFETY: The builder exclusively owns a live X.509 context with an initialized
        // certificate store; the getter returns only a borrowed store pointer.
        Ok(unsafe { X509StoreBuilderRef::from_ptr(ffi::SSL_CTX_get_cert_store(self.as_ptr())) })
    }

    /// Returns a mutable reference to the context's certificate store.
    ///
    /// Newly-created `SslContextBuilder` will have its own default mutable store.
    ///
    /// # Errors
    ///
    /// The store is shared or the context does not support X.509 certificates.
    ///
    #[corresponds(SSL_CTX_get_cert_store)]
    pub fn cert_store_mut(&mut self) -> Result<&mut X509StoreBuilderRef, ErrorStack> {
        self.ctx.check_x509()?;

        if self.has_shared_cert_store {
            return Err(ErrorStack::internal_error_str(
                "shared certificate store is immutable",
            ));
        }
        // OTOH, it's not safe to return a shared &X509Store when the builder owns it exclusively

        // SAFETY: The builder owns the only mutable certificate store, checked above
        // against an installed shared store; the native pointer stays live.
        Ok(
            unsafe {
                X509StoreBuilderRef::from_ptr_mut(ffi::SSL_CTX_get_cert_store(self.as_ptr()))
            },
        )
    }

    /// Sets the callback dealing with OCSP stapling.
    ///
    /// On the client side, this callback is responsible for validating the OCSP status response
    /// returned by the server. The status may be retrieved with the `SslRef::ocsp_status` method.
    /// A response of `Ok(true)` indicates that the OCSP status is valid, and a response of
    /// `Ok(false)` indicates that the OCSP status is invalid and the handshake should be
    /// terminated.
    ///
    /// On the server side, this callback is resopnsible for setting the OCSP status response to be
    /// returned to clients. The status may be set with the `SslRef::set_ocsp_status` method. A
    /// response of `Ok(true)` indicates that the OCSP status should be returned to the client, and
    /// `Ok(false)` indicates that the status should not be returned to the client.
    #[corresponds(SSL_CTX_set_tlsext_status_cb)]
    pub fn set_status_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef) -> Result<bool, ErrorStack> + 'static + Sync + Send,
    {
        // SAFETY: The callback state is stored in typed context extra-data
        // before the native context retains its static function pointer.
        unsafe {
            self.replace_ex_data(
                SslContext::register_callback::<F>(CallbackRole::Status)?,
                callback,
            )?;
            cvt(ffi::SSL_CTX_set_tlsext_status_cb(
                self.as_ptr(),
                Some(raw_tlsext_status::<F>),
            ))
        }
    }

    /// Sets the callback for providing an identity and pre-shared key for a TLS-PSK client.
    ///
    /// The callback will be called with the SSL context, an identity hint if one was provided
    /// by the server, a mutable slice for each of the identity and pre-shared key bytes. The
    /// identity must be written as a null-terminated C string.
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_set_psk_client_callback)]
    pub fn set_psk_client_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef, Option<&[u8]>, &mut [u8], &mut [u8]) -> Result<usize, ErrorStack>
            + 'static
            + Sync
            + Send,
    {
        // SAFETY: The native context retains the monomorphized callback
        // entrypoint, whose closure remains owned by its registered extra-data slot.
        unsafe {
            self.replace_ex_data(
                SslContext::register_callback::<F>(CallbackRole::PskClient)?,
                callback,
            )?;
            ffi::SSL_CTX_set_psk_client_callback(self.as_ptr(), Some(raw_client_psk::<F>));
        }
        Ok(())
    }

    /// Sets the callback for providing an identity and pre-shared key for a TLS-PSK server.
    ///
    /// The callback will be called with the SSL context, an identity provided by the client,
    /// and, a mutable slice for the pre-shared key bytes. The callback returns the number of
    /// bytes in the pre-shared key.
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_set_psk_server_callback)]
    pub fn set_psk_server_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef, Option<&[u8]>, &mut [u8]) -> Result<usize, ErrorStack>
            + 'static
            + Sync
            + Send,
    {
        // SAFETY: The native context retains the monomorphized callback
        // entrypoint, whose closure remains owned by its registered extra-data slot.
        unsafe {
            self.replace_ex_data(
                SslContext::register_callback::<F>(CallbackRole::PskServer)?,
                callback,
            )?;
            ffi::SSL_CTX_set_psk_server_callback(self.as_ptr(), Some(raw_server_psk::<F>));
        }
        Ok(())
    }

    /// Sets the callback which is called when new sessions are negotiated.
    ///
    /// This can be used by clients to implement session caching. While in TLSv1.2 the session is
    /// available to access via [`SslRef::session`] immediately after the handshake completes, this
    /// is not the case for TLSv1.3. There, a session is not generally available immediately, and
    /// the server may provide multiple session tokens to the client over a single session. The new
    /// session callback is a portable way to deal with both cases.
    ///
    /// Note that session caching must be enabled for the callback to be invoked, and it defaults
    /// off for clients. [`set_session_cache_mode`] controls that behavior. This replaces
    /// [`SslConnectorBuilder::set_client_session_callback`], which uses the same BoringSSL callback.
    ///
    /// [`SslRef::session`]: struct.SslRef.html#method.session
    /// [`set_session_cache_mode`]: #method.set_session_cache_mode
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_sess_set_new_cb)]
    pub fn set_new_session_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef, SslSession) + 'static + Sync + Send,
    {
        // SAFETY: The native context retains a static callback entrypoint; its
        // concrete state has already been installed in typed context extra-data.
        unsafe {
            self.replace_ex_data(
                SslContext::register_callback::<F>(CallbackRole::NewSession)?,
                callback,
            )?;
            ffi::SSL_CTX_sess_set_new_cb(self.as_ptr(), Some(callbacks::raw_new_session::<F>));
        }
        Ok(())
    }

    /// Sets the callback which is called when sessions are removed from the context.
    ///
    /// Sessions can be removed because they have timed out or because they are considered faulty.
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_sess_set_remove_cb)]
    pub fn set_remove_session_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&SslContextRef, &SslSessionRef) + 'static + Sync + Send,
    {
        // SAFETY: The native context retains a static callback entrypoint; its
        // concrete state has already been installed in typed context extra-data.
        unsafe {
            self.replace_ex_data(
                SslContext::register_callback::<F>(CallbackRole::RemoveSession)?,
                callback,
            )?;
            ffi::SSL_CTX_sess_set_remove_cb(
                self.as_ptr(),
                Some(callbacks::raw_remove_session::<F>),
            );
        }
        Ok(())
    }

    /// Sets the callback which is called when a client proposed to resume a session but it was not
    /// found in the internal cache.
    ///
    /// The callback is passed a reference to the session ID provided by the client. It should
    /// return the session corresponding to that ID if available. This is only used for servers, not
    /// clients.
    ///
    /// # Safety
    ///
    /// The returned [`SslSession`] must not be associated with a different [`SslContext`].
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_sess_set_get_cb)]
    pub unsafe fn set_get_session_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef, &[u8]) -> Result<Option<SslSession>, GetSessionPendingError>
            + 'static
            + Sync
            + Send,
    {
        self.replace_ex_data(
            SslContext::register_callback::<F>(CallbackRole::GetSession)?,
            callback,
        )?;
        // SAFETY: The native context stores a static callback; its concrete state
        // is owned by the typed context extra-data slot populated above.
        unsafe {
            ffi::SSL_CTX_sess_set_get_cb(self.as_ptr(), Some(callbacks::raw_get_session::<F>));
        }
        Ok(())
    }

    /// Sets the TLS key logging callback.
    ///
    /// The callback is invoked whenever TLS key material is generated, and is passed a line of NSS
    /// SSLKEYLOGFILE-formatted text. This can be used by tools like Wireshark to decrypt message
    /// traffic. The line does not contain a trailing newline.
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_set_keylog_callback)]
    pub fn set_keylog_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&SslRef, &str) + 'static + Sync + Send,
    {
        // SAFETY: The context retains a monomorphized callback entrypoint, while
        // typed extra-data owns the Rust closure for the context lifetime.
        unsafe {
            self.replace_ex_data(
                SslContext::register_callback::<F>(CallbackRole::Keylog)?,
                callback,
            )?;
            ffi::SSL_CTX_set_keylog_callback(self.as_ptr(), Some(callbacks::raw_keylog::<F>));
        }
        Ok(())
    }

    /// Sets the session caching mode use for connections made with the context.
    ///
    /// Returns the previous session caching mode.
    #[corresponds(SSL_CTX_set_session_cache_mode)]
    pub fn set_session_cache_mode(&mut self, mode: SslSessionCacheMode) -> SslSessionCacheMode {
        // SAFETY: The exclusive context borrow permits the native cache-mode
        // bitset update; its return value is copied back into a Rust bitset.
        unsafe {
            let bits = ffi::SSL_CTX_set_session_cache_mode(self.as_ptr(), mode.bits());
            SslSessionCacheMode::from_bits_retain(bits)
        }
    }

    /// Sets the lifetime of TLS 1.2 and earlier sessions created by this context.
    ///
    /// Returns the previous timeout in seconds. TLS 1.3 session lifetimes are configured
    /// separately by BoringSSL.
    #[corresponds(SSL_CTX_set_timeout)]
    pub fn set_session_timeout(&mut self, timeout: u32) -> u32 {
        // SAFETY: The live context receives a scalar timeout; no Rust pointer is
        // retained or aliased by the native implementation.
        unsafe { ffi::SSL_CTX_set_timeout(self.as_ptr(), timeout) }
    }

    /// Sets or overwrites the extra data at the specified registered index.
    ///
    /// # Errors
    ///
    /// The native context cannot allocate storage for this index.
    pub fn set_ex_data<T: 'static + Send + Sync>(
        &mut self,
        index: Index<SslContext, T>,
        data: T,
    ) -> Result<(), ErrorStack> {
        drop(self.replace_ex_data(index, data)?);
        Ok(())
    }

    /// Replaces the extra data, returning the previous owned value if any.
    ///
    /// # Errors
    ///
    /// The native context cannot allocate storage for this index.
    #[corresponds(SSL_CTX_set_ex_data)]
    pub fn replace_ex_data<T: 'static + Send + Sync>(
        &mut self,
        index: Index<SslContext, T>,
        data: T,
    ) -> Result<Option<T>, ErrorStack> {
        // SAFETY: the unpublished builder guarantees a uniquely owned context.
        unsafe { self.ctx.replace_ex_data(index, data) }
    }

    /// Sets the context's session cache size limit, returning the previous limit.
    ///
    /// A value of 0 means that the cache size is unbounded.
    #[corresponds(SSL_CTX_sess_set_cache_size)]
    pub fn set_session_cache_size(&mut self, size: c_ulong) -> c_ulong {
        // SAFETY: The live context receives a scalar capacity, without passing
        // or retaining any borrowed Rust memory.
        unsafe { ffi::SSL_CTX_sess_set_cache_size(self.as_ptr(), size) }
    }

    /// Sets the context's supported signature algorithms.
    ///
    /// Prefer [`set_verify_algorithm_prefs`](Self::set_verify_algorithm_prefs),
    /// which takes raw IANA codepoints rather than an OpenSSL-style colon-separated
    /// string. Note that unlike `set_sigalgs_list`, `set_verify_algorithm_prefs`
    /// only configures the verify preference list and does not also set the
    /// signing algorithm prefs.
    #[corresponds(SSL_CTX_set1_sigalgs_list)]
    pub fn set_sigalgs_list(&mut self, sigalgs: &str) -> Result<(), ErrorStack> {
        let sigalgs = CString::new(sigalgs).map_err(ErrorStack::internal_error)?;
        // SAFETY: The NUL-terminated signature-algorithm list is borrowed during
        // this synchronous native configuration of the context.
        unsafe {
            cvt(ffi::SSL_CTX_set1_sigalgs_list(
                self.as_ptr(),
                sigalgs.as_ptr(),
            ))
        }
    }

    /// Set's whether the context should enable GREASE.
    #[corresponds(SSL_CTX_set_grease_enabled)]
    pub fn set_grease_enabled(&mut self, enabled: bool) {
        // SAFETY: The exclusively borrowed context receives an integer flag,
        // converted without a lossy cast from the Rust boolean.
        unsafe { ffi::SSL_CTX_set_grease_enabled(self.as_ptr(), c_int::from(enabled)) }
    }

    /// Sets whether the context should include a GREASE value in `signature_algorithms`
    /// extensions when sending ClientHello.
    ///
    /// See [RFC 8701].
    ///
    /// [RFC 8701]: https://www.rfc-editor.org/rfc/rfc8701.html
    #[corresponds(SSL_CTX_set_grease_sigalgs_enabled)]
    pub fn set_grease_sigalgs_enabled(&mut self, enabled: bool) {
        // SAFETY: The exclusively borrowed context receives an integer flag,
        // converted without a lossy cast from the Rust boolean.
        unsafe { ffi::SSL_CTX_set_grease_sigalgs_enabled(self.as_ptr(), c_int::from(enabled)) }
    }

    /// Advertises, with the [RFC 8449] `record_size_limit` extension, the largest
    /// protected-record plaintext this endpoint accepts. The limit applies only
    /// when the peer negotiates the extension.
    ///
    /// Zero, the default, disables the extension. Other values are clamped to
    /// 64..=16385 in TLS 1.3, where the limit counts the content type, and to
    /// 64..=16384 in TLS 1.2 and earlier, so 16385 advertises no restriction.
    /// GnuTLS peers reject values below 512 by default. The peer's value bounds
    /// the records this endpoint sends. DTLS ignores the setting.
    ///
    /// 0-RTT records may use the protocol maximum, because they precede the
    /// server's limit. When the client offers the extension, a server whose
    /// limit is below the maximum declines 0-RTT.
    ///
    /// [RFC 8449]: https://www.rfc-editor.org/rfc/rfc8449
    #[cfg(not(feature = "fips"))]
    #[corresponds(SSL_CTX_set_record_size_limit)]
    pub fn set_record_size_limit(&mut self, limit: u16) {
        // SAFETY: The exclusively borrowed context receives the native scalar
        // record-size limit, with no borrowed Rust pointer.
        unsafe { ffi::SSL_CTX_set_record_size_limit(self.as_ptr(), limit as _) }
    }

    /// Requests and verifies server delegated credentials ([RFC 9345]),
    /// advertising the given colon-separated signature algorithms in order.
    ///
    /// The list only covers the delegated key; the signature over the
    /// credential follows the normal signature algorithm list. Support is off
    /// by default and applies to (D)TLS 1.3 clients. Only ECDSA and Ed25519
    /// delegated keys are usable: `rsa_pss_rsae_*` (forbidden by RFC 9345),
    /// `rsa_pkcs1_*` and `ecdsa_sha1` (forbidden in TLS 1.3) may be listed, but
    /// credentials using them are rejected, and `rsa_pss_pss_*` is unsupported.
    /// Servers may still answer with a plain certificate; see
    /// [`SslRef::used_delegated_credential`].
    ///
    /// # Errors
    ///
    /// Returns an error for an empty list or element, an unknown name, or an
    /// embedded NUL.
    ///
    /// [RFC 9345]: https://www.rfc-editor.org/rfc/rfc9345
    #[cfg(not(feature = "fips"))]
    #[corresponds(SSL_CTX_set_delegated_credentials)]
    pub fn set_delegated_credentials(&mut self, sigalgs: &str) -> Result<(), ErrorStack> {
        let sigalgs = CString::new(sigalgs).map_err(ErrorStack::internal_error)?;
        // SAFETY: The NUL-terminated algorithm list stays live until the
        // native setter finishes copying or validating it.
        unsafe {
            cvt(ffi::SSL_CTX_set_delegated_credentials(
                self.as_ptr(),
                sigalgs.as_ptr(),
            ))
        }
    }

    /// Sets the TLS 1.3 cipher suites in preference order.
    ///
    /// Clients offer them in this order, and servers pick strictly by it. An empty list restores
    /// BoringSSL's default, which depends on AES hardware support. [`Self::set_cipher_list`] does
    /// not affect TLS 1.3. [`Self::set_compliance_policy`] and this method replace each other's
    /// TLS 1.3 list, so the later call wins.
    #[corresponds(SSL_CTX_set1_tls13_ciphers)]
    pub fn set_tls13_ciphers(&mut self, ciphers: &[Tls13Cipher]) -> Result<(), ErrorStack> {
        // SAFETY: `Tls13Cipher` is a transparent `u16`, and BoringSSL copies the list.
        unsafe {
            cvt(ffi::SSL_CTX_set1_tls13_ciphers(
                self.as_ptr(),
                ciphers.as_ptr().cast(),
                ptr::null(),
                ciphers.len(),
            ))
        }
    }

    /// Sets the ClientHello extension order.
    ///
    /// Known extensions stay in the configured order. Unlisted extensions are
    /// appended in random order.
    #[cfg(not(feature = "fips"))]
    #[corresponds(SSL_CTX_set_extension_order)]
    pub fn set_extension_permutation(
        &mut self,
        indices: &[ExtensionType],
    ) -> Result<(), ErrorStack> {
        // SAFETY: ExtensionType is represented as a native u16 and the borrowed
        // slice stays live until the native setter returns.
        unsafe {
            cvt(ffi::SSL_CTX_set_extension_order(
                self.as_ptr(),
                indices.as_ptr().cast::<u16>(),
                try_int(indices.len())?,
            ))
        }
    }

    /// Configures whether ClientHello extensions should be permuted.
    #[corresponds(SSL_CTX_set_permute_extensions)]
    pub fn set_permute_extensions(&mut self, enabled: bool) {
        // SAFETY: The live context is exclusively borrowed for its scalar
        // extension-permutation setting.
        unsafe { ffi::SSL_CTX_set_permute_extensions(self.as_ptr(), c_int::from(enabled)) }
    }

    /// Sets the context's supported signature verification algorithms.
    #[corresponds(SSL_CTX_set_verify_algorithm_prefs)]
    pub fn set_verify_algorithm_prefs(
        &mut self,
        prefs: &[SslSignatureAlgorithm],
    ) -> Result<(), ErrorStack> {
        // SAFETY: The borrowed list of transparent native codepoints stays
        // alive until the context copies its verification preferences.
        unsafe {
            cvt_0i(ffi::SSL_CTX_set_verify_algorithm_prefs(
                self.as_ptr(),
                prefs.as_ptr().cast(),
                prefs.len(),
            ))
            .map(|_| ())
        }
    }

    /// Enables SCT requests on all client SSL handshakes.
    #[corresponds(SSL_CTX_enable_signed_cert_timestamps)]
    pub fn enable_signed_cert_timestamps(&mut self) {
        // SAFETY: This setter updates a boolean state on the live
        // exclusively borrowed context, without retaining Rust memory.
        unsafe { ffi::SSL_CTX_enable_signed_cert_timestamps(self.as_ptr()) }
    }

    /// Enables OCSP stapling on all client SSL handshakes.
    #[corresponds(SSL_CTX_enable_ocsp_stapling)]
    pub fn enable_ocsp_stapling(&mut self) {
        // SAFETY: This setter updates a boolean state on the live
        // exclusively borrowed context, without retaining Rust memory.
        unsafe { ffi::SSL_CTX_enable_ocsp_stapling(self.as_ptr()) }
    }

    /// Sets the supported TLS named groups in preference order.
    /// An empty list restores the native defaults.
    ///
    /// # Errors
    /// A group is unsupported or repeated, or native configuration fails.
    #[corresponds(SSL_CTX_set1_group_ids)]
    pub fn set_groups(&mut self, groups: &[KeyShare]) -> Result<(), ErrorStack> {
        // SAFETY: KeyShare is transparent over u16; the native setter copies
        // the borrowed group IDs into the exclusively accessed configuration.
        unsafe {
            cvt(ffi::SSL_CTX_set1_group_ids(
                self.as_ptr(),
                groups.as_ptr().cast(),
                groups.len(),
            ))
        }
    }

    /// Sets the context's supported groups by name.
    #[corresponds(SSL_CTX_set1_curves_list)]
    pub fn set_curves_list(&mut self, curves: &str) -> Result<(), ErrorStack> {
        let curves = CString::new(curves).map_err(ErrorStack::internal_error)?;
        // SAFETY: The checked NUL-terminated curve-list string stays live during
        // the native configuration of this exclusively borrowed context.
        unsafe {
            cvt_0i(ffi::SSL_CTX_set1_curves_list(
                self.as_ptr(),
                curves.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the context's compliance policy.
    ///
    /// This feature isn't available in the certified version of BoringSSL.
    #[corresponds(SSL_CTX_set_compliance_policy)]
    pub fn set_compliance_policy(&mut self, policy: CompliancePolicy) -> Result<(), ErrorStack> {
        // SAFETY: The live context receives a native scalar policy; no
        // borrowed memory crosses the call boundary.
        unsafe { cvt_0i(ffi::SSL_CTX_set_compliance_policy(self.as_ptr(), policy.0)).map(|_| ()) }
    }

    /// Configures client connections to send the TLS 1.3 `trust_anchors` extension.
    ///
    /// `ids` is a sequence of non-empty, one-byte length-prefixed trust anchor IDs, without the
    /// extension's outer 16-bit length. See the [TLS Trust Anchor Identifiers draft].
    ///
    /// The extension is omitted by default, while an empty slice still sends it. This setting
    /// guides server certificate selection and does not change certificate verification.
    /// BoringSSL currently uses a provisional codepoint and supports only server certificates.
    ///
    /// # Errors
    ///
    /// Returns an error if `ids` is not a correctly encoded list or BoringSSL cannot copy it.
    ///
    /// [TLS Trust Anchor Identifiers draft]: https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids/
    #[corresponds(SSL_CTX_set1_requested_trust_anchors)]
    pub fn set_requested_trust_anchors(&mut self, ids: &[u8]) -> Result<(), ErrorStack> {
        // SAFETY: `self` is valid and BoringSSL validates and copies `ids` before returning.
        unsafe {
            cvt_0i(ffi::SSL_CTX_set1_requested_trust_anchors(
                self.as_ptr(),
                ids.as_ptr(),
                ids.len(),
            ))
            .map(|_| ())
        }
    }

    /// Configures servers to send `ids` as the trust anchors they have certificates for, which
    /// lets a client whose requested anchors did not match retry with others.
    ///
    /// `ids` is a non-empty sequence of non-empty, one-byte length-prefixed trust anchor IDs, in
    /// decreasing preference. See [`set_requested_trust_anchors`](Self::set_requested_trust_anchors).
    #[corresponds(SSL_CTX_set1_available_trust_anchors)]
    pub fn set_available_trust_anchors(&mut self, ids: &[u8]) -> Result<(), ErrorStack> {
        // SAFETY: `self` is valid and BoringSSL validates and copies `ids` before returning.
        unsafe {
            cvt_0i(ffi::SSL_CTX_set1_available_trust_anchors(
                self.as_ptr(),
                ids.as_ptr(),
                ids.len(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the context's info callback.
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_set_info_callback)]
    pub fn set_info_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&SslRef, SslInfoCallbackMode, SslInfoCallbackValue) + Send + Sync + 'static,
    {
        // SAFETY: The typed context extra-data holds the Rust closure before
        // BoringSSL retains a static monomorphized function pointer.
        unsafe {
            self.replace_ex_data(
                SslContext::register_callback::<F>(CallbackRole::Info)?,
                callback,
            )?;
            ffi::SSL_CTX_set_info_callback(self.as_ptr(), Some(callbacks::raw_info_callback::<F>));
        }
        Ok(())
    }

    /// Registers a list of ECH keys on the context. This list should contain new and old
    /// ECHConfigs to allow stale DNS caches to update. Unlike most `SSL_CTX` APIs, this function
    /// is safe to call even after the `SSL_CTX` has been associated with connections on various
    /// threads.
    #[corresponds(SSL_CTX_set1_ech_keys)]
    pub fn set_ech_keys(&self, keys: &SslEchKeys) -> Result<(), ErrorStack> {
        // SAFETY: the live native context accepts this borrowed, reference-
        // counted key collection and retains its own ownership. BoringSSL
        // synchronizes this operation even on contexts shared across threads.
        unsafe { cvt(ffi::SSL_CTX_set1_ech_keys(self.as_ptr(), keys.as_ptr())) }
    }

    /// Adds a credential.
    #[corresponds(SSL_CTX_add1_credential)]
    #[cfg(feature = "credential")]
    pub fn add_credential(&mut self, credential: &SslCredentialRef) -> Result<(), ErrorStack> {
        // SAFETY: The credential is borrowed while the live context acquires its
        // own reference, so the Rust owner is not consumed.
        unsafe {
            cvt_0i(ffi::SSL_CTX_add1_credential(
                self.as_ptr(),
                credential.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the list of server certificate types that clients attached to this context
    /// can process.
    #[corresponds(SSL_CTX_set1_accepted_peer_cert_types)]
    #[cfg(feature = "rpk")]
    pub fn set_server_certificate_types(
        &mut self,
        types: &[CertificateType],
    ) -> Result<(), ErrorStack> {
        // SAFETY: The slice of transparent one-byte certificate-type
        // values remains live while BoringSSL copies the configuration.
        unsafe {
            cvt_0i(ffi::SSL_CTX_set1_accepted_peer_cert_types(
                self.as_ptr(),
                types.as_ptr().cast::<u8>(),
                types.len(),
            ))
            .map(|_| ())
        }
    }

    /// Consumes the builder, returning a new `SslContext`.
    #[must_use = "The returned owned value is the result of consuming the original owner."]
    pub fn build(self) -> SslContext {
        self.ctx
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::SSL_CTX;
    fn drop = ffi::SSL_CTX_free;

    /// A context object for TLS streams.
    ///
    /// Applications commonly configure a single `SslContext` that is shared by all of its
    /// `SslStreams`.
    pub struct SslContext;
}

impl Clone for SslContext {
    fn clone(&self) -> Self {
        (**self).to_owned()
    }
}

impl ToOwned for SslContextRef {
    type Owned = SslContext;

    fn to_owned(&self) -> Self::Owned {
        // SAFETY: A valid borrowed context has a nonnull native pointer. BoringSSL
        // increments its native reference count unconditionally before
        // the second Rust owner takes responsibility for releasing it.
        unsafe {
            SSL_CTX_up_ref(self.as_ptr());
            SslContext::from_ptr(self.as_ptr())
        }
    }
}

// TODO: add useful info here
impl fmt::Debug for SslContext {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "SslContext")
    }
}

// Allocate a native index for the exact wrapper and payload type. The native
// class-specific allocator installs the matching destructor.
macro_rules! callback_indices {
    ($native:ident, $allocate:ident, $registry:ident $(, #[$attr:meta])?) => {
        /// Allocates a distinct typed extra-data index.
        ///
        /// # Errors
        ///
        /// Returns an error if the native index allocation fails.
        #[corresponds($native)]
        pub fn new_ex_index<T: 'static + Sync + Send>() -> Result<Index<Self, T>, ErrorStack> {
            // SAFETY: the class-specific allocator registers the destructor for T.
            unsafe {
                ffi::init();
                let idx = cvt_n($allocate(Some(free_data_box::<T>)))?;
                Ok(Index::from_raw(idx))
            }
        }

        $(#[$attr])?
        fn register_callback<T: 'static + Send + Sync>(
            role: CallbackRole,
        ) -> Result<Index<Self, T>, ErrorStack> {
            $registry.register(role, Self::new_ex_index)
        }
    };
}

impl SslContext {
    /// Creates a new builder object for an `SslContext`.
    ///
    /// # Errors
    ///
    /// Native context allocation or the X.509 marker registration fails.
    pub fn builder(method: SslMethod) -> Result<SslContextBuilder, ErrorStack> {
        SslContextBuilder::new(method)
    }

    callback_indices!(SSL_CTX_get_ex_new_index, get_new_idx, CONTEXT_CALLBACKS);

    /// Gets the list of supported ciphers for protocols before TLSv1.3.
    ///
    /// See [`ciphers`] for details on the format
    ///
    /// [`ciphers`]: https://www.openssl.org/docs/manmaster/man1/ciphers.html
    #[corresponds(SSL_CTX_get_ciphers)]
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn ciphers(&self) -> Option<&StackRef<SslCipher>> {
        // SAFETY: The live context owns this optional cipher stack; the getter only
        // borrows it, and null is checked before creating a Rust reference.
        unsafe {
            let ciphers = ffi::SSL_CTX_get_ciphers(self.as_ptr());
            if ciphers.is_null() {
                None
            } else {
                Some(StackRef::from_ptr(ciphers))
            }
        }
    }
}

impl SslContextRef {
    /// Returns the certificate associated with this `SslContext`, if present.
    #[corresponds(SSL_CTX_get0_certificate)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn certificate(&self) -> Option<&X509Ref> {
        if !self.has_x509_support() {
            return None;
        }

        // SAFETY: The live X.509 context owns its optional certificate; the
        // getter returns a borrowed pointer checked for null before dereference.
        unsafe {
            let ptr = ffi::SSL_CTX_get0_certificate(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(X509Ref::from_ptr(ptr))
            }
        }
    }

    /// Returns the private key associated with this `SslContext`, if present.
    #[corresponds(SSL_CTX_get0_privatekey)]
    #[must_use = "The returned key component is the result of this accessor."]
    pub fn private_key(&self) -> Option<&PKeyRef<Private>> {
        // SAFETY: The live context retains its configured key and the getter
        // returns only a nullable borrowed pointer, checked before access.
        unsafe {
            let ptr = ffi::SSL_CTX_get0_privatekey(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(PKeyRef::from_ptr(ptr))
            }
        }
    }

    /// Returns a shared reference to the certificate store used for verification.
    ///
    /// # Errors
    /// The context does not support X.509 certificates.
    #[corresponds(SSL_CTX_get_cert_store)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn cert_store(&self) -> Result<&X509StoreRef, ErrorStack> {
        self.check_x509()?;

        // SAFETY: The live X.509 context holds its initialized certificate store,
        // and this native getter returns only a borrowed reference.
        Ok(unsafe { X509StoreRef::from_ptr(ffi::SSL_CTX_get_cert_store(self.as_ptr())) })
    }

    /// Returns any extra certificate chain attached to this context.
    ///
    /// An empty or unavailable chain is represented as `None`. The native
    /// getter can succeed without populating the chain pointer.
    #[corresponds(SSL_CTX_get_extra_chain_certs)]
    #[must_use = "Inspect the borrowed chain or handle its absence."]
    pub fn extra_chain_certs(&self) -> Option<&StackRef<X509>> {
        if !self.has_x509_support() {
            return None;
        }
        // SAFETY: the native getter writes a nullable, borrowed stack pointer
        // owned by this live context. It may return success with a null chain.
        // Only a non-null successful result is exposed as a shared reference.
        unsafe {
            let mut chain = ptr::null_mut();
            if ffi::SSL_CTX_get_extra_chain_certs(self.as_ptr(), &raw mut chain) == 0 {
                return None;
            }
            if chain.is_null() {
                None
            } else {
                Some(StackRef::from_ptr(chain))
            }
        }
    }

    /// Returns a reference to the extra data at the registered index.
    #[corresponds(SSL_CTX_get_ex_data)]
    #[must_use = "Use the returned application data, or handle an empty slot."]
    pub fn ex_data<T: 'static + Send + Sync>(&self, index: Index<SslContext, T>) -> Option<&T> {
        // SAFETY: the typed index identifies a live boxed T owned by this context.
        unsafe {
            ffi::SSL_CTX_get_ex_data(self.as_ptr(), index.as_raw())
                .cast::<T>()
                .as_ref()
        }
    }

    fn slot_data<T: 'static + Send + Sync>(&self, slot: &IndexSlot<SslContext, T>) -> Option<&T> {
        self.ex_data(slot.get()?)
    }

    fn callback<T: 'static + Send + Sync>(&self, role: CallbackRole) -> Option<&T> {
        self.ex_data(CONTEXT_CALLBACKS.get(role)?)
    }

    // The caller must establish exclusive context ownership, as on a builder.
    unsafe fn replace_ex_data<T: 'static + Send + Sync>(
        &mut self,
        index: Index<SslContext, T>,
        data: T,
    ) -> Result<Option<T>, ErrorStack> {
        let ctx = self.as_ptr();
        // SAFETY: the caller establishes exclusive ownership and the matching
        // typed slot; native storage accepts the pointer only on success.
        unsafe {
            replace_boxed(ffi::SSL_CTX_get_ex_data(ctx, index.as_raw()), data, |ptr| {
                cvt(ffi::SSL_CTX_set_ex_data(ctx, index.as_raw(), ptr))
            })
        }
    }

    /// Adds a session to the context's cache.
    ///
    /// Returns `true` if the session was successfully added to the cache, and `false` if it was already present.
    ///
    /// # Safety
    ///
    /// The caller of this method is responsible for ensuring that the session has never been used with another
    /// `SslContext` than this one.
    #[corresponds(SSL_CTX_add_session)]
    #[must_use = "Check whether the session was actually accepted into the native cache."]
    pub unsafe fn add_session(&self, session: &SslSessionRef) -> bool {
        // SAFETY: The caller guarantees this session belongs to the context;
        // the live context and session reference remain valid for native caching.
        unsafe { ffi::SSL_CTX_add_session(self.as_ptr(), session.as_ptr()) != 0 }
    }

    /// Removes a session from the context's cache and marks it as non-resumable.
    ///
    /// Returns `true` if the session was successfully found and removed, and `false` otherwise.
    ///
    /// # Safety
    ///
    /// The caller of this method is responsible for ensuring that the session has never been used with another
    /// `SslContext` than this one.
    #[corresponds(SSL_CTX_remove_session)]
    #[must_use = "Check whether the session was actually removed from the native cache."]
    pub unsafe fn remove_session(&self, session: &SslSessionRef) -> bool {
        // SAFETY: The caller guarantees the session is associated with
        // this context, which remains live during native cache removal.
        unsafe { ffi::SSL_CTX_remove_session(self.as_ptr(), session.as_ptr()) != 0 }
    }

    /// Returns the context's session cache size limit.
    ///
    /// A value of 0 means that the cache size is unbounded.
    #[corresponds(SSL_CTX_sess_get_cache_size)]
    #[must_use = "The configured cache capacity is the result of this query."]
    pub fn session_cache_size(&self) -> c_ulong {
        // SAFETY: The getter reads a scalar cache limit from a live
        // native context; no borrowed Rust memory escapes.
        unsafe { ffi::SSL_CTX_sess_get_cache_size(self.as_ptr()) }
    }

    /// Returns the verify mode that was set on this context from [`SslContextBuilder::set_verify_mode`].
    ///
    /// [`SslContextBuilder::set_verify_mode`]: struct.SslContextBuilder.html#method.set_verify_mode
    ///
    /// # Errors
    /// The context does not support X.509 certificates.
    #[corresponds(SSL_CTX_get_verify_mode)]
    #[must_use = "Use the returned flags to inspect current configuration."]
    pub fn verify_mode(&self) -> Result<SslVerifyMode, ErrorStack> {
        self.check_x509()?;

        // SAFETY: The context has been checked for X.509 support and
        // remains live while the getter reads its native mode bits.
        let mode = unsafe { ffi::SSL_CTX_get_verify_mode(self.as_ptr()) };
        Ok(SslVerifyMode::from_bits_retain(mode))
    }

    /// Assumes that this `SslContext` is configured for X.509 certificates.
    ///
    /// # Safety
    ///
    /// The native context must use the X.509 certificate method and be exclusively owned.
    /// No other reference may access its extra-data slots during this operation.
    ///
    /// # Errors
    ///
    /// Registration or replacement of the native X.509 marker fails.
    pub unsafe fn assume_x509(&mut self) -> Result<(), ErrorStack> {
        // SAFETY: the caller guarantees this native SSL context really uses
        // X.509 and owns its native extra-data slots exclusively. The newly
        // registered typed index therefore matches the stored marker.
        unsafe { self.replace_ex_data(X509_FLAG_INDEX.register()?, true)? };
        Ok(())
    }

    /// Returns `true` if context is configured for X.509 certificates.
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn has_x509_support(&self) -> bool {
        self.slot_data(&X509_FLAG_INDEX)
            .copied()
            .unwrap_or_default()
    }

    fn check_x509(&self) -> Result<(), ErrorStack> {
        if self.has_x509_support() {
            Ok(())
        } else {
            Err(ErrorStack::internal_error_str(
                "context does not support x.509 certificates",
            ))
        }
    }

    /// Registers a list of ECH keys on the context. This list should contain new and old
    /// ECHConfigs to allow stale DNS caches to update. Unlike most `SSL_CTX` APIs, this function
    /// is safe to call even after the `SSL_CTX` has been associated with connections on various
    /// threads.
    #[corresponds(SSL_CTX_set1_ech_keys)]
    pub fn set_ech_keys(&self, keys: &SslEchKeys) -> Result<(), ErrorStack> {
        // SAFETY: the live native context accepts this borrowed, reference-
        // counted key collection and retains its own ownership. BoringSSL
        // synchronizes this operation even on contexts shared across threads.
        unsafe { cvt(ffi::SSL_CTX_set1_ech_keys(self.as_ptr(), keys.as_ptr())) }
    }

    /// Returns the list of server certificate types.
    #[corresponds(SSL_CTX_get0_server_certificate_types)]
    #[cfg(feature = "rpk")]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn server_certificate_types(&self) -> Option<&[CertificateType]> {
        let mut types = ptr::null();
        let mut types_len = 0;
        // SAFETY: The live context owns the optional
        // certificate-type buffer; an empty native length is handled before
        // constructing a borrowed Rust slice of transparent u8 values.
        unsafe {
            ffi::SSL_CTX_get0_accepted_peer_cert_types(
                self.as_ptr(),
                &raw mut types,
                &raw mut types_len,
            );

            if types_len == 0 {
                return None;
            }

            Some(slice::from_raw_parts(
                types.cast::<CertificateType>(),
                types_len,
            ))
        }
    }
}

/// Error returned by the callback to get a session when operation
/// could not complete and should be retried later.
///
/// See [`SslContextBuilder::set_get_session_callback`].
#[derive(Debug)]
pub struct GetSessionPendingError;

/// Information about the state of a cipher.
pub struct CipherBits {
    /// The number of secret bits used for the cipher.
    pub secret: i32,

    /// The number of bits processed by the chosen algorithm.
    pub algorithm: i32,
}

#[repr(transparent)]
pub struct ClientHello<'ssl>(&'ssl ffi::SSL_CLIENT_HELLO);

impl ClientHello<'_> {
    /// Returns the data of a given extension, if present.
    #[corresponds(SSL_early_callback_ctx_extension_get)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn get_extension(&self, ext_type: ExtensionType) -> Option<&[u8]> {
        // SAFETY: The ClientHello is live for the native callback and the
        // output slots are writable; the returned borrowed bytes are checked before slicing.
        unsafe {
            let mut ptr = ptr::null();
            let mut len = 0;
            let result = ffi::SSL_early_callback_ctx_extension_get(
                self.0,
                ext_type.0,
                &raw mut ptr,
                &raw mut len,
            );
            if result == 0 {
                return None;
            }
            // SAFETY: successful BoringSSL extension lookup borrows the input
            // ClientHello buffer for the duration of this callback.
            native_input(ptr, len)
        }
    }

    pub fn ssl_mut(&mut self) -> &mut SslRef {
        // SAFETY: The ClientHello is live for the certificate-selection callback;
        // the exclusive Rust borrow allows a mutable reference to its SSL.
        unsafe { SslRef::from_ptr_mut(self.0.ssl) }
    }

    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn ssl(&self) -> &SslRef {
        // SAFETY: The ClientHello is live for the certificate-selection callback;
        // the native SSL pointer remains valid for the shared borrow.
        unsafe { SslRef::from_ptr(self.0.ssl) }
    }

    /// Returns the servername sent by the client via Server Name Indication (SNI).
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn servername(&self, type_: NameType) -> Option<&str> {
        self.ssl().servername(type_)
    }

    /// Returns the version sent by the client in its Client Hello record.
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub const fn client_version(&self) -> SslVersion {
        SslVersion(self.0.version)
    }

    /// Returns the protocol version string, if its native representation is valid UTF-8.
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn version_str(&self) -> Option<&'static str> {
        self.ssl().version_str()
    }

    /// Returns the raw data of the client hello message
    #[must_use = "The returned byte representation is the result of serialization or borrowing."]
    pub const fn as_bytes(&self) -> &[u8] {
        // SAFETY: BoringSSL owns the ClientHello bytes until callback return.
        // Any empty/null or oversized pair is handled before making a slice.
        match unsafe { native_input(self.0.client_hello, self.0.client_hello_len) } {
            Some(data) => data,
            None => &[],
        }
    }

    /// Returns the client random data
    #[must_use = "Use the returned handshake random bytes for the intended protocol inspection."]
    pub const fn random(&self) -> &[u8] {
        // SAFETY: the random bytes belong to the live native ClientHello.
        match unsafe { native_input(self.0.random, self.0.random_len) } {
            Some(data) => data,
            None => &[],
        }
    }

    /// Returns the raw list of ciphers supported by the client in its Client Hello record.
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub const fn ciphers(&self) -> &[u8] {
        // SAFETY: the cipher-suite bytes belong to the live native ClientHello.
        match unsafe { native_input(self.0.cipher_suites, self.0.cipher_suites_len) } {
            Some(data) => data,
            None => &[],
        }
    }
}

/// Information about a cipher.
#[derive(Clone, Copy)]
pub struct SslCipher(&'static SslCipherRef);

impl SslCipher {
    #[corresponds(SSL_get_cipher_by_value)]
    #[must_use = "Use the wrapper returned for the supplied native representation."]
    pub fn from_value(value: u16) -> Option<Self> {
        // SAFETY: BoringSSL returns a null or a process-lifetime static
        // cipher descriptor; null is checked before exposing the borrowed ref.
        unsafe {
            let ptr = ffi::SSL_get_cipher_by_value(value);
            if ptr.is_null() {
                None
            } else {
                Some(Self::from_ptr(ptr.cast_mut()))
            }
        }
    }
}

// SAFETY: the native stack type matches static native SSL_CIPHER descriptors; ownership release is a no-op.
unsafe impl Stackable for SslCipher {
    type StackType = ffi::stack_st_SSL_CIPHER;
}

// SAFETY: SSL_CIPHER descriptors are immutable process-lifetime native objects;
// the wrapper retains a shared reference and does not own or free the pointer.
unsafe impl ForeignType for SslCipher {
    type CType = ffi::SSL_CIPHER;
    type Ref = SslCipherRef;

    #[inline]
    unsafe fn from_ptr(ptr: *mut ffi::SSL_CIPHER) -> Self {
        // SAFETY: The unsafe ForeignType caller supplies a valid static cipher
        // descriptor; converting it to a shared native reference cannot free it.
        Self(unsafe { SslCipherRef::from_ptr(ptr) })
    }

    #[inline]
    fn as_ptr(&self) -> *mut ffi::SSL_CIPHER {
        self.0.as_ptr()
    }
}

impl Deref for SslCipher {
    type Target = SslCipherRef;

    fn deref(&self) -> &SslCipherRef {
        self.0
    }
}

/// Reference to an [`SslCipher`].
///
/// [`SslCipher`]: struct.SslCipher.html
pub struct SslCipherRef(Opaque);

// SAFETY: native SSL_CIPHER descriptors are immutable static data. The
// `Opaque` field intentionally blocks derived auto-traits, not this contract.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "SSL_CIPHER descriptors are immutable and global; Opaque deliberately blocks auto-Send"
)]
// SAFETY: native cipher descriptors are immutable static storage shared by
// all TLS connections; moving a borrowed descriptor does not permit mutation.
unsafe impl Send for SslCipherRef {}
// SAFETY: all public accessors query immutable native cipher metadata.
unsafe impl Sync for SslCipherRef {}

// SAFETY: foreign references borrow a valid native SSL_CIPHER descriptor.
unsafe impl ForeignTypeRef for SslCipherRef {
    type CType = ffi::SSL_CIPHER;
}

impl SslCipherRef {
    /// Returns the IANA number of the cipher.
    #[corresponds(SSL_CIPHER_get_protocol_id)]
    #[must_use = "Use the returned native representation when crossing the native API boundary."]
    pub fn protocol_id(&self) -> u16 {
        // SAFETY: The borrowed cipher is a live immutable native
        // descriptor; its protocol ID is returned by value.
        unsafe { ffi::SSL_CIPHER_get_protocol_id(self.as_ptr()) }
    }

    /// Returns the cipher name, or `None` for absent or invalid native metadata.
    #[corresponds(SSL_CIPHER_get_name)]
    #[must_use = "Use the returned name for reporting or selecting the native identifier."]
    pub fn name(&self) -> Option<&'static str> {
        // SAFETY: the native name is a static NUL-terminated string when
        // non-null. Its UTF-8 validity is checked before returning to Rust.
        unsafe {
            let ptr = ffi::SSL_CIPHER_get_name(self.as_ptr());
            if ptr.is_null() {
                return None;
            }
            CStr::from_ptr(ptr).to_str().ok()
        }
    }

    /// Returns the RFC-standard name of the cipher, if one exists.
    #[corresponds(SSL_CIPHER_standard_name)]
    #[must_use = "Use the standardized cipher suite name for protocol diagnostics."]
    pub fn standard_name(&self) -> Option<&'static str> {
        // SAFETY: a non-null result points to static NUL-terminated native
        // metadata. The RFC name is omitted if the bytes are not UTF-8.
        unsafe {
            let ptr = ffi::SSL_CIPHER_standard_name(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                CStr::from_ptr(ptr).to_str().ok()
            }
        }
    }

    /// Returns the protocol version that introduced the cipher, or `None` if
    /// native metadata is absent or not valid UTF-8.
    #[corresponds(SSL_CIPHER_get_version)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn version(&self) -> Option<&'static str> {
        // SAFETY: non-null native version strings have static storage and are
        // NUL terminated; invalid UTF-8 is represented as `None`.
        unsafe {
            let ptr = ffi::SSL_CIPHER_get_version(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                CStr::from_ptr(ptr).to_str().ok()
            }
        }
    }

    /// Returns the number of bits used for the cipher.
    #[corresponds(SSL_CIPHER_get_bits)]
    #[must_use = "Use the returned cryptographic size or bit count to validate parameters."]
    pub fn bits(&self) -> CipherBits {
        // SAFETY: The immutable native cipher is live; the local algorithm
        // bit-count output slot is writable until the call returns.
        unsafe {
            let mut algo_bits = 0;
            let secret_bits = ffi::SSL_CIPHER_get_bits(self.as_ptr(), &raw mut algo_bits);
            CipherBits {
                secret: secret_bits,
                algorithm: algo_bits,
            }
        }
    }

    /// Returns a textual description of the cipher.
    #[corresponds(SSL_CIPHER_description)]
    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    pub fn description(&self) -> Option<String> {
        // SAFETY: the native API writes into this 128-byte stack buffer and
        // returns the buffer or null on error. Check null before reading its
        // NUL-terminated output; no native allocation escapes this call.
        unsafe {
            let mut buf = [0; 128];
            let ptr = ffi::SSL_CIPHER_description(self.as_ptr(), buf.as_mut_ptr(), 128);
            if ptr.is_null() {
                None
            } else {
                Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
            }
        }
    }

    /// Returns one if the cipher uses an AEAD cipher.
    #[corresponds(SSL_CIPHER_is_aead)]
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn cipher_is_aead(&self) -> bool {
        // SAFETY: The borrowed cipher is an immutable native descriptor;
        // the getter returns only a scalar flag.
        unsafe { ffi::SSL_CIPHER_is_aead(self.as_ptr()) != 0 }
    }

    /// Returns the NID corresponding to the cipher's key exchange.
    ///
    /// TLS 1.3 ciphers report [`Nid::KX_ANY`].
    #[corresponds(SSL_CIPHER_get_kx_nid)]
    #[must_use = "Use the returned algorithm or parameter identity when selecting or reporting cryptographic settings."]
    pub fn cipher_kx_nid(&self) -> Option<Nid> {
        // SAFETY: The borrowed cipher is an immutable native descriptor;
        // a zero native NID is represented as absence.
        let n = unsafe { ffi::SSL_CIPHER_get_kx_nid(self.as_ptr()) };
        if n == 0 { None } else { Some(Nid::from_raw(n)) }
    }

    /// Returns the NID corresponding to the cipher's authentication type.
    #[corresponds(SSL_CIPHER_get_auth_nid)]
    #[must_use = "Use the returned algorithm or parameter identity when selecting or reporting cryptographic settings."]
    pub fn cipher_auth_nid(&self) -> Option<Nid> {
        // SAFETY: The borrowed cipher is an immutable native descriptor;
        // a zero native NID is represented as absence.
        let n = unsafe { ffi::SSL_CIPHER_get_auth_nid(self.as_ptr()) };
        if n == 0 { None } else { Some(Nid::from_raw(n)) }
    }

    /// Returns the NID corresponding to the cipher.
    #[corresponds(SSL_CIPHER_get_cipher_nid)]
    #[must_use = "Use the returned algorithm or parameter identity when selecting or reporting cryptographic settings."]
    pub fn cipher_nid(&self) -> Option<Nid> {
        // SAFETY: The borrowed cipher is an immutable native descriptor;
        // a zero native NID is represented as absence.
        let n = unsafe { ffi::SSL_CIPHER_get_cipher_nid(self.as_ptr()) };
        if n == 0 { None } else { Some(Nid::from_raw(n)) }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::SSL_SESSION;
    fn drop = ffi::SSL_SESSION_free;

    /// An encoded SSL session.
    ///
    /// These can be cached to share sessions across connections.
    pub struct SslSession;
}

impl Clone for SslSession {
    fn clone(&self) -> Self {
        SslSessionRef::to_owned(self)
    }
}

impl SslSession {
    from_der! {
        /// Deserializes a DER-encoded session structure.
        #[corresponds(d2i_SSL_SESSION)]
        from_der,
        SslSession,
        ffi::d2i_SSL_SESSION,
        ::libc::c_long
    }
}

impl ToOwned for SslSessionRef {
    type Owned = SslSession;

    fn to_owned(&self) -> SslSession {
        // SAFETY: The borrowed session has a valid nonnull native pointer. BoringSSL
        // always increments its reference count; Rust then owns the extra
        // session reference until it is dropped.
        unsafe {
            SSL_SESSION_up_ref(self.as_ptr());
            SslSession(NonNull::new_unchecked(self.as_ptr()))
        }
    }
}

impl SslSessionRef {
    /// Returns the SSL session ID.
    #[corresponds(SSL_SESSION_get_id)]
    #[must_use = "Use the returned algorithm or parameter identity when selecting or reporting cryptographic settings."]
    pub fn id(&self) -> &[u8] {
        // SAFETY: The live session owns the ID bytes; the out-length is writable,
        // and the validated native slice handles an empty/null ID safely.
        unsafe {
            let mut len = 0;
            let p = ffi::SSL_SESSION_get_id(self.as_ptr(), &raw mut len);
            // SAFETY: BoringSSL keeps the ID storage live for this session;
            // empty native IDs may be represented by null pointers.
            native_input(p, usize::try_from(len).unwrap_or(0)).unwrap_or(&[])
        }
    }

    /// Returns the length of the master key.
    #[corresponds(SSL_SESSION_get_master_key)]
    #[must_use = "Use the returned length or capacity to size buffers or validate input."]
    pub fn master_key_len(&self) -> usize {
        // SAFETY: The live session may be queried for the key size using a null
        // output buffer and zero capacity, as required by this native API.
        unsafe { SSL_SESSION_get_master_key(self.as_ptr(), ptr::null_mut(), 0) }
    }

    /// Copies the master key into the provided buffer.
    ///
    /// Returns the number of bytes written, or the size of the master key if the buffer is empty.
    #[corresponds(SSL_SESSION_get_master_key)]
    pub fn master_key(&self, buf: &mut [u8]) -> usize {
        // SAFETY: The output buffer is writable for its full native length and the
        // live session borrows it synchronously without retaining it.
        unsafe { SSL_SESSION_get_master_key(self.as_ptr(), buf.as_mut_ptr(), buf.len()) }
    }

    /// Returns the time at which the session was established, in seconds since the Unix epoch.
    #[corresponds(SSL_SESSION_get_time)]
    #[must_use = "Use the returned timestamp or lifetime when determining session validity."]
    pub fn time(&self) -> u64 {
        // SAFETY: The live borrowed session contains this scalar timestamp
        // and no raw buffer is exposed by the native getter.
        unsafe { ffi::SSL_SESSION_get_time(self.as_ptr()) }
    }

    /// Returns the sessions timeout, in seconds.
    ///
    /// A session older than this time should not be used for session resumption.
    #[corresponds(SSL_SESSION_get_timeout)]
    #[must_use = "Use the returned timestamp or lifetime when determining session validity."]
    pub fn timeout(&self) -> u32 {
        // SAFETY: The live borrowed session contains this scalar
        // timeout and no raw buffer is exposed by the native getter.
        unsafe { ffi::SSL_SESSION_get_timeout(self.as_ptr()) }
    }

    /// Returns whether an external cache should consume this session after one lookup.
    ///
    /// Single-use TLS 1.3 tickets prevent connection correlation; see
    /// [RFC 8446 Appendix C.4](https://datatracker.ietf.org/doc/html/rfc8446#appendix-C.4).
    #[corresponds(SSL_SESSION_should_be_single_use)]
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn should_be_single_use(&self) -> bool {
        // SAFETY: The live session supplies a scalar reuse
        // policy flag through a synchronous native getter.
        unsafe { ffi::SSL_SESSION_should_be_single_use(self.as_ptr()) != 0 }
    }

    /// Returns an owned session with early data disabled.
    ///
    /// BoringSSL may return the same session with an increased reference count when early data is
    /// already disabled.
    #[corresponds(SSL_SESSION_copy_without_early_data)]
    pub fn copy_without_early_data(&self) -> Result<SslSession, ErrorStack> {
        // SAFETY: BoringSSL returns an owned reference
        // (or null on failure) to a session. cvt_p checks null before Rust
        // takes ownership, including if the native session was retained.
        unsafe {
            cvt_p(ffi::SSL_SESSION_copy_without_early_data(self.as_ptr()))
                .map(|session| SslSession::from_ptr(session))
        }
    }

    /// Returns the earliest expiry in the peer certificate chain, as seconds since the Unix epoch.
    ///
    /// Returns `None` when the session holds no peer certificates.
    #[corresponds(SSL_SESSION_get0_peer_certificates)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn peer_chain_not_after(&self) -> Option<i64> {
        // SAFETY: the session owns the stack and its buffers for the duration of this call, and
        // each parsed certificate holds its own reference to its buffer.
        unsafe {
            let certs =
                ffi::SSL_SESSION_get0_peer_certificates(self.as_ptr()).cast::<ffi::OPENSSL_STACK>();
            if certs.is_null() {
                return None;
            }
            earliest_not_after((0..ffi::OPENSSL_sk_num(certs)).filter_map(|index| {
                let buffer = ffi::OPENSSL_sk_value(certs, index).cast::<ffi::CRYPTO_BUFFER>();
                let cert = ffi::X509_parse_from_buffer(buffer);
                (!cert.is_null()).then(|| X509::from_ptr(cert))
            }))
        }
    }

    /// Returns the cipher negotiated by the connection that established the session.
    ///
    /// TLS 1.3 resumptions may use a different cipher.
    #[corresponds(SSL_SESSION_get0_cipher)]
    #[must_use = "Use the negotiated cipher description to inspect the connection."]
    pub fn cipher(&self) -> Option<&SslCipherRef> {
        // SAFETY: The live session owns or references the negotiated
        // cipher, which is immutable. Null is checked before borrowing.
        unsafe {
            let ptr = ffi::SSL_SESSION_get0_cipher(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(SslCipherRef::from_ptr(ptr.cast_mut()))
            }
        }
    }

    /// Returns the session's TLS protocol version.
    #[corresponds(SSL_SESSION_get_protocol_version)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn protocol_version(&self) -> SslVersion {
        // SAFETY: The live native session returns its
        // negotiated protocol version as a scalar.
        unsafe {
            let version = ffi::SSL_SESSION_get_protocol_version(self.as_ptr());
            SslVersion(version)
        }
    }

    /// Returns the session ID context recorded when the session was created.
    #[corresponds(SSL_SESSION_get0_id_context)]
    fn id_context(&self) -> &[u8] {
        // SAFETY: The live session owns its optional ID-context bytes and the local
        // output-length slot is writable; native_input validates the pair.
        unsafe {
            let mut len = 0;
            let p = ffi::SSL_SESSION_get0_id_context(self.as_ptr(), &raw mut len);
            // SAFETY: the ID-context buffer is owned by this session; null
            // pointers with zero length are treated as the empty ID context.
            native_input(p, usize::try_from(len).unwrap_or(0)).unwrap_or(&[])
        }
    }

    to_der! {
        /// Serializes the session into a DER-encoded structure.
        #[corresponds(i2d_SSL_SESSION)]
        to_der,
        ffi::i2d_SSL_SESSION
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::SSL;
    fn drop = ffi::SSL_free;

    /// The state of an SSL/TLS session.
    ///
    /// `Ssl` objects are created from an [`SslContext`], which provides configuration defaults.
    /// These defaults can be overridden on a per-`Ssl` basis, however.
    ///
    /// [`SslContext`]: struct.SslContext.html
    pub struct Ssl;
}

impl fmt::Debug for Ssl {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, fmt)
    }
}

impl Ssl {
    callback_indices!(SSL_get_ex_new_index, get_new_ssl_idx, SSL_CALLBACKS, #[cfg(not(feature = "fips"))]);

    /// Creates a new [`Ssl`].
    #[corresponds(SSL_new)]
    pub fn new(ctx: &SslContextRef) -> Result<Self, ErrorStack> {
        // SAFETY: The borrowed live context stays valid through allocation and the
        // native SSL handle is checked for null before Rust takes ownership.
        unsafe {
            let ptr = cvt_p(ffi::SSL_new(ctx.as_ptr()))?;
            let mut ssl = Self::from_ptr(ptr);
            ssl.set_ex_data(SESSION_CTX_INDEX.register()?, ctx.to_owned())?;

            Ok(ssl)
        }
    }

    /// Initiates a client-side TLS handshake, returning a [`MidHandshakeSslStream`].
    ///
    /// This method is guaranteed to return without calling any callback defined
    /// in the internal [`Ssl`] or [`SslContext`].
    ///
    /// See [`SslStreamBuilder::setup_connect`] for more details.
    ///
    /// # Warning
    ///
    /// `BoringSSL`'s default configuration is insecure. It is highly recommended to use
    /// [`SslConnector`] rather than [`Ssl`] directly, as it manages that configuration.
    ///
    /// # Errors
    ///
    /// Allocating the stream's native BIO transport fails before the handshake.
    pub fn setup_connect<S>(self, stream: S) -> Result<MidHandshakeSslStream<S>, ErrorStack>
    where
        S: Read + Write,
    {
        Ok(SslStreamBuilder::new(self, stream)?.setup_connect())
    }

    /// Attempts a client-side TLS handshake.
    ///
    /// This is a convenience method which combines [`Self::setup_connect`] and
    /// [`MidHandshakeSslStream::handshake`].
    ///
    /// # Warning
    ///
    /// OpenSSL's default configuration is insecure. It is highly recommended to use
    /// [`SslConnector`] rather than `Ssl` directly, as it manages that configuration.
    ///
    /// # Errors
    ///
    /// Transport setup or the TLS handshake fails or needs additional I/O.
    pub fn connect<S>(self, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        self.setup_connect(stream)?.handshake()
    }

    /// Initiates a server-side TLS handshake.
    ///
    /// This method is guaranteed to return without calling any callback defined
    /// in the internal [`Ssl`] or [`SslContext`].
    ///
    /// See [`SslStreamBuilder::setup_accept`] for more details.
    ///
    /// # Warning
    ///
    /// `BoringSSL`'s default configuration is insecure. It is highly recommended to use
    /// [`SslAcceptor`] rather than [`Ssl`] directly, as it manages that configuration.
    ///
    /// # Errors
    ///
    /// Allocating the stream's native BIO transport fails before the handshake.
    pub fn setup_accept<S>(self, stream: S) -> Result<MidHandshakeSslStream<S>, ErrorStack>
    where
        S: Read + Write,
    {
        Ok(SslStreamBuilder::new(self, stream)?.setup_accept())
    }

    /// Attempts a server-side TLS handshake.
    ///
    /// This is a convenience method which combines [`Self::setup_accept`] and
    /// [`MidHandshakeSslStream::handshake`].
    ///
    /// # Warning
    ///
    /// OpenSSL's default configuration is insecure. It is highly recommended to use
    /// `SslAcceptor` rather than `Ssl` directly, as it manages that configuration.
    ///
    /// [`SSL_accept`]: https://www.openssl.org/docs/manmaster/man3/SSL_accept.html
    ///
    /// # Errors
    ///
    /// Transport setup or the TLS handshake fails or needs additional I/O.
    pub fn accept<S>(self, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        self.setup_accept(stream)?.handshake()
    }
}

impl fmt::Debug for SslRef {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = fmt.debug_struct("Ssl");

        builder.field("state", &self.state_string_long());

        if self.ssl_context().has_x509_support() {
            builder.field("verify_result", &self.verify_result());
        }

        builder.field("verify_result", &self.verify_result());

        builder.finish()
    }
}

impl SslRef {
    fn get_raw_rbio(&self) -> *mut ffi::BIO {
        // SAFETY: This live connection holds its owned BIO, and the getter only
        // returns its borrowed pointer for internal use.
        unsafe { ffi::SSL_get_rbio(self.as_ptr()) }
    }

    /// Sets the options used by the ongoing session, returning the old set.
    ///
    /// # Note
    ///
    /// This *enables* the specified options, but does not disable unspecified options. Use
    /// `clear_options` for that.
    #[corresponds(SSL_set_options)]
    pub fn set_options(&mut self, option: SslOptions) -> SslOptions {
        // SAFETY: The live SSL connection is uniquely borrowed while the
        // native function applies and returns an option bitset.
        let bits = unsafe { ffi::SSL_set_options(self.as_ptr(), option.bits()) };
        SslOptions::from_bits_retain(bits)
    }

    /// Clears the options used by the ongoing session, returning the old set.
    #[corresponds(SSL_clear_options)]
    pub fn clear_options(&mut self, option: SslOptions) -> SslOptions {
        // SAFETY: The live SSL connection is uniquely borrowed while the
        // native function clears and returns an option bitset.
        let bits = unsafe { ffi::SSL_clear_options(self.as_ptr(), option.bits()) };
        SslOptions::from_bits_retain(bits)
    }

    /// Sets the supported TLS named groups in preference order.
    /// An empty list restores the native defaults.
    ///
    /// # Errors
    /// A group is unsupported or repeated, or native configuration fails.
    #[corresponds(SSL_set1_group_ids)]
    pub fn set_groups(&mut self, groups: &[KeyShare]) -> Result<(), ErrorStack> {
        // SAFETY: KeyShare is transparent over u16; the native setter copies
        // the borrowed group IDs into the exclusively accessed configuration.
        unsafe {
            cvt(ffi::SSL_set1_group_ids(
                self.as_ptr(),
                groups.as_ptr().cast(),
                groups.len(),
            ))
        }
    }

    #[corresponds(SSL_set1_curves_list)]
    pub fn set_curves_list(&mut self, curves: &str) -> Result<(), ErrorStack> {
        let curves = CString::new(curves).map_err(ErrorStack::internal_error)?;
        // SAFETY: The NUL-terminated curve list stays alive during
        // synchronous configuration of the uniquely borrowed connection.
        unsafe { cvt_0i(ffi::SSL_set1_curves_list(self.as_ptr(), curves.as_ptr())).map(|_| ()) }
    }

    #[corresponds(SSL_set_verify_algorithm_prefs)]
    pub fn set_verify_algorithm_prefs(
        &mut self,
        prefs: &[SslSignatureAlgorithm],
    ) -> Result<(), ErrorStack> {
        // SAFETY: The transparent u16 preference slice
        // remains live while BoringSSL copies its requested algorithms.
        unsafe {
            cvt_0i(ffi::SSL_set_verify_algorithm_prefs(
                self.as_ptr(),
                prefs.as_ptr().cast(),
                prefs.len(),
            ))
            .map(|_| ())
        }
    }

    /// Returns the curve ID (aka group ID) used for this `SslRef`.
    #[corresponds(SSL_get_curve_id)]
    #[must_use = "Use the returned algorithm or parameter identity when selecting or reporting cryptographic settings."]
    pub fn curve(&self) -> Option<u16> {
        // SAFETY: The live SSL connection reports a scalar curve ID;
        // unsupported or unselected curves are handled by the Rust wrapper.
        let curve_id = unsafe { ffi::SSL_get_curve_id(self.as_ptr()) };
        if curve_id == 0 {
            return None;
        }
        Some(curve_id)
    }

    /// Returns the curve name used for this `SslRef`.
    #[corresponds(SSL_get_curve_name)]
    #[must_use = "Use the returned algorithm or parameter identity when selecting or reporting cryptographic settings."]
    pub fn curve_name(&self) -> Option<&'static str> {
        let curve_id = self.curve()?;

        // SAFETY: The native curve name is a static string or null,
        // which is checked before converting the borrowed bytes to UTF-8.
        unsafe {
            let ptr = ffi::SSL_get_curve_name(curve_id);
            if ptr.is_null() {
                return None;
            }

            CStr::from_ptr(ptr).to_str().ok()
        }
    }

    /// Returns whether the TLS 1.3 `HelloRetryRequest` was used
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn used_hello_retry_request(&self) -> bool {
        // SAFETY: The native getter reads a scalar flag
        // from the live SSL handshake state.
        unsafe { ffi::SSL_used_hello_retry_request(self.as_ptr()) == 1 }
    }

    /// Returns an `ErrorCode` value for the most recent operation on this `SslRef`.
    #[corresponds(SSL_get_error)]
    #[must_use = "Use the returned diagnostic information to handle or report the result."]
    pub fn error_code(&self, ret: c_int) -> ErrorCode {
        // SAFETY: The live SSL connection supplies a native error code
        // describing the immediately preceding operation result.
        unsafe { ErrorCode::from_raw(ffi::SSL_get_error(self.as_ptr(), ret)) }
    }

    /// Changes only the verification mode, preserving all callbacks.
    /// # Errors
    /// X.509 is unsupported or the connection configuration is unavailable.
    #[corresponds(SSL_set_verify)]
    pub fn set_verify_mode(&mut self, mode: SslVerifyMode) -> Result<(), ErrorStack> {
        self.ssl_context().check_x509()?;
        self.require_verification_config()?;
        // SAFETY: a live X.509 connection with configuration; native preserves
        // the existing per-certificate callback when supplied null.
        unsafe { ffi::SSL_set_verify(self.as_ptr(), c_int::from(mode.bits()), None) };
        Ok(())
    }

    fn require_verification_config(&self) -> Result<(), ErrorStack> {
        // SAFETY: the getter works with any certificate method and returns -1
        // when the configuration has been discarded.
        if unsafe { ffi::SSL_get_verify_mode(self.as_ptr()) } < 0 {
            return Err(ErrorStack::internal_error_str(
                "TLS verification configuration unavailable",
            ));
        }
        Ok(())
    }

    /// Sets the certificate verification depth.
    ///
    /// If the peer's certificate chain is longer than this value, verification will fail.
    ///
    /// # Errors
    /// The context does not support X.509 certificates or the depth exceeds the signed native integer range.
    #[corresponds(SSL_set_verify_depth)]
    pub fn set_verify_depth(&mut self, depth: u32) -> Result<(), ErrorStack> {
        let depth = c_int::try_from(depth).map_err(ErrorStack::internal_error)?;
        self.ssl_context().check_x509()?;
        self.require_verification_config()?;

        // SAFETY: the live SSL connection is exclusively borrowed and depth
        // has been checked against the native signed integer range.
        unsafe { ffi::SSL_set_verify_depth(self.as_ptr(), depth) };
        Ok(())
    }

    /// Returns the verify mode that was set using `set_verify_mode`.
    ///
    /// # Errors
    /// The context does not support X.509 certificates.
    #[corresponds(SSL_get_verify_mode)]
    #[must_use = "Use the returned flags to inspect current configuration."]
    pub fn verify_mode(&self) -> Result<SslVerifyMode, ErrorStack> {
        self.ssl_context().check_x509()?;

        // SAFETY: The live SSL connection returns its native verify
        // bitset; the wrapper preserves any recognized or future bits.
        let mode = unsafe { ffi::SSL_get_verify_mode(self.as_ptr()) };
        if mode < 0 {
            return Err(ErrorStack::internal_error_str(
                "TLS verification configuration unavailable",
            ));
        }
        Ok(SslVerifyMode::from_bits_retain(mode))
    }

    /// Like [`SslContextBuilder::set_verify_callback`].
    ///
    /// *Warning*: This callback does not replace the default certificate verification
    /// process and is, instead, called multiple times in the course of that process.
    /// It is very difficult to implement this callback correctly, without inadvertently
    /// relying on implementation details or making incorrect assumptions about when the
    /// callback is called.
    ///
    /// Instead, use [`SslContextBuilder::set_custom_verify_callback`] to customize
    /// certificate verification. Those callbacks can inspect the peer-sent chain,
    /// call [`X509StoreContextRef::verify_cert`] and inspect the result, or perform
    /// other operations more straightforwardly.
    ///
    /// # Errors
    /// The context does not support X.509 certificates.
    ///
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_set_verify)]
    pub fn set_verify_callback<F>(
        &mut self,
        mode: SslVerifyMode,
        callback: F,
    ) -> Result<(), ErrorStack>
    where
        F: Fn(bool, &mut X509StoreContextRef) -> bool + 'static + Sync + Send,
    {
        self.ssl_context().check_x509()?;

        self.require_verification_config()?;
        self.set_ex_data(SSL_VERIFY_INDEX.register()?, Some(Arc::new(callback)))?;
        // SAFETY: the live X.509 connection owns its callback state and config.
        unsafe {
            ffi::SSL_set_verify(
                self.as_ptr(),
                c_int::from(mode.bits()),
                Some(ssl_raw_verify),
            );
        }
        Ok(())
    }

    /// Removes the inherited or connection-specific per-certificate verifier.
    /// The whole-chain X.509 and custom TLS callbacks remain unchanged.
    /// # Errors
    /// X.509 is unsupported or configuration is unavailable.
    #[corresponds(SSL_clear_verify_callback)]
    pub fn clear_verify_callback(&mut self, mode: SslVerifyMode) -> Result<(), ErrorStack> {
        self.ssl_context().check_x509()?;
        // SAFETY: exclusive X.509 SSL; native checks config before changing it.
        unsafe {
            cvt(ffi::SSL_clear_verify_callback(
                self.as_ptr(),
                c_int::from(mode.bits()),
            ))?;
        }
        if let Some(index) = SSL_VERIFY_INDEX.get()
            && let Some(data) = self.ex_data_mut(index)
        {
            *data = None;
        }
        Ok(())
    }

    /// Sets a custom certificate store for verifying peer certificates.
    ///
    /// # Errors
    /// The context does not support X.509 certificates or native store installation fails.
    #[corresponds(SSL_set1_verify_cert_store)]
    pub fn set_verify_cert_store(&mut self, cert_store: &X509StoreRef) -> Result<(), ErrorStack> {
        self.ssl_context().check_x509()?;
        // SAFETY: live native objects; BoringSSL takes its own store reference.
        unsafe {
            cvt(ffi::SSL_set1_verify_cert_store(
                self.as_ptr(),
                cert_store.as_ptr(),
            ))
        }
    }

    /// Like [`SslContextBuilder::set_custom_verify_callback`].
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_set_custom_verify)]
    pub fn set_custom_verify_callback<F>(
        &mut self,
        mode: SslVerifyMode,
        callback: F,
    ) -> Result<(), ErrorStack>
    where
        F: Fn(&mut Self) -> Result<(), SslVerifyError> + 'static + Sync + Send,
    {
        self.require_verification_config()?;
        self.set_ex_data(
            SSL_CUSTOM_VERIFY_INDEX.register()?,
            Some(Arc::new(callback)),
        )?;
        // SAFETY: the live SSL owns the installed callback state and config.
        unsafe {
            ffi::SSL_set_custom_verify(
                self.as_ptr(),
                c_int::from(mode.bits()),
                Some(ssl_raw_custom_verify),
            );
        }
        async_callbacks::cancel_custom_verify_future(self);
        Ok(())
    }

    /// Removes the inherited or connection-specific custom TLS verifier and
    /// sets the mode. Native verification, including configured X.509 callbacks,
    /// is used instead. Any pending asynchronous custom verification is discarded.
    /// # Errors
    /// The connection configuration is unavailable.
    #[corresponds(SSL_set_custom_verify)]
    pub fn clear_custom_verify_callback(&mut self, mode: SslVerifyMode) -> Result<(), ErrorStack> {
        self.require_verification_config()?;
        // SAFETY: exclusive live SSL with configuration; null clears the callback.
        unsafe { ffi::SSL_set_custom_verify(self.as_ptr(), c_int::from(mode.bits()), None) };
        if let Some(index) = SSL_CUSTOM_VERIFY_INDEX.get()
            && let Some(data) = self.ex_data_mut(index)
        {
            *data = None;
        }
        async_callbacks::cancel_custom_verify_future(self);
        Ok(())
    }

    /// Configures whether ClientHello extensions should be permuted.
    #[corresponds(SSL_set_permute_extensions)]
    pub fn set_permute_extensions(&mut self, enabled: bool) {
        // SAFETY: The uniquely borrowed SSL connection receives
        // a scalar extension-permutation flag.
        unsafe { ffi::SSL_set_permute_extensions(self.as_ptr(), c_int::from(enabled)) }
    }

    /// Sets the [RFC 8449] record size limit for this connection only.
    ///
    /// See [`SslContextBuilder::set_record_size_limit`]. A server may still call
    /// this from [`SslContextBuilder::set_select_certificate_callback`]. The
    /// servername callback is too late, and [`SslRef::set_ssl_context`] does not
    /// change the limit.
    ///
    /// [RFC 8449]: https://www.rfc-editor.org/rfc/rfc8449
    #[cfg(not(feature = "fips"))]
    #[corresponds(SSL_set_record_size_limit)]
    pub fn set_record_size_limit(&mut self, limit: u16) {
        // SAFETY: The native connection is exclusively borrowed
        // while BoringSSL installs its scalar record-size setting.
        unsafe { ffi::SSL_set_record_size_limit(self.as_ptr(), limit as _) }
    }

    /// Like [`SslContextBuilder::set_alpn_protos`].
    ///
    /// [`SslContextBuilder::set_alpn_protos`]: struct.SslContextBuilder.html#method.set_alpn_protos
    #[corresponds(SSL_set_alpn_protos)]
    pub fn set_alpn_protos(&mut self, protocols: &[u8]) -> Result<(), ErrorStack> {
        // SAFETY: The native setter borrows the wire-format ALPN bytes
        // only for this synchronous call; the length is checked before conversion.
        unsafe {
            let r = ffi::SSL_set_alpn_protos(
                self.as_ptr(),
                protocols.as_ptr(),
                try_int(protocols.len())?,
            );
            // fun fact, SSL_set_alpn_protos has a reversed return code D:
            if r == 0 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// Returns the stack of available SslCiphers for `SSL`, sorted by preference.
    #[corresponds(SSL_get_ciphers)]
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn ciphers(&self) -> &StackRef<SslCipher> {
        // SAFETY: The live connection owns the returned cipher stack;
        // the wrapper only borrows it while that connection remains live.
        unsafe {
            let cipher_list = ffi::SSL_get_ciphers(self.as_ptr());
            StackRef::from_ptr(cipher_list)
        }
    }

    /// Returns the current cipher if the session is active.
    #[corresponds(SSL_get_current_cipher)]
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn current_cipher(&self) -> Option<&SslCipherRef> {
        // SAFETY: The live connection owns the optional negotiated
        // cipher pointer, and null is checked before returning a shared ref.
        unsafe {
            let ptr = ffi::SSL_get_current_cipher(self.as_ptr());

            if ptr.is_null() {
                None
            } else {
                Some(SslCipherRef::from_ptr(ptr.cast_mut()))
            }
        }
    }

    /// Returns the signature algorithm used by the peer in the most recent TLS handshake,
    /// or `None` if no signature was produced (e.g. session resumption).
    #[corresponds(SSL_get_peer_signature_algorithm)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn peer_signature_algorithm(&self) -> Option<SslSignatureAlgorithm> {
        // SAFETY: The live SSL connection writes the
        // peer signature-algorithm code to an initialized local output slot.
        let sigalg = unsafe { ffi::SSL_get_peer_signature_algorithm(self.as_ptr()) };
        if sigalg == 0 {
            None
        } else {
            Some(SslSignatureAlgorithm(sigalg))
        }
    }

    /// Returns whether the peer authenticated with an [RFC 9345] delegated
    /// credential in the most recent handshake.
    ///
    /// Read this after a successful handshake. The value becomes `true` once
    /// the credential and the peer's CertificateVerify signature have both
    /// been validated; it does not by itself indicate handshake completion.
    ///
    /// Returns `false` for session resumption, even if the original session
    /// was authenticated with a delegated credential.
    ///
    /// [RFC 9345]: https://www.rfc-editor.org/rfc/rfc9345
    #[cfg(not(feature = "fips"))]
    #[corresponds(SSL_used_delegated_credential)]
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn used_delegated_credential(&self) -> bool {
        // SAFETY: The live SSL connection returns a scalar
        // negotiated-credential flag; no pointer is retained.
        unsafe { ffi::SSL_used_delegated_credential(self.as_ptr()) != 0 }
    }

    /// Returns the signature algorithm this side used to sign the current TLS handshake,
    /// or `None` if not applicable.
    ///
    /// BoringSSL only retains this value during the handshake; to observe it post-handshake,
    /// capture it from an [`SslContextBuilder::set_info_callback`] handler at
    /// [`SslInfoCallbackMode::HANDSHAKE_DONE`].
    #[corresponds(SSL_get_signature_algorithm_used)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn signature_algorithm_used(&self) -> Option<SslSignatureAlgorithm> {
        // SAFETY: The live SSL connection writes an
        // optional signature code to a local output slot for this handshake.
        let sigalg = unsafe { ffi::SSL_get_signature_algorithm_used(self.as_ptr()) };
        if sigalg == 0 {
            None
        } else {
            Some(SslSignatureAlgorithm(sigalg))
        }
    }

    /// Returns a short string describing the state of the session.
    ///
    /// Returns empty string if the state wasn't valid UTF-8.
    #[corresponds(SSL_state_string)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn state_string(&self) -> &'static str {
        // SAFETY: The live SSL object provides a static native state string;
        // the Rust wrapper handles its native C-string representation.
        let state = unsafe {
            let ptr = ffi::SSL_state_string(self.as_ptr());
            CStr::from_ptr(ptr)
        };

        state.to_str().unwrap_or_default()
    }

    /// Returns a longer string describing the state of the session.
    ///
    /// Returns empty string if the state wasn't valid UTF-8.
    #[corresponds(SSL_state_string_long)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn state_string_long(&self) -> &'static str {
        // SAFETY: The live SSL object provides a static native state
        // string; the wrapper handles its native C-string representation.
        let state = unsafe {
            let ptr = ffi::SSL_state_string_long(self.as_ptr());
            CStr::from_ptr(ptr)
        };

        state.to_str().unwrap_or_default()
    }

    /// Sets the host name to be sent to the server for Server Name Indication (SNI).
    ///
    /// It has no effect for a server-side connection.
    #[corresponds(SSL_set_tlsext_host_name)]
    pub fn set_hostname(&mut self, hostname: &str) -> Result<(), ErrorStack> {
        let cstr = CString::new(hostname).map_err(ErrorStack::internal_error)?;
        // SAFETY: The checked NUL-terminated SNI value stays live
        // while the uniquely borrowed SSL connection copies its hostname.
        unsafe { cvt(ffi::SSL_set_tlsext_host_name(self.as_ptr(), cstr.as_ptr())) }
    }

    /// Returns the peer's certificate, if present.
    #[corresponds(SSL_get_peer_certificate)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn peer_certificate(&self) -> Option<X509> {
        if !self.ssl_context().has_x509_support() {
            return None;
        }

        // SAFETY: The live connection returns an owned certificate
        // reference or null; null is checked before Rust assumes ownership.
        unsafe {
            let ptr = ffi::SSL_get_peer_certificate(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(X509::from_ptr(ptr))
            }
        }
    }

    /// Returns the certificate chain of the peer, if present.
    ///
    /// On the client side, the chain includes the leaf certificate, but on the server side it does
    /// not. Fun!
    #[corresponds(SSL_get_peer_cert_chain)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn peer_cert_chain(&self) -> Option<&StackRef<X509>> {
        if !self.ssl_context().has_x509_support() {
            return None;
        }

        // SAFETY: The live connection owns the peer chain; the
        // borrowed stack pointer is checked for null before use.
        unsafe {
            let ptr = ffi::SSL_get_peer_cert_chain(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(StackRef::from_ptr(ptr))
            }
        }
    }

    /// Like [`SslContext::certificate`].
    #[corresponds(SSL_get_certificate)]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn certificate(&self) -> Option<&X509Ref> {
        if !self.ssl_context().has_x509_support() {
            return None;
        }

        // SAFETY: The live SSL connection owns the installed
        // certificate; a nullable borrowed pointer is checked before dereference.
        unsafe {
            let ptr = ffi::SSL_get_certificate(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(X509Ref::from_ptr(ptr))
            }
        }
    }

    /// Like [`SslContext::private_key`].
    #[corresponds(SSL_get_privatekey)]
    #[must_use = "The returned key component is the result of this accessor."]
    pub fn private_key(&self) -> Option<&PKeyRef<Private>> {
        // SAFETY: The live SSL connection owns the installed key;
        // a nullable borrowed pointer is checked before dereference.
        unsafe {
            let ptr = ffi::SSL_get_privatekey(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(PKeyRef::from_ptr(ptr))
            }
        }
    }

    #[deprecated(since = "0.10.5", note = "renamed to `version_str`")]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn version(&self) -> Option<&str> {
        self.version_str()
    }

    /// Returns the protocol version of the session.
    #[corresponds(SSL_version)]
    pub fn version2(&self) -> Option<SslVersion> {
        // SAFETY: The native getter reports a negotiated scalar version
        // from the live SSL connection; unsupported values are rejected.
        unsafe {
            let r = ffi::SSL_version(self.as_ptr());
            if r == 0 {
                None
            } else {
                r.try_into().ok().map(SslVersion)
            }
        }
    }

    /// Returns the negotiated protocol version name, if native metadata is
    /// present and valid UTF-8. Use [`Self::version2`] for its numeric form.
    #[corresponds(SSL_get_version)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn version_str(&self) -> Option<&'static str> {
        // SAFETY: a non-null native string has static storage while BoringSSL
        // is initialized; it is checked for UTF-8 validity before returning.
        unsafe {
            let ptr = ffi::SSL_get_version(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                CStr::from_ptr(ptr).to_str().ok()
            }
        }
    }

    /// Sets the minimum supported protocol version.
    ///
    /// If version is `None`, the default minimum version is used. For BoringSSL this defaults to
    /// TLS 1.0.
    #[corresponds(SSL_set_min_proto_version)]
    pub fn set_min_proto_version(&mut self, version: Option<SslVersion>) -> Result<(), ErrorStack> {
        // SAFETY: The uniquely borrowed native connection accepts
        // a scalar protocol version, zero for the native default.
        unsafe {
            cvt(ffi::SSL_set_min_proto_version(
                self.as_ptr(),
                version.map_or(0, |v| v.0 as _),
            ))
        }
    }

    /// Sets the maximum supported protocol version.
    ///
    /// If version is `None`, the default maximum version is used. For BoringSSL this is TLS 1.3.
    #[corresponds(SSL_set_max_proto_version)]
    pub fn set_max_proto_version(&mut self, version: Option<SslVersion>) -> Result<(), ErrorStack> {
        // SAFETY: The uniquely borrowed native connection accepts
        // a scalar protocol version, zero for the native default.
        unsafe {
            cvt(ffi::SSL_set_max_proto_version(
                self.as_ptr(),
                version.map_or(0, |v| v.0 as _),
            ))
        }
    }

    /// Gets the minimum supported protocol version.
    #[corresponds(SSL_get_min_proto_version)]
    pub fn min_proto_version(&mut self) -> Option<SslVersion> {
        // SAFETY: The getter reads a scalar protocol version
        // from the live SSL connection; zero means native default.
        unsafe {
            let r = ffi::SSL_get_min_proto_version(self.as_ptr());
            if r == 0 { None } else { Some(SslVersion(r)) }
        }
    }

    /// Gets the maximum supported protocol version.
    #[corresponds(SSL_get_max_proto_version)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn max_proto_version(&self) -> Option<SslVersion> {
        // SAFETY: The getter reads a scalar protocol version
        // from the live SSL connection; zero means native default.
        let r = unsafe { ffi::SSL_get_max_proto_version(self.as_ptr()) };
        if r == 0 { None } else { Some(SslVersion(r)) }
    }

    /// Returns the protocol selected via Application Layer Protocol Negotiation (ALPN).
    ///
    /// The protocol's name is returned is an opaque sequence of bytes. It is up to the client
    /// to interpret it.
    #[corresponds(SSL_get0_alpn_selected)]
    #[must_use = "Use the negotiated protocol to dispatch the application connection."]
    pub fn selected_alpn_protocol(&self) -> Option<&[u8]> {
        // SAFETY: The live SSL connection owns the selected ALPN
        // bytes, with writable local output slots and a nullable pointer.
        unsafe {
            let mut data: *const c_uchar = ptr::null();
            let mut len: c_uint = 0;
            // Get the negotiated protocol from the SSL instance.
            // `data` will point at a `c_uchar` array; `len` will contain the length of this array.
            ffi::SSL_get0_alpn_selected(self.as_ptr(), &raw mut data, &raw mut len);

            if data.is_null() {
                None
            } else {
                // SAFETY: ALPN output is borrowed from the live handshake.
                native_input(data, len as usize)
            }
        }
    }

    /// Returns the peer's ALPS (application-layer protocol settings) value, or `None` if ALPS
    /// was not negotiated.
    ///
    /// The value may be empty. It is available once the handshake has negotiated ALPS.
    #[corresponds(SSL_get0_peer_application_settings)]
    #[must_use = "Inspect any application settings negotiated by the peer."]
    pub fn peer_application_settings(&self) -> Option<&[u8]> {
        // SAFETY: The native query reads an ALPS negotiation
        // flag from this live SSL connection before fetching its data.
        unsafe {
            if ffi::SSL_has_application_settings(self.as_ptr()) == 0 {
                return None;
            }
            let mut data = ptr::null();
            let mut len = 0;
            ffi::SSL_get0_peer_application_settings(self.as_ptr(), &raw mut data, &raw mut len);
            // SAFETY: negotiated ALPS output is borrowed from this live SSL
            // connection. An empty negotiated value may have a null pointer.
            native_input(data, len)
        }
    }

    /// Enables the DTLS extension "use_srtp" as defined in RFC5764.
    #[corresponds(SSL_set_tlsext_use_srtp)]
    pub fn set_tlsext_use_srtp(&mut self, protocols: &str) -> Result<(), ErrorStack> {
        // SAFETY: The NUL-terminated SRTP profile list stays live
        // while this uniquely borrowed connection installs its configuration.
        unsafe {
            let cstr = CString::new(protocols).map_err(ErrorStack::internal_error)?;

            let r = ffi::SSL_set_tlsext_use_srtp(self.as_ptr(), cstr.as_ptr());
            // fun fact, set_tlsext_use_srtp has a reversed return code D:
            if r == 0 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// Gets all SRTP profiles that are enabled for handshake via set_tlsext_use_srtp
    ///
    /// DTLS extension "use_srtp" as defined in RFC5764 has to be enabled.
    #[corresponds(SSL_get_strp_profiles)]
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn srtp_profiles(&self) -> Option<&StackRef<SrtpProtectionProfile>> {
        // SAFETY: The SSL connection owns the optional native
        // SRTP profile stack, checked for null before exposing a reference.
        unsafe {
            let chain = ffi::SSL_get_srtp_profiles(self.as_ptr());

            if chain.is_null() {
                None
            } else {
                Some(StackRef::from_ptr(chain.cast_mut()))
            }
        }
    }

    /// Gets the SRTP profile selected by handshake.
    ///
    /// DTLS extension "use_srtp" as defined in RFC5764 has to be enabled.
    #[corresponds(SSL_get_selected_srtp_profile)]
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn selected_srtp_profile(&self) -> Option<&SrtpProtectionProfileRef> {
        // SAFETY: The live SSL connection owns the optional
        // negotiated SRTP descriptor, checked for null before borrowing.
        unsafe {
            let profile = ffi::SSL_get_selected_srtp_profile(self.as_ptr());

            if profile.is_null() {
                None
            } else {
                Some(SrtpProtectionProfileRef::from_ptr(profile.cast_mut()))
            }
        }
    }

    /// Returns the number of bytes remaining in the currently processed TLS record.
    ///
    /// If this is greater than 0, the next call to `read` will not call down to the underlying
    /// stream.
    #[corresponds(SSL_pending)]
    #[must_use = "Use the returned length or capacity to size buffers or validate input."]
    pub fn pending(&self) -> usize {
        // SAFETY: the native getter reads pending plaintext bytes from a live
        // SSL connection. Negative values cannot represent pending bytes.
        usize::try_from(unsafe { ffi::SSL_pending(self.as_ptr()) }).unwrap_or(0)
    }

    /// Returns the servername sent by the client via Server Name Indication (SNI).
    ///
    /// It is only useful on the server side.
    ///
    /// # Note
    ///
    /// While the SNI specification requires that servernames be valid domain names (and therefore
    /// ASCII), OpenSSL does not enforce this restriction. If the servername provided by the client
    /// is not valid UTF-8, this function will return `None`. The `servername_raw` method returns
    /// the raw bytes and does not have this restriction.
    ///
    // FIXME maybe rethink in 0.11?
    #[corresponds(SSL_get_servername)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn servername(&self, type_: NameType) -> Option<&str> {
        self.servername_raw(type_)
            .and_then(|b| str::from_utf8(b).ok())
    }

    /// Returns the servername sent by the client via Server Name Indication (SNI).
    ///
    /// It is only useful on the server side.
    ///
    /// # Note
    ///
    /// Unlike `servername`, this method does not require the name be valid UTF-8.
    #[corresponds(SSL_get_servername)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn servername_raw(&self, type_: NameType) -> Option<&[u8]> {
        // SAFETY: The live connection owns its optional
        // NUL-terminated SNI buffer, checked for null before reading.
        unsafe {
            let name = ffi::SSL_get_servername(self.as_ptr(), type_.0);
            if name.is_null() {
                None
            } else {
                Some(CStr::from_ptr(name).to_bytes())
            }
        }
    }

    /// Changes the context corresponding to the current connection.
    ///
    /// It is most commonly used in the Server Name Indication (SNI) callback.
    #[corresponds(SSL_set_SSL_CTX)]
    pub fn set_ssl_context(&mut self, ctx: &SslContextRef) -> Result<(), ErrorStack> {
        if self.ssl_context().has_x509_support() != ctx.has_x509_support() {
            return Err(ErrorStack::internal_error_str(
                "X.509 certificate support in old and new contexts doesn't match",
            ));
        }

        // SAFETY: the borrowed new context is live during reconfiguration;
        // BoringSSL retains its context reference and replaces certificate settings.
        unsafe { cvt_p(ffi::SSL_set_SSL_CTX(self.as_ptr(), ctx.as_ptr())).map(|_| ()) }
    }

    /// Returns the context corresponding to the current connection.
    #[corresponds(SSL_get_SSL_CTX)]
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn ssl_context(&self) -> &SslContextRef {
        // SAFETY: Every live SSL connection retains its current context;
        // this native getter returns the borrowed context pointer.
        unsafe {
            let ssl_ctx = ffi::SSL_get_SSL_CTX(self.as_ptr());
            SslContextRef::from_ptr(ssl_ctx)
        }
    }

    /// Returns a mutable reference to the X509 verification configuration.
    ///
    /// # Errors
    /// The context does not support X.509 certificates.
    #[corresponds(SSL_get0_param)]
    pub fn verify_param_mut(&mut self) -> Result<&mut X509VerifyParamRef, ErrorStack> {
        self.ssl_context().check_x509()?;

        // SAFETY: The X.509-enabled SSL object owns this native verification
        // parameter; the exclusive Rust borrow permits mutable access.
        unsafe {
            cvt_p(ffi::SSL_get0_param(self.as_ptr()))
                .map(|param| X509VerifyParamRef::from_ptr_mut(param))
        }
    }

    /// Returns the certificate verification result.
    ///
    /// # Errors
    /// A connection without X.509 support returns [`X509VerifyError::INVALID_CALL`].
    /// Otherwise, returns the native certificate verification error, if any.
    #[corresponds(SSL_get_verify_result)]
    pub fn verify_result(&self) -> X509VerifyResult {
        if !self.ssl_context().has_x509_support() {
            return Err(X509VerifyError::INVALID_CALL);
        }

        // SAFETY: the live X.509 connection supplies a native verification
        // result. Reject out-of-range codes instead of truncating them.
        let raw = unsafe { ffi::SSL_get_verify_result(self.as_ptr()) };
        let code = c_int::try_from(raw).map_err(|_| X509VerifyError::UNSPECIFIED)?;
        // SAFETY: from_raw maps a checked scalar native result to the Rust
        // verification enum without retaining or dereferencing pointers.
        unsafe { X509VerifyError::from_raw(code) }
    }

    /// Runs BoringSSL's built-in X.509 verifier on the current peer chain.
    ///
    /// Call it from [`SslContextBuilder::set_custom_verify_callback`] to keep the built-in checks,
    /// including when [`SslContextBuilder::set_reverify_on_resume`] is enabled. It uses the actual
    /// native verify store, connection parameters, ECH name override and X.509 verification
    /// callbacks. It does not call the custom TLS verifier recursively or modify the cached session.
    /// Unlike implicit handshake verification, this explicit check is strict even with
    /// [`SslVerifyMode::NONE`]. A mutable borrow excludes recursive invocation from X.509 callbacks,
    /// which receive only a shared SSL reference through [`X509StoreContextRef::ssl`].
    ///
    /// On a full handshake BoringSSL reports a rejection through [`Self::verify_result`] as
    /// [`X509VerifyError::APPLICATION_VERIFICATION`]; a rejected resumption fails with
    /// `CERTIFICATE_VERIFY_FAILED` and keeps the resumed session's result.
    ///
    /// # Errors
    /// The peer chain or connection configuration is unavailable, or verification fails.
    #[corresponds(SSL_verify_peer_cert_chain)]
    pub fn verify_peer_cert_chain(&mut self) -> X509VerifyResult {
        // SAFETY: exclusive access to the live SSL permits invoking its X.509
        // verification callbacks. The native verifier checks the configuration
        // and peer chain before using either, and leaves the session immutable.
        let raw = unsafe { ffi::SSL_verify_peer_cert_chain(self.as_ptr()) };
        let code = c_int::try_from(raw).map_err(|_| X509VerifyError::UNSPECIFIED)?;
        // SAFETY: the checked native result is a scalar X.509 verification code.
        unsafe { X509VerifyError::from_raw(code) }
    }

    /// Returns a shared reference to the SSL session.
    #[corresponds(SSL_get_session)]
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn session(&self) -> Option<&SslSessionRef> {
        // SAFETY: The live SSL connection owns an optional session;
        // the getter returns a borrowed pointer checked for null.
        unsafe {
            let p = ffi::SSL_get_session(self.as_ptr());
            if p.is_null() {
                None
            } else {
                Some(SslSessionRef::from_ptr(p))
            }
        }
    }

    /// Copies the client_random value sent by the client in the TLS handshake into a buffer.
    ///
    /// Returns the number of bytes copied, or if the buffer is empty, the size of the client_random
    /// value.
    #[corresponds(SSL_get_client_random)]
    pub fn client_random(&self, buf: &mut [u8]) -> usize {
        // SAFETY: The caller supplies a writable buffer and its full
        // native size_t length; the live SSL connection copies its random bytes.
        unsafe { ffi::SSL_get_client_random(self.as_ptr(), buf.as_mut_ptr(), buf.len()) }
    }

    /// Copies the server_random value sent by the server in the TLS handshake into a buffer.
    ///
    /// Returns the number of bytes copied, or if the buffer is empty, the size of the server_random
    /// value.
    #[corresponds(SSL_get_server_random)]
    pub fn server_random(&self, buf: &mut [u8]) -> usize {
        // SAFETY: The caller supplies a writable buffer and its full
        // native size_t length; the live SSL connection copies its random bytes.
        unsafe { ffi::SSL_get_server_random(self.as_ptr(), buf.as_mut_ptr(), buf.len()) }
    }

    /// Derives keying material for application use in accordance to RFC 5705.
    #[corresponds(SSL_export_keying_material)]
    pub fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &str,
        context: Option<&[u8]>,
    ) -> Result<(), ErrorStack> {
        // SAFETY: The output and optional context buffers
        // stay valid for their supplied native lengths; the live connection
        // only borrows them during derivation.
        unsafe {
            let (context, contextlen, use_context) = context
                .map_or((ptr::null(), 0, 0), |context| {
                    (context.as_ptr(), context.len(), 1)
                });
            cvt(ffi::SSL_export_keying_material(
                self.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
                label.as_ptr().cast::<c_char>(),
                label.len(),
                context,
                contextlen,
                use_context,
            ))
        }
    }

    /// Sets the session to be used.
    ///
    /// This should be called before the handshake to attempt to reuse a previously established
    /// session. If the server is not willing to reuse the session, a new one will be transparently
    /// negotiated.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    ///
    /// - the handshake has not started;
    /// - the session authenticates the intended peer under the current verification and client
    ///   authentication policies; and
    /// - the session ID context, protocol, and cipher configuration are compatible.
    ///
    /// [`ConnectConfiguration::set_client_session`] is a checked alternative for sessions from
    /// [`SslConnectorBuilder::set_client_session_callback`].
    #[corresponds(SSL_set_session)]
    pub unsafe fn set_session(&mut self, session: &SslSessionRef) -> Result<(), ErrorStack> {
        // SAFETY: The unsafe caller establishes the session identity
        // and handshake preconditions; both native handles remain valid
        // while the connection acquires its session reference.
        unsafe { cvt(ffi::SSL_set_session(self.as_ptr(), session.as_ptr())) }
    }

    /// Returns the session ID context new sessions on this connection will record.
    #[corresponds(SSL_get0_session_id_context)]
    fn session_id_context(&self) -> Option<&[u8]> {
        // SAFETY: The native SSL owns its optional ID-context
        // bytes, and local length and pointer slots remain writable until return.
        unsafe {
            let mut len = 0;
            let p = ffi::SSL_get0_session_id_context(self.as_ptr(), &raw mut len);
            if p.is_null() {
                None
            } else {
                // SAFETY: this ID context is owned by the live native SSL
                // object and is borrowed only for the connection lifetime.
                native_input(p, len)
            }
        }
    }

    /// Determines if the session provided to `set_session` was successfully reused.
    #[corresponds(SSL_session_reused)]
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn session_reused(&self) -> bool {
        // SAFETY: The native getter reads a scalar resumption status
        // from the live SSL connection.
        unsafe { ffi::SSL_session_reused(self.as_ptr()) != 0 }
    }

    /// Sets the status response a client wishes the server to reply with.
    #[corresponds(SSL_set_tlsext_status_type)]
    pub fn set_status_type(&mut self, type_: StatusType) -> Result<(), ErrorStack> {
        // SAFETY: The uniquely borrowed connection receives
        // an integer OCSP status-request setting.
        unsafe {
            cvt(ffi::SSL_set_tlsext_status_type(
                self.as_ptr(),
                type_.as_raw(),
            ))
        }
    }

    /// Returns the server's OCSP response, if present.
    #[corresponds(SSL_get_tlsext_status_ocsp_resp)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn ocsp_status(&self) -> Option<&[u8]> {
        // SAFETY: The native getter supplies an optional
        // connection-owned OCSP buffer and writes its pointer into a local slot.
        unsafe {
            let mut p = ptr::null();
            let len = ffi::SSL_get_tlsext_status_ocsp_resp(self.as_ptr(), &raw mut p);

            if len == 0 {
                None
            } else {
                // SAFETY: positive-length OCSP output belongs to this SSL
                // connection; a malformed null/length pair is rejected.
                native_input(p, len)
            }
        }
    }

    /// Sets the OCSP response to be returned to the client.
    ///
    /// # Errors
    ///
    /// The native connection cannot copy the supplied response.
    #[corresponds(SSL_set_ocsp_response)]
    pub fn set_ocsp_status(&mut self, response: &[u8]) -> Result<(), ErrorStack> {
        // SAFETY: BoringSSL takes a borrowed `size_t`-length byte slice and
        // copies it synchronously; the live SSL connection is uniquely borrowed.
        unsafe {
            cvt(ffi::SSL_set_ocsp_response(
                self.as_ptr(),
                response.as_ptr(),
                response.len(),
            ))
        }
    }

    /// Determines if this `Ssl` is configured for server-side or client-side use.
    #[corresponds(SSL_is_server)]
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn is_server(&self) -> bool {
        // SAFETY: The live connection exposes its client/server role as a native
        // scalar and no memory is borrowed beyond this synchronous call.
        unsafe { SSL_is_server(self.as_ptr()) != 0 }
    }

    /// Sets or overwrites the extra data at a registered index.
    ///
    /// # Errors
    ///
    /// The native SSL cannot allocate storage for the index.
    pub fn set_ex_data<T: 'static + Send + Sync>(
        &mut self,
        index: Index<Ssl, T>,
        data: T,
    ) -> Result<(), ErrorStack> {
        drop(self.replace_ex_data(index, data)?);
        Ok(())
    }

    /// Replaces the extra data and returns the previous owned value, if any.
    ///
    /// # Errors
    ///
    /// The native SSL cannot allocate storage for the index.
    #[corresponds(SSL_set_ex_data)]
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "native ex-data replacement mutates the uniquely borrowed SSL object"
    )]
    pub fn replace_ex_data<T: 'static + Send + Sync>(
        &mut self,
        index: Index<Ssl, T>,
        data: T,
    ) -> Result<Option<T>, ErrorStack> {
        let ssl = self.as_ptr();
        // SAFETY: self establishes exclusive SSL access and the registered
        // index establishes the type of its boxed allocation.
        unsafe {
            replace_boxed(ffi::SSL_get_ex_data(ssl, index.as_raw()), data, |ptr| {
                cvt(ffi::SSL_set_ex_data(ssl, index.as_raw(), ptr))
            })
        }
    }

    /// Returns a reference to registered application data.
    #[corresponds(SSL_get_ex_data)]
    #[must_use = "Use the returned application data, or handle an empty slot."]
    pub fn ex_data<T: 'static + Send + Sync>(&self, index: Index<Ssl, T>) -> Option<&T> {
        // SAFETY: the registered typed index identifies a live boxed T.
        unsafe {
            ffi::SSL_get_ex_data(self.as_ptr(), index.as_raw())
                .cast::<T>()
                .as_ref()
        }
    }

    /// Returns a mutable reference to registered application data.
    #[corresponds(SSL_get_ex_data)]
    pub fn ex_data_mut<T: 'static + Send + Sync>(
        &mut self,
        index: Index<Ssl, T>,
    ) -> Option<&mut T> {
        // SAFETY: the typed index identifies the boxed allocation, and the
        // exclusive SSL borrow prevents a concurrent mutable access.
        unsafe {
            ffi::SSL_get_ex_data(self.as_ptr(), index.as_raw())
                .cast::<T>()
                .as_mut()
        }
    }

    fn slot_data<T: 'static + Send + Sync>(&self, slot: &IndexSlot<Ssl, T>) -> Option<&T> {
        self.ex_data(slot.get()?)
    }

    #[cfg(not(feature = "fips"))]
    fn callback<T: 'static + Send + Sync>(&self, role: CallbackRole) -> Option<&T> {
        self.ex_data(SSL_CALLBACKS.get(role)?)
    }

    fn session_context(&self) -> Option<&SslContextRef> {
        self.slot_data(&SESSION_CTX_INDEX).map(|owner| &**owner)
    }

    /// Copies the contents of the last Finished message sent to the peer into the provided buffer.
    ///
    /// The total size of the message is returned, so this can be used to determine the size of the
    /// buffer required.
    #[corresponds(SSL_get_finished)]
    pub fn finished(&self, buf: &mut [u8]) -> usize {
        // SAFETY: The live connection copies the finished message into
        // a writable output slice whose length is supplied exactly.
        unsafe { ffi::SSL_get_finished(self.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) }
    }

    /// Copies the contents of the last Finished message received from the peer into the provided
    /// buffer.
    ///
    /// The total size of the message is returned, so this can be used to determine the size of the
    /// buffer required.
    #[corresponds(SSL_get_peer_finished)]
    pub fn peer_finished(&self, buf: &mut [u8]) -> usize {
        // SAFETY: The live connection copies the peer finished message
        // into a writable output slice whose length is supplied exactly.
        unsafe { ffi::SSL_get_peer_finished(self.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) }
    }

    /// Determines if the initial handshake has been completed.
    #[corresponds(SSL_is_init_finished)]
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn is_init_finished(&self) -> bool {
        // SAFETY: The live native connection returns a scalar
        // handshake-completion status.
        unsafe { ffi::SSL_is_init_finished(self.as_ptr()) != 0 }
    }

    /// Sets the MTU used for DTLS connections.
    #[corresponds(SSL_set_mtu)]
    pub fn set_mtu(&mut self, mtu: u32) -> Result<(), ErrorStack> {
        // SAFETY: This uniquely borrowed DTLS connection accepts a native
        // unsigned MTU scalar without retaining Rust memory.
        unsafe { cvt(ffi::SSL_set_mtu(self.as_ptr(), mtu as c_uint)) }
    }

    /// Sets the maximum plaintext fragment length for TLS records sent by this connection.
    ///
    /// Handshake messages and application data are split into smaller records when needed.
    /// Values are clamped to `512..=16_384` bytes; the default is `16_384`.
    /// This is a local sending limit and does not negotiate a record-size limit with the peer.
    /// DTLS handshake fragmentation is controlled by [`set_mtu`](Self::set_mtu) instead.
    #[corresponds(SSL_set_max_send_fragment)]
    pub fn set_max_send_fragment(&mut self, max_send_fragment: usize) -> Result<(), ErrorStack> {
        // SAFETY: `self` holds a live SSL object; BoringSSL clamps the fragment length.
        unsafe {
            cvt(ffi::SSL_set_max_send_fragment(
                self.as_ptr(),
                max_send_fragment,
            ))
        }
    }

    /// Returns the limits for sealing application data now, or `None` if writes must go
    /// through [`SslStream::ssl_write`].
    ///
    /// Always `None` in FIPS builds, which lack the BoringSSL patch.
    #[corresponds(SSL_seal_app_data_limits)]
    #[must_use = "Use the returned limits when allocating and framing TLS record buffers."]
    pub fn seal_app_data_limits(&self) -> Option<SealLimits> {
        #[cfg(not(feature = "fips"))]
        {
            let (mut max_fragment, mut record_overhead, mut pending_len) = (0, 0, 0);
            // SAFETY: `self` is a live `SSL`, and the out-pointers are valid for writes.
            let ok = unsafe {
                ffi::SSL_seal_app_data_limits(
                    self.as_ptr(),
                    &raw mut max_fragment,
                    &raw mut record_overhead,
                    &raw mut pending_len,
                )
            };
            (ok == 1 && max_fragment > 0).then_some(SealLimits {
                max_fragment,
                record_overhead,
                pending_len,
            })
        }
        #[cfg(feature = "fips")]
        None
    }

    /// Seals up to `max_in` bytes of `bufs` as application data records at the start of `out`,
    /// without transport I/O.
    ///
    /// Returns `Ok(None)`, changing nothing, when writes must go through
    /// [`SslStream::ssl_write`] or `out` cannot hold the pending handshake records and the first
    /// record; [`seal_app_data_limits`](Self::seal_app_data_limits) tells which. Records ignore
    /// slice boundaries, and a success consumes at least one byte unless `max_in` is 0 or `bufs`
    /// holds no bytes. The first `written` bytes of `out` must reach the peer before anything the
    /// connection writes later, including a shutdown or an alert.
    #[corresponds(SSL_seal_app_data)]
    pub fn seal_app_data(
        &mut self,
        bufs: &[IoSlice<'_>],
        max_in: usize,
        out: &mut [MaybeUninit<u8>],
    ) -> Result<Option<Sealed>, ErrorStack> {
        #[cfg(not(feature = "fips"))]
        {
            use ffi::ssl_seal_app_data_result_t as R;

            let (mut written, mut consumed) = (0, 0);
            let res = with_ivecs(bufs, max_in, |ivecs| {
                // SAFETY: `self` is a live `SSL`. `ivecs` describe readable memory borrowed from
                // `bufs`, and `out` is valid for `out.len()` writes; the two cannot overlap
                // because `bufs` is borrowed shared while `out` is exclusive.
                unsafe {
                    ffi::SSL_seal_app_data(
                        self.as_ptr(),
                        out.as_mut_ptr().cast(),
                        &raw mut written,
                        out.len(),
                        ivecs.as_ptr(),
                        ivecs.len(),
                        max_in,
                        &raw mut consumed,
                    )
                }
            });
            match res {
                R::ssl_seal_app_data_success => {}
                R::ssl_seal_app_data_declined => return Ok(None),
                _ => return Err(ErrorStack::get()),
            }
            if written > out.len() || consumed > max_in {
                return Err(ErrorStack::internal_error_str(
                    "SSL_seal_app_data reported more than it was given",
                ));
            }
            Ok(Some(Sealed { consumed, written }))
        }
        #[cfg(feature = "fips")]
        {
            let _ = (bufs, max_in, out);
            Ok(None)
        }
    }

    /// Sets the certificate.
    #[corresponds(SSL_use_certificate)]
    pub fn set_certificate(&mut self, cert: &X509Ref) -> Result<(), ErrorStack> {
        // SAFETY: The certificate remains live until BoringSSL
        // retains its own reference in the exclusively borrowed connection.
        unsafe {
            cvt(ffi::SSL_use_certificate(self.as_ptr(), cert.as_ptr()))?;
        }

        Ok(())
    }

    /// Sets the list of CA names sent to the client.
    ///
    /// The CA certificates must still be added to the trust root - they are not automatically set
    /// as trusted by this method.
    ///
    /// # Errors
    /// The context does not support X.509 certificates.
    #[corresponds(SSL_set_client_CA_list)]
    pub fn set_client_ca_list(&mut self, list: Stack<X509Name>) -> Result<(), ErrorStack> {
        self.ssl_context().check_x509()?;

        // SAFETY: The connection takes ownership of the native
        // CA-name stack, and Rust relinquishes the original owner exactly once.
        unsafe { ffi::SSL_set_client_CA_list(self.as_ptr(), list.as_ptr()) }
        mem::forget(list);
        Ok(())
    }

    /// Sets the private key.
    #[corresponds(SSL_use_PrivateKey)]
    pub fn set_private_key<T>(&mut self, key: &PKeyRef<T>) -> Result<(), ErrorStack>
    where
        T: HasPrivate,
    {
        // SAFETY: The borrowed private key remains live while the native
        // connection acquires its own key reference.
        unsafe { cvt(ffi::SSL_use_PrivateKey(self.as_ptr(), key.as_ptr())) }
    }

    /// Enables all modes set in `mode` in `SSL`. Returns a bitmask representing the resulting
    /// enabled modes.
    #[corresponds(SSL_set_mode)]
    pub fn set_mode(&mut self, mode: SslMode) -> SslMode {
        // SAFETY: The live connection receives a native mode-bitset update
        // through an exclusive Rust borrow.
        let bits = unsafe { ffi::SSL_set_mode(self.as_ptr(), mode.bits()) };
        SslMode::from_bits_retain(bits)
    }

    /// Disables all modes set in `mode` in `SSL`. Returns a bitmask representing the resulting
    /// enabled modes.
    #[corresponds(SSL_clear_mode)]
    pub fn clear_mode(&mut self, mode: SslMode) -> SslMode {
        // SAFETY: The live connection receives a native mode-bitset update
        // through an exclusive Rust borrow.
        let bits = unsafe { ffi::SSL_clear_mode(self.as_ptr(), mode.bits()) };
        SslMode::from_bits_retain(bits)
    }

    /// Appends `cert` to the chain associated with the current certificate of `SSL`.
    #[corresponds(SSL_add1_chain_cert)]
    pub fn add_chain_cert(&mut self, cert: &X509Ref) -> Result<(), ErrorStack> {
        // SAFETY: The live connection borrows this certificate while
        // BoringSSL increments and stores its own reference.
        unsafe { cvt(ffi::SSL_add1_chain_cert(self.as_ptr(), cert.as_ptr())) }
    }

    /// Configures `ech_config_list` on `SSL` for offering ECH during handshakes. If the server
    /// cannot decrypt the encrypted ClientHello, `SSL` will instead handshake using
    /// the cleartext parameters of the ClientHelloOuter.
    ///
    /// Clients should use `get_ech_name_override` to verify the server certificate in case of ECH
    /// rejection, and follow up with `get_ech_retry_configs` to retry the connection with a fresh
    /// set of ECHConfigs. If the retry also fails, clients should report a connection failure.
    #[corresponds(SSL_set1_ech_config_list)]
    pub fn set_ech_config_list(&mut self, ech_config_list: &[u8]) -> Result<(), ErrorStack> {
        // SAFETY: The ECH-config byte slice stays live during
        // its synchronous native validation/copy into this SSL connection.
        unsafe {
            cvt_0i(ffi::SSL_set1_ech_config_list(
                self.as_ptr(),
                ech_config_list.as_ptr(),
                ech_config_list.len(),
            ))
            .map(|_| ())
        }
    }

    /// This function returns a serialized `ECHConfigList` as provided by the
    /// server, if one exists.
    ///
    /// Clients should call this function when handling an `SSL_R_ECH_REJECTED` error code to
    /// recover from potential key mismatches. If the result is `Some`, the client should retry the
    /// connection using the returned `ECHConfigList`.
    #[corresponds(SSL_get0_ech_retry_configs)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn get_ech_retry_configs(&self) -> Option<&[u8]> {
        // SAFETY: The live SSL connection owns its optional
        // ECH retry config and writes pointer and size to valid local slots.
        unsafe {
            let mut data = ptr::null();
            let mut len: usize = 0;
            ffi::SSL_get0_ech_retry_configs(self.as_ptr(), &raw mut data, &raw mut len);

            if data.is_null() {
                None
            } else {
                // SAFETY: the ECH retry bytes are owned by the live SSL
                // connection and stay immutable for the borrowed lifetime.
                native_input(data, len)
            }
        }
    }

    /// If `SSL` is a client and the server rejects ECH, this function returns the public name
    /// associated with the ECHConfig that was used to attempt ECH.
    ///
    /// Clients should call this function during the certificate verification callback to
    /// ensure the server's certificate is valid for the public name, which is required to
    /// authenticate retry configs.
    #[corresponds(SSL_get0_ech_name_override)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn get_ech_name_override(&self) -> Option<&[u8]> {
        // SAFETY: The live SSL connection owns its optional
        // ECH public-name bytes and writes pointer and size into local slots.
        unsafe {
            let mut data: *const c_char = ptr::null();
            let mut len: usize = 0;
            ffi::SSL_get0_ech_name_override(self.as_ptr(), &raw mut data, &raw mut len);

            if data.is_null() {
                None
            } else {
                // SAFETY: the ECH public-name byte buffer belongs to the
                // live native SSL connection and is not modified by this call.
                native_input(data.cast::<u8>(), len)
            }
        }
    }

    /// Whether or not `SSL` negotiated ECH.
    #[corresponds(SSL_ech_accepted)]
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn ech_accepted(&self) -> bool {
        // SAFETY: The native getter reads a scalar ECH status from
        // the live SSL connection.
        unsafe { ffi::SSL_ech_accepted(self.as_ptr()) != 0 }
    }

    /// Enables ECH GREASE when no supported ECH configuration is available.
    /// Set before the first ClientHello. This does not enable real ECH.
    #[corresponds(SSL_set_enable_ech_grease)]
    pub fn set_enable_ech_grease(&mut self, enable: bool) {
        let enable = c_int::from(enable);

        // SAFETY: The exclusively borrowed connection receives a scalar ECH
        // GREASE flag with no borrowed Rust data.
        unsafe {
            ffi::SSL_set_enable_ech_grease(self.as_ptr(), enable);
        }
    }

    /// Sets the compliance policy on `SSL`.
    #[corresponds(SSL_set_compliance_policy)]
    pub fn set_compliance_policy(&mut self, policy: CompliancePolicy) -> Result<(), ErrorStack> {
        // SAFETY: The live connection receives a scalar
        // policy value and no borrowed Rust data.
        unsafe { cvt_0i(ffi::SSL_set_compliance_policy(self.as_ptr(), policy.0)).map(|_| ()) }
    }

    /// Adds a credential.
    #[corresponds(SSL_add1_credential)]
    #[cfg(feature = "credential")]
    pub fn add_credential(&mut self, credential: &SslCredentialRef) -> Result<(), ErrorStack> {
        // SAFETY: The credential remains live while BoringSSL
        // retains its own reference for this connection.
        unsafe { cvt_0i(ffi::SSL_add1_credential(self.as_ptr(), credential.as_ptr())).map(|_| ()) }
    }

    /// Returns the public key sent by the other peer, `None` if there is no ongoing handshake.
    #[corresponds(SSL_get0_peer_pubkey)]
    #[cfg(feature = "rpk")]
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn peer_pubkey(&self) -> Option<&PKeyRef<Public>> {
        // SAFETY: The connection owns the optional peer key,
        // and the native borrowed pointer is checked for null before use.
        unsafe {
            let pubkey = ffi::SSL_get0_peer_pubkey(self.as_ptr());

            if pubkey.is_null() {
                return None;
            }

            Some(PKeyRef::from_ptr(pubkey.cast_mut()))
        }
    }

    /// Sets the list of server certificate types that this client will accept
    /// from the server.
    ///
    /// Only valid on a client-side `Ssl`; returns an error on server-side SSLs.
    #[corresponds(SSL_set1_accepted_peer_cert_types)]
    #[cfg(feature = "rpk")]
    pub fn set_server_certificate_types(
        &mut self,
        types: &[CertificateType],
    ) -> Result<(), ErrorStack> {
        if self.is_server() {
            return Err(ErrorStack::internal_error_str(
                "called set_server_certificate_types as server",
            ));
        }

        // SAFETY: The transparent u8
        // certificate-type values remain live until the connection copies them.
        unsafe {
            cvt_0i(ffi::SSL_set1_accepted_peer_cert_types(
                self.as_ptr(),
                types.as_ptr().cast::<u8>(),
                types.len(),
            ))
            .map(|_| ())
        }
    }

    /// Returns the list of server certificate types that this client will
    /// accept from the server, or `None` if none are configured.
    ///
    /// Only valid on a client-side `Ssl`; returns `None` on server-side SSLs.
    #[corresponds(SSL_get0_accepted_peer_cert_types)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    #[cfg(feature = "rpk")]
    pub fn server_certificate_types(&self) -> Option<&[CertificateType]> {
        if self.is_server() {
            return None;
        }

        let mut types = ptr::null();
        let mut types_len = 0;
        // SAFETY: The connection owns the
        // optional native certificate-type array and writes its pointer
        // and length into valid local output slots.
        unsafe {
            ffi::SSL_get0_accepted_peer_cert_types(
                self.as_ptr(),
                &raw mut types,
                &raw mut types_len,
            );

            if types_len == 0 {
                return None;
            }

            Some(slice::from_raw_parts(
                types.cast::<CertificateType>(),
                types_len,
            ))
        }
    }

    /// Returns the server certificate type selected by the server during the
    /// handshake.
    ///
    /// Only valid on a client-side `Ssl`; returns `None` on server-side SSLs
    /// (a server knows its own selected credential type by other means).
    #[corresponds(SSL_get_peer_cert_type)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    #[cfg(feature = "rpk")]
    pub fn selected_server_certificate_type(&self) -> Option<CertificateType> {
        if self.is_server() {
            return None;
        }

        // SAFETY: the live connection provides a scalar peer certificate-type
        // code. Reject missing, negative or out-of-range native values.
        let code = unsafe { ffi::SSL_get_peer_cert_type(self.as_ptr()) };
        u8::try_from(code).ok().map(CertificateType)
    }

    /// Sets the client key shares to be used in the TLS 1.3 handshake.
    #[corresponds(SSL_set1_client_key_shares)]
    pub fn set_client_key_shares(&mut self, key_shares: &[KeyShare]) -> Result<(), ErrorStack> {
        // SAFETY: KeyShare is a transparent native u16; BoringSSL validates and
        // copies the borrowed slice while the SSL connection is live.
        unsafe {
            cvt(ffi::SSL_set1_client_key_shares(
                self.as_ptr(),
                key_shares.as_ptr().cast::<u16>(),
                key_shares.len(),
            ))
        }
    }

    /// Overrides [`SslContextBuilder::set_requested_trust_anchors`] for this connection.
    /// Call this method before the handshake starts.
    #[corresponds(SSL_set1_requested_trust_anchors)]
    pub fn set_requested_trust_anchors(&mut self, ids: &[u8]) -> Result<(), ErrorStack> {
        // SAFETY: `self` is valid and BoringSSL validates and copies `ids` before returning.
        unsafe {
            cvt_0i(ffi::SSL_set1_requested_trust_anchors(
                self.as_ptr(),
                ids.as_ptr(),
                ids.len(),
            ))
            .map(|_| ())
        }
    }

    /// Overrides [`SslContextBuilder::set_available_trust_anchors`] for this connection.
    #[corresponds(SSL_set1_available_trust_anchors)]
    pub fn set_available_trust_anchors(&mut self, ids: &[u8]) -> Result<(), ErrorStack> {
        // SAFETY: `self` is valid and BoringSSL validates and copies `ids` before returning.
        unsafe {
            cvt_0i(ffi::SSL_set1_available_trust_anchors(
                self.as_ptr(),
                ids.as_ptr(),
                ids.len(),
            ))
            .map(|_| ())
        }
    }

    /// Returns whether the server reported that its certificate chain matched one of the trust
    /// anchors this client requested, so verification may treat the chain as a built path.
    ///
    /// Only known during the handshake, such as in a certificate verification callback.
    #[corresponds(SSL_peer_matched_trust_anchor)]
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn peer_matched_trust_anchor(&self) -> bool {
        // SAFETY: The live SSL connection returns a
        // scalar peer trust-anchor match flag.
        unsafe { ffi::SSL_peer_matched_trust_anchor(self.as_ptr()) == 1 }
    }

    /// Returns the trust anchor IDs the server has certificates for, in the format of
    /// [`SslContextBuilder::set_requested_trust_anchors`], or an empty slice if it sent none.
    ///
    /// Only known during the handshake, such as in a certificate verification callback, where a
    /// client that rejects the certificate can choose anchors to request when it retries.
    #[corresponds(SSL_get0_peer_available_trust_anchors)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn peer_available_trust_anchors(&self) -> &[u8] {
        let mut data = ptr::null();
        let mut len = 0;
        // SAFETY: `self` is valid. BoringSSL keeps the list until the handshake moves on, which
        // the shared borrow of `self` prevents.
        unsafe {
            ffi::SSL_get0_peer_available_trust_anchors(self.as_ptr(), &raw mut data, &raw mut len);
            if data.is_null() {
                &[]
            } else {
                slice::from_raw_parts(data, len)
            }
        }
    }

    /// Enables ALPS (application-layer protocol settings) for the ALPN protocol `proto`, sending
    /// `settings` to the peer, or an empty value if `None`.
    ///
    /// `proto` must also be configured for ALPN. A server may instead call this from its ALPN
    /// select callback, for the selected protocol only. The peer's value is available with
    /// [`Self::peer_application_settings`].
    #[corresponds(SSL_add_application_settings)]
    pub fn add_application_settings(
        &mut self,
        proto: &[u8],
        settings: Option<&[u8]>,
    ) -> Result<(), ErrorStack> {
        let settings = settings.unwrap_or_default();
        // SAFETY: Both borrowed ALPN protocol and ALPS
        // payload slices remain live while BoringSSL copies their sizes
        // and contents into the uniquely borrowed connection.
        unsafe {
            cvt(ffi::SSL_add_application_settings(
                self.as_ptr(),
                proto.as_ptr(),
                proto.len(),
                settings.as_ptr(),
                settings.len(),
            ))
        }
    }

    /// Selects the ALPS extension codepoint: `true` for the new one (17613), `false` for the old
    /// one (17513). Defaults to the new codepoint.
    ///
    /// Both peers must use the same codepoint for ALPS to be negotiated.
    #[corresponds(SSL_set_alps_use_new_codepoint)]
    pub fn set_alps_use_new_codepoint(&mut self, enable: bool) {
        let enable = c_int::from(enable);
        // SAFETY: The native connection receives a scalar
        // ALPS codepoint-selection flag.
        unsafe { ffi::SSL_set_alps_use_new_codepoint(self.as_ptr(), enable) }
    }

    /// Overrides [`SslContextBuilder::set_tls13_ciphers`] for this connection.
    ///
    /// An empty list restores BoringSSL's default, not the context's list.
    #[corresponds(SSL_set1_tls13_ciphers)]
    pub fn set_tls13_ciphers(&mut self, ciphers: &[Tls13Cipher]) -> Result<(), ErrorStack> {
        // SAFETY: `Tls13Cipher` is a transparent `u16`, and BoringSSL copies the list.
        unsafe {
            cvt(ffi::SSL_set1_tls13_ciphers(
                self.as_ptr(),
                ciphers.as_ptr().cast(),
                ptr::null(),
                ciphers.len(),
            ))
        }
    }

    /// Requests `num_bytes` of padding from the server in its EncryptedExtensions.
    ///
    /// Servers answer only over TLS 1.3, and not for more than 16 KiB. The extension is
    /// experimental in BoringSSL.
    #[corresponds(SSL_set_server_padding_request)]
    pub fn set_server_padding_request(&mut self, num_bytes: u16) {
        // SAFETY: The uniquely borrowed SSL connection
        // receives a scalar padding size and no pointer is retained.
        unsafe { ffi::SSL_set_server_padding_request(self.as_ptr(), num_bytes) }
    }

    /// Sets whether a server answers the client's server padding request.
    #[corresponds(SSL_set_server_padding_enabled)]
    pub fn set_server_padding_enabled(&mut self, enabled: bool) {
        // SAFETY: The uniquely borrowed SSL connection
        // receives a scalar boolean converted to a native integer.
        unsafe { ffi::SSL_set_server_padding_enabled(self.as_ptr(), c_int::from(enabled)) }
    }

    /// Returns whether the server sent the padding requested with
    /// [`set_server_padding_request`](Self::set_server_padding_request).
    #[corresponds(SSL_server_sent_requested_padding)]
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn server_sent_requested_padding(&self) -> bool {
        // SAFETY: The live SSL connection returns a
        // scalar negotiated-padding flag.
        unsafe { ffi::SSL_server_sent_requested_padding(self.as_ptr()) == 1 }
    }
}

/// Record limits for [`SslRef::seal_app_data`] in the connection's current state.
///
/// Valid until the connection is next used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealLimits {
    max_fragment: usize,
    record_overhead: usize,
    pending_len: usize,
}

impl SealLimits {
    /// Most plaintext bytes in one record.
    #[must_use = "Use the returned length or capacity to size buffers or validate input."]
    pub const fn max_fragment(&self) -> usize {
        self.max_fragment
    }

    /// Most bytes one record adds to its plaintext.
    #[must_use = "Use the returned length or capacity to size buffers or validate input."]
    pub const fn record_overhead(&self) -> usize {
        self.record_overhead
    }

    /// Most bytes of pending handshake records written ahead of the data.
    #[must_use = "Use the returned length or capacity to size buffers or validate input."]
    pub const fn pending_len(&self) -> usize {
        self.pending_len
    }

    /// Returns the output room needed to seal `len` plaintext bytes, or `None` on overflow.
    #[must_use = "Use the returned length or capacity to size buffers or validate input."]
    pub fn sealed_len(&self, len: usize) -> Option<usize> {
        len.div_ceil(self.max_fragment)
            .checked_mul(self.record_overhead)?
            .checked_add(len)?
            .checked_add(self.pending_len)
    }
}

/// Input taken and output written by [`SslRef::seal_app_data`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Sealed {
    /// Plaintext bytes sealed, from the start of the input slices.
    pub consumed: usize,
    /// Bytes written to the start of the output, pending handshake records included.
    pub written: usize,
}

// std guarantees that `IoSlice` is ABI-compatible with `iovec` on Unix, so it can be read as a
// `CRYPTO_IVEC` when `iovec` has the same field layout.
#[cfg(all(unix, not(feature = "fips")))]
const _: () = assert!(
    mem::size_of::<IoSlice<'static>>() == mem::size_of::<ffi::CRYPTO_IVEC>()
        && mem::align_of::<IoSlice<'static>>() == mem::align_of::<ffi::CRYPTO_IVEC>()
        && mem::offset_of!(libc::iovec, iov_base) == mem::offset_of!(ffi::CRYPTO_IVEC, in_)
        && mem::offset_of!(libc::iovec, iov_len) == mem::offset_of!(ffi::CRYPTO_IVEC, len)
);

/// Passes `bufs` to `f` as `CRYPTO_IVEC`s.
#[cfg(all(unix, not(feature = "fips")))]
fn with_ivecs<R>(
    bufs: &[IoSlice<'_>],
    _max_in: usize,
    f: impl FnOnce(&[ffi::CRYPTO_IVEC]) -> R,
) -> R {
    // SAFETY: the assertion above makes the layouts identical, and the cast slice borrows `bufs`.
    f(unsafe { slice::from_raw_parts(bufs.as_ptr().cast(), bufs.len()) })
}

/// Passes the slices of `bufs` that cover `max_in` bytes to `f` as `CRYPTO_IVEC`s.
#[cfg(all(not(unix), not(feature = "fips")))]
fn with_ivecs<R>(
    bufs: &[IoSlice<'_>],
    max_in: usize,
    f: impl FnOnce(&[ffi::CRYPTO_IVEC]) -> R,
) -> R {
    // `IoSlice` has no `iovec` layout here (a Windows `WSABUF` puts the length first), so copy
    // the slices: on the stack up to `STACK_LEN`, which covers most writes, else in a `Vec`.
    const STACK_LEN: usize = 64;

    let mut left = max_in;
    let n = bufs
        .iter()
        .take_while(|buf| {
            let take = left > 0;
            left = left.saturating_sub(buf.len());
            take
        })
        .count();
    let ivecs = bufs[..n].iter().map(|buf| ffi::CRYPTO_IVEC {
        in_: buf.as_ptr(),
        len: buf.len(),
    });
    if n <= STACK_LEN {
        let mut stack = [ffi::CRYPTO_IVEC {
            in_: ptr::null(),
            len: 0,
        }; STACK_LEN];
        for (slot, ivec) in stack.iter_mut().zip(ivecs) {
            *slot = ivec;
        }
        f(&stack[..n])
    } else {
        f(&ivecs.collect::<Vec<_>>())
    }
}

/// An SSL stream midway through the handshake process.
#[derive(Debug)]
pub struct MidHandshakeSslStream<S> {
    stream: SslStream<S>,
    error: Error,
}

impl<S> MidHandshakeSslStream<S> {
    /// Returns a shared reference to the inner stream.
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }

    /// Returns a shared reference to the `Ssl` of the stream.
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn ssl(&self) -> &SslRef {
        self.stream.ssl()
    }

    /// Returns a mutable reference to the `Ssl` of the stream.
    pub fn ssl_mut(&mut self) -> &mut SslRef {
        self.stream.ssl_mut()
    }

    /// Returns the underlying error which interrupted this handshake.
    #[must_use = "Inspect the returned failure information before deciding how to resume the handshake."]
    pub const fn error(&self) -> &Error {
        &self.error
    }

    /// Consumes `self`, returning its error.
    #[must_use = "The returned owned value is the result of consuming the original owner."]
    pub fn into_error(self) -> Error {
        self.error
    }

    /// Returns the source data stream.
    #[must_use = "The returned underlying transport is the result of consuming the failed handshake."]
    pub fn into_source_stream(self) -> S {
        self.stream.into_inner()
    }

    /// Returns both the error and the source data stream, consuming `self`.
    #[must_use = "The returned owned value is the result of consuming the original owner."]
    pub fn into_parts(self) -> (Error, S) {
        (self.error, self.stream.into_inner())
    }

    /// Restarts the handshake process.
    #[corresponds(SSL_do_handshake)]
    pub fn handshake(mut self) -> Result<SslStream<S>, HandshakeError<S>> {
        // SAFETY: The owned live SSL connection retains its BIO and callbacks
        // throughout this handshake continuation, which may return an error.
        let ret = unsafe { ffi::SSL_do_handshake(self.stream.ssl.as_ptr()) };
        if ret > 0 {
            Ok(self.stream)
        } else {
            self.error = self.stream.make_error(ret);
            Err(if self.error.would_block() {
                HandshakeError::WouldBlock(self)
            } else {
                HandshakeError::Failure(self)
            })
        }
    }
}

/// A TLS session over a stream.
pub struct SslStream<S> {
    ssl: ManuallyDrop<Ssl>,
    method: ManuallyDrop<BioMethod>,
    _p: PhantomData<S>,
}

impl<S> Drop for SslStream<S> {
    fn drop(&mut self) {
        // Detach the Rust transport before SSL_free invokes the BIO destructor.
        // The transport's Drop may unwind; release the native resources before
        // dropping it in Rust rather than unwinding through a C callback.
        // SAFETY: We own the stream and its BIO exclusively. into_inner may
        // already have detached the state. SSL holds a reference to method,
        // so freeing SSL must precede freeing the method.
        let state = unsafe {
            let state = bio::detach_state::<S>(self.ssl.get_raw_rbio());
            ManuallyDrop::drop(&mut self.ssl);
            ManuallyDrop::drop(&mut self.method);
            state
        };
        drop(state);
    }
}

impl<S> fmt::Debug for SslStream<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("SslStream")
            .field("stream", &self.get_ref())
            .field("ssl", &self.ssl())
            .finish()
    }
}

/// Clamps an I/O slice length to `BoringSSL`'s signed `int` API limit.
/// The Rust slice can be larger than a single native `SSL_read` or `SSL_write` call.
fn ssl_io_len(len: usize) -> c_int {
    c_int::try_from(len).unwrap_or(c_int::MAX)
}

impl<S: Read + Write> SslStream<S> {
    /// Creates a new `SslStream`.
    ///
    /// This function performs no IO; the stream will not have performed any part of the handshake
    /// with the peer. The `connect` and `accept` methods can be used to
    /// explicitly perform the handshake.
    ///
    /// # Errors
    ///
    /// The native BIO transport cannot be constructed.
    pub fn new(ssl: Ssl, stream: S) -> Result<Self, ErrorStack> {
        let (bio, method) = bio::new(stream)?;
        Ok(Self::attach_bio(ssl, bio, method))
    }

    /// Constructs a TLS stream whose transport supports initialization-aware BIO reads.
    /// # Errors
    /// The native BIO transport cannot be constructed.
    pub fn new_uninit(ssl: Ssl, stream: S) -> Result<Self, ErrorStack>
    where
        S: ReadUninit,
    {
        let (bio, method) = bio::new_uninit(stream)?;
        Ok(Self::attach_bio(ssl, bio, method))
    }

    fn attach_bio(ssl: Ssl, bio: *mut ffi::BIO, method: BioMethod) -> Self {
        // SAFETY: the new BIO and its native reference are transferred to
        // this live SSL object. BoringSSL owns the BIO until stream teardown.
        unsafe {
            ffi::SSL_set_bio(ssl.as_ptr(), bio, bio);
        }

        Self {
            ssl: ManuallyDrop::new(ssl),
            method: ManuallyDrop::new(method),
            _p: PhantomData,
        }
    }

    /// Constructs an `SslStream` from a pointer to the underlying OpenSSL `SSL` struct.
    ///
    /// This is useful if the handshake has already been completed elsewhere.
    ///
    /// # Safety
    ///
    /// The caller must transfer sole ownership of a live `SSL` allocation to
    /// this stream and must not use that pointer afterward.
    ///
    /// # Errors
    ///
    /// The native BIO transport cannot be constructed.
    pub unsafe fn from_raw_parts(ssl: *mut ffi::SSL, stream: S) -> Result<Self, ErrorStack> {
        // SAFETY: the caller transfers sole ownership of the live SSL handle.
        let ssl = unsafe { Ssl::from_ptr(ssl) };
        Self::new(ssl, stream)
    }

    /// Like `read`, but takes a possibly-uninitialized slice.
    ///
    /// # Initialization
    ///
    /// The method never de-initializes `buf`. On success the first `n` bytes
    /// are initialized; all other bytes retain their original initialization state.
    ///
    /// # Errors
    ///
    /// The TLS read or underlying transport fails. Nonblocking reads may
    /// report that additional network readiness is required.
    pub fn read_uninit(&mut self, buf: &mut [MaybeUninit<u8>]) -> io::Result<usize> {
        loop {
            match self.ssl_read_uninit(buf) {
                Ok(n) => return Ok(n),
                Err(ref e) if e.code() == ErrorCode::ZERO_RETURN => return Ok(0),
                Err(ref e) if e.code() == ErrorCode::SYSCALL && e.io_error().is_none() => {
                    return Ok(0);
                }
                Err(ref e) if e.code() == ErrorCode::WANT_READ && e.io_error().is_none() => {}
                Err(e) => {
                    return Err(e.into_stream_io_error());
                }
            }
        }
    }

    /// Like `read`, but returns an `ssl::Error` rather than an `io::Error`.
    ///
    /// It is particularly useful with a nonblocking socket, where the error value will identify if
    /// OpenSSL is waiting on read or write readiness.
    ///
    /// # Errors
    ///
    /// The native read or underlying transport cannot complete the operation.
    #[corresponds(SSL_read)]
    pub fn ssl_read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        // SAFETY: `ssl_read_uninit` does not de-initialize the buffer.
        unsafe {
            self.ssl_read_uninit(slice::from_raw_parts_mut(
                buf.as_mut_ptr().cast::<MaybeUninit<u8>>(),
                buf.len(),
            ))
        }
    }

    // Native SSL_read/SSL_write use signed results. Keep both paths' output
    // conversion and bounds checks identical, including impossible invalid
    // positive lengths from native code.
    fn finish_native_io(&mut self, ret: c_int, offered_len: usize) -> Result<usize, Error> {
        match usize::try_from(ret) {
            Ok(n) if n > 0 && n <= offered_len => Ok(n),
            _ => Err(self.make_error(ret)),
        }
    }

    /// Like `read_ssl`, but takes a possibly-uninitialized slice.
    ///
    /// # Initialization
    ///
    /// On success, the returned prefix of `buf` is initialized. All other
    /// bytes retain their original initialization state.
    ///
    /// # Errors
    ///
    /// The native TLS read cannot complete or requires network readiness.
    pub fn ssl_read_uninit(&mut self, buf: &mut [MaybeUninit<u8>]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        let len = ssl_io_len(buf.len());
        // SAFETY: the live SSL stream has exclusive access to a writable
        // `len`-byte prefix. Uninitialized output is valid for SSL_read.
        let ret = unsafe { ffi::SSL_read(self.ssl().as_ptr(), buf.as_mut_ptr().cast(), len) };
        self.finish_native_io(ret, buf.len())
    }

    /// Like `write`, but returns an `ssl::Error` rather than an `io::Error`.
    ///
    /// It is particularly useful with a nonblocking socket, where the error value will identify if
    /// OpenSSL is waiting on read or write readiness.
    ///
    /// # Errors
    ///
    /// The native TLS write cannot complete or requires network readiness.
    #[corresponds(SSL_write)]
    pub fn ssl_write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        let len = ssl_io_len(buf.len());
        // SAFETY: the borrowed input is readable for its entire lifetime and
        // the live SSL stream reads at most `len` bytes synchronously.
        let ret = unsafe { ffi::SSL_write(self.ssl().as_ptr(), buf.as_ptr().cast(), len) };
        self.finish_native_io(ret, buf.len())
    }

    /// Shuts down the session.
    ///
    /// The shutdown process consists of two steps. The first step sends a close notify message to
    /// the peer, after which `ShutdownResult::Sent` is returned. The second step awaits the receipt
    /// of a close notify message from the peer, after which `ShutdownResult::Received` is returned.
    ///
    /// While the connection may be closed after the first step, it is recommended to fully shut the
    /// session down. In particular, it must be fully shut down if the connection is to be used for
    /// further communication in the future.
    ///
    /// # Errors
    ///
    /// Shutdown requires network readiness or the TLS transport fails.
    #[corresponds(SSL_shutdown)]
    pub fn shutdown(&mut self) -> Result<ShutdownResult, Error> {
        // SAFETY: this stream uniquely owns the live SSL connection while
        // BoringSSL drives the protocol shutdown state machine.
        match unsafe { ffi::SSL_shutdown(self.ssl.as_ptr()) } {
            0 => Ok(ShutdownResult::Sent),
            1 => Ok(ShutdownResult::Received),
            n => Err(self.make_error(n)),
        }
    }

    /// Returns the session's shutdown state.
    #[corresponds(SSL_get_shutdown)]
    #[must_use = "Inspect the peer and local TLS shutdown state."]
    pub fn get_shutdown(&mut self) -> ShutdownState {
        // SAFETY: the native getter reads flags from a live SSL object.
        unsafe {
            let bits = ffi::SSL_get_shutdown(self.ssl.as_ptr());
            ShutdownState::from_bits_retain(bits)
        }
    }

    /// Sets the session's shutdown state.
    ///
    /// This can be used to tell OpenSSL that the session should be cached even if a full two-way
    /// shutdown was not completed.
    #[corresponds(SSL_set_shutdown)]
    pub fn set_shutdown(&mut self, state: ShutdownState) {
        // SAFETY: the borrowed live SSL object receives a native flag bitset.
        unsafe { ffi::SSL_set_shutdown(self.ssl.as_ptr(), state.bits()) }
    }

    /// Initiates a client-side TLS handshake.
    ///
    /// # Errors
    ///
    /// The handshake fails or needs additional transport readiness.
    #[corresponds(SSL_connect)]
    pub fn connect(&mut self) -> Result<(), Error> {
        // SAFETY: the stream exclusively owns the SSL connection during the
        // native client handshake. Transport callbacks remain attached.
        let ret = unsafe { ffi::SSL_connect(self.ssl.as_ptr()) };
        if ret > 0 {
            Ok(())
        } else {
            Err(self.make_error(ret))
        }
    }

    /// Initiates a server-side TLS handshake.
    ///
    /// # Errors
    ///
    /// The handshake fails or needs additional transport readiness.
    #[corresponds(SSL_accept)]
    pub fn accept(&mut self) -> Result<(), Error> {
        // SAFETY: the stream exclusively owns the SSL connection during the
        // native server handshake. Transport callbacks remain attached.
        let ret = unsafe { ffi::SSL_accept(self.ssl.as_ptr()) };
        if ret > 0 {
            Ok(())
        } else {
            Err(self.make_error(ret))
        }
    }

    /// Initiates the handshake.
    #[corresponds(SSL_do_handshake)]
    pub fn do_handshake(&mut self) -> Result<(), Error> {
        // SAFETY: The stream exclusively holds the live SSL connection, its BIO
        // and the native callback state throughout this handshake operation.
        let ret = unsafe { ffi::SSL_do_handshake(self.ssl.as_ptr()) };
        if ret > 0 {
            Ok(())
        } else {
            Err(self.make_error(ret))
        }
    }
}

impl<S> SslStream<S> {
    /// Drives a synchronous TLS operation with a task waker scoped to this
    /// connection. Async callbacks poll their futures using this waker.
    ///
    /// The waker is not retained by the stream after this call (including
    /// unwinding). Nested operations on another stream have independent scopes.
    #[inline]
    pub fn with_task_waker<R>(
        &mut self,
        waker: &std::task::Waker,
        f: impl FnOnce(&mut Self) -> R,
    ) -> R {
        async_callbacks::with_task_waker(self.ssl.as_ptr(), waker, || f(self))
    }

    fn make_error(&mut self, ret: c_int) -> Error {
        self.check_panic();

        let code = self.ssl.error_code(ret);

        let cause = match code {
            ErrorCode::SSL => Some(InnerError::Ssl(ErrorStack::get())),
            ErrorCode::SYSCALL => {
                let errs = ErrorStack::get();
                if errs.errors().is_empty() {
                    self.get_bio_error().map(InnerError::Io)
                } else {
                    Some(InnerError::Ssl(errs))
                }
            }
            ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => {
                self.get_bio_error().map(InnerError::Io)
            }
            _ => None,
        };

        Error {
            code,
            cause,
            async_callback_pending: async_callbacks::take_pending(&self.ssl, code),
        }
    }

    fn check_panic(&mut self) {
        // SAFETY: The owned BIO holds a panic slot for the current transport type;
        // the native state remains live until stream teardown.
        if let Some(err) = unsafe { bio::take_panic::<S>(self.ssl.get_raw_rbio()) } {
            resume_unwind(err)
        }
    }

    fn get_bio_error(&mut self) -> Option<io::Error> {
        // SAFETY: The owned BIO holds the transport error slot for the current
        // stream type, which is read before native teardown.
        unsafe { bio::take_error::<S>(self.ssl.get_raw_rbio()) }
    }

    /// Converts the `SslStream` to the underlying data stream.
    #[must_use = "The returned owned value is the result of consuming the original owner."]
    pub fn into_inner(self) -> S {
        // SAFETY: Consuming this stream transfers its transport out of the owned
        // native BIO exactly once; teardown observes the detached state.
        unsafe { bio::take_stream::<S>(self.ssl.get_raw_rbio()) }
    }

    /// Returns a shared reference to the underlying stream.
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn get_ref(&self) -> &S {
        // SAFETY: The live owned BIO contains the stream state and the returned
        // shared reference cannot outlive this SslStream borrow.
        unsafe {
            let bio = self.ssl.get_raw_rbio();
            bio::get_ref(bio)
        }
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// # Warning
    ///
    /// It is inadvisable to read from or write to the underlying stream as it
    /// will most likely corrupt the SSL session.
    pub fn get_mut(&mut self) -> &mut S {
        // SAFETY: The live owned BIO contains the stream state; the exclusive
        // Rust borrow prevents mutable aliasing of its transport.
        unsafe {
            let bio = self.ssl.get_raw_rbio();
            bio::get_mut(bio)
        }
    }

    /// Returns a shared reference to the `Ssl` object associated with this stream.
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn ssl(&self) -> &SslRef {
        &self.ssl
    }

    /// Returns a mutable reference to the `Ssl` object associated with this stream.
    pub fn ssl_mut(&mut self) -> &mut SslRef {
        &mut self.ssl
    }
}

impl<S: Read + Write> Read for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `read_uninit` does not de-initialize the buffer
        unsafe {
            self.read_uninit(slice::from_raw_parts_mut(
                buf.as_mut_ptr().cast::<MaybeUninit<u8>>(),
                buf.len(),
            ))
        }
    }
}

impl<S: Read + Write> Write for SslStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            match self.ssl_write(buf) {
                Ok(n) => return Ok(n),
                Err(ref e) if e.code() == ErrorCode::WANT_READ && e.io_error().is_none() => {}
                Err(e) => {
                    return Err(e.into_stream_io_error());
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.get_mut().flush()
    }
}

/// A partially constructed `SslStream`, useful for unusual handshakes.
pub struct SslStreamBuilder<S> {
    inner: SslStream<S>,
}

impl<S> SslStreamBuilder<S>
where
    S: Read + Write,
{
    /// Begin creating an `SslStream` atop `stream`.
    ///
    /// # Errors
    ///
    /// The native BIO transport cannot be constructed.
    pub fn new(ssl: Ssl, stream: S) -> Result<Self, ErrorStack> {
        Ok(Self {
            inner: SslStream::new(ssl, stream)?,
        })
    }

    fn pending(self, code: ErrorCode, message: &'static str) -> MidHandshakeSslStream<S> {
        MidHandshakeSslStream {
            stream: self.inner,
            error: Error {
                code,
                async_callback_pending: false,
                cause: Some(InnerError::Io(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    message,
                ))),
            },
        }
    }

    /// Configure as an outgoing stream from a client.
    #[corresponds(SSL_set_connect_state)]
    pub fn set_connect_state(&mut self) {
        // SAFETY: the builder owns a live SSL object and exclusively borrows it.
        unsafe { ffi::SSL_set_connect_state(self.inner.ssl.as_ptr()) }
    }

    /// Configure as an incoming stream to a server.
    #[corresponds(SSL_set_accept_state)]
    pub fn set_accept_state(&mut self) {
        // SAFETY: the builder owns a live SSL object and exclusively borrows it.
        unsafe { ffi::SSL_set_accept_state(self.inner.ssl.as_ptr()) }
    }

    /// Initiates a client-side TLS handshake, returning a [`MidHandshakeSslStream`].
    ///
    /// This method calls [`Self::set_connect_state`] and returns without actually
    /// initiating the handshake. The caller is then free to call
    /// [`MidHandshakeSslStream`] and loop on [`HandshakeError::WouldBlock`].
    #[must_use = "Drive the returned handshake state; dropping it discards the underlying stream."]
    pub fn setup_connect(mut self) -> MidHandshakeSslStream<S> {
        self.set_connect_state();

        self.pending(
            ErrorCode::WANT_WRITE,
            "connect handshake has not started yet",
        )
    }

    /// Attempts a client-side TLS handshake.
    ///
    /// This is a convenience method which combines [`Self::setup_connect`] and
    /// [`MidHandshakeSslStream::handshake`].
    ///
    /// # Errors
    ///
    /// The handshake fails or needs additional I/O readiness.
    pub fn connect(self) -> Result<SslStream<S>, HandshakeError<S>> {
        self.setup_connect().handshake()
    }

    /// Initiates a server-side TLS handshake, returning a [`MidHandshakeSslStream`].
    ///
    /// This method calls [`Self::set_accept_state`] and returns without actually
    /// initiating the handshake. The caller is then free to call
    /// [`MidHandshakeSslStream`] and loop on [`HandshakeError::WouldBlock`].
    #[must_use = "Drive the returned handshake state; dropping it discards the underlying stream."]
    pub fn setup_accept(mut self) -> MidHandshakeSslStream<S> {
        self.set_accept_state();

        self.pending(ErrorCode::WANT_READ, "accept handshake has not started yet")
    }

    /// Attempts a server-side TLS handshake.
    ///
    /// This is a convenience method which combines [`Self::setup_accept`] and
    /// [`MidHandshakeSslStream::handshake`].
    ///
    /// # Errors
    ///
    /// The handshake fails or needs additional I/O readiness.
    pub fn accept(self) -> Result<SslStream<S>, HandshakeError<S>> {
        self.setup_accept().handshake()
    }

    /// Initiates the handshake.
    ///
    /// This will fail if `set_accept_state` or `set_connect_state` was not called first.
    #[corresponds(SSL_do_handshake)]
    pub fn handshake(self) -> Result<SslStream<S>, HandshakeError<S>> {
        let mut stream = self.inner;
        // SAFETY: The builder owns the live SSL handle and BIO while BoringSSL
        // advances this handshake and uses its installed callbacks.
        let ret = unsafe { ffi::SSL_do_handshake(stream.ssl.as_ptr()) };
        if ret > 0 {
            Ok(stream)
        } else {
            let error = stream.make_error(ret);
            Err(if error.would_block() {
                HandshakeError::WouldBlock(MidHandshakeSslStream { stream, error })
            } else {
                HandshakeError::Failure(MidHandshakeSslStream { stream, error })
            })
        }
    }
}

impl<S> SslStreamBuilder<S> {
    /// Returns a shared reference to the underlying stream.
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn get_ref(&self) -> &S {
        self.inner.get_ref()
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// # Warning
    ///
    /// It is inadvisable to read from or write to the underlying stream as it
    /// will most likely corrupt the SSL session.
    pub fn get_mut(&mut self) -> &mut S {
        self.inner.get_mut()
    }

    /// Returns a shared reference to the `Ssl` object associated with this builder.
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn ssl(&self) -> &SslRef {
        &self.inner.ssl
    }

    /// Returns a mutable reference to the `Ssl` object associated with this builder.
    pub fn ssl_mut(&mut self) -> &mut SslRef {
        &mut self.inner.ssl
    }
}

/// A certificate type.
#[cfg(feature = "rpk")]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct CertificateType(u8);

#[cfg(feature = "rpk")]
impl CertificateType {
    /// A X.509 certificate.
    pub const X509: Self = Self(crate::native_u8(ffi::TLSEXT_cert_type_x509));

    /// A raw public key.
    pub const RAW_PUBLIC_KEY: Self = Self(crate::native_u8(ffi::TLSEXT_cert_type_rpk));
}

/// The result of a shutdown request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShutdownResult {
    /// A close notify message has been sent to the peer.
    Sent,

    /// A close notify response message has been received from the peer.
    Received,
}

bitflags! {
    /// The shutdown state of a session.
    #[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
    pub struct ShutdownState: c_int {
        /// A close notify message has been sent to the peer.
        const SENT = ffi::SSL_SENT_SHUTDOWN;
        /// A close notify message has been received from the peer.
        const RECEIVED = ffi::SSL_RECEIVED_SHUTDOWN;
    }
}

/// Private key hooks for signing and decryption, including offloading to a
/// custom asynchronous backend. The certificate supplies key metadata such as
/// its type and size.
///
/// Corresponds to [`ssl_private_key_method_st`].
///
/// [`ssl_private_key_method_st`]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#ssl_private_key_method_st
pub trait PrivateKeyMethod: Send + Sync + 'static {
    /// Signs the message `input` using the specified signature algorithm.
    ///
    /// On success, it returns `Ok(written)` where `written` is the number of
    /// bytes written into `output`. On failure, it returns
    /// `Err(PrivateKeyMethodError::FAILURE)`. If the operation has not completed,
    /// it returns `Err(PrivateKeyMethodError::RETRY)`.
    ///
    /// The caller should arrange for the high-level operation on `ssl` to be
    /// retried when the operation is completed. This will result in a call to
    /// [`Self::complete`].
    ///
    /// # Errors
    ///
    /// The operation fails or must be retried after asynchronous completion.
    fn sign(
        &self,
        ssl: &mut SslRef,
        input: &[u8],
        signature_algorithm: SslSignatureAlgorithm,
        output: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError>;

    /// Decrypts `input`.
    ///
    /// On success, it returns `Ok(written)` where `written` is the number of
    /// bytes written into `output`. On failure, it returns
    /// `Err(PrivateKeyMethodError::FAILURE)`. If the operation has not completed,
    /// it returns `Err(PrivateKeyMethodError::RETRY)`.
    ///
    /// The caller should arrange for the high-level operation on `ssl` to be
    /// retried when the operation is completed. This will result in a call to
    /// [`Self::complete`].
    ///
    /// This method only works with RSA keys and should perform a raw RSA
    /// decryption operation with no padding.
    ///
    /// # Errors
    ///
    /// The operation fails or must be retried after asynchronous completion.
    fn decrypt(
        &self,
        ssl: &mut SslRef,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError>;

    /// Completes a pending operation.
    ///
    /// On success, it returns `Ok(written)` where `written` is the number of
    /// bytes written into `output`. On failure, it returns
    /// `Err(PrivateKeyMethodError::FAILURE)`. If the operation has not completed,
    /// it returns `Err(PrivateKeyMethodError::RETRY)`.
    ///
    /// This method may be called arbitrarily many times before completion.
    ///
    /// # Errors
    ///
    /// The operation fails or remains pending and needs a later retry.
    fn complete(&self, ssl: &mut SslRef, output: &mut [u8])
    -> Result<usize, PrivateKeyMethodError>;
}

/// An error returned from a private key method.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PrivateKeyMethodError(ffi::ssl_private_key_result_t);

impl PrivateKeyMethodError {
    /// A fatal error occurred and the handshake should be terminated.
    pub const FAILURE: Self = Self(ffi::ssl_private_key_result_t::ssl_private_key_failure);

    /// The operation could not be completed and should be retried later.
    pub const RETRY: Self = Self(ffi::ssl_private_key_result_t::ssl_private_key_retry);
}

/// Describes certificate compression algorithm. Implementation MUST implement transformation at least in one direction.
pub trait CertificateCompressor: Send + Sync + 'static {
    /// An IANA assigned identifier of compression algorithm
    const ALGORITHM: CertificateCompressionAlgorithm;

    /// Indicates if compressor support compression
    const CAN_COMPRESS: bool;

    /// Indicates if compressor support decompression
    const CAN_DECOMPRESS: bool;

    /// Compress `input` into `output`.
    ///
    /// # Errors
    ///
    /// Compression is unsupported by this implementation, or writing fails.
    fn compress<W>(&self, _input: &[u8], _output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        Err(io::Error::other("not implemented"))
    }

    /// Decompress `input` into `output`.
    ///
    /// # Errors
    ///
    /// Decompression is unsupported by this implementation, or writing fails.
    fn decompress<W>(&self, _input: &[u8], _output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        Err(io::Error::other("not implemented"))
    }
}

use crate::ffi::{SSL_CTX_up_ref, SSL_SESSION_get_master_key, SSL_SESSION_up_ref, SSL_is_server};

unsafe fn get_new_idx(f: ffi::CRYPTO_EX_free) -> c_int {
    // SAFETY: The native callback is a static function pointer and the
    // register call retains no temporary Rust storage; other args are null.
    unsafe { ffi::SSL_CTX_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, f) }
}

unsafe fn get_new_ssl_idx(f: ffi::CRYPTO_EX_free) -> c_int {
    // SAFETY: The native callback is a static function pointer and the
    // register call retains no temporary Rust storage; other args are null.
    unsafe { ffi::SSL_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, f) }
}

fn path_to_cstring(path: &Path) -> Result<CString, ErrorStack> {
    CString::new(path.as_os_str().as_encoded_bytes()).map_err(ErrorStack::internal_error)
}
