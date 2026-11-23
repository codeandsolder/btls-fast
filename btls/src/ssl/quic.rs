//! QUIC support for TLS 1.3 connections ([RFC 9001](https://www.rfc-editor.org/rfc/rfc9001)).
//!
//! A QUIC connection has no BIO. BoringSSL hands its secrets and handshake messages to the
//! [`QuicMethod`] of the context instead of writing records, and takes the peer's handshake
//! messages through [`Ssl::provide_quic_data`].
//!
//! Handshake input, role selection and driving methods require an owned [`Ssl`]. Callbacks
//! only receive [`SslRef`], so they cannot reenter the handshake or invalidate its input.

use super::{ErrorCode, Ssl, SslAlert, SslCipherRef, SslContext, SslContextBuilder, SslRef};
use crate::error::ErrorStack;
use crate::{cvt, ffi};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::ffi::c_int;
use std::marker::PhantomData;
use std::{ptr, slice};

/// A QUIC encryption level ([RFC 9001 §4.1.4](https://www.rfc-editor.org/rfc/rfc9001#section-4.1.4)).
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct QuicEncryptionLevel(ffi::ssl_encryption_level_t);

impl QuicEncryptionLevel {
    /// Protects the ClientHello and ServerHello.
    pub const INITIAL: Self = Self(ffi::ssl_encryption_level_t::ssl_encryption_initial);
    /// Protects client 0-RTT data. The handshake itself never writes at this level.
    pub const EARLY_DATA: Self = Self(ffi::ssl_encryption_level_t::ssl_encryption_early_data);
    /// Protects the rest of the handshake.
    pub const HANDSHAKE: Self = Self(ffi::ssl_encryption_level_t::ssl_encryption_handshake);
    /// Protects 1-RTT data and post-handshake messages, such as session tickets.
    pub const APPLICATION: Self = Self(ffi::ssl_encryption_level_t::ssl_encryption_application);
}

/// A failed [`QuicMethod`] callback, which terminates the handshake.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct QuicMethodError;

/// The QUIC hooks of a context (`SSL_QUIC_METHOD`), see [`SslContextBuilder::set_quic_method`].
///
/// BoringSSL calls them from inside [`Ssl::do_handshake`] and
/// [`Ssl::process_quic_post_handshake`], and from calls that send an alert, never from
/// [`Ssl::provide_quic_data`]. Callbacks receive an [`SslRef`] for configuration and queries;
/// handshake input and driving require the [`Ssl`] owner after the callback returns.
/// Per-connection state belongs in the connection's ex data. An error terminates the handshake.
pub trait QuicMethod: Send + Sync + 'static {
    /// Installs the read secret and cipher suite of `level`. BoringSSL calls it at most once per
    /// level, and only after the write secret that ACKs the packets it protects.
    fn set_read_secret(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        cipher: &SslCipherRef,
        secret: &[u8],
    ) -> Result<(), QuicMethodError>;

    /// Installs the write secret and cipher suite of `level`, at most once per level.
    ///
    /// A server gets its [`QuicEncryptionLevel::APPLICATION`] secret before the client Finished,
    /// so it can send half-RTT data. The handshake is not confirmed then, and a client that was
    /// asked for a certificate is not authenticated yet. After a 0-RTT reject, the
    /// [`QuicEncryptionLevel::EARLY_DATA`] secret may use another cipher suite than the other
    /// levels.
    fn set_write_secret(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        cipher: &SslCipherRef,
        secret: &[u8],
    ) -> Result<(), QuicMethodError>;

    /// Adds handshake data to the current flight at `level`.
    fn add_handshake_data(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        data: &[u8],
    ) -> Result<(), QuicMethodError>;

    /// Signals that the current flight, which may span several levels, is complete.
    fn flush_flight(&self, ssl: &mut SslRef) -> Result<(), QuicMethodError>;

    /// Sends a fatal alert at `level`.
    fn send_alert(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        alert: SslAlert,
    ) -> Result<(), QuicMethodError>;
}

/// The `SSL_QUIC_METHOD` of `M`, which BoringSSL keeps a pointer to.
struct QuicMethodTable<M>(PhantomData<M>);

impl<M: QuicMethod> QuicMethodTable<M> {
    const METHOD: ffi::SSL_QUIC_METHOD = ffi::SSL_QUIC_METHOD {
        set_read_secret: Some(raw_set_read_secret::<M>),
        set_write_secret: Some(raw_set_write_secret::<M>),
        add_handshake_data: Some(raw_add_handshake_data::<M>),
        flush_flight: Some(raw_flush_flight::<M>),
        send_alert: Some(raw_send_alert::<M>),
    };
}

impl SslContextBuilder {
    /// Configures the context for QUIC, with `method` receiving the secrets and handshake data
    /// of its connections.
    ///
    /// A connection keeps the method table of the context it was created with, but the
    /// callbacks look `method` up in its current context. A context switched in during the
    /// handshake, such as by [`SslRef::set_ssl_context`], must therefore hold a method of the
    /// same type, or the handshake fails.
    ///
    /// # Errors
    ///
    /// Returns an error if callback storage cannot be allocated or the native QUIC method cannot be installed.
    #[corresponds(SSL_CTX_set_quic_method)]
    pub fn set_quic_method<M: QuicMethod>(&mut self, method: M) -> Result<(), ErrorStack> {
        self.set_ex_data(
            SslContext::register_callback::<M>(super::CallbackRole::Quic)?,
            method,
        )?;
        // A promoted constant, so the table lives for the whole program.
        let table: &'static ffi::SSL_QUIC_METHOD = &QuicMethodTable::<M>::METHOD;
        // SAFETY: the native context is uniquely borrowed; it retains only
        // the static function table, and the callback state lives in ex-data.
        unsafe { cvt(ffi::SSL_CTX_set_quic_method(self.as_ptr(), table)) }
    }
}

impl Ssl {
    /// Makes the connection a client, for connections without a BIO such as QUIC ones.
    ///
    /// Callbacks cannot change the connection role.
    ///
    /// ```compile_fail,E0599
    /// fn callback(ssl: &mut btls::ssl::SslRef) {
    ///     ssl.set_connect_state();
    /// }
    /// ```
    #[corresponds(SSL_set_connect_state)]
    pub fn set_connect_state(&mut self) {
        // SAFETY: only the owner of this connection may change its role.
        unsafe { ffi::SSL_set_connect_state(self.as_ptr()) }
    }

    /// Makes the connection a server, for connections without a BIO such as QUIC ones.
    ///
    /// Callbacks cannot change the connection role.
    ///
    /// ```compile_fail,E0599
    /// fn callback(ssl: &mut btls::ssl::SslRef) {
    ///     ssl.set_accept_state();
    /// }
    /// ```
    #[corresponds(SSL_set_accept_state)]
    pub fn set_accept_state(&mut self) {
        // SAFETY: only the owner of this connection may change its role.
        unsafe { ffi::SSL_set_accept_state(self.as_ptr()) }
    }

    /// Advances the handshake of a connection without a BIO, such as a QUIC one. Streams use
    /// [`SslStream::do_handshake`](super::SslStream::do_handshake) instead.
    ///
    /// [`ErrorCode::WANT_READ`] means the handshake waits for peer data. On [`ErrorCode::SSL`],
    /// the reason is on the error queue.
    ///
    /// Callbacks cannot reenter the handshake through their borrowed connection.
    ///
    /// ```compile_fail,E0599
    /// fn callback(ssl: &mut btls::ssl::SslRef) {
    ///     let _ = ssl.do_handshake();
    /// }
    /// ```
    #[corresponds(SSL_do_handshake)]
    ///
    /// # Errors
    ///
    /// The native handshake may need peer input or fail with an SSL error code.
    pub fn do_handshake(&mut self) -> Result<(), ErrorCode> {
        // SAFETY: The owner drives the native handshake, and callback views cannot reenter it.
        let ret = unsafe { ffi::SSL_do_handshake(self.as_ptr()) };
        if ret == 1 {
            Ok(())
        } else {
            Err(self.error_code(ret))
        }
    }

    /// Provides handshake data the peer sent at `level`, which the next
    /// [`Ssl::do_handshake`] or [`Ssl::process_quic_post_handshake`] processes.
    ///
    /// It fails with `SSL_R_WRONG_ENCRYPTION_LEVEL_RECEIVED` if `level` is not
    /// [`SslRef::quic_read_level`], and with `SSL_R_EXCESSIVE_MESSAGE_SIZE` if the buffered data
    /// would exceed [`SslRef::quic_max_handshake_flight_len`]. The connection should then be
    /// closed.
    ///
    /// Callbacks cannot change the input buffer while BoringSSL is processing it.
    ///
    /// ```compile_fail,E0599
    /// fn callback(ssl: &mut btls::ssl::SslRef) {
    ///     let _ = ssl.provide_quic_data(btls::ssl::QuicEncryptionLevel::INITIAL, &[]);
    /// }
    /// ```
    #[corresponds(SSL_provide_quic_data)]
    ///
    /// # Errors
    ///
    /// Native rejects invalid encryption levels, oversized input or invalid state.
    pub fn provide_quic_data(
        &mut self,
        level: QuicEncryptionLevel,
        data: &[u8],
    ) -> Result<(), ErrorStack> {
        // SAFETY: The owner uniquely holds SSL, and native borrows the data slice only during this call.
        unsafe {
            cvt(ffi::SSL_provide_quic_data(
                self.as_ptr(),
                level.0,
                data.as_ptr(),
                data.len(),
            ))
        }
    }

    /// Processes the handshake data provided after the handshake, such as session tickets.
    ///
    /// On [`ErrorCode::SSL`], the reason is on the error queue.
    ///
    /// Callbacks cannot reenter post-handshake processing.
    ///
    /// ```compile_fail,E0599
    /// fn callback(ssl: &mut btls::ssl::SslRef) {
    ///     let _ = ssl.process_quic_post_handshake();
    /// }
    /// ```
    #[corresponds(SSL_process_quic_post_handshake)]
    ///
    /// # Errors
    ///
    /// Native rejects malformed post-handshake input or invalid state.
    pub fn process_quic_post_handshake(&mut self) -> Result<(), ErrorCode> {
        // SAFETY: The owner drives native post-handshake state, and callbacks cannot reenter it.
        let ret = unsafe { ffi::SSL_process_quic_post_handshake(self.as_ptr()) };
        if ret == 1 {
            Ok(())
        } else {
            Err(self.error_code(ret))
        }
    }
}

impl SslRef {
    /// Sets the transport parameters this endpoint sends
    /// ([RFC 9001 §8.2](https://www.rfc-editor.org/rfc/rfc9001#section-8.2)).
    #[corresponds(SSL_set_quic_transport_params)]
    ///
    /// # Errors
    ///
    /// The native connection may reject the parameter bytes or current state.
    pub fn set_quic_transport_params(&mut self, params: &[u8]) -> Result<(), ErrorStack> {
        // SAFETY: Native copies this readable parameter slice during an exclusive SSL borrow.
        unsafe {
            cvt(ffi::SSL_set_quic_transport_params(
                self.as_ptr(),
                params.as_ptr(),
                params.len(),
            ))
        }
    }

    /// Returns the transport parameters the peer sent, once they arrived.
    #[corresponds(SSL_get_peer_quic_transport_params)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn peer_quic_transport_params(&self) -> Option<&[u8]> {
        let mut params = ptr::null();
        let mut len = 0;
        // SAFETY: native returns a borrowed byte view into the live SSL
        // session. A shared borrow prevents concurrent connection mutation.
        unsafe {
            ffi::SSL_get_peer_quic_transport_params(self.as_ptr(), &raw mut params, &raw mut len);
            if len == 0 || params.is_null() {
                None
            } else {
                Some(slice::from_raw_parts(params, len))
            }
        }
    }

    /// Selects the legacy codepoint 0xffa5 of the transport parameters extension instead of the
    /// standard 57, for draft versions of QUIC.
    #[corresponds(SSL_set_quic_use_legacy_codepoint)]
    pub fn set_quic_use_legacy_codepoint(&mut self, use_legacy: bool) {
        // SAFETY: the connection is exclusively borrowed, and bool converts
        // infallibly to the C ABI integer flag.
        unsafe { ffi::SSL_set_quic_use_legacy_codepoint(self.as_ptr(), use_legacy.into()) }
    }

    /// Sets the context a server accepts 0-RTT under. BoringSSL stores it in the tickets it
    /// issues, and rejects 0-RTT from a ticket with another one. It should cover the transport
    /// parameters and application state that 0-RTT depends on
    /// ([RFC 9000 §7.4.1](https://www.rfc-editor.org/rfc/rfc9000#section-7.4.1)). Without it,
    /// a QUIC server issues no tickets for 0-RTT.
    #[corresponds(SSL_set_quic_early_data_context)]
    ///
    /// # Errors
    ///
    /// The native connection may reject the early-data context or its state.
    pub fn set_quic_early_data_context(&mut self, context: &[u8]) -> Result<(), ErrorStack> {
        // SAFETY: The connection is exclusive and native copies the readable context slice.
        unsafe {
            cvt(ffi::SSL_set_quic_early_data_context(
                self.as_ptr(),
                context.as_ptr(),
                context.len(),
            ))
        }
    }

    /// Returns the level that peer handshake data is expected at.
    ///
    /// BoringSSL asserts that the connection is a QUIC one in debug builds.
    #[corresponds(SSL_quic_read_level)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn quic_read_level(&self) -> QuicEncryptionLevel {
        // SAFETY: The native QUIC session is live and shared-borrowed.
        QuicEncryptionLevel(unsafe { ffi::SSL_quic_read_level(self.as_ptr()) })
    }

    /// Returns the level that handshake data is written at.
    ///
    /// BoringSSL asserts that the connection is a QUIC one in debug builds.
    #[corresponds(SSL_quic_write_level)]
    #[must_use = "Use the returned handshake or negotiated protocol data to inspect or drive the connection."]
    pub fn quic_write_level(&self) -> QuicEncryptionLevel {
        // SAFETY: The native QUIC session is live and shared-borrowed.
        QuicEncryptionLevel(unsafe { ffi::SSL_quic_write_level(self.as_ptr()) })
    }

    /// Returns the most handshake data the peer may send at `level`, to bound buffering
    /// ([RFC 9000 §7.5](https://www.rfc-editor.org/rfc/rfc9000#section-7.5)).
    #[corresponds(SSL_quic_max_handshake_flight_len)]
    #[must_use = "Use the returned length or capacity to size buffers or validate input."]
    pub fn quic_max_handshake_flight_len(&self, level: QuicEncryptionLevel) -> usize {
        // SAFETY: the native QUIC session stays borrowed for this size query.
        unsafe { ffi::SSL_quic_max_handshake_flight_len(self.as_ptr(), level.0) }
    }
}

/// Finds the [`QuicMethod`] of the context `ssl` belongs to and runs `f` with it. A missing
/// method fails like `f`.
///
/// # Safety
///
/// The pointer must refer to the live native SSL connection invoking the
/// QUIC callback; it remains uniquely accessible throughout the callback.
unsafe fn with_method<M: QuicMethod>(
    ssl: *mut ffi::SSL,
    f: impl FnOnce(&M, &mut SslRef) -> Result<(), QuicMethodError>,
) -> c_int {
    // SAFETY: BoringSSL passes the callbacks the `SSL` they run for.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let ssl_context = ssl.ssl_context().to_owned();
    let Some(method) = ssl_context.callback::<M>(super::CallbackRole::Quic) else {
        return 0;
    };
    crate::util::catch_native(|| f(method, ssl).is_ok())
        .unwrap_or(false)
        .into()
}

/// Pushes `SSL_R_QUIC_INTERNAL_ERROR` for a failed secret callback. BoringSSL does so for the
/// other callbacks, but not these, which would leave the error queue empty.
fn secret_result(ret: c_int) -> c_int {
    if ret == 0 {
        // SAFETY: the file name is a static C string.
        unsafe {
            ffi::ERR_put_error(
                ffi::ERR_LIB_SSL.0.cast_signed(),
                0,
                ffi::SSL_R_QUIC_INTERNAL_ERROR,
                concat!(file!(), "\0").as_ptr().cast(),
                line!(),
            );
        }
    }
    ret
}

/// Dispatches a native secret callback with one shared validated byte view.
///
/// # Safety
///
/// The native caller supplies a live SSL connection, and non-null cipher and
/// secret storage for every nonempty secret during the synchronous callback.
unsafe fn dispatch_secret<M: QuicMethod>(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
    apply: fn(
        &M,
        &mut SslRef,
        QuicEncryptionLevel,
        &SslCipherRef,
        &[u8],
    ) -> Result<(), QuicMethodError>,
) -> c_int {
    if cipher.is_null() || (secret_len != 0 && secret.is_null()) {
        return secret_result(0);
    }
    // SAFETY: the native callback supplies an immutable live cipher object.
    let cipher = unsafe { SslCipherRef::from_ptr(cipher.cast_mut()) };
    let secret = if secret_len == 0 {
        &[]
    } else {
        // SAFETY: native keeps secret_len bytes readable until callback return.
        unsafe { slice::from_raw_parts(secret, secret_len) }
    };
    // SAFETY: ssl remains live and uniquely accessible for the native callback.
    secret_result(unsafe {
        with_method::<M>(ssl, |method, ssl| {
            apply(method, ssl, QuicEncryptionLevel(level), cipher, secret)
        })
    })
}

unsafe extern "C" fn raw_set_read_secret<M: QuicMethod>(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    // SAFETY: the native QUIC callback passes a live SSL, cipher, and secret.
    unsafe { dispatch_secret::<M>(ssl, level, cipher, secret, secret_len, M::set_read_secret) }
}

unsafe extern "C" fn raw_set_write_secret<M: QuicMethod>(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    // SAFETY: the native QUIC callback passes a live SSL, cipher, and secret.
    unsafe { dispatch_secret::<M>(ssl, level, cipher, secret, secret_len, M::set_write_secret) }
}

unsafe extern "C" fn raw_add_handshake_data<M: QuicMethod>(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    data: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: BoringSSL passes `len` bytes of handshake data.
    // A zero-length native buffer is permitted to have a null pointer.
    let data = if len == 0 {
        &[]
    } else {
        // SAFETY: native keeps these reported handshake bytes readable.
        unsafe { slice::from_raw_parts(data, len) }
    };
    // SAFETY: native keeps the SSL owner alive for this callback.
    unsafe {
        with_method::<M>(ssl, |method, ssl| {
            method.add_handshake_data(ssl, QuicEncryptionLevel(level), data)
        })
    }
}

unsafe extern "C" fn raw_flush_flight<M: QuicMethod>(ssl: *mut ffi::SSL) -> c_int {
    // SAFETY: native keeps the SSL owner alive for this callback.
    unsafe { with_method::<M>(ssl, |method, ssl| method.flush_flight(ssl)) }
}

unsafe extern "C" fn raw_send_alert<M: QuicMethod>(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    alert: u8,
) -> c_int {
    // SAFETY: native keeps the SSL owner alive for this callback.
    unsafe {
        with_method::<M>(ssl, |method, ssl| {
            method.send_alert(ssl, QuicEncryptionLevel(level), SslAlert(alert.into()))
        })
    }
}
