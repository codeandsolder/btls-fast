#![forbid(unsafe_op_in_unsafe_fn)]

use super::connector::{CLIENT_SESSION_INDEX, SESSION_PEER_INDEX};
use super::{
    AlpnError, CallbackRole, CertificateCompressor, ClientHello, ClientSession,
    GetSessionPendingError, PrivateKeyMethod, PrivateKeyMethodError, SelectCertAction,
    SelectCertError, SniError, SslAlert, SslContextRef, SslInfoCallbackAlert, SslInfoCallbackMode,
    SslInfoCallbackValue, SslRef, SslSession, SslSessionRef, SslSignatureAlgorithm, SslVerifyError,
};
use crate::error::ErrorStack;
use crate::ffi;
use crate::hmac::HmacCtxRef;
use crate::ssl::{TicketKeyCallbackResult, TicketKeyMode};
use crate::symm::CipherCtxRef;
use crate::util::{catch_native, native_input};
use crate::x509::X509StoreContextRef;
use foreign_types::ForeignType;
use foreign_types::ForeignTypeRef;
use libc::{c_char, c_int, c_uchar, c_uint, c_void};
use std::ffi::CStr;
use std::mem;
use std::ptr;
use std::slice;
use std::str;
use std::sync::Arc;

/// `BoringSSL` retains the pointer to a private-key callback method table.
/// Every monomorphized table therefore needs storage that outlives the native
/// context or credential, not a temporary constructed by its setter.
pub(super) struct PrivateKeyMethodDescriptor<M, const CREDENTIAL: bool>(
    std::marker::PhantomData<M>,
);

impl<M: PrivateKeyMethod, const CREDENTIAL: bool> PrivateKeyMethodDescriptor<M, CREDENTIAL> {
    const TABLE: ffi::SSL_PRIVATE_KEY_METHOD = ffi::SSL_PRIVATE_KEY_METHOD {
        sign: Some(raw_sign::<M, CREDENTIAL>),
        decrypt: Some(raw_decrypt::<M, CREDENTIAL>),
        complete: Some(raw_complete::<M, CREDENTIAL>),
    };

    pub(super) const fn descriptor() -> &'static ffi::SSL_PRIVATE_KEY_METHOD {
        &Self::TABLE
    }
}

pub extern "C" fn raw_verify<F>(preverify_ok: c_int, x509_ctx: *mut ffi::X509_STORE_CTX) -> c_int
where
    F: Fn(bool, &mut X509StoreContextRef) -> bool + 'static + Sync + Send,
{
    // SAFETY: btls provides valid inputs.
    let ctx = unsafe { X509StoreContextRef::from_ptr_mut(x509_ctx) };

    let Some(ssl_context) = ctx
        .ssl()
        .and_then(SslRef::session_context)
        .map(ToOwned::to_owned)
    else {
        return 0;
    };
    let Some(verify) = ssl_context.callback::<F>(CallbackRole::Verify) else {
        return 0;
    };
    catch_native(|| c_int::from(verify(preverify_ok != 0, ctx))).unwrap_or(0)
}

pub(super) unsafe extern "C" fn raw_custom_verify<F>(
    ssl: *mut ffi::SSL,
    out_alert: *mut u8,
) -> ffi::ssl_verify_result_t
where
    F: Fn(&mut SslRef) -> Result<(), SslVerifyError> + 'static + Sync + Send,
{
    let callback = |ssl: &mut SslRef| {
        let context = ssl
            .session_context()
            .map(ToOwned::to_owned)
            .ok_or(SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR))?;
        let callback = context
            .callback::<F>(CallbackRole::CustomVerify)
            .ok_or(SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR))?;
        callback(ssl)
    };

    // SAFETY: The native custom verification callback supplies exclusive access to SSL and a writable alert slot; helper checks both.
    unsafe { raw_custom_verify_callback(ssl, out_alert, callback) }
}

pub(super) unsafe extern "C" fn raw_cert_verify<F>(
    x509_ctx: *mut ffi::X509_STORE_CTX,
    _arg: *mut c_void,
) -> c_int
where
    F: Fn(&mut X509StoreContextRef) -> bool + 'static + Sync + Send,
{
    // SAFETY: btls provides valid inputs.
    let ctx = unsafe { X509StoreContextRef::from_ptr_mut(x509_ctx) };

    let Some(ssl_context) = ctx.ssl().map(|ssl| ssl.ssl_context().to_owned()) else {
        return 0;
    };
    let Some(verify) = ssl_context.callback::<F>(CallbackRole::CertVerify) else {
        return 0;
    };
    catch_native(|| c_int::from(verify(ctx))).unwrap_or(0)
}

pub(super) unsafe extern "C" fn ssl_raw_custom_verify<F>(
    ssl: *mut ffi::SSL,
    out_alert: *mut u8,
) -> ffi::ssl_verify_result_t
where
    F: Fn(&mut SslRef) -> Result<(), SslVerifyError> + 'static + Sync + Send,
{
    let callback = |ssl: &mut SslRef| {
        let callback = ssl
            .callback::<Arc<F>>(CallbackRole::CustomVerify)
            .cloned()
            .ok_or(SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR))?;

        callback(ssl)
    };

    // SAFETY: The native SSL-specific custom verifier uses the same checked pointer and alert contracts.
    unsafe { raw_custom_verify_callback(ssl, out_alert, callback) }
}

unsafe fn raw_custom_verify_callback(
    ssl: *mut ffi::SSL,
    out_alert: *mut u8,
    callback: impl FnOnce(&mut SslRef) -> Result<(), SslVerifyError>,
) -> ffi::ssl_verify_result_t {
    if ssl.is_null() || out_alert.is_null() {
        return ffi::ssl_verify_result_t::ssl_verify_invalid;
    }
    // SAFETY: native verification owns exclusive access to the live SSL.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    match catch_native(|| callback(ssl)) {
        Some(Ok(())) => ffi::ssl_verify_result_t::ssl_verify_ok,
        Some(Err(SslVerifyError::Retry)) => ffi::ssl_verify_result_t::ssl_verify_retry,
        failure => {
            let alert = match failure {
                Some(Err(SslVerifyError::Invalid(alert))) => alert,
                _ => SslAlert::INTERNAL_ERROR,
            };
            // SAFETY: the caller supplies a writable alert output slot, which
            // need not have been initialized before this callback.
            unsafe { out_alert.write(u8::try_from(alert.0).unwrap_or(80)) };
            ffi::ssl_verify_result_t::ssl_verify_invalid
        }
    }
}

// Caller provides len exclusively writable bytes with a lifetime bounded
// by the synchronous native callback. Null is permitted only for empty output.
const unsafe fn native_output<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 {
        return Some(&mut []);
    }
    if ptr.is_null() || len > isize::MAX.unsigned_abs() {
        return None;
    }
    // SAFETY: the caller guarantees writable disjoint storage. Initialize it
    // before creating an initialized byte slice.
    unsafe {
        ptr.write_bytes(0, len);
        Some(slice::from_raw_parts_mut(ptr, len))
    }
}

fn psk_result(capacity: usize, callback: impl FnOnce() -> Result<usize, ErrorStack>) -> c_uint {
    catch_native(|| match callback() {
        Ok(written) if written <= capacity => c_uint::try_from(written).unwrap_or(0),
        Ok(_) => 0,
        Err(error) => {
            error.put();
            0
        }
    })
    .unwrap_or(0)
}

pub(super) unsafe extern "C" fn raw_client_psk<F>(
    ssl_ptr: *mut ffi::SSL,
    hint: *const c_char,
    identity: *mut c_char,
    max_identity_len: c_uint,
    psk: *mut c_uchar,
    max_psk_len: c_uint,
) -> c_uint
where
    F: Fn(&mut SslRef, Option<&[u8]>, &mut [u8], &mut [u8]) -> Result<usize, ErrorStack>
        + 'static
        + Sync
        + Send,
{
    if ssl_ptr.is_null() {
        return 0;
    }
    // SAFETY: the native callback exclusively borrows SSL and supplies a
    // readable NUL-terminated hint when present.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl_ptr) };
    let hint = if hint.is_null() {
        None
    } else {
        // SAFETY: A non-null PSK hint is a NUL-terminated native string valid for this callback invocation.
        Some(unsafe { CStr::from_ptr(hint) }.to_bytes())
    };
    let (Ok(identity_capacity), Ok(psk_capacity)) = (
        usize::try_from(max_identity_len),
        usize::try_from(max_psk_len),
    ) else {
        return 0;
    };
    // SAFETY: both native buffers are disjoint, writable output storage.
    let Some(identity) = (unsafe { native_output(identity.cast(), identity_capacity) }) else {
        return 0;
    };
    // SAFETY: psk describes the second exclusive native output allocation.
    let Some(psk) = (unsafe { native_output(psk, psk_capacity) }) else {
        return 0;
    };
    if identity.is_empty() {
        return 0;
    }
    psk_result(psk_capacity, || {
        let Some(context) = ssl.session_context().map(ToOwned::to_owned) else {
            return Ok(0);
        };
        let Some(callback) = context.callback::<F>(CallbackRole::PskClient) else {
            return Ok(0);
        };
        let len = callback(ssl, hint, identity, psk)?;
        Ok(if identity.contains(&0) { len } else { 0 })
    })
}

pub(super) unsafe extern "C" fn raw_server_psk<F>(
    ssl: *mut ffi::SSL,
    identity: *const c_char,
    psk: *mut c_uchar,
    max_psk_len: c_uint,
) -> c_uint
where
    F: Fn(&mut SslRef, Option<&[u8]>, &mut [u8]) -> Result<usize, ErrorStack>
        + 'static
        + Sync
        + Send,
{
    if ssl.is_null() {
        return 0;
    }
    // SAFETY: native handshake exclusively borrows SSL and supplies a
    // readable NUL-terminated identity when present.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let identity = if identity.is_null() {
        None
    } else {
        // SAFETY: A non-null peer PSK identity is a NUL-terminated string borrowed for this callback.
        Some(unsafe { CStr::from_ptr(identity) }.to_bytes())
    };
    let Ok(capacity) = usize::try_from(max_psk_len) else {
        return 0;
    };
    // SAFETY: the native caller provides capacity bytes of exclusive output.
    let Some(psk) = (unsafe { native_output(psk, capacity) }) else {
        return 0;
    };
    psk_result(capacity, || {
        let Some(context) = ssl.session_context().map(ToOwned::to_owned) else {
            return Ok(0);
        };
        let Some(callback) = context.callback::<F>(CallbackRole::PskServer) else {
            return Ok(0);
        };
        callback(ssl, identity, psk)
    })
}

pub(super) unsafe extern "C" fn ssl_raw_verify<F>(
    preverify_ok: c_int,
    x509_ctx: *mut ffi::X509_STORE_CTX,
) -> c_int
where
    F: Fn(bool, &mut X509StoreContextRef) -> bool + 'static + Sync + Send,
{
    // SAFETY: btls provides valid inputs.
    let ctx = unsafe { X509StoreContextRef::from_ptr_mut(x509_ctx) };

    let Some(callback) = ctx
        .ssl()
        .and_then(|ssl| ssl.callback::<Arc<F>>(CallbackRole::Verify).cloned())
    else {
        return 0;
    };
    catch_native(|| c_int::from(callback(preverify_ok != 0, ctx))).unwrap_or(0)
}

pub(super) unsafe extern "C" fn raw_sni<F>(
    ssl: *mut ffi::SSL,
    al: *mut c_int,
    arg: *mut c_void,
) -> c_int
where
    F: Fn(&mut SslRef, &mut SslAlert) -> Result<(), SniError> + 'static + Sync + Send,
{
    if ssl.is_null() || al.is_null() || arg.is_null() {
        return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    // SAFETY: SNI runs with exclusive access to the live SSL. BoringSSL
    // selects the callback from current context or original session context.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    // Hold the current context across a possible context switch in the callback.
    let _current_context = ssl.ssl_context().to_owned();
    // SAFETY: the callback arg is the registered stable boxed F, owned by
    // either the retained current context or the native session context.
    let callback = unsafe { &*arg.cast::<F>() };
    // SAFETY: BoringSSL initializes this alert to UNRECOGNIZED_NAME.
    let mut alert = SslAlert(unsafe { al.read() });
    let result = catch_native(|| callback(ssl, &mut alert));
    if result.is_none() {
        alert = SslAlert::INTERNAL_ERROR;
    }
    // SAFETY: the initialized alert slot is writable for the duration of SNI.
    unsafe { al.write(alert.0) };
    match result {
        Some(Ok(())) => ffi::SSL_TLSEXT_ERR_OK,
        Some(Err(error)) => error.0,
        None => ffi::SSL_TLSEXT_ERR_ALERT_FATAL,
    }
}

pub(super) unsafe extern "C" fn raw_ticket_key<F>(
    ssl: *mut ffi::SSL,
    key_name: *mut u8,
    iv: *mut u8,
    evp_ctx: *mut ffi::EVP_CIPHER_CTX,
    hmac_ctx: *mut ffi::HMAC_CTX,
    encrypt: c_int,
) -> c_int
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
    if ssl.is_null()
        || key_name.is_null()
        || iv.is_null()
        || evp_ctx.is_null()
        || hmac_ctx.is_null()
    {
        return TicketKeyCallbackResult::Error.into();
    }
    // SAFETY: ticket processing borrows the live SSL and provides initialized
    // uniquely borrowed cipher/HMAC contexts.
    let ssl = unsafe { SslRef::from_ptr(ssl) };
    // SAFETY: The cipher context is non-null and exclusively borrowed during ticket processing.
    let evp_ctx = unsafe { CipherCtxRef::from_ptr_mut(evp_ctx) };
    // SAFETY: The HMAC context is non-null, disjoint from the cipher context, and exclusive for this callback.
    let hmac_ctx = unsafe { HmacCtxRef::from_ptr_mut(hmac_ctx) };
    let key_name = key_name.cast::<[u8; 16]>();
    let iv = iv.cast::<[u8; ffi::EVP_MAX_IV_LENGTH as usize]>();
    let mode = match encrypt {
        1 => {
            // SAFETY: encryption receives writable output arrays which are
            // uninitialized on entry. Initialize each before mutable borrowing.
            unsafe {
                key_name.write([0; 16]);
                iv.write([0; ffi::EVP_MAX_IV_LENGTH as usize]);
                TicketKeyMode::Encrypt {
                    key_name: &mut *key_name,
                    iv: &mut *iv,
                }
            }
        }
        0 => {
            // SAFETY: decryption receives pointers into immutable ticket input
            // (native API const_casts them). Expose shared references only.
            unsafe {
                TicketKeyMode::Decrypt {
                    key_name: &*key_name,
                    iv: &*iv,
                }
            }
        }
        _ => return TicketKeyCallbackResult::Error.into(),
    };

    // BoringSSL always invokes the callback of the original session context,
    // even if SNI has switched the connection's current context.
    let result = catch_native(|| {
        let Some(callback) = ssl
            .session_context()
            .and_then(|ctx| ctx.callback::<F>(CallbackRole::TicketKey))
        else {
            return TicketKeyCallbackResult::Error;
        };
        callback(ssl, mode, evp_ctx, hmac_ctx)
    })
    .unwrap_or(TicketKeyCallbackResult::Error);
    if encrypt == 1 && result == TicketKeyCallbackResult::DecryptSuccessRenew {
        return TicketKeyCallbackResult::Error.into();
    }
    result.into()
}

pub(super) unsafe extern "C" fn raw_alpn_select<F>(
    ssl: *mut ffi::SSL,
    out: *mut *const c_uchar,
    outlen: *mut c_uchar,
    inbuf: *const c_uchar,
    inlen: c_uint,
    _arg: *mut c_void,
) -> c_int
where
    F: for<'a> Fn(&mut SslRef, &'a [u8]) -> Result<&'a [u8], AlpnError> + 'static + Sync + Send,
{
    if ssl.is_null() || out.is_null() || outlen.is_null() {
        return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    let Ok(inlen) = usize::try_from(inlen) else {
        return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
    };
    // SAFETY: native handshake owns SSL exclusively and supplies the readable
    // ALPN wire-format protocol list for the duration of this call.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    // SAFETY: The ALPN protocol list belongs to the native handshake and stays valid during the synchronous callback.
    let Some(protos) = (unsafe { native_input(inbuf, inlen) }) else {
        return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
    };
    let result = catch_native(|| {
        let context = ssl.ssl_context().to_owned();
        let Some(callback) = context.callback::<F>(CallbackRole::Alpn) else {
            return Err(AlpnError::ALERT_FATAL);
        };
        let selected = callback(ssl, protos)?;
        offered_protocol(protos, selected).ok_or(AlpnError::ALERT_FATAL)
    });

    match result {
        Some(Ok(proto)) => {
            let Ok(len) = u8::try_from(proto.len()) else {
                return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
            };
            // SAFETY: native output slots may be uninitialized. The selected
            // entry points into the caller's ALPN input, which outlives the callback.
            unsafe {
                out.write(proto.as_ptr());
                outlen.write(len);
            }
            ffi::SSL_TLSEXT_ERR_OK
        }
        Some(Err(error)) => error.0,
        None => ffi::SSL_TLSEXT_ERR_ALERT_FATAL,
    }
}

fn offered_protocol<'a>(mut offered: &'a [u8], selected: &[u8]) -> Option<&'a [u8]> {
    let mut matched = None;
    while let Some((&len, rest)) = offered.split_first() {
        if len == 0 {
            return None;
        }
        let (protocol, remaining) = rest.split_at_checked(usize::from(len))?;
        if protocol == selected {
            matched = Some(protocol);
        }
        offered = remaining;
    }
    matched
}

pub(super) unsafe extern "C" fn raw_select_cert<F>(
    client_hello: *const ffi::SSL_CLIENT_HELLO,
) -> ffi::ssl_select_cert_result_t
where
    F: Fn(ClientHello<'_>) -> Result<SelectCertAction, SelectCertError> + Sync + Send + 'static,
{
    // SAFETY: btls provides valid inputs.
    let client_hello = ClientHello(unsafe { &*client_hello });
    let ech_accepted = client_hello.ssl().ech_accepted();

    let ssl_context = client_hello.ssl().ssl_context().to_owned();
    let result = catch_native(|| {
        let Some(callback) = ssl_context.callback::<F>(CallbackRole::SelectCert) else {
            return Err(SelectCertError(
                ffi::ssl_select_cert_result_t::ssl_select_cert_error,
            ));
        };
        callback(client_hello)
    });
    match result {
        Some(Ok(SelectCertAction::Success)) => {
            ffi::ssl_select_cert_result_t::ssl_select_cert_success
        }
        Some(Ok(SelectCertAction::DisableEch)) if ech_accepted => {
            ffi::ssl_select_cert_result_t::ssl_select_cert_disable_ech
        }
        Some(Err(error)) => error.0,
        _ => ffi::ssl_select_cert_result_t::ssl_select_cert_error,
    }
}

pub(super) unsafe extern "C" fn raw_tlsext_status<F>(ssl: *mut ffi::SSL, _: *mut c_void) -> c_int
where
    F: Fn(&mut SslRef) -> Result<bool, ErrorStack> + 'static + Sync + Send,
{
    // SAFETY: btls provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };

    let ssl_context = ssl.ssl_context().to_owned();
    let ret = catch_native(|| {
        let Some(callback) = ssl_context.callback::<F>(CallbackRole::Status) else {
            return Err(ErrorStack::internal_error_str("missing OCSP callback"));
        };
        callback(ssl)
    })
    .unwrap_or_else(|| Err(ErrorStack::internal_error_str("OCSP callback panicked")));

    if ssl.is_server() {
        match ret {
            Ok(true) => ffi::SSL_TLSEXT_ERR_OK,
            Ok(false) => ffi::SSL_TLSEXT_ERR_NOACK,
            Err(e) => {
                e.put();
                ffi::SSL_TLSEXT_ERR_ALERT_FATAL
            }
        }
    } else {
        match ret {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(e) => {
                e.put();
                -1
            }
        }
    }
}

pub(super) unsafe extern "C" fn raw_new_session<F>(
    ssl: *mut ffi::SSL,
    session: *mut ffi::SSL_SESSION,
) -> c_int
where
    F: Fn(&mut SslRef, SslSession) + 'static + Sync + Send,
{
    // SAFETY: btls provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    // SAFETY: The BoringSSL new-session callback supplies an owned session reference for the Rust callback to consume.
    let session = unsafe { SslSession::from_ptr(session) };

    if let Some(context) = ssl.session_context().map(ToOwned::to_owned) {
        if let Some(callback) = context.callback::<F>(CallbackRole::NewSession) {
            catch_native(|| callback(ssl, session));
        }
    }
    // The Rust owner consumes the reference, even without a callback.
    1
}

pub(super) unsafe extern "C" fn raw_client_session(
    ssl: *mut ffi::SSL,
    session: *mut ffi::SSL_SESSION,
) -> c_int {
    // SAFETY: btls provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    // SAFETY: The new-session callback supplies an owned session reference, even when no application callback is registered.
    let session = unsafe { SslSession::from_ptr(session) };

    // Sessions from connections not created by `ConnectConfiguration::into_ssl` have no recorded
    // peer and are dropped.
    let Some(peer) = ssl.slot_data(&SESSION_PEER_INDEX).cloned() else {
        return 1;
    };
    let Some(context) = ssl.session_context().map(ToOwned::to_owned) else {
        return 1;
    };
    let Some(callback) = context.slot_data(&CLIENT_SESSION_INDEX) else {
        return 1;
    };
    let session = ClientSession::new(session, peer, ssl);
    catch_native(|| (callback.callback)(ssl, session));
    1
}

pub(super) unsafe extern "C" fn raw_remove_session<F>(
    ctx: *mut ffi::SSL_CTX,
    session: *mut ffi::SSL_SESSION,
) where
    F: Fn(&SslContextRef, &SslSessionRef) + 'static + Sync + Send,
{
    // SAFETY: btls provides valid inputs.
    let ctx = unsafe { SslContextRef::from_ptr(ctx) };
    // SAFETY: The removal callback borrows a session owned by the live native context; it must not be freed here.
    let session = unsafe { SslSessionRef::from_ptr(session) };

    let Some(callback) = ctx.callback::<F>(CallbackRole::RemoveSession) else {
        return;
    };

    catch_native(|| callback(ctx, session));
}

type DataPtr = *const c_uchar;

pub(super) unsafe extern "C" fn raw_get_session<F>(
    ssl: *mut ffi::SSL,
    data: DataPtr,
    len: c_int,
    copy: *mut c_int,
) -> *mut ffi::SSL_SESSION
where
    F: Fn(&mut SslRef, &[u8]) -> Result<Option<SslSession>, GetSessionPendingError>
        + 'static
        + Sync
        + Send,
{
    let Ok(len) = usize::try_from(len) else {
        return ptr::null_mut();
    };
    if ssl.is_null() || copy.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: native supplies the session ID and exclusively borrowed SSL.
    let Some(data) = (unsafe { native_input(data, len) }) else {
        return ptr::null_mut();
    };
    // SAFETY: The native session identifier is readable for the declared checked length and lifetime of the callback.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let Some(context) = ssl.session_context().map(ToOwned::to_owned) else {
        return ptr::null_mut();
    };
    let Some(callback) = context.callback::<F>(CallbackRole::GetSession) else {
        return ptr::null_mut();
    };
    match catch_native(|| callback(ssl, data)) {
        Some(Ok(Some(session))) => {
            // SAFETY: native supplies writable storage; transfer the owned reference.
            unsafe { copy.write(0) };
            session.into_ptr()
        }
        // SAFETY: Native session lookup exclusively borrows the live SSL pointer during the synchronous callback.
        Some(Err(GetSessionPendingError)) => unsafe { ffi::SSL_magic_pending_session_ptr() },
        _ => ptr::null_mut(),
    }
}

pub(super) unsafe extern "C" fn raw_keylog<F>(ssl: *const ffi::SSL, line: *const c_char)
where
    F: Fn(&SslRef, &str) + 'static + Sync + Send,
{
    // SAFETY: btls provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr(ssl.cast_mut()) };
    // SAFETY: BoringSSL exposes a sentinel pointer for an asynchronous pending-session lookup; it is not dereferenced.
    let line = unsafe { CStr::from_ptr(line).to_string_lossy() };

    let Some(callback) = ssl.ssl_context().callback::<F>(CallbackRole::Keylog) else {
        return;
    };

    catch_native(|| callback(ssl, &line));
}

pub(super) unsafe extern "C" fn raw_sign<M, const CREDENTIAL: bool>(
    ssl: *mut ffi::SSL,
    out: *mut u8,
    out_len: *mut usize,
    max_out: usize,
    signature_algorithm: u16,
    in_: *const u8,
    in_len: usize,
) -> ffi::ssl_private_key_result_t
where
    M: PrivateKeyMethod,
{
    // SAFETY: the native private-key callback supplies readable input for
    // the duration of the call.
    let Some(input) = (unsafe { native_input(in_, in_len) }) else {
        return PrivateKeyMethodError::FAILURE.0;
    };

    let signature_algorithm = SslSignatureAlgorithm(signature_algorithm);

    let callback = |method: &M, ssl: &mut _, output: &mut _| {
        method.sign(ssl, input, signature_algorithm, output)
    };

    // SAFETY: btls provides valid inputs.
    unsafe { raw_private_key_callback::<M, CREDENTIAL>(ssl, out, out_len, max_out, callback) }
}

pub(super) unsafe extern "C" fn raw_decrypt<M, const CREDENTIAL: bool>(
    ssl: *mut ffi::SSL,
    out: *mut u8,
    out_len: *mut usize,
    max_out: usize,
    in_: *const u8,
    in_len: usize,
) -> ffi::ssl_private_key_result_t
where
    M: PrivateKeyMethod,
{
    // SAFETY: the native private-key callback supplies readable input for
    // the duration of the call.
    let Some(input) = (unsafe { native_input(in_, in_len) }) else {
        return PrivateKeyMethodError::FAILURE.0;
    };

    let callback = |method: &M, ssl: &mut _, output: &mut _| method.decrypt(ssl, input, output);

    // SAFETY: btls provides valid inputs.
    unsafe { raw_private_key_callback::<M, CREDENTIAL>(ssl, out, out_len, max_out, callback) }
}

pub(super) unsafe extern "C" fn raw_complete<M, const CREDENTIAL: bool>(
    ssl: *mut ffi::SSL,
    out: *mut u8,
    out_len: *mut usize,
    max_out: usize,
) -> ffi::ssl_private_key_result_t
where
    M: PrivateKeyMethod,
{
    // SAFETY: btls provides valid inputs.
    unsafe { raw_private_key_callback::<M, CREDENTIAL>(ssl, out, out_len, max_out, M::complete) }
}

unsafe fn raw_private_key_callback<M, const CREDENTIAL: bool>(
    ssl: *mut ffi::SSL,
    out: *mut u8,
    out_len: *mut usize,
    max_out: usize,
    callback: impl FnOnce(&M, &mut SslRef, &mut [u8]) -> Result<usize, PrivateKeyMethodError>,
) -> ffi::ssl_private_key_result_t
where
    M: PrivateKeyMethod,
{
    if ssl.is_null()
        || out_len.is_null()
        || max_out > isize::MAX.unsigned_abs()
        || (max_out != 0 && out.is_null())
    {
        return PrivateKeyMethodError::FAILURE.0;
    }

    // SAFETY: the native callback holds exclusive use of SSL and provides a
    // writable length result and max_out bytes of disjoint output storage.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    // SAFETY: use a raw write, because the output length need not be initialized.
    unsafe { out_len.write(0) };
    // SAFETY: the native caller provides max_out writable disjoint bytes.
    let Some(output) = (unsafe { native_output(out, max_out) }) else {
        return PrivateKeyMethodError::FAILURE.0;
    };

    // Hold a separate Arc while calling application code, rather than borrow
    // data through an SSL/credential whose configuration the callback can change.
    let result = catch_native(|| {
        let method: Option<Arc<M>> = if CREDENTIAL {
            #[cfg(feature = "credential")]
            {
                // SAFETY: BoringSSL exposes the currently selected credential
                // for use during a private-key callback. Its typed ex-data
                // slot was allocated for Arc<M> by the credential builder.
                unsafe {
                    let cred = ffi::SSL_get0_selected_credential(ssl.as_ptr());
                    let index = super::SslCredential::registered_ex_index::<Arc<M>>()?;
                    if cred.is_null() {
                        return None;
                    }
                    ffi::SSL_CREDENTIAL_get_ex_data(cred, index.as_raw())
                        .cast::<Arc<M>>()
                        .as_ref()
                        .cloned()
                }
            }
            #[cfg(not(feature = "credential"))]
            {
                None
            }
        } else {
            ssl.ssl_context()
                .callback::<Arc<M>>(CallbackRole::PrivateKey)
                .cloned()
        };
        Some(callback(method.as_deref()?, ssl, output))
    })
    .flatten();

    match result {
        Some(Ok(written)) if written <= max_out => {
            // SAFETY: out_len is the native caller's writable output slot.
            unsafe { out_len.write(written) };
            ffi::ssl_private_key_result_t::ssl_private_key_success
        }
        Some(Err(err)) => err.0,
        _ => PrivateKeyMethodError::FAILURE.0,
    }
}

pub(super) unsafe extern "C" fn raw_info_callback<F>(
    ssl: *const ffi::SSL,
    mode: c_int,
    value: c_int,
) where
    F: Fn(&SslRef, SslInfoCallbackMode, SslInfoCallbackValue) + Send + Sync + 'static,
{
    // Due to FFI signature requirements we have to pass a *const SSL into this function, but
    // foreign-types requires a *mut SSL to get the Rust SslRef
    let mut_ref = ssl.cast_mut();

    // SAFETY: btls provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr(mut_ref) };
    let ssl_context = ssl.ssl_context();

    let Some(callback) = ssl_context.callback::<F>(CallbackRole::Info) else {
        return;
    };

    let value = match mode {
        ffi::SSL_CB_READ_ALERT | ffi::SSL_CB_WRITE_ALERT => {
            SslInfoCallbackValue::Alert(SslInfoCallbackAlert(value))
        }
        _ => SslInfoCallbackValue::Unit,
    };

    catch_native(|| callback(ssl, SslInfoCallbackMode(mode), value));
}

// Both native certificate-compression entry points need the same guarded
// callback lookup and borrowed input. The closure may only return a boolean:
// neither a borrowed native SSL value nor an input slice can escape this scope.
//
/// # Safety
/// Non-null SSL and input pointers must remain live and readable for this
/// synchronous native callback. A null input is allowed only for zero length.
unsafe fn with_certificate_compressor<C: CertificateCompressor>(
    ssl: *mut ffi::SSL,
    input: *const u8,
    input_len: usize,
    run: impl FnOnce(&C, &[u8]) -> bool,
) -> bool {
    if ssl.is_null() {
        return false;
    }
    // SAFETY: BoringSSL supplies a live exclusive SSL borrow for this callback.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let context = ssl.ssl_context();
    let Some(compressor) = context
        .callback::<Option<C>>(CallbackRole::Compression)
        .and_then(Option::as_ref)
    else {
        return false;
    };
    // SAFETY: The native caller provides the input for this synchronous callback;
    // native_input checks its bounds and the null/empty representation.
    let Some(data) = (unsafe { native_input(input, input_len) }) else {
        return false;
    };
    catch_native(|| run(compressor, data)).unwrap_or(false)
}

pub(super) unsafe extern "C" fn raw_ssl_cert_compress<C>(
    ssl: *mut ffi::SSL,
    out: *mut ffi::CBB,
    input: *const u8,
    input_len: usize,
) -> ::std::os::raw::c_int
where
    C: CertificateCompressor,
{
    const {
        assert!(C::CAN_COMPRESS);
    }

    if ssl.is_null() || out.is_null() {
        return 0;
    }
    let mut writer = CryptoByteBuilder::from_ptr(out);
    // SAFETY: Native SSL and input are live for the synchronous callback;
    // the output CBB is non-null and exclusively writable during compression.
    if !unsafe {
        with_certificate_compressor::<C>(ssl, input, input_len, |compressor, data| {
            compressor.compress(data, &mut writer).is_ok()
        })
    } {
        return 0;
    }

    1
}

pub(super) unsafe extern "C" fn raw_ssl_cert_decompress<C>(
    ssl: *mut ffi::SSL,
    out: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    input: *const u8,
    input_len: usize,
) -> ::std::os::raw::c_int
where
    C: CertificateCompressor,
{
    const {
        assert!(C::CAN_DECOMPRESS);
    }

    if ssl.is_null() || out.is_null() {
        return 0;
    }
    // SAFETY: Native SSL and input remain live for the synchronous callback.
    // Constructing the output only after validating the callback and input avoids
    // allocating the advertised decompressed size for malformed native input.
    if !unsafe {
        with_certificate_compressor::<C>(ssl, input, input_len, |compressor, data| {
            let Ok(mut buffer) = CryptoBufferBuilder::with_capacity(uncompressed_len) else {
                return false;
            };
            if compressor.decompress(data, &mut buffer).is_err() {
                return false;
            }
            let Ok(crypto_buffer) = buffer.build() else {
                return false;
            };
            // SAFETY: The native callback supplies a writable non-null output
            // slot. Ownership transfers only after a fully initialized buffer.
            unsafe { out.write(crypto_buffer) };
            true
        })
    } {
        return 0;
    }

    1
}

struct CryptoByteBuilder<'a>(*mut ffi::CBB, std::marker::PhantomData<&'a [u8]>);

impl CryptoByteBuilder<'_> {
    const fn from_ptr(ptr: *mut ffi::CBB) -> Self {
        Self(ptr, std::marker::PhantomData)
    }
}

impl std::io::Write for CryptoByteBuilder<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // SAFETY: The native CBB remains live and exclusively borrowed while writing the initialized Rust byte slice.
        let success = unsafe { ffi::CBB_add_bytes(self.0, buf.as_ptr(), buf.len()) == 1 };
        if !success {
            return Err(std::io::Error::other("CBB_add_bytes failed"));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // SAFETY: The native CBB remains live and exclusively borrowed while flushing its pending bytes.
        let success = unsafe { ffi::CBB_flush(self.0) == 1 };
        if !success {
            return Err(std::io::Error::other("CBB_flush failed"));
        }
        Ok(())
    }
}

// Own the native allocation until exactly its declared length has been
// initialized. A write-only cursor avoids constructing an initialized slice
// over CRYPTO_BUFFER_alloc's uninitialized memory.
struct CryptoBufferBuilder {
    buffer: *mut ffi::CRYPTO_BUFFER,
    data: *mut u8,
    capacity: usize,
    written: usize,
}

impl CryptoBufferBuilder {
    fn with_capacity(capacity: usize) -> Result<Self, ErrorStack> {
        if capacity > isize::MAX.unsigned_abs() {
            return Err(ErrorStack::internal_error_str(
                "certificate buffer too large",
            ));
        }
        let mut data = ptr::null_mut();
        // SAFETY: native allocation writes the data pointer and returns an owned buffer.
        let buffer = unsafe { crate::cvt_p(ffi::CRYPTO_BUFFER_alloc(&raw mut data, capacity))? };
        let owner = Self {
            buffer,
            data,
            capacity,
            written: 0,
        };
        if capacity != 0 && data.is_null() {
            return Err(ErrorStack::internal_error_str(
                "missing certificate buffer storage",
            ));
        }
        Ok(owner)
    }

    fn build(mut self) -> Result<*mut ffi::CRYPTO_BUFFER, ErrorStack> {
        if self.written != self.capacity {
            return Err(ErrorStack::internal_error_str(
                "incomplete certificate decompression",
            ));
        }
        Ok(mem::replace(&mut self.buffer, ptr::null_mut()))
    }
}

impl std::io::Write for CryptoBufferBuilder {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let count = input.len().min(self.capacity - self.written);
        if count != 0 {
            // SAFETY: the owned native allocation is exclusively writable.
            // The checked count stays inside it; the safe input cannot borrow it.
            unsafe { ptr::copy_nonoverlapping(input.as_ptr(), self.data.add(self.written), count) };
            self.written += count;
        }
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for CryptoBufferBuilder {
    fn drop(&mut self) {
        if !self.buffer.is_null() {
            // SAFETY: the owner has not transferred the native buffer to BoringSSL.
            unsafe { ffi::CRYPTO_BUFFER_free(self.buffer) };
        }
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use std::mem::MaybeUninit;

    #[test]
    fn decompression_requires_complete_initialized_buffer() {
        use std::io::Write;
        let mut short = CryptoBufferBuilder::with_capacity(4).unwrap();
        short.write_all(b"ab").unwrap();
        assert!(short.build().is_err());

        let mut exact = CryptoBufferBuilder::with_capacity(4).unwrap();
        exact.write_all(b"ab").unwrap();
        assert_eq!(exact.write(b"cdef").unwrap(), 2);
        assert_eq!(exact.write(b"excess").unwrap(), 0);
        let buffer = exact.build().unwrap();
        // SAFETY: build transferred ownership only after all four bytes were initialized.
        unsafe {
            assert_eq!(
                slice::from_raw_parts(ffi::CRYPTO_BUFFER_data(buffer), 4),
                b"abcd"
            );
            ffi::CRYPTO_BUFFER_free(buffer);
        }
    }

    #[test]
    fn initialized_callback_output_and_result_bounds() {
        let mut bytes = MaybeUninit::<[u8; 8]>::uninit();
        // SAFETY: this local storage is exclusively writable for eight bytes.
        let output = unsafe { native_output(bytes.as_mut_ptr().cast(), 8) }.unwrap();
        assert_eq!(output, &[0; 8]);
        assert_eq!(psk_result(output.len(), || Ok(1)), 1);
        assert_eq!(psk_result(output.len(), || Ok(output.len() + 1)), 0);
        assert_eq!(
            psk_result(output.len(), || panic!("PSK application panic")),
            0
        );
    }

    #[test]
    fn alpn_selection_requires_whole_valid_offer() {
        let offered = b"\x02h2\x08http/1.1";
        assert_eq!(offered_protocol(offered, b"h2"), Some(&offered[1..3]));
        assert_eq!(offered_protocol(offered, b"http/1.1"), Some(&offered[4..]));
        assert!(offered_protocol(offered, b"http").is_none());
        assert!(offered_protocol(b"\x02h2\x00", b"h2").is_none());
        assert!(offered_protocol(b"\x02h2\x05abc", b"h2").is_none());
    }
}
