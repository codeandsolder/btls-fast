use std::io::Write;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ssl::test::server::Server;
use crate::ssl::{
    ErrorCode, GetSessionPendingError, HandshakeError, SessionEncoding, Ssl, SslContext,
    SslContextBuilder, SslMethod, SslOptions, SslSession, SslSessionCacheMode, SslVersion,
};

#[test]
fn idle_session() {
    let ctx = SslContext::builder(SslMethod::tls()).unwrap().build();
    let ssl = Ssl::new(&ctx).unwrap();
    assert!(ssl.session().is_none());
}

#[test]
fn active_session() {
    let server = Server::builder().build();

    let s = server.client().connect();

    let session = s.ssl().session().unwrap();
    let len = session.secret_len();
    assert!(len > 0);
    let mut short = vec![0x5a; len - 1];
    assert!(session.copy_secret(&mut short).is_err());
    assert!(short.iter().all(|&byte| byte == 0x5a));
    let mut full = vec![0x5a; len + 1];
    assert_eq!(session.copy_secret(&mut full).unwrap().len(), len);
    assert_eq!(full[len], 0x5a);
    let mut exact = vec![0; len];
    assert_eq!(session.copy_secret(&mut exact).unwrap(), &full[..len]);
    crate::util::cleanse(&mut full);
    crate::util::cleanse(&mut exact);
}

#[test]
fn unresumable_session_cannot_be_encoded() {
    let mut server = Server::builder();
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    // SAFETY: the exclusively owned context is configured before publication.
    unsafe {
        assert_eq!(
            crate::ffi::SSL_CTX_set_num_tickets(server.ctx().as_ptr(), 0),
            1
        );
    }
    let server = server.build();
    let stream = server.client().connect();
    let session = stream.ssl().session().unwrap();
    assert!(!session.is_resumable());
    assert!(session.to_bytes().is_err());
}

#[test]
fn new_get_session_callback() {
    static FOUND_SESSION: AtomicBool = AtomicBool::new(false);
    static SERVER_SESSION_DER: OnceLock<SessionEncoding> = OnceLock::new();
    static CLIENT_SESSION_DER: OnceLock<SessionEncoding> = OnceLock::new();

    let mut server = Server::builder();

    server.expected_connections_count(2);
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    server.ctx().set_options(SslOptions::NO_TICKET);
    server
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::SERVER | SslSessionCacheMode::NO_INTERNAL);
    server
        .ctx()
        .set_new_session_callback(|_, session| {
            SERVER_SESSION_DER.set(session.to_bytes().unwrap()).unwrap();
        })
        .unwrap();
    unsafe {
        server
            .ctx()
            .set_get_session_callback(|ssl, id| {
                let Some(der) = SERVER_SESSION_DER.get() else {
                    return Ok(None);
                };

                let session = SslSession::from_bytes(ssl.ssl_context(), der).unwrap();

                FOUND_SESSION.store(true, Ordering::SeqCst);

                assert_eq!(id, session.id());

                Ok(Some(session))
            })
            .unwrap();
    }
    server.ctx().set_session_id_context(b"foo").unwrap();

    let server = server.build();

    let mut client = server.client();

    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    client
        .ctx()
        .set_new_session_callback(|_, session| {
            CLIENT_SESSION_DER.set(session.to_bytes().unwrap()).unwrap();
        })
        .unwrap();

    let client = client.build();

    client.builder().connect();

    assert!(CLIENT_SESSION_DER.get().is_some());
    assert!(SERVER_SESSION_DER.get().is_some());
    assert!(!FOUND_SESSION.load(Ordering::SeqCst));

    let mut ssl_builder = client.builder();
    let encoded = CLIENT_SESSION_DER.get().unwrap();
    let decoded = SslSession::from_bytes(ssl_builder.ssl().ssl_context(), encoded).unwrap();
    assert_eq!(decoded.to_bytes().unwrap().as_bytes(), encoded.as_bytes());
    assert!(format!("{encoded:?}").contains("[redacted]"));

    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(SslSession::from_bytes(ssl_builder.ssl().ssl_context(), &trailing).is_err());
    crate::util::cleanse(&mut trailing);
    assert!(SslSession::from_bytes(ssl_builder.ssl().ssl_context(), b"NOT RESUMABLE").is_err());

    // SAFETY: this buffer-only context is used only for session parsing,
    // not to authenticate a connection.
    let buffer_method = unsafe { SslMethod::tls_with_buffer() };
    let buffer_ctx = SslContext::builder(buffer_method).unwrap().build();
    let buffered = SslSession::from_bytes(&buffer_ctx, encoded).unwrap();
    assert_eq!(buffered.to_bytes().unwrap().as_bytes(), encoded.as_bytes());
    // SAFETY: both native sessions are live; the X.509 getter returns null
    // when the destination certificate method does not parse certificates.
    unsafe {
        use foreign_types::ForeignTypeRef;
        assert!(!crate::ffi::SSL_SESSION_get0_peer(decoded.as_ptr()).is_null());
        assert!(crate::ffi::SSL_SESSION_get0_peer(buffered.as_ptr()).is_null());
        assert!(ssl_builder.ssl().set_session(&buffered).is_err());
        assert!(ssl_builder.ssl().session().is_none());
        ssl_builder.ssl().set_session(&decoded).unwrap();
        assert!(ssl_builder.ssl().set_session(&buffered).is_err());
        assert_eq!(
            ssl_builder.ssl().session().unwrap().as_ptr(),
            decoded.as_ptr()
        );
    }

    let mut resumed = ssl_builder.connect();
    assert!(resumed.ssl().session_reused());
    // SAFETY: decoded is authenticated for this connection. The native
    // state check rejects installation after the completed handshake.
    unsafe {
        assert!(resumed.ssl_mut().set_session(&decoded).is_err());
    }
    assert!(resumed.ssl().session_reused());

    assert!(FOUND_SESSION.load(Ordering::SeqCst));
}

#[test]
fn new_get_session_callback_pending() {
    static CALLED_SERVER_CALLBACK: AtomicBool = AtomicBool::new(false);

    let mut server = Server::builder();

    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    server.ctx().set_options(SslOptions::NO_TICKET);
    server
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::SERVER | SslSessionCacheMode::NO_INTERNAL);
    unsafe {
        server
            .ctx()
            .set_get_session_callback(|_, _| {
                if !CALLED_SERVER_CALLBACK.swap(true, Ordering::SeqCst) {
                    return Err(GetSessionPendingError);
                }

                Ok(None)
            })
            .unwrap();
    }
    server.ctx().set_session_id_context(b"foo").unwrap();
    server.err_cb(|error| {
        let HandshakeError::WouldBlock(mid_handshake) = error else {
            panic!("should be WouldBlock");
        };

        assert!(mid_handshake.error().would_block());
        assert_eq!(mid_handshake.error().code(), ErrorCode::PENDING_SESSION);

        let mut socket = mid_handshake.handshake().unwrap();

        socket.write_all(&[0]).unwrap();
    });

    let server = server.build();

    let mut client = server.client();

    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);

    client.connect();
}

#[test]
fn new_session_callback_swapped_ctx() {
    static CALLED_BACK: AtomicBool = AtomicBool::new(false);

    let mut server = Server::builder();
    server.ctx().set_session_id_context(b"foo").unwrap();

    let server = server.build();

    let mut client = server.client();

    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
    client
        .ctx()
        .set_new_session_callback(|_, _| CALLED_BACK.store(true, Ordering::SeqCst))
        .unwrap();

    let mut client = client.build().builder();

    let ctx = SslContextBuilder::new(SslMethod::tls()).unwrap().build();
    client.ssl().set_ssl_context(&ctx).unwrap();

    client.connect();

    assert!(CALLED_BACK.load(Ordering::SeqCst));
}

#[test]
fn session_cache_size() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_session_cache_size(1234);
    let ctx = ctx.build();
    assert_eq!(ctx.session_cache_size(), 1234);
}
