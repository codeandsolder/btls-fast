use std::io::Read;
use std::sync::{Arc, Mutex};

use super::server::Server;
use crate::error::ErrorStack;
use crate::ssl::{
    ErrorCode, HandshakeError, SessionLookupError, Ssl, SslContext, SslMethod, SslOptions,
    SslSessionCacheMode, SslVersion,
};

#[test]
fn shared_cache_membership_and_destruction_notifications() {
    let removed = Arc::new(Mutex::new(Vec::new()));
    let issued = Arc::new(Mutex::new(None));
    let context = Arc::new(Mutex::new(None));
    let mut server = Server::builder();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    server.ctx().set_options(SslOptions::NO_TICKET);
    server
        .ctx()
        .set_session_id_context(b"shared server")
        .unwrap();

    let removed_in_callback = Arc::clone(&removed);
    server
        .ctx()
        .set_remove_session_callback(move |session| {
            removed_in_callback.lock().unwrap().push(session.to_owned());
        })
        .unwrap();
    let issued_in_callback = Arc::clone(&issued);
    server
        .ctx()
        .set_new_session_callback(move |_, session| {
            *issued_in_callback.lock().unwrap() = Some(session);
        })
        .unwrap();
    let context_in_callback = Arc::clone(&context);
    server.io_cb(move |stream| {
        *context_in_callback.lock().unwrap() = Some(stream.ssl().session_context().to_owned());
    });

    let server = server.build();
    let mut client = server.client().connect();
    client.read_exact(&mut [0]).unwrap();
    drop(client);
    drop(server);
    let ctx = context.lock().unwrap().take().unwrap();
    let session = issued.lock().unwrap().take().unwrap();
    assert_eq!(ctx.session_count(), 1);
    let mut other = SslContext::builder(SslMethod::tls()).unwrap();
    other.set_session_id_context(b"shared server").unwrap();
    let other = other.build();

    // SAFETY: this test deliberately shares the authenticated session
    // namespace between the two server contexts.
    unsafe {
        assert!(other.add_session(&session));
    }
    assert_eq!(other.session_count(), 1);
    assert!(ctx.remove_session(&session));
    assert!(!ctx.remove_session(&session));
    assert_eq!(ctx.session_count(), 0);
    assert_eq!(other.session_count(), 1);

    // SAFETY: this is the same context and authentication scope which
    // issued the session.
    unsafe {
        assert!(ctx.add_session(&session));
    }
    drop(ctx);
    let removed = removed.lock().unwrap();
    assert_eq!(removed.len(), 2);
    assert!(removed.iter().all(|value| value.id() == session.id()));
    assert_eq!(other.session_count(), 1);
    other.flush_sessions(0);
    assert_eq!(other.session_count(), 0);
}

#[test]
fn lookup_failures_are_distinct_from_misses() {
    // All four forms of failure must reach the server error queue instead of
    // triggering a successful full handshake.
    for failure in [
        "sync error",
        "panic",
        "async creation",
        "async without waker",
    ] {
        let mut server = Server::builder();
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
            .set_session_id_context(b"lookup errors")
            .unwrap();
        // SAFETY: these callbacks never supply a session, so no resumption
        // authentication claim is made.
        unsafe {
            match failure {
                "sync error" => server
                    .ctx()
                    .set_get_session_callback(|_, _| {
                        Err(SessionLookupError::Failed(ErrorStack::internal_error_str(
                            "lookup failed",
                        )))
                    })
                    .unwrap(),
                "panic" => server
                    .ctx()
                    .set_get_session_callback(|_, _| panic!("lookup panicked"))
                    .unwrap(),
                "async creation" => {
                    server.ssl_cb(|ssl| {
                        ssl.set_task_waker(Some(std::task::Waker::noop().clone()))
                            .unwrap()
                    });
                    server
                        .ctx()
                        .set_async_get_session_callback(|_, _| {
                            Err(ErrorStack::internal_error_str("lookup creation failed"))
                        })
                        .unwrap();
                }
                _ => server
                    .ctx()
                    .set_async_get_session_callback(|_, _| {
                        panic!("lookup must not start without a task waker")
                    })
                    .unwrap(),
            }
        }
        let expected = match failure {
            "sync error" => "lookup failed",
            "panic" => "session lookup callback panicked",
            "async creation" => "lookup creation failed",
            _ => "async TLS callback requires a task waker",
        };
        server.err_cb(move |error| {
            let HandshakeError::Failure(stream) = error else {
                panic!("unexpected lookup error: {error}");
            };
            assert_eq!(stream.error().code(), ErrorCode::SSL);
            assert!(
                stream.error().to_string().contains(expected),
                "{}",
                stream.error()
            );
        });
        let server = server.build();
        let ctx = SslContext::builder(SslMethod::tls()).unwrap().build();
        assert!(
            Ssl::new(&ctx)
                .unwrap()
                .connect(server.connect_tcp())
                .is_err()
        );
    }
}
