use super::server::Server;
use crate::ssl::SslRef;
use crate::ssl::{ErrorCode, HandshakeError, SslAlert, SslVerifyMode};
use crate::x509::X509StoreContext;
use crate::{hash::MessageDigest, ssl::SslVerifyError};
use hex;
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn untrusted_callback_override_bad() {
    let mut server = Server::builder();

    server.err_cb(|err| {
        let HandshakeError::Failure(handshake) = err else {
            panic!("expected failure error");
        };

        assert_eq!(
            handshake.error().to_string(),
            "[SSLV3_ALERT_CERTIFICATE_REVOKED]"
        );
    });

    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_custom_verify_callback(SslVerifyMode::PEER, |_| {
            Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_REVOKED))
        })
        .unwrap();

    client.connect_err();
}

#[test]
fn untrusted_callback_override_ok() {
    let server = Server::builder().build();
    let mut client = server.client();

    client
        .ctx()
        .set_custom_verify_callback(SslVerifyMode::PEER, |ssl| {
            assert!(ssl.peer_cert_chain().is_some());

            Ok(())
        })
        .unwrap();

    client.connect();
}

#[test]
fn untrusted_with_set_cert() {
    let mut server = Server::builder();

    server.should_error();

    let server = server.build();
    let mut client = server.client();

    client
        .ctx()
        .set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            let store = ssl.ssl_context().cert_store().unwrap();
            let cert = ssl.peer_certificate().unwrap();
            let cert_chain = ssl.peer_cert_chain().unwrap();

            assert_eq!(store.objects_len(), 0);

            X509StoreContext::new()
                .unwrap()
                .init(store, &cert, cert_chain, |store_ctx| {
                    assert!(!store_ctx.verify_cert().unwrap());
                    assert!(store_ctx.verify_result().is_err());

                    Ok(())
                })
                .unwrap();

            Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))
        })
        .unwrap();

    client.connect_err();
}

#[test]
fn trusted_with_set_cert() {
    let server = Server::builder().build();
    let mut client = server.client_with_root_ca();

    client
        .ctx()
        .set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            let store = ssl.ssl_context().cert_store().unwrap();
            let cert = ssl.peer_certificate().unwrap();
            let cert_chain = ssl.peer_cert_chain().unwrap();

            assert_eq!(store.objects_len(), 1);

            X509StoreContext::new()
                .unwrap()
                .init(store, &cert, cert_chain, |store_ctx| {
                    assert!(store_ctx.verify_cert().unwrap());
                    assert_eq!(store_ctx.verify_result(), Ok(()));

                    Ok(())
                })
                .unwrap();

            Ok(())
        })
        .unwrap();

    client.connect();
}

#[test]
fn trusted_callback_override_ok() {
    let server = Server::builder().build();
    let mut client = server.client_with_root_ca();

    client
        .ctx()
        .set_custom_verify_callback(SslVerifyMode::PEER, |ssl| {
            assert!(ssl.peer_certificate().is_some());

            Ok(())
        })
        .unwrap();

    client.connect();
}

#[test]
fn trusted_callback_override_bad() {
    let mut server = Server::builder();

    server.should_error();

    let server = server.build();
    let mut client = server.client_with_root_ca();

    client
        .ctx()
        .set_custom_verify_callback(SslVerifyMode::PEER, |_| {
            Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))
        })
        .unwrap();

    client.connect_err();
}

fn check_peer_digest(ssl: &mut SslRef) -> Result<(), SslVerifyError> {
    let cert = ssl.peer_certificate().unwrap();
    let digest = cert.digest(MessageDigest::sha1()).unwrap();
    assert_eq!(hex::encode(digest), super::TEST_CERT_DIGEST);
    Ok(())
}

#[test]
fn callback() {
    static CALLED_BACK: AtomicBool = AtomicBool::new(false);
    let server = Server::builder().build();
    let mut client = server.client();
    client
        .ctx()
        .set_verify_callback(SslVerifyMode::PEER, |_, _| {
            panic!("verify callback should not be called");
        })
        .unwrap();
    client
        .ctx()
        .set_custom_verify_callback(SslVerifyMode::PEER, |ssl| {
            CALLED_BACK.store(true, Ordering::SeqCst);
            check_peer_digest(ssl)
        })
        .unwrap();
    client.connect();
    assert!(CALLED_BACK.load(Ordering::SeqCst));
}

#[test]
fn ssl_callback() {
    static CALLED_BACK: AtomicBool = AtomicBool::new(false);
    let server = Server::builder().build();
    let mut client = server.client().build().builder();
    client
        .ssl()
        .set_verify_callback(SslVerifyMode::PEER, |_, _| {
            panic!("verify callback should not be called");
        })
        .unwrap();
    client
        .ssl()
        .set_custom_verify_callback(SslVerifyMode::PEER, |ssl| {
            CALLED_BACK.store(true, Ordering::SeqCst);
            check_peer_digest(ssl)
        })
        .unwrap();
    client.connect();
    assert!(CALLED_BACK.load(Ordering::SeqCst));
}

#[test]
fn both_callback() {
    static CALLED_BACK: AtomicBool = AtomicBool::new(false);
    let server = Server::builder().build();
    let mut client = server.client();

    client
        .ctx()
        .set_custom_verify_callback(SslVerifyMode::PEER, |_| {
            panic!("verify callback should not be called");
        })
        .unwrap();

    let mut client = client.build().builder();
    let expected = super::TEST_CERT_DIGEST;

    client
        .ssl()
        .set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            CALLED_BACK.store(true, Ordering::SeqCst);

            let cert = ssl.peer_certificate().unwrap();
            let digest = cert.digest(MessageDigest::sha1()).unwrap();

            assert_eq!(hex::encode(digest), expected);

            Ok(())
        })
        .unwrap();

    client.connect();
    assert!(CALLED_BACK.load(Ordering::SeqCst));
}

#[test]
fn retry() {
    let mut server = Server::builder();

    server.err_cb(|err| {
        let HandshakeError::Failure(handshake) = err else {
            panic!("expected failure error");
        };

        assert_eq!(
            handshake.error().to_string(),
            "[SSLV3_ALERT_CERTIFICATE_REVOKED]"
        );
    });

    let server = server.build();
    let mut client = server.client();
    static CALLED_BACK: AtomicBool = AtomicBool::new(false);

    client
        .ctx()
        .set_custom_verify_callback(SslVerifyMode::PEER, move |_| {
            if !CALLED_BACK.swap(true, Ordering::SeqCst) {
                return Err(SslVerifyError::Retry);
            }

            Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_REVOKED))
        })
        .unwrap();

    let HandshakeError::WouldBlock(handshake) = client.connect_err() else {
        panic!("should be WouldBlock");
    };

    assert!(CALLED_BACK.load(Ordering::SeqCst));
    assert!(handshake.error().would_block());
    assert_eq!(handshake.error().code(), ErrorCode::WANT_CERTIFICATE_VERIFY);
    handshake.handshake().unwrap_err();
}

#[test]
fn copied_custom_verifier_survives_context_switch() {
    use crate::ssl::{SslContextBuilder, SslMethod};
    use std::sync::Arc;

    fn policy(
        called: Arc<AtomicBool>,
        accept: bool,
    ) -> impl Fn(&mut SslRef) -> Result<(), SslVerifyError> {
        move |ssl| {
            called.store(true, Ordering::SeqCst);
            if accept {
                check_peer_digest(ssl)
            } else {
                Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))
            }
        }
    }

    let called = Arc::new(AtomicBool::new(false));
    let replacement_called = Arc::new(AtomicBool::new(false));
    let server = Server::builder().build();
    let mut client = server.client();
    client
        .ctx()
        .set_custom_verify_callback(SslVerifyMode::PEER, policy(called.clone(), true))
        .unwrap();
    let mut replacement = SslContextBuilder::new(SslMethod::tls()).unwrap();
    replacement
        .set_custom_verify_callback(
            SslVerifyMode::PEER,
            policy(replacement_called.clone(), false),
        )
        .unwrap();
    let replacement = replacement.build();
    let mut client = client.build().builder();
    client.ssl().set_ssl_context(&replacement).unwrap();
    client.connect();
    assert!(called.load(Ordering::SeqCst));
    assert!(!replacement_called.load(Ordering::SeqCst));
}
