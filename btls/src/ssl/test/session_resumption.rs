use super::server::Server;
use crate::asn1::Asn1Time;
use crate::bn::BigNum;
use crate::error::ErrorStack;
use crate::pkey::PKey;
use crate::sign::Signer;
use crate::ssl::ClientSession;
use crate::ssl::ConnectConfiguration;
use crate::ssl::SslMethod;
use crate::ssl::SslRef;
use crate::ssl::SslSession;
use crate::ssl::SslSessionCacheMode;
use crate::ssl::SslVerifyError;
use crate::ssl::SslVerifyMode;
use crate::ssl::SslVersion;
use crate::ssl::test::MessageDigest;
use crate::ssl::{SslConnector, SslConnectorBuilder};
use crate::ssl::{TicketKey, TicketKeyProvider, TicketRenewal};
use crate::x509::extension::SubjectAlternativeName;
use crate::x509::{X509, X509Name};
use std::fs;
use std::io::Read;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn resume_session() {
    static SESSION_TICKET: OnceLock<SslSession> = OnceLock::new();
    static NST_RECIEVED_COUNT: AtomicU8 = AtomicU8::new(0);

    let mut server = Server::builder();
    server.expected_connections_count(2);
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    client
        .ctx()
        .set_new_session_callback(|_, session| {
            NST_RECIEVED_COUNT.fetch_add(1, Ordering::SeqCst);
            // The server sends multiple session tickets but we only care to retrieve one.
            let _ = SESSION_TICKET.set(session);
        })
        .unwrap();
    let ssl_stream = client.connect();

    assert!(!ssl_stream.ssl().session_reused());
    assert!(SESSION_TICKET.get().is_some());
    assert_eq!(NST_RECIEVED_COUNT.load(Ordering::SeqCst), 2);

    // Retrieve the session ticket
    let session_ticket = SESSION_TICKET.get().unwrap();

    // Attempt to resume the connection using the session ticket
    let client_2 = server.client();
    let mut ssl_builder = client_2.build().builder();
    unsafe { ssl_builder.ssl().set_session(session_ticket).unwrap() };
    let ssl_stream_2 = ssl_builder.connect();

    assert!(ssl_stream_2.ssl().session_reused());
}

#[test]
fn client_session_cache_apis() {
    let mut server = Server::builder();
    server.expected_connections_count(2);
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    let server = server.build();

    let sessions = Arc::new(Mutex::new(Vec::new()));
    let callback_sessions = Arc::clone(&sessions);
    let verify_count = Arc::new(AtomicU8::new(0));
    let callback_verify_count = Arc::clone(&verify_count);

    let mut client = server.client();
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
    let _ = client.ctx().set_session_timeout(60);
    assert_eq!(client.ctx().set_session_timeout(120), 60);
    client.ctx().set_reverify_on_resume(true);
    client
        .ctx()
        .set_custom_verify_callback(SslVerifyMode::PEER, move |_| {
            callback_verify_count.fetch_add(1, Ordering::SeqCst);
            Ok::<_, SslVerifyError>(())
        })
        .unwrap();
    client
        .ctx()
        .set_new_session_callback(move |_, session| {
            callback_sessions.lock().unwrap().push(session);
        })
        .unwrap();
    let client = client.build();

    let first = client.builder().connect();
    assert!(!first.ssl().session_reused());
    assert_eq!(verify_count.load(Ordering::SeqCst), 1);

    let mut sessions = sessions.lock().unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|session| session.should_be_single_use())
    );
    let session = sessions.pop().unwrap();
    drop(sessions);
    assert!(session.should_be_single_use());
    let session_without_early_data = session.copy_without_early_data().unwrap();
    assert_eq!(
        session.to_der().unwrap(),
        session_without_early_data.to_der().unwrap()
    );

    let mut resumed = client.builder();
    // SAFETY: The session was created by this client's SSL_CTX, and the new handshake has not
    // started.
    unsafe { resumed.ssl().set_session(&session).unwrap() };
    let resumed = resumed.connect();
    assert!(resumed.ssl().session_reused());
    assert_eq!(verify_count.load(Ordering::SeqCst), 2);
}

#[test]
fn resume_reverification_rejects_disabled_verification() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let mut server = Server::builder();
        server.expected_connections_count(2);
        server.should_error_when(|attempt| attempt == 1);
        server.ctx().set_min_proto_version(Some(version)).unwrap();
        server.ctx().set_max_proto_version(Some(version)).unwrap();
        let server = server.build();

        let sessions = Arc::new(Mutex::new(Vec::new()));
        let issued = Arc::clone(&sessions);
        let calls = Arc::new(AtomicU8::new(0));
        let observed = Arc::clone(&calls);
        let mut client = server.client_with_root_ca();
        client.ctx().set_reverify_on_resume(true);
        client
            .ctx()
            .set_session_cache_mode(SslSessionCacheMode::CLIENT);
        client
            .ctx()
            .set_new_session_callback(move |_, session| {
                issued.lock().unwrap().push(session);
            })
            .unwrap();
        client
            .ctx()
            .set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                observed.fetch_add(1, Ordering::SeqCst);
                ssl.verify_peer_cert_chain()
                    .map_err(|_| SslVerifyError::Invalid(crate::ssl::SslAlert::CERTIFICATE_UNKNOWN))
            })
            .unwrap();
        let client = client.build();
        let first = client.builder().connect();
        assert!(!first.ssl().session_reused());
        let session = sessions.lock().unwrap().pop().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let mut resumed = client.builder();
        // SAFETY: this is an authenticated session from the same client context,
        // with the same peer and protocol; the new handshake has not started.
        unsafe { resumed.ssl().set_session(&session).unwrap() };
        let observed = Arc::clone(&calls);
        resumed
            .ssl()
            .set_custom_verify_callback(SslVerifyMode::NONE, move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();
        let crate::ssl::HandshakeError::Failure(failed) = resumed.connect_err() else {
            panic!("expected a verification failure");
        };
        assert!(
            failed
                .error()
                .ssl_error()
                .unwrap()
                .errors()
                .iter()
                .any(|error| {
                    error.library_reason(crate::ffi::ERR_LIB_SSL)
                        == Some(crate::ffi::SSL_R_CERTIFICATE_VERIFY_FAILED)
                })
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

type Sessions = Arc<Mutex<Vec<ClientSession>>>;

fn collect_sessions(connector: &mut SslConnectorBuilder, sessions: &Sessions) {
    let issued = Arc::clone(sessions);
    connector
        .set_client_session_callback(move |_, session| issued.lock().unwrap().push(session))
        .unwrap();
}

fn trusted_connector() -> SslConnectorBuilder {
    let mut connector = SslConnector::bare_builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();
    connector
}

fn issue_session(
    config: ConnectConfiguration,
    server: &Server,
    domain: &str,
    sessions: &Sessions,
) -> ClientSession {
    let mut stream = config.connect(domain, server.connect_tcp()).unwrap();
    // Reading processes tickets sent after the handshake.
    stream.read_exact(&mut [0]).unwrap();
    sessions.lock().unwrap().drain(..).next_back().unwrap()
}

#[test]
fn raw_and_checked_session_callbacks_replace_each_other() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut server = Server::builder();
    server.expected_connections_count(2);
    let server = server.build();
    let token = Arc::new(());
    let raw_calls = Arc::new(AtomicUsize::new(0));
    let mut connector = trusted_connector();
    let captured = Arc::clone(&token);
    connector
        .set_client_session_callback(move |_, _| {
            let _keep = &captured;
        })
        .unwrap();
    assert_eq!(Arc::strong_count(&token), 2);
    let calls = Arc::clone(&raw_calls);
    connector
        .set_new_session_callback(move |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
    assert_eq!(Arc::strong_count(&token), 1);
    let connector = connector.build();
    let mut stream = connector
        .connect("foobar.com", server.connect_tcp())
        .unwrap();
    stream.read_exact(&mut [0]).unwrap();
    assert!(raw_calls.load(Ordering::SeqCst) > 0);
    drop(stream);

    let mut connector = trusted_connector();
    let captured = Arc::clone(&token);
    connector
        .set_new_session_callback(move |_, _| {
            let _keep = &captured;
        })
        .unwrap();
    assert_eq!(Arc::strong_count(&token), 2);
    let sessions = Arc::new(Mutex::new(Vec::new()));
    collect_sessions(&mut connector, &sessions);
    assert_eq!(Arc::strong_count(&token), 1);
    let connector = connector.build();
    let _session = issue_session(
        connector.configure().unwrap(),
        &server,
        "foobar.com",
        &sessions,
    );
}

#[test]
fn client_session_resumes_within_scope_and_domain() {
    let mut server = Server::builder();
    server.expected_connections_count(3);
    let server = server.build();

    let sessions = Arc::new(Mutex::new(Vec::new()));
    let connector = |scope: &[u8]| {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_ca_file("test/root-ca.pem").unwrap();
        connector.set_session_id_context(scope).unwrap();
        collect_sessions(&mut connector, &sessions);
        connector.build()
    };
    let issue = |connector: &SslConnector, configure: fn(&mut ConnectConfiguration)| {
        let mut config = connector.configure().unwrap();
        configure(&mut config);
        issue_session(config, &server, "foobar.com", &sessions)
    };
    let offers = |connector: &SslConnector,
                  session: &ClientSession,
                  domain,
                  configure: fn(&mut ConnectConfiguration)| {
        let mut config = connector
            .configure()
            .unwrap()
            .client_session(session.clone());
        configure(&mut config);
        config.into_ssl(domain).unwrap().session().is_some()
    };

    // A shared session ID context resumes across contexts for the same domain and SNI use.
    let session = issue(&connector(b"scope"), |_| {});
    let shared = connector(b"scope");
    assert!(offers(&shared, &session, "foobar.com", |_| {}));
    assert!(offers(&shared, &session, "FOOBAR.com", |_| {}));
    assert!(!offers(&shared, &session, "bogus.com", |config| {
        config.set_verify_hostname(false)
    }));
    assert!(!offers(&shared, &session, "foobar.com", |config| {
        config.set_use_server_name_indication(false)
    }));
    assert!(!offers(
        &connector(b"other"),
        &session,
        "foobar.com",
        |_| {}
    ));
    let resumed = shared
        .configure()
        .unwrap()
        .client_session(session)
        .connect("foobar.com", server.connect_tcp())
        .unwrap();
    assert!(resumed.ssl().session_reused());

    // Without one, only the issuing context resumes, and never under stricter verification.
    let unscoped = connector(b"");
    let session = issue(&unscoped, |config| {
        config.set_verify_hostname(false);
        config.set_verify_mode(SslVerifyMode::NONE).unwrap();
    });
    assert!(offers(&unscoped, &session, "foobar.com", |config| {
        config.set_verify_hostname(false);
        config.set_verify_mode(SslVerifyMode::NONE).unwrap();
    }));
    assert!(!offers(&unscoped, &session, "foobar.com", |config| {
        config.set_verify_hostname(false)
    }));
    assert!(!offers(&unscoped, &session, "foobar.com", |config| {
        config.set_verify_mode(SslVerifyMode::NONE).unwrap()
    }));
    assert!(!offers(&connector(b""), &session, "foobar.com", |config| {
        config.set_verify_hostname(false);
        config.set_verify_mode(SslVerifyMode::NONE).unwrap();
    }));
}

#[test]
fn unscoped_session_issuer_is_the_original_notification_registration() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let mut server = Server::builder();
        server.expected_connections_count(2);
        server.ctx().set_min_proto_version(Some(version)).unwrap();
        server.ctx().set_max_proto_version(Some(version)).unwrap();
        let server = server.build();
        let origin_sessions = Arc::new(Mutex::new(Vec::new()));
        let replacement_sessions = Arc::new(Mutex::new(Vec::new()));
        let mut origin = trusted_connector();
        collect_sessions(&mut origin, &origin_sessions);
        let origin = origin.build();
        let mut replacement = trusted_connector();
        collect_sessions(&mut replacement, &replacement_sessions);
        let replacement = replacement.build();

        let mut config = origin.configure().unwrap();
        config.set_ssl_context(replacement.context()).unwrap();
        let session = issue_session(config, &server, "foobar.com", &origin_sessions);
        assert!(replacement_sessions.lock().unwrap().is_empty());
        let wrong_origin = replacement
            .configure()
            .unwrap()
            .client_session(session.clone())
            .into_ssl("foobar.com")
            .unwrap();
        assert!(wrong_origin.session().is_none());
        let mut resumed = origin
            .configure()
            .unwrap()
            .client_session(session)
            .into_ssl("foobar.com")
            .unwrap();
        assert!(resumed.session().is_some());
        // A switch after tentative installation also keeps the original session
        // scope. Current native trust and hostname policy are still revalidated.
        resumed.set_ssl_context(replacement.context()).unwrap();
        let mut stream = resumed.connect(server.connect_tcp()).unwrap();
        assert!(stream.ssl().session_reused());
        stream.read_exact(&mut [0]).unwrap();
        assert!(replacement_sessions.lock().unwrap().is_empty());
    }
}

#[test]
fn cached_session_rechecks_current_hostname_policy_before_client_hello() {
    use crate::x509::verify::X509CheckFlags;
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let mut server = Server::builder();
        server.expected_connections_count(3);
        server.should_error_when(|index| index == 2);
        server
            .ctx()
            .set_certificate_chain_file("test/cert-wildcard.pem")
            .unwrap();
        server.ctx().set_min_proto_version(Some(version)).unwrap();
        server.ctx().set_max_proto_version(Some(version)).unwrap();
        let server = server.build();
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let mut connector = trusted_connector();
        collect_sessions(&mut connector, &sessions);
        let connector = connector.build();
        let session = issue_session(
            connector.configure().unwrap(),
            &server,
            "yes.foobar.com",
            &sessions,
        );
        let mut second = connector
            .configure()
            .unwrap()
            .client_session(session.clone())
            .connect("yes.foobar.com", server.connect_tcp())
            .unwrap();
        assert!(second.ssl().session_reused());
        second.read_exact(&mut [0]).unwrap();
        let session = if version == SslVersion::TLS1_3 {
            sessions.lock().unwrap().drain(..).next_back().unwrap()
        } else {
            session
        };
        // Change the verification policy after `into_ssl` has tentatively
        // installed the session. The cached wildcard must not bypass it.
        let mut ssl = connector
            .configure()
            .unwrap()
            .client_session(session)
            .into_ssl("yes.foobar.com")
            .unwrap();
        assert!(ssl.session().is_some());
        ssl.verify_param_mut()
            .unwrap()
            .set_hostflags(X509CheckFlags::NO_WILDCARDS);
        let result = ssl.connect(server.connect_tcp());
        assert!(
            matches!(result, Err(crate::ssl::HandshakeError::Failure(ref mid)) if mid.ssl().verify_result() == Err(crate::x509::X509VerifyError::HOSTNAME_MISMATCH))
        );
    }
}

#[test]
fn cached_session_rechecks_current_trust_store() {
    let mut server = Server::builder();
    server.expected_connections_count(2);
    server.should_error_when(|index| index == 1);
    let server = server.build();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let mut connector = trusted_connector();
    connector.set_session_id_context(b"shared scope").unwrap();
    collect_sessions(&mut connector, &sessions);
    let connector = connector.build();
    let session = issue_session(
        connector.configure().unwrap(),
        &server,
        "foobar.com",
        &sessions,
    );
    let mut untrusted = SslConnector::bare_builder(SslMethod::tls()).unwrap();
    untrusted.set_session_id_context(b"shared scope").unwrap();
    let result = untrusted
        .build()
        .configure()
        .unwrap()
        .client_session(session)
        .connect("foobar.com", server.connect_tcp());
    assert!(
        matches!(result, Err(crate::ssl::HandshakeError::Failure(ref mid)) if mid.ssl().verify_result().is_err())
    );
}

#[test]
fn cached_session_does_not_skip_custom_verification() {
    let mut server = Server::builder();
    server.expected_connections_count(2);
    let server = server.build();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let mut connector = trusted_connector();
    collect_sessions(&mut connector, &sessions);
    let connector = connector.build();
    let session = issue_session(
        connector.configure().unwrap(),
        &server,
        "foobar.com",
        &sessions,
    );
    let calls = Arc::new(AtomicU8::new(0));
    let mut ssl = connector
        .configure()
        .unwrap()
        .client_session(session)
        .into_ssl("foobar.com")
        .unwrap();
    let verified = Arc::clone(&calls);
    ssl.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        verified.fetch_add(1, Ordering::SeqCst);
        ssl.verify_peer_cert_chain()
            .map_err(|_| SslVerifyError::Invalid(crate::ssl::SslAlert::BAD_CERTIFICATE))
    })
    .unwrap();
    let mut stream = ssl.connect(server.connect_tcp()).unwrap();
    stream.read_exact(&mut [0]).unwrap();
    assert!(!stream.ssl().session_reused());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn cached_session_uses_current_native_verification_time() {
    // A foobar.com leaf from the test root that expired a day ago.
    let day: i64 = 24 * 60 * 60;
    let now: i64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();
    let key = PKey::private_key_from_pem(&fs::read("test/key.pem").unwrap()).unwrap();
    let ca = X509::from_pem(&fs::read("test/root-ca.pem").unwrap()).unwrap();
    let ca_key = PKey::private_key_from_pem(&fs::read("test/root-ca.key").unwrap()).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "foobar.com").unwrap();
    let name = name.build().unwrap();
    let mut leaf = X509::builder().unwrap();
    leaf.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    leaf.set_serial_number(&serial).unwrap();
    leaf.set_subject_name(&name).unwrap();
    leaf.set_issuer_name(ca.subject_name().unwrap()).unwrap();
    leaf.set_pubkey(&key).unwrap();
    leaf.set_not_before(&Asn1Time::from_unix(now - 2 * day).unwrap())
        .unwrap();
    leaf.set_not_after(&Asn1Time::from_unix(now - day).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("foobar.com")
        .build(&leaf.x509v3_context(Some(&ca), None))
        .unwrap();
    leaf.append_extension(&san).unwrap();
    let leaf = leaf
        .sign(Signer::new_oneshot(MessageDigest::sha256(), &ca_key).unwrap())
        .unwrap();

    let mut server = Server::builder();
    server.expected_connections_count(4);
    server.should_error_when(|index| index == 2);
    server.ctx().set_certificate(&leaf).unwrap();
    let server = server.build();

    let sessions = Arc::new(Mutex::new(Vec::new()));
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();
    collect_sessions(&mut connector, &sessions);
    let connector = connector.build();

    // Verified as of a time inside the validity period.
    let mut config = connector.configure().unwrap();
    config
        .verify_param_mut()
        .unwrap()
        .set_time(now - day - day / 2);
    let session = issue_session(config, &server, "foobar.com", &sessions);
    assert_eq!(
        session.session().peer_chain_not_after().unwrap(),
        Some(now - day)
    );

    // The certificate is expired at the wall clock, but valid under the
    // explicitly requested historical verification policy.
    let mut historical = connector
        .configure()
        .unwrap()
        .client_session(session.clone());
    historical
        .verify_param_mut()
        .unwrap()
        .set_time(now - day - day / 2);
    let mut stream = historical
        .connect("foobar.com", server.connect_tcp())
        .unwrap();
    assert!(stream.ssl().session_reused());
    stream.read_exact(&mut [0]).unwrap();

    // Changing the policy to the current time must reject the cached session
    // before it is offered. A full handshake with the expired leaf then fails.
    let result = connector
        .configure()
        .unwrap()
        .client_session(session.clone())
        .connect("foobar.com", server.connect_tcp());
    assert!(
        matches!(result, Err(crate::ssl::HandshakeError::Failure(ref mid))
        if mid.ssl().verify_result() == Err(crate::x509::X509VerifyError::CERT_HAS_EXPIRED))
    );

    let mut unverified = connector.configure().unwrap().client_session(session);
    unverified.set_verify_mode(SslVerifyMode::NONE).unwrap();
    let mut stream = unverified
        .connect("foobar.com", server.connect_tcp())
        .unwrap();
    assert!(stream.ssl().session_reused());
    stream.read_exact(&mut [0]).unwrap();
}

#[derive(Default)]
struct TicketKeys {
    current: Option<TicketKey>,
    previous: Option<TicketKey>,
}

struct TestTicketProvider(Arc<Mutex<TicketKeys>>);

impl TicketKeyProvider for TestTicketProvider {
    fn issuing_key(&self, _: &SslRef) -> Result<Option<TicketKey>, ErrorStack> {
        Ok(self.0.lock().unwrap().current.clone())
    }

    fn decryption_key(
        &self,
        _: &SslRef,
        name: &[u8; 16],
    ) -> Result<Option<(TicketKey, TicketRenewal)>, ErrorStack> {
        let keys = self.0.lock().unwrap();
        Ok([
            (keys.current.as_ref(), TicketRenewal::Keep),
            (keys.previous.as_ref(), TicketRenewal::Renew),
        ]
        .into_iter()
        .find_map(|(key, renewal)| {
            key.filter(|key| key.name() == name)
                .map(|key| (key.clone(), renewal))
        }))
    }
}

#[test]
fn ticket_provider_replacement_and_clear_release_state() {
    let keys = Arc::new(Mutex::new(TicketKeys::default()));
    let mut ctx = crate::ssl::SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_ticket_key_provider(TestTicketProvider(Arc::clone(&keys)))
        .unwrap();
    assert_eq!(Arc::strong_count(&keys), 2);
    ctx.set_ticket_key_provider(TestTicketProvider(Arc::default()))
        .unwrap();
    assert_eq!(Arc::strong_count(&keys), 1);
    ctx.set_ticket_key_provider(TestTicketProvider(Arc::clone(&keys)))
        .unwrap();
    ctx.clear_ticket_key_provider().unwrap();
    assert_eq!(Arc::strong_count(&keys), 1);
}

#[test]
fn ticket_provider_rotates_renews_and_retires_keys() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let old_key = TicketKey::from_keys([1; 16], &[2; 16], &[3; 32]).unwrap();
        let new_key = TicketKey::generate().unwrap();
        let keys = Arc::new(Mutex::new(TicketKeys {
            current: Some(old_key),
            previous: None,
        }));
        let mut server = Server::builder();
        server.ctx().set_min_proto_version(Some(version)).unwrap();
        server.ctx().set_max_proto_version(Some(version)).unwrap();
        server
            .ctx()
            .set_ticket_key_provider(TestTicketProvider(Arc::clone(&keys)))
            .unwrap();
        server.expected_connections_count(4);
        let server = server.build();
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let mut connector = trusted_connector();
        collect_sessions(&mut connector, &sessions);
        let connector = connector.build();
        let old_session = issue_session(
            connector.configure().unwrap(),
            &server,
            "foobar.com",
            &sessions,
        );
        {
            let mut keys = keys.lock().unwrap();
            keys.previous = keys.current.replace(new_key);
        }

        // Old keys resume and request a ticket encrypted with the new key.
        let mut stream = connector
            .configure()
            .unwrap()
            .client_session(old_session.clone())
            .connect("foobar.com", server.connect_tcp())
            .unwrap();
        assert!(stream.ssl().session_reused());
        stream.read_exact(&mut [0]).unwrap();
        let renewed = sessions.lock().unwrap().drain(..).next_back().unwrap();
        drop(stream);

        // A retired key is not a fatal error, but cannot resume.
        keys.lock().unwrap().previous = None;
        let mut stream = connector
            .configure()
            .unwrap()
            .client_session(old_session)
            .connect("foobar.com", server.connect_tcp())
            .unwrap();
        assert!(!stream.ssl().session_reused());
        stream.read_exact(&mut [0]).unwrap();
        drop(stream);

        // The renewed ticket remains usable after retiring the old key.
        let mut stream = connector
            .configure()
            .unwrap()
            .client_session(renewed)
            .connect("foobar.com", server.connect_tcp())
            .unwrap();
        assert!(stream.ssl().session_reused());
        stream.read_exact(&mut [0]).unwrap();
    }
}

#[test]
fn ticket_provider_can_decline_issuance() {
    let mut server = Server::builder();
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .ctx()
        .set_ticket_key_provider(TestTicketProvider(Arc::default()))
        .unwrap();
    let server = server.build();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let mut connector = trusted_connector();
    collect_sessions(&mut connector, &sessions);
    let mut stream = connector
        .build()
        .configure()
        .unwrap()
        .connect("foobar.com", server.connect_tcp())
        .unwrap();
    stream.read_exact(&mut [0]).unwrap();
    assert!(sessions.lock().unwrap().is_empty());
}
