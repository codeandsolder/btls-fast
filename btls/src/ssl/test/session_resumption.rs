use super::server::Server;
use crate::asn1::Asn1Time;
use crate::bn::BigNum;
use crate::pkey::PKey;
use crate::ssl::ClientSession;
use crate::ssl::ConnectConfiguration;
use crate::ssl::HmacCtxRef;
use crate::ssl::SslMethod;
use crate::ssl::SslRef;
use crate::ssl::SslSession;
use crate::ssl::SslSessionCacheMode;
use crate::ssl::SslVerifyError;
use crate::ssl::SslVerifyMode;
use crate::ssl::SslVersion;
use crate::ssl::connector::earliest_not_after;
use crate::ssl::test::MessageDigest;
use crate::ssl::{SslConnector, SslConnectorBuilder};
use crate::ssl::{TicketKeyCallbackResult, TicketKeyMode};
use crate::symm::Cipher;
use crate::symm::CipherCtxRef;
use crate::x509::extension::SubjectAlternativeName;
use crate::x509::{X509, X509Name};
use std::fs;
use std::io::Read;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

static SUCCESS_ENCRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static SUCCESS_DECRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static NOOP_ENCRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static NOOP_DECRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);

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
        config.set_verify(SslVerifyMode::NONE).unwrap();
    });
    assert!(offers(&unscoped, &session, "foobar.com", |config| {
        config.set_verify_hostname(false);
        config.set_verify(SslVerifyMode::NONE).unwrap();
    }));
    assert!(!offers(&unscoped, &session, "foobar.com", |config| {
        config.set_verify_hostname(false)
    }));
    assert!(!offers(&unscoped, &session, "foobar.com", |config| {
        config.set_verify(SslVerifyMode::NONE).unwrap()
    }));
    assert!(!offers(&connector(b""), &session, "foobar.com", |config| {
        config.set_verify_hostname(false);
        config.set_verify(SslVerifyMode::NONE).unwrap();
    }));
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
fn client_session_is_not_offered_after_its_chain_expires() {
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
    leaf.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let leaf = leaf.build();

    let mut server = Server::builder();
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
    let not_after = session.session().peer_chain_not_after();
    assert!(not_after.is_some());
    assert_eq!(not_after, earliest_not_after([&*leaf]));

    let offers = |configure: fn(&mut ConnectConfiguration)| {
        let mut config = connector
            .configure()
            .unwrap()
            .client_session(session.clone());
        configure(&mut config);
        config.into_ssl("foobar.com").unwrap().session().is_some()
    };
    assert!(!offers(|_| {}));
    assert!(offers(|config| config
        .set_verify(SslVerifyMode::NONE)
        .unwrap()));
}

#[test]
fn custom_callback_success() {
    custom_callback_roundtrip(
        test_success_tickey_key_callback,
        &SUCCESS_ENCRYPTION_CALLED_BACK,
        &SUCCESS_DECRYPTION_CALLED_BACK,
        true,
    );
}

#[test]
fn custom_callback_unrecognized_decryption_ticket() {
    custom_callback_roundtrip(
        test_noop_tickey_key_callback,
        &NOOP_ENCRYPTION_CALLED_BACK,
        &NOOP_DECRYPTION_CALLED_BACK,
        false,
    );
}

fn custom_callback_roundtrip(
    callback: fn(
        &SslRef,
        TicketKeyMode<'_>,
        &mut CipherCtxRef,
        &mut HmacCtxRef,
    ) -> TicketKeyCallbackResult,
    encryptions: &AtomicU8,
    decryptions: &AtomicU8,
    resumed: bool,
) {
    let session_ticket = std::sync::Arc::new(OnceLock::new());
    let received = std::sync::Arc::new(AtomicU8::new(0));

    let mut server = Server::builder();
    server.expected_connections_count(2);
    unsafe {
        server.ctx().set_ticket_key_callback(callback).unwrap();
    };
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    let ticket_out = session_ticket.clone();
    let received_out = received.clone();
    client
        .ctx()
        .set_new_session_callback(move |_, session| {
            received_out.fetch_add(1, Ordering::SeqCst);
            // The server sends multiple session tickets but we only care to retrieve one.
            let _ = ticket_out.set(session);
        })
        .unwrap();
    let ssl_stream = client.connect();

    assert!(!ssl_stream.ssl().session_reused());
    assert!(session_ticket.get().is_some());
    assert_eq!(encryptions.load(Ordering::SeqCst), 2);
    assert_eq!(decryptions.load(Ordering::SeqCst), 0);
    assert_eq!(received.load(Ordering::SeqCst), 2);

    // Retrieve the session ticket
    let session_ticket = session_ticket.get().unwrap();

    // Attempt to resume the connection using the session ticket
    let client_2 = server.client();
    let mut ssl_builder = client_2.build().builder();
    unsafe { ssl_builder.ssl().set_session(session_ticket).unwrap() };
    let ssl_stream_2 = ssl_builder.connect();

    assert_eq!(ssl_stream_2.ssl().session_reused(), resumed);
    assert_eq!(encryptions.load(Ordering::SeqCst), 4);
    assert_eq!(decryptions.load(Ordering::SeqCst), 1);
}

// Successfully return a session ticket in encryption mode but return a
// TicketKeyCallbackResult::Noop in decryption mode.
fn test_noop_tickey_key_callback(
    _ssl: &SslRef,
    mode: TicketKeyMode<'_>,
    evp_ctx: &mut CipherCtxRef,
    hmac_ctx: &mut HmacCtxRef,
) -> TicketKeyCallbackResult {
    // These should only be used for testing purposes.
    const TEST_KEY_NAME: [u8; 16] = [5; 16];
    const TEST_CBC_IV: [u8; ffi::EVP_MAX_IV_LENGTH as usize] = [1; ffi::EVP_MAX_IV_LENGTH as usize];
    const TEST_AES_128_CBC_KEY: [u8; 16] = [2; 16];
    const TEST_HMAC_KEY: [u8; 32] = [3; 32];

    let digest = MessageDigest::sha256();
    let cipher = Cipher::aes_128_cbc();

    match mode {
        TicketKeyMode::Encrypt { key_name, iv } => {
            NOOP_ENCRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);

            // Ensure key_name and iv are initialized and set test values.
            assert_eq!(key_name, &[0; 16]);
            assert_eq!(iv, &[0; 16]);
            key_name.copy_from_slice(&TEST_KEY_NAME);
            iv.copy_from_slice(&TEST_CBC_IV);

            // Set the encryption context.
            evp_ctx
                .init(
                    cipher,
                    crate::symm::Mode::Encrypt,
                    &TEST_AES_128_CBC_KEY,
                    Some(&TEST_CBC_IV),
                )
                .unwrap();

            // Set the hmac context.
            hmac_ctx.init(&TEST_HMAC_KEY, &digest).unwrap();

            TicketKeyCallbackResult::Success
        }
        TicketKeyMode::Decrypt { key_name, iv: _ } => {
            NOOP_DECRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);

            // Check key_name matches.
            assert_eq!(key_name, &TEST_KEY_NAME);

            TicketKeyCallbackResult::Noop
        }
    }
}

// Custom callback to encrypt and decrypt session tickets
fn test_success_tickey_key_callback(
    _ssl: &SslRef,
    mode: TicketKeyMode<'_>,
    evp_ctx: &mut CipherCtxRef,
    hmac_ctx: &mut HmacCtxRef,
) -> TicketKeyCallbackResult {
    // These should only be used for testing purposes.
    const TEST_KEY_NAME: [u8; 16] = [5; 16];
    const TEST_CBC_IV: [u8; ffi::EVP_MAX_IV_LENGTH as usize] = [1; ffi::EVP_MAX_IV_LENGTH as usize];
    const TEST_AES_128_CBC_KEY: [u8; 16] = [2; 16];
    const TEST_HMAC_KEY: [u8; 32] = [3; 32];

    let digest = MessageDigest::sha256();
    let cipher = Cipher::aes_128_cbc();

    match mode {
        TicketKeyMode::Encrypt { key_name, iv } => {
            SUCCESS_ENCRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);

            // Ensure key_name and iv are initialized and set test values.
            assert_eq!(key_name, &[0; 16]);
            assert_eq!(iv, &[0; 16]);
            key_name.copy_from_slice(&TEST_KEY_NAME);
            iv.copy_from_slice(&TEST_CBC_IV);

            // Set the encryption context.
            evp_ctx
                .init(
                    cipher,
                    crate::symm::Mode::Encrypt,
                    &TEST_AES_128_CBC_KEY,
                    Some(&TEST_CBC_IV),
                )
                .unwrap();

            // Set the hmac context.
            hmac_ctx.init(&TEST_HMAC_KEY, &digest).unwrap();
        }
        TicketKeyMode::Decrypt { key_name, iv } => {
            SUCCESS_DECRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);

            // Check key_name matches.
            assert_eq!(key_name, &TEST_KEY_NAME);

            // Set the decryption context.
            evp_ctx
                .init(
                    cipher,
                    crate::symm::Mode::Decrypt,
                    &TEST_AES_128_CBC_KEY,
                    Some(iv),
                )
                .unwrap();

            // Set the hmac context.
            hmac_ctx.init(&TEST_HMAC_KEY, &digest).unwrap();
        }
    }

    TicketKeyCallbackResult::Success
}
