use foreign_types::{ForeignType, ForeignTypeRef};
use std::ffi::c_int;
use std::io;
use std::io::prelude::*;
use std::mem;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::error::ErrorStack;
use crate::hash::MessageDigest;
use crate::pkey::PKey;
use crate::srtp::SrtpProfileId;
use crate::ssl::test::server::Server;
use crate::ssl::{
    self, ExtensionType, KeyShare, NameType, ShutdownResult, ShutdownState, Ssl, SslAcceptor,
    SslAcceptorBuilder, SslConnector, SslContext, SslFiletype, SslInfoCallbackMode, SslMethod,
    SslOptions, SslSignatureAlgorithm, SslStream, SslVerifyMode, Tls13Cipher,
};
use crate::ssl::{HandshakeError, SslVersion};
use crate::x509::store::X509StoreBuilder;
use crate::x509::verify::X509CheckFlags;
use crate::x509::{X509, X509Name};

use super::CompliancePolicy;

mod cert_compressor;
mod cert_verify;
mod custom_verify;
mod delegated_credentials;
mod ech;
mod ech_grease;
mod grease_sigalgs;
mod patch_ciphers;
mod patches;
mod private_key_method;
mod quic;
mod reverify;
mod server;
mod server_padding;
mod session;
mod session_resumption;
mod trust_anchors;
mod verify;

static ROOT_CERT: &[u8] = include_bytes!("../../../test/root-ca.pem");
static CERT: &[u8] = include_bytes!("../../../test/cert.pem");
static KEY: &[u8] = include_bytes!("../../../test/key.pem");
const TEST_CERT_DIGEST: &str = "585e3a58acfd3b4e5e2825659407244ddd93539c";

#[test]
fn context_extra_chain_handles_empty_and_populated_chains() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    assert!(ctx.ctx.extra_chain_certs().is_none());

    ctx.set_certificate(&X509::from_pem(CERT).unwrap()).unwrap();
    assert!(ctx.ctx.extra_chain_certs().is_none());

    let extra = X509::from_pem(ROOT_CERT).unwrap();
    ctx.add_extra_chain_cert(extra).unwrap();
    let ctx = ctx.build();
    assert_eq!(ctx.extra_chain_certs().unwrap().len(), 1);
}

#[test]
fn non_x509_context_rejects_certificate_operations_without_panicking() {
    // SAFETY: No handshake is driven, and the X.509 wrapper operations
    // below reject unsupported contexts before invoking native X.509 APIs.
    let mut ctx = SslContext::builder(unsafe { SslMethod::tls_with_buffer() }).unwrap();
    assert!(!ctx.ctx.has_x509_support());
    assert!(ctx.cert_store().is_err());
    assert!(ctx.cert_store_mut().is_err());
    assert!(ctx.set_verify(SslVerifyMode::PEER).is_err());
    assert!(ctx.verify_mode().is_err());
    assert!(ctx.set_verify_depth(1).is_err());
    assert!(
        ctx.set_verify_callback(SslVerifyMode::PEER, |_, _| true)
            .is_err()
    );
    assert!(ctx.set_cert_verify_callback(|_| true).is_err());
    assert!(ctx.set_default_verify_paths().is_err());
    assert!(ctx.ctx.certificate().is_none());
    assert!(ctx.ctx.extra_chain_certs().is_none());
    // Custom verification is explicitly supported by this native method.
    ctx.set_custom_verify_callback(SslVerifyMode::PEER, |_| {
        Err(super::SslVerifyError::Invalid(
            super::SslAlert::BAD_CERTIFICATE,
        ))
    })
    .unwrap();
    let ctx = ctx.build();
    assert!(ctx.cert_store().is_err());
    let mut ssl = Ssl::new(&ctx).unwrap();
    assert!(ssl.set_verify(SslVerifyMode::PEER).is_err());
    assert!(ssl.verify_mode().is_err());
    assert!(ssl.verify_param_mut().is_err());
    assert!(ssl.peer_certificate().is_none());
    assert!(ssl.peer_cert_chain().is_none());
    assert!(ssl.certificate().is_none());
    assert_eq!(
        ssl.verify_result(),
        Err(crate::x509::X509VerifyError::INVALID_CALL)
    );
}

#[test]
fn native_ssl_io_length_is_bounded_without_wrapping() {
    assert_eq!(super::ssl_io_len(0), 0);
    assert_eq!(super::ssl_io_len(usize::MAX), c_int::MAX);
    assert_eq!(super::ssl_io_len(1000), 1000);
}

#[test]
fn get_ctx_options() {
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let _ = ctx.options();
}

#[test]
fn set_ctx_options() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let opts = ctx.set_options(SslOptions::NO_TICKET);
    assert!(opts.contains(SslOptions::NO_TICKET));
}

#[test]
fn clear_ctx_options() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_options(SslOptions::NO_TICKET);
    let opts = ctx.clear_options(SslOptions::NO_TICKET);
    assert!(!opts.contains(SslOptions::NO_TICKET));
}

#[test]
fn verify_depth_setters_reject_unsigned_overflow() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    assert!(ctx.set_verify_depth(2).is_ok());
    assert!(ctx.set_verify_depth(u32::MAX).is_err());

    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    assert!(ssl.set_verify_depth(2).is_ok());
    assert!(ssl.set_verify_depth(u32::MAX).is_err());
}

#[test]
fn session_id_context_rejects_excess_native_length() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    assert!(ctx.set_session_id_context(&[0; 32]).is_ok());
    assert!(ctx.set_session_id_context(&[0; 33]).is_err());
}

#[test]
fn zero_length_buffers() {
    let server = Server::builder().build();

    let mut s = server.client().connect();
    assert_eq!(s.write(&[]).unwrap(), 0);
    assert_eq!(s.read(&mut []).unwrap(), 0);
}

#[test]
#[cfg(feature = "fips")]
fn seal_app_data_is_unavailable_in_fips() {
    let server = Server::builder().build();

    let mut s = server.client().connect();
    assert_eq!(s.ssl().seal_app_data_limits(), None);
    let mut out = [mem::MaybeUninit::uninit(); 64];
    assert!(matches!(
        s.ssl_mut()
            .seal_app_data(&[io::IoSlice::new(b"x")], 1, &mut out),
        Ok(None)
    ));
}

#[test]
fn peer_certificate() {
    let server = Server::builder().build();

    let s = server.client().connect();
    let cert = s.ssl().peer_certificate().unwrap();
    let fingerprint = cert.digest(MessageDigest::sha1()).unwrap();
    assert_eq!(hex::encode(fingerprint), TEST_CERT_DIGEST);
}

#[test]
fn pending() {
    let mut server = Server::builder();
    server.io_cb(|mut s| s.write_all(&[0; 10]).unwrap());
    let server = server.build();

    let mut s = server.client().connect();
    s.read_exact(&mut [0]).unwrap();

    assert_eq!(s.ssl().pending(), 9);
    assert_eq!(s.read(&mut [0; 10]).unwrap(), 9);
}

#[test]
fn state() {
    let server = Server::builder().build();

    let s = server.client().connect();
    // NOTE: Boring returs a placeholder string for state_string
    assert_eq!(s.ssl().state_string(), "!!!!!!");
    assert_eq!(
        s.ssl().state_string_long(),
        "SSL negotiation finished successfully"
    );
}

const TEST_SRTP_PROFILES: &str = "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32";

#[derive(Clone, Copy)]
enum SrtpConfiguration {
    Context,
    Connection,
}

/// The context and per-connection SRTP configuration paths must agree on the
/// selected profile and derive identical exporter keys on both peers.
fn verify_srtp_handshake(configuration: SrtpConfiguration) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();
        if matches!(configuration, SrtpConfiguration::Context) {
            ctx.set_tlsext_use_srtp(TEST_SRTP_PROFILES).unwrap();
        }
        ctx.set_certificate_file(Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        let mut ssl = Ssl::new(&ctx.build()).unwrap();
        if matches!(configuration, SrtpConfiguration::Connection) {
            ssl.set_tlsext_use_srtp(TEST_SRTP_PROFILES).unwrap();
            let profile_names = ssl
                .srtp_profiles()
                .unwrap()
                .iter()
                .map(|profile| profile.name().unwrap())
                .collect::<Vec<_>>()
                .join(":");
            assert_eq!(TEST_SRTP_PROFILES, profile_names);
        }
        ssl.set_mtu(1500).unwrap();
        let mut stream = ssl.accept(stream).unwrap();

        let mut key = [0; 60];
        stream
            .ssl()
            .export_keying_material(&mut key, "EXTRACTOR-dtls_srtp", None)
            .unwrap();
        stream.write_all(&[0]).unwrap();
        key
    });

    let stream = TcpStream::connect(addr).unwrap();
    let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();
    if matches!(configuration, SrtpConfiguration::Context) {
        ctx.set_tlsext_use_srtp(TEST_SRTP_PROFILES).unwrap();
    }
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    if matches!(configuration, SrtpConfiguration::Connection) {
        ssl.set_tlsext_use_srtp(TEST_SRTP_PROFILES).unwrap();
    }
    ssl.set_mtu(1500).unwrap();
    let mut stream = ssl.connect(stream).unwrap();

    let profile = stream.ssl().selected_srtp_profile().unwrap();
    assert_eq!("SRTP_AES128_CM_SHA1_80", profile.name().unwrap());
    assert_eq!(SrtpProfileId::SRTP_AES128_CM_SHA1_80, profile.id());

    let mut key = [1; 60];
    stream
        .ssl()
        .export_keying_material(&mut key, "EXTRACTOR-dtls_srtp", None)
        .unwrap();
    stream.read_exact(&mut [0]).unwrap();
    assert_eq!(key, server.join().unwrap());
}

#[test]
fn test_connect_with_srtp_ctx() {
    verify_srtp_handshake(SrtpConfiguration::Context);
}

#[test]
fn test_connect_with_srtp_ssl() {
    verify_srtp_handshake(SrtpConfiguration::Connection);
}

/// Tests that DTLS 1.3 can be enabled and negotiated successfully.
#[test]
fn test_dtls_1_3_version() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();
        ctx.set_certificate_file(Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        // Enable DTLS 1.3
        ctx.set_max_proto_version(Some(SslVersion::DTLS1_3))
            .unwrap();
        let mut ssl = Ssl::new(&ctx.build()).unwrap();
        ssl.set_mtu(1500).unwrap();
        let stream = ssl.accept(stream).unwrap();

        // Verify DTLS 1.3 was negotiated
        let version = stream.ssl().version2().unwrap();
        assert_eq!(version, SslVersion::DTLS1_3);

        stream
    });

    let stream = TcpStream::connect(addr).unwrap();
    let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();
    // Enable DTLS 1.3 on client
    ctx.set_max_proto_version(Some(SslVersion::DTLS1_3))
        .unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_mtu(1500).unwrap();
    let stream = ssl.connect(stream).unwrap();

    // Verify DTLS 1.3 was negotiated on client side
    let version = stream.ssl().version2().unwrap();
    assert_eq!(version, SslVersion::DTLS1_3);

    // Also check version string
    let version_str = stream.ssl().version_str();
    assert_eq!(version_str, Some("DTLSv1.3"));

    guard.join().unwrap();
}

/// Tests that when the `SslStream` is created as a server stream, the protocols
/// are correctly advertised to the client.
#[test]
fn test_alpn_server_advertise_multiple() {
    let mut server = Server::builder();
    server
        .ctx()
        .set_alpn_select_callback(|_, client| {
            ssl::select_next_proto(b"\x08http/1.1\x08spdy/3.1", client).ok_or(ssl::AlpnError::NOACK)
        })
        .unwrap();
    let server = server.build();

    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x08spdy/3.1").unwrap();
    let s = client.connect();
    assert_eq!(s.ssl().selected_alpn_protocol(), Some(&b"spdy/3.1"[..]));
}

#[test]
fn alpn_rejects_unoffered_protocol() {
    let mut server = Server::builder();
    server
        .ctx()
        .set_alpn_select_callback(|_, _| Ok(b"unoffered"))
        .unwrap();
    server.should_error();
    let server = server.build();
    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x02h2").unwrap();
    client.connect_err();
}

#[test]
fn test_alpn_server_select_none_fatal() {
    let mut server = Server::builder();
    server
        .ctx()
        .set_alpn_select_callback(|_, client| {
            ssl::select_next_proto(b"\x08http/1.1\x08spdy/3.1", client)
                .ok_or(ssl::AlpnError::ALERT_FATAL)
        })
        .unwrap();
    server.should_error();
    let server = server.build();

    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x06http/2").unwrap();
    client.connect_err();
}

#[test]
fn test_alpn_server_select_none() {
    let mut server = Server::builder();
    server
        .ctx()
        .set_alpn_select_callback(|_, client| {
            ssl::select_next_proto(b"\x08http/1.1\x08spdy/3.1", client).ok_or(ssl::AlpnError::NOACK)
        })
        .unwrap();
    let server = server.build();

    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x06http/2").unwrap();
    let s = client.connect();
    assert_eq!(None, s.ssl().selected_alpn_protocol());
}

#[test]
fn application_settings() {
    const SETTINGS: &[u8] = b"\x00\x03\x00\x00\x00\x64";

    /// Returns the ALPS values the client and the server received; `server` is `None` when the
    /// server does not enable ALPS, which it does from its ALPN select callback.
    /// `new_codepoint` selects the client's and the server's ALPS codepoint.
    fn handshake(
        new_codepoint: [bool; 2],
        client: Option<&'static [u8]>,
        server: Option<Option<&'static [u8]>>,
    ) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut builder = Server::builder();
        builder
            .ctx()
            .set_alpn_select_callback(move |ssl, client| {
                let proto =
                    ssl::select_next_proto(b"\x02h2", client).ok_or(ssl::AlpnError::NOACK)?;
                if let Some(settings) = server {
                    ssl.add_application_settings(proto, settings).unwrap();
                }
                Ok(proto)
            })
            .unwrap();
        builder.ssl_cb(move |ssl| ssl.set_alps_use_new_codepoint(new_codepoint[1]));
        builder.io_cb(move |s| {
            let received = s.ssl().peer_application_settings().map(ToOwned::to_owned);
            tx.send(received).unwrap();
        });
        let server = builder.build();

        let mut builder = server.client().build().builder();
        builder.ssl().set_alpn_protos(b"\x02h2").unwrap();
        builder.ssl().set_alps_use_new_codepoint(new_codepoint[0]);
        builder
            .ssl()
            .add_application_settings(b"h2", client)
            .unwrap();
        let s = builder.connect();
        let client = s.ssl().peer_application_settings().map(ToOwned::to_owned);
        (client, rx.recv().unwrap())
    }

    let some = Some(SETTINGS.to_vec());
    let empty = Some(Vec::new());
    for codepoint in [true, false] {
        assert_eq!(
            handshake([codepoint; 2], Some(SETTINGS), Some(Some(SETTINGS))),
            (some.clone(), some.clone())
        );
    }
    // ALPS is not negotiated when the codepoints differ.
    assert_eq!(
        handshake([true, false], Some(SETTINGS), Some(Some(SETTINGS))),
        (None, None)
    );
    assert_eq!(
        handshake([true; 2], None, Some(Some(SETTINGS))),
        (some, empty.clone())
    );
    assert_eq!(
        handshake([true; 2], Some(b""), Some(None)),
        (empty.clone(), empty)
    );
    assert_eq!(handshake([true; 2], Some(SETTINGS), None), (None, None));
}

#[test]
fn test_empty_alpn() {
    assert_eq!(ssl::select_next_proto(b"", b""), None);
    assert_eq!(ssl::select_next_proto(b"", b"\x08http/1.1"), None);
    assert_eq!(ssl::select_next_proto(b"\x08http/1.1", b""), None);
}

#[test]
fn test_alpn_server_unilateral() {
    let server = Server::builder().build();

    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x06http/2").unwrap();
    let s = client.connect();
    assert_eq!(None, s.ssl().selected_alpn_protocol());
}

#[test]
fn test_select_cert_ok() {
    let mut server = Server::builder();
    server
        .ctx()
        .set_select_certificate_callback(|_client_hello| Ok(()))
        .unwrap();
    let server = server.build();

    let client = server.client();
    client.connect();
}

#[test]
fn test_select_cert_last_setter_wins() {
    let old_calls = Arc::new(AtomicUsize::new(0));
    let action_calls = Arc::new(AtomicUsize::new(0));
    let mut server = Server::builder();

    let old_calls_clone = old_calls.clone();
    server
        .ctx()
        .set_select_certificate_callback(move |_client_hello| {
            old_calls_clone.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();

    let action_calls_clone = action_calls.clone();
    server
        .ctx()
        .set_select_certificate_callback_with_action(move |_client_hello| {
            action_calls_clone.fetch_add(1, Ordering::Relaxed);
            Ok(ssl::SelectCertAction::Success)
        })
        .unwrap();

    let server = server.build();
    server.client().connect();

    assert_eq!(old_calls.load(Ordering::Relaxed), 0);
    assert_eq!(action_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn test_mutable_store() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let cert2 = include_bytes!("../../../test/root-ca.pem");
    let cert2 = X509::from_pem(cert2).unwrap();

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.cert_store_mut()
        .unwrap()
        .add_cert(cert.clone())
        .unwrap();
    assert_eq!(1, ctx.cert_store().unwrap().objects_len());

    ctx.set_cert_store_builder(X509StoreBuilder::new().unwrap())
        .unwrap();
    assert_eq!(0, ctx.cert_store().unwrap().objects_len());

    ctx.cert_store_mut()
        .unwrap()
        .add_cert(cert.clone())
        .unwrap();
    assert_eq!(1, ctx.cert_store().unwrap().objects_len());

    let mut new_store = X509StoreBuilder::new().unwrap();
    new_store.add_cert(&cert).unwrap();
    new_store.add_cert(&cert2).unwrap();
    let new_store = new_store.build();
    assert_eq!(2, new_store.objects_len());

    ctx.set_cert_store(new_store.clone()).unwrap();
    assert_eq!(2, ctx.cert_store().unwrap().objects_len());
    assert!(std::ptr::eq(
        new_store.as_ptr(),
        ctx.cert_store().unwrap().as_ptr()
    ));

    let ctx = ctx.build();
    assert!(std::ptr::eq(
        new_store.as_ptr(),
        ctx.cert_store().unwrap().as_ptr()
    ));

    drop(new_store);
    assert_eq!(2, ctx.cert_store().unwrap().objects_len());
}

#[test]
fn shared_store_must_not_be_mutated() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();

    let shared = X509StoreBuilder::new().unwrap().build();
    ctx.set_cert_store(shared.clone()).unwrap();
    assert!(ctx.cert_store_mut().is_err());
}

#[test]
fn test_select_cert_error() {
    let mut server = Server::builder();
    server.should_error();
    server
        .ctx()
        .set_select_certificate_callback(|_client_hello| Err(ssl::SelectCertError::ERROR))
        .unwrap();
    let server = server.build();

    let client = server.client();
    client.connect_err();
}

#[test]
fn test_select_cert_disable_ech_without_ech_fails() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut server = Server::builder();
    server.should_error();
    let callback_calls = calls.clone();
    server
        .ctx()
        .set_select_certificate_callback_with_action(move |_client_hello| {
            if callback_calls.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(ssl::SelectCertAction::DisableEch)
            } else {
                Err(ssl::SelectCertError::ERROR)
            }
        })
        .unwrap();
    let server = server.build();

    let client = server.client();
    client.connect_err();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn test_select_cert_unknown_extension() {
    let mut server = Server::builder();
    let unknown_extension = Arc::new(std::sync::Mutex::new(Some(vec![])));

    server
        .ctx()
        .set_select_certificate_callback({
            let unknown = unknown_extension.clone();
            move |client_hello| {
                let ext = client_hello
                    .get_extension(ExtensionType::SERVER_NAME)
                    .map(ToOwned::to_owned);
                assert!(ext.is_none());
                *unknown.lock().unwrap() = ext;
                Ok(())
            }
        })
        .unwrap();

    let server = server.build();
    let client = server.client();

    client.connect();
    assert_eq!(unknown_extension.lock().unwrap().as_deref(), None);
}

#[test]
fn test_select_cert_alpn_extension() {
    let mut server = Server::builder();
    let alpn_extension = Arc::new(std::sync::Mutex::new(None));
    server
        .ctx()
        .set_select_certificate_callback({
            let alpn = alpn_extension.clone();
            move |client_hello| {
                *alpn.lock().unwrap() = Some(
                    client_hello
                        .get_extension(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
                        .unwrap()
                        .to_owned(),
                );
                Ok(())
            }
        })
        .unwrap();
    let server = server.build();

    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x06http/2").unwrap();
    client.connect();
    assert_eq!(
        alpn_extension.lock().unwrap().as_deref(),
        Some(&b"\x00\x07\x06http/2"[..]),
    );
}

#[test]
fn test_io_retry() {
    #[derive(Debug)]
    struct RetryStream {
        inner: TcpStream,
        first_read: bool,
        first_write: bool,
        first_flush: bool,
    }

    impl Read for RetryStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if mem::replace(&mut self.first_read, false) {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "first read"))
            } else {
                self.inner.read(buf)
            }
        }
    }

    impl Write for RetryStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if mem::replace(&mut self.first_write, false) {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "first write"))
            } else {
                self.inner.write(buf)
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            if mem::replace(&mut self.first_flush, false) {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "first flush"))
            } else {
                self.inner.flush()
            }
        }
    }

    let server = Server::builder().build();

    let stream = RetryStream {
        inner: server.connect_tcp(),
        first_read: true,
        first_write: true,
        first_flush: true,
    };

    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let mut s = match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(mut s) => return s.read_exact(&mut [0]).unwrap(),
        Err(HandshakeError::WouldBlock(s)) => s,
        Err(_) => panic!("should not fail on setup"),
    };
    loop {
        match s.handshake() {
            Ok(mut s) => return s.read_exact(&mut [0]).unwrap(),
            Err(HandshakeError::WouldBlock(mid_s)) => s = mid_s,
            Err(_) => panic!("should not fail on handshake"),
        }
    }
}

#[test]
#[should_panic(expected = "blammo")]
fn write_panic() {
    struct ExplodingStream(TcpStream);

    impl Read for ExplodingStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for ExplodingStream {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("blammo");
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    let mut server = Server::builder();
    server.should_error();
    let server = server.build();

    let stream = ExplodingStream(server.connect_tcp());

    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let _ = Ssl::new(&ctx.build()).unwrap().connect(stream);
}

#[test]
#[should_panic(expected = "blammo")]
fn read_panic() {
    struct ExplodingStream(TcpStream);

    impl Read for ExplodingStream {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("blammo");
        }
    }

    impl Write for ExplodingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    let mut server = Server::builder();
    server.should_error();
    let server = server.build();

    let stream = ExplodingStream(server.connect_tcp());

    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let _ = Ssl::new(&ctx.build()).unwrap().connect(stream);
}

#[test]
#[should_panic(expected = "blammo")]
fn flush_panic() {
    struct ExplodingStream(TcpStream);

    impl Read for ExplodingStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for ExplodingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            panic!("blammo");
        }
    }

    let mut server = Server::builder();
    server.should_error();
    let server = server.build();

    let stream = ExplodingStream(server.connect_tcp());

    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let _ = Ssl::new(&ctx.build()).unwrap().connect(stream);
}

#[test]
fn refcount_ssl_context() {
    let mut ssl = {
        let ctx = SslContext::builder(SslMethod::tls()).unwrap();
        Ssl::new(&ctx.build()).unwrap()
    };

    {
        let new_ctx_a = SslContext::builder(SslMethod::tls()).unwrap().build();
        let _new_ctx_b = ssl.set_ssl_context(&new_ctx_a);
    }
}

#[test]
#[cfg_attr(target_os = "windows", ignore)]
#[cfg_attr(all(target_os = "macos"), ignore)]
fn default_verify_paths() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_default_verify_paths().unwrap();
    ctx.set_verify(SslVerifyMode::PEER).unwrap();
    let ctx = ctx.build();
    let s = match TcpStream::connect("google.com:443") {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut ssl = Ssl::new(&ctx).unwrap();
    ssl.set_hostname("google.com").unwrap();
    let mut socket = ssl.connect(s).unwrap();

    socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut result = vec![];
    socket.read_to_end(&mut result).unwrap();

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"));
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

#[test]
fn add_extra_chain_cert() {
    let cert = X509::from_pem(CERT).unwrap();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.add_extra_chain_cert(cert).unwrap();
}

#[test]
fn verify_valid_hostname() {
    let server = Server::builder().build();
    let mut client = server.client_with_root_ca();

    client.ctx().set_verify(SslVerifyMode::PEER).unwrap();

    let mut client = client.build().builder();

    client
        .ssl()
        .verify_param_mut()
        .unwrap()
        .set_host("foobar.com")
        .unwrap();
    client.connect();
}

#[test]
fn verify_valid_hostname_with_wildcard() {
    let mut server = Server::builder();

    server
        .ctx()
        .set_certificate_chain_file("test/cert-wildcard.pem")
        .unwrap();

    let server = server.build();
    let mut client = server.client_with_root_ca();

    client.ctx().set_verify(SslVerifyMode::PEER).unwrap();

    let mut client = client.build().builder();
    client
        .ssl()
        .verify_param_mut()
        .unwrap()
        .set_host("yes.foobar.com")
        .unwrap();
    client.connect();
}

#[test]
fn verify_reject_underscore_hostname_with_wildcard() {
    let mut server = Server::builder();

    server.should_error();
    server
        .ctx()
        .set_certificate_chain_file("test/cert-wildcard.pem")
        .unwrap();

    let server = server.build();
    let mut client = server.client_with_root_ca();

    client.ctx().set_verify(SslVerifyMode::PEER).unwrap();

    let mut client = client.build().builder();
    client
        .ssl()
        .verify_param_mut()
        .unwrap()
        .set_host("not_allowed.foobar.com")
        .unwrap();
    client.connect_err();
}

#[cfg(feature = "underscore-wildcards")]
#[test]
fn verify_allow_underscore_hostname_with_wildcard() {
    let mut server = Server::builder();

    server
        .ctx()
        .set_certificate_chain_file("test/cert-wildcard.pem")
        .unwrap();

    let server = server.build();
    let mut client = server.client_with_root_ca();

    client.ctx().set_verify(SslVerifyMode::PEER).unwrap();

    let mut client = client.build().builder();

    client
        .ssl()
        .verify_param_mut()
        .unwrap()
        .set_hostflags(X509CheckFlags::UNDERSCORE_WILDCARDS);
    client
        .ssl()
        .verify_param_mut()
        .unwrap()
        .set_host("now_allowed.foobar.com")
        .unwrap();
    client.connect();
}

#[test]
fn verify_invalid_hostname() {
    let mut server = Server::builder();

    server.should_error();

    let server = server.build();
    let mut client = server.client_with_root_ca();

    client.ctx().set_verify(SslVerifyMode::PEER).unwrap();

    let mut client = client.build().builder();
    client
        .ssl()
        .verify_param_mut()
        .unwrap()
        .set_host("bogus.com")
        .unwrap();
    client.connect_err();
}

#[test]
fn connector_valid_hostname() {
    let server = Server::builder().build();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();

    let s = server.connect_tcp();
    let mut s = connector.build().connect("foobar.com", s).unwrap();
    s.read_exact(&mut [0]).unwrap();
}

#[test]
fn bare_connector_requires_trusted_certificate_by_default() {
    let mut server = Server::builder();
    server.should_error();
    let server = server.build();
    let connector = SslConnector::bare_builder(SslMethod::tls()).unwrap();
    let result = connector
        .build()
        .connect("foobar.com", server.connect_tcp());
    assert!(
        matches!(result, Err(HandshakeError::Failure(ref mid)) if mid.ssl().verify_result().is_err())
    );
}

#[test]
fn bare_connector_uses_caller_trust_store() {
    let server = Server::builder().build();
    let mut connector = SslConnector::bare_builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();
    let mut stream = connector
        .build()
        .connect("foobar.com", server.connect_tcp())
        .unwrap();
    stream.read_exact(&mut [0]).unwrap();
}

#[test]
fn connector_retains_connection_hostname_policy() {
    let mut server = Server::builder();
    server.should_error();
    server
        .ctx()
        .set_certificate_chain_file("test/cert-wildcard.pem")
        .unwrap();
    let server = server.build();
    let mut connector = SslConnector::bare_builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();
    let connector = connector.build();
    let mut config = connector.configure().unwrap();
    config
        .verify_param_mut()
        .unwrap()
        .set_hostflags(X509CheckFlags::NO_WILDCARDS);
    let result = config.connect("yes.foobar.com", server.connect_tcp());
    assert!(
        matches!(result, Err(HandshakeError::Failure(ref mid)) if mid.ssl().verify_result() == Err(crate::x509::X509VerifyError::HOSTNAME_MISMATCH))
    );
}

#[test]
fn connector_retains_store_hostname_policy() {
    let mut server = Server::builder();
    server.should_error();
    let server = server.build();
    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(X509::from_pem(ROOT_CERT).unwrap()).unwrap();
    store
        .verify_param_mut()
        .set_hostflags(X509CheckFlags::NEVER_CHECK_SUBJECT);
    let mut connector = SslConnector::bare_builder(SslMethod::tls()).unwrap();
    connector.set_cert_store(store.build()).unwrap();
    let result = connector
        .build()
        .connect("foobar.com", server.connect_tcp());
    assert!(
        matches!(result, Err(HandshakeError::Failure(ref mid)) if mid.ssl().verify_result() == Err(crate::x509::X509VerifyError::HOSTNAME_MISMATCH))
    );
}

#[test]
fn connector_inherits_context_hostname_policy() {
    let mut server = Server::builder();
    server.should_error();
    server
        .ctx()
        .set_certificate_chain_file("test/cert-wildcard.pem")
        .unwrap();
    let server = server.build();
    let mut connector = SslConnector::bare_builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();
    connector
        .verify_param_mut()
        .unwrap()
        .set_hostflags(X509CheckFlags::NO_WILDCARDS);
    let result = connector
        .build()
        .connect("yes.foobar.com", server.connect_tcp());
    assert!(
        matches!(result, Err(HandshakeError::Failure(ref mid)) if mid.ssl().verify_result() == Err(crate::x509::X509VerifyError::HOSTNAME_MISMATCH))
    );
}

#[test]
fn invalid_context_parameters_prevent_connection_creation() {
    let mut context = SslContext::builder(SslMethod::tls()).unwrap();
    assert!(context.verify_param_mut().unwrap().set_host("").is_err());
    assert!(Ssl::new(&context.build()).is_err());
}

#[test]
fn connector_invalid_hostname() {
    let mut server = Server::builder();
    server.should_error();
    let server = server.build();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();

    let s = server.connect_tcp();
    connector.build().connect("bogus.com", s).unwrap_err();
}

#[test]
fn connector_invalid_no_hostname_verification() {
    let server = Server::builder().build();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();

    let s = server.connect_tcp();
    let mut s = connector
        .build()
        .configure()
        .unwrap()
        .verify_hostname(false)
        .connect("bogus.com", s)
        .unwrap();
    s.read_exact(&mut [0]).unwrap();
}

// SNI is omitted for IP literals and when disabled; a domain name carries it.
#[test]
fn connector_sends_sni_only_for_domain_names() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let mut server = Server::builder();
    server.expected_connections_count(3);
    server
        .ctx()
        .set_select_certificate_callback({
            let observed = Arc::clone(&observed);
            move |client_hello| {
                observed.lock().unwrap().push((
                    client_hello
                        .get_extension(ExtensionType::SERVER_NAME)
                        .is_some(),
                    client_hello
                        .servername(NameType::HOST_NAME)
                        .map(ToOwned::to_owned),
                ));
                Ok(())
            }
        })
        .unwrap();
    let server = server.build();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();
    let connector = connector.build();
    for (domain, use_sni) in [
        ("127.0.0.1", true),
        ("foobar.com", false),
        ("foobar.com", true),
    ] {
        let mut s = connector
            .configure()
            .unwrap()
            .use_server_name_indication(use_sni)
            .verify_hostname(false)
            .connect(domain, server.connect_tcp())
            .unwrap();
        s.read_exact(&mut [0]).unwrap();
    }
    assert_eq!(
        *observed.lock().unwrap(),
        [
            (false, None),
            (false, None),
            (true, Some("foobar.com".to_owned()))
        ]
    );
}

#[test]
fn connector_no_hostname_still_verifies() {
    let mut server = Server::builder();
    server.should_error();
    let server = server.build();

    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();

    let s = server.connect_tcp();
    assert!(
        connector
            .configure()
            .unwrap()
            .verify_hostname(false)
            .connect("fizzbuzz.com", s)
            .is_err()
    );
}

#[test]
fn connector_no_hostname_can_disable_verify() {
    let server = Server::builder().build();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_verify(SslVerifyMode::NONE).unwrap();
    let connector = connector.build();

    let s = server.connect_tcp();
    let mut s = connector
        .configure()
        .unwrap()
        .verify_hostname(false)
        .connect("foobar.com", s)
        .unwrap();
    s.read_exact(&mut [0]).unwrap();
}

fn test_mozilla_server(new: fn(SslMethod) -> Result<SslAcceptorBuilder, ErrorStack>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let t = thread::spawn(move || {
        let key = PKey::private_key_from_pem(KEY).unwrap();
        let cert = X509::from_pem(CERT).unwrap();
        let mut acceptor = new(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        let acceptor = acceptor.build();
        let stream = listener.accept().unwrap().0;
        let mut stream = acceptor.accept(stream).unwrap();

        stream.write_all(b"hello").unwrap();
    });

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();
    let connector = connector.build();

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut stream = connector.connect("foobar.com", stream).unwrap();

    let mut buf = [0; 5];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(b"hello", &buf);

    t.join().unwrap();
}

#[test]
fn connector_client_server_mozilla_intermediate() {
    test_mozilla_server(SslAcceptor::mozilla_intermediate);
}

#[test]
fn connector_client_server_mozilla_modern() {
    test_mozilla_server(SslAcceptor::mozilla_modern);
}

#[test]
fn connector_client_server_mozilla_intermediate_v5() {
    test_mozilla_server(SslAcceptor::mozilla_intermediate_v5);
}

#[test]
fn shutdown() {
    let mut server = Server::builder();
    server.io_cb(|mut s| {
        assert_eq!(s.read(&mut [0]).unwrap(), 0);
        assert_eq!(s.shutdown().unwrap(), ShutdownResult::Received);
    });
    let server = server.build();

    let mut s = server.client().connect();

    assert_eq!(s.get_shutdown(), ShutdownState::empty());
    assert_eq!(s.shutdown().unwrap(), ShutdownResult::Sent);
    assert_eq!(s.get_shutdown(), ShutdownState::SENT);
    assert_eq!(s.shutdown().unwrap(), ShutdownResult::Received);
    assert_eq!(
        s.get_shutdown(),
        ShutdownState::SENT | ShutdownState::RECEIVED
    );
}

#[test]
fn client_ca_list() {
    let names = X509Name::load_client_ca_file("test/root-ca.pem").unwrap();
    assert_eq!(names.len(), 1);

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_client_ca_list(names).unwrap();
}

#[test]
fn keying_export() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let label = "EXPERIMENTAL test";
    let context = b"my context";

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        let ssl = Ssl::new(&ctx.build()).unwrap();
        let mut stream = ssl.accept(stream).unwrap();

        let mut buf = [0; 32];
        stream
            .ssl()
            .export_keying_material(&mut buf, label, Some(context))
            .unwrap();

        stream.write_all(&[0]).unwrap();

        buf
    });

    let stream = TcpStream::connect(addr).unwrap();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let ssl = Ssl::new(&ctx.build()).unwrap();
    let mut stream = ssl.connect(stream).unwrap();

    let mut buf = [1; 32];
    stream
        .ssl()
        .export_keying_material(&mut buf, label, Some(context))
        .unwrap();

    stream.read_exact(&mut [0]).unwrap();

    let buf2 = guard.join().unwrap();

    assert_eq!(buf, buf2);
}

#[test]
fn no_version_overlap() {
    let mut server = Server::builder();
    server.ctx().set_min_proto_version(None).unwrap();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_1))
        .unwrap();
    assert_eq!(server.ctx().max_proto_version(), Some(SslVersion::TLS1_1));
    server.should_error();
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    assert_eq!(client.ctx().min_proto_version(), Some(SslVersion::TLS1_2));
    client.ctx().set_max_proto_version(None).unwrap();

    client.connect_err();
}

fn _check_kinds() {
    fn is_send<T: Send>() {}
    fn is_sync<T: Sync>() {}

    is_send::<SslStream<TcpStream>>();
    is_sync::<SslStream<TcpStream>>();
}

#[test]
fn psk_ciphers() {
    const CIPHER: &str = "PSK-AES128-CBC-SHA";
    const PSK: &[u8] = b"thisisaverysecurekey";
    const CLIENT_IDENT: &[u8] = b"thisisaclient";
    static CLIENT_CALLED: AtomicBool = AtomicBool::new(false);
    static SERVER_CALLED: AtomicBool = AtomicBool::new(false);

    let mut server = Server::builder();
    server.ctx().set_cipher_list(CIPHER).unwrap();
    server
        .ctx()
        .set_psk_server_callback(|_, identity, psk| {
            assert_eq!(identity.unwrap_or(&[]), CLIENT_IDENT);
            psk[..PSK.len()].copy_from_slice(PSK);
            SERVER_CALLED.store(true, Ordering::SeqCst);
            Ok(PSK.len())
        })
        .unwrap();

    let server = server.build();

    let mut client = server.client();
    // This test relies on TLS 1.2 suites
    client.ctx().set_options(SslOptions::NO_TLSV1_3);
    client.ctx().set_cipher_list(CIPHER).unwrap();
    client
        .ctx()
        .set_psk_client_callback(move |_, _, identity, psk| {
            identity[..CLIENT_IDENT.len()].copy_from_slice(CLIENT_IDENT);
            identity[CLIENT_IDENT.len()] = 0;
            psk[..PSK.len()].copy_from_slice(PSK);
            CLIENT_CALLED.store(true, Ordering::SeqCst);
            Ok(PSK.len())
        })
        .unwrap();

    client.connect();

    assert!(CLIENT_CALLED.load(Ordering::SeqCst) && SERVER_CALLED.load(Ordering::SeqCst));
}

#[test]
fn psk_callbacks_reject_invalid_output() {
    const CIPHER: &str = "PSK-AES128-CBC-SHA";
    for invalid_length in [false, true] {
        let mut server = Server::builder();
        server.ctx().set_cipher_list(CIPHER).unwrap();
        server
            .ctx()
            .set_psk_server_callback(|_, _, output| {
                output[0] = 1;
                Ok(1)
            })
            .unwrap();
        server.should_error();
        let server = server.build();
        let mut client = server.client();
        client.ctx().set_options(SslOptions::NO_TLSV1_3);
        client.ctx().set_cipher_list(CIPHER).unwrap();
        let invoked = std::sync::Arc::new(AtomicBool::new(false));
        let called = invoked.clone();
        client
            .ctx()
            .set_psk_client_callback(move |_, _, identity, output| {
                called.store(true, Ordering::SeqCst);
                assert!(identity.iter().chain(output.iter()).all(|&byte| byte == 0));
                output[0] = 1;
                if invalid_length {
                    Ok(output.len() + 1)
                } else {
                    identity.fill(b'a');
                    Ok(1)
                }
            })
            .unwrap();
        client.connect_err();
        assert!(invoked.load(Ordering::SeqCst));
    }
}

#[test]
fn sni_callback_swapped_ctx() {
    static CALLED_BACK: AtomicBool = AtomicBool::new(false);

    let mut server = Server::builder();

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_servername_callback(|_, _| {
        CALLED_BACK.store(true, Ordering::SeqCst);
        Ok(())
    })
    .unwrap();

    let keyed_ctx = mem::replace(server.ctx(), ctx).build();
    server.ssl_cb(move |ssl| ssl.set_ssl_context(&keyed_ctx).unwrap());

    let server = server.build();

    server.client().connect();

    assert!(CALLED_BACK.load(Ordering::SeqCst));
}

#[test]
fn get_curve() {
    let server = Server::builder().build();
    let client = server.client_with_root_ca();
    let client_stream = client.connect();
    let curve = client_stream.ssl().curve();
    assert!(curve.is_some());
    let curve_name = client_stream.ssl().curve_name();
    assert!(curve_name.is_some());
}

#[test]
fn typed_group_configuration_controls_negotiation() {
    let mut server = Server::builder();
    server.ctx().set_groups(&[KeyShare::P256]).unwrap();
    assert!(
        server
            .ctx()
            .set_groups(&[KeyShare::P256, KeyShare::P256])
            .is_err()
    );
    let server = server.build();
    let mut client = server.client_with_root_ca().build().builder();
    client.ssl().set_groups(&[KeyShare::X25519]).unwrap();
    client.ssl().set_groups(&[]).unwrap();
    client.ssl().set_groups(&[KeyShare::P256]).unwrap();
    assert!(
        client
            .ssl()
            .set_groups(&[KeyShare::P256, KeyShare::P256])
            .is_err()
    );
    let stream = client.connect();
    assert_eq!(stream.ssl().curve(), Some(KeyShare::P256.0));
}

#[test]
fn used_hello_retry_request_true() {
    let mut server_builder = Server::builder();
    // Configures the server to prefer it's options over the client
    server_builder
        .ctx()
        .set_options(SslOptions::CIPHER_SERVER_PREFERENCE);
    server_builder
        .ctx()
        .set_groups(&[KeyShare::P256, KeyShare::X25519])
        .unwrap();
    let server = server_builder.build();
    let mut client_builder = server.client_with_root_ca();
    // configures the client to send this supported groups
    client_builder
        .ctx()
        .set_groups(&[KeyShare::X25519, KeyShare::P256])
        .unwrap();

    let client_stream = client_builder.connect();
    let ssl = client_stream.ssl();
    assert!(ssl.used_hello_retry_request());
}

#[test]
fn used_hello_retry_request_false() {
    let mut server_builder = Server::builder();
    // Server doesn't configure CIPHER_SERVER_PREFERENCE, so it will use the preference of the client
    server_builder
        .ctx()
        .set_groups(&[KeyShare::P256, KeyShare::X25519])
        .unwrap();
    let server = server_builder.build();
    let mut client_builder = server.client_with_root_ca();
    // configures the client to send this supported groups
    client_builder
        .ctx()
        .set_groups(&[KeyShare::X25519, KeyShare::P256])
        .unwrap();

    let client_stream = client_builder.connect();
    let ssl = client_stream.ssl();
    assert!(!ssl.used_hello_retry_request());
}

#[test]
fn test_get_ciphers() {
    let ctx_builder = SslContext::builder(SslMethod::tls()).unwrap();
    let ctx_builder_ciphers: Vec<Option<&str>> = ctx_builder
        .ciphers()
        .unwrap()
        .into_iter()
        .map(|v| v.name())
        .collect();
    assert!(!ctx_builder_ciphers.is_empty());
    assert!(ctx_builder_ciphers.iter().all(Option::is_some));

    let ctx = ctx_builder.build();
    let ctx_ciphers: Vec<Option<&str>> = ctx
        .ciphers()
        .unwrap()
        .into_iter()
        .map(|v| v.name())
        .collect();
    assert!(!ctx_ciphers.is_empty());
    assert!(ctx_ciphers.iter().all(Option::is_some));

    assert_eq!(ctx_builder_ciphers.len(), ctx_ciphers.len());

    for (ctx_builder_cipher, ctx_cipher) in ctx_builder_ciphers.into_iter().zip(ctx_ciphers) {
        assert_eq!(ctx_builder_cipher, ctx_cipher);
    }
}

/// Whether BoringSSL sees AES hardware. CI masks AES-NI with `OPENSSL_ia32cap`
/// and sets `BTLS_TEST_NO_AES` to also cover the defaults chosen without it.
fn has_aes_hardware() -> bool {
    // SAFETY: `EVP_has_aes_hardware` only reads CPU capabilities.
    let has_aes = unsafe { crate::ffi::EVP_has_aes_hardware() } == 1;
    assert!(
        !(has_aes && std::env::var_os("BTLS_TEST_NO_AES").is_some()),
        "OPENSSL_ia32cap did not mask AES hardware"
    );
    has_aes
}

#[test]
fn set_tls13_ciphers_orders_offer_and_selection() {
    // BoringSSL's default client order depends on AES hardware.
    let default_order = if has_aes_hardware() {
        vec![0x1301, 0x1302, 0x1303]
    } else {
        vec![0x1303, 0x1301, 0x1302]
    };
    let offered = Arc::new(Mutex::new(Vec::new()));
    let tls13_offer = |hello: &ssl::ClientHello<'_>| {
        hello
            .ciphers()
            .chunks_exact(2)
            .map(|id| u16::from_be_bytes([id[0], id[1]]))
            .filter(|id| (0x1301..=0x1303).contains(id))
            .collect::<Vec<_>>()
    };

    let mut server = Server::builder();
    server.expected_connections_count(3);
    // Never first in BoringSSL's default server order, with or without AES hardware.
    server
        .ctx()
        .set_tls13_ciphers(&[Tls13Cipher::AES_256_GCM_SHA384])
        .unwrap();
    server
        .ctx()
        .set_select_certificate_callback({
            let offered = offered.clone();
            move |hello| {
                offered.lock().unwrap().push(tls13_offer(&hello));
                Ok(())
            }
        })
        .unwrap();
    let server = server.build();

    // A non-default order, as Firefox sends it.
    let mut client = server.client_with_root_ca();
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
        .ctx()
        .set_tls13_ciphers(&[
            Tls13Cipher::AES_128_GCM_SHA256,
            Tls13Cipher::CHACHA20_POLY1305_SHA256,
            Tls13Cipher::AES_256_GCM_SHA384,
        ])
        .unwrap();
    let client = client.build();
    let stream = client.builder().connect();
    // The server's own list decides the suite.
    assert_eq!(
        stream.ssl().current_cipher().unwrap().standard_name(),
        Some("TLS_AES_256_GCM_SHA384")
    );

    let mut connection = client.builder();
    connection
        .ssl()
        .set_tls13_ciphers(&[
            Tls13Cipher::CHACHA20_POLY1305_SHA256,
            Tls13Cipher::AES_256_GCM_SHA384,
        ])
        .unwrap();
    connection.connect();

    // An empty list restores BoringSSL's default, not the context's list.
    let mut connection = client.builder();
    connection.ssl().set_tls13_ciphers(&[]).unwrap();
    connection.connect();

    assert_eq!(
        *offered.lock().unwrap(),
        [
            vec![0x1301, 0x1303, 0x1302],
            vec![0x1303, 0x1302],
            default_order
        ]
    );
    // Only TLS 1.3 suites are accepted.
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    assert!(ctx.set_tls13_ciphers(&[Tls13Cipher(0xc02f)]).is_err());
}

#[test]
fn test_set_compliance() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_compliance_policy(CompliancePolicy::FIPS_202205)
        .unwrap();

    assert_eq!(ctx.max_proto_version().unwrap(), SslVersion::TLS1_3);
    assert_eq!(ctx.min_proto_version().unwrap(), SslVersion::TLS1_2);

    const FIPS_CIPHERS: [&str; 4] = [
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    ];

    let ciphers = ctx.ciphers().unwrap();
    assert_eq!(ciphers.len(), FIPS_CIPHERS.len());

    for cipher in ciphers.into_iter().zip(FIPS_CIPHERS) {
        assert_eq!(cipher.0.name(), Some(cipher.1));
    }

    {
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_compliance_policy(CompliancePolicy::WPA3_192_202304)
            .unwrap();

        assert_eq!(ctx.max_proto_version().unwrap(), SslVersion::TLS1_3);
        assert_eq!(ctx.min_proto_version().unwrap(), SslVersion::TLS1_2);

        const WPA3_192_CIPHERS: [&str; 2] = [
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
        ];

        let ciphers = ctx.ciphers().unwrap();
        assert_eq!(ciphers.len(), WPA3_192_CIPHERS.len());

        for cipher in ciphers.into_iter().zip(WPA3_192_CIPHERS) {
            assert_eq!(cipher.0.name(), Some(cipher.1));
        }

        ctx.set_compliance_policy(CompliancePolicy::NONE)
            .expect_err("Testing expect err if set compliance policy to NONE");
    }
}

#[test]
fn drop_ex_data_in_context() {
    let index = SslContext::new_ex_index::<&'static str>().unwrap();
    let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();

    assert_eq!(ctx.replace_ex_data(index, "comté").unwrap(), None);
    assert_eq!(
        ctx.replace_ex_data(index, "camembert").unwrap(),
        Some("comté")
    );
    assert_eq!(
        ctx.replace_ex_data(index, "raclette").unwrap(),
        Some("camembert")
    );
}

#[test]
fn drop_ex_data_in_ssl() {
    let index = Ssl::new_ex_index::<&'static str>().unwrap();
    let ctx = SslContext::builder(SslMethod::dtls()).unwrap().build();
    let mut ssl = Ssl::new(&ctx).unwrap();

    assert_eq!(ssl.replace_ex_data(index, "comté").unwrap(), None);
    assert_eq!(
        ssl.replace_ex_data(index, "camembert").unwrap(),
        Some("comté")
    );
    assert_eq!(
        ssl.replace_ex_data(index, "raclette").unwrap(),
        Some("camembert")
    );
}

#[test]
fn test_info_callback() {
    static CALLED_BACK: AtomicBool = AtomicBool::new(false);

    let server = Server::builder().build();
    let mut client = server.client();
    client
        .ctx()
        .set_info_callback(move |_, _, _| {
            CALLED_BACK.store(true, Ordering::Relaxed);
        })
        .unwrap();

    client.connect();
    assert!(CALLED_BACK.load(Ordering::Relaxed));
}

#[test]
fn test_ssl_set_compliance() {
    let ctx = SslContext::builder(SslMethod::tls()).unwrap().build();
    let mut ssl = Ssl::new(&ctx).unwrap();
    ssl.set_compliance_policy(CompliancePolicy::FIPS_202205)
        .unwrap();

    assert_eq!(ssl.max_proto_version().unwrap(), SslVersion::TLS1_3);
    assert_eq!(ssl.min_proto_version().unwrap(), SslVersion::TLS1_2);

    const FIPS_CIPHERS: [&str; 4] = [
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    ];

    let ciphers = ssl.ciphers();
    assert_eq!(ciphers.len(), FIPS_CIPHERS.len());

    for cipher in ciphers.into_iter().zip(FIPS_CIPHERS) {
        assert_eq!(cipher.0.name(), Some(cipher.1));
    }

    {
        let ctx = SslContext::builder(SslMethod::tls()).unwrap().build();
        let mut ssl = Ssl::new(&ctx).unwrap();
        ssl.set_compliance_policy(CompliancePolicy::WPA3_192_202304)
            .unwrap();

        assert_eq!(ssl.max_proto_version().unwrap(), SslVersion::TLS1_3);
        assert_eq!(ssl.min_proto_version().unwrap(), SslVersion::TLS1_2);

        const WPA3_192_CIPHERS: [&str; 2] = [
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
        ];

        let ciphers = ssl.ciphers();
        assert_eq!(ciphers.len(), WPA3_192_CIPHERS.len());

        for cipher in ciphers.into_iter().zip(WPA3_192_CIPHERS) {
            assert_eq!(cipher.0.name(), Some(cipher.1));
        }

        ssl.set_compliance_policy(CompliancePolicy::NONE)
            .expect_err("Testing expect err if set compliance policy to NONE");
    }
}

#[test]
fn ex_data_drop() {
    use crate::ssl::SslContextBuilder;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU32;
    use std::sync::atomic::Ordering::Relaxed;

    struct TrackDrop(Arc<AtomicU32>);
    impl Drop for TrackDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Relaxed);
        }
    }

    let mut ctx = SslContextBuilder::new(SslMethod::tls()).unwrap();
    let index = SslContext::new_ex_index().unwrap();
    let d1 = Arc::new(AtomicU32::new(100));
    let d2 = Arc::new(AtomicU32::new(200));
    let d3 = Arc::new(AtomicU32::new(300));
    ctx.set_ex_data(index, TrackDrop(d1.clone())).unwrap();
    assert_eq!(100, d1.load(Relaxed));
    assert_eq!(200, d2.load(Relaxed));
    ctx.replace_ex_data(index, TrackDrop(d2.clone())).unwrap();
    assert_eq!(101, d1.load(Relaxed));
    assert_eq!(200, d2.load(Relaxed));
    ctx.replace_ex_data(index, TrackDrop(d3.clone())).unwrap();
    assert_eq!(101, d1.load(Relaxed));
    assert_eq!(201, d2.load(Relaxed));
    assert_eq!(300, d3.load(Relaxed));
    drop(ctx);
    assert_eq!(101, d1.load(Relaxed));
    assert_eq!(201, d2.load(Relaxed));
    assert_eq!(301, d3.load(Relaxed));

    let mut ctx2 = SslContextBuilder::new(SslMethod::tls()).unwrap();

    ctx2.set_ex_data(index, TrackDrop(d1.clone())).unwrap();
    ctx2.set_ex_data(index, TrackDrop(d2.clone())).unwrap();
    drop(ctx2);
    assert_eq!(102, d1.load(Relaxed));
    assert_eq!(202, d2.load(Relaxed));
}

#[test]
fn peer_signature_algorithm() {
    // Default handshake: client should observe the server's CertificateVerify signature.
    let server = Server::builder().build();
    let s = server.client().connect();
    let sigalg = s.ssl().peer_signature_algorithm();
    assert!(
        sigalg.is_some(),
        "client should see peer (server) signature algorithm after handshake",
    );
    assert!(
        sigalg.unwrap().name().is_some(),
        "peer signature algorithm should have a resolvable name",
    );
}

#[test]
fn peer_signature_algorithm_mtls_server_sees_client() {
    // Server requires a client certificate; verify that the server-side SslRef
    // surfaces the client's CertificateVerify signature scheme as its peer sig alg.
    // Observe from a server-side HANDSHAKE_DONE info callback so the capture
    // happens synchronously during the server's accept, before the client's
    // connect() returns.
    let captured = Arc::new(AtomicBool::new(false));

    let mut server_builder = Server::builder();
    {
        let mut store = X509StoreBuilder::new().unwrap();
        store.add_cert(X509::from_pem(ROOT_CERT).unwrap()).unwrap();
        server_builder
            .ctx()
            .set_verify_cert_store(&store.build())
            .unwrap();
        server_builder
            .ctx()
            .set_verify(SslVerifyMode::PEER)
            .unwrap();
        let captured_cb = Arc::clone(&captured);
        server_builder
            .ctx()
            .set_info_callback(move |ssl, mode, _value| {
                if mode == SslInfoCallbackMode::HANDSHAKE_DONE
                    && let Some(sa) = ssl.peer_signature_algorithm()
                {
                    assert!(sa.name().is_some(), "client sig scheme should have a name");
                    captured_cb.store(true, Ordering::SeqCst);
                }
            })
            .unwrap();
    }
    let server = server_builder.build();

    let mut client_builder = server.client_with_root_ca();
    client_builder
        .ctx()
        .set_certificate_chain_file("test/cert.pem")
        .unwrap();
    client_builder
        .ctx()
        .set_private_key_file("test/key.pem", SslFiletype::PEM)
        .unwrap();
    let _ = client_builder.connect();

    assert!(
        captured.load(Ordering::SeqCst),
        "server should observe client signature scheme during mTLS",
    );
}

#[test]
fn signature_algorithm_used_server_default() {
    // BoringSSL only retains signature_algorithm_used during the handshake, so we
    // capture it from a HANDSHAKE_DONE info callback.
    let captured = Arc::new(AtomicBool::new(false));

    let mut server_builder = Server::builder();
    {
        let captured_cb = Arc::clone(&captured);
        server_builder
            .ctx()
            .set_info_callback(move |ssl, mode, _value| {
                if mode == SslInfoCallbackMode::HANDSHAKE_DONE
                    && let Some(sa) = ssl.signature_algorithm_used()
                {
                    assert!(sa.name().is_some());
                    captured_cb.store(true, Ordering::SeqCst);
                }
            })
            .unwrap();
    }
    let server = server_builder.build();
    let _ = server.client_with_root_ca().connect();

    assert!(
        captured.load(Ordering::SeqCst),
        "server should observe signature_algorithm_used at HANDSHAKE_DONE",
    );
}

#[test]
fn signature_algorithm_used_post_handshake_returns_none() {
    // BoringSSL drops the value after the handshake. Confirm the binding
    // surfaces that contract: calling on the client SslStream post-handshake
    // returns None.
    let server = Server::builder().build();
    let s = server.client_with_root_ca().connect();
    assert!(
        s.ssl().signature_algorithm_used().is_none(),
        "BoringSSL discards signature_algorithm_used after handshake",
    );
}

#[test]
fn signature_algorithm_used_mtls_client() {
    // Client side mTLS: capture the sig scheme the client used in CertificateVerify.
    let mut server_builder = Server::builder();
    {
        let mut store = X509StoreBuilder::new().unwrap();
        store.add_cert(X509::from_pem(ROOT_CERT).unwrap()).unwrap();
        server_builder
            .ctx()
            .set_verify_cert_store(&store.build())
            .unwrap();
        server_builder
            .ctx()
            .set_verify(SslVerifyMode::PEER)
            .unwrap();
    }
    let server = server_builder.build();

    let captured = Arc::new(AtomicBool::new(false));
    let captured_cb = Arc::clone(&captured);

    let mut client_builder = server.client_with_root_ca();
    client_builder
        .ctx()
        .set_certificate_chain_file("test/cert.pem")
        .unwrap();
    client_builder
        .ctx()
        .set_private_key_file("test/key.pem", SslFiletype::PEM)
        .unwrap();
    client_builder
        .ctx()
        .set_info_callback(move |ssl, mode, _value| {
            if mode == SslInfoCallbackMode::HANDSHAKE_DONE
                && let Some(sa) = ssl.signature_algorithm_used()
            {
                assert!(sa.name().is_some());
                captured_cb.store(true, Ordering::SeqCst);
            }
        })
        .unwrap();
    let _ = client_builder.connect();

    assert!(
        captured.load(Ordering::SeqCst),
        "client should observe signature_algorithm_used at HANDSHAKE_DONE in mTLS",
    );
}

// ===========================================================================
// per-connection verify algorithm prefs
// ===========================================================================

#[test]
fn set_verify_algorithm_prefs_ssl_accepts_matching() {
    // Client restricts verify prefs to a scheme the server can satisfy.
    let server = Server::builder().build();

    let client_builder = server.client();
    let mut ssl_builder = client_builder.build().builder();
    ssl_builder
        .ssl()
        .set_verify_algorithm_prefs(&[SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256])
        .expect("verify prefs should be accepted");
    let s = ssl_builder.connect();
    let sa = s.ssl().peer_signature_algorithm().unwrap();
    assert_eq!(sa, SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256);
}

#[test]
fn set_verify_algorithm_prefs_ssl_rejects_unsatisfiable() {
    // Client restricts verify prefs to a scheme the server's RSA cert cannot
    // satisfy. The handshake must fail.
    let mut server_builder = Server::builder();
    server_builder.should_error();
    let server = server_builder.build();

    let client_builder = server.client();
    let mut ssl_builder = client_builder.build().builder();
    ssl_builder
        .ssl()
        .set_verify_algorithm_prefs(&[SslSignatureAlgorithm::ED25519])
        .expect("verify prefs should be accepted by setter");
    let _err = ssl_builder.connect_err();
}
