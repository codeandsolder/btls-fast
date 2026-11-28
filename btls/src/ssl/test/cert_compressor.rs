use std::io::Write as _;

use super::server::Server;
use crate::ssl::CertificateCompressor;
use crate::x509::X509;
use crate::x509::store::X509StoreBuilder;

struct BrotliCompressor {
    q: u32,
    lgwin: u32,
}

impl Default for BrotliCompressor {
    fn default() -> Self {
        Self { q: 11, lgwin: 32 }
    }
}

impl CertificateCompressor for BrotliCompressor {
    const ALGORITHM: crate::ssl::CertificateCompressionAlgorithm =
        crate::ssl::CertificateCompressionAlgorithm(1234);

    const CAN_COMPRESS: bool = true;

    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        let mut writer = brotli::CompressorWriter::new(output, 1024, self.q, self.lgwin);
        writer.write_all(input)?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        brotli::BrotliDecompress(&mut std::io::Cursor::new(input), output)?;
        Ok(())
    }
}

#[test]
fn server_only_cert_compression() {
    let mut server_builder = Server::builder();
    server_builder
        .ctx()
        .add_certificate_compression_algorithm(BrotliCompressor::default())
        .unwrap();

    let server = server_builder.build();

    let mut store = X509StoreBuilder::new().unwrap();
    let x509 = X509::from_pem(super::ROOT_CERT).unwrap();
    store.add_cert(&x509).unwrap();

    let client = server.client();

    client.connect();
}

#[test]
fn client_only_cert_compression() {
    let server_builder = Server::builder().build();

    let mut store = X509StoreBuilder::new().unwrap();
    let x509 = X509::from_pem(super::ROOT_CERT).unwrap();
    store.add_cert(&x509).unwrap();

    let mut client = server_builder.client();
    client
        .ctx()
        .add_certificate_compression_algorithm(BrotliCompressor::default())
        .unwrap();

    client.connect();
}

#[test]
fn client_and_server_cert_compression() {
    let mut server = Server::builder();
    server
        .ctx()
        .add_certificate_compression_algorithm(BrotliCompressor::default())
        .unwrap();

    let server = server.build();

    let mut store = X509StoreBuilder::new().unwrap();
    let x509 = X509::from_pem(super::ROOT_CERT).unwrap();
    store.add_cert(&x509).unwrap();

    let mut client = server.client();
    client
        .ctx()
        .add_certificate_compression_algorithm(BrotliCompressor::default())
        .unwrap();

    client.connect();
}

// The two test codecs are identity transforms with distinct IDs. Their
// counters make it observable which registered implementation was invoked.
struct TrackedCompressor<const ID: u16, const COMPRESS: bool, const DECOMPRESS: bool> {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl<const ID: u16, const COMPRESS: bool, const DECOMPRESS: bool> CertificateCompressor
    for TrackedCompressor<ID, COMPRESS, DECOMPRESS>
{
    const ALGORITHM: crate::ssl::CertificateCompressionAlgorithm =
        crate::ssl::CertificateCompressionAlgorithm(ID);
    const CAN_COMPRESS: bool = COMPRESS;
    const CAN_DECOMPRESS: bool = DECOMPRESS;

    fn compress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        output.write_all(input)
    }

    fn decompress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        output.write_all(input)
    }
}

#[test]
fn native_compression_registration_dispatches_by_algorithm_and_owns_state() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let chosen_compress = Arc::new(AtomicUsize::new(0));
    let chosen_decompress = Arc::new(AtomicUsize::new(0));
    let unused = Arc::new(AtomicUsize::new(0));
    let rejected = Arc::new(AtomicUsize::new(0));
    let mut server = Server::builder();
    // The server's preference order wins despite the reversed client list.
    server
        .ctx()
        .add_certificate_compression_algorithm(TrackedCompressor::<1234, true, false> {
            calls: Arc::clone(&chosen_compress),
        })
        .unwrap();
    server
        .ctx()
        .add_certificate_compression_algorithm(TrackedCompressor::<1235, true, false> {
            calls: Arc::clone(&unused),
        })
        .unwrap();
    let error = server
        .ctx()
        .add_certificate_compression_algorithm(TrackedCompressor::<1234, true, true> {
            calls: Arc::clone(&rejected),
        })
        .unwrap_err();
    assert!(!error.errors().is_empty());
    assert_eq!(Arc::strong_count(&rejected), 1);
    assert_eq!(Arc::strong_count(&chosen_compress), 2);
    let server = server.build();
    let mut client = server.client_with_root_ca();
    client
        .ctx()
        .add_certificate_compression_algorithm(TrackedCompressor::<1235, false, true> {
            calls: Arc::clone(&unused),
        })
        .unwrap();
    client
        .ctx()
        .add_certificate_compression_algorithm(TrackedCompressor::<1234, false, true> {
            calls: Arc::clone(&chosen_decompress),
        })
        .unwrap();
    let stream = client.connect();
    assert_eq!(chosen_compress.load(Ordering::SeqCst), 1);
    assert_eq!(chosen_decompress.load(Ordering::SeqCst), 1);
    assert_eq!(unused.load(Ordering::SeqCst), 0);
    assert_eq!(Arc::strong_count(&chosen_decompress), 2);
    drop(stream);
    drop(server);
    assert_eq!(Arc::strong_count(&chosen_compress), 1);
    assert_eq!(Arc::strong_count(&chosen_decompress), 1);
    assert_eq!(Arc::strong_count(&unused), 1);
}

#[test]
fn certificate_compression_advertisement_limit_is_checked_at_registration() {
    use crate::{
        ffi,
        ssl::{SslContext, SslMethod},
    };
    use foreign_types::ForeignTypeRef;
    unsafe extern "C" fn unused_decompress(
        _: *mut ffi::SSL,
        _: *mut *mut ffi::CRYPTO_BUFFER,
        _: usize,
        _: *const u8,
        _: usize,
    ) -> libc::c_int {
        0
    }
    let context = SslContext::builder(SslMethod::tls()).unwrap();
    // SAFETY: the unpublished context is exclusively owned by the test. The
    // native callback has static lifetime and no handshake invokes it.
    unsafe {
        for id in 1..=127 {
            assert_eq!(
                ffi::SSL_CTX_add_cert_compression_alg(
                    context.as_ptr(),
                    id,
                    None,
                    Some(unused_decompress)
                ),
                1
            );
        }
        assert_eq!(
            ffi::SSL_CTX_add_cert_compression_alg(
                context.as_ptr(),
                128,
                None,
                Some(unused_decompress)
            ),
            0
        );
        assert!(!crate::error::ErrorStack::get().errors().is_empty());
    }
}
