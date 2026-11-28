//! PKCS #12 archives.

use crate::ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;
use openssl_macros::corresponds;
use std::ffi::CString;
use std::ptr;

use crate::error::ErrorStack;
use crate::nid::Nid;
use crate::pkey::{HasPrivate, PKey, PKeyRef, Private};
use crate::stack::{Stack, StackRef};
use crate::x509::{X509, X509Ref};
use crate::{cvt_0i, cvt_p, util::SecretCString};

pub const PKCS12_DEFAULT_ITER: c_int = 2048;

foreign_type_and_impl_send_sync! {
    type CType = ffi::PKCS12;
    fn drop = ffi::PKCS12_free;

    pub struct Pkcs12;
}

impl Pkcs12Ref {
    to_der! {
        /// Serializes the `Pkcs12` to its standard DER encoding.
        #[corresponds(i2d_PKCS12)]
        to_der,
        ffi::i2d_PKCS12
    }

    /// Extracts the contents of the `Pkcs12` with `pkey` and `cert` required.
    ///
    /// # Errors
    ///
    /// Parsing fails or the archive contains no private key or certificate.
    pub fn parse(&self, pass: &str) -> Result<ParsedPkcs12, ErrorStack> {
        let p2 = self.parse2(pass)?;
        Ok(ParsedPkcs12 {
            pkey: p2
                .pkey
                .ok_or_else(|| ErrorStack::internal_error_str("missing pkey"))?,
            cert: p2
                .cert
                .ok_or_else(|| ErrorStack::internal_error_str("missing cert"))?,
            chain: p2.ca,
        })
    }

    /// Extracts the contents of the `Pkcs12` with `pkey` and `cert` optional.
    ///
    /// # Errors
    ///
    /// The password contains a NUL byte or the native parser rejects the archive.
    #[corresponds(PKCS12_parse)]
    pub fn parse2(&self, pass: &str) -> Result<ParsedPkcs12_2, ErrorStack> {
        // SAFETY: the parser receives a valid borrowed archive, a live C-string,
        // and three writable output-pointer slots. Any returned non-null values
        // transfer native ownership to the corresponding Rust wrappers.
        unsafe {
            let pass = SecretCString::new(pass.as_bytes())?;

            let mut pkey = ptr::null_mut();
            let mut cert = ptr::null_mut();
            let mut ca = ptr::null_mut();

            cvt_0i(ffi::PKCS12_parse(
                self.as_ptr(),
                pass.as_ptr(),
                &raw mut pkey,
                &raw mut cert,
                &raw mut ca,
            ))?;

            let pkey = (!pkey.is_null()).then(|| PKey::from_ptr(pkey));
            let cert = (!cert.is_null()).then(|| X509::from_ptr(cert));
            let ca = (!ca.is_null()).then(|| Stack::from_ptr(ca));

            Ok(ParsedPkcs12_2 { pkey, cert, ca })
        }
    }
}

impl Pkcs12 {
    from_der! {
        /// Deserializes a DER-encoded PKCS#12 archive.
        #[corresponds(d2i_PKCS12)]
        from_der,
        Pkcs12,
        ffi::d2i_PKCS12,
        ::libc::size_t
    }

    /// Creates a new builder for a protected pkcs12 certificate.
    ///
    /// Uses the native defaults: AES-256-CBC with PBES2/PBKDF2-HMAC-SHA256
    /// for the private key and certificates, and 2048 iterations for both
    /// encryption-key and MAC derivation. Choose iteration counts suitable
    /// for the deployment.
    #[must_use = "Configure or consume the returned builder or cryptographic state."]
    pub fn builder() -> Pkcs12Builder {
        ffi::init();

        Pkcs12Builder {
            nid_key: Nid::UNDEF,
            nid_cert: Nid::UNDEF,
            iter: PKCS12_DEFAULT_ITER,
            mac_iter: PKCS12_DEFAULT_ITER,
            ca: None,
        }
    }
}

pub struct ParsedPkcs12 {
    pub pkey: PKey<Private>,
    pub cert: X509,
    pub chain: Option<Stack<X509>>,
}

/// [`ParsedPkcs12`] with optional fields
pub struct ParsedPkcs12_2 {
    pub pkey: Option<PKey<Private>>,
    pub cert: Option<X509>,
    pub ca: Option<Stack<X509>>,
}

impl ParsedPkcs12_2 {
    #[must_use = "Use the returned certificate, component or validity information for inspection or verification."]
    pub fn chain(&self) -> Option<&StackRef<X509>> {
        self.ca.as_deref()
    }
}

pub struct Pkcs12Builder {
    nid_key: Nid,
    nid_cert: Nid,
    iter: c_int,
    mac_iter: c_int,
    ca: Option<Stack<X509>>,
}

impl Pkcs12Builder {
    /// The encryption algorithm that should be used for the key
    pub const fn key_algorithm(&mut self, nid: Nid) -> &mut Self {
        self.nid_key = nid;
        self
    }

    /// The encryption algorithm that should be used for the cert
    pub const fn cert_algorithm(&mut self, nid: Nid) -> &mut Self {
        self.nid_cert = nid;
        self
    }

    /// Sets the key-derivation iteration count.
    ///
    /// # Errors
    ///
    /// Returns an error for a count outside the native signed integer range.
    pub fn key_iter(&mut self, iter: u32) -> Result<&mut Self, ErrorStack> {
        self.iter = c_int::try_from(iter).map_err(ErrorStack::internal_error)?;
        Ok(self)
    }

    /// Sets the independent MAC key-derivation iteration count.
    ///
    /// Zero requests the native default of 2048 iterations.
    ///
    /// # Errors
    ///
    /// Returns an error for a count outside the native signed integer range.
    pub fn mac_iter(&mut self, mac_iter: u32) -> Result<&mut Self, ErrorStack> {
        self.mac_iter = c_int::try_from(mac_iter).map_err(ErrorStack::internal_error)?;
        Ok(self)
    }

    /// An additional set of certificates to include in the archive beyond the one provided to
    /// `build`.
    pub fn ca(&mut self, ca: Stack<X509>) -> &mut Self {
        self.ca = Some(ca);
        self
    }

    /// Builds the PKCS #12 object
    ///
    /// # Arguments
    ///
    /// * `password` - the password used to encrypt the key and certificate
    /// * `friendly_name` - user defined name for the certificate
    /// * `pkey` - key to store
    /// * `cert` - certificate to store
    ///
    /// # Errors
    ///
    /// The password or name contains a NUL byte, or native archive creation fails.
    pub fn build<T>(
        self,
        password: &str,
        friendly_name: &str,
        pkey: &PKeyRef<T>,
        cert: &X509Ref,
    ) -> Result<Pkcs12, ErrorStack>
    where
        T: HasPrivate,
    {
        // SAFETY: all borrowed strings, native key and certificate references,
        // and optional CA stack remain live through the synchronous creation.
        // A non-null result transfers ownership to the new `Pkcs12`.
        unsafe {
            let pass = SecretCString::new(password.as_bytes())?;
            let friendly_name = CString::new(friendly_name).map_err(ErrorStack::internal_error)?;
            let pkey = pkey.as_ptr();
            let cert = cert.as_ptr();
            let ca = self.ca.as_ref().map_or(ptr::null_mut(), Stack::as_ptr);
            let nid_key = self.nid_key.as_raw();
            let nid_cert = self.nid_cert.as_raw();

            // According to the OpenSSL docs, keytype is a non-standard extension for MSIE,
            // It's values are KEY_SIG or KEY_EX, see the OpenSSL docs for more information:
            // https://www.openssl.org/docs/man1.0.2/crypto/PKCS12_create.html
            let keytype = 0;

            let archive = cvt_p(ffi::PKCS12_create(
                pass.as_ptr(),
                friendly_name.as_ptr(),
                pkey,
                cert,
                ca,
                nid_key,
                nid_cert,
                self.iter,
                self.mac_iter,
                keytype,
            ))?;
            // The non-null result transfers ownership to the Rust wrapper.
            Ok(Pkcs12::from_ptr(archive))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::hash::MessageDigest;
    use crate::sign::Signer;
    use hex;

    use crate::asn1::Asn1Time;
    use crate::nid::Nid;
    use crate::pkey::PKey;
    use crate::rsa::Rsa;
    use crate::x509::extension::KeyUsage;
    use crate::x509::{X509, X509Name};

    use super::*;

    #[test]
    fn iteration_counts_are_checked_before_assignment() {
        let mut builder = Pkcs12::builder();
        let max_native = c_int::MAX.unsigned_abs();
        assert!(builder.key_iter(max_native).is_ok());
        assert_eq!(builder.iter, c_int::MAX);
        assert!(builder.key_iter(max_native + 1).is_err());
        assert_eq!(builder.iter, c_int::MAX);

        assert!(builder.mac_iter(u32::MAX).is_err());
        assert_eq!(builder.mac_iter, PKCS12_DEFAULT_ITER);
        assert!(builder.mac_iter(1).is_ok());
        assert_eq!(builder.mac_iter, 1);
    }

    #[test]
    fn parse() {
        let der = include_bytes!("../test/identity.p12");
        let pkcs12 = Pkcs12::from_der(der).unwrap();
        let parsed = pkcs12.parse("mypass").unwrap();

        assert_eq!(
            hex::encode(parsed.cert.digest(MessageDigest::sha1()).unwrap()),
            "59172d9313e84459bcff27f967e79e6e9217e584"
        );

        let chain = parsed.chain.unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(
            hex::encode(chain[0].digest(MessageDigest::sha1()).unwrap()),
            "c0cbdf7cdd03c9773e5468e1f6d2da7d5cbb1875"
        );
    }

    #[test]
    fn parse_empty_chain() {
        let der = include_bytes!("../test/keystore-empty-chain.p12");
        let pkcs12 = Pkcs12::from_der(der).unwrap();
        let parsed = pkcs12.parse("cassandra").unwrap();
        assert_eq!(parsed.chain.unwrap().len(), 0);
    }

    #[test]
    fn create() {
        let subject_name = "ns.example.com";
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, subject_name)
            .unwrap();
        let name = name.build().unwrap();

        let key_usage = KeyUsage::new().digital_signature().build().unwrap();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.append_extension(&key_usage).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        let cert = builder
            .sign(Signer::new_oneshot(MessageDigest::sha256(), &pkey).unwrap())
            .unwrap();

        let pkcs12_builder = Pkcs12::builder();
        let pkcs12 = pkcs12_builder
            .build("mypass", subject_name, &pkey, &cert)
            .unwrap();
        let der = pkcs12.to_der().unwrap();

        let pkcs12 = Pkcs12::from_der(&der).unwrap();
        let parsed = pkcs12.parse("mypass").unwrap();

        assert_eq!(
            &*parsed.cert.digest(MessageDigest::sha1()).unwrap(),
            &*cert.digest(MessageDigest::sha1()).unwrap()
        );
        assert!(parsed.pkey.public_eq(&pkey));
    }
}
