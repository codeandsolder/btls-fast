//! Authenticated PKCS #12 archives.
//!
//! Parsing authenticates the complete archive and preserves all supported X.509
//! certificate bags. It does not choose an identity or establish a trust chain.

use crate::error::ErrorStack;
use crate::ffi;
use crate::nid::Nid;
use crate::pkey::{PKey, PKeyRef, Private};
use crate::stack::Stack;
use crate::util::{NativeBuffer, SecretCString};
use crate::x509::{X509, X509Ref};
use crate::{cvt, cvt_nz, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;
use openssl_macros::corresponds;
use std::{ffi::CString, ptr};

pub const PKCS12_DEFAULT_ITER: c_int = ffi::PKCS12_DEFAULT_ITER;
pub const PKCS12_MAX_ITER: c_int = ffi::PKCS12_MAX_ITER;

/// The authenticated contents of one PKCS #12 archive.
///
/// BoringSSL supports at most one private key and preserves certificate order.
/// The certificates are not necessarily CAs, trusted, or an ordered chain.
pub struct ParsedPkcs12 {
    pub private_key: Option<PKey<Private>>,
    pub certificates: Stack<X509>,
}

impl ParsedPkcs12 {
    /// Returns every certificate matching the archive's private key.
    ///
    /// Multiple matches are possible, for example after certificate renewal.
    /// No match is returned when the archive has no private key. This checks
    /// key correspondence, not certificate validity or trust.
    ///
    /// # Errors
    /// A certificate's public key cannot be decoded.
    pub fn matching_certificates(&self) -> Result<Vec<&X509Ref>, ErrorStack> {
        let Some(key) = &self.private_key else {
            return Ok(Vec::new());
        };
        let mut matches = Vec::new();
        for cert in &self.certificates {
            if key.public_eq(&cert.public_key()?) {
                matches.push(cert);
            }
        }
        Ok(matches)
    }
}

/// Authenticates and decrypts one complete BER- or DER-encoded PKCS #12 archive.
///
/// The native parser supports one private key and X.509 certificate bags.
/// Unsupported bag types are not returned. Empty passwords use the native
/// parser's handling of both standard empty-password encodings.
///
/// # Errors
/// The password contains a NUL byte, authentication or decoding fails, or
/// bytes remain after the archive.
#[corresponds(PKCS12_get_key_and_certs)]
pub fn parse(encoded: &[u8], password: &str) -> Result<ParsedPkcs12, ErrorStack> {
    ffi::init();
    let pass = SecretCString::new(password.as_bytes())?;
    let certificates = Stack::new()?;
    let mut key = ptr::null_mut();
    let mut input = ffi::CBS {
        data: encoded.as_ptr(),
        len: encoded.len(),
    };
    // SAFETY: input and password remain live; the stack is privately owned,
    // and key is a writable output slot. Native rolls back both outputs on
    // failure and transfers ownership of a non-null key on success.
    let private_key = unsafe {
        cvt(ffi::PKCS12_get_key_and_certs(
            &raw mut key,
            certificates.as_ptr(),
            &raw mut input,
            pass.as_ptr(),
        ))?;
        (!key.is_null()).then(|| PKey::from_ptr(key))
    };
    if input.len != 0 {
        return Err(ErrorStack::internal_error_str(
            "trailing bytes after PKCS12 archive",
        ));
    }
    Ok(ParsedPkcs12 {
        private_key,
        certificates,
    })
}

/// Encryption policy for key or certificate bags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encryption {
    /// A native-supported PBES1 suite or PBES2 cipher, selected by NID.
    Encrypted(Nid),
    /// Deliberately store the bag without encryption; the archive retains its MAC.
    Unencrypted,
}

impl Encryption {
    fn native_nid(self) -> Result<Nid, ErrorStack> {
        match self {
            Self::Encrypted(nid) if nid.as_raw() > 0 => Ok(nid),
            Self::Encrypted(_) => Err(ErrorStack::internal_error_str(
                "invalid PKCS12 encryption algorithm",
            )),
            Self::Unencrypted => Ok(Nid::from_raw(-1)),
        }
    }
}

/// Options for encoding a password-protected PKCS #12 archive.
pub struct Pkcs12Builder {
    nid_key: Nid,
    nid_cert: Nid,
    iter: c_int,
    mac_iter: c_int,
    additional_certificates: Option<Stack<X509>>,
}

impl Default for Pkcs12Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Pkcs12Builder {
    /// Creates a builder using AES-256-CBC with PBES2/PBKDF2-HMAC-SHA256.
    ///
    /// The native default is 2048 iterations for both encryption and MAC
    /// derivation. Choose iteration counts suitable for the deployment.
    #[must_use = "Configure or consume the returned archive builder."]
    pub const fn new() -> Self {
        Self {
            nid_key: Nid::AES_256_CBC,
            nid_cert: Nid::AES_256_CBC,
            iter: PKCS12_DEFAULT_ITER,
            mac_iter: PKCS12_DEFAULT_ITER,
            additional_certificates: None,
        }
    }

    /// Sets the private key encryption policy.
    ///
    /// # Errors
    /// An encrypted policy requires a positive algorithm identifier.
    pub fn key_encryption(&mut self, policy: Encryption) -> Result<&mut Self, ErrorStack> {
        self.nid_key = policy.native_nid()?;
        Ok(self)
    }

    /// Sets the certificate encryption policy.
    ///
    /// # Errors
    /// An encrypted policy requires a positive algorithm identifier.
    pub fn certificate_encryption(&mut self, policy: Encryption) -> Result<&mut Self, ErrorStack> {
        self.nid_cert = policy.native_nid()?;
        Ok(self)
    }

    /// Sets the encryption key-derivation iteration count.
    ///
    /// # Errors
    /// The count is outside the supported positive iteration range.
    pub fn key_iter(&mut self, iter: u32) -> Result<&mut Self, ErrorStack> {
        self.iter = checked_iterations(iter)?;
        Ok(self)
    }

    /// Sets the independent MAC key-derivation iteration count.
    ///
    /// # Errors
    /// The count is outside the supported positive iteration range.
    pub fn mac_iter(&mut self, iter: u32) -> Result<&mut Self, ErrorStack> {
        self.mac_iter = checked_iterations(iter)?;
        Ok(self)
    }

    /// Includes additional certificates in archive order, without asserting trust.
    pub fn additional_certificates(&mut self, certificates: Stack<X509>) -> &mut Self {
        self.additional_certificates = Some(certificates);
        self
    }

    /// Encodes an authenticated PKCS #12 archive containing a key, certificates, or both.
    ///
    /// When both a private key and primary certificate are provided, they must
    /// match. A friendly name is optional; when omitted, native certificate
    /// aliases may be used. The result is the encoded archive, not an unparsed
    /// native placeholder object.
    ///
    /// # Errors
    /// The archive is empty, the key and primary certificate do not match,
    /// the password or name contains a NUL byte, or native encoding fails.
    #[corresponds(PKCS12_create)]
    pub fn build(
        self,
        password: &str,
        friendly_name: Option<&str>,
        private_key: Option<&PKeyRef<Private>>,
        certificate: Option<&X509Ref>,
    ) -> Result<Vec<u8>, ErrorStack> {
        ffi::init();
        let pass = SecretCString::new(password.as_bytes())?;
        let name = friendly_name
            .map(CString::new)
            .transpose()
            .map_err(ErrorStack::internal_error)?;
        let key = private_key.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr);
        let cert = certificate.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr);
        let additional = self
            .additional_certificates
            .as_ref()
            .map_or(ptr::null_mut(), Stack::as_ptr);
        // SAFETY: all borrowed native objects, password and name remain live.
        // The successful native call returns an owned archive, immediately
        // wrapped to guarantee release even if encoding fails.
        let archive = unsafe {
            NativeArchive(cvt_p(ffi::PKCS12_create(
                pass.as_ptr(),
                name.as_ref().map_or(ptr::null(), |name| name.as_ptr()),
                key,
                cert,
                additional,
                self.nid_key.as_raw(),
                self.nid_cert.as_raw(),
                self.iter,
                self.mac_iter,
                0,
            ))?)
        };
        let mut output = NativeBuffer::new();
        // SAFETY: the owned archive is live. A null output slot requests an
        // allocated encoded buffer, which is copied before both owners drop.
        unsafe {
            let len = cvt_nz(ffi::i2d_PKCS12(archive.0, output.output()))?;
            output.copy(len.get())
        }
    }
}

fn checked_iterations(iterations: u32) -> Result<c_int, ErrorStack> {
    // Match BoringSSL's production PKCS12 parser limit. Never create an archive
    // that the same library refuses to decode because of its iteration count.
    if !(1..=PKCS12_MAX_ITER.cast_unsigned()).contains(&iterations) {
        return Err(ErrorStack::internal_error_str(
            "invalid PKCS12 iteration count",
        ));
    }
    c_int::try_from(iterations).map_err(ErrorStack::internal_error)
}

struct NativeArchive(*mut ffi::PKCS12);

impl Drop for NativeArchive {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the non-null native archive exactly once.
        unsafe { ffi::PKCS12_free(self.0) };
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
        let mut builder = Pkcs12Builder::new();
        let max_native = PKCS12_MAX_ITER.cast_unsigned();
        assert!(builder.key_iter(max_native).is_ok());
        assert_eq!(builder.iter, PKCS12_MAX_ITER);
        assert!(builder.key_iter(max_native + 1).is_err());
        assert_eq!(builder.iter, PKCS12_MAX_ITER);

        assert!(builder.key_iter(0).is_err());
        assert!(builder.mac_iter(0).is_err());
        assert!(builder.mac_iter(u32::MAX).is_err());
        assert_eq!(builder.mac_iter, PKCS12_DEFAULT_ITER);
        assert!(builder.mac_iter(1).is_ok());
        assert_eq!(builder.mac_iter, 1);
    }

    #[test]
    fn encryption_policy_does_not_accept_implicit_native_sentinels() {
        let mut builder = Pkcs12Builder::new();
        for nid in [Nid::UNDEF, Nid::from_raw(-1), Nid::from_raw(-2)] {
            assert!(builder.key_encryption(Encryption::Encrypted(nid)).is_err());
            assert!(
                builder
                    .certificate_encryption(Encryption::Encrypted(nid))
                    .is_err()
            );
        }
        assert_eq!(builder.nid_key, Nid::AES_256_CBC);
        assert_eq!(builder.nid_cert, Nid::AES_256_CBC);
        builder.key_encryption(Encryption::Unencrypted).unwrap();
        assert_eq!(builder.nid_key, Nid::from_raw(-1));
    }

    #[test]
    fn parse_identity_preserves_all_certificates() {
        let der = include_bytes!("../test/identity.p12");
        let parsed = super::parse(der, "mypass").unwrap();
        let matches = parsed.matching_certificates().unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(
            hex::encode(matches[0].digest(MessageDigest::sha1()).unwrap()),
            "59172d9313e84459bcff27f967e79e6e9217e584"
        );
        assert_eq!(parsed.certificates.len(), 2);
        assert!(parsed.certificates.iter().any(|cert| hex::encode(
            cert.digest(MessageDigest::sha1()).unwrap()
        ) == "c0cbdf7cdd03c9773e5468e1f6d2da7d5cbb1875"));
        assert!(super::parse(der, "wrong").is_err());
        let mut trailing = der.to_vec();
        trailing.extend_from_slice(&[0x30, 0]);
        assert!(super::parse(&trailing, "mypass").is_err());
        // Put the same extra element inside the outer PFX length, leaving the
        // authenticated payload and MAC intact. Native framing must reject it.
        assert_eq!(&trailing[..2], &[0x30, 0x82]);
        let len = u16::from_be_bytes([trailing[2], trailing[3]]) + 2;
        trailing[2..4].copy_from_slice(&len.to_be_bytes());
        assert!(super::parse(&trailing, "mypass").is_err());
        assert!(super::parse(&der[..der.len() - 1], "mypass").is_err());
    }

    #[test]
    fn parse_single_certificate() {
        let der = include_bytes!("../test/keystore-empty-chain.p12");
        let parsed = super::parse(der, "cassandra").unwrap();
        assert_eq!(parsed.certificates.len(), 1);
        assert_eq!(parsed.matching_certificates().unwrap().len(), 1);
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

        let encoded = Pkcs12Builder::new()
            .build("mypass", Some(subject_name), Some(&pkey), Some(&cert))
            .unwrap();
        let parsed = super::parse(&encoded, "mypass").unwrap();
        let matches = parsed.matching_certificates().unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].digest(MessageDigest::sha1()).unwrap().as_ref(),
            cert.digest(MessageDigest::sha1()).unwrap().as_ref()
        );
        assert!(parsed.private_key.unwrap().public_eq(&pkey));

        let mut builder = Pkcs12Builder::new();
        let mut additional = Stack::new().unwrap();
        additional.push(cert.clone()).unwrap();
        builder.additional_certificates(additional);
        let encoded = builder
            .build("mypass", None, Some(&pkey), Some(&cert))
            .unwrap();
        let parsed = super::parse(&encoded, "mypass").unwrap();
        assert_eq!(parsed.matching_certificates().unwrap().len(), 2);
        assert_eq!(parsed.certificates.len(), 2);

        let encoded = Pkcs12Builder::new()
            .build("mypass", None, None, Some(&cert))
            .unwrap();
        let parsed = super::parse(&encoded, "mypass").unwrap();
        assert!(parsed.private_key.is_none());
        assert_eq!(parsed.certificates.len(), 1);
        assert!(parsed.matching_certificates().unwrap().is_empty());

        let encoded = Pkcs12Builder::new()
            .build("mypass", None, Some(&pkey), None)
            .unwrap();
        let parsed = super::parse(&encoded, "mypass").unwrap();
        assert!(parsed.private_key.unwrap().public_eq(&pkey));
        assert!(parsed.certificates.is_empty());
        assert!(
            Pkcs12Builder::new()
                .build("mypass", None, None, None)
                .is_err()
        );
    }
}
