//! Add extensions to an `X509` certificate or certificate request.
//!
//! The extensions defined for X.509 v3 certificates provide methods for
//! associating additional attributes with users or public keys and for
//! managing relationships between CAs. The extensions created using this
//! module can be used with `X509v3Context` objects.
//!
//! # Example
//!
//! ```rust
//! use btls::x509::extension::BasicConstraints;
//! use btls::x509::X509Extension;
//!
//! let mut bc = BasicConstraints::new();
//! let bc = bc.critical().ca().pathlen(1);
//! let extension: X509Extension = bc.build().unwrap();
//! ```
use std::fmt::Write;

use crate::asn1::Asn1Object;
use crate::error::ErrorStack;
use crate::nid::Nid;
use crate::x509::{GeneralName, Stack, X509Extension, X509v3Context};
use foreign_types::ForeignType;

/// An extension which indicates whether a certificate is a CA certificate.
pub struct BasicConstraints {
    critical: bool,
    ca: bool,
    pathlen: Option<u32>,
}

impl Default for BasicConstraints {
    fn default() -> Self {
        Self::new()
    }
}

impl BasicConstraints {
    /// Construct a new `BasicConstraints` extension.
    #[must_use = "Configure or consume the returned builder or cryptographic state."]
    pub const fn new() -> Self {
        Self {
            critical: false,
            ca: false,
            pathlen: None,
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub const fn critical(&mut self) -> &mut Self {
        self.critical = true;
        self
    }

    /// Sets the `ca` flag to `true`.
    pub const fn ca(&mut self) -> &mut Self {
        self.ca = true;
        self
    }

    /// Sets the pathlen to an optional non-negative value. The pathlen is the
    /// maximum number of CAs that can appear below this one in a chain.
    pub const fn pathlen(&mut self, pathlen: u32) -> &mut Self {
        self.pathlen = Some(pathlen);
        self
    }

    /// Return the `BasicConstraints` extension as an `X509Extension`.
    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        if self.critical {
            value.push_str("critical,");
        }
        value.push_str("CA:");
        if self.ca {
            value.push_str("TRUE");
        } else {
            value.push_str("FALSE");
        }
        if let Some(pathlen) = self.pathlen {
            write!(value, ",pathlen:{pathlen}").map_err(ErrorStack::internal_error)?;
        }
        X509Extension::new_nid(None, None, Nid::BASIC_CONSTRAINTS, &value)
    }
}

/// An extension consisting of a list of names of the permitted key usages.
pub struct KeyUsage {
    critical: bool,
    digital_signature: bool,
    non_repudiation: bool,
    key_encipherment: bool,
    data_encipherment: bool,
    key_agreement: bool,
    key_cert_sign: bool,
    crl_sign: bool,
    encipher_only: bool,
    decipher_only: bool,
}

impl Default for KeyUsage {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyUsage {
    /// Construct a new `KeyUsage` extension.
    #[must_use = "Configure or consume the returned builder or cryptographic state."]
    pub const fn new() -> Self {
        Self {
            critical: false,
            digital_signature: false,
            non_repudiation: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
            encipher_only: false,
            decipher_only: false,
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub const fn critical(&mut self) -> &mut Self {
        self.critical = true;
        self
    }

    /// Sets the `digitalSignature` flag to `true`.
    pub const fn digital_signature(&mut self) -> &mut Self {
        self.digital_signature = true;
        self
    }

    /// Sets the `nonRepudiation` flag to `true`.
    pub const fn non_repudiation(&mut self) -> &mut Self {
        self.non_repudiation = true;
        self
    }

    /// Sets the `keyEncipherment` flag to `true`.
    pub const fn key_encipherment(&mut self) -> &mut Self {
        self.key_encipherment = true;
        self
    }

    /// Sets the `dataEncipherment` flag to `true`.
    pub const fn data_encipherment(&mut self) -> &mut Self {
        self.data_encipherment = true;
        self
    }

    /// Sets the `keyAgreement` flag to `true`.
    pub const fn key_agreement(&mut self) -> &mut Self {
        self.key_agreement = true;
        self
    }

    /// Sets the `keyCertSign` flag to `true`.
    pub const fn key_cert_sign(&mut self) -> &mut Self {
        self.key_cert_sign = true;
        self
    }

    /// Sets the `cRLSign` flag to `true`.
    pub const fn crl_sign(&mut self) -> &mut Self {
        self.crl_sign = true;
        self
    }

    /// Sets the `encipherOnly` flag to `true`.
    pub const fn encipher_only(&mut self) -> &mut Self {
        self.encipher_only = true;
        self
    }

    /// Sets the `decipherOnly` flag to `true`.
    pub const fn decipher_only(&mut self) -> &mut Self {
        self.decipher_only = true;
        self
    }

    /// Return the `KeyUsage` extension as an `X509Extension`.
    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        append(
            &mut value,
            &mut first,
            self.digital_signature,
            "digitalSignature",
        );
        append(
            &mut value,
            &mut first,
            self.non_repudiation,
            "nonRepudiation",
        );
        append(
            &mut value,
            &mut first,
            self.key_encipherment,
            "keyEncipherment",
        );
        append(
            &mut value,
            &mut first,
            self.data_encipherment,
            "dataEncipherment",
        );
        append(&mut value, &mut first, self.key_agreement, "keyAgreement");
        append(&mut value, &mut first, self.key_cert_sign, "keyCertSign");
        append(&mut value, &mut first, self.crl_sign, "cRLSign");
        append(&mut value, &mut first, self.encipher_only, "encipherOnly");
        append(&mut value, &mut first, self.decipher_only, "decipherOnly");
        X509Extension::new_nid(None, None, Nid::KEY_USAGE, &value)
    }
}

/// An extension consisting of a list of usages indicating purposes
/// for which the certificate public key can be used for.
pub struct ExtendedKeyUsage {
    critical: bool,
    items: Vec<String>,
}

impl Default for ExtendedKeyUsage {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtendedKeyUsage {
    /// Construct a new `ExtendedKeyUsage` extension.
    #[must_use = "Configure or consume the returned builder or cryptographic state."]
    pub const fn new() -> Self {
        Self {
            critical: false,
            items: vec![],
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub const fn critical(&mut self) -> &mut Self {
        self.critical = true;
        self
    }

    /// Sets the `serverAuth` flag to `true`.
    pub fn server_auth(&mut self) -> &mut Self {
        self.other("serverAuth")
    }

    /// Sets the `clientAuth` flag to `true`.
    pub fn client_auth(&mut self) -> &mut Self {
        self.other("clientAuth")
    }

    /// Sets the `codeSigning` flag to `true`.
    pub fn code_signing(&mut self) -> &mut Self {
        self.other("codeSigning")
    }

    /// Sets the `timeStamping` flag to `true`.
    pub fn time_stamping(&mut self) -> &mut Self {
        self.other("timeStamping")
    }

    /// Sets the `msCodeInd` flag to `true`.
    pub fn ms_code_ind(&mut self) -> &mut Self {
        self.other("msCodeInd")
    }

    /// Sets the `msCodeCom` flag to `true`.
    pub fn ms_code_com(&mut self) -> &mut Self {
        self.other("msCodeCom")
    }

    /// Sets the `msCTLSign` flag to `true`.
    pub fn ms_ctl_sign(&mut self) -> &mut Self {
        self.other("msCTLSign")
    }

    /// Sets the `msSGC` flag to `true`.
    pub fn ms_sgc(&mut self) -> &mut Self {
        self.other("msSGC")
    }

    /// Sets the `msEFS` flag to `true`.
    pub fn ms_efs(&mut self) -> &mut Self {
        self.other("msEFS")
    }

    /// Sets the `nsSGC` flag to `true`.
    pub fn ns_sgc(&mut self) -> &mut Self {
        self.other("nsSGC")
    }

    /// Sets a flag not already defined.
    pub fn other(&mut self, other: &str) -> &mut Self {
        self.items.push(other.to_string());
        self
    }

    /// Return the `ExtendedKeyUsage` extension as an `X509Extension`.
    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        let mut stack = Stack::new()?;
        for item in &self.items {
            stack.push(item.parse::<Asn1Object>()?)?;
        }
        unsafe {
            X509Extension::new_internal(Nid::EXT_KEY_USAGE, self.critical, stack.as_ptr().cast())
        }
    }
}

/// An extension that provides a means of identifying certificates that contain a
/// particular public key.
pub struct SubjectKeyIdentifier {
    critical: bool,
}

impl Default for SubjectKeyIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

impl SubjectKeyIdentifier {
    /// Construct a new `SubjectKeyIdentifier` extension.
    #[must_use = "Configure or consume the returned builder or cryptographic state."]
    pub const fn new() -> Self {
        Self { critical: false }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub const fn critical(&mut self) -> &mut Self {
        self.critical = true;
        self
    }

    /// Return a `SubjectKeyIdentifier` extension as an `X509Extension`.
    pub fn build(&self, ctx: &X509v3Context) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        append(&mut value, &mut first, true, "hash");
        X509Extension::new_nid(None, Some(ctx), Nid::SUBJECT_KEY_IDENTIFIER, &value)
    }
}

/// An extension that provides a means of identifying the public key corresponding
/// to the private key used to sign a CRL.
pub struct AuthorityKeyIdentifier {
    critical: bool,
    keyid: Option<bool>,
    issuer: Option<bool>,
}

impl Default for AuthorityKeyIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthorityKeyIdentifier {
    /// Construct a new `AuthorityKeyIdentifier` extension.
    #[must_use = "Configure or consume the returned builder or cryptographic state."]
    pub const fn new() -> Self {
        Self {
            critical: false,
            keyid: None,
            issuer: None,
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub const fn critical(&mut self) -> &mut Self {
        self.critical = true;
        self
    }

    /// Sets the `keyid` flag.
    pub const fn keyid(&mut self, always: bool) -> &mut Self {
        self.keyid = Some(always);
        self
    }

    /// Sets the `issuer` flag.
    pub const fn issuer(&mut self, always: bool) -> &mut Self {
        self.issuer = Some(always);
        self
    }

    /// Return a `AuthorityKeyIdentifier` extension as an `X509Extension`.
    pub fn build(&self, ctx: &X509v3Context) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        match self.keyid {
            Some(true) => append(&mut value, &mut first, true, "keyid:always"),
            Some(false) => append(&mut value, &mut first, true, "keyid"),
            None => {}
        }
        match self.issuer {
            Some(true) => append(&mut value, &mut first, true, "issuer:always"),
            Some(false) => append(&mut value, &mut first, true, "issuer"),
            None => {}
        }
        X509Extension::new_nid(None, Some(ctx), Nid::AUTHORITY_KEY_IDENTIFIER, &value)
    }
}

enum RustGeneralName {
    Dns(String),
    Email(String),
    Uri(String),
    Ip(String),
    Rid(String),
}

/// An extension that allows additional identities to be bound to the subject
/// of the certificate.
pub struct SubjectAlternativeName {
    critical: bool,
    items: Vec<RustGeneralName>,
}

impl Default for SubjectAlternativeName {
    fn default() -> Self {
        Self::new()
    }
}

impl SubjectAlternativeName {
    /// Construct a new `SubjectAlternativeName` extension.
    #[must_use = "Configure or consume the returned builder or cryptographic state."]
    pub const fn new() -> Self {
        Self {
            critical: false,
            items: vec![],
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub const fn critical(&mut self) -> &mut Self {
        self.critical = true;
        self
    }

    /// Sets the `email` flag.
    pub fn email(&mut self, email: &str) -> &mut Self {
        self.items.push(RustGeneralName::Email(email.to_owned()));
        self
    }

    /// Sets the `uri` flag.
    pub fn uri(&mut self, uri: &str) -> &mut Self {
        self.items.push(RustGeneralName::Uri(uri.to_owned()));
        self
    }

    /// Sets the `dns` flag.
    pub fn dns(&mut self, dns: &str) -> &mut Self {
        self.items.push(RustGeneralName::Dns(dns.to_owned()));
        self
    }

    /// Sets the `rid` flag.
    pub fn rid(&mut self, rid: &str) -> &mut Self {
        self.items.push(RustGeneralName::Rid(rid.to_owned()));
        self
    }

    /// Sets the `ip` flag.
    pub fn ip(&mut self, ip: &str) -> &mut Self {
        self.items.push(RustGeneralName::Ip(ip.to_owned()));
        self
    }

    /// Return a `SubjectAlternativeName` extension as an `X509Extension`.
    pub fn build(&self, _ctx: &X509v3Context<'_>) -> Result<X509Extension, ErrorStack> {
        let mut stack = Stack::new()?;
        for item in &self.items {
            let gn = match item {
                RustGeneralName::Dns(s) => GeneralName::new_dns(s.as_bytes())?,
                RustGeneralName::Email(s) => GeneralName::new_email(s.as_bytes())?,
                RustGeneralName::Uri(s) => GeneralName::new_uri(s.as_bytes())?,
                RustGeneralName::Ip(s) => {
                    GeneralName::new_ip(s.parse().map_err(|_| ErrorStack::get())?)?
                }
                RustGeneralName::Rid(s) => GeneralName::new_rid(s.parse::<Asn1Object>()?)?,
            };
            stack.push(gn)?;
        }

        unsafe {
            X509Extension::new_internal(Nid::SUBJECT_ALT_NAME, self.critical, stack.as_ptr().cast())
        }
    }
}

fn append(value: &mut String, first: &mut bool, should: bool, element: &str) {
    if !should {
        return;
    }

    if !*first {
        value.push(',');
    }
    *first = false;
    value.push_str(element);
}
