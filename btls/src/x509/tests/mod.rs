use hex::{self, FromHex};

use crate::asn1::Asn1Time;
use crate::bn::{BigNum, MsbOption};
use crate::hash::MessageDigest;
use crate::nid::Nid;
use crate::pkey::{PKey, Private};
use crate::rsa::Rsa;
use crate::sign::Signer;
use crate::stack::Stack;
use crate::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use crate::x509::store::X509StoreBuilder;
use crate::x509::verify::X509CheckFlags;
use crate::x509::{X509, X509Extension, X509Name, X509Req, X509StoreContext};
const TEST_CERT_DIGEST: &str = "585e3a58acfd3b4e5e2825659407244ddd93539c";

mod trusted_first;

fn pkey() -> PKey<Private> {
    let rsa = Rsa::generate(2048).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

fn cert_with_dns_name(dns_name: &str) -> X509 {
    let key = PKey::from_ec_key(
        crate::ec::EcKey::generate(
            &crate::ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "test.example.com")
        .unwrap();
    let name = name.build().unwrap();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let subject_alternative_name = SubjectAlternativeName::new()
        .dns(dns_name)
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(&subject_alternative_name).unwrap();
    builder
        .sign(Signer::new_oneshot(MessageDigest::sha256(), &key).unwrap())
        .unwrap()
}

#[test]
fn test_cert_loading() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let fingerprint = cert.digest(MessageDigest::sha1()).unwrap();

    let hash_vec = Vec::from_hex(TEST_CERT_DIGEST).unwrap();

    assert_eq!(hash_vec, &*fingerprint);
}

#[test]
fn test_debug() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let debugged = format!("{cert:#?}");

    assert!(debugged.contains(r#"serial_number: "8771f7bdee982fa5""#));
    assert!(debugged.contains(r#"signature_algorithm: sha256WithRSAEncryption"#));
    assert!(debugged.contains(r#"countryName = "AU""#));
    assert!(debugged.contains(r#"stateOrProvinceName = "Some-State""#));
    assert!(debugged.contains(r#"not_before: Aug 12 21:37:58 2026 GMT"#));
    assert!(debugged.contains(r#"not_after: Aug  9 21:37:58 2036 GMT"#));
}

#[test]
fn test_cert_issue_validity() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    assert_eq!(not_before, "Aug 12 21:37:58 2026 GMT");
    assert_eq!(not_after, "Aug  9 21:37:58 2036 GMT");
}

#[test]
fn test_save_der() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let der = cert.to_der().unwrap();
    assert!(!der.is_empty());
}

#[test]
fn test_subject_read_cn() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name().unwrap();
    let cn = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"foobar.com");
}

#[test]
fn test_nid_values() {
    let cert = include_bytes!("../../../test/nid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name().unwrap();

    let cn = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"example.com");

    let email = subject
        .entries_by_nid(Nid::PKCS9_EMAILADDRESS)
        .next()
        .unwrap();
    assert_eq!(email.data().as_slice(), b"test@example.com");

    let friendly = subject.entries_by_nid(Nid::FRIENDLYNAME).next().unwrap();
    assert_eq!(friendly.data().as_utf8().unwrap(), "Example");
}

#[test]
fn test_nameref_iterator() {
    let cert = include_bytes!("../../../test/nid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name().unwrap();
    let mut all_entries = subject.entries();

    let email = all_entries.next().unwrap();
    assert_eq!(
        email.object().nid().as_raw(),
        Nid::PKCS9_EMAILADDRESS.as_raw()
    );
    assert_eq!(email.data().as_slice(), b"test@example.com");

    let cn = all_entries.next().unwrap();
    assert_eq!(cn.object().nid().as_raw(), Nid::COMMONNAME.as_raw());
    assert_eq!(cn.data().as_slice(), b"example.com");

    let friendly = all_entries.next().unwrap();
    assert_eq!(friendly.object().nid().as_raw(), Nid::FRIENDLYNAME.as_raw());
    assert_eq!(friendly.data().as_utf8().unwrap(), "Example");

    if all_entries.next().is_some() {
        panic!();
    }
}

#[test]
fn test_nid_uid_value() {
    let cert = include_bytes!("../../../test/nid_uid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name().unwrap();

    let cn = subject.entries_by_nid(Nid::USERID).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"this is the userId");
}

#[test]
fn test_subject_alt_name() {
    let cert = include_bytes!("../../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let subject_alt_names = cert.subject_alt_names().unwrap();
    assert_eq!(5, subject_alt_names.len());
    assert_eq!(Some("example.com"), subject_alt_names[0].dnsname());
    assert_eq!(subject_alt_names[1].ipaddress(), Some(&[127, 0, 0, 1][..]));
    assert_eq!(
        subject_alt_names[2].ipaddress(),
        Some(&b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..])
    );
    assert_eq!(Some("test@example.com"), subject_alt_names[3].email());
    assert_eq!(Some("http://www.example.com"), subject_alt_names[4].uri());
}

#[test]
fn test_subject_alt_name_iter() {
    let cert = include_bytes!("../../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let subject_alt_names = cert.subject_alt_names().unwrap();
    let mut subject_alt_names_iter = subject_alt_names.iter();
    assert_eq!(
        subject_alt_names_iter.next().unwrap().dnsname(),
        Some("example.com")
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().ipaddress(),
        Some(&[127, 0, 0, 1][..])
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().ipaddress(),
        Some(&b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..])
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().email(),
        Some("test@example.com")
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().uri(),
        Some("http://www.example.com")
    );
    assert!(subject_alt_names_iter.next().is_none());
}

#[test]
fn check_host_uses_default_flags() {
    let cert = cert_with_dns_name("*.example.com");

    assert!(cert.check_host("www.example.com").unwrap());
    assert_eq!(
        cert.check_host("www.example.com").unwrap(),
        cert.check_host_with_flags("www.example.com", X509CheckFlags::empty())
            .unwrap()
    );
}

#[test]
fn check_host_with_standard_flags() {
    let cert = cert_with_dns_name("*.example.com");

    assert!(
        cert.check_host_with_flags("www.example.com", X509CheckFlags::empty())
            .unwrap()
    );
    assert!(
        !cert
            .check_host_with_flags("www.example.com", X509CheckFlags::NO_WILDCARDS)
            .unwrap()
    );
}

#[cfg(feature = "underscore-wildcards")]
#[test]
fn check_host_with_underscore_wildcards() {
    let cert = cert_with_dns_name("*.example.com");

    assert!(!cert.check_host("_service.example.com").unwrap());
    assert!(
        cert.check_host_with_flags("_service.example.com", X509CheckFlags::UNDERSCORE_WILDCARDS)
            .unwrap()
    );
}

#[test]
fn test_subject_key_id() {
    // nid_test_cert_pem has SKI, but no AKI
    let cert = include_bytes!("../../../test/nid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let ski = cert.subject_key_id().expect("unable to extract SKI");
    assert_eq!(
        ski.as_slice(),
        [
            80, 107, 158, 237, 95, 61, 235, 100, 212, 115, 249, 244, 219, 163, 124, 55, 141, 2, 76,
            5
        ]
    );

    let aki = cert.authority_key_id();
    assert!(aki.is_none());
}

#[test]
fn test_x509_name_print_ex() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let name_no_flags = cert
        .subject_name()
        .unwrap()
        .print_ex(0)
        .expect("failed to print cert subject name");
    assert_eq!(
        name_no_flags,
        "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=foobar.com"
    );

    let name_rfc2253 = cert
        .subject_name()
        .unwrap()
        .print_ex(ffi::XN_FLAG_RFC2253)
        .expect("failed to print cert subject name");
    assert_eq!(
        name_rfc2253,
        "CN=foobar.com,O=Internet Widgits Pty Ltd,ST=Some-State,C=AU"
    );
}

#[test]
fn x509_builder() {
    let pkey = pkey();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "foobar.com")
        .unwrap();
    let name = name.build().unwrap();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    builder
        .append_extension(basic_constraints.as_ref())
        .unwrap();
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    builder.append_extension(&key_usage).unwrap();
    let ext_key_usage = ExtendedKeyUsage::new()
        .client_auth()
        .server_auth()
        .other("2.999.1")
        .build()
        .unwrap();
    builder.append_extension(&ext_key_usage).unwrap();
    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(&subject_key_identifier).unwrap();
    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(&authority_key_identifier).unwrap();
    let subject_alternative_name = SubjectAlternativeName::new()
        .dns("example.com")
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(&subject_alternative_name).unwrap();

    let x509 = builder
        .sign(Signer::new_oneshot(MessageDigest::sha256(), &pkey).unwrap())
        .unwrap();

    assert!(pkey.public_eq(&x509.public_key().unwrap()));
    assert!(x509.verify(&pkey).unwrap());

    let cn = x509
        .subject_name()
        .unwrap()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .unwrap();
    assert_eq!(cn.data().as_slice(), b"foobar.com");
    assert_eq!(serial, x509.serial_number().to_bn().unwrap());
}

#[test]
fn x509_extension_new() {
    assert!(X509Extension::new(None, None, "crlDistributionPoints", "section").is_err());
    assert!(X509Extension::new(None, None, "proxyCertInfo", "").is_err());
    assert!(X509Extension::new(None, None, "certificatePolicies", "").is_err());
    assert!(X509Extension::new(None, None, "subjectAltName", "dirName:section").is_err());
}

#[test]
fn extension_by_name_and_nid_use_the_same_scoped_context() {
    let by_name = X509Extension::new(None, None, "basicConstraints", "CA:TRUE").unwrap();
    let by_nid = X509Extension::new_nid(None, None, Nid::BASIC_CONSTRAINTS, "CA:TRUE").unwrap();
    assert_eq!(by_name.to_der().unwrap(), by_nid.to_der().unwrap());

    let builder = X509::builder().unwrap();
    let context = builder.x509v3_context(None, None);
    let by_name = X509Extension::new(None, Some(&context), "basicConstraints", "CA:FALSE").unwrap();
    let by_nid =
        X509Extension::new_nid(None, Some(&context), Nid::BASIC_CONSTRAINTS, "CA:FALSE").unwrap();
    assert_eq!(by_name.to_der().unwrap(), by_nid.to_der().unwrap());
}

#[test]
fn x509_extension_to_der() {
    let builder = X509::builder().unwrap();

    for (ext, expected) in [
        (
            BasicConstraints::new().critical().ca().build().unwrap(),
            b"0\x0f\x06\x03U\x1d\x13\x01\x01\xff\x04\x050\x03\x01\x01\xff" as &[u8],
        ),
        (
            SubjectAlternativeName::new()
                .dns("example.com,DNS:example2.com")
                .build(&builder.x509v3_context(None, None))
                .unwrap(),
            b"0'\x06\x03U\x1d\x11\x04 0\x1e\x82\x1cexample.com,DNS:example2.com",
        ),
        (
            SubjectAlternativeName::new()
                .rid("1.2.3.4")
                .uri("https://example.com")
                .build(&builder.x509v3_context(None, None))
                .unwrap(),
            b"0#\x06\x03U\x1d\x11\x04\x1c0\x1a\x88\x03*\x03\x04\x86\x13https://example.com",
        ),
        (
            ExtendedKeyUsage::new()
                .server_auth()
                .other("2.999.1")
                .other("clientAuth")
                .build()
                .unwrap(),
            b"0\x22\x06\x03U\x1d%\x04\x1b0\x19\x06\x08+\x06\x01\x05\x05\x07\x03\x01\x06\x03\x887\x01\x06\x08+\x06\x01\x05\x05\x07\x03\x02",
        ),
    ] {
        assert_eq!(&ext.to_der().unwrap(), expected);
    }
}

#[test]
fn eku_invalid_other() {
    assert!(
        ExtendedKeyUsage::new()
            .other("1.1.1.1.1,2.2.2.2.2")
            .build()
            .is_err()
    );
}

#[test]
fn x509_req_builder() {
    let pkey = pkey();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "foobar.com")
        .unwrap();
    let name = name.build().unwrap();

    let mut builder = X509Req::builder().unwrap();
    builder.set_version(0).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let mut extensions = Stack::new().unwrap();
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    extensions.push(key_usage).unwrap();
    let subject_alternative_name = SubjectAlternativeName::new()
        .dns("example.com")
        .build(&builder.x509v3_context(None))
        .unwrap();
    extensions.push(subject_alternative_name).unwrap();
    builder.add_extensions(&extensions).unwrap();

    let req = builder
        .sign(Signer::new_oneshot(MessageDigest::sha256(), &pkey).unwrap())
        .unwrap();
    assert!(req.public_key().unwrap().public_eq(&pkey));
    assert_eq!(req.extensions().unwrap().len(), extensions.len());
    assert!(req.verify(&pkey).unwrap());
}

#[test]
fn certificate_and_request_support_configured_signers() {
    use crate::pkey::Id;
    use crate::rsa::Padding;
    use crate::sign::RsaPssSaltlen;

    let rsa = pkey();
    let ed25519 = PKey::generate(Id::ED25519).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "signing test")
        .unwrap();
    let name = name.build().unwrap();
    fn configure(key: &PKey<Private>, algorithm: Nid) -> Signer<'_, crate::sign::OneShot> {
        if algorithm == Nid::RSASSAPSS {
            let mut signer = Signer::new_oneshot(MessageDigest::sha256(), key).unwrap();
            signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
            signer.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
            signer
                .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .unwrap();
            signer
        } else {
            Signer::new_without_digest(key).unwrap()
        }
    }
    for (key, algorithm) in [(&rsa, Nid::RSASSAPSS), (&ed25519, Nid::ED25519)] {
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(key).unwrap();
        builder
            .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        let certificate = builder.sign(configure(key, algorithm)).unwrap();
        let certificate = X509::from_der(&certificate.to_der().unwrap()).unwrap();
        assert_eq!(
            certificate.signature_algorithm().object().unwrap().nid(),
            algorithm
        );
        assert!(certificate.verify(key).unwrap());

        let mut request = X509Req::builder().unwrap();
        request.set_subject_name(&name).unwrap();
        request.set_pubkey(key).unwrap();
        let request = request.sign(configure(key, algorithm)).unwrap();
        let request = X509Req::from_der(&request.to_der().unwrap()).unwrap();
        assert!(request.verify(&request.public_key().unwrap()).unwrap());
    }
}

#[test]
fn request_rejects_missing_or_mismatched_subject_key() {
    let key = pkey();
    let other = pkey();
    let signer = Signer::new_oneshot(MessageDigest::sha256(), &key).unwrap();
    assert!(X509Req::builder().unwrap().sign(signer).is_err());
    let mut builder = X509Req::builder().unwrap();
    builder.set_pubkey(&other).unwrap();
    let signer = Signer::new_oneshot(MessageDigest::sha256(), &key).unwrap();
    assert!(builder.sign(signer).is_err());
}

#[test]
fn test_stack_from_pem() {
    let certs = include_bytes!("../../../test/certs.pem");
    let certs = X509::stack_from_pem(certs).unwrap();

    assert_eq!(certs.len(), 2);
    assert_eq!(
        hex::encode(certs[0].digest(MessageDigest::sha1()).unwrap()),
        "585e3a58acfd3b4e5e2825659407244ddd93539c"
    );
    assert_eq!(
        hex::encode(certs[1].digest(MessageDigest::sha1()).unwrap()),
        "1b1ad6250902865aea72bc1e843d45b769e6c553"
    );
}

#[test]
fn issued() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../../test/root-ca.pem");
    let ca = X509::from_pem(ca).unwrap();

    assert_eq!(ca.issued(&cert), Ok(()));
    assert!(cert.issued(&cert).is_err());
}

#[test]
fn signature() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let signature = cert.signature();
    assert_eq!(
        hex::encode(signature.as_slice()),
        "73a2bbd9e91b011f11d18a75e247b09b3288dcc837900ee38ce36f4b8fcef2dbc201db032f5d0206e990f64\
          e22a5445d559d91dc52797a6a9115cb2325eb79ca4a2c036ac8bb4aae54b2f0c285efc80d404b1c703e\
          bca56ce85e3a64173853b45d243cb023e8b4fe2ae02ebf59f415938295ce41970a583f147a2f83592cd\
          0ae639c2da9cd4f04a521b1eada862a2142774aedcc9bb7f4e5019443ba01b50174abc2373566a6e91aa\
          8ba1e4ddffbec5d308575fa9bd160555965a718dee775568dde57808f0b45794562ab9095fe6242af85f\
          4c2da698c8b219a3f2054b1c505a526f176ebcee4b16f0ad76b341ba0ddaad7bea1ac97076ed37041fa\
          45d58b0c"
    );
    let algorithm = cert.signature_algorithm();
    assert_eq!(
        algorithm.object().unwrap().nid(),
        Nid::SHA256WITHRSAENCRYPTION
    );
    assert_eq!(
        algorithm.object().unwrap().to_string(),
        "sha256WithRSAEncryption"
    );
}

#[test]
fn clone_x509() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let shared = cert.clone();
    let original = cert.to_der().unwrap();
    drop(cert);
    assert_eq!(shared.to_der().unwrap(), original);
}

#[test]
fn test_verify_cert() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../../test/root-ca.pem");
    let ca = X509::from_pem(ca).unwrap();
    let chain = Stack::new().unwrap();

    let mut store_bldr = X509StoreBuilder::new().unwrap();
    store_bldr.add_cert(&ca).unwrap();
    let store = store_bldr.build();
    let empty_store = X509StoreBuilder::new().unwrap().build();

    let mut context = X509StoreContext::new().unwrap();
    assert!(
        context
            .init(&store, &cert, &chain, |c| c.verify_cert())
            .unwrap()
    );
    assert!(
        !context
            .init(&empty_store, &cert, &chain, |c| c.verify_cert())
            .unwrap()
    );
    assert!(
        context
            .init(&store, &cert, &chain, |c| c.verify_cert())
            .unwrap()
    );

    context
        .reset_with_context_data(empty_store, cert.clone(), Stack::new().unwrap())
        .unwrap();
    assert!(!context.verify_cert().unwrap());

    context.reset_with_context_data(store, cert, chain).unwrap();
    assert!(context.verify_cert().unwrap());
}

#[test]
fn verification_purpose_enforces_extended_key_usage() {
    use crate::x509::verify::X509Purpose;

    let key = pkey();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "purpose test")
        .unwrap();
    let name = name.build().unwrap();
    let mut ca = X509::builder().unwrap();
    ca.set_version(2).unwrap();
    ca.set_subject_name(&name).unwrap();
    ca.set_issuer_name(&name).unwrap();
    ca.set_pubkey(&key).unwrap();
    ca.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    ca.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    ca.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    ca.append_extension(&BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    ca.append_extension(&KeyUsage::new().critical().key_cert_sign().build().unwrap())
        .unwrap();
    let ca = ca
        .sign(Signer::new_oneshot(MessageDigest::sha256(), &key).unwrap())
        .unwrap();

    let leaf_key = pkey();
    let mut leaf = X509::builder().unwrap();
    leaf.set_version(2).unwrap();
    leaf.set_subject_name(&name).unwrap();
    leaf.set_issuer_name(&name).unwrap();
    leaf.set_pubkey(&leaf_key).unwrap();
    leaf.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    leaf.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    leaf.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    leaf.append_extension(&BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    leaf.append_extension(
        &KeyUsage::new()
            .critical()
            .digital_signature()
            .build()
            .unwrap(),
    )
    .unwrap();
    leaf.append_extension(
        &ExtendedKeyUsage::new()
            .critical()
            .client_auth()
            .build()
            .unwrap(),
    )
    .unwrap();
    let leaf = leaf
        .sign(Signer::new_oneshot(MessageDigest::sha256(), &key).unwrap())
        .unwrap();
    let chain = Stack::new().unwrap();
    for (purpose, expected) in [
        (X509Purpose::TlsClient, true),
        (X509Purpose::TlsServer, false),
    ] {
        let mut store = X509StoreBuilder::new().unwrap();
        store.add_cert(&ca).unwrap();
        store.verify_param_mut().set_purpose(purpose).unwrap();
        let mut context = X509StoreContext::new().unwrap();
        let verified = context
            .init(&store.build(), &leaf, &chain, |ctx| ctx.verify_cert())
            .unwrap();
        assert_eq!(verified, expected);
    }
}

#[test]
fn uninitialized_context_and_panicking_ex_data_drop() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    struct PanicOnDrop(Arc<AtomicBool>);
    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
            panic!("application ex-data destructor");
        }
    }

    let mut context = X509StoreContext::new().unwrap();
    assert!(context.ssl().is_none());
    assert!(context.verify_param().is_none());
    assert!(context.verify_param_mut().is_none());
    assert!(context.verify_cert().is_err());
    let called = Arc::new(AtomicBool::new(false));
    let index = X509StoreContext::new_ex_index().unwrap();
    context
        .set_ex_data(index, PanicOnDrop(called.clone()))
        .unwrap();
    drop(context);
    assert!(called.load(Ordering::Relaxed));
}

#[test]
fn test_verify_fails() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../../test/alt_name_cert.pem");
    let ca = X509::from_pem(ca).unwrap();
    let chain = Stack::new().unwrap();

    let mut store_bldr = X509StoreBuilder::new().unwrap();
    store_bldr.add_cert(&ca).unwrap();
    let store = store_bldr.build();

    let mut context = X509StoreContext::new().unwrap();
    assert!(
        !context
            .init(&store, &cert, &chain, |c| c.verify_cert())
            .unwrap()
    );
}

#[test]
fn test_save_subject_der() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let der = cert.subject_name().unwrap().to_der().unwrap();
    println!("der: {der:?}");
    assert!(!der.is_empty());
}

#[test]
fn test_load_subject_der() {
    // The subject from ../../../test/cert.pem
    const SUBJECT_DER: &[u8] = &[
        48, 90, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 65, 85, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12,
        10, 83, 111, 109, 101, 45, 83, 116, 97, 116, 101, 49, 33, 48, 31, 6, 3, 85, 4, 10, 12, 24,
        73, 110, 116, 101, 114, 110, 101, 116, 32, 87, 105, 100, 103, 105, 116, 115, 32, 80, 116,
        121, 32, 76, 116, 100, 49, 19, 48, 17, 6, 3, 85, 4, 3, 12, 10, 102, 111, 111, 98, 97, 114,
        46, 99, 111, 109,
    ];
    X509Name::from_der(SUBJECT_DER).unwrap();
}

#[test]
fn test_check_ip_asc() {
    // Covers 127.0.0.1 and 0:0:0:0:0:0:0:1
    let cert = include_bytes!("../../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    assert!(cert.check_ip_asc("127.0.0.1").unwrap());
    assert!(!cert.check_ip_asc("127.0.0.2").unwrap());

    assert!(cert.check_ip_asc("0:0:0:0:0:0:0:1").unwrap());
    assert!(!cert.check_ip_asc("0:0:0:0:0:0:0:2").unwrap());
}
