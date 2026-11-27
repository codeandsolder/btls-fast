//! `BoringSSL` crypto provider for jsonwebtoken. Token parsing and validation
//! remain in jsonwebtoken; this crate implements its cryptographic primitives.
use btls::{
    bn::BigNum,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    error::ErrorStack,
    hash::{self, MessageDigest},
    memcmp,
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Signer, Verifier},
};
use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey, DecodingKeyKind, EncodingKey,
    crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils},
    errors::{ErrorKind, Result, new_error},
    jwk::{EllipticCurve, ThumbprintHash},
};

type SigResult<T> = std::result::Result<T, signature::Error>;

fn native_error(error: &ErrorStack) -> jsonwebtoken::errors::Error {
    new_error(ErrorKind::Provider(error.to_string()))
}

fn signature_error(_: ErrorStack) -> signature::Error {
    signature::Error::new()
}

fn digest(algorithm: Algorithm) -> Result<MessageDigest> {
    match algorithm {
        Algorithm::HS256 | Algorithm::RS256 | Algorithm::PS256 | Algorithm::ES256 => {
            Ok(MessageDigest::sha256())
        }
        Algorithm::HS384 | Algorithm::RS384 | Algorithm::PS384 | Algorithm::ES384 => {
            Ok(MessageDigest::sha384())
        }
        Algorithm::HS512 | Algorithm::RS512 | Algorithm::PS512 => Ok(MessageDigest::sha512()),
        _ => Err(new_error(ErrorKind::UnsupportedAlgorithm)),
    }
}

fn mac<T>(
    algorithm: Algorithm,
    key: &[u8],
    message: &[u8],
    consume: impl FnOnce(&[u8]) -> T,
) -> SigResult<T> {
    match algorithm {
        Algorithm::HS256 => hash::hmac_sha256(key, message).map(|v| consume(&v)),
        Algorithm::HS384 => hash::hmac_sha384(key, message).map(|v| consume(&v)),
        Algorithm::HS512 => hash::hmac_sha512(key, message).map(|v| consume(&v)),
        _ => return Err(signature::Error::new()),
    }
    .map_err(signature_error)
}

const fn rsa_pss(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512
    )
}

fn curve(algorithm: Algorithm) -> Result<(Nid, EllipticCurve, usize)> {
    match algorithm {
        Algorithm::ES256 => Ok((Nid::X9_62_PRIME256V1, EllipticCurve::P256, 32)),
        Algorithm::ES384 => Ok((Nid::SECP384R1, EllipticCurve::P384, 48)),
        _ => Err(new_error(ErrorKind::InvalidAlgorithm)),
    }
}

fn check_rsa<T: btls::pkey::HasPublic>(rsa: &Rsa<T>) -> Result<()> {
    if !(2048..=8192).contains(&rsa.n().num_bits()) {
        return Err(new_error(ErrorKind::InvalidRsaKey(
            "RSA modulus must be 2048–8192 bits".into(),
        )));
    }
    Ok(())
}

fn private_key(algorithm: Algorithm, bytes: &[u8]) -> Result<PKey<Private>> {
    let key = PKey::private_key_from_der(bytes).map_err(|error| native_error(&error))?;
    match algorithm.family() {
        AlgorithmFamily::Rsa if key.id() == Id::RSA => {
            check_rsa(&key.rsa().map_err(|error| native_error(&error))?)?;
        }
        AlgorithmFamily::Ec if key.id() == Id::EC => {
            let key = key.ec_key().map_err(|error| native_error(&error))?;
            if key.group().curve_name() != Some(curve(algorithm)?.0) {
                return Err(new_error(ErrorKind::InvalidEcdsaKey));
            }
            key.check_key().map_err(|error| native_error(&error))?;
        }
        AlgorithmFamily::Ed if key.id() == Id::ED25519 => {}
        _ => return Err(new_error(ErrorKind::InvalidKeyFormat)),
    }
    Ok(key)
}

fn rsa_public(bytes: &[u8]) -> Result<Rsa<Public>> {
    let rsa = Rsa::public_key_from_der_pkcs1(bytes)
        .or_else(|_| Rsa::public_key_from_der(bytes))
        .map_err(|error| native_error(&error))?;
    check_rsa(&rsa)?;
    Ok(rsa)
}

fn public_key(algorithm: Algorithm, key: &DecodingKey) -> Result<PKey<Public>> {
    match algorithm.family() {
        AlgorithmFamily::Rsa => {
            let rsa = match key.kind() {
                DecodingKeyKind::RsaModulusExponent { n, e } => {
                    let rsa = Rsa::from_public_components(
                        BigNum::from_slice(n).map_err(|error| native_error(&error))?,
                        BigNum::from_slice(e).map_err(|error| native_error(&error))?,
                    )
                    .map_err(|error| native_error(&error))?;
                    check_rsa(&rsa)?;
                    rsa
                }
                DecodingKeyKind::SecretOrDer(bytes) => rsa_public(bytes)?,
            };
            PKey::from_rsa(rsa).map_err(|error| native_error(&error))
        }
        AlgorithmFamily::Ec => {
            let (nid, _, width) = curve(algorithm)?;
            let bytes = key.try_get_as_bytes()?;
            let ec = if bytes.len() == 1 + width * 2 && bytes.first() == Some(&4) {
                let group = EcGroup::from_curve_name(nid).map_err(|error| native_error(&error))?;
                let point =
                    EcPoint::from_bytes(&group, bytes).map_err(|error| native_error(&error))?;
                EcKey::from_public_key(&group, &point).map_err(|error| native_error(&error))?
            } else {
                PKey::public_key_from_der(bytes)
                    .map_err(|error| native_error(&error))?
                    .ec_key()
                    .map_err(|error| native_error(&error))?
            };
            if ec.group().curve_name() != Some(nid) {
                return Err(new_error(ErrorKind::InvalidEcdsaKey));
            }
            ec.check_key().map_err(|error| native_error(&error))?;
            PKey::from_ec_key(ec).map_err(|error| native_error(&error))
        }
        AlgorithmFamily::Ed => {
            let bytes = key.try_get_as_bytes()?;
            let key = if bytes.len() == 32 {
                PKey::public_key_from_raw_bytes(bytes, Id::ED25519)
            } else {
                PKey::public_key_from_der(bytes)
            }
            .map_err(|error| native_error(&error))?;
            if key.id() != Id::ED25519 {
                return Err(new_error(ErrorKind::InvalidEddsaKey));
            }
            Ok(key)
        }
        AlgorithmFamily::Hmac => Err(new_error(ErrorKind::InvalidAlgorithm)),
    }
}

enum SigningKey {
    Hmac(EncodingKey),
    Asymmetric(PKey<Private>),
}

struct BtlsSigner {
    algorithm: Algorithm,
    key: SigningKey,
}

impl signature::Signer<Vec<u8>> for BtlsSigner {
    fn try_sign(&self, message: &[u8]) -> SigResult<Vec<u8>> {
        let key = match &self.key {
            SigningKey::Hmac(key) => {
                return mac(self.algorithm, key.as_bytes(), message, <[u8]>::to_vec);
            }
            SigningKey::Asymmetric(key) => key,
        };
        if self.algorithm == Algorithm::EdDSA {
            return Signer::new_without_digest(key)
                .and_then(|signer| signer.sign_oneshot_to_vec(message))
                .map_err(signature_error);
        }
        let md = digest(self.algorithm).map_err(|_| signature::Error::new())?;
        if self.algorithm.family() == AlgorithmFamily::Ec {
            let (_, _, width) = curve(self.algorithm).map_err(|_| signature::Error::new())?;
            let ec = key.ec_key().map_err(signature_error)?;
            let hashed = hash::hash(md, message).map_err(signature_error)?;
            let sig = EcdsaSig::sign_digest(&hashed, &ec).map_err(signature_error)?;
            let mut raw = sig.r().to_vec_padded(width).map_err(signature_error)?;
            raw.extend(sig.s().to_vec_padded(width).map_err(signature_error)?);
            return Ok(raw);
        }
        let mut signer = Signer::new_oneshot(md, key).map_err(signature_error)?;
        if rsa_pss(self.algorithm) {
            signer
                .set_rsa_padding(Padding::PKCS1_PSS)
                .map_err(signature_error)?;
            signer.set_rsa_mgf1_md(md).map_err(signature_error)?;
            signer
                .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .map_err(signature_error)?;
        } else {
            signer
                .set_rsa_padding(Padding::PKCS1)
                .map_err(signature_error)?;
        }
        signer.sign_oneshot_to_vec(message).map_err(signature_error)
    }
}

impl JwtSigner for BtlsSigner {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

enum VerificationKey {
    Hmac(DecodingKey),
    Asymmetric(PKey<Public>),
}

struct BtlsVerifier {
    algorithm: Algorithm,
    key: VerificationKey,
}

impl signature::Verifier<Vec<u8>> for BtlsVerifier {
    fn verify(&self, message: &[u8], signature: &Vec<u8>) -> SigResult<()> {
        let ok = match &self.key {
            VerificationKey::Hmac(key) => {
                let key = key
                    .try_get_as_bytes()
                    .map_err(|_| signature::Error::new())?;
                mac(self.algorithm, key, message, |expected| {
                    memcmp::eq(expected, signature)
                })?
            }
            VerificationKey::Asymmetric(key) if self.algorithm == Algorithm::EdDSA => {
                Verifier::new_without_digest(key)
                    .and_then(|verifier| verifier.verify_oneshot(signature, message))
                    .map_err(signature_error)?
            }
            VerificationKey::Asymmetric(key) => {
                let md = digest(self.algorithm).map_err(|_| signature::Error::new())?;
                if self.algorithm.family() == AlgorithmFamily::Ec {
                    let (_, _, width) =
                        curve(self.algorithm).map_err(|_| signature::Error::new())?;
                    if signature.len() != 2 * width {
                        return Err(signature::Error::new());
                    }
                    let (r, s) = signature.split_at(width);
                    let sig = EcdsaSig::from_components(
                        BigNum::from_slice(r).map_err(signature_error)?,
                        BigNum::from_slice(s).map_err(signature_error)?,
                    )
                    .map_err(signature_error)?;
                    let hashed = hash::hash(md, message).map_err(signature_error)?;
                    let ec = key.ec_key().map_err(signature_error)?;
                    sig.verify_digest(&hashed, &ec).map_err(signature_error)?;
                    true
                } else {
                    let mut verifier = Verifier::new_oneshot(md, key).map_err(signature_error)?;
                    if rsa_pss(self.algorithm) {
                        verifier
                            .set_rsa_padding(Padding::PKCS1_PSS)
                            .map_err(signature_error)?;
                        verifier.set_rsa_mgf1_md(md).map_err(signature_error)?;
                        verifier
                            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                            .map_err(signature_error)?;
                    } else {
                        verifier
                            .set_rsa_padding(Padding::PKCS1)
                            .map_err(signature_error)?;
                    }
                    verifier
                        .verify_oneshot(signature, message)
                        .map_err(signature_error)?
                }
            }
        };
        if ok {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}

impl JwtVerifier for BtlsVerifier {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

fn new_signer(algorithm: Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
    if key.family() != algorithm.family() {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }
    let key = if key.family() == AlgorithmFamily::Hmac {
        SigningKey::Hmac(key.clone())
    } else {
        SigningKey::Asymmetric(private_key(algorithm, key.as_bytes())?)
    };
    Ok(Box::new(BtlsSigner { algorithm, key }))
}

fn new_verifier(algorithm: Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
    if key.family() != algorithm.family() {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }
    let key = if key.family() == AlgorithmFamily::Hmac {
        VerificationKey::Hmac(key.clone())
    } else {
        VerificationKey::Asymmetric(public_key(algorithm, key)?)
    };
    Ok(Box::new(BtlsVerifier { algorithm, key }))
}

fn rsa_components_private(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = private_key(Algorithm::RS256, bytes)?;
    let rsa = key.rsa().map_err(|error| native_error(&error))?;
    Ok((rsa.n().to_vec(), rsa.e().to_vec()))
}

fn rsa_components_public(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let rsa = rsa_public(bytes)?;
    Ok((rsa.n().to_vec(), rsa.e().to_vec()))
}

fn ec_components_private(
    bytes: &[u8],
    algorithm: Algorithm,
) -> Result<(EllipticCurve, Vec<u8>, Vec<u8>)> {
    let (_, curve, width) = curve(algorithm)?;
    let ec = private_key(algorithm, bytes)?
        .ec_key()
        .map_err(|error| native_error(&error))?;
    let point = ec
        .public_key()
        .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED)
        .map_err(|error| native_error(&error))?;
    if point.len() != 1 + 2 * width || point.first() != Some(&4) {
        return Err(new_error(ErrorKind::InvalidEcdsaKey));
    }
    let (x, y) = point[1..].split_at(width);
    Ok((curve, x.to_vec(), y.to_vec()))
}

fn ed_components_private(bytes: &[u8], curve: &EllipticCurve) -> Result<Vec<u8>> {
    if *curve != EllipticCurve::Ed25519 {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }
    let key = private_key(Algorithm::EdDSA, bytes)?;
    let mut raw = [0; 32];
    Ok(key
        .raw_public_key(&mut raw)
        .map_err(|error| native_error(&error))?
        .to_vec())
}

fn compute_digest(data: &[u8], algorithm: &ThumbprintHash) -> Result<Vec<u8>> {
    let md = match algorithm {
        ThumbprintHash::SHA256 => MessageDigest::sha256(),
        ThumbprintHash::SHA384 => MessageDigest::sha384(),
        ThumbprintHash::SHA512 => MessageDigest::sha512(),
        _ => return Err(new_error(ErrorKind::UnsupportedAlgorithm)),
    };
    Ok(hash::hash(md, data)
        .map_err(|error| native_error(&error))?
        .to_vec())
}

/// BoringSSL-backed implementation of all jsonwebtoken 12 signing algorithms.
pub static DEFAULT_PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: |algorithm, key| new_signer(*algorithm, key),
    verifier_factory: |algorithm, key| new_verifier(*algorithm, key),
    key_utils: KeyUtils {
        rsa_pub_components_from_private_key: rsa_components_private,
        rsa_pub_components_from_public_key: rsa_components_public,
        ec_pub_components_from_private_key: ec_components_private,
        ed_pub_components_from_private_key: ed_components_private,
        compute_digest: |data, algorithm| compute_digest(data, &algorithm),
    },
};

/// Install this provider, or return an error if a different provider is already installed.
///
/// # Errors
/// Another crypto provider was installed first.
pub fn install() -> Result<()> {
    let _ = DEFAULT_PROVIDER.install_default();
    if CryptoProvider::try_get_default()
        .is_some_and(|provider| std::ptr::eq(provider, &raw const DEFAULT_PROVIDER))
    {
        Ok(())
    } else {
        Err(new_error(ErrorKind::Provider(
            "another JWT crypto provider is installed".into(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Header, Validation, decode, encode, jwk::Jwk};
    use serde_json::json;

    fn roundtrip(algorithm: Algorithm, key: &EncodingKey, public: &DecodingKey) -> Result<()> {
        install()?;
        let claims = json!({"exp": 4_102_444_800_u64, "sub": "provider regression"});
        let token = encode(&Header::new(algorithm), &claims, key)?;
        let validation = Validation::new(algorithm);
        assert_eq!(
            decode::<serde_json::Value>(&token, public, &validation)?.claims,
            claims
        );
        let (message, _) = token.rsplit_once('.').expect("compact signature");
        let bad_token = format!("{message}.AA");
        assert!(decode::<serde_json::Value>(&bad_token, public, &validation).is_err());
        let signer = (DEFAULT_PROVIDER.signer_factory)(&algorithm, key)?;
        let verifier = (DEFAULT_PROVIDER.verifier_factory)(&algorithm, public)?;
        let signature = signer
            .try_sign(b"original")
            .map_err(|_| new_error(ErrorKind::InvalidSignature))?;
        verifier
            .verify(b"original", &signature)
            .map_err(|_| new_error(ErrorKind::InvalidSignature))?;
        assert!(verifier.verify(b"altered", &signature).is_err());
        let jwk = Jwk::from_encoding_key(key, algorithm)?;
        let jwk_key = DecodingKey::from_jwk(&jwk)?;
        assert_eq!(
            decode::<serde_json::Value>(&token, &jwk_key, &validation)?.claims,
            claims
        );
        for hash in [
            ThumbprintHash::SHA256,
            ThumbprintHash::SHA384,
            ThumbprintHash::SHA512,
        ] {
            assert!(!jwk.thumbprint(hash)?.is_empty());
        }
        Ok(())
    }

    #[test]
    fn hmac_algorithms_and_known_answer() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let key = [0x0b; 20];
        let message = b"Hi There";
        let encoding = EncodingKey::from_secret(&key)?;
        let decoding = DecodingKey::from_secret(&key)?;
        // RFC 4231, test case 1: validate the provider, not just the native hash.
        for (algorithm, expected) in [
            (
                Algorithm::HS256,
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                Algorithm::HS384,
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            ),
            (
                Algorithm::HS512,
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            ),
        ] {
            let signer = (DEFAULT_PROVIDER.signer_factory)(&algorithm, &encoding)?;
            let verifier = (DEFAULT_PROVIDER.verifier_factory)(&algorithm, &decoding)?;
            let expected = hex::decode(expected)?;
            assert_eq!(signer.try_sign(message)?, expected);
            verifier.verify(message, &expected)?;
            let key = [0x5a; 64];
            roundtrip(
                algorithm,
                &EncodingKey::from_secret(&key)?,
                &DecodingKey::from_secret(&key)?,
            )?;
        }
        Ok(())
    }

    #[test]
    fn rsa_algorithms_and_key_formats() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let rsa = Rsa::generate(2048)?;
        let private = EncodingKey::from_rsa_der(&rsa.private_key_to_der()?);
        let public = DecodingKey::from_rsa_der(&rsa.public_key_to_der_pkcs1()?);
        for algorithm in [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ] {
            roundtrip(algorithm, &private, &public)?;
        }
        let modulus = rsa.n().to_vec();
        for exponent in [&[][..], &[0], &[1], &[2], &[4], &[1, 0, 0, 0, 0, 1]] {
            let malformed = DecodingKey::from_rsa_raw_components(&modulus, exponent);
            assert!((DEFAULT_PROVIDER.verifier_factory)(&Algorithm::RS256, &malformed).is_err());
        }
        let mut even_modulus = modulus;
        *even_modulus.last_mut().unwrap() &= !1;
        let malformed = DecodingKey::from_rsa_raw_components(&even_modulus, &[1, 0, 1]);
        assert!((DEFAULT_PROVIDER.verifier_factory)(&Algorithm::RS256, &malformed).is_err());
        let signer = (DEFAULT_PROVIDER.signer_factory)(&Algorithm::RS256, &private)?;
        let verifier = (DEFAULT_PROVIDER.verifier_factory)(&Algorithm::PS256, &public)?;
        assert!(
            verifier
                .verify(b"same", &signer.try_sign(b"same")?)
                .is_err()
        );
        // JOSE fixes both the salt length and MGF1 hash; otherwise valid
        // RSA-PSS signatures with different parameters must be rejected.
        let native_key = PKey::from_rsa(rsa)?;
        for (salt, mgf) in [
            (RsaPssSaltlen::custom(20), MessageDigest::sha256()),
            (RsaPssSaltlen::DIGEST_LENGTH, MessageDigest::sha384()),
        ] {
            let mut signer = Signer::new_oneshot(MessageDigest::sha256(), &native_key)?;
            signer.set_rsa_padding(Padding::PKCS1_PSS)?;
            signer.set_rsa_mgf1_md(mgf)?;
            signer.set_rsa_pss_saltlen(salt)?;
            let signature = signer.sign_oneshot_to_vec(b"same")?;
            assert!(verifier.verify(b"same", &signature).is_err());
        }
        let weak = Rsa::generate(1024)?;
        assert!(
            (DEFAULT_PROVIDER.verifier_factory)(
                &Algorithm::RS256,
                &DecodingKey::from_rsa_raw_components(&weak.n().to_vec(), &weak.e().to_vec())
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn ecdsa_algorithms_and_curve_mismatch() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        for algorithm in [Algorithm::ES256, Algorithm::ES384] {
            let (nid, _, width) = curve(algorithm)?;
            let group = EcGroup::from_curve_name(nid)?;
            let ec = EcKey::generate(&group)?;
            let key = PKey::from_ec_key(ec)?;
            let private = EncodingKey::from_ec_der(&key.private_key_to_der_pkcs8()?);
            let public = DecodingKey::from_ec_der(&key.public_key_to_der()?);
            roundtrip(algorithm, &private, &public)?;
            let signer = (DEFAULT_PROVIDER.signer_factory)(&algorithm, &private)?;
            assert_eq!(signer.try_sign(b"raw signature")?.len(), 2 * width);
            let other = if algorithm == Algorithm::ES256 {
                Algorithm::ES384
            } else {
                Algorithm::ES256
            };
            assert!((DEFAULT_PROVIDER.verifier_factory)(&other, &public).is_err());
        }
        Ok(())
    }

    #[test]
    fn ed25519_jwk_and_key_formats() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let key = PKey::generate(Id::ED25519)?;
        let private = EncodingKey::from_ed_der(&key.private_key_to_der_pkcs8()?);
        let public = DecodingKey::from_ed_der(&key.public_key_to_der()?);
        roundtrip(Algorithm::EdDSA, &private, &public)?;
        Ok(())
    }

    #[test]
    fn ed25519_rfc8032_known_answer() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // RFC 8032 section 7.1, TEST 1; PKCS#8 wrapping from RFC 8410.
        let private = hex::decode(
            "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )?;
        let public =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")?;
        let expected = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )?;
        let signer = (DEFAULT_PROVIDER.signer_factory)(
            &Algorithm::EdDSA,
            &EncodingKey::from_ed_der(&private),
        )?;
        let verifier = (DEFAULT_PROVIDER.verifier_factory)(
            &Algorithm::EdDSA,
            &DecodingKey::from_ed_der(&public),
        )?;
        assert_eq!(signer.try_sign(b"")?, expected);
        verifier.verify(b"", &expected)?;
        assert!(verifier.verify(b"changed", &expected).is_err());
        Ok(())
    }

    #[test]
    fn wrong_key_family_rejected() -> Result<()> {
        let key = DecodingKey::from_secret(b"not a public key")?;
        assert!((DEFAULT_PROVIDER.verifier_factory)(&Algorithm::RS256, &key).is_err());
        Ok(())
    }
}
