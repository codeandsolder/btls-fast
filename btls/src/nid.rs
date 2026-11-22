//! A collection of numerical identifiers for OpenSSL objects.
use crate::ffi;
use libc::c_int;
use openssl_macros::corresponds;

use std::ffi::CStr;
use std::str;

use crate::cvt_p;
use crate::error::ErrorStack;

/// The digest and public-key algorithms associated with a signature.
pub struct SignatureAlgorithms {
    /// The signature's digest.
    ///
    /// If the signature does not specify a digest, this will be `NID::UNDEF`.
    pub digest: Nid,

    /// The signature's public-key.
    pub pkey: Nid,
}

/// A numerical identifier for an OpenSSL object.
///
/// Objects in OpenSSL can have a short name, a long name, and
/// a numerical identifier (NID). For convenience, objects
/// are usually represented in source code using these numeric
/// identifiers.
///
/// Users should generally not need to create new `Nid`s.
///
/// # Examples
///
/// To view the integer representation of a `Nid`:
///
/// ```
/// use btls::nid::Nid;
///
/// assert!(Nid::AES_256_GCM.as_raw() == 901);
/// ```
///
/// # External Documentation
///
/// The following documentation provides context about `Nid`s and their usage
/// in OpenSSL.
///
/// - [Obj_nid2obj](https://www.openssl.org/docs/man1.1.0/crypto/OBJ_create.html)
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Nid(c_int);

impl Nid {
    /// Create a `Nid` from an integer representation.
    #[must_use]
    pub const fn from_raw(raw: c_int) -> Self {
        Self(raw)
    }

    /// Return the integer representation of a `Nid`.
    #[must_use = "The returned native representation is needed by the caller."]
    pub const fn as_raw(self) -> c_int {
        self.0
    }

    /// Returns the `Nid`s of the digest and public key algorithms associated with a signature ID.
    #[corresponds(OBJ_find_sigid_algs)]
    #[must_use = "The returned algorithm identifiers describe the signature."]
    pub fn signature_algorithms(self) -> Option<SignatureAlgorithms> {
        unsafe {
            let mut digest = 0;
            let mut pkey = 0;
            if ffi::OBJ_find_sigid_algs(self.0, &raw mut digest, &raw mut pkey) == 1 {
                Some(SignatureAlgorithms {
                    digest: Self(digest),
                    pkey: Self(pkey),
                })
            } else {
                None
            }
        }
    }

    /// Return the string representation of a `Nid` (long)
    #[corresponds(OBJ_nid2ln)]
    pub fn long_name(self) -> Result<&'static str, ErrorStack> {
        unsafe {
            let nameptr = cvt_p(ffi::OBJ_nid2ln(self.0).cast_mut())?;
            CStr::from_ptr(nameptr)
                .to_str()
                .map_err(ErrorStack::internal_error)
        }
    }

    /// Return the string representation of a `Nid` (short)
    #[corresponds(OBJ_nid2sn)]
    pub fn short_name(self) -> Result<&'static str, ErrorStack> {
        unsafe {
            let nameptr = cvt_p(ffi::OBJ_nid2sn(self.0).cast_mut())?;
            CStr::from_ptr(nameptr)
                .to_str()
                .map_err(ErrorStack::internal_error)
        }
    }

    pub const UNDEF: Self = Self(ffi::NID_undef);
    pub const ITU_T: Self = Self(ffi::NID_itu_t);
    pub const ISO: Self = Self(ffi::NID_iso);
    pub const JOINT_ISO_ITU_T: Self = Self(ffi::NID_joint_iso_itu_t);
    pub const MEMBER_BODY: Self = Self(ffi::NID_member_body);
    pub const IDENTIFIED_ORGANIZATION: Self = Self(ffi::NID_identified_organization);
    pub const HMAC_MD5: Self = Self(ffi::NID_hmac_md5);
    pub const HMAC_SHA1: Self = Self(ffi::NID_hmac_sha1);
    pub const CERTICOM_ARC: Self = Self(ffi::NID_certicom_arc);
    pub const INTERNATIONAL_ORGANIZATIONS: Self = Self(ffi::NID_international_organizations);
    pub const WAP: Self = Self(ffi::NID_wap);
    pub const WAP_WSG: Self = Self(ffi::NID_wap_wsg);
    pub const SELECTED_ATTRIBUTE_TYPES: Self = Self(ffi::NID_selected_attribute_types);
    pub const CLEARANCE: Self = Self(ffi::NID_clearance);
    pub const ISO_US: Self = Self(ffi::NID_ISO_US);
    pub const X9_57: Self = Self(ffi::NID_X9_57);
    pub const X9CM: Self = Self(ffi::NID_X9cm);
    pub const DSA: Self = Self(ffi::NID_dsa);
    pub const DSAWITHSHA1: Self = Self(ffi::NID_dsaWithSHA1);
    pub const ANSI_X9_62: Self = Self(ffi::NID_ansi_X9_62);
    pub const X9_62_PRIME_FIELD: Self = Self(ffi::NID_X9_62_prime_field);
    pub const X9_62_CHARACTERISTIC_TWO_FIELD: Self = Self(ffi::NID_X9_62_characteristic_two_field);
    pub const X9_62_ID_CHARACTERISTIC_TWO_BASIS: Self =
        Self(ffi::NID_X9_62_id_characteristic_two_basis);
    pub const X9_62_ONBASIS: Self = Self(ffi::NID_X9_62_onBasis);
    pub const X9_62_TPBASIS: Self = Self(ffi::NID_X9_62_tpBasis);
    pub const X9_62_PPBASIS: Self = Self(ffi::NID_X9_62_ppBasis);
    pub const X9_62_ID_ECPUBLICKEY: Self = Self(ffi::NID_X9_62_id_ecPublicKey);
    pub const X9_62_C2PNB163V1: Self = Self(ffi::NID_X9_62_c2pnb163v1);
    pub const X9_62_C2PNB163V2: Self = Self(ffi::NID_X9_62_c2pnb163v2);
    pub const X9_62_C2PNB163V3: Self = Self(ffi::NID_X9_62_c2pnb163v3);
    pub const X9_62_C2PNB176V1: Self = Self(ffi::NID_X9_62_c2pnb176v1);
    pub const X9_62_C2TNB191V1: Self = Self(ffi::NID_X9_62_c2tnb191v1);
    pub const X9_62_C2TNB191V2: Self = Self(ffi::NID_X9_62_c2tnb191v2);
    pub const X9_62_C2TNB191V3: Self = Self(ffi::NID_X9_62_c2tnb191v3);
    pub const X9_62_C2ONB191V4: Self = Self(ffi::NID_X9_62_c2onb191v4);
    pub const X9_62_C2ONB191V5: Self = Self(ffi::NID_X9_62_c2onb191v5);
    pub const X9_62_C2PNB208W1: Self = Self(ffi::NID_X9_62_c2pnb208w1);
    pub const X9_62_C2TNB239V1: Self = Self(ffi::NID_X9_62_c2tnb239v1);
    pub const X9_62_C2TNB239V2: Self = Self(ffi::NID_X9_62_c2tnb239v2);
    pub const X9_62_C2TNB239V3: Self = Self(ffi::NID_X9_62_c2tnb239v3);
    pub const X9_62_C2ONB239V4: Self = Self(ffi::NID_X9_62_c2onb239v4);
    pub const X9_62_C2ONB239V5: Self = Self(ffi::NID_X9_62_c2onb239v5);
    pub const X9_62_C2PNB272W1: Self = Self(ffi::NID_X9_62_c2pnb272w1);
    pub const X9_62_C2PNB304W1: Self = Self(ffi::NID_X9_62_c2pnb304w1);
    pub const X9_62_C2TNB359V1: Self = Self(ffi::NID_X9_62_c2tnb359v1);
    pub const X9_62_C2PNB368W1: Self = Self(ffi::NID_X9_62_c2pnb368w1);
    pub const X9_62_C2TNB431R1: Self = Self(ffi::NID_X9_62_c2tnb431r1);
    pub const X9_62_PRIME192V1: Self = Self(ffi::NID_X9_62_prime192v1);
    pub const X9_62_PRIME192V2: Self = Self(ffi::NID_X9_62_prime192v2);
    pub const X9_62_PRIME192V3: Self = Self(ffi::NID_X9_62_prime192v3);
    pub const X9_62_PRIME239V1: Self = Self(ffi::NID_X9_62_prime239v1);
    pub const X9_62_PRIME239V2: Self = Self(ffi::NID_X9_62_prime239v2);
    pub const X9_62_PRIME239V3: Self = Self(ffi::NID_X9_62_prime239v3);
    pub const X9_62_PRIME256V1: Self = Self(ffi::NID_X9_62_prime256v1);
    pub const ECDSA_WITH_SHA1: Self = Self(ffi::NID_ecdsa_with_SHA1);
    pub const ECDSA_WITH_RECOMMENDED: Self = Self(ffi::NID_ecdsa_with_Recommended);
    pub const ECDSA_WITH_SPECIFIED: Self = Self(ffi::NID_ecdsa_with_Specified);
    pub const ECDSA_WITH_SHA224: Self = Self(ffi::NID_ecdsa_with_SHA224);
    pub const ECDSA_WITH_SHA256: Self = Self(ffi::NID_ecdsa_with_SHA256);
    pub const ECDSA_WITH_SHA384: Self = Self(ffi::NID_ecdsa_with_SHA384);
    pub const ECDSA_WITH_SHA512: Self = Self(ffi::NID_ecdsa_with_SHA512);
    pub const SECP112R1: Self = Self(ffi::NID_secp112r1);
    pub const SECP112R2: Self = Self(ffi::NID_secp112r2);
    pub const SECP128R1: Self = Self(ffi::NID_secp128r1);
    pub const SECP128R2: Self = Self(ffi::NID_secp128r2);
    pub const SECP160K1: Self = Self(ffi::NID_secp160k1);
    pub const SECP160R1: Self = Self(ffi::NID_secp160r1);
    pub const SECP160R2: Self = Self(ffi::NID_secp160r2);
    pub const SECP192K1: Self = Self(ffi::NID_secp192k1);
    pub const SECP224K1: Self = Self(ffi::NID_secp224k1);
    pub const SECP224R1: Self = Self(ffi::NID_secp224r1);
    pub const SECP256K1: Self = Self(ffi::NID_secp256k1);
    pub const SECP384R1: Self = Self(ffi::NID_secp384r1);
    pub const SECP521R1: Self = Self(ffi::NID_secp521r1);
    pub const SECT113R1: Self = Self(ffi::NID_sect113r1);
    pub const SECT113R2: Self = Self(ffi::NID_sect113r2);
    pub const SECT131R1: Self = Self(ffi::NID_sect131r1);
    pub const SECT131R2: Self = Self(ffi::NID_sect131r2);
    pub const SECT163K1: Self = Self(ffi::NID_sect163k1);
    pub const SECT163R1: Self = Self(ffi::NID_sect163r1);
    pub const SECT163R2: Self = Self(ffi::NID_sect163r2);
    pub const SECT193R1: Self = Self(ffi::NID_sect193r1);
    pub const SECT193R2: Self = Self(ffi::NID_sect193r2);
    pub const SECT233K1: Self = Self(ffi::NID_sect233k1);
    pub const SECT233R1: Self = Self(ffi::NID_sect233r1);
    pub const SECT239K1: Self = Self(ffi::NID_sect239k1);
    pub const SECT283K1: Self = Self(ffi::NID_sect283k1);
    pub const SECT283R1: Self = Self(ffi::NID_sect283r1);
    pub const SECT409K1: Self = Self(ffi::NID_sect409k1);
    pub const SECT409R1: Self = Self(ffi::NID_sect409r1);
    pub const SECT571K1: Self = Self(ffi::NID_sect571k1);
    pub const SECT571R1: Self = Self(ffi::NID_sect571r1);
    pub const WAP_WSG_IDM_ECID_WTLS1: Self = Self(ffi::NID_wap_wsg_idm_ecid_wtls1);
    pub const WAP_WSG_IDM_ECID_WTLS3: Self = Self(ffi::NID_wap_wsg_idm_ecid_wtls3);
    pub const WAP_WSG_IDM_ECID_WTLS4: Self = Self(ffi::NID_wap_wsg_idm_ecid_wtls4);
    pub const WAP_WSG_IDM_ECID_WTLS5: Self = Self(ffi::NID_wap_wsg_idm_ecid_wtls5);
    pub const WAP_WSG_IDM_ECID_WTLS6: Self = Self(ffi::NID_wap_wsg_idm_ecid_wtls6);
    pub const WAP_WSG_IDM_ECID_WTLS7: Self = Self(ffi::NID_wap_wsg_idm_ecid_wtls7);
    pub const WAP_WSG_IDM_ECID_WTLS8: Self = Self(ffi::NID_wap_wsg_idm_ecid_wtls8);
    pub const WAP_WSG_IDM_ECID_WTLS9: Self = Self(ffi::NID_wap_wsg_idm_ecid_wtls9);
    pub const WAP_WSG_IDM_ECID_WTLS10: Self = Self(ffi::NID_wap_wsg_idm_ecid_wtls10);
    pub const WAP_WSG_IDM_ECID_WTLS11: Self = Self(ffi::NID_wap_wsg_idm_ecid_wtls11);
    pub const WAP_WSG_IDM_ECID_WTLS12: Self = Self(ffi::NID_wap_wsg_idm_ecid_wtls12);
    pub const CAST5_CBC: Self = Self(ffi::NID_cast5_cbc);
    pub const CAST5_ECB: Self = Self(ffi::NID_cast5_ecb);
    pub const CAST5_CFB64: Self = Self(ffi::NID_cast5_cfb64);
    pub const CAST5_OFB64: Self = Self(ffi::NID_cast5_ofb64);
    pub const PBEWITHMD5ANDCAST5_CBC: Self = Self(ffi::NID_pbeWithMD5AndCast5_CBC);
    pub const ID_PASSWORDBASEDMAC: Self = Self(ffi::NID_id_PasswordBasedMAC);
    pub const ID_DHBASEDMAC: Self = Self(ffi::NID_id_DHBasedMac);
    pub const RSADSI: Self = Self(ffi::NID_rsadsi);
    pub const PKCS: Self = Self(ffi::NID_pkcs);
    pub const PKCS1: Self = Self(ffi::NID_pkcs1);
    pub const RSAENCRYPTION: Self = Self(ffi::NID_rsaEncryption);
    pub const MD2WITHRSAENCRYPTION: Self = Self(ffi::NID_md2WithRSAEncryption);
    pub const MD4WITHRSAENCRYPTION: Self = Self(ffi::NID_md4WithRSAEncryption);
    pub const MD5WITHRSAENCRYPTION: Self = Self(ffi::NID_md5WithRSAEncryption);
    pub const SHA1WITHRSAENCRYPTION: Self = Self(ffi::NID_sha1WithRSAEncryption);
    pub const RSAESOAEP: Self = Self(ffi::NID_rsaesOaep);
    pub const MGF1: Self = Self(ffi::NID_mgf1);
    pub const RSASSAPSS: Self = Self(ffi::NID_rsassaPss);
    pub const SHA256WITHRSAENCRYPTION: Self = Self(ffi::NID_sha256WithRSAEncryption);
    pub const SHA384WITHRSAENCRYPTION: Self = Self(ffi::NID_sha384WithRSAEncryption);
    pub const SHA512WITHRSAENCRYPTION: Self = Self(ffi::NID_sha512WithRSAEncryption);
    pub const SHA224WITHRSAENCRYPTION: Self = Self(ffi::NID_sha224WithRSAEncryption);
    pub const PKCS3: Self = Self(ffi::NID_pkcs3);
    pub const DHKEYAGREEMENT: Self = Self(ffi::NID_dhKeyAgreement);
    pub const PKCS5: Self = Self(ffi::NID_pkcs5);
    pub const PBEWITHMD2ANDDES_CBC: Self = Self(ffi::NID_pbeWithMD2AndDES_CBC);
    pub const PBEWITHMD5ANDDES_CBC: Self = Self(ffi::NID_pbeWithMD5AndDES_CBC);
    pub const PBEWITHMD2ANDRC2_CBC: Self = Self(ffi::NID_pbeWithMD2AndRC2_CBC);
    pub const PBEWITHMD5ANDRC2_CBC: Self = Self(ffi::NID_pbeWithMD5AndRC2_CBC);
    pub const PBEWITHSHA1ANDDES_CBC: Self = Self(ffi::NID_pbeWithSHA1AndDES_CBC);
    pub const PBEWITHSHA1ANDRC2_CBC: Self = Self(ffi::NID_pbeWithSHA1AndRC2_CBC);
    pub const ID_PBKDF2: Self = Self(ffi::NID_id_pbkdf2);
    pub const PBES2: Self = Self(ffi::NID_pbes2);
    pub const PBMAC1: Self = Self(ffi::NID_pbmac1);
    pub const PKCS7: Self = Self(ffi::NID_pkcs7);
    pub const PKCS7_DATA: Self = Self(ffi::NID_pkcs7_data);
    pub const PKCS7_SIGNED: Self = Self(ffi::NID_pkcs7_signed);
    pub const PKCS7_ENVELOPED: Self = Self(ffi::NID_pkcs7_enveloped);
    pub const PKCS7_SIGNEDANDENVELOPED: Self = Self(ffi::NID_pkcs7_signedAndEnveloped);
    pub const PKCS7_DIGEST: Self = Self(ffi::NID_pkcs7_digest);
    pub const PKCS7_ENCRYPTED: Self = Self(ffi::NID_pkcs7_encrypted);
    pub const PKCS9: Self = Self(ffi::NID_pkcs9);
    pub const PKCS9_EMAILADDRESS: Self = Self(ffi::NID_pkcs9_emailAddress);
    pub const PKCS9_UNSTRUCTUREDNAME: Self = Self(ffi::NID_pkcs9_unstructuredName);
    pub const PKCS9_CONTENTTYPE: Self = Self(ffi::NID_pkcs9_contentType);
    pub const PKCS9_MESSAGEDIGEST: Self = Self(ffi::NID_pkcs9_messageDigest);
    pub const PKCS9_SIGNINGTIME: Self = Self(ffi::NID_pkcs9_signingTime);
    pub const PKCS9_COUNTERSIGNATURE: Self = Self(ffi::NID_pkcs9_countersignature);
    pub const PKCS9_CHALLENGEPASSWORD: Self = Self(ffi::NID_pkcs9_challengePassword);
    pub const PKCS9_UNSTRUCTUREDADDRESS: Self = Self(ffi::NID_pkcs9_unstructuredAddress);
    pub const PKCS9_EXTCERTATTRIBUTES: Self = Self(ffi::NID_pkcs9_extCertAttributes);
    pub const EXT_REQ: Self = Self(ffi::NID_ext_req);
    pub const SMIMECAPABILITIES: Self = Self(ffi::NID_SMIMECapabilities);
    pub const SMIME: Self = Self(ffi::NID_SMIME);
    pub const ID_SMIME_MOD: Self = Self(ffi::NID_id_smime_mod);
    pub const ID_SMIME_CT: Self = Self(ffi::NID_id_smime_ct);
    pub const ID_SMIME_AA: Self = Self(ffi::NID_id_smime_aa);
    pub const ID_SMIME_ALG: Self = Self(ffi::NID_id_smime_alg);
    pub const ID_SMIME_CD: Self = Self(ffi::NID_id_smime_cd);
    pub const ID_SMIME_SPQ: Self = Self(ffi::NID_id_smime_spq);
    pub const ID_SMIME_CTI: Self = Self(ffi::NID_id_smime_cti);
    pub const ID_SMIME_MOD_CMS: Self = Self(ffi::NID_id_smime_mod_cms);
    pub const ID_SMIME_MOD_ESS: Self = Self(ffi::NID_id_smime_mod_ess);
    pub const ID_SMIME_MOD_OID: Self = Self(ffi::NID_id_smime_mod_oid);
    pub const ID_SMIME_MOD_MSG_V3: Self = Self(ffi::NID_id_smime_mod_msg_v3);
    pub const ID_SMIME_MOD_ETS_ESIGNATURE_88: Self = Self(ffi::NID_id_smime_mod_ets_eSignature_88);
    pub const ID_SMIME_MOD_ETS_ESIGNATURE_97: Self = Self(ffi::NID_id_smime_mod_ets_eSignature_97);
    pub const ID_SMIME_MOD_ETS_ESIGPOLICY_88: Self = Self(ffi::NID_id_smime_mod_ets_eSigPolicy_88);
    pub const ID_SMIME_MOD_ETS_ESIGPOLICY_97: Self = Self(ffi::NID_id_smime_mod_ets_eSigPolicy_97);
    pub const ID_SMIME_CT_RECEIPT: Self = Self(ffi::NID_id_smime_ct_receipt);
    pub const ID_SMIME_CT_AUTHDATA: Self = Self(ffi::NID_id_smime_ct_authData);
    pub const ID_SMIME_CT_PUBLISHCERT: Self = Self(ffi::NID_id_smime_ct_publishCert);
    pub const ID_SMIME_CT_TSTINFO: Self = Self(ffi::NID_id_smime_ct_TSTInfo);
    pub const ID_SMIME_CT_TDTINFO: Self = Self(ffi::NID_id_smime_ct_TDTInfo);
    pub const ID_SMIME_CT_CONTENTINFO: Self = Self(ffi::NID_id_smime_ct_contentInfo);
    pub const ID_SMIME_CT_DVCSREQUESTDATA: Self = Self(ffi::NID_id_smime_ct_DVCSRequestData);
    pub const ID_SMIME_CT_DVCSRESPONSEDATA: Self = Self(ffi::NID_id_smime_ct_DVCSResponseData);
    pub const ID_SMIME_CT_COMPRESSEDDATA: Self = Self(ffi::NID_id_smime_ct_compressedData);
    pub const ID_CT_ASCIITEXTWITHCRLF: Self = Self(ffi::NID_id_ct_asciiTextWithCRLF);
    pub const ID_SMIME_AA_RECEIPTREQUEST: Self = Self(ffi::NID_id_smime_aa_receiptRequest);
    pub const ID_SMIME_AA_SECURITYLABEL: Self = Self(ffi::NID_id_smime_aa_securityLabel);
    pub const ID_SMIME_AA_MLEXPANDHISTORY: Self = Self(ffi::NID_id_smime_aa_mlExpandHistory);
    pub const ID_SMIME_AA_CONTENTHINT: Self = Self(ffi::NID_id_smime_aa_contentHint);
    pub const ID_SMIME_AA_MSGSIGDIGEST: Self = Self(ffi::NID_id_smime_aa_msgSigDigest);
    pub const ID_SMIME_AA_ENCAPCONTENTTYPE: Self = Self(ffi::NID_id_smime_aa_encapContentType);
    pub const ID_SMIME_AA_CONTENTIDENTIFIER: Self = Self(ffi::NID_id_smime_aa_contentIdentifier);
    pub const ID_SMIME_AA_MACVALUE: Self = Self(ffi::NID_id_smime_aa_macValue);
    pub const ID_SMIME_AA_EQUIVALENTLABELS: Self = Self(ffi::NID_id_smime_aa_equivalentLabels);
    pub const ID_SMIME_AA_CONTENTREFERENCE: Self = Self(ffi::NID_id_smime_aa_contentReference);
    pub const ID_SMIME_AA_ENCRYPKEYPREF: Self = Self(ffi::NID_id_smime_aa_encrypKeyPref);
    pub const ID_SMIME_AA_SIGNINGCERTIFICATE: Self = Self(ffi::NID_id_smime_aa_signingCertificate);
    pub const ID_SMIME_AA_SMIMEENCRYPTCERTS: Self = Self(ffi::NID_id_smime_aa_smimeEncryptCerts);
    pub const ID_SMIME_AA_TIMESTAMPTOKEN: Self = Self(ffi::NID_id_smime_aa_timeStampToken);
    pub const ID_SMIME_AA_ETS_SIGPOLICYID: Self = Self(ffi::NID_id_smime_aa_ets_sigPolicyId);
    pub const ID_SMIME_AA_ETS_COMMITMENTTYPE: Self = Self(ffi::NID_id_smime_aa_ets_commitmentType);
    pub const ID_SMIME_AA_ETS_SIGNERLOCATION: Self = Self(ffi::NID_id_smime_aa_ets_signerLocation);
    pub const ID_SMIME_AA_ETS_SIGNERATTR: Self = Self(ffi::NID_id_smime_aa_ets_signerAttr);
    pub const ID_SMIME_AA_ETS_OTHERSIGCERT: Self = Self(ffi::NID_id_smime_aa_ets_otherSigCert);
    pub const ID_SMIME_AA_ETS_CONTENTTIMESTAMP: Self =
        Self(ffi::NID_id_smime_aa_ets_contentTimestamp);
    pub const ID_SMIME_AA_ETS_CERTIFICATEREFS: Self =
        Self(ffi::NID_id_smime_aa_ets_CertificateRefs);
    pub const ID_SMIME_AA_ETS_REVOCATIONREFS: Self = Self(ffi::NID_id_smime_aa_ets_RevocationRefs);
    pub const ID_SMIME_AA_ETS_CERTVALUES: Self = Self(ffi::NID_id_smime_aa_ets_certValues);
    pub const ID_SMIME_AA_ETS_REVOCATIONVALUES: Self =
        Self(ffi::NID_id_smime_aa_ets_revocationValues);
    pub const ID_SMIME_AA_ETS_ESCTIMESTAMP: Self = Self(ffi::NID_id_smime_aa_ets_escTimeStamp);
    pub const ID_SMIME_AA_ETS_CERTCRLTIMESTAMP: Self =
        Self(ffi::NID_id_smime_aa_ets_certCRLTimestamp);
    pub const ID_SMIME_AA_ETS_ARCHIVETIMESTAMP: Self =
        Self(ffi::NID_id_smime_aa_ets_archiveTimeStamp);
    pub const ID_SMIME_AA_SIGNATURETYPE: Self = Self(ffi::NID_id_smime_aa_signatureType);
    pub const ID_SMIME_AA_DVCS_DVC: Self = Self(ffi::NID_id_smime_aa_dvcs_dvc);
    pub const ID_SMIME_ALG_ESDHWITH3DES: Self = Self(ffi::NID_id_smime_alg_ESDHwith3DES);
    pub const ID_SMIME_ALG_ESDHWITHRC2: Self = Self(ffi::NID_id_smime_alg_ESDHwithRC2);
    pub const ID_SMIME_ALG_3DESWRAP: Self = Self(ffi::NID_id_smime_alg_3DESwrap);
    pub const ID_SMIME_ALG_RC2WRAP: Self = Self(ffi::NID_id_smime_alg_RC2wrap);
    pub const ID_SMIME_ALG_ESDH: Self = Self(ffi::NID_id_smime_alg_ESDH);
    pub const ID_SMIME_ALG_CMS3DESWRAP: Self = Self(ffi::NID_id_smime_alg_CMS3DESwrap);
    pub const ID_SMIME_ALG_CMSRC2WRAP: Self = Self(ffi::NID_id_smime_alg_CMSRC2wrap);
    pub const ID_ALG_PWRI_KEK: Self = Self(ffi::NID_id_alg_PWRI_KEK);
    pub const ID_SMIME_CD_LDAP: Self = Self(ffi::NID_id_smime_cd_ldap);
    pub const ID_SMIME_SPQ_ETS_SQT_URI: Self = Self(ffi::NID_id_smime_spq_ets_sqt_uri);
    pub const ID_SMIME_SPQ_ETS_SQT_UNOTICE: Self = Self(ffi::NID_id_smime_spq_ets_sqt_unotice);
    pub const ID_SMIME_CTI_ETS_PROOFOFORIGIN: Self = Self(ffi::NID_id_smime_cti_ets_proofOfOrigin);
    pub const ID_SMIME_CTI_ETS_PROOFOFRECEIPT: Self =
        Self(ffi::NID_id_smime_cti_ets_proofOfReceipt);
    pub const ID_SMIME_CTI_ETS_PROOFOFDELIVERY: Self =
        Self(ffi::NID_id_smime_cti_ets_proofOfDelivery);
    pub const ID_SMIME_CTI_ETS_PROOFOFSENDER: Self = Self(ffi::NID_id_smime_cti_ets_proofOfSender);
    pub const ID_SMIME_CTI_ETS_PROOFOFAPPROVAL: Self =
        Self(ffi::NID_id_smime_cti_ets_proofOfApproval);
    pub const ID_SMIME_CTI_ETS_PROOFOFCREATION: Self =
        Self(ffi::NID_id_smime_cti_ets_proofOfCreation);
    pub const FRIENDLYNAME: Self = Self(ffi::NID_friendlyName);
    pub const LOCALKEYID: Self = Self(ffi::NID_localKeyID);
    pub const MS_CSP_NAME: Self = Self(ffi::NID_ms_csp_name);
    pub const LOCALKEYSET: Self = Self(ffi::NID_LocalKeySet);
    pub const X509CERTIFICATE: Self = Self(ffi::NID_x509Certificate);
    pub const SDSICERTIFICATE: Self = Self(ffi::NID_sdsiCertificate);
    pub const X509CRL: Self = Self(ffi::NID_x509Crl);
    pub const PBE_WITHSHA1AND128BITRC4: Self = Self(ffi::NID_pbe_WithSHA1And128BitRC4);
    pub const PBE_WITHSHA1AND40BITRC4: Self = Self(ffi::NID_pbe_WithSHA1And40BitRC4);
    pub const PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC: Self =
        Self(ffi::NID_pbe_WithSHA1And3_Key_TripleDES_CBC);
    pub const PBE_WITHSHA1AND2_KEY_TRIPLEDES_CBC: Self =
        Self(ffi::NID_pbe_WithSHA1And2_Key_TripleDES_CBC);
    pub const PBE_WITHSHA1AND128BITRC2_CBC: Self = Self(ffi::NID_pbe_WithSHA1And128BitRC2_CBC);
    pub const PBE_WITHSHA1AND40BITRC2_CBC: Self = Self(ffi::NID_pbe_WithSHA1And40BitRC2_CBC);
    pub const KEYBAG: Self = Self(ffi::NID_keyBag);
    pub const PKCS8SHROUDEDKEYBAG: Self = Self(ffi::NID_pkcs8ShroudedKeyBag);
    pub const CERTBAG: Self = Self(ffi::NID_certBag);
    pub const CRLBAG: Self = Self(ffi::NID_crlBag);
    pub const SECRETBAG: Self = Self(ffi::NID_secretBag);
    pub const SAFECONTENTSBAG: Self = Self(ffi::NID_safeContentsBag);
    pub const MD2: Self = Self(ffi::NID_md2);
    pub const MD4: Self = Self(ffi::NID_md4);
    pub const MD5: Self = Self(ffi::NID_md5);
    pub const MD5_SHA1: Self = Self(ffi::NID_md5_sha1);
    pub const HMACWITHMD5: Self = Self(ffi::NID_hmacWithMD5);
    pub const HMACWITHSHA1: Self = Self(ffi::NID_hmacWithSHA1);
    pub const HMACWITHSHA224: Self = Self(ffi::NID_hmacWithSHA224);
    pub const HMACWITHSHA256: Self = Self(ffi::NID_hmacWithSHA256);
    pub const HMACWITHSHA384: Self = Self(ffi::NID_hmacWithSHA384);
    pub const HMACWITHSHA512: Self = Self(ffi::NID_hmacWithSHA512);
    pub const RC2_CBC: Self = Self(ffi::NID_rc2_cbc);
    pub const RC2_ECB: Self = Self(ffi::NID_rc2_ecb);
    pub const RC2_CFB64: Self = Self(ffi::NID_rc2_cfb64);
    pub const RC2_OFB64: Self = Self(ffi::NID_rc2_ofb64);
    pub const RC2_40_CBC: Self = Self(ffi::NID_rc2_40_cbc);
    pub const RC2_64_CBC: Self = Self(ffi::NID_rc2_64_cbc);
    pub const RC4: Self = Self(ffi::NID_rc4);
    pub const RC4_40: Self = Self(ffi::NID_rc4_40);
    pub const DES_EDE3_CBC: Self = Self(ffi::NID_des_ede3_cbc);
    pub const RC5_CBC: Self = Self(ffi::NID_rc5_cbc);
    pub const RC5_ECB: Self = Self(ffi::NID_rc5_ecb);
    pub const RC5_CFB64: Self = Self(ffi::NID_rc5_cfb64);
    pub const RC5_OFB64: Self = Self(ffi::NID_rc5_ofb64);
    pub const MS_EXT_REQ: Self = Self(ffi::NID_ms_ext_req);
    pub const MS_CODE_IND: Self = Self(ffi::NID_ms_code_ind);
    pub const MS_CODE_COM: Self = Self(ffi::NID_ms_code_com);
    pub const MS_CTL_SIGN: Self = Self(ffi::NID_ms_ctl_sign);
    pub const MS_SGC: Self = Self(ffi::NID_ms_sgc);
    pub const MS_EFS: Self = Self(ffi::NID_ms_efs);
    pub const MS_SMARTCARD_LOGIN: Self = Self(ffi::NID_ms_smartcard_login);
    pub const MS_UPN: Self = Self(ffi::NID_ms_upn);
    pub const IDEA_CBC: Self = Self(ffi::NID_idea_cbc);
    pub const IDEA_ECB: Self = Self(ffi::NID_idea_ecb);
    pub const IDEA_CFB64: Self = Self(ffi::NID_idea_cfb64);
    pub const IDEA_OFB64: Self = Self(ffi::NID_idea_ofb64);
    pub const BF_CBC: Self = Self(ffi::NID_bf_cbc);
    pub const BF_ECB: Self = Self(ffi::NID_bf_ecb);
    pub const BF_CFB64: Self = Self(ffi::NID_bf_cfb64);
    pub const BF_OFB64: Self = Self(ffi::NID_bf_ofb64);
    pub const ID_PKIX: Self = Self(ffi::NID_id_pkix);
    pub const ID_PKIX_MOD: Self = Self(ffi::NID_id_pkix_mod);
    pub const ID_PE: Self = Self(ffi::NID_id_pe);
    pub const ID_QT: Self = Self(ffi::NID_id_qt);
    pub const ID_KP: Self = Self(ffi::NID_id_kp);
    pub const ID_IT: Self = Self(ffi::NID_id_it);
    pub const ID_PKIP: Self = Self(ffi::NID_id_pkip);
    pub const ID_ALG: Self = Self(ffi::NID_id_alg);
    pub const ID_CMC: Self = Self(ffi::NID_id_cmc);
    pub const ID_ON: Self = Self(ffi::NID_id_on);
    pub const ID_PDA: Self = Self(ffi::NID_id_pda);
    pub const ID_ACA: Self = Self(ffi::NID_id_aca);
    pub const ID_QCS: Self = Self(ffi::NID_id_qcs);
    pub const ID_CCT: Self = Self(ffi::NID_id_cct);
    pub const ID_PPL: Self = Self(ffi::NID_id_ppl);
    pub const ID_AD: Self = Self(ffi::NID_id_ad);
    pub const ID_PKIX1_EXPLICIT_88: Self = Self(ffi::NID_id_pkix1_explicit_88);
    pub const ID_PKIX1_IMPLICIT_88: Self = Self(ffi::NID_id_pkix1_implicit_88);
    pub const ID_PKIX1_EXPLICIT_93: Self = Self(ffi::NID_id_pkix1_explicit_93);
    pub const ID_PKIX1_IMPLICIT_93: Self = Self(ffi::NID_id_pkix1_implicit_93);
    pub const ID_MOD_CRMF: Self = Self(ffi::NID_id_mod_crmf);
    pub const ID_MOD_CMC: Self = Self(ffi::NID_id_mod_cmc);
    pub const ID_MOD_KEA_PROFILE_88: Self = Self(ffi::NID_id_mod_kea_profile_88);
    pub const ID_MOD_KEA_PROFILE_93: Self = Self(ffi::NID_id_mod_kea_profile_93);
    pub const ID_MOD_CMP: Self = Self(ffi::NID_id_mod_cmp);
    pub const ID_MOD_QUALIFIED_CERT_88: Self = Self(ffi::NID_id_mod_qualified_cert_88);
    pub const ID_MOD_QUALIFIED_CERT_93: Self = Self(ffi::NID_id_mod_qualified_cert_93);
    pub const ID_MOD_ATTRIBUTE_CERT: Self = Self(ffi::NID_id_mod_attribute_cert);
    pub const ID_MOD_TIMESTAMP_PROTOCOL: Self = Self(ffi::NID_id_mod_timestamp_protocol);
    pub const ID_MOD_OCSP: Self = Self(ffi::NID_id_mod_ocsp);
    pub const ID_MOD_DVCS: Self = Self(ffi::NID_id_mod_dvcs);
    pub const ID_MOD_CMP2000: Self = Self(ffi::NID_id_mod_cmp2000);
    pub const INFO_ACCESS: Self = Self(ffi::NID_info_access);
    pub const BIOMETRICINFO: Self = Self(ffi::NID_biometricInfo);
    pub const QCSTATEMENTS: Self = Self(ffi::NID_qcStatements);
    pub const AC_AUDITENTITY: Self = Self(ffi::NID_ac_auditEntity);
    pub const AC_TARGETING: Self = Self(ffi::NID_ac_targeting);
    pub const AACONTROLS: Self = Self(ffi::NID_aaControls);
    pub const SBGP_IPADDRBLOCK: Self = Self(ffi::NID_sbgp_ipAddrBlock);
    pub const SBGP_AUTONOMOUSSYSNUM: Self = Self(ffi::NID_sbgp_autonomousSysNum);
    pub const SBGP_ROUTERIDENTIFIER: Self = Self(ffi::NID_sbgp_routerIdentifier);
    pub const AC_PROXYING: Self = Self(ffi::NID_ac_proxying);
    pub const SINFO_ACCESS: Self = Self(ffi::NID_sinfo_access);
    pub const PROXYCERTINFO: Self = Self(ffi::NID_proxyCertInfo);
    pub const ID_QT_CPS: Self = Self(ffi::NID_id_qt_cps);
    pub const ID_QT_UNOTICE: Self = Self(ffi::NID_id_qt_unotice);
    pub const TEXTNOTICE: Self = Self(ffi::NID_textNotice);
    pub const SERVER_AUTH: Self = Self(ffi::NID_server_auth);
    pub const CLIENT_AUTH: Self = Self(ffi::NID_client_auth);
    pub const CODE_SIGN: Self = Self(ffi::NID_code_sign);
    pub const EMAIL_PROTECT: Self = Self(ffi::NID_email_protect);
    pub const IPSECENDSYSTEM: Self = Self(ffi::NID_ipsecEndSystem);
    pub const IPSECTUNNEL: Self = Self(ffi::NID_ipsecTunnel);
    pub const IPSECUSER: Self = Self(ffi::NID_ipsecUser);
    pub const TIME_STAMP: Self = Self(ffi::NID_time_stamp);
    pub const OCSP_SIGN: Self = Self(ffi::NID_OCSP_sign);
    pub const DVCS: Self = Self(ffi::NID_dvcs);
    pub const ID_IT_CAPROTENCCERT: Self = Self(ffi::NID_id_it_caProtEncCert);
    pub const ID_IT_SIGNKEYPAIRTYPES: Self = Self(ffi::NID_id_it_signKeyPairTypes);
    pub const ID_IT_ENCKEYPAIRTYPES: Self = Self(ffi::NID_id_it_encKeyPairTypes);
    pub const ID_IT_PREFERREDSYMMALG: Self = Self(ffi::NID_id_it_preferredSymmAlg);
    pub const ID_IT_CAKEYUPDATEINFO: Self = Self(ffi::NID_id_it_caKeyUpdateInfo);
    pub const ID_IT_CURRENTCRL: Self = Self(ffi::NID_id_it_currentCRL);
    pub const ID_IT_UNSUPPORTEDOIDS: Self = Self(ffi::NID_id_it_unsupportedOIDs);
    pub const ID_IT_SUBSCRIPTIONREQUEST: Self = Self(ffi::NID_id_it_subscriptionRequest);
    pub const ID_IT_SUBSCRIPTIONRESPONSE: Self = Self(ffi::NID_id_it_subscriptionResponse);
    pub const ID_IT_KEYPAIRPARAMREQ: Self = Self(ffi::NID_id_it_keyPairParamReq);
    pub const ID_IT_KEYPAIRPARAMREP: Self = Self(ffi::NID_id_it_keyPairParamRep);
    pub const ID_IT_REVPASSPHRASE: Self = Self(ffi::NID_id_it_revPassphrase);
    pub const ID_IT_IMPLICITCONFIRM: Self = Self(ffi::NID_id_it_implicitConfirm);
    pub const ID_IT_CONFIRMWAITTIME: Self = Self(ffi::NID_id_it_confirmWaitTime);
    pub const ID_IT_ORIGPKIMESSAGE: Self = Self(ffi::NID_id_it_origPKIMessage);
    pub const ID_IT_SUPPLANGTAGS: Self = Self(ffi::NID_id_it_suppLangTags);
    pub const ID_REGCTRL: Self = Self(ffi::NID_id_regCtrl);
    pub const ID_REGINFO: Self = Self(ffi::NID_id_regInfo);
    pub const ID_REGCTRL_REGTOKEN: Self = Self(ffi::NID_id_regCtrl_regToken);
    pub const ID_REGCTRL_AUTHENTICATOR: Self = Self(ffi::NID_id_regCtrl_authenticator);
    pub const ID_REGCTRL_PKIPUBLICATIONINFO: Self = Self(ffi::NID_id_regCtrl_pkiPublicationInfo);
    pub const ID_REGCTRL_PKIARCHIVEOPTIONS: Self = Self(ffi::NID_id_regCtrl_pkiArchiveOptions);
    pub const ID_REGCTRL_OLDCERTID: Self = Self(ffi::NID_id_regCtrl_oldCertID);
    pub const ID_REGCTRL_PROTOCOLENCRKEY: Self = Self(ffi::NID_id_regCtrl_protocolEncrKey);
    pub const ID_REGINFO_UTF8PAIRS: Self = Self(ffi::NID_id_regInfo_utf8Pairs);
    pub const ID_REGINFO_CERTREQ: Self = Self(ffi::NID_id_regInfo_certReq);
    pub const ID_ALG_DES40: Self = Self(ffi::NID_id_alg_des40);
    pub const ID_ALG_NOSIGNATURE: Self = Self(ffi::NID_id_alg_noSignature);
    pub const ID_ALG_DH_SIG_HMAC_SHA1: Self = Self(ffi::NID_id_alg_dh_sig_hmac_sha1);
    pub const ID_ALG_DH_POP: Self = Self(ffi::NID_id_alg_dh_pop);
    pub const ID_CMC_STATUSINFO: Self = Self(ffi::NID_id_cmc_statusInfo);
    pub const ID_CMC_IDENTIFICATION: Self = Self(ffi::NID_id_cmc_identification);
    pub const ID_CMC_IDENTITYPROOF: Self = Self(ffi::NID_id_cmc_identityProof);
    pub const ID_CMC_DATARETURN: Self = Self(ffi::NID_id_cmc_dataReturn);
    pub const ID_CMC_TRANSACTIONID: Self = Self(ffi::NID_id_cmc_transactionId);
    pub const ID_CMC_SENDERNONCE: Self = Self(ffi::NID_id_cmc_senderNonce);
    pub const ID_CMC_RECIPIENTNONCE: Self = Self(ffi::NID_id_cmc_recipientNonce);
    pub const ID_CMC_ADDEXTENSIONS: Self = Self(ffi::NID_id_cmc_addExtensions);
    pub const ID_CMC_ENCRYPTEDPOP: Self = Self(ffi::NID_id_cmc_encryptedPOP);
    pub const ID_CMC_DECRYPTEDPOP: Self = Self(ffi::NID_id_cmc_decryptedPOP);
    pub const ID_CMC_LRAPOPWITNESS: Self = Self(ffi::NID_id_cmc_lraPOPWitness);
    pub const ID_CMC_GETCERT: Self = Self(ffi::NID_id_cmc_getCert);
    pub const ID_CMC_GETCRL: Self = Self(ffi::NID_id_cmc_getCRL);
    pub const ID_CMC_REVOKEREQUEST: Self = Self(ffi::NID_id_cmc_revokeRequest);
    pub const ID_CMC_REGINFO: Self = Self(ffi::NID_id_cmc_regInfo);
    pub const ID_CMC_RESPONSEINFO: Self = Self(ffi::NID_id_cmc_responseInfo);
    pub const ID_CMC_QUERYPENDING: Self = Self(ffi::NID_id_cmc_queryPending);
    pub const ID_CMC_POPLINKRANDOM: Self = Self(ffi::NID_id_cmc_popLinkRandom);
    pub const ID_CMC_POPLINKWITNESS: Self = Self(ffi::NID_id_cmc_popLinkWitness);
    pub const ID_CMC_CONFIRMCERTACCEPTANCE: Self = Self(ffi::NID_id_cmc_confirmCertAcceptance);
    pub const ID_ON_PERSONALDATA: Self = Self(ffi::NID_id_on_personalData);
    pub const ID_ON_PERMANENTIDENTIFIER: Self = Self(ffi::NID_id_on_permanentIdentifier);
    pub const ID_PDA_DATEOFBIRTH: Self = Self(ffi::NID_id_pda_dateOfBirth);
    pub const ID_PDA_PLACEOFBIRTH: Self = Self(ffi::NID_id_pda_placeOfBirth);
    pub const ID_PDA_GENDER: Self = Self(ffi::NID_id_pda_gender);
    pub const ID_PDA_COUNTRYOFCITIZENSHIP: Self = Self(ffi::NID_id_pda_countryOfCitizenship);
    pub const ID_PDA_COUNTRYOFRESIDENCE: Self = Self(ffi::NID_id_pda_countryOfResidence);
    pub const ID_ACA_AUTHENTICATIONINFO: Self = Self(ffi::NID_id_aca_authenticationInfo);
    pub const ID_ACA_ACCESSIDENTITY: Self = Self(ffi::NID_id_aca_accessIdentity);
    pub const ID_ACA_CHARGINGIDENTITY: Self = Self(ffi::NID_id_aca_chargingIdentity);
    pub const ID_ACA_GROUP: Self = Self(ffi::NID_id_aca_group);
    pub const ID_ACA_ROLE: Self = Self(ffi::NID_id_aca_role);
    pub const ID_ACA_ENCATTRS: Self = Self(ffi::NID_id_aca_encAttrs);
    pub const ID_QCS_PKIXQCSYNTAX_V1: Self = Self(ffi::NID_id_qcs_pkixQCSyntax_v1);
    pub const ID_CCT_CRS: Self = Self(ffi::NID_id_cct_crs);
    pub const ID_CCT_PKIDATA: Self = Self(ffi::NID_id_cct_PKIData);
    pub const ID_CCT_PKIRESPONSE: Self = Self(ffi::NID_id_cct_PKIResponse);
    pub const ID_PPL_ANYLANGUAGE: Self = Self(ffi::NID_id_ppl_anyLanguage);
    pub const ID_PPL_INHERITALL: Self = Self(ffi::NID_id_ppl_inheritAll);
    pub const INDEPENDENT: Self = Self(ffi::NID_Independent);
    pub const AD_OCSP: Self = Self(ffi::NID_ad_OCSP);
    pub const AD_CA_ISSUERS: Self = Self(ffi::NID_ad_ca_issuers);
    pub const AD_TIMESTAMPING: Self = Self(ffi::NID_ad_timeStamping);
    pub const AD_DVCS: Self = Self(ffi::NID_ad_dvcs);
    pub const CAREPOSITORY: Self = Self(ffi::NID_caRepository);
    pub const ID_PKIX_OCSP_BASIC: Self = Self(ffi::NID_id_pkix_OCSP_basic);
    pub const ID_PKIX_OCSP_NONCE: Self = Self(ffi::NID_id_pkix_OCSP_Nonce);
    pub const ID_PKIX_OCSP_CRLID: Self = Self(ffi::NID_id_pkix_OCSP_CrlID);
    pub const ID_PKIX_OCSP_ACCEPTABLERESPONSES: Self =
        Self(ffi::NID_id_pkix_OCSP_acceptableResponses);
    pub const ID_PKIX_OCSP_NOCHECK: Self = Self(ffi::NID_id_pkix_OCSP_noCheck);
    pub const ID_PKIX_OCSP_ARCHIVECUTOFF: Self = Self(ffi::NID_id_pkix_OCSP_archiveCutoff);
    pub const ID_PKIX_OCSP_SERVICELOCATOR: Self = Self(ffi::NID_id_pkix_OCSP_serviceLocator);
    pub const ID_PKIX_OCSP_EXTENDEDSTATUS: Self = Self(ffi::NID_id_pkix_OCSP_extendedStatus);
    pub const ID_PKIX_OCSP_VALID: Self = Self(ffi::NID_id_pkix_OCSP_valid);
    pub const ID_PKIX_OCSP_PATH: Self = Self(ffi::NID_id_pkix_OCSP_path);
    pub const ID_PKIX_OCSP_TRUSTROOT: Self = Self(ffi::NID_id_pkix_OCSP_trustRoot);
    pub const ALGORITHM: Self = Self(ffi::NID_algorithm);
    pub const MD5WITHRSA: Self = Self(ffi::NID_md5WithRSA);
    pub const DES_ECB: Self = Self(ffi::NID_des_ecb);
    pub const DES_CBC: Self = Self(ffi::NID_des_cbc);
    pub const DES_OFB64: Self = Self(ffi::NID_des_ofb64);
    pub const DES_CFB64: Self = Self(ffi::NID_des_cfb64);
    pub const RSASIGNATURE: Self = Self(ffi::NID_rsaSignature);
    pub const DSA_2: Self = Self(ffi::NID_dsa_2);
    pub const DSAWITHSHA: Self = Self(ffi::NID_dsaWithSHA);
    pub const SHAWITHRSAENCRYPTION: Self = Self(ffi::NID_shaWithRSAEncryption);
    pub const DES_EDE_ECB: Self = Self(ffi::NID_des_ede_ecb);
    pub const DES_EDE3_ECB: Self = Self(ffi::NID_des_ede3_ecb);
    pub const DES_EDE_CBC: Self = Self(ffi::NID_des_ede_cbc);
    pub const DES_EDE_CFB64: Self = Self(ffi::NID_des_ede_cfb64);
    pub const DES_EDE3_CFB64: Self = Self(ffi::NID_des_ede3_cfb64);
    pub const DES_EDE_OFB64: Self = Self(ffi::NID_des_ede_ofb64);
    pub const DES_EDE3_OFB64: Self = Self(ffi::NID_des_ede3_ofb64);
    pub const DESX_CBC: Self = Self(ffi::NID_desx_cbc);
    pub const SHA: Self = Self(ffi::NID_sha);
    pub const SHA1: Self = Self(ffi::NID_sha1);
    pub const DSAWITHSHA1_2: Self = Self(ffi::NID_dsaWithSHA1_2);
    pub const SHA1WITHRSA: Self = Self(ffi::NID_sha1WithRSA);
    pub const RIPEMD160: Self = Self(ffi::NID_ripemd160);
    pub const RIPEMD160WITHRSA: Self = Self(ffi::NID_ripemd160WithRSA);
    pub const SXNET: Self = Self(ffi::NID_sxnet);
    pub const X500: Self = Self(ffi::NID_X500);
    pub const X509: Self = Self(ffi::NID_X509);
    pub const COMMONNAME: Self = Self(ffi::NID_commonName);
    pub const SURNAME: Self = Self(ffi::NID_surname);
    pub const SERIALNUMBER: Self = Self(ffi::NID_serialNumber);
    pub const COUNTRYNAME: Self = Self(ffi::NID_countryName);
    pub const LOCALITYNAME: Self = Self(ffi::NID_localityName);
    pub const STATEORPROVINCENAME: Self = Self(ffi::NID_stateOrProvinceName);
    pub const STREETADDRESS: Self = Self(ffi::NID_streetAddress);
    pub const ORGANIZATIONNAME: Self = Self(ffi::NID_organizationName);
    pub const ORGANIZATIONALUNITNAME: Self = Self(ffi::NID_organizationalUnitName);
    pub const TITLE: Self = Self(ffi::NID_title);
    pub const DESCRIPTION: Self = Self(ffi::NID_description);
    pub const SEARCHGUIDE: Self = Self(ffi::NID_searchGuide);
    pub const BUSINESSCATEGORY: Self = Self(ffi::NID_businessCategory);
    pub const POSTALADDRESS: Self = Self(ffi::NID_postalAddress);
    pub const POSTALCODE: Self = Self(ffi::NID_postalCode);
    pub const POSTOFFICEBOX: Self = Self(ffi::NID_postOfficeBox);
    pub const PHYSICALDELIVERYOFFICENAME: Self = Self(ffi::NID_physicalDeliveryOfficeName);
    pub const TELEPHONENUMBER: Self = Self(ffi::NID_telephoneNumber);
    pub const TELEXNUMBER: Self = Self(ffi::NID_telexNumber);
    pub const TELETEXTERMINALIDENTIFIER: Self = Self(ffi::NID_teletexTerminalIdentifier);
    pub const FACSIMILETELEPHONENUMBER: Self = Self(ffi::NID_facsimileTelephoneNumber);
    pub const X121ADDRESS: Self = Self(ffi::NID_x121Address);
    pub const INTERNATIONALISDNNUMBER: Self = Self(ffi::NID_internationaliSDNNumber);
    pub const REGISTEREDADDRESS: Self = Self(ffi::NID_registeredAddress);
    pub const DESTINATIONINDICATOR: Self = Self(ffi::NID_destinationIndicator);
    pub const PREFERREDDELIVERYMETHOD: Self = Self(ffi::NID_preferredDeliveryMethod);
    pub const PRESENTATIONADDRESS: Self = Self(ffi::NID_presentationAddress);
    pub const SUPPORTEDAPPLICATIONCONTEXT: Self = Self(ffi::NID_supportedApplicationContext);
    pub const MEMBER: Self = Self(ffi::NID_member);
    pub const OWNER: Self = Self(ffi::NID_owner);
    pub const ROLEOCCUPANT: Self = Self(ffi::NID_roleOccupant);
    pub const SEEALSO: Self = Self(ffi::NID_seeAlso);
    pub const USERPASSWORD: Self = Self(ffi::NID_userPassword);
    pub const USERCERTIFICATE: Self = Self(ffi::NID_userCertificate);
    pub const CACERTIFICATE: Self = Self(ffi::NID_cACertificate);
    pub const AUTHORITYREVOCATIONLIST: Self = Self(ffi::NID_authorityRevocationList);
    pub const CERTIFICATEREVOCATIONLIST: Self = Self(ffi::NID_certificateRevocationList);
    pub const CROSSCERTIFICATEPAIR: Self = Self(ffi::NID_crossCertificatePair);
    pub const NAME: Self = Self(ffi::NID_name);
    pub const GIVENNAME: Self = Self(ffi::NID_givenName);
    pub const INITIALS: Self = Self(ffi::NID_initials);
    pub const GENERATIONQUALIFIER: Self = Self(ffi::NID_generationQualifier);
    pub const X500UNIQUEIDENTIFIER: Self = Self(ffi::NID_x500UniqueIdentifier);
    pub const DNQUALIFIER: Self = Self(ffi::NID_dnQualifier);
    pub const ENHANCEDSEARCHGUIDE: Self = Self(ffi::NID_enhancedSearchGuide);
    pub const PROTOCOLINFORMATION: Self = Self(ffi::NID_protocolInformation);
    pub const DISTINGUISHEDNAME: Self = Self(ffi::NID_distinguishedName);
    pub const UNIQUEMEMBER: Self = Self(ffi::NID_uniqueMember);
    pub const HOUSEIDENTIFIER: Self = Self(ffi::NID_houseIdentifier);
    pub const SUPPORTEDALGORITHMS: Self = Self(ffi::NID_supportedAlgorithms);
    pub const DELTAREVOCATIONLIST: Self = Self(ffi::NID_deltaRevocationList);
    pub const DMDNAME: Self = Self(ffi::NID_dmdName);
    pub const PSEUDONYM: Self = Self(ffi::NID_pseudonym);
    pub const ROLE: Self = Self(ffi::NID_role);
    pub const X500ALGORITHMS: Self = Self(ffi::NID_X500algorithms);
    pub const RSA: Self = Self(ffi::NID_rsa);
    pub const MDC2WITHRSA: Self = Self(ffi::NID_mdc2WithRSA);
    pub const MDC2: Self = Self(ffi::NID_mdc2);
    pub const ID_CE: Self = Self(ffi::NID_id_ce);
    pub const SUBJECT_DIRECTORY_ATTRIBUTES: Self = Self(ffi::NID_subject_directory_attributes);
    pub const SUBJECT_KEY_IDENTIFIER: Self = Self(ffi::NID_subject_key_identifier);
    pub const KEY_USAGE: Self = Self(ffi::NID_key_usage);
    pub const PRIVATE_KEY_USAGE_PERIOD: Self = Self(ffi::NID_private_key_usage_period);
    pub const SUBJECT_ALT_NAME: Self = Self(ffi::NID_subject_alt_name);
    pub const ISSUER_ALT_NAME: Self = Self(ffi::NID_issuer_alt_name);
    pub const BASIC_CONSTRAINTS: Self = Self(ffi::NID_basic_constraints);
    pub const CRL_NUMBER: Self = Self(ffi::NID_crl_number);
    pub const CRL_REASON: Self = Self(ffi::NID_crl_reason);
    pub const INVALIDITY_DATE: Self = Self(ffi::NID_invalidity_date);
    pub const DELTA_CRL: Self = Self(ffi::NID_delta_crl);
    pub const ISSUING_DISTRIBUTION_POINT: Self = Self(ffi::NID_issuing_distribution_point);
    pub const CERTIFICATE_ISSUER: Self = Self(ffi::NID_certificate_issuer);
    pub const NAME_CONSTRAINTS: Self = Self(ffi::NID_name_constraints);
    pub const CRL_DISTRIBUTION_POINTS: Self = Self(ffi::NID_crl_distribution_points);
    pub const CERTIFICATE_POLICIES: Self = Self(ffi::NID_certificate_policies);
    pub const ANY_POLICY: Self = Self(ffi::NID_any_policy);
    pub const POLICY_MAPPINGS: Self = Self(ffi::NID_policy_mappings);
    pub const AUTHORITY_KEY_IDENTIFIER: Self = Self(ffi::NID_authority_key_identifier);
    pub const POLICY_CONSTRAINTS: Self = Self(ffi::NID_policy_constraints);
    pub const EXT_KEY_USAGE: Self = Self(ffi::NID_ext_key_usage);
    pub const FRESHEST_CRL: Self = Self(ffi::NID_freshest_crl);
    pub const INHIBIT_ANY_POLICY: Self = Self(ffi::NID_inhibit_any_policy);
    pub const TARGET_INFORMATION: Self = Self(ffi::NID_target_information);
    pub const NO_REV_AVAIL: Self = Self(ffi::NID_no_rev_avail);
    pub const ANYEXTENDEDKEYUSAGE: Self = Self(ffi::NID_anyExtendedKeyUsage);
    pub const NETSCAPE: Self = Self(ffi::NID_netscape);
    pub const NETSCAPE_CERT_EXTENSION: Self = Self(ffi::NID_netscape_cert_extension);
    pub const NETSCAPE_DATA_TYPE: Self = Self(ffi::NID_netscape_data_type);
    pub const NETSCAPE_CERT_TYPE: Self = Self(ffi::NID_netscape_cert_type);
    pub const NETSCAPE_BASE_URL: Self = Self(ffi::NID_netscape_base_url);
    pub const NETSCAPE_REVOCATION_URL: Self = Self(ffi::NID_netscape_revocation_url);
    pub const NETSCAPE_CA_REVOCATION_URL: Self = Self(ffi::NID_netscape_ca_revocation_url);
    pub const NETSCAPE_RENEWAL_URL: Self = Self(ffi::NID_netscape_renewal_url);
    pub const NETSCAPE_CA_POLICY_URL: Self = Self(ffi::NID_netscape_ca_policy_url);
    pub const NETSCAPE_SSL_SERVER_NAME: Self = Self(ffi::NID_netscape_ssl_server_name);
    pub const NETSCAPE_COMMENT: Self = Self(ffi::NID_netscape_comment);
    pub const NETSCAPE_CERT_SEQUENCE: Self = Self(ffi::NID_netscape_cert_sequence);
    pub const NS_SGC: Self = Self(ffi::NID_ns_sgc);
    pub const ORG: Self = Self(ffi::NID_org);
    pub const DOD: Self = Self(ffi::NID_dod);
    pub const IANA: Self = Self(ffi::NID_iana);
    pub const DIRECTORY: Self = Self(ffi::NID_Directory);
    pub const MANAGEMENT: Self = Self(ffi::NID_Management);
    pub const EXPERIMENTAL: Self = Self(ffi::NID_Experimental);
    pub const PRIVATE: Self = Self(ffi::NID_Private);
    pub const SECURITY: Self = Self(ffi::NID_Security);
    pub const SNMPV2: Self = Self(ffi::NID_SNMPv2);
    pub const MAIL: Self = Self(ffi::NID_Mail);
    pub const ENTERPRISES: Self = Self(ffi::NID_Enterprises);
    pub const DCOBJECT: Self = Self(ffi::NID_dcObject);
    pub const MIME_MHS: Self = Self(ffi::NID_mime_mhs);
    pub const MIME_MHS_HEADINGS: Self = Self(ffi::NID_mime_mhs_headings);
    pub const MIME_MHS_BODIES: Self = Self(ffi::NID_mime_mhs_bodies);
    pub const ID_HEX_PARTIAL_MESSAGE: Self = Self(ffi::NID_id_hex_partial_message);
    pub const ID_HEX_MULTIPART_MESSAGE: Self = Self(ffi::NID_id_hex_multipart_message);
    pub const ZLIB_COMPRESSION: Self = Self(ffi::NID_zlib_compression);
    pub const AES_128_ECB: Self = Self(ffi::NID_aes_128_ecb);
    pub const AES_128_CBC: Self = Self(ffi::NID_aes_128_cbc);
    pub const AES_128_OFB128: Self = Self(ffi::NID_aes_128_ofb128);
    pub const AES_128_CFB128: Self = Self(ffi::NID_aes_128_cfb128);
    pub const ID_AES128_WRAP: Self = Self(ffi::NID_id_aes128_wrap);
    pub const AES_128_GCM: Self = Self(ffi::NID_aes_128_gcm);
    pub const AES_128_CCM: Self = Self(ffi::NID_aes_128_ccm);
    pub const ID_AES128_WRAP_PAD: Self = Self(ffi::NID_id_aes128_wrap_pad);
    pub const AES_192_ECB: Self = Self(ffi::NID_aes_192_ecb);
    pub const AES_192_CBC: Self = Self(ffi::NID_aes_192_cbc);
    pub const AES_192_OFB128: Self = Self(ffi::NID_aes_192_ofb128);
    pub const AES_192_CFB128: Self = Self(ffi::NID_aes_192_cfb128);
    pub const ID_AES192_WRAP: Self = Self(ffi::NID_id_aes192_wrap);
    pub const AES_192_GCM: Self = Self(ffi::NID_aes_192_gcm);
    pub const AES_192_CCM: Self = Self(ffi::NID_aes_192_ccm);
    pub const ID_AES192_WRAP_PAD: Self = Self(ffi::NID_id_aes192_wrap_pad);
    pub const AES_256_ECB: Self = Self(ffi::NID_aes_256_ecb);
    pub const AES_256_CBC: Self = Self(ffi::NID_aes_256_cbc);
    pub const AES_256_OFB128: Self = Self(ffi::NID_aes_256_ofb128);
    pub const AES_256_CFB128: Self = Self(ffi::NID_aes_256_cfb128);
    pub const ID_AES256_WRAP: Self = Self(ffi::NID_id_aes256_wrap);
    pub const AES_256_GCM: Self = Self(ffi::NID_aes_256_gcm);
    pub const AES_256_CCM: Self = Self(ffi::NID_aes_256_ccm);
    pub const ID_AES256_WRAP_PAD: Self = Self(ffi::NID_id_aes256_wrap_pad);
    pub const AES_128_CFB1: Self = Self(ffi::NID_aes_128_cfb1);
    pub const AES_192_CFB1: Self = Self(ffi::NID_aes_192_cfb1);
    pub const AES_256_CFB1: Self = Self(ffi::NID_aes_256_cfb1);
    pub const AES_128_CFB8: Self = Self(ffi::NID_aes_128_cfb8);
    pub const AES_192_CFB8: Self = Self(ffi::NID_aes_192_cfb8);
    pub const AES_256_CFB8: Self = Self(ffi::NID_aes_256_cfb8);
    pub const AES_128_CTR: Self = Self(ffi::NID_aes_128_ctr);
    pub const AES_192_CTR: Self = Self(ffi::NID_aes_192_ctr);
    pub const AES_256_CTR: Self = Self(ffi::NID_aes_256_ctr);
    pub const AES_128_XTS: Self = Self(ffi::NID_aes_128_xts);
    pub const AES_256_XTS: Self = Self(ffi::NID_aes_256_xts);
    pub const DES_CFB1: Self = Self(ffi::NID_des_cfb1);
    pub const DES_CFB8: Self = Self(ffi::NID_des_cfb8);
    pub const DES_EDE3_CFB1: Self = Self(ffi::NID_des_ede3_cfb1);
    pub const DES_EDE3_CFB8: Self = Self(ffi::NID_des_ede3_cfb8);
    pub const SHA256: Self = Self(ffi::NID_sha256);
    pub const SHA384: Self = Self(ffi::NID_sha384);
    pub const SHA512: Self = Self(ffi::NID_sha512);
    pub const SHA512_256: Self = Self(ffi::NID_sha512_256);
    pub const SHA224: Self = Self(ffi::NID_sha224);
    pub const DSA_WITH_SHA224: Self = Self(ffi::NID_dsa_with_SHA224);
    pub const DSA_WITH_SHA256: Self = Self(ffi::NID_dsa_with_SHA256);
    pub const HOLD_INSTRUCTION_CODE: Self = Self(ffi::NID_hold_instruction_code);
    pub const HOLD_INSTRUCTION_NONE: Self = Self(ffi::NID_hold_instruction_none);
    pub const HOLD_INSTRUCTION_CALL_ISSUER: Self = Self(ffi::NID_hold_instruction_call_issuer);
    pub const HOLD_INSTRUCTION_REJECT: Self = Self(ffi::NID_hold_instruction_reject);
    pub const DATA: Self = Self(ffi::NID_data);
    pub const PSS: Self = Self(ffi::NID_pss);
    pub const UCL: Self = Self(ffi::NID_ucl);
    pub const PILOT: Self = Self(ffi::NID_pilot);
    pub const PILOTATTRIBUTETYPE: Self = Self(ffi::NID_pilotAttributeType);
    pub const PILOTATTRIBUTESYNTAX: Self = Self(ffi::NID_pilotAttributeSyntax);
    pub const PILOTOBJECTCLASS: Self = Self(ffi::NID_pilotObjectClass);
    pub const PILOTGROUPS: Self = Self(ffi::NID_pilotGroups);
    pub const IA5STRINGSYNTAX: Self = Self(ffi::NID_iA5StringSyntax);
    pub const CASEIGNOREIA5STRINGSYNTAX: Self = Self(ffi::NID_caseIgnoreIA5StringSyntax);
    pub const PILOTOBJECT: Self = Self(ffi::NID_pilotObject);
    pub const PILOTPERSON: Self = Self(ffi::NID_pilotPerson);
    pub const ACCOUNT: Self = Self(ffi::NID_account);
    pub const DOCUMENT: Self = Self(ffi::NID_document);
    pub const ROOM: Self = Self(ffi::NID_room);
    pub const DOCUMENTSERIES: Self = Self(ffi::NID_documentSeries);
    pub const DOMAIN: Self = Self(ffi::NID_Domain);
    pub const RFC822LOCALPART: Self = Self(ffi::NID_rFC822localPart);
    pub const DNSDOMAIN: Self = Self(ffi::NID_dNSDomain);
    pub const DOMAINRELATEDOBJECT: Self = Self(ffi::NID_domainRelatedObject);
    pub const FRIENDLYCOUNTRY: Self = Self(ffi::NID_friendlyCountry);
    pub const SIMPLESECURITYOBJECT: Self = Self(ffi::NID_simpleSecurityObject);
    pub const PILOTORGANIZATION: Self = Self(ffi::NID_pilotOrganization);
    pub const PILOTDSA: Self = Self(ffi::NID_pilotDSA);
    pub const QUALITYLABELLEDDATA: Self = Self(ffi::NID_qualityLabelledData);
    pub const USERID: Self = Self(ffi::NID_userId);
    pub const TEXTENCODEDORADDRESS: Self = Self(ffi::NID_textEncodedORAddress);
    pub const RFC822MAILBOX: Self = Self(ffi::NID_rfc822Mailbox);
    pub const INFO: Self = Self(ffi::NID_info);
    pub const FAVOURITEDRINK: Self = Self(ffi::NID_favouriteDrink);
    pub const ROOMNUMBER: Self = Self(ffi::NID_roomNumber);
    pub const PHOTO: Self = Self(ffi::NID_photo);
    pub const USERCLASS: Self = Self(ffi::NID_userClass);
    pub const HOST: Self = Self(ffi::NID_host);
    pub const MANAGER: Self = Self(ffi::NID_manager);
    pub const DOCUMENTIDENTIFIER: Self = Self(ffi::NID_documentIdentifier);
    pub const DOCUMENTTITLE: Self = Self(ffi::NID_documentTitle);
    pub const DOCUMENTVERSION: Self = Self(ffi::NID_documentVersion);
    pub const DOCUMENTAUTHOR: Self = Self(ffi::NID_documentAuthor);
    pub const DOCUMENTLOCATION: Self = Self(ffi::NID_documentLocation);
    pub const HOMETELEPHONENUMBER: Self = Self(ffi::NID_homeTelephoneNumber);
    pub const SECRETARY: Self = Self(ffi::NID_secretary);
    pub const OTHERMAILBOX: Self = Self(ffi::NID_otherMailbox);
    pub const LASTMODIFIEDTIME: Self = Self(ffi::NID_lastModifiedTime);
    pub const LASTMODIFIEDBY: Self = Self(ffi::NID_lastModifiedBy);
    pub const DOMAINCOMPONENT: Self = Self(ffi::NID_domainComponent);
    pub const ARECORD: Self = Self(ffi::NID_aRecord);
    pub const PILOTATTRIBUTETYPE27: Self = Self(ffi::NID_pilotAttributeType27);
    pub const MXRECORD: Self = Self(ffi::NID_mXRecord);
    pub const NSRECORD: Self = Self(ffi::NID_nSRecord);
    pub const SOARECORD: Self = Self(ffi::NID_sOARecord);
    pub const CNAMERECORD: Self = Self(ffi::NID_cNAMERecord);
    pub const ASSOCIATEDDOMAIN: Self = Self(ffi::NID_associatedDomain);
    pub const ASSOCIATEDNAME: Self = Self(ffi::NID_associatedName);
    pub const HOMEPOSTALADDRESS: Self = Self(ffi::NID_homePostalAddress);
    pub const PERSONALTITLE: Self = Self(ffi::NID_personalTitle);
    pub const MOBILETELEPHONENUMBER: Self = Self(ffi::NID_mobileTelephoneNumber);
    pub const PAGERTELEPHONENUMBER: Self = Self(ffi::NID_pagerTelephoneNumber);
    pub const FRIENDLYCOUNTRYNAME: Self = Self(ffi::NID_friendlyCountryName);
    pub const ORGANIZATIONALSTATUS: Self = Self(ffi::NID_organizationalStatus);
    pub const JANETMAILBOX: Self = Self(ffi::NID_janetMailbox);
    pub const MAILPREFERENCEOPTION: Self = Self(ffi::NID_mailPreferenceOption);
    pub const BUILDINGNAME: Self = Self(ffi::NID_buildingName);
    pub const DSAQUALITY: Self = Self(ffi::NID_dSAQuality);
    pub const SINGLELEVELQUALITY: Self = Self(ffi::NID_singleLevelQuality);
    pub const SUBTREEMINIMUMQUALITY: Self = Self(ffi::NID_subtreeMinimumQuality);
    pub const SUBTREEMAXIMUMQUALITY: Self = Self(ffi::NID_subtreeMaximumQuality);
    pub const PERSONALSIGNATURE: Self = Self(ffi::NID_personalSignature);
    pub const DITREDIRECT: Self = Self(ffi::NID_dITRedirect);
    pub const AUDIO: Self = Self(ffi::NID_audio);
    pub const DOCUMENTPUBLISHER: Self = Self(ffi::NID_documentPublisher);
    pub const ID_SET: Self = Self(ffi::NID_id_set);
    pub const SET_CTYPE: Self = Self(ffi::NID_set_ctype);
    pub const SET_MSGEXT: Self = Self(ffi::NID_set_msgExt);
    pub const SET_ATTR: Self = Self(ffi::NID_set_attr);
    pub const SET_POLICY: Self = Self(ffi::NID_set_policy);
    pub const SET_CERTEXT: Self = Self(ffi::NID_set_certExt);
    pub const SET_BRAND: Self = Self(ffi::NID_set_brand);
    pub const SETCT_PANDATA: Self = Self(ffi::NID_setct_PANData);
    pub const SETCT_PANTOKEN: Self = Self(ffi::NID_setct_PANToken);
    pub const SETCT_PANONLY: Self = Self(ffi::NID_setct_PANOnly);
    pub const SETCT_OIDATA: Self = Self(ffi::NID_setct_OIData);
    pub const SETCT_PI: Self = Self(ffi::NID_setct_PI);
    pub const SETCT_PIDATA: Self = Self(ffi::NID_setct_PIData);
    pub const SETCT_PIDATAUNSIGNED: Self = Self(ffi::NID_setct_PIDataUnsigned);
    pub const SETCT_HODINPUT: Self = Self(ffi::NID_setct_HODInput);
    pub const SETCT_AUTHRESBAGGAGE: Self = Self(ffi::NID_setct_AuthResBaggage);
    pub const SETCT_AUTHREVREQBAGGAGE: Self = Self(ffi::NID_setct_AuthRevReqBaggage);
    pub const SETCT_AUTHREVRESBAGGAGE: Self = Self(ffi::NID_setct_AuthRevResBaggage);
    pub const SETCT_CAPTOKENSEQ: Self = Self(ffi::NID_setct_CapTokenSeq);
    pub const SETCT_PINITRESDATA: Self = Self(ffi::NID_setct_PInitResData);
    pub const SETCT_PI_TBS: Self = Self(ffi::NID_setct_PI_TBS);
    pub const SETCT_PRESDATA: Self = Self(ffi::NID_setct_PResData);
    pub const SETCT_AUTHREQTBS: Self = Self(ffi::NID_setct_AuthReqTBS);
    pub const SETCT_AUTHRESTBS: Self = Self(ffi::NID_setct_AuthResTBS);
    pub const SETCT_AUTHRESTBSX: Self = Self(ffi::NID_setct_AuthResTBSX);
    pub const SETCT_AUTHTOKENTBS: Self = Self(ffi::NID_setct_AuthTokenTBS);
    pub const SETCT_CAPTOKENDATA: Self = Self(ffi::NID_setct_CapTokenData);
    pub const SETCT_CAPTOKENTBS: Self = Self(ffi::NID_setct_CapTokenTBS);
    pub const SETCT_ACQCARDCODEMSG: Self = Self(ffi::NID_setct_AcqCardCodeMsg);
    pub const SETCT_AUTHREVREQTBS: Self = Self(ffi::NID_setct_AuthRevReqTBS);
    pub const SETCT_AUTHREVRESDATA: Self = Self(ffi::NID_setct_AuthRevResData);
    pub const SETCT_AUTHREVRESTBS: Self = Self(ffi::NID_setct_AuthRevResTBS);
    pub const SETCT_CAPREQTBS: Self = Self(ffi::NID_setct_CapReqTBS);
    pub const SETCT_CAPREQTBSX: Self = Self(ffi::NID_setct_CapReqTBSX);
    pub const SETCT_CAPRESDATA: Self = Self(ffi::NID_setct_CapResData);
    pub const SETCT_CAPREVREQTBS: Self = Self(ffi::NID_setct_CapRevReqTBS);
    pub const SETCT_CAPREVREQTBSX: Self = Self(ffi::NID_setct_CapRevReqTBSX);
    pub const SETCT_CAPREVRESDATA: Self = Self(ffi::NID_setct_CapRevResData);
    pub const SETCT_CREDREQTBS: Self = Self(ffi::NID_setct_CredReqTBS);
    pub const SETCT_CREDREQTBSX: Self = Self(ffi::NID_setct_CredReqTBSX);
    pub const SETCT_CREDRESDATA: Self = Self(ffi::NID_setct_CredResData);
    pub const SETCT_CREDREVREQTBS: Self = Self(ffi::NID_setct_CredRevReqTBS);
    pub const SETCT_CREDREVREQTBSX: Self = Self(ffi::NID_setct_CredRevReqTBSX);
    pub const SETCT_CREDREVRESDATA: Self = Self(ffi::NID_setct_CredRevResData);
    pub const SETCT_PCERTREQDATA: Self = Self(ffi::NID_setct_PCertReqData);
    pub const SETCT_PCERTRESTBS: Self = Self(ffi::NID_setct_PCertResTBS);
    pub const SETCT_BATCHADMINREQDATA: Self = Self(ffi::NID_setct_BatchAdminReqData);
    pub const SETCT_BATCHADMINRESDATA: Self = Self(ffi::NID_setct_BatchAdminResData);
    pub const SETCT_CARDCINITRESTBS: Self = Self(ffi::NID_setct_CardCInitResTBS);
    pub const SETCT_MEAQCINITRESTBS: Self = Self(ffi::NID_setct_MeAqCInitResTBS);
    pub const SETCT_REGFORMRESTBS: Self = Self(ffi::NID_setct_RegFormResTBS);
    pub const SETCT_CERTREQDATA: Self = Self(ffi::NID_setct_CertReqData);
    pub const SETCT_CERTREQTBS: Self = Self(ffi::NID_setct_CertReqTBS);
    pub const SETCT_CERTRESDATA: Self = Self(ffi::NID_setct_CertResData);
    pub const SETCT_CERTINQREQTBS: Self = Self(ffi::NID_setct_CertInqReqTBS);
    pub const SETCT_ERRORTBS: Self = Self(ffi::NID_setct_ErrorTBS);
    pub const SETCT_PIDUALSIGNEDTBE: Self = Self(ffi::NID_setct_PIDualSignedTBE);
    pub const SETCT_PIUNSIGNEDTBE: Self = Self(ffi::NID_setct_PIUnsignedTBE);
    pub const SETCT_AUTHREQTBE: Self = Self(ffi::NID_setct_AuthReqTBE);
    pub const SETCT_AUTHRESTBE: Self = Self(ffi::NID_setct_AuthResTBE);
    pub const SETCT_AUTHRESTBEX: Self = Self(ffi::NID_setct_AuthResTBEX);
    pub const SETCT_AUTHTOKENTBE: Self = Self(ffi::NID_setct_AuthTokenTBE);
    pub const SETCT_CAPTOKENTBE: Self = Self(ffi::NID_setct_CapTokenTBE);
    pub const SETCT_CAPTOKENTBEX: Self = Self(ffi::NID_setct_CapTokenTBEX);
    pub const SETCT_ACQCARDCODEMSGTBE: Self = Self(ffi::NID_setct_AcqCardCodeMsgTBE);
    pub const SETCT_AUTHREVREQTBE: Self = Self(ffi::NID_setct_AuthRevReqTBE);
    pub const SETCT_AUTHREVRESTBE: Self = Self(ffi::NID_setct_AuthRevResTBE);
    pub const SETCT_AUTHREVRESTBEB: Self = Self(ffi::NID_setct_AuthRevResTBEB);
    pub const SETCT_CAPREQTBE: Self = Self(ffi::NID_setct_CapReqTBE);
    pub const SETCT_CAPREQTBEX: Self = Self(ffi::NID_setct_CapReqTBEX);
    pub const SETCT_CAPRESTBE: Self = Self(ffi::NID_setct_CapResTBE);
    pub const SETCT_CAPREVREQTBE: Self = Self(ffi::NID_setct_CapRevReqTBE);
    pub const SETCT_CAPREVREQTBEX: Self = Self(ffi::NID_setct_CapRevReqTBEX);
    pub const SETCT_CAPREVRESTBE: Self = Self(ffi::NID_setct_CapRevResTBE);
    pub const SETCT_CREDREQTBE: Self = Self(ffi::NID_setct_CredReqTBE);
    pub const SETCT_CREDREQTBEX: Self = Self(ffi::NID_setct_CredReqTBEX);
    pub const SETCT_CREDRESTBE: Self = Self(ffi::NID_setct_CredResTBE);
    pub const SETCT_CREDREVREQTBE: Self = Self(ffi::NID_setct_CredRevReqTBE);
    pub const SETCT_CREDREVREQTBEX: Self = Self(ffi::NID_setct_CredRevReqTBEX);
    pub const SETCT_CREDREVRESTBE: Self = Self(ffi::NID_setct_CredRevResTBE);
    pub const SETCT_BATCHADMINREQTBE: Self = Self(ffi::NID_setct_BatchAdminReqTBE);
    pub const SETCT_BATCHADMINRESTBE: Self = Self(ffi::NID_setct_BatchAdminResTBE);
    pub const SETCT_REGFORMREQTBE: Self = Self(ffi::NID_setct_RegFormReqTBE);
    pub const SETCT_CERTREQTBE: Self = Self(ffi::NID_setct_CertReqTBE);
    pub const SETCT_CERTREQTBEX: Self = Self(ffi::NID_setct_CertReqTBEX);
    pub const SETCT_CERTRESTBE: Self = Self(ffi::NID_setct_CertResTBE);
    pub const SETCT_CRLNOTIFICATIONTBS: Self = Self(ffi::NID_setct_CRLNotificationTBS);
    pub const SETCT_CRLNOTIFICATIONRESTBS: Self = Self(ffi::NID_setct_CRLNotificationResTBS);
    pub const SETCT_BCIDISTRIBUTIONTBS: Self = Self(ffi::NID_setct_BCIDistributionTBS);
    pub const SETEXT_GENCRYPT: Self = Self(ffi::NID_setext_genCrypt);
    pub const SETEXT_MIAUTH: Self = Self(ffi::NID_setext_miAuth);
    pub const SETEXT_PINSECURE: Self = Self(ffi::NID_setext_pinSecure);
    pub const SETEXT_PINANY: Self = Self(ffi::NID_setext_pinAny);
    pub const SETEXT_TRACK2: Self = Self(ffi::NID_setext_track2);
    pub const SETEXT_CV: Self = Self(ffi::NID_setext_cv);
    pub const SET_POLICY_ROOT: Self = Self(ffi::NID_set_policy_root);
    pub const SETCEXT_HASHEDROOT: Self = Self(ffi::NID_setCext_hashedRoot);
    pub const SETCEXT_CERTTYPE: Self = Self(ffi::NID_setCext_certType);
    pub const SETCEXT_MERCHDATA: Self = Self(ffi::NID_setCext_merchData);
    pub const SETCEXT_CCERTREQUIRED: Self = Self(ffi::NID_setCext_cCertRequired);
    pub const SETCEXT_TUNNELING: Self = Self(ffi::NID_setCext_tunneling);
    pub const SETCEXT_SETEXT: Self = Self(ffi::NID_setCext_setExt);
    pub const SETCEXT_SETQUALF: Self = Self(ffi::NID_setCext_setQualf);
    pub const SETCEXT_PGWYCAPABILITIES: Self = Self(ffi::NID_setCext_PGWYcapabilities);
    pub const SETCEXT_TOKENIDENTIFIER: Self = Self(ffi::NID_setCext_TokenIdentifier);
    pub const SETCEXT_TRACK2DATA: Self = Self(ffi::NID_setCext_Track2Data);
    pub const SETCEXT_TOKENTYPE: Self = Self(ffi::NID_setCext_TokenType);
    pub const SETCEXT_ISSUERCAPABILITIES: Self = Self(ffi::NID_setCext_IssuerCapabilities);
    pub const SETATTR_CERT: Self = Self(ffi::NID_setAttr_Cert);
    pub const SETATTR_PGWYCAP: Self = Self(ffi::NID_setAttr_PGWYcap);
    pub const SETATTR_TOKENTYPE: Self = Self(ffi::NID_setAttr_TokenType);
    pub const SETATTR_ISSCAP: Self = Self(ffi::NID_setAttr_IssCap);
    pub const SET_ROOTKEYTHUMB: Self = Self(ffi::NID_set_rootKeyThumb);
    pub const SET_ADDPOLICY: Self = Self(ffi::NID_set_addPolicy);
    pub const SETATTR_TOKEN_EMV: Self = Self(ffi::NID_setAttr_Token_EMV);
    pub const SETATTR_TOKEN_B0PRIME: Self = Self(ffi::NID_setAttr_Token_B0Prime);
    pub const SETATTR_ISSCAP_CVM: Self = Self(ffi::NID_setAttr_IssCap_CVM);
    pub const SETATTR_ISSCAP_T2: Self = Self(ffi::NID_setAttr_IssCap_T2);
    pub const SETATTR_ISSCAP_SIG: Self = Self(ffi::NID_setAttr_IssCap_Sig);
    pub const SETATTR_GENCRYPTGRM: Self = Self(ffi::NID_setAttr_GenCryptgrm);
    pub const SETATTR_T2ENC: Self = Self(ffi::NID_setAttr_T2Enc);
    pub const SETATTR_T2CLEARTXT: Self = Self(ffi::NID_setAttr_T2cleartxt);
    pub const SETATTR_TOKICCSIG: Self = Self(ffi::NID_setAttr_TokICCsig);
    pub const SETATTR_SECDEVSIG: Self = Self(ffi::NID_setAttr_SecDevSig);
    pub const SET_BRAND_IATA_ATA: Self = Self(ffi::NID_set_brand_IATA_ATA);
    pub const SET_BRAND_DINERS: Self = Self(ffi::NID_set_brand_Diners);
    pub const SET_BRAND_AMERICANEXPRESS: Self = Self(ffi::NID_set_brand_AmericanExpress);
    pub const SET_BRAND_JCB: Self = Self(ffi::NID_set_brand_JCB);
    pub const SET_BRAND_VISA: Self = Self(ffi::NID_set_brand_Visa);
    pub const SET_BRAND_MASTERCARD: Self = Self(ffi::NID_set_brand_MasterCard);
    pub const SET_BRAND_NOVUS: Self = Self(ffi::NID_set_brand_Novus);
    pub const DES_CDMF: Self = Self(ffi::NID_des_cdmf);
    pub const RSAOAEPENCRYPTIONSET: Self = Self(ffi::NID_rsaOAEPEncryptionSET);
    pub const IPSEC3: Self = Self(ffi::NID_ipsec3);
    pub const IPSEC4: Self = Self(ffi::NID_ipsec4);
    pub const WHIRLPOOL: Self = Self(ffi::NID_whirlpool);
    pub const CRYPTOPRO: Self = Self(ffi::NID_cryptopro);
    pub const CRYPTOCOM: Self = Self(ffi::NID_cryptocom);
    pub const ID_GOSTR3411_94_WITH_GOSTR3410_2001: Self =
        Self(ffi::NID_id_GostR3411_94_with_GostR3410_2001);
    pub const ID_GOSTR3411_94_WITH_GOSTR3410_94: Self =
        Self(ffi::NID_id_GostR3411_94_with_GostR3410_94);
    pub const ID_GOSTR3411_94: Self = Self(ffi::NID_id_GostR3411_94);
    pub const ID_HMACGOSTR3411_94: Self = Self(ffi::NID_id_HMACGostR3411_94);
    pub const ID_GOSTR3410_2001: Self = Self(ffi::NID_id_GostR3410_2001);
    pub const ID_GOSTR3410_94: Self = Self(ffi::NID_id_GostR3410_94);
    pub const ID_GOST28147_89: Self = Self(ffi::NID_id_Gost28147_89);
    pub const GOST89_CNT: Self = Self(ffi::NID_gost89_cnt);
    pub const ID_GOST28147_89_MAC: Self = Self(ffi::NID_id_Gost28147_89_MAC);
    pub const ID_GOSTR3411_94_PRF: Self = Self(ffi::NID_id_GostR3411_94_prf);
    pub const ID_GOSTR3410_2001DH: Self = Self(ffi::NID_id_GostR3410_2001DH);
    pub const ID_GOSTR3410_94DH: Self = Self(ffi::NID_id_GostR3410_94DH);
    pub const ID_GOST28147_89_CRYPTOPRO_KEYMESHING: Self =
        Self(ffi::NID_id_Gost28147_89_CryptoPro_KeyMeshing);
    pub const ID_GOST28147_89_NONE_KEYMESHING: Self =
        Self(ffi::NID_id_Gost28147_89_None_KeyMeshing);
    pub const ID_GOSTR3411_94_TESTPARAMSET: Self = Self(ffi::NID_id_GostR3411_94_TestParamSet);
    pub const ID_GOSTR3411_94_CRYPTOPROPARAMSET: Self =
        Self(ffi::NID_id_GostR3411_94_CryptoProParamSet);
    pub const ID_GOST28147_89_TESTPARAMSET: Self = Self(ffi::NID_id_Gost28147_89_TestParamSet);
    pub const ID_GOST28147_89_CRYPTOPRO_A_PARAMSET: Self =
        Self(ffi::NID_id_Gost28147_89_CryptoPro_A_ParamSet);
    pub const ID_GOST28147_89_CRYPTOPRO_B_PARAMSET: Self =
        Self(ffi::NID_id_Gost28147_89_CryptoPro_B_ParamSet);
    pub const ID_GOST28147_89_CRYPTOPRO_C_PARAMSET: Self =
        Self(ffi::NID_id_Gost28147_89_CryptoPro_C_ParamSet);
    pub const ID_GOST28147_89_CRYPTOPRO_D_PARAMSET: Self =
        Self(ffi::NID_id_Gost28147_89_CryptoPro_D_ParamSet);
    pub const ID_GOST28147_89_CRYPTOPRO_OSCAR_1_1_PARAMSET: Self =
        Self(ffi::NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet);
    pub const ID_GOST28147_89_CRYPTOPRO_OSCAR_1_0_PARAMSET: Self =
        Self(ffi::NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet);
    pub const ID_GOST28147_89_CRYPTOPRO_RIC_1_PARAMSET: Self =
        Self(ffi::NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet);
    pub const ID_GOSTR3410_94_TESTPARAMSET: Self = Self(ffi::NID_id_GostR3410_94_TestParamSet);
    pub const ID_GOSTR3410_94_CRYPTOPRO_A_PARAMSET: Self =
        Self(ffi::NID_id_GostR3410_94_CryptoPro_A_ParamSet);
    pub const ID_GOSTR3410_94_CRYPTOPRO_B_PARAMSET: Self =
        Self(ffi::NID_id_GostR3410_94_CryptoPro_B_ParamSet);
    pub const ID_GOSTR3410_94_CRYPTOPRO_C_PARAMSET: Self =
        Self(ffi::NID_id_GostR3410_94_CryptoPro_C_ParamSet);
    pub const ID_GOSTR3410_94_CRYPTOPRO_D_PARAMSET: Self =
        Self(ffi::NID_id_GostR3410_94_CryptoPro_D_ParamSet);
    pub const ID_GOSTR3410_94_CRYPTOPRO_XCHA_PARAMSET: Self =
        Self(ffi::NID_id_GostR3410_94_CryptoPro_XchA_ParamSet);
    pub const ID_GOSTR3410_94_CRYPTOPRO_XCHB_PARAMSET: Self =
        Self(ffi::NID_id_GostR3410_94_CryptoPro_XchB_ParamSet);
    pub const ID_GOSTR3410_94_CRYPTOPRO_XCHC_PARAMSET: Self =
        Self(ffi::NID_id_GostR3410_94_CryptoPro_XchC_ParamSet);
    pub const ID_GOSTR3410_2001_TESTPARAMSET: Self = Self(ffi::NID_id_GostR3410_2001_TestParamSet);
    pub const ID_GOSTR3410_2001_CRYPTOPRO_A_PARAMSET: Self =
        Self(ffi::NID_id_GostR3410_2001_CryptoPro_A_ParamSet);
    pub const ID_GOSTR3410_2001_CRYPTOPRO_B_PARAMSET: Self =
        Self(ffi::NID_id_GostR3410_2001_CryptoPro_B_ParamSet);
    pub const ID_GOSTR3410_2001_CRYPTOPRO_C_PARAMSET: Self =
        Self(ffi::NID_id_GostR3410_2001_CryptoPro_C_ParamSet);
    pub const ID_GOSTR3410_2001_CRYPTOPRO_XCHA_PARAMSET: Self =
        Self(ffi::NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet);
    pub const ID_GOSTR3410_2001_CRYPTOPRO_XCHB_PARAMSET: Self =
        Self(ffi::NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet);
    pub const ID_GOSTR3410_94_A: Self = Self(ffi::NID_id_GostR3410_94_a);
    pub const ID_GOSTR3410_94_ABIS: Self = Self(ffi::NID_id_GostR3410_94_aBis);
    pub const ID_GOSTR3410_94_B: Self = Self(ffi::NID_id_GostR3410_94_b);
    pub const ID_GOSTR3410_94_BBIS: Self = Self(ffi::NID_id_GostR3410_94_bBis);
    pub const ID_GOST28147_89_CC: Self = Self(ffi::NID_id_Gost28147_89_cc);
    pub const ID_GOSTR3410_94_CC: Self = Self(ffi::NID_id_GostR3410_94_cc);
    pub const ID_GOSTR3410_2001_CC: Self = Self(ffi::NID_id_GostR3410_2001_cc);
    pub const ID_GOSTR3411_94_WITH_GOSTR3410_94_CC: Self =
        Self(ffi::NID_id_GostR3411_94_with_GostR3410_94_cc);
    pub const ID_GOSTR3411_94_WITH_GOSTR3410_2001_CC: Self =
        Self(ffi::NID_id_GostR3411_94_with_GostR3410_2001_cc);
    pub const ID_GOSTR3410_2001_PARAMSET_CC: Self = Self(ffi::NID_id_GostR3410_2001_ParamSet_cc);
    pub const CAMELLIA_128_CBC: Self = Self(ffi::NID_camellia_128_cbc);
    pub const CAMELLIA_192_CBC: Self = Self(ffi::NID_camellia_192_cbc);
    pub const CAMELLIA_256_CBC: Self = Self(ffi::NID_camellia_256_cbc);
    pub const ID_CAMELLIA128_WRAP: Self = Self(ffi::NID_id_camellia128_wrap);
    pub const ID_CAMELLIA192_WRAP: Self = Self(ffi::NID_id_camellia192_wrap);
    pub const ID_CAMELLIA256_WRAP: Self = Self(ffi::NID_id_camellia256_wrap);
    pub const CAMELLIA_128_ECB: Self = Self(ffi::NID_camellia_128_ecb);
    pub const CAMELLIA_128_OFB128: Self = Self(ffi::NID_camellia_128_ofb128);
    pub const CAMELLIA_128_CFB128: Self = Self(ffi::NID_camellia_128_cfb128);
    pub const CAMELLIA_192_ECB: Self = Self(ffi::NID_camellia_192_ecb);
    pub const CAMELLIA_192_OFB128: Self = Self(ffi::NID_camellia_192_ofb128);
    pub const CAMELLIA_192_CFB128: Self = Self(ffi::NID_camellia_192_cfb128);
    pub const CAMELLIA_256_ECB: Self = Self(ffi::NID_camellia_256_ecb);
    pub const CAMELLIA_256_OFB128: Self = Self(ffi::NID_camellia_256_ofb128);
    pub const CAMELLIA_256_CFB128: Self = Self(ffi::NID_camellia_256_cfb128);
    pub const CAMELLIA_128_CFB1: Self = Self(ffi::NID_camellia_128_cfb1);
    pub const CAMELLIA_192_CFB1: Self = Self(ffi::NID_camellia_192_cfb1);
    pub const CAMELLIA_256_CFB1: Self = Self(ffi::NID_camellia_256_cfb1);
    pub const CAMELLIA_128_CFB8: Self = Self(ffi::NID_camellia_128_cfb8);
    pub const CAMELLIA_192_CFB8: Self = Self(ffi::NID_camellia_192_cfb8);
    pub const CAMELLIA_256_CFB8: Self = Self(ffi::NID_camellia_256_cfb8);
    pub const KISA: Self = Self(ffi::NID_kisa);
    pub const SEED_ECB: Self = Self(ffi::NID_seed_ecb);
    pub const SEED_CBC: Self = Self(ffi::NID_seed_cbc);
    pub const SEED_CFB128: Self = Self(ffi::NID_seed_cfb128);
    pub const SEED_OFB128: Self = Self(ffi::NID_seed_ofb128);
    pub const HMAC: Self = Self(ffi::NID_hmac);
    pub const CMAC: Self = Self(ffi::NID_cmac);
    pub const RC4_HMAC_MD5: Self = Self(ffi::NID_rc4_hmac_md5);
    pub const AES_128_CBC_HMAC_SHA1: Self = Self(ffi::NID_aes_128_cbc_hmac_sha1);
    pub const AES_192_CBC_HMAC_SHA1: Self = Self(ffi::NID_aes_192_cbc_hmac_sha1);
    pub const AES_256_CBC_HMAC_SHA1: Self = Self(ffi::NID_aes_256_cbc_hmac_sha1);
    pub const AUTH_RSA: Self = Self(ffi::NID_auth_rsa);
    pub const AUTH_ECDSA: Self = Self(ffi::NID_auth_ecdsa);
    pub const AUTH_PSK: Self = Self(ffi::NID_auth_psk);
    pub const AUTH_ANY: Self = Self(ffi::NID_auth_any);
    pub const KX_RSA: Self = Self(ffi::NID_kx_rsa);
    pub const KX_ECDHE: Self = Self(ffi::NID_kx_ecdhe);
    pub const KX_PSK: Self = Self(ffi::NID_kx_psk);
    pub const KX_ANY: Self = Self(ffi::NID_kx_any);
    pub const BRAINPOOL_P256R1: Self = Self(ffi::NID_brainpoolP256r1);
    pub const BRAINPOOL_P256T1: Self = Self(ffi::NID_brainpoolP256t1);
    pub const BRAINPOOL_P320R1: Self = Self(ffi::NID_brainpoolP320r1);
    pub const BRAINPOOL_P320T1: Self = Self(ffi::NID_brainpoolP320t1);
    pub const BRAINPOOL_P384R1: Self = Self(ffi::NID_brainpoolP384r1);
    pub const BRAINPOOL_P384T1: Self = Self(ffi::NID_brainpoolP384t1);
    pub const BRAINPOOL_P512R1: Self = Self(ffi::NID_brainpoolP512r1);
    pub const BRAINPOOL_P512T1: Self = Self(ffi::NID_brainpoolP512t1);
    pub const CHACHA20_POLY1305: Self = Self(ffi::NID_chacha20_poly1305);
}

#[cfg(test)]
mod test {
    use super::Nid;

    #[test]
    fn signature_digest() {
        let algs = Nid::SHA256WITHRSAENCRYPTION.signature_algorithms().unwrap();
        assert_eq!(algs.digest, Nid::SHA256);
        assert_eq!(algs.pkey, Nid::RSAENCRYPTION);
    }

    #[test]
    fn test_long_name_conversion() {
        let common_name = Nid::COMMONNAME;
        let organizational_unit_name = Nid::ORGANIZATIONALUNITNAME;
        let aes256_cbc_hmac_sha1 = Nid::AES_256_CBC_HMAC_SHA1;
        let id_cmc_lrapopwitness = Nid::ID_CMC_LRAPOPWITNESS;
        let ms_ctl_sign = Nid::MS_CTL_SIGN;
        let undefined_nid = Nid::from_raw(118);

        assert_eq!(common_name.long_name().unwrap(), "commonName");
        assert_eq!(
            organizational_unit_name.long_name().unwrap(),
            "organizationalUnitName"
        );
        assert_eq!(
            aes256_cbc_hmac_sha1.long_name().unwrap(),
            "aes-256-cbc-hmac-sha1"
        );
        assert_eq!(
            id_cmc_lrapopwitness.long_name().unwrap(),
            "id-cmc-lraPOPWitness"
        );
        assert_eq!(
            ms_ctl_sign.long_name().unwrap(),
            "Microsoft Trust List Signing"
        );
        assert!(
            undefined_nid.long_name().is_err(),
            "undefined_nid should not return a valid value"
        );
    }

    #[test]
    fn test_short_name_conversion() {
        let common_name = Nid::COMMONNAME;
        let organizational_unit_name = Nid::ORGANIZATIONALUNITNAME;
        let aes256_cbc_hmac_sha1 = Nid::AES_256_CBC_HMAC_SHA1;
        let id_cmc_lrapopwitness = Nid::ID_CMC_LRAPOPWITNESS;
        let ms_ctl_sign = Nid::MS_CTL_SIGN;
        let undefined_nid = Nid::from_raw(118);

        assert_eq!(common_name.short_name().unwrap(), "CN");
        assert_eq!(organizational_unit_name.short_name().unwrap(), "OU");
        assert_eq!(
            aes256_cbc_hmac_sha1.short_name().unwrap(),
            "AES-256-CBC-HMAC-SHA1"
        );
        assert_eq!(
            id_cmc_lrapopwitness.short_name().unwrap(),
            "id-cmc-lraPOPWitness"
        );
        assert_eq!(ms_ctl_sign.short_name().unwrap(), "msCTLSign");
        assert!(
            undefined_nid.short_name().is_err(),
            "undefined_nid should not return a valid value"
        );
    }
}
