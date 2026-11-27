//! Digital Signatures
//!
//! DSA ensures a message originated from a known sender, and was not modified.
//! DSA uses asymetrical keys and an algorithm to output a signature of the message
//! using the private key that can be validated with the public key but not be generated
//! without the private key.

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::fmt;
use std::mem;
use std::ptr;

use crate::bn::{BigNum, BigNumContext, BigNumContextRef, BigNumRef};
use crate::error::ErrorStack;
use crate::ffi;
use crate::pkey::{HasParams, HasPrivate, HasPublic, Params, Private, Public};
use crate::util::SecretBytes;
use crate::{cvt, cvt_nz, cvt_p};

generic_foreign_type_and_impl_send_sync! {
    type CType = ffi::DSA;
    fn drop = ffi::DSA_free;

    /// Object representing DSA keys.
    ///
    /// A DSA object contains the parameters p, q, and g.  There is a private
    /// and public key.  The values p, g, and q are:
    ///
    /// * `p`: DSA prime parameter
    /// * `q`: DSA sub-prime parameter
    /// * `g`: DSA base parameter
    ///
    /// These values are used to calculate a pair of asymetrical keys used for
    /// signing.
    ///
    /// OpenSSL documentation at [`DSA_new`]
    ///
    /// [`DSA_new`]: https://www.openssl.org/docs/man1.1.0/crypto/DSA_new.html
    ///
    /// # Examples
    ///
    /// ```
    /// use btls::dsa::Dsa;
    /// use btls::error::ErrorStack;
    /// use btls::pkey::Private;
    ///
    /// fn create_dsa() -> Result<Dsa<Private>, ErrorStack> {
    ///     let sign = Dsa::generate(2048)?;
    ///     Ok(sign)
    /// }
    /// # fn main() {
    /// #    create_dsa().unwrap();
    /// # }
    /// ```
    pub struct Dsa<T>;
    /// Reference to [`Dsa`].
    ///
    /// [`Dsa`]: struct.Dsa.html
    pub struct DsaRef<T>;
}

impl<T> Clone for Dsa<T> {
    fn clone(&self) -> Self {
        (**self).to_owned()
    }
}

impl<T> ToOwned for DsaRef<T> {
    type Owned = Dsa<T>;

    fn to_owned(&self) -> Dsa<T> {
        // SAFETY: the live native key supports atomic reference counting and
        // this creates a new owned reference without modifying its key components.
        unsafe {
            ffi::DSA_up_ref(self.as_ptr());
            Dsa::from_ptr(self.as_ptr())
        }
    }
}

impl<T> DsaRef<T>
where
    T: HasPublic,
{
    to_pem! {
        /// Serialies the public key into a PEM-encoded SubjectPublicKeyInfo structure.
        ///
        /// The output will have a header of `-----BEGIN PUBLIC KEY-----`.
        #[corresponds(PEM_write_bio_DSA_PUBKEY)]
        public_key_to_pem,
        ffi::PEM_write_bio_DSA_PUBKEY
    }

    to_der! {
        /// Serializes the public key into a DER-encoded SubjectPublicKeyInfo structure.
        #[corresponds(i2d_DSA_PUBKEY)]
        public_key_to_der,
        ffi::i2d_DSA_PUBKEY
    }

    /// Checks the prime-order group and public key subgroup membership.
    /// Use after parsing an externally supplied key, since native parsers only check bounds.
    ///
    /// # Errors
    /// Invalid group or public key, allocation, or native computation failure.
    pub fn check_public_key(&self) -> Result<(), ErrorStack> {
        let mut ctx = BigNumContext::new()?;
        validate_public_components(self.p(), self.q(), self.g(), self.pub_key(), &mut ctx)
    }

    /// Returns a reference to the public key component of `self`.
    #[must_use = "The returned key component is the result of this accessor."]
    #[corresponds(DSA_get0_pub_key)]
    pub fn pub_key(&self) -> &BigNumRef {
        // SAFETY: the public-key capability guarantees the component is
        // present, and the native key retains it for the shared borrow.
        unsafe { BigNumRef::from_ptr(ffi::DSA_get0_pub_key(self.as_ptr()).cast_mut()) }
    }
}

impl<T> DsaRef<T>
where
    T: HasPrivate,
{
    private_key_to_pem! {
        /// Serializes the private key to a PEM-encoded DSAPrivateKey structure.
        ///
        /// The output will have a header of `-----BEGIN DSA PRIVATE KEY-----`.
        #[corresponds(PEM_write_bio_DSAPrivateKey)]
        private_key_to_pem,
        /// Serializes the private key to a PEM-encoded encrypted DSAPrivateKey structure.
        ///
        /// The output will have a header of `-----BEGIN DSA PRIVATE KEY-----`.
        #[corresponds(PEM_write_bio_DSAPrivateKey)]
        private_key_to_pem_passphrase,
        ffi::PEM_write_bio_DSAPrivateKey
    }

    /// Checks the prime-order group, subgroup membership and private/public key consistency.
    ///
    /// # Errors
    /// Invalid or inconsistent key components, allocation, or native computation failure.
    pub fn check_private_key(&self) -> Result<(), ErrorStack> {
        let mut ctx = BigNumContext::new()?;
        validate_public_components(self.p(), self.q(), self.g(), self.pub_key(), &mut ctx)?;
        validated_private_scalar(
            self.p(),
            self.q(),
            self.g(),
            self.priv_key(),
            self.pub_key(),
            &mut ctx,
        )?;
        Ok(())
    }

    /// Returns a reference to the private key component of `self`.
    #[must_use = "The returned key component is the result of this accessor."]
    #[corresponds(DSA_get0_priv_key)]
    pub fn priv_key(&self) -> &BigNumRef {
        // SAFETY: the private-key capability guarantees the component is
        // present, and the native key retains it for the shared borrow.
        unsafe { BigNumRef::from_ptr(ffi::DSA_get0_priv_key(self.as_ptr()).cast_mut()) }
    }
}

impl<T> DsaRef<T>
where
    T: HasParams,
{
    /// Maximum encoded signature length in bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the native key cannot determine its signature length.
    #[corresponds(DSA_size)]
    pub fn signature_capacity(&self) -> Result<usize, ErrorStack> {
        // SAFETY: the parameter capability guarantees the native key has its
        // group parameters, including the subgroup order used for sizing.
        let size = unsafe { ffi::DSA_size(self.as_ptr()) };
        cvt_nz(size).map(core::num::NonZeroUsize::get)
    }

    /// Returns the DSA prime parameter of `self`.
    #[must_use = "The returned key component is the result of this accessor."]
    #[corresponds(DSA_get0_p)]
    pub fn p(&self) -> &BigNumRef {
        // SAFETY: the parameter capability guarantees the component is
        // present, and the native key retains it for the shared borrow.
        unsafe { BigNumRef::from_ptr(ffi::DSA_get0_p(self.as_ptr()).cast_mut()) }
    }

    /// Returns the DSA sub-prime parameter of `self`.
    #[must_use = "The returned key component is the result of this accessor."]
    #[corresponds(DSA_get0_q)]
    pub fn q(&self) -> &BigNumRef {
        // SAFETY: the parameter capability guarantees the component is
        // present, and the native key retains it for the shared borrow.
        unsafe { BigNumRef::from_ptr(ffi::DSA_get0_q(self.as_ptr()).cast_mut()) }
    }

    /// Returns the DSA base parameter of `self`.
    #[must_use = "The returned key component is the result of this accessor."]
    #[corresponds(DSA_get0_g)]
    pub fn g(&self) -> &BigNumRef {
        // SAFETY: the parameter capability guarantees the component is
        // present, and the native key retains it for the shared borrow.
        unsafe { BigNumRef::from_ptr(ffi::DSA_get0_g(self.as_ptr()).cast_mut()) }
    }
}

// Native DSA parsing only checks bounds. Validate group order and primality
// before admitting caller-supplied components as a cryptographic key.
fn validate_public_components(
    p: &BigNumRef,
    q: &BigNumRef,
    g: &BigNumRef,
    public: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Result<(), ErrorStack> {
    let one = BigNum::from_u32(1)?;
    if p.is_negative()
        || p.is_even()
        || p.num_bits() > ffi::OPENSSL_DSA_MAX_MODULUS_BITS.cast_unsigned()
        || q.is_negative()
        || q.is_even()
        || !matches!(q.num_bits(), 160 | 224 | 256)
        || q >= p
        || g <= &*one
        || g >= p
        || public <= &*one
        || public >= p
    {
        return Err(ErrorStack::internal_error_str(
            "invalid DSA component bounds",
        ));
    }
    let mut scratch = BigNum::new()?;
    scratch.nnmod(p, q, ctx)?;
    if scratch != one
        || !q.is_prime(ffi::BN_prime_checks_for_validation, ctx, true)?
        || !p.is_prime(ffi::BN_prime_checks_for_validation, ctx, true)?
    {
        return Err(ErrorStack::internal_error_str("invalid DSA prime subgroup"));
    }
    for element in [g, public] {
        scratch.mod_exp(element, q, p, ctx)?;
        if scratch != one {
            return Err(ErrorStack::internal_error_str(
                "DSA element outside prime-order subgroup",
            ));
        }
    }
    Ok(())
}

// Native constant-time exponentiation uses the stored word width, so import
// the private scalar at the public subgroup width, including leading zeroes.
fn validated_private_scalar(
    p: &BigNumRef,
    q: &BigNumRef,
    g: &BigNumRef,
    private: &BigNumRef,
    public: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Result<BigNum, ErrorStack> {
    if private.is_negative() || private.num_bits() == 0 || private >= q {
        return Err(ErrorStack::internal_error_str("invalid DSA private scalar"));
    }
    let mut bytes = SecretBytes::zeroed(q.num_bytes())?;
    // SAFETY: the scalar is borrowed; the writable buffer has the exact
    // public subgroup length. Native serialization writes within this range.
    unsafe {
        cvt(ffi::BN_bn2bin_padded(
            bytes.as_mut_ptr(),
            bytes.len(),
            private.as_ptr(),
        ))?;
    }
    let private = BigNum::from_slice(&bytes)?;
    let result = BigNum::new()?;
    // SAFETY: group validation established an odd positive modulus and a
    // reduced base. Native exponentiation uses the padded scalar width.
    unsafe {
        cvt(ffi::BN_mod_exp_mont_consttime(
            result.as_ptr(),
            g.as_ptr(),
            private.as_ptr(),
            p.as_ptr(),
            ctx.as_ptr(),
            ptr::null(),
        ))?;
    }
    if &*result != public {
        return Err(ErrorStack::internal_error_str("inconsistent DSA key pair"));
    }
    Ok(private)
}

impl Dsa<Params> {
    fn from_parameters(p: BigNum, q: BigNum, g: BigNum) -> Result<Self, ErrorStack> {
        ffi::init();
        // SAFETY: the new parameter object owns its allocation before the
        // setter runs. Native takes the three non-null values only on success.
        unsafe {
            let dsa = Self::from_ptr(cvt_p(ffi::DSA_new())?);
            cvt(ffi::DSA_set0_pqg(
                dsa.as_ptr(),
                p.as_ptr(),
                q.as_ptr(),
                g.as_ptr(),
            ))?;
            mem::forget((p, q, g));
            Ok(dsa)
        }
    }

    fn install_key(&mut self, public: BigNum, private: Option<BigNum>) -> Result<(), ErrorStack> {
        let private_ptr = private
            .as_ref()
            .map_or(ptr::null_mut(), ForeignType::as_ptr);
        // SAFETY: the parameter key is exclusively owned during construction;
        // native accepts a non-null public component and optional private one,
        // transferring them only on success.
        unsafe {
            cvt(ffi::DSA_set0_key(
                self.as_ptr(),
                public.as_ptr(),
                private_ptr,
            ))?;
        };
        mem::forget((public, private));
        Ok(())
    }
}

impl Dsa<Private> {
    /// Generate a DSA key pair.
    ///
    /// Calls [`DSA_generate_parameters_ex`] to populate the `p`, `g`, and `q` values.
    /// These values are used to generate the key pair with [`DSA_generate_key`].
    ///
    /// The `bits` parameter corresponds to the length of the prime `p`.
    ///
    /// [`DSA_generate_parameters_ex`]: https://www.openssl.org/docs/man1.1.0/crypto/DSA_generate_parameters_ex.html
    /// [`DSA_generate_key`]: https://www.openssl.org/docs/man1.1.0/crypto/DSA_generate_key.html
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported bit count or native generation failure.
    pub fn generate(bits: u32) -> Result<Self, ErrorStack> {
        ffi::init();
        // SAFETY: the fresh native object is owned from allocation onward.
        // Null seed, optional outputs and callback request native generation.
        // Private capability is published only after both native calls succeed.
        unsafe {
            let dsa = Dsa::<Params>::from_ptr(cvt_p(ffi::DSA_new())?);
            cvt(ffi::DSA_generate_parameters_ex(
                dsa.as_ptr(),
                bits,
                ptr::null(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            ))?;
            cvt(ffi::DSA_generate_key(dsa.as_ptr()))?;
            Ok(Self::from_ptr(dsa.into_ptr()))
        }
    }

    /// Create a DSA key pair with the given parameters
    ///
    /// `p`, `q` and `g` are the common parameters.
    /// `priv_key` is the private component of the key pair.
    /// `pub_key` is the public component of the key. Can be computed via `g^(priv_key) mod p`
    ///
    /// Validates the prime-order group, subgroup membership and key consistency.
    ///
    /// # Errors
    ///
    /// Invalid group or key components, allocation, or native computation failure.
    pub fn from_private_components(
        p: BigNum,
        q: BigNum,
        g: BigNum,
        priv_key: BigNum,
        pub_key: BigNum,
    ) -> Result<Self, ErrorStack> {
        let mut ctx = BigNumContext::new()?;
        validate_public_components(&p, &q, &g, &pub_key, &mut ctx)?;
        let priv_key = validated_private_scalar(&p, &q, &g, &priv_key, &pub_key, &mut ctx)?;
        let mut dsa = Dsa::<Params>::from_parameters(p, q, g)?;
        dsa.install_key(pub_key, Some(priv_key))?;
        // SAFETY: successful installation establishes both key components.
        Ok(unsafe { Self::from_ptr(dsa.into_ptr()) })
    }
}

impl Dsa<Public> {
    from_pem! {
        /// Decodes a PEM-encoded SubjectPublicKeyInfo structure containing a DSA key.
        ///
        /// The input should have a header of `-----BEGIN PUBLIC KEY-----`.
        /// Use [`DsaRef::check_public_key`] to establish domain parameter validity.
        #[corresponds(PEM_read_bio_DSA_PUBKEY)]
        public_key_from_pem,
        Dsa<Public>,
        ffi::PEM_read_bio_DSA_PUBKEY
    }

    from_der! {
        /// Decodes a DER-encoded SubjectPublicKeyInfo structure containing a DSA key.
        /// Use [`DsaRef::check_public_key`] to establish domain parameter validity.
        #[corresponds(d2i_DSA_PUBKEY)]
        public_key_from_der,
        Dsa<Public>,
        ffi::d2i_DSA_PUBKEY,
        ::libc::c_long
    }

    /// Create a new DSA key with only public components.
    ///
    /// `p`, `q` and `g` are the common parameters.
    /// `pub_key` is the public component of the key.
    ///
    /// Validates the prime-order group and public key subgroup membership.
    ///
    /// # Errors
    ///
    /// Invalid group or public key components, allocation, or native computation failure.
    pub fn from_public_components(
        p: BigNum,
        q: BigNum,
        g: BigNum,
        pub_key: BigNum,
    ) -> Result<Self, ErrorStack> {
        let mut ctx = BigNumContext::new()?;
        validate_public_components(&p, &q, &g, &pub_key, &mut ctx)?;
        let mut dsa = Dsa::<Params>::from_parameters(p, q, g)?;
        dsa.install_key(pub_key, None)?;
        // SAFETY: successful installation establishes the public component.
        Ok(unsafe { Self::from_ptr(dsa.into_ptr()) })
    }
}

impl<T> fmt::Debug for Dsa<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DSA")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_generate() {
        Dsa::generate(1024).unwrap();
    }

    #[test]
    fn test_pubkey_generation() {
        let dsa = Dsa::generate(1024).unwrap();
        let p = dsa.p();
        let g = dsa.g();
        let priv_key = dsa.priv_key();
        let pub_key = dsa.pub_key();
        let mut ctx = BigNumContext::new().unwrap();
        let validated =
            validated_private_scalar(p, dsa.q(), g, priv_key, pub_key, &mut ctx).unwrap();
        assert_eq!(&validated, priv_key);
    }

    #[test]
    fn validates_component_keys() {
        let key = Dsa::generate(1024).unwrap();
        let components = || {
            (
                key.p().to_owned().unwrap(),
                key.q().to_owned().unwrap(),
                key.g().to_owned().unwrap(),
            )
        };
        let (p, q, g) = components();
        let reconstructed = Dsa::from_private_components(
            p,
            q,
            g,
            key.priv_key().to_owned().unwrap(),
            key.pub_key().to_owned().unwrap(),
        )
        .unwrap();
        assert_eq!(reconstructed.priv_key(), key.priv_key());
        assert_eq!(reconstructed.pub_key(), key.pub_key());
        reconstructed.check_private_key().unwrap();
        let (p, q, g) = components();
        // A small scalar must be accepted and padded to the public subgroup width.
        let scalar_one = Dsa::from_private_components(
            p,
            q,
            g,
            BigNum::from_u32(1).unwrap(),
            key.g().to_owned().unwrap(),
        )
        .unwrap();
        assert_eq!(scalar_one.pub_key(), key.g());
        let (p, q, g) = components();
        let public =
            Dsa::from_public_components(p, q, g, key.pub_key().to_owned().unwrap()).unwrap();
        assert_eq!(public.pub_key(), key.pub_key());
        public.check_public_key().unwrap();
        let (p, q, g) = components();
        assert!(
            Dsa::from_private_components(
                p,
                q,
                g,
                BigNum::from_u32(0).unwrap(),
                key.pub_key().to_owned().unwrap()
            )
            .is_err()
        );
        let (p, q, g) = components();
        assert!(
            Dsa::from_private_components(
                p,
                q,
                g,
                key.q().to_owned().unwrap(),
                key.pub_key().to_owned().unwrap()
            )
            .is_err()
        );
        let (p, q, g) = components();
        // Both candidate public values are valid subgroup elements, but they
        // correspond to different private scalars.
        let wrong_public = if key.pub_key() == key.g() {
            let mut square = BigNum::new().unwrap();
            square
                .mod_exp(
                    key.g(),
                    &BigNum::from_u32(2).unwrap(),
                    key.p(),
                    &mut BigNumContext::new().unwrap(),
                )
                .unwrap();
            square
        } else {
            key.g().to_owned().unwrap()
        };
        assert!(
            Dsa::from_private_components(p, q, g, key.priv_key().to_owned().unwrap(), wrong_public)
                .is_err()
        );
        let (p, q, g) = components();
        assert!(Dsa::from_public_components(p, q, g, BigNum::from_u32(1).unwrap()).is_err());
        let (p, q, _) = components();
        assert!(
            Dsa::from_public_components(
                p,
                q,
                BigNum::from_u32(1).unwrap(),
                key.pub_key().to_owned().unwrap()
            )
            .is_err()
        );
        let (p, q, g) = components();
        let mut outside_subgroup = p.to_owned().unwrap();
        outside_subgroup.sub_word(1).unwrap();
        assert!(Dsa::from_public_components(p, q, g, outside_subgroup).is_err());
        let (p, _, g) = components();
        assert!(
            Dsa::from_public_components(
                p,
                BigNum::from_u32(47).unwrap(),
                g,
                key.pub_key().to_owned().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn clone() {
        let key = Dsa::generate(2048).unwrap();
        let shared = key.clone();
        assert_eq!(key.pub_key().to_vec(), shared.pub_key().to_vec());
        drop(key);
        assert!(!shared.pub_key().to_vec().is_empty());
    }
}
