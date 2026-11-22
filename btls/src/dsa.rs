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

use crate::bn::{BigNum, BigNumRef};
use crate::error::ErrorStack;
use crate::ffi;
use crate::pkey::{HasParams, HasPrivate, HasPublic, Params, Private, Public};
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
            ))?
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
    /// Components are installed without validating the group or key consistency.
    ///
    /// # Errors
    ///
    /// Returns an error if allocation or component installation fails.
    pub fn from_private_components(
        p: BigNum,
        q: BigNum,
        g: BigNum,
        priv_key: BigNum,
        pub_key: BigNum,
    ) -> Result<Self, ErrorStack> {
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
        #[corresponds(PEM_read_bio_DSA_PUBKEY)]
        public_key_from_pem,
        Dsa<Public>,
        ffi::PEM_read_bio_DSA_PUBKEY
    }

    from_der! {
        /// Decodes a DER-encoded SubjectPublicKeyInfo structure containing a DSA key.
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
    /// Components are installed without validating the group or key consistency.
    ///
    /// # Errors
    ///
    /// Returns an error if allocation or component installation fails.
    pub fn from_public_components(
        p: BigNum,
        q: BigNum,
        g: BigNum,
        pub_key: BigNum,
    ) -> Result<Self, ErrorStack> {
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
    use crate::bn::BigNumContext;

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
        let mut calc = BigNum::new().unwrap();
        calc.mod_exp(g, priv_key, p, &mut ctx).unwrap();
        assert_eq!(&calc, pub_key);
    }

    #[test]
    fn test_priv_key_from_parts() {
        let p = BigNum::from_u32(283).unwrap();
        let q = BigNum::from_u32(47).unwrap();
        let g = BigNum::from_u32(60).unwrap();
        let priv_key = BigNum::from_u32(15).unwrap();
        let pub_key = BigNum::from_u32(207).unwrap();

        let dsa = Dsa::from_private_components(p, q, g, priv_key, pub_key).unwrap();
        assert_eq!(dsa.pub_key(), &BigNum::from_u32(207).unwrap());
        assert_eq!(dsa.priv_key(), &BigNum::from_u32(15).unwrap());
        assert_eq!(dsa.p(), &BigNum::from_u32(283).unwrap());
        assert_eq!(dsa.q(), &BigNum::from_u32(47).unwrap());
        assert_eq!(dsa.g(), &BigNum::from_u32(60).unwrap());
    }

    #[test]
    fn test_pub_key_from_parts() {
        let p = BigNum::from_u32(283).unwrap();
        let q = BigNum::from_u32(47).unwrap();
        let g = BigNum::from_u32(60).unwrap();
        let pub_key = BigNum::from_u32(207).unwrap();

        let dsa = Dsa::from_public_components(p, q, g, pub_key).unwrap();
        assert_eq!(dsa.pub_key(), &BigNum::from_u32(207).unwrap());
        assert_eq!(dsa.p(), &BigNum::from_u32(283).unwrap());
        assert_eq!(dsa.q(), &BigNum::from_u32(47).unwrap());
        assert_eq!(dsa.g(), &BigNum::from_u32(60).unwrap());
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
