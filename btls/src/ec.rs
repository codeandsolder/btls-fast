//! Elliptic-curve groups, points, and keys backed by `BoringSSL`.
//!
//! Named prime-field curves are preferred. Scalar multiplication accepts
//! caller-owned scratch storage when reduction of large scalars requires it.
//! The native group and point operations validate curve compatibility.

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::fmt;
use std::ptr;

use crate::bn::{BigNumContextRef, BigNumRef};
use crate::error::ErrorStack;
use crate::ffi;
use crate::nid::Nid;
use crate::pkey::{HasParams, HasPrivate, HasPublic, Params, Private, Public};
use crate::try_int;
use crate::{cvt, cvt_n, cvt_p, init};

/// Supported X9.62 point encoding formats.
#[derive(Copy, Clone)]
pub struct PointConversionForm(ffi::point_conversion_form_t);

impl PointConversionForm {
    /// X coordinate and parity of the Y coordinate.
    pub const COMPRESSED: Self = Self(ffi::point_conversion_form_t::POINT_CONVERSION_COMPRESSED);

    /// Full X and Y coordinates.
    pub const UNCOMPRESSED: Self =
        Self(ffi::point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED);
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::EC_GROUP;
    fn drop = ffi::EC_GROUP_free;

    /// An immutable prime-field elliptic-curve group.
    ///
    /// Use a supported named curve selected by its native identifier.
    pub struct EcGroup;
}

impl EcGroup {
    /// Returns the group of a supported named curve.
    ///
    /// # Errors
    ///
    /// The curve identifier is unsupported or native allocation fails.
    #[corresponds(EC_GROUP_new_by_curve_name)]
    pub fn from_curve_name(nid: Nid) -> Result<Self, ErrorStack> {
        // SAFETY: The native lookup allocates or returns a static group reference;
        // successful results have a matching EC_GROUP_free.
        unsafe {
            init();
            cvt_p(ffi::EC_GROUP_new_by_curve_name(nid.as_raw())).map(|p| Self::from_ptr(p))
        }
    }
}

impl EcGroupRef {
    /// Writes requested prime-field parameters of the curve.
    /// The equation is `y² = x³ + ax + b (mod p)`.
    /// Pass no output for a parameter that is not needed.
    ///
    /// OpenSSL documentation available at [`EC_GROUP_get_curve_GFp`]
    ///
    /// [`EC_GROUP_get_curve_GFp`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_get_curve_GFp.html
    ///
    /// # Errors
    ///
    /// Native parameter extraction or output allocation fails.
    pub fn components_gfp(
        &self,
        p: Option<&mut BigNumRef>,
        a: Option<&mut BigNumRef>,
        b: Option<&mut BigNumRef>,
    ) -> Result<(), ErrorStack> {
        // SAFETY: The group remains immutably borrowed and requested non-null outputs
        // are separately exclusive. Native supports null outputs.
        unsafe {
            cvt(ffi::EC_GROUP_get_curve_GFp(
                self.as_ptr(),
                p.map_or(ptr::null_mut(), |output| output.as_ptr()),
                a.map_or(ptr::null_mut(), |output| output.as_ptr()),
                b.map_or(ptr::null_mut(), |output| output.as_ptr()),
                ptr::null_mut(),
            ))
        }
    }

    /// Places the cofactor of the group in the provided `BigNum`.
    ///
    /// # Errors
    ///
    /// Native output allocation fails.
    #[corresponds(EC_GROUP_get_cofactor)]
    pub fn cofactor(&self, cofactor: &mut BigNumRef) -> Result<(), ErrorStack> {
        // SAFETY: The group is live and the cofactor destination is exclusive; the
        // scratch argument is ignored.
        unsafe {
            cvt(ffi::EC_GROUP_get_cofactor(
                self.as_ptr(),
                cofactor.as_ptr(),
                ptr::null_mut(),
            ))
        }
    }

    /// Returns the degree of the curve.
    #[corresponds(EC_GROUP_get_degree)]
    #[must_use = "Use the returned cryptographic size or bit count to validate parameters."]
    pub fn degree(&self) -> u32 {
        // SAFETY: The degree getter reads the live immutable group.
        unsafe { ffi::EC_GROUP_get_degree(self.as_ptr()) }
    }

    /// Returns the number of bits in the group order, or zero if incomplete.
    #[must_use = "Use the returned cryptographic size or bit count to validate parameters."]
    pub fn order_bits(&self) -> u32 {
        self.order().map_or(0, BigNumRef::num_bits)
    }

    /// Borrows the generator, if the native group is complete.
    #[corresponds(EC_GROUP_get0_generator)]
    #[must_use = "Use the returned algorithm or parameter identity when selecting or reporting cryptographic settings."]
    pub fn generator(&self) -> Option<&EcPointRef> {
        // SAFETY: the group owns the optional borrowed native generator.
        unsafe { EcPointRef::from_const_ptr_opt(ffi::EC_GROUP_get0_generator(self.as_ptr())) }
    }

    /// Returns the group order, or no value for an incomplete native group.
    #[corresponds(EC_GROUP_get0_order)]
    #[must_use = "Use the borrowed group order for scalar bounds."]
    pub fn order(&self) -> Option<&BigNumRef> {
        self.generator()?;
        // SAFETY: a non-null generator establishes that the native group has
        // an order. The group owns both values throughout the shared borrow.
        unsafe { BigNumRef::from_const_ptr_opt(ffi::EC_GROUP_get0_order(self.as_ptr())) }
    }

    /// Returns the name of the curve, if a name is associated.
    #[corresponds(EC_GROUP_get_curve_name)]
    #[must_use = "Use the returned algorithm or parameter identity when selecting or reporting cryptographic settings."]
    pub fn curve_name(&self) -> Option<Nid> {
        // SAFETY: the native getter reads the live immutable group.
        let nid = unsafe { ffi::EC_GROUP_get_curve_name(self.as_ptr()) };
        if nid > 0 {
            Some(Nid::from_raw(nid))
        } else {
            None
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::EC_POINT;
    fn drop = ffi::EC_POINT_free;

    /// Represents a point on the curve
    ///
    /// OpenSSL documentation at [`EC_POINT_new`]
    ///
    /// [`EC_POINT_new`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_new.html
    pub struct EcPoint;
}

impl EcPointRef {
    /// Computes `a + b`, storing the result in `self`.
    ///
    /// # Errors
    ///
    /// The operands or destination belong to an incompatible group.
    #[corresponds(EC_POINT_add)]
    pub fn add(&mut self, group: &EcGroupRef, a: &Self, b: &Self) -> Result<(), ErrorStack> {
        // SAFETY: Both point inputs and group are borrowed; destination is exclusive.
        // Native checks group compatibility.
        unsafe {
            cvt(ffi::EC_POINT_add(
                group.as_ptr(),
                self.as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                ptr::null_mut(),
            ))
        }
    }

    /// Computes `q * m`, storing the result in `self`.
    ///
    /// For secret scalars, supply nonnegative values strictly below the group
    /// order. Native reduction of out-of-range values is not constant-time.
    ///
    /// # Errors
    ///
    /// Any point belongs to an incompatible group or native scalar processing fails.
    #[corresponds(EC_POINT_mul)]
    pub fn mul(
        &mut self,
        group: &EcGroupRef,
        q: &Self,
        m: &BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: All scalar/point/group inputs are live, and destination and scratch
        // context are separately exclusive. The null arguments select only the
        // requested terms.
        unsafe {
            cvt(ffi::EC_POINT_mul(
                group.as_ptr(),
                self.as_ptr(),
                ptr::null(),
                q.as_ptr(),
                m.as_ptr(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Computes `generator * n`, storing the result in `self`.
    ///
    /// For secret scalars, supply nonnegative values strictly below the group
    /// order. Native reduction of out-of-range values is not constant-time.
    ///
    /// # Errors
    ///
    /// The destination belongs to an incompatible group or native scalar processing fails.
    pub fn mul_generator(
        &mut self,
        group: &EcGroupRef,
        n: &BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: All scalar/point/group inputs are live, and destination and scratch
        // context are separately exclusive. The null arguments select only the
        // requested terms.
        unsafe {
            cvt(ffi::EC_POINT_mul(
                group.as_ptr(),
                self.as_ptr(),
                n.as_ptr(),
                ptr::null(),
                ptr::null(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Computes `generator * n + q * m`, storing the result in `self`.
    ///
    /// For secret scalars, supply nonnegative values strictly below the group
    /// order. Native reduction of out-of-range values is not constant-time.
    ///
    /// # Errors
    ///
    /// Any point belongs to an incompatible group or native scalar processing fails.
    pub fn mul_full(
        &mut self,
        group: &EcGroupRef,
        n: &BigNumRef,
        q: &Self,
        m: &BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: All scalar/point/group inputs are live, and destination and scratch
        // context are separately exclusive. The null arguments select only the
        // requested terms.
        unsafe {
            cvt(ffi::EC_POINT_mul(
                group.as_ptr(),
                self.as_ptr(),
                n.as_ptr(),
                q.as_ptr(),
                m.as_ptr(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Negates this point in the group law.
    ///
    /// # Errors
    ///
    /// The point belongs to an incompatible group.
    #[corresponds(EC_POINT_invert)]
    pub fn invert(&mut self, group: &EcGroupRef) -> Result<(), ErrorStack> {
        // SAFETY: The destination is exclusive and the live group is immutable; native
        // validates their compatibility.
        unsafe {
            cvt(ffi::EC_POINT_invert(
                group.as_ptr(),
                self.as_ptr(),
                ptr::null_mut(),
            ))
        }
    }

    /// Serializes the point to a binary representation.
    ///
    /// # Errors
    ///
    /// The group is incompatible, the point is at infinity, or encoding or allocation fails.
    #[corresponds(EC_POINT_point2oct)]
    pub fn to_bytes(
        &self,
        group: &EcGroupRef,
        form: PointConversionForm,
    ) -> Result<Vec<u8>, ErrorStack> {
        // SAFETY: group and point stay alive and immutable. Native's null
        // output query returns the exact capacity without converting coordinates.
        let capacity = unsafe {
            ffi::EC_POINT_point2oct(
                group.as_ptr(),
                self.as_ptr(),
                form.0,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        };
        if capacity == 0 {
            return Err(ErrorStack::get());
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(ErrorStack::internal_error)?;
        // SAFETY: the allocation covers capacity bytes and the native
        // serializer writes at most that length, returning the initialized count.
        let written = unsafe {
            ffi::EC_POINT_point2oct(
                group.as_ptr(),
                self.as_ptr(),
                form.0,
                bytes.as_mut_ptr(),
                capacity,
                ptr::null_mut(),
            )
        };
        if written == 0 {
            return Err(ErrorStack::get());
        }
        if written > capacity {
            return Err(ErrorStack::internal_error_str(
                "invalid point encoding length",
            ));
        }
        // SAFETY: native success initialized exactly written bytes.
        unsafe { bytes.set_len(written) };
        Ok(bytes)
    }

    /// Creates a new point on the specified curve with the same value.
    ///
    /// # Errors
    ///
    /// The group is incompatible or native point allocation fails.
    #[corresponds(EC_POINT_dup)]
    pub fn to_owned(&self, group: &EcGroupRef) -> Result<EcPoint, ErrorStack> {
        // SAFETY: Native duplicates the borrowed point into an owned result, retaining
        // its group reference.
        unsafe {
            cvt_p(ffi::EC_POINT_dup(self.as_ptr(), group.as_ptr())).map(|p| EcPoint::from_ptr(p))
        }
    }

    /// Determines if this point is equal to another.
    ///
    /// OpenSSL doucmentation at [`EC_POINT_cmp`]
    ///
    /// [`EC_POINT_cmp`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_cmp.html
    ///
    /// # Errors
    ///
    /// Either point belongs to an incompatible group.
    pub fn eq(&self, group: &EcGroupRef, other: &Self) -> Result<bool, ErrorStack> {
        // SAFETY: All three inputs are live and immutable; native validates group
        // compatibility before comparison.
        unsafe {
            let res = cvt_n(ffi::EC_POINT_cmp(
                group.as_ptr(),
                self.as_ptr(),
                other.as_ptr(),
                ptr::null_mut(),
            ))?;
            Ok(res == 0)
        }
    }

    /// Writes the requested affine coordinates of this point.
    ///
    /// Pass no output for a coordinate that is not needed.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched curve, point at infinity, or native allocation failure.
    #[corresponds(EC_POINT_get_affine_coordinates)]
    pub fn affine_coordinates(
        &self,
        group: &EcGroupRef,
        x: Option<&mut BigNumRef>,
        y: Option<&mut BigNumRef>,
    ) -> Result<(), ErrorStack> {
        // SAFETY: the group and point are live immutable inputs, and each
        // non-null output is separately exclusively borrowed. Native permits
        // null outputs and checks that the point belongs to the group.
        unsafe {
            cvt(ffi::EC_POINT_get_affine_coordinates(
                group.as_ptr(),
                self.as_ptr(),
                x.map_or(ptr::null_mut(), |value| value.as_ptr()),
                y.map_or(ptr::null_mut(), |value| value.as_ptr()),
                ptr::null_mut(),
            ))
        }
    }

    /// Tests whether this point is at infinity.
    /// An incompatible group also returns false.
    #[corresponds(EC_POINT_is_at_infinity)]
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn is_infinity(&self, group: &EcGroupRef) -> bool {
        // SAFETY: The point and group are live and immutable; native validates group
        // compatibility.
        unsafe { ffi::EC_POINT_is_at_infinity(group.as_ptr(), self.as_ptr()) == 1 }
    }

    /// Tests whether the point belongs to this curve.
    ///
    /// The native API returns false for an incompatible group or any other failure.
    #[corresponds(EC_POINT_is_on_curve)]
    #[must_use = "Use the curve-membership result when validating a point."]
    pub fn is_on_curve(&self, group: &EcGroupRef) -> bool {
        // SAFETY: both native objects are borrowed, and native validates compatibility.
        unsafe { ffi::EC_POINT_is_on_curve(group.as_ptr(), self.as_ptr(), ptr::null_mut()) == 1 }
    }
}

impl EcPoint {
    /// Creates a new point on the specified curve.
    ///
    /// # Errors
    ///
    /// Native point allocation fails.
    #[corresponds(EC_POINT_new)]
    pub fn new(group: &EcGroupRef) -> Result<Self, ErrorStack> {
        // SAFETY: Native returns a fresh owned point and retains its group reference.
        unsafe { cvt_p(ffi::EC_POINT_new(group.as_ptr())).map(|p| Self::from_ptr(p)) }
    }

    /// Decodes and validates a compressed or uncompressed point.
    ///
    /// # Errors
    ///
    /// The input is not a valid point encoding for the given curve or native allocation fails.
    #[corresponds(EC_POINT_oct2point)]
    pub fn from_bytes(group: &EcGroupRef, buf: &[u8]) -> Result<Self, ErrorStack> {
        let point = Self::new(group)?;
        // SAFETY: The fresh point is exclusively owned, the group is live, and the
        // input slice is readable for the supplied length.
        unsafe {
            cvt(ffi::EC_POINT_oct2point(
                group.as_ptr(),
                point.as_ptr(),
                buf.as_ptr(),
                buf.len(),
                ptr::null_mut(),
            ))?;
        }
        Ok(point)
    }
}

generic_foreign_type_and_impl_send_sync! {
    type CType = ffi::EC_KEY;
    fn drop = ffi::EC_KEY_free;

    /// Public and optional Private key on the given curve
    ///
    pub struct EcKey<T>;

    /// Reference to [`EcKey`]
    ///
    /// [`EcKey`]: struct.EcKey.html
    pub struct EcKeyRef<T>;
}

impl<T> EcKeyRef<T>
where
    T: HasPrivate,
{
    private_key_to_pem! {
        /// Serializes the private key to a PEM-encoded ECPrivateKey structure.
        ///
        /// The output will have a header of `-----BEGIN EC PRIVATE KEY-----`.
        #[corresponds(PEM_write_bio_ECPrivateKey)]
        private_key_to_pem,
        /// Serializes the private key to a PEM-encoded encrypted ECPrivateKey structure.
        ///
        /// The output will have a header of `-----BEGIN EC PRIVATE KEY-----`.
        #[corresponds(PEM_write_bio_ECPrivateKey)]
        private_key_to_pem_passphrase,
        ffi::PEM_write_bio_ECPrivateKey
    }

    to_der! {
        /// Serializes the private key into a DER-encoded ECPrivateKey structure.
        #[corresponds(i2d_ECPrivateKey)]
        private_key_to_der,
        ffi::i2d_ECPrivateKey
    }

    /// Returns the private scalar.
    #[corresponds(EC_KEY_get0_private_key)]
    #[must_use = "The returned key component is the result of this accessor."]
    pub fn private_key(&self) -> &BigNumRef {
        // SAFETY: The private-key capability guarantees a native private scalar, owned
        // by the key for the shared borrow.
        unsafe {
            let ptr = ffi::EC_KEY_get0_private_key(self.as_ptr());
            BigNumRef::from_ptr(ptr.cast_mut())
        }
    }
}

impl<T> EcKeyRef<T>
where
    T: HasPublic,
{
    /// Returns the public key.
    #[corresponds(EC_KEY_get0_public_key)]
    #[must_use = "The returned key component is the result of this accessor."]
    pub fn public_key(&self) -> &EcPointRef {
        // SAFETY: The public-key capability guarantees a native public point, owned by
        // the key for the shared borrow.
        unsafe {
            let ptr = ffi::EC_KEY_get0_public_key(self.as_ptr());
            EcPointRef::from_ptr(ptr.cast_mut())
        }
    }

    to_pem! {
        /// Serialies the public key into a PEM-encoded SubjectPublicKeyInfo structure.
        ///
        /// The output will have a header of `-----BEGIN PUBLIC KEY-----`.
        #[corresponds(PEM_write_bio_EC_PUBKEY)]
        public_key_to_pem,
        ffi::PEM_write_bio_EC_PUBKEY
    }

    to_der! {
        /// Serializes the public key into a DER-encoded SubjectPublicKeyInfo structure.
        #[corresponds(i2d_EC_PUBKEY)]
        public_key_to_der,
        ffi::i2d_EC_PUBKEY
    }
}

impl<T> EcKeyRef<T>
where
    T: HasParams,
{
    /// Return [`EcGroup`] of the `EcKey`
    #[corresponds(EC_KEY_get0_group)]
    #[must_use = "Use the returned algorithm or parameter identity when selecting or reporting cryptographic settings."]
    pub fn group(&self) -> &EcGroupRef {
        // SAFETY: The parameter capability guarantees a native group reference retained
        // by the key.
        unsafe {
            let ptr = ffi::EC_KEY_get0_group(self.as_ptr());
            EcGroupRef::from_ptr(ptr.cast_mut())
        }
    }

    /// Checks the key for validity.
    ///
    /// # Errors
    ///
    /// The key is incomplete or its components are invalid or inconsistent.
    #[corresponds(EC_KEY_check_key)]
    pub fn check_key(&self) -> Result<(), ErrorStack> {
        // SAFETY: The native key stays alive during read-only validation.
        unsafe { cvt(ffi::EC_KEY_check_key(self.as_ptr())) }
    }
}

impl<T> ToOwned for EcKeyRef<T> {
    type Owned = EcKey<T>;

    fn to_owned(&self) -> EcKey<T> {
        // SAFETY: native up_ref always increments this live refcount and returns one.
        unsafe {
            ffi::EC_KEY_up_ref(self.as_ptr());
            EcKey::from_ptr(self.as_ptr())
        }
    }
}

impl EcKey<Params> {
    /// Constructs an `EcKey` corresponding to a known curve.
    ///
    /// It will not have an associated public or private key. This kind of key is primarily useful
    /// to be provided to the `set_tmp_ecdh` methods on `Ssl` and `SslContextBuilder`.
    ///
    /// # Errors
    ///
    /// The curve identifier is unsupported or native allocation fails.
    #[corresponds(EC_KEY_new_by_curve_name)]
    pub fn from_curve_name(nid: Nid) -> Result<Self, ErrorStack> {
        // SAFETY: The native constructor returns a new owned parameter key or null.
        unsafe {
            init();
            cvt_p(ffi::EC_KEY_new_by_curve_name(nid.as_raw())).map(|p| Self::from_ptr(p))
        }
    }

    /// Constructs an `EcKey` corresponding to a curve.
    ///
    /// # Errors
    ///
    /// Native parameter-key allocation or group installation fails.
    #[corresponds(EC_KEY_set_group)]
    pub fn from_group(group: &EcGroupRef) -> Result<Self, ErrorStack> {
        init();
        // SAFETY: native allocation transfers a fresh owned key, and setting
        // its group retains the immutable native group reference.
        unsafe {
            let key = Self::from_ptr(cvt_p(ffi::EC_KEY_new())?);
            cvt(ffi::EC_KEY_set_group(key.as_ptr(), group.as_ptr()))?;
            Ok(key)
        }
    }
}

impl EcKey<Public> {
    /// Constructs an `EcKey` from the specified group with the associated `EcPoint`, public_key.
    ///
    /// This will only have the associated public_key.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use btls::ec::*;
    /// use btls::nid::Nid;
    /// use btls::pkey::PKey;
    ///
    /// // get bytes from somewhere, i.e. this will not produce a valid key
    /// let public_key: Vec<u8> = vec![];
    ///
    /// // create an EcKey from the binary form of a EcPoint
    /// let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    /// let point = EcPoint::from_bytes(&group, &public_key).unwrap();
    /// let key = EcKey::from_public_key(&group, &point);
    /// ```
    ///
    /// # Errors
    ///
    /// The point is invalid, incompatible, at infinity, or native allocation fails.
    pub fn from_public_key(
        group: &EcGroupRef,
        public_key: &EcPointRef,
    ) -> Result<Self, ErrorStack> {
        let key = EcKey::<Params>::from_group(group)?;
        // SAFETY: the new key is exclusively owned. Native duplicates the
        // borrowed point and verifies group compatibility and non-infinity.
        unsafe {
            cvt(ffi::EC_KEY_set_public_key(
                key.as_ptr(),
                public_key.as_ptr(),
            ))?
        };
        key.check_key()?;
        // SAFETY: successful installation and validation established the public component.
        Ok(unsafe { Self::from_ptr(key.into_ptr()) })
    }

    /// Constructs a public key from its affine coordinates.
    ///
    /// # Errors
    ///
    /// The coordinates do not specify a valid point on the group or native allocation fails.
    pub fn from_public_key_affine_coordinates(
        group: &EcGroupRef,
        x: &BigNumRef,
        y: &BigNumRef,
    ) -> Result<Self, ErrorStack> {
        let key = EcKey::<Params>::from_group(group)?;
        // SAFETY: the new key is exclusively owned; both coordinate inputs
        // remain live. The native setter constructs and validates the public point.
        unsafe {
            cvt(ffi::EC_KEY_set_public_key_affine_coordinates(
                key.as_ptr(),
                x.as_ptr(),
                y.as_ptr(),
            ))?
        };
        // SAFETY: the native setter succeeded, establishing the public component.
        Ok(unsafe { Self::from_ptr(key.into_ptr()) })
    }

    from_pem! {
        /// Decodes a PEM-encoded SubjectPublicKeyInfo structure containing a EC key.
        ///
        /// The input should have a header of `-----BEGIN PUBLIC KEY-----`.
        #[corresponds(PEM_read_bio_EC_PUBKEY)]
        public_key_from_pem,
        EcKey<Public>,
        ffi::PEM_read_bio_EC_PUBKEY
    }

    from_der! {
        /// Decodes a DER-encoded SubjectPublicKeyInfo structure containing a EC key.
        #[corresponds(d2i_EC_PUBKEY)]
        public_key_from_der,
        EcKey<Public>,
        ffi::d2i_EC_PUBKEY,
        ::libc::c_long
    }
}

impl EcKey<Private> {
    /// Generates a new public/private key pair on the specified curve.
    ///
    /// # Errors
    ///
    /// Native key generation or allocation fails.
    pub fn generate(group: &EcGroupRef) -> Result<Self, ErrorStack> {
        let key = EcKey::<Params>::from_group(group)?;
        // SAFETY: the exclusive parameter key has a valid group, and native
        // generation initializes both matching key components.
        unsafe { cvt(ffi::EC_KEY_generate_key(key.as_ptr()))? };
        // SAFETY: successful generation established private and public components.
        Ok(unsafe { Self::from_ptr(key.into_ptr()) })
    }

    /// Constructs an public/private key pair given a curve, a private key and a public key point.
    ///
    /// # Errors
    ///
    /// The components are invalid, inconsistent, incompatible, or native allocation fails.
    pub fn from_private_components(
        group: &EcGroupRef,
        private_number: &BigNumRef,
        public_key: &EcPointRef,
    ) -> Result<Self, ErrorStack> {
        let key = EcKey::<Params>::from_group(group)?;
        // SAFETY: only this owner can mutate the fresh native key; both
        // component inputs remain borrowed while native copies them.
        unsafe {
            cvt(ffi::EC_KEY_set_private_key(
                key.as_ptr(),
                private_number.as_ptr(),
            ))?;
            cvt(ffi::EC_KEY_set_public_key(
                key.as_ptr(),
                public_key.as_ptr(),
            ))?;
        }
        key.check_key()?;
        // SAFETY: native validation establishes a matching key pair.
        Ok(unsafe { Self::from_ptr(key.into_ptr()) })
    }

    private_key_from_pem! {
        /// Deserializes a private key from a PEM-encoded ECPrivateKey structure.
        ///
        /// The input should have a header of `-----BEGIN EC PRIVATE KEY-----`.
        #[corresponds(PEM_read_bio_ECPrivateKey)]
        private_key_from_pem,

        /// Deserializes a private key from a PEM-encoded encrypted ECPrivateKey structure.
        ///
        /// The input should have a header of `-----BEGIN EC PRIVATE KEY-----`.
        #[corresponds(PEM_read_bio_ECPrivateKey)]
        private_key_from_pem_passphrase,

        /// Deserializes a private key from a PEM-encoded encrypted ECPrivateKey structure.
        ///
        /// The callback should fill the password into the provided buffer and return its length.
        ///
        /// The input should have a header of `-----BEGIN EC PRIVATE KEY-----`.
        #[corresponds(PEM_read_bio_ECPrivateKey)]
        private_key_from_pem_callback,
        EcKey<Private>,
        ffi::PEM_read_bio_ECPrivateKey
    }

    from_der! {
        /// Decodes a DER-encoded elliptic curve private key structure.
        #[corresponds(d2i_ECPrivateKey)]
        private_key_from_der,
        EcKey<Private>,
        ffi::d2i_ECPrivateKey,
        ::libc::c_long
    }
}

impl<T> Clone for EcKey<T> {
    fn clone(&self) -> Self {
        (**self).to_owned()
    }
}

impl<T> fmt::Debug for EcKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EcKey")
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    use super::*;
    use crate::bn::{BigNum, BigNumContext};
    use crate::nid::Nid;

    #[test]
    fn key_new_by_curve_name() {
        EcKey::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    }

    #[test]
    fn generate() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        EcKey::generate(&group).unwrap();
    }

    #[test]
    fn cofactor() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut cofactor = BigNum::new().unwrap();
        group.cofactor(&mut cofactor).unwrap();
        let one = BigNum::from_u32(1).unwrap();
        assert_eq!(cofactor, one);
    }

    #[test]
    fn dup() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let shared = key.clone();
        assert!(std::ptr::eq(key.as_ptr(), shared.as_ptr()));
        drop(key);
        shared.check_key().unwrap();
    }

    #[test]
    fn point_new() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        EcPoint::new(&group).unwrap();
    }

    #[test]
    fn point_bytes() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let point = key.public_key();
        let bytes = point
            .to_bytes(&group, PointConversionForm::COMPRESSED)
            .unwrap();
        let point2 = EcPoint::from_bytes(&group, &bytes).unwrap();
        assert!(point.eq(&group, &point2).unwrap());
    }

    #[test]
    fn point_owned() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let point = key.public_key();
        let owned = point.to_owned(&group).unwrap();
        assert!(owned.eq(&group, point).unwrap());
    }

    #[test]
    fn mul_generator() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let mut public_key = EcPoint::new(&group).unwrap();
        public_key
            .mul_generator(&group, key.private_key(), &mut ctx)
            .unwrap();
        assert!(public_key.eq(&group, key.public_key()).unwrap());
    }

    #[test]
    fn generator() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let generator = group.generator().unwrap();
        let one = BigNum::from_u32(1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let mut ecp = EcPoint::new(&group).unwrap();
        ecp.mul_generator(&group, &one, &mut ctx).unwrap();
        assert!(ecp.eq(&group, generator).unwrap());
    }

    #[test]
    fn key_from_public_key() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let bytes = key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED)
            .unwrap();

        drop(key);
        let public_key = EcPoint::from_bytes(&group, &bytes).unwrap();
        let ec_key = EcKey::from_public_key(&group, &public_key).unwrap();
        assert!(ec_key.check_key().is_ok());
    }

    #[test]
    fn key_from_private_components() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();

        let dup_key =
            EcKey::from_private_components(&group, key.private_key(), key.public_key()).unwrap();
        dup_key.check_key().unwrap();

        assert_eq!(key.private_key(), dup_key.private_key());
    }

    #[test]
    fn rejects_mismatched_private_components() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let one = BigNum::from_u32(1).unwrap();
        let two = BigNum::from_u32(2).unwrap();
        let generator = group.generator().unwrap();
        assert!(EcKey::from_private_components(&group, &one, generator).is_ok());
        assert!(EcKey::from_private_components(&group, &two, generator).is_err());
        assert_eq!(group.order().unwrap().num_bits(), group.order_bits());
    }

    #[test]
    fn key_from_affine_coordinates() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let x = Vec::from_hex("30a0424cd21c2944838a2d75c92b37e76ea20d9f00893a3b4eee8a3c0aafec3e")
            .unwrap();
        let y = Vec::from_hex("e04b65e92456d9888b52b379bdfbd51ee869ef1f0fc65b6659695b6cce081723")
            .unwrap();

        let xbn = BigNum::from_slice(&x).unwrap();
        let ybn = BigNum::from_slice(&y).unwrap();

        let ec_key = EcKey::from_public_key_affine_coordinates(&group, &xbn, &ybn).unwrap();
        assert!(ec_key.check_key().is_ok());
    }

    #[test]
    fn get_affine_coordinates() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let x = Vec::from_hex("30a0424cd21c2944838a2d75c92b37e76ea20d9f00893a3b4eee8a3c0aafec3e")
            .unwrap();
        let y = Vec::from_hex("e04b65e92456d9888b52b379bdfbd51ee869ef1f0fc65b6659695b6cce081723")
            .unwrap();

        let xbn = BigNum::from_slice(&x).unwrap();
        let ybn = BigNum::from_slice(&y).unwrap();

        let ec_key = EcKey::from_public_key_affine_coordinates(&group, &xbn, &ybn).unwrap();

        let mut xbn2 = BigNum::new().unwrap();
        let mut ybn2 = BigNum::new().unwrap();
        let ec_key_pk = ec_key.public_key();
        ec_key_pk
            .affine_coordinates(&group, Some(&mut xbn2), Some(&mut ybn2))
            .unwrap();
        assert_eq!(xbn2, xbn);
        assert_eq!(ybn2, ybn);
    }
}
