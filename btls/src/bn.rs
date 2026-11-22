//! Arbitrary-precision integers
//!
//! Large numbers are important for a cryptographic library.  OpenSSL implementation
//! of the integer uses dynamically assigned memory to store an array of bit chunks.  This
//! allows numbers of any size to be compared and mathematical functions performed.
//!
//! OpenSSL wiki describes the [`BIGNUM`] data structure.
//!
//! # Examples
//!
//! ```
//! use btls::bn::BigNum;
//! use btls::error::ErrorStack;
//!
//! fn main() -> Result<(), ErrorStack> {
//!   let a = BigNum::new()?; // a = 0
//!   let b = BigNum::from_dec_str("1234567890123456789012345")?;
//!   let c = (&a * &b)?;
//!   assert_eq!(a, c);
//!   Ok(())
//! }
//! ```
//!
//! [`BIGNUM`]: https://wiki.openssl.org/index.php/Manual:Bn_internal(3)
use crate::ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;
use std::cmp::Ordering;
use std::ffi::CString;
use std::ops::{Add, Deref, Div, Mul, Neg, Rem, Shl, Shr, Sub};
use std::{fmt, ptr};

use crate::asn1::Asn1Integer;
use crate::error::ErrorStack;
use crate::ffi::BN_is_negative;
use crate::string::OpensslString;
use crate::{cvt, cvt_p, try_int};
use openssl_macros::corresponds;

/// Options for the most significant bits of a randomly generated `BigNum`.
pub struct MsbOption(c_int);

impl MsbOption {
    /// The most significant bit of the number may be 0.
    pub const MAYBE_ZERO: Self = Self(-1);

    /// The most significant bit of the number must be 1.
    pub const ONE: Self = Self(0);

    /// The most significant two bits of the number must be 1.
    ///
    /// The number of bits in the product of two such numbers will always be exactly twice the
    /// number of bits in the original numbers.
    pub const TWO_ONES: Self = Self(1);
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::BN_CTX;
    fn drop = ffi::BN_CTX_free;

    /// Temporary storage for BigNums on the secure heap
    ///
    /// BigNum values are stored dynamically and therefore can be expensive
    /// to allocate.  BigNumContext and the OpenSSL [`BN_CTX`] structure are used
    /// internally when passing BigNum values between subroutines.
    ///
    /// [`BN_CTX`]: https://www.openssl.org/docs/man1.1.0/crypto/BN_CTX_new.html
    pub struct BigNumContext;
}

impl BigNumContext {
    /// Returns a new `BigNumContext`.
    ///
    /// # Errors
    ///
    /// Native allocation fails.
    #[corresponds(BN_CTX_new)]
    pub fn new() -> Result<Self, ErrorStack> {
        // SAFETY: The allocator takes no inputs and returns a newly owned scratch
        // context or null.
        unsafe {
            ffi::init();
            cvt_p(ffi::BN_CTX_new()).map(|p| Self::from_ptr(p))
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::BIGNUM;
    fn drop = ffi::BN_free;

    /// Dynamically sized arbitrary-precision integer
    ///
    /// Perform large number mathematics.  Create a new BigNum
    /// with [`new`].  Perform standard mathematics on large numbers using
    /// methods from [`Deref<Target = BigNumRef>`]
    ///
    /// OpenSSL documentation at [`BN_new`].
    ///
    /// [`new`]: struct.BigNum.html#method.new
    /// [`Deref<Target = BigNumRef>`]: struct.BigNum.html#deref-methods
    /// [`BN_new`]: https://www.openssl.org/docs/man1.1.0/crypto/BN_new.html
    ///
    /// # Examples
    /// ```
    /// use btls::bn::BigNum;
    /// # use btls::error::ErrorStack;
    /// # fn bignums() -> Result< (), ErrorStack > {
    /// let little_big = BigNum::from_u32(std::u32::MAX)?;
    /// assert_eq!(little_big.num_bytes(), 4);
    /// # Ok(())
    /// # }
    /// # fn main () { bignums(); }
    /// ```
    pub struct BigNum;
}

impl BigNumRef {
    /// Erases the memory used by this `BigNum`, resetting its value to 0.
    ///
    /// This can be used to destroy sensitive data such as keys when they are no longer needed.
    #[corresponds(BN_clear)]
    pub fn clear(&mut self) {
        // SAFETY: The exclusive borrow permits clearing the entire native integer
        // allocation.
        unsafe { ffi::BN_clear(self.as_ptr()) }
    }

    /// Adds a `u32` to `self`.
    ///
    /// # Errors
    ///
    /// Native allocation fails.
    #[corresponds(BN_add_word)]
    pub fn add_word(&mut self, w: u32) -> Result<(), ErrorStack> {
        // SAFETY: The destination is exclusively borrowed and w fits the native word on
        // supported targets.
        unsafe { cvt(ffi::BN_add_word(self.as_ptr(), ffi::BN_ULONG::from(w))) }
    }

    /// Subtracts a `u32` from `self`.
    ///
    /// # Errors
    ///
    /// Native allocation fails.
    #[corresponds(BN_sub_word)]
    pub fn sub_word(&mut self, w: u32) -> Result<(), ErrorStack> {
        // SAFETY: The destination is exclusively borrowed and w fits the native word on
        // supported targets.
        unsafe { cvt(ffi::BN_sub_word(self.as_ptr(), ffi::BN_ULONG::from(w))) }
    }

    /// Multiplies a `u32` by `self`.
    ///
    /// # Errors
    ///
    /// Native allocation fails.
    #[corresponds(BN_mul_word)]
    pub fn mul_word(&mut self, w: u32) -> Result<(), ErrorStack> {
        // SAFETY: The destination is exclusively borrowed and w fits the native word on
        // supported targets.
        unsafe { cvt(ffi::BN_mul_word(self.as_ptr(), ffi::BN_ULONG::from(w))) }
    }

    /// Divides `self` by a `u32`, returning the remainder.
    ///
    /// # Errors
    ///
    /// The divisor is zero or native arithmetic fails.
    #[corresponds(BN_div_word)]
    #[expect(
        clippy::useless_conversion,
        reason = "The input conversion is an identity on 32-bit targets; the output conversion is an identity on 64-bit targets. Both preserve the fixed-width Rust API across BN_ULONG widths."
    )]
    pub fn div_word(&mut self, w: u32) -> Result<u64, ErrorStack> {
        // SAFETY: The native routine mutates only the exclusive integer and reports
        // division failure with its sentinel.
        unsafe {
            let r = ffi::BN_div_word(self.as_ptr(), w.into());
            if r == ffi::BN_ULONG::MAX {
                Err(ErrorStack::get())
            } else {
                Ok(r.into())
            }
        }
    }

    /// Returns the result of `self` modulo `w`.
    ///
    /// # Errors
    ///
    /// The modulus is zero or native arithmetic fails.
    #[corresponds(BN_mod_word)]
    #[expect(
        clippy::useless_conversion,
        reason = "The input conversion is an identity on 32-bit targets; the output conversion is an identity on 64-bit targets. Both preserve the fixed-width Rust API across BN_ULONG widths."
    )]
    pub fn mod_word(&self, w: u32) -> Result<u64, ErrorStack> {
        // SAFETY: The number is borrowed read-only; the native routine returns a
        // remainder or its failure sentinel.
        unsafe {
            let r = ffi::BN_mod_word(self.as_ptr(), w.into());
            if r == ffi::BN_ULONG::MAX {
                Err(ErrorStack::get())
            } else {
                Ok(r.into())
            }
        }
    }

    /// Places a cryptographically-secure pseudo-random nonnegative
    /// number less than `self` in `rnd`.
    ///
    /// # Errors
    ///
    /// The range is invalid or native random generation fails.
    #[corresponds(BN_rand_range)]
    pub fn rand_range(&self, rnd: &mut Self) -> Result<(), ErrorStack> {
        // SAFETY: The range is an immutable live integer and rnd is an exclusive live
        // output; native validates the range.
        unsafe { cvt(ffi::BN_rand_range(rnd.as_ptr(), self.as_ptr())) }
    }

    /// Sets bit `n`. Equivalent to `self |= (1 << n)`.
    ///
    /// When setting a bit outside of `self`, it is expanded.
    ///
    /// # Errors
    ///
    /// The bit index is invalid or native allocation fails.
    #[corresponds(BN_set_bit)]
    pub fn set_bit(&mut self, n: i32) -> Result<(), ErrorStack> {
        // SAFETY: The destination is exclusive; native validates the signed bit index
        // before resizing.
        unsafe { cvt(ffi::BN_set_bit(self.as_ptr(), n)) }
    }

    /// Clears bit `n`, setting it to 0. Equivalent to `self &= ~(1 << n)`.
    ///
    /// When clearing a bit outside of `self`, an error is returned.
    ///
    /// # Errors
    ///
    /// The bit index is invalid or outside the existing integer.
    #[corresponds(BN_clear_bit)]
    pub fn clear_bit(&mut self, n: i32) -> Result<(), ErrorStack> {
        // SAFETY: The destination is exclusive; native validates the signed bit index
        // before clearing.
        unsafe { cvt(ffi::BN_clear_bit(self.as_ptr(), n)) }
    }

    /// Returns `true` if the `n`th bit of `self` is set to 1, `false` otherwise.
    #[corresponds(BN_is_bit_set)]
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn is_bit_set(&self, n: i32) -> bool {
        // SAFETY: The native query borrows the integer and checks the signed bit index.
        unsafe { ffi::BN_is_bit_set(self.as_ptr(), n) == 1 }
    }

    /// Truncates `self` to the lowest `n` bits.
    ///
    /// An error occurs if `self` is already shorter than `n` bits.
    ///
    /// # Errors
    ///
    /// The bit count is invalid or exceeds the current integer size.
    #[corresponds(BN_mask_bits)]
    pub fn mask_bits(&mut self, n: i32) -> Result<(), ErrorStack> {
        // SAFETY: The destination is exclusive; native validates the requested bit
        // count.
        unsafe { cvt(ffi::BN_mask_bits(self.as_ptr(), n)) }
    }

    /// Places `a << 1` in `self`.  Equivalent to `self * 2`.
    ///
    /// # Errors
    ///
    /// Native allocation fails.
    #[corresponds(BN_lshift1)]
    pub fn lshift1(&mut self, a: &Self) -> Result<(), ErrorStack> {
        // SAFETY: The source remains borrowed and the destination is exclusively
        // borrowed.
        unsafe { cvt(ffi::BN_lshift1(self.as_ptr(), a.as_ptr())) }
    }

    /// Places `a >> 1` in `self`. Equivalent to `self / 2`.
    ///
    /// # Errors
    ///
    /// Native allocation fails.
    #[corresponds(BN_rshift1)]
    pub fn rshift1(&mut self, a: &Self) -> Result<(), ErrorStack> {
        // SAFETY: The source remains borrowed and the destination is exclusively
        // borrowed.
        unsafe { cvt(ffi::BN_rshift1(self.as_ptr(), a.as_ptr())) }
    }

    /// Places `a + b` in `self`.  [`core::ops::Add`] is also implemented for `BigNumRef`.
    ///
    /// [`core::ops::Add`]: struct.BigNumRef.html#method.add
    ///
    /// # Errors
    ///
    /// Native allocation fails.
    #[corresponds(BN_add)]
    pub fn checked_add(&mut self, a: &Self, b: &Self) -> Result<(), ErrorStack> {
        // SAFETY: Both operands are live immutable integers and the destination is
        // exclusive.
        unsafe { cvt(ffi::BN_add(self.as_ptr(), a.as_ptr(), b.as_ptr())) }
    }

    /// Places `a - b` in `self`. [`core::ops::Sub`] is also implemented for `BigNumRef`.
    ///
    /// [`core::ops::Sub`]: struct.BigNumRef.html#method.sub
    ///
    /// # Errors
    ///
    /// Native allocation fails.
    #[corresponds(BN_sub)]
    pub fn checked_sub(&mut self, a: &Self, b: &Self) -> Result<(), ErrorStack> {
        // SAFETY: Both operands are live immutable integers and the destination is
        // exclusive.
        unsafe { cvt(ffi::BN_sub(self.as_ptr(), a.as_ptr(), b.as_ptr())) }
    }

    /// Places `a << n` in `self`.  Equivalent to `a * 2 ^ n`.
    ///
    /// # Errors
    ///
    /// The shift count is invalid or native allocation fails.
    #[corresponds(BN_lshift)]
    pub fn lshift(&mut self, a: &Self, n: i32) -> Result<(), ErrorStack> {
        // SAFETY: The input is borrowed and the destination is exclusive; native
        // validates the shift count.
        unsafe { cvt(ffi::BN_lshift(self.as_ptr(), a.as_ptr(), n)) }
    }

    /// Places `a >> n` in `self`. Equivalent to `a / 2 ^ n`.
    ///
    /// # Errors
    ///
    /// The shift count is invalid or native allocation fails.
    #[corresponds(BN_rshift)]
    pub fn rshift(&mut self, a: &Self, n: i32) -> Result<(), ErrorStack> {
        // SAFETY: The input is borrowed and the destination is exclusive; native
        // validates the shift count.
        unsafe { cvt(ffi::BN_rshift(self.as_ptr(), a.as_ptr(), n)) }
    }

    /// Creates a new BigNum with the same value.
    ///
    /// # Errors
    ///
    /// Native allocation fails.
    #[corresponds(BN_dup)]
    pub fn to_owned(&self) -> Result<BigNum, ErrorStack> {
        // SAFETY: The source remains live and the native duplicate transfers a new
        // owned allocation.
        unsafe { cvt_p(ffi::BN_dup(self.as_ptr())).map(|b| BigNum::from_ptr(b)) }
    }

    /// Sets the sign of `self`.  Pass true to set `self` to a negative.  False sets
    /// `self` positive.
    #[corresponds(BN_set_negative)]
    pub fn set_negative(&mut self, negative: bool) {
        // SAFETY: Exclusive borrowing allows modifying the native sign field; the flag
        // is zero or one.
        unsafe { ffi::BN_set_negative(self.as_ptr(), c_int::from(negative)) }
    }

    /// Compare the absolute values of `self` and `oth`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use btls::bn::BigNum;
    /// # use std::cmp::Ordering;
    /// let s = -BigNum::from_u32(8).unwrap();
    /// let o = BigNum::from_u32(8).unwrap();
    ///
    /// assert_eq!(s.ucmp(&o), Ordering::Equal);
    /// ```
    #[corresponds(BN_ucmp)]
    #[must_use = "Use the comparison result to determine the ordering of the operands."]
    pub fn ucmp(&self, oth: &Self) -> Ordering {
        // SAFETY: Both operands are live and borrowed; comparison does not mutate
        // either.
        unsafe { ffi::BN_ucmp(self.as_ptr(), oth.as_ptr()).cmp(&0) }
    }

    /// Returns `true` if `self` is negative.
    #[corresponds(BN_is_negative)]
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn is_negative(&self) -> bool {
        // SAFETY: The live borrowed integer is queried without mutation.
        unsafe { BN_is_negative(self.as_ptr()) == 1 }
    }

    #[corresponds(BN_is_odd)]
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn is_odd(&self) -> bool {
        // SAFETY: The live borrowed integer is queried without mutation.
        unsafe { ffi::BN_is_odd(self.as_ptr()) == 1 }
    }

    #[corresponds(BN_is_even)]
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn is_even(&self) -> bool {
        !self.is_odd()
    }

    /// Returns the number of significant bits in `self`.
    #[corresponds(BN_num_bits)]
    #[must_use = "Use the returned cryptographic size or bit count to validate parameters."]
    pub fn num_bits(&self) -> u32 {
        // SAFETY: the live BIGNUM remains borrowed throughout the query.
        unsafe { ffi::BN_num_bits(self.as_ptr()) }
    }

    /// Returns the size of `self` in bytes. Implemented natively.
    #[must_use = "Use the returned length or capacity to size buffers or validate input."]
    pub fn num_bytes(&self) -> usize {
        // SAFETY: the live BIGNUM is borrowed. The native byte count fits in
        // int, and consequently in usize on all supported BoringSSL targets.
        unsafe { ffi::BN_num_bytes(self.as_ptr()) as usize }
    }

    /// Generates a cryptographically strong pseudo-random `BigNum`, placing it in `self`.
    ///
    /// # Parameters
    ///
    /// * `bits`: Length of the number in bits.
    /// * `msb`: The desired properties of the most significant bit. See [`constants`].
    /// * `odd`: If `true`, the generated number will be odd.
    ///
    /// # Examples
    ///
    /// ```
    /// use btls::bn::{BigNum, MsbOption};
    /// use btls::error::ErrorStack;
    ///
    /// fn generate_random() -> Result< BigNum, ErrorStack > {
    ///    let mut big = BigNum::new()?;
    ///
    ///    // Generates a 128-bit odd random number
    ///    big.rand(128, MsbOption::MAYBE_ZERO, true)?;
    ///    Ok((big))
    /// }
    /// ```
    ///
    /// [`constants`]: index.html#constants
    ///
    /// # Errors
    ///
    /// The requested bit length or flags are invalid, or generation fails.
    #[corresponds(BN_rand)]
    pub fn rand(&mut self, bits: i32, msb: MsbOption, odd: bool) -> Result<(), ErrorStack> {
        // SAFETY: The destination is exclusive; native validates the bit count and the
        // typed flags.
        unsafe { cvt(ffi::BN_rand(self.as_ptr(), bits, msb.0, c_int::from(odd))) }
    }

    /// Generates a prime number, placing it in `self`.
    ///
    /// # Parameters
    ///
    /// * `bits`: The length of the prime in bits (lower bound).
    /// * `safe`: If true, returns a "safe" prime `p` so that `(p-1)/2` is also prime.
    /// * `add`/`rem`: If `add` is set to `Some(add)`, `p % add == rem` will hold, where `p` is the
    ///   generated prime and `rem` is `1` if not specified (`None`).
    ///
    /// # Examples
    ///
    /// ```
    /// use btls::bn::BigNum;
    /// use btls::error::ErrorStack;
    ///
    /// fn generate_weak_prime() -> Result< BigNum, ErrorStack > {
    ///    let mut big = BigNum::new()?;
    ///
    ///    // Generates a 128-bit simple prime number
    ///    big.generate_prime(128, false, None, None)?;
    ///    Ok((big))
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// The parameters are invalid or native prime generation fails.
    #[corresponds(BN_generate_prime_ex)]
    pub fn generate_prime(
        &mut self,
        bits: i32,
        safe: bool,
        add: Option<&Self>,
        rem: Option<&Self>,
    ) -> Result<(), ErrorStack> {
        // SAFETY: The destination is exclusive, optional constraints are live immutable
        // inputs, and the null callback disables progress calls.
        unsafe {
            cvt(ffi::BN_generate_prime_ex(
                self.as_ptr(),
                bits,
                c_int::from(safe),
                add.map_or(ptr::null(), |number| number.as_ptr().cast_const()),
                rem.map_or(ptr::null(), |number| number.as_ptr().cast_const()),
                ptr::null_mut(),
            ))
        }
    }

    /// Places the result of `a * b` in `self`.
    /// [`core::ops::Mul`] is also implemented for `BigNumRef`.
    ///
    /// [`core::ops::Mul`]: struct.BigNumRef.html#method.mul
    ///
    /// # Errors
    ///
    /// Native arithmetic or scratch allocation fails.
    #[corresponds(BN_mul)]
    pub fn checked_mul(
        &mut self,
        a: &Self,
        b: &Self,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: The operands remain borrowed; destination and native scratch context
        // are separately exclusively borrowed.
        unsafe {
            cvt(ffi::BN_mul(
                self.as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Places the result of `a / b` in `self`. The remainder is discarded.
    /// [`core::ops::Div`] is also implemented for `BigNumRef`.
    ///
    /// [`core::ops::Div`]: struct.BigNumRef.html#method.div
    ///
    /// # Errors
    ///
    /// The divisor is zero or native computation fails.
    #[corresponds(BN_div)]
    pub fn checked_div(
        &mut self,
        a: &Self,
        b: &Self,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: The operands remain borrowed, and any non-null output and scratch
        // context are separately exclusively borrowed. Native checks division by zero.
        unsafe {
            cvt(ffi::BN_div(
                self.as_ptr(),
                ptr::null_mut(),
                a.as_ptr(),
                b.as_ptr(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Places the result of `a % b` in `self`.
    ///
    /// # Errors
    ///
    /// The divisor is zero or native computation fails.
    #[corresponds(BN_div)]
    pub fn checked_rem(
        &mut self,
        a: &Self,
        b: &Self,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: The operands remain borrowed, and any non-null output and scratch
        // context are separately exclusively borrowed. Native checks division by zero.
        unsafe {
            cvt(ffi::BN_div(
                ptr::null_mut(),
                self.as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Places the result of `a / b` in `self` and `a % b` in `rem`.
    ///
    /// # Errors
    ///
    /// The divisor is zero or native computation fails.
    #[corresponds(BN_div)]
    pub fn div_rem(
        &mut self,
        rem: &mut Self,
        a: &Self,
        b: &Self,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: The operands remain borrowed, and any non-null output and scratch
        // context are separately exclusively borrowed. Native checks division by zero.
        unsafe {
            cvt(ffi::BN_div(
                self.as_ptr(),
                rem.as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Places the result of `a²` in `self`.
    ///
    /// # Errors
    ///
    /// Native arithmetic or scratch allocation fails.
    #[corresponds(BN_sqr)]
    pub fn sqr(&mut self, a: &Self, ctx: &mut BigNumContextRef) -> Result<(), ErrorStack> {
        // SAFETY: The input is immutable; the integer destination and scratch context
        // are separately exclusively borrowed.
        unsafe { cvt(ffi::BN_sqr(self.as_ptr(), a.as_ptr(), ctx.as_ptr())) }
    }

    /// Places the result of `a mod m` in `self`.  As opposed to `div_rem`
    /// the result is non-negative.
    ///
    /// # Errors
    ///
    /// The modulus is zero or native computation fails.
    #[corresponds(BN_nnmod)]
    pub fn nnmod(
        &mut self,
        a: &Self,
        m: &Self,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: Both operands are immutable and both output and scratch context are
        // exclusive; native checks modulus validity.
        unsafe {
            cvt(ffi::BN_nnmod(
                self.as_ptr(),
                a.as_ptr(),
                m.as_ptr(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Places the result of `(a + b) mod m` in `self`.
    ///
    /// # Errors
    ///
    /// The modulus is invalid or native computation fails.
    #[corresponds(BN_mod_add)]
    pub fn mod_add(
        &mut self,
        a: &Self,
        b: &Self,
        m: &Self,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: Inputs are immutable and output and scratch context are exclusive;
        // native checks modulus validity.
        unsafe {
            cvt(ffi::BN_mod_add(
                self.as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                m.as_ptr(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Places the result of `(a - b) mod m` in `self`.
    ///
    /// # Errors
    ///
    /// The modulus is invalid or native computation fails.
    #[corresponds(BN_mod_sub)]
    pub fn mod_sub(
        &mut self,
        a: &Self,
        b: &Self,
        m: &Self,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: Inputs are immutable and output and scratch context are exclusive;
        // native checks modulus validity.
        unsafe {
            cvt(ffi::BN_mod_sub(
                self.as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                m.as_ptr(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Places the result of `(a * b) mod m` in `self`.
    ///
    /// # Errors
    ///
    /// The modulus is invalid or native computation fails.
    #[corresponds(BN_mod_mul)]
    pub fn mod_mul(
        &mut self,
        a: &Self,
        b: &Self,
        m: &Self,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: Inputs are immutable and output and scratch context are exclusive;
        // native checks modulus validity.
        unsafe {
            cvt(ffi::BN_mod_mul(
                self.as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                m.as_ptr(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Places the result of `a² mod m` in `self`.
    ///
    /// # Errors
    ///
    /// The modulus is invalid or native computation fails.
    #[corresponds(BN_mod_sqr)]
    pub fn mod_sqr(
        &mut self,
        a: &Self,
        m: &Self,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: Inputs are immutable and output and scratch context are exclusive;
        // native checks modulus validity.
        unsafe {
            cvt(ffi::BN_mod_sqr(
                self.as_ptr(),
                a.as_ptr(),
                m.as_ptr(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Places the result of `a^p` in `self`.
    ///
    /// # Errors
    ///
    /// Native exponentiation or allocation fails.
    #[corresponds(BN_exp)]
    pub fn exp(
        &mut self,
        a: &Self,
        p: &Self,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: The base and exponent are live immutable inputs; destination and
        // scratch context are exclusive.
        unsafe {
            cvt(ffi::BN_exp(
                self.as_ptr(),
                a.as_ptr(),
                p.as_ptr(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Places the result of `a^p mod m` in `self`.
    ///
    /// # Errors
    ///
    /// The exponent or modulus is invalid or native computation fails.
    #[corresponds(BN_mod_exp)]
    pub fn mod_exp(
        &mut self,
        a: &Self,
        p: &Self,
        m: &Self,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: All three operands are borrowed read-only; destination and scratch
        // context are exclusive.
        unsafe {
            cvt(ffi::BN_mod_exp(
                self.as_ptr(),
                a.as_ptr(),
                p.as_ptr(),
                m.as_ptr(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Places the inverse of `a` modulo `n` in `self`.
    ///
    /// # Errors
    ///
    /// No modular inverse exists, or native computation fails.
    #[corresponds(BN_mod_inverse)]
    pub fn mod_inverse(
        &mut self,
        a: &Self,
        n: &Self,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: All operands remain borrowed, destination and scratch context are
        // exclusive, and the result pointer refers to that destination.
        unsafe {
            cvt_p(ffi::BN_mod_inverse(
                self.as_ptr(),
                a.as_ptr(),
                n.as_ptr(),
                ctx.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Places the greatest common divisor of `a` and `b` in `self`.
    ///
    /// # Errors
    ///
    /// Native arithmetic or scratch allocation fails.
    #[corresponds(BN_gcd)]
    pub fn gcd(
        &mut self,
        a: &Self,
        b: &Self,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: The operands are live immutable inputs; destination and scratch
        // context are exclusive.
        unsafe {
            cvt(ffi::BN_gcd(
                self.as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                ctx.as_ptr(),
            ))
        }
    }

    /// Tests primality with the native Miller-Rabin implementation.
    ///
    /// A true result means probably prime. A false result means composite.
    /// If trial division is enabled, small prime divisors are checked first.
    /// Use 64 rounds for validation of externally supplied candidates.
    ///
    /// # Errors
    ///
    /// Returns an error if native primality testing fails.
    #[corresponds(BN_primality_test)]
    pub fn is_prime(
        &self,
        checks: i32,
        ctx: &mut BigNumContextRef,
        trial_division: bool,
    ) -> Result<bool, ErrorStack> {
        let mut prime = 0;
        // SAFETY: the candidate is borrowed, the scratch context is exclusive,
        // and the native function writes the local output on success.
        unsafe {
            cvt(ffi::BN_primality_test(
                &raw mut prime,
                self.as_ptr(),
                checks,
                ctx.as_ptr(),
                c_int::from(trial_division),
                ptr::null_mut(),
            ))?;
        }
        Ok(prime != 0)
    }

    /// Returns a big-endian byte vector representation of the absolute value of `self`.
    ///
    /// `self` can be recreated by using `from_slice`.
    ///
    /// ```
    /// # use btls::bn::BigNum;
    /// let s = -BigNum::from_u32(4543).unwrap();
    /// let r = BigNum::from_u32(4543).unwrap();
    ///
    /// let s_vec = s.to_vec();
    /// assert_eq!(BigNum::from_slice(&s_vec).unwrap(), r);
    /// ```
    #[corresponds(BN_bn2bin)]
    #[must_use = "The returned byte representation is the result of serialization or borrowing."]
    pub fn to_vec(&self) -> Vec<u8> {
        let size = self.num_bytes();
        let mut v = Vec::with_capacity(size);
        // SAFETY: the live immutable BIGNUM needs exactly num_bytes bytes
        // of output. The native encoder returns its initialized byte count.
        unsafe {
            let written = ffi::BN_bn2bin(self.as_ptr(), v.as_mut_ptr());
            v.set_len(written);
        }
        v
    }

    /// Returns a big-endian byte vector representation of the absolute value of `self` padded
    /// to `pad_to` bytes.
    ///
    /// If `pad_to` is less than `self.num_bytes()` then an error is returned.
    ///
    /// `self` can be recreated by using `from_slice`.
    ///
    /// ```
    /// # use btls::bn::BigNum;
    /// let bn = BigNum::from_u32(0x4543).unwrap();
    ///
    /// let bn_vec = bn.to_vec_padded(4).unwrap();
    /// assert_eq!(&bn_vec, &[0, 0, 0x45, 0x43]);
    ///
    /// let r = bn.to_vec_padded(1);
    /// assert!(r.is_err());
    ///
    /// let bn = -BigNum::from_u32(0x4543).unwrap();
    /// let bn_vec = bn.to_vec_padded(4).unwrap();
    /// assert_eq!(&bn_vec, &[0, 0, 0x45, 0x43]);
    /// ```
    ///
    /// # Errors
    ///
    /// The requested width is too small, unrepresentable, or allocation fails.
    pub fn to_vec_padded(&self, pad_to: usize) -> Result<Vec<u8>, ErrorStack> {
        if pad_to < self.num_bytes() || pad_to > isize::MAX.unsigned_abs() {
            return Err(ErrorStack::internal_error_str(
                "invalid padded integer length",
            ));
        }
        let mut v = Vec::new();
        v.try_reserve_exact(pad_to)
            .map_err(ErrorStack::internal_error)?;
        // SAFETY: the reserved writable allocation covers pad_to bytes.
        // BN_bn2bin_padded initializes that exact length on success.
        unsafe {
            cvt(ffi::BN_bn2bin_padded(v.as_mut_ptr(), pad_to, self.as_ptr()))?;
            v.set_len(pad_to);
        }
        Ok(v)
    }

    /// Returns a decimal string representation of `self`.
    ///
    /// ```
    /// # use btls::bn::BigNum;
    /// let s = -BigNum::from_u32(12345).unwrap();
    ///
    /// assert_eq!(&**s.to_dec_str().unwrap(), "-12345");
    /// ```
    ///
    /// # Errors
    ///
    /// Native allocation or conversion fails.
    #[corresponds(BN_bn2dec)]
    pub fn to_dec_str(&self) -> Result<OpensslString, ErrorStack> {
        // SAFETY: The live immutable number is serialized into a newly owned NUL-
        // terminated native allocation.
        unsafe {
            let buf = cvt_p(ffi::BN_bn2dec(self.as_ptr()))?;
            Ok(OpensslString::from_ptr(buf))
        }
    }

    /// Returns a hexadecimal string representation of `self`.
    ///
    /// ```
    /// # use btls::bn::BigNum;
    /// let s = -BigNum::from_u32(0x99ff).unwrap();
    ///
    /// assert_eq!(&**s.to_hex_str().unwrap(), "-99ff");
    /// ```
    ///
    /// # Errors
    ///
    /// Native allocation or conversion fails.
    #[corresponds(BN_bn2hex)]
    pub fn to_hex_str(&self) -> Result<OpensslString, ErrorStack> {
        // SAFETY: The live immutable number is serialized into a newly owned NUL-
        // terminated native allocation.
        unsafe {
            let buf = cvt_p(ffi::BN_bn2hex(self.as_ptr()))?;
            Ok(OpensslString::from_ptr(buf))
        }
    }

    /// Places into `self` the modular square root of `a` such that `self^2 = a (mod p)`.
    ///
    /// Returns an error if `a` is not a square mod `p`. In the latter case, it will add
    /// `BN_R_NOT_A_SQUARE` to the error queue. If `a` is a square and `p` > 2, there are two
    /// possible square roots; this function may return either.
    ///
    /// This function only works if `p` is a prime. If `p` is composite, it may fail or return an
    /// arbitrary value. Callers should not pass attacker-controlled values of `p`.
    ///
    /// # Errors
    ///
    /// No square root exists, or native computation fails.
    #[corresponds(BN_mod_sqrt)]
    pub fn mod_sqrt(
        &mut self,
        a: &Self,
        p: &Self,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        // SAFETY: The operands are immutable, destination and scratch context are
        // exclusive, and native returns the destination or null.
        unsafe {
            cvt_p(ffi::BN_mod_sqrt(
                self.as_ptr(),
                a.as_ptr(),
                p.as_ptr(),
                ctx.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Returns an `Asn1Integer` containing the value of `self`.
    ///
    /// # Errors
    ///
    /// Native allocation or ASN.1 conversion fails.
    #[corresponds(BN_to_ASN1_INTEGER)]
    pub fn to_asn1_integer(&self) -> Result<Asn1Integer, ErrorStack> {
        // SAFETY: The number is borrowed; a null destination asks native to allocate a
        // new owned ASN.1 integer.
        unsafe {
            cvt_p(ffi::BN_to_ASN1_INTEGER(self.as_ptr(), ptr::null_mut()))
                .map(|p| Asn1Integer::from_ptr(p))
        }
    }
}

impl BigNum {
    /// Creates a new `BigNum` with the value 0.
    ///
    /// # Errors
    ///
    /// Native allocation fails.
    #[corresponds(BN_new)]
    pub fn new() -> Result<Self, ErrorStack> {
        // SAFETY: The native allocator returns a new owned zero integer or null.
        unsafe {
            ffi::init();
            let v = cvt_p(ffi::BN_new())?;
            Ok(Self::from_ptr(v))
        }
    }

    /// Creates a new `BigNum` with the given value.
    ///
    /// # Errors
    ///
    /// Native allocation or integer initialization fails.
    #[corresponds(BN_set_word)]
    pub fn from_u32(n: u32) -> Result<Self, ErrorStack> {
        let value = Self::new()?;
        // SAFETY: value is a newly owned number. The input fits every BN_ULONG.
        unsafe { cvt(ffi::BN_set_word(value.as_ptr(), ffi::BN_ULONG::from(n)))? };
        Ok(value)
    }

    /// Creates a signed integer from a complete decimal string.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid syntax, an unrepresentable input length,
    /// or native allocation failure.
    #[corresponds(BN_dec2bn)]
    pub fn from_dec_str(s: &str) -> Result<Self, ErrorStack> {
        Self::parse_text(s, u8::is_ascii_digit, ffi::BN_dec2bn)
    }

    /// Creates a signed integer from a complete hexadecimal string.
    ///
    /// The input may begin with a minus sign; a hexadecimal prefix is not accepted.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid syntax, an unrepresentable input length,
    /// or native allocation failure.
    #[corresponds(BN_hex2bn)]
    pub fn from_hex_str(s: &str) -> Result<Self, ErrorStack> {
        Self::parse_text(s, u8::is_ascii_hexdigit, ffi::BN_hex2bn)
    }

    fn parse_text(
        s: &str,
        is_digit: fn(&u8) -> bool,
        decode: unsafe extern "C" fn(*mut *mut ffi::BIGNUM, *const libc::c_char) -> c_int,
    ) -> Result<Self, ErrorStack> {
        let digits = s.strip_prefix('-').unwrap_or(s);
        if digits.is_empty() || !digits.as_bytes().iter().all(is_digit) {
            return Err(ErrorStack::internal_error_str("invalid integer syntax"));
        }
        let expected: c_int = try_int(s.len())?;
        let input = CString::new(s).map_err(ErrorStack::internal_error)?;
        let value = Self::new()?;
        let mut target = value.as_ptr();
        // SAFETY: input is a live C string; both native decoders reuse the
        // supplied non-null BIGNUM, whose Rust owner survives every error path.
        let count = unsafe { decode(&raw mut target, input.as_ptr()) };
        if count == 0 {
            return Err(ErrorStack::get());
        }
        if count != expected {
            return Err(ErrorStack::internal_error_str("incomplete integer parse"));
        }
        Ok(value)
    }

    /// Creates a new `BigNum` from an unsigned, big-endian encoded number of arbitrary length.
    ///
    /// ```
    /// # use btls::bn::BigNum;
    /// let bignum = BigNum::from_slice(&[0x12, 0x00, 0x34]).unwrap();
    ///
    /// assert_eq!(bignum, BigNum::from_u32(0x120034).unwrap());
    /// ```
    ///
    /// # Errors
    ///
    /// The input exceeds native integer bounds or allocation fails.
    #[corresponds(BN_bin2bn)]
    pub fn from_slice(n: &[u8]) -> Result<Self, ErrorStack> {
        // SAFETY: The input slice is readable for its full native size_t length. The
        // null destination requests a new owned integer.
        unsafe {
            ffi::init();
            cvt_p(ffi::BN_bin2bn(n.as_ptr(), n.len(), ptr::null_mut())).map(|p| Self::from_ptr(p))
        }
    }

    /// Copies data from a big-endian byte slice into `self`, overwriting its current value.
    ///
    /// # Errors
    ///
    /// The input exceeds native integer bounds or allocation fails.
    #[corresponds(BN_bin2bn)]
    pub fn copy_from_slice(&mut self, n: &[u8]) -> Result<(), ErrorStack> {
        // SAFETY: The input slice is readable for its full native size_t length. The
        // existing integer is exclusively borrowed.
        unsafe {
            cvt_p(ffi::BN_bin2bn(n.as_ptr(), n.len(), self.as_ptr()))?;
            Ok(())
        }
    }
}

impl fmt::Debug for BigNumRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_dec_str() {
            Ok(s) => f.write_str(&s),
            Err(e) => Err(e.into()),
        }
    }
}

impl fmt::Debug for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_dec_str() {
            Ok(s) => f.write_str(&s),
            Err(e) => Err(e.into()),
        }
    }
}

impl fmt::Display for BigNumRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_dec_str() {
            Ok(s) => f.write_str(&s),
            Err(e) => Err(e.into()),
        }
    }
}

impl fmt::Display for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_dec_str() {
            Ok(s) => f.write_str(&s),
            Err(e) => Err(e.into()),
        }
    }
}

impl PartialEq<Self> for BigNumRef {
    fn eq(&self, oth: &Self) -> bool {
        self.cmp(oth) == Ordering::Equal
    }
}

impl PartialEq<BigNum> for BigNumRef {
    fn eq(&self, oth: &BigNum) -> bool {
        self.eq(&**oth)
    }
}

impl Eq for BigNumRef {}

impl PartialEq for BigNum {
    fn eq(&self, oth: &Self) -> bool {
        self.deref().eq(oth)
    }
}

impl PartialEq<BigNumRef> for BigNum {
    fn eq(&self, oth: &BigNumRef) -> bool {
        self.deref().eq(oth)
    }
}

impl Eq for BigNum {}

impl PartialOrd<Self> for BigNumRef {
    fn partial_cmp(&self, oth: &Self) -> Option<Ordering> {
        Some(self.cmp(oth))
    }
}

impl PartialOrd<BigNum> for BigNumRef {
    fn partial_cmp(&self, oth: &BigNum) -> Option<Ordering> {
        Some(self.cmp(&**oth))
    }
}

impl Ord for BigNumRef {
    fn cmp(&self, oth: &Self) -> Ordering {
        // SAFETY: Both live integers remain immutably borrowed throughout the
        // comparison.
        unsafe { ffi::BN_cmp(self.as_ptr(), oth.as_ptr()).cmp(&0) }
    }
}

impl PartialOrd for BigNum {
    fn partial_cmp(&self, oth: &Self) -> Option<Ordering> {
        Some(self.cmp(oth))
    }
}

impl PartialOrd<BigNumRef> for BigNum {
    fn partial_cmp(&self, oth: &BigNumRef) -> Option<Ordering> {
        self.deref().partial_cmp(oth)
    }
}

impl Ord for BigNum {
    fn cmp(&self, oth: &Self) -> Ordering {
        self.deref().cmp(&**oth)
    }
}

// Binary operators allocate the result and propagate native errors. The
// in-place checked methods remain available for reusing output and scratch space.
macro_rules! binary_operator {
    ($trait:ident, $method:ident, $checked:ident $(, $context:ident)?) => {
        impl $trait<&BigNumRef> for &BigNumRef {
            type Output = Result<BigNum, ErrorStack>;

            fn $method(self, other: &BigNumRef) -> Self::Output {
                $(let mut $context = BigNumContext::new()?;)?
                let mut result = BigNum::new()?;
                result.$checked(self, other $(, &mut $context)?)?;
                Ok(result)
            }
        }

        impl $trait<&BigNum> for &BigNumRef {
            type Output = Result<BigNum, ErrorStack>;

            fn $method(self, other: &BigNum) -> Self::Output {
                $trait::$method(self, other.deref())
            }
        }

        impl $trait<&BigNumRef> for &BigNum {
            type Output = Result<BigNum, ErrorStack>;

            fn $method(self, other: &BigNumRef) -> Self::Output {
                $trait::$method(self.deref(), other)
            }
        }

        impl $trait<&BigNum> for &BigNum {
            type Output = Result<BigNum, ErrorStack>;

            fn $method(self, other: &BigNum) -> Self::Output {
                $trait::$method(self.deref(), other.deref())
            }
        }
    };
}

binary_operator!(Add, add, checked_add);
binary_operator!(Sub, sub, checked_sub);
binary_operator!(Mul, mul, checked_mul, ctx);
binary_operator!(Div, div, checked_div, ctx);
binary_operator!(Rem, rem, checked_rem, ctx);

macro_rules! shift_operator {
    ($trait:ident, $method:ident, $checked:ident) => {
        impl $trait<i32> for &BigNumRef {
            type Output = Result<BigNum, ErrorStack>;

            fn $method(self, count: i32) -> Self::Output {
                let mut result = BigNum::new()?;
                result.$checked(self, count)?;
                Ok(result)
            }
        }

        impl $trait<i32> for &BigNum {
            type Output = Result<BigNum, ErrorStack>;

            fn $method(self, count: i32) -> Self::Output {
                $trait::$method(self.deref(), count)
            }
        }
    };
}

shift_operator!(Shl, shl, lshift);
shift_operator!(Shr, shr, rshift);

impl Neg for &BigNumRef {
    type Output = Result<BigNum, ErrorStack>;

    fn neg(self) -> Self::Output {
        Ok(self.to_owned()?.neg())
    }
}

impl Neg for &BigNum {
    type Output = Result<BigNum, ErrorStack>;

    fn neg(self) -> Self::Output {
        self.deref().neg()
    }
}

impl Neg for BigNum {
    type Output = Self;

    fn neg(mut self) -> Self {
        let negative = self.is_negative();
        self.set_negative(!negative);
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::bn::{BigNum, BigNumContext};

    #[test]
    fn parses_only_complete_signed_integers() {
        for invalid in ["", "-", "12x", "+1", " 12", "12 ", "12\\0"] {
            assert!(BigNum::from_dec_str(invalid).is_err(), "{invalid:?}");
        }
        for invalid in ["", "-", "0x12", "1g", " 12", "12 ", "12\\0"] {
            assert!(BigNum::from_hex_str(invalid).is_err(), "{invalid:?}");
        }
        assert_eq!(
            BigNum::from_dec_str("-255").unwrap(),
            BigNum::from_hex_str("-fF").unwrap()
        );
        assert_eq!(BigNum::from_dec_str("-0").unwrap(), BigNum::new().unwrap());
    }

    #[test]
    fn arithmetic_propagates_native_failure() {
        let one = BigNum::from_u32(1).unwrap();
        let zero = BigNum::new().unwrap();
        assert!((&one / &zero).is_err());
        assert!((&one % &zero).is_err());
        assert_eq!((&one + &one).unwrap(), BigNum::from_u32(2).unwrap());
        assert_eq!((-&one).unwrap(), -one);
    }

    #[test]
    fn serialization_uses_exact_native_sizes() {
        for (bytes, bits) in [(&[][..], 0), (&[0x80][..], 8), (&[0x01, 0][..], 9)] {
            let value = BigNum::from_slice(bytes).unwrap();
            assert_eq!(value.num_bits(), bits);
            assert_eq!(value.num_bytes(), bytes.len());
            assert_eq!(value.to_vec(), bytes);
        }
        let value = BigNum::from_u32(256).unwrap();
        assert!(value.to_vec_padded(1).is_err());
        assert_eq!(value.to_vec_padded(3).unwrap(), [0, 1, 0]);
    }

    #[test]
    fn test_to_from_slice() {
        let mut v0 = BigNum::from_u32(10_203_004).unwrap();
        let vec = v0.to_vec();
        let v1 = BigNum::from_slice(&vec).unwrap();
        assert_eq!(v0, v1);

        v0.copy_from_slice(&[0x12, 0, 0x34]).unwrap();
        assert_eq!(v0, BigNum::from_u32(0x12_0034).unwrap());
        v0.copy_from_slice(&[0xff]).unwrap();
        assert_eq!(v0, BigNum::from_u32(0xff).unwrap());
    }

    #[test]
    fn test_negation() {
        let a = BigNum::from_u32(909_829_283).unwrap();

        assert!(!a.is_negative());
        assert!((-a).is_negative());
    }

    #[test]
    fn test_shift() {
        let a = BigNum::from_u32(909_829_283).unwrap();

        assert_eq!(a, (&(&a << 1).unwrap() >> 1).unwrap());
    }

    #[test]
    fn test_rand_range() {
        let range = BigNum::from_u32(909_829_283).unwrap();
        let mut result = BigNum::from_dec_str(&range.to_dec_str().unwrap()).unwrap();
        range.rand_range(&mut result).unwrap();
        assert!(result >= BigNum::from_u32(0).unwrap() && result < range);
    }

    #[test]
    fn test_prime_numbers() {
        let a = BigNum::from_u32(19_029_017).unwrap();
        let mut p = BigNum::new().unwrap();
        p.generate_prime(128, true, None, Some(&a)).unwrap();

        let mut ctx = BigNumContext::new().unwrap();
        assert!(p.is_prime(100, &mut ctx, false).unwrap());
        assert!(p.is_prime(100, &mut ctx, true).unwrap());
    }

    #[test]
    fn test_mod_sqrt() {
        let mut ctx = BigNumContext::new().unwrap();

        // 2 is a quadratic residue mod 0x7DEB1 (a prime)
        let s = BigNum::from_hex_str("2").unwrap();
        let p = BigNum::from_hex_str("7DEB1").unwrap();
        let mut sqrt = BigNum::new().unwrap();
        let mut out = BigNum::new().unwrap();

        // Square the root since there are two possible roots; verify the square equals s mod p
        sqrt.mod_sqrt(&s, &p, &mut ctx).unwrap();
        out.mod_sqr(&sqrt, &p, &mut ctx).unwrap();
        assert_eq!(out, s);

        // 3 is not a quadratic residue mod 5, so mod_sqrt must fail
        let non_residue = BigNum::from_hex_str("3").unwrap();
        let p5 = BigNum::from_hex_str("5").unwrap();
        assert!(out.mod_sqrt(&non_residue, &p5, &mut ctx).is_err());
    }
}
