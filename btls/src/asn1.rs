#![deny(missing_docs)]

//! Defines the format of certificiates
//!
//! This module is used by [`x509`] and other certificate building functions
//! to describe time, strings, and objects.
//!
//! Abstract Syntax Notation One is an interface description language.
//! The specification comes from [X.208] by OSI, and rewritten in X.680.
//! ASN.1 describes properties of an object with a type set.  Those types
//! can be atomic, structured, choice, and other (CHOICE and ANY).  These
//! types are expressed as a number and the assignment operator ::=  gives
//! the type a name.
//!
//! The implementation here provides a subset of the ASN.1 types that OpenSSL
//! uses, especially in the properties of a certificate used in HTTPS.
//!
//! [X.208]: https://www.itu.int/rec/T-REC-X.208-198811-W/en
//! [`x509`]: ../x509/struct.X509Builder.html
//!
//! ## Examples
//!
//! ```
//! use btls::asn1::Asn1Time;
//! let tomorrow = Asn1Time::days_from_now(1);
//! ```
use crate::ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_long};
use std::cmp::Ordering;
use std::ffi::CString;
use std::fmt;
use std::ptr;
use std::slice;
use std::str;

use crate::bio::MemBio;
use crate::bn::{BigNum, BigNumRef};
use crate::error::ErrorStack;
use crate::nid::Nid;
use crate::stack::Stackable;
use crate::{cvt, cvt_p};
use openssl_macros::corresponds;

foreign_type_and_impl_send_sync! {
    type CType = ffi::ASN1_GENERALIZEDTIME;
    fn drop = ffi::ASN1_GENERALIZEDTIME_free;

    /// GeneralizedTime encoding of an ASN.1 timestamp, supporting years outside 1950–2049.
    pub struct Asn1GeneralizedTime;
}

impl Asn1GeneralizedTime {
    #[corresponds(ASN1_GENERALIZEDTIME_new)]
    fn new() -> Result<Self, ErrorStack> {
        ffi::init();

        // SAFETY: the native allocator returns an independently owned
        // generalized-time object (or null) and no borrowed pointers.
        unsafe {
            let handle = cvt_p(ffi::ASN1_GENERALIZEDTIME_new())?;
            Ok(Self::from_ptr(handle))
        }
    }
}

impl str::FromStr for Asn1GeneralizedTime {
    type Err = ErrorStack;

    /// Creates a new `Asn1GeneralizedTime` corresponding to the specified ASN1
    /// time string.
    ///
    /// The string must be a valid GeneralizedTime. Returns an error if the
    /// string is not valid.
    #[corresponds(ASN1_GENERALIZEDTIME_set_string)]
    fn from_str(s: &str) -> Result<Self, ErrorStack> {
        let time = Self::new()?;
        let s = CString::new(s).map_err(ErrorStack::internal_error)?;
        // SAFETY: the owned time is uniquely writable, and the CString
        // remains NUL-terminated and readable for native parsing.
        unsafe {
            cvt(ffi::ASN1_GENERALIZEDTIME_set_string(
                time.as_ptr(),
                s.as_ptr(),
            ))?;
            Ok(time)
        }
    }
}

impl fmt::Display for Asn1GeneralizedTimeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Ok(bio) = MemBio::new() else {
            return f.write_str("error");
        };
        // SAFETY: both native handles remain live for the synchronous
        // conversion; the BIO owns the output memory.
        if unsafe { ffi::ASN1_GENERALIZEDTIME_print(bio.as_ptr(), self.as_ptr()) } != 1 {
            return f.write_str("error");
        }
        let Ok(text) = bio.get_buf() else {
            return f.write_str("error");
        };
        f.write_str(str::from_utf8(text).unwrap_or("error"))
    }
}

/// The type of an ASN.1 value.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Asn1Type(c_int);

impl Asn1Type {
    native_constants! {
        /// End-of-contents marker.
        EOC = ffi::V_ASN1_EOC;

        /// Boolean value.
        BOOLEAN = ffi::V_ASN1_BOOLEAN;

        /// Integer value.
        INTEGER = ffi::V_ASN1_INTEGER;

        /// Bit string.
        BIT_STRING = ffi::V_ASN1_BIT_STRING;

        /// Octet string.
        OCTET_STRING = ffi::V_ASN1_OCTET_STRING;

        /// Null value.
        NULL = ffi::V_ASN1_NULL;

        /// Object identifier.
        OBJECT = ffi::V_ASN1_OBJECT;

        /// Object descriptor.
        OBJECT_DESCRIPTOR = ffi::V_ASN1_OBJECT_DESCRIPTOR;

        /// External value.
        EXTERNAL = ffi::V_ASN1_EXTERNAL;

        /// Real number.
        REAL = ffi::V_ASN1_REAL;

        /// Enumerated value.
        ENUMERATED = ffi::V_ASN1_ENUMERATED;

        /// UTF-8 string.
        UTF8STRING = ffi::V_ASN1_UTF8STRING;

        /// Ordered sequence.
        SEQUENCE = ffi::V_ASN1_SEQUENCE;

        /// Set of values.
        SET = ffi::V_ASN1_SET;

        /// Numeric string.
        NUMERICSTRING = ffi::V_ASN1_NUMERICSTRING;

        /// Printable string.
        PRINTABLESTRING = ffi::V_ASN1_PRINTABLESTRING;

        /// T.61 string.
        T61STRING = ffi::V_ASN1_T61STRING;

        /// Teletex string.
        TELETEXSTRING = ffi::V_ASN1_TELETEXSTRING;

        /// Videotex string.
        VIDEOTEXSTRING = ffi::V_ASN1_VIDEOTEXSTRING;

        /// IA5 string.
        IA5STRING = ffi::V_ASN1_IA5STRING;

        /// UTC time.
        UTCTIME = ffi::V_ASN1_UTCTIME;

        /// Generalized time.
        GENERALIZEDTIME = ffi::V_ASN1_GENERALIZEDTIME;

        /// Graphic string.
        GRAPHICSTRING = ffi::V_ASN1_GRAPHICSTRING;

        /// ISO 64 string.
        ISO64STRING = ffi::V_ASN1_ISO64STRING;

        /// Visible string.
        VISIBLESTRING = ffi::V_ASN1_VISIBLESTRING;

        /// General string.
        GENERALSTRING = ffi::V_ASN1_GENERALSTRING;

        /// Universal string.
        UNIVERSALSTRING = ffi::V_ASN1_UNIVERSALSTRING;

        /// Basic multilingual plane string.
        BMPSTRING = ffi::V_ASN1_BMPSTRING;
    }

    /// Constructs an `Asn1Type` from a raw OpenSSL value.
    #[must_use = "Use the wrapper returned for the supplied native representation."]
    pub const fn from_raw(value: c_int) -> Self {
        Self(value)
    }

    /// Returns the raw OpenSSL value represented by this type.
    #[must_use = "Use the returned native representation when crossing the native API boundary."]
    pub const fn as_raw(self) -> c_int {
        self.0
    }
}

/// Difference between two ASN1 times.
///
/// This `struct` is created by the [`diff`] method on [`Asn1TimeRef`]. See its
/// documentation for more.
///
/// [`diff`]: struct.Asn1TimeRef.html#method.diff
/// [`Asn1TimeRef`]: struct.Asn1TimeRef.html
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TimeDiff {
    /// Difference in days
    pub days: c_int,
    /// Difference in seconds.
    ///
    /// This is always less than the number of seconds in a day.
    pub secs: c_int,
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::ASN1_TIME;
    fn drop = ffi::ASN1_TIME_free;
    /// ASN.1 certificate time in UTC or GeneralizedTime representation.
    pub struct Asn1Time;
}

impl Asn1TimeRef {
    /// Find difference between two times
    #[corresponds(ASN1_TIME_diff)]
    pub fn diff(&self, compare: &Self) -> Result<TimeDiff, ErrorStack> {
        let mut days = 0;
        let mut secs = 0;
        let other = compare.as_ptr();

        // SAFETY: the two time objects remain borrowed; the native function
        // writes both local output counters on success.
        let err =
            unsafe { ffi::ASN1_TIME_diff(&raw mut days, &raw mut secs, self.as_ptr(), other) };

        match err {
            0 => Err(ErrorStack::get()),
            _ => Ok(TimeDiff { days, secs }),
        }
    }

    /// Compare two times
    #[corresponds(ASN1_TIME_compare)]
    pub fn compare(&self, other: &Self) -> Result<Ordering, ErrorStack> {
        let d = self.diff(other)?;
        if d.days > 0 || d.secs > 0 {
            return Ok(Ordering::Less);
        }
        if d.days < 0 || d.secs < 0 {
            return Ok(Ordering::Greater);
        }

        Ok(Ordering::Equal)
    }
}

impl PartialEq for Asn1TimeRef {
    fn eq(&self, other: &Self) -> bool {
        self.diff(other).is_ok_and(|t| t.days == 0 && t.secs == 0)
    }
}

impl PartialEq<Asn1Time> for Asn1TimeRef {
    fn eq(&self, other: &Asn1Time) -> bool {
        self.diff(other).is_ok_and(|t| t.days == 0 && t.secs == 0)
    }
}

impl PartialEq<Asn1Time> for &Asn1TimeRef {
    fn eq(&self, other: &Asn1Time) -> bool {
        self.diff(other).is_ok_and(|t| t.days == 0 && t.secs == 0)
    }
}

impl PartialOrd for Asn1TimeRef {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.compare(other).ok()
    }
}

impl PartialOrd<Asn1Time> for Asn1TimeRef {
    fn partial_cmp(&self, other: &Asn1Time) -> Option<Ordering> {
        self.compare(other).ok()
    }
}

impl PartialOrd<Asn1Time> for &Asn1TimeRef {
    fn partial_cmp(&self, other: &Asn1Time) -> Option<Ordering> {
        self.compare(other).ok()
    }
}

impl fmt::Display for Asn1TimeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Ok(bio) = MemBio::new() else {
            return f.write_str("error");
        };
        // SAFETY: the native time is live and shared-borrowed; the output
        // BIO is owned and remains valid for the duration of this call.
        if unsafe { ffi::ASN1_TIME_print(bio.as_ptr(), self.as_ptr()) } != 1 {
            return f.write_str("error");
        }
        let Ok(text) = bio.get_buf() else {
            return f.write_str("error");
        };
        f.write_str(str::from_utf8(text).unwrap_or("error"))
    }
}

impl fmt::Debug for Asn1TimeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Asn1Time {
    #[corresponds(ASN1_TIME_new)]
    fn new() -> Result<Self, ErrorStack> {
        ffi::init();

        // SAFETY: this allocator returns an independently owned native time.
        unsafe {
            let handle = cvt_p(ffi::ASN1_TIME_new())?;
            Ok(Self::from_ptr(handle))
        }
    }

    /// Creates a new time on the specified interval in days from now.
    ///
    /// # Errors
    ///
    /// Returns an error for an unrepresentable day offset or native conversion failure.
    pub fn days_from_now(days: u32) -> Result<Self, ErrorStack> {
        let days = c_int::try_from(days).map_err(ErrorStack::internal_error)?;
        ffi::init();
        // SAFETY: A null output requests an allocated ASN1_TIME, and a null
        // base time selects the current clock. The day offset fits C int.
        unsafe {
            let handle = cvt_p(ffi::X509_time_adj_ex(
                ptr::null_mut(),
                days,
                0,
                ptr::null_mut(),
            ))?;
            Ok(Self::from_ptr(handle))
        }
    }

    /// Creates a new time from seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns an error if the time is outside the native supported range.
    #[corresponds(ASN1_TIME_set_posix)]
    pub fn from_unix(time: i64) -> Result<Self, ErrorStack> {
        ffi::init();
        // SAFETY: The POSIX API takes a fixed-width timestamp and allocates
        // the ASN1_TIME when the output argument is null.
        unsafe {
            let handle = cvt_p(ffi::ASN1_TIME_set_posix(ptr::null_mut(), time))?;
            Ok(Self::from_ptr(handle))
        }
    }

    /// Creates a new time corresponding to the specified X509 time string.
    ///
    /// Behaves like parsing with [`str::FromStr`] except it additionally converts
    /// GeneralizedTime to UTCTime if it is in the range where UTCTime is used.
    /// See RFC 5280, section 4.1.2.5.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time syntax, embedded NUL or native allocation failure.
    #[corresponds(ASN1_TIME_set_string_X509)]
    pub fn from_str_x509(s: &str) -> Result<Self, ErrorStack> {
        let time = Self::new()?;
        let s = CString::new(s).map_err(ErrorStack::internal_error)?;
        // SAFETY: the owned time is uniquely writable, and the CString
        // outlives the synchronous native parse.
        unsafe {
            cvt(ffi::ASN1_TIME_set_string_X509(time.as_ptr(), s.as_ptr()))?;
        }
        Ok(time)
    }
}

impl str::FromStr for Asn1Time {
    type Err = ErrorStack;

    /// Creates a new time corresponding to the specified ASN1 time string.
    #[corresponds(ASN1_TIME_set_string)]
    fn from_str(s: &str) -> Result<Self, ErrorStack> {
        let time = Self::new()?;
        let s = CString::new(s).map_err(ErrorStack::internal_error)?;
        // SAFETY: the owned time is uniquely writable, and the CString
        // outlives the synchronous native parse.
        unsafe {
            cvt(ffi::ASN1_TIME_set_string(time.as_ptr(), s.as_ptr()))?;
        }
        Ok(time)
    }
}

impl PartialEq for Asn1Time {
    fn eq(&self, other: &Self) -> bool {
        self.diff(other).is_ok_and(|t| t.days == 0 && t.secs == 0)
    }
}

impl PartialEq<Asn1TimeRef> for Asn1Time {
    fn eq(&self, other: &Asn1TimeRef) -> bool {
        self.diff(other).is_ok_and(|t| t.days == 0 && t.secs == 0)
    }
}

impl<'a> PartialEq<&'a Asn1TimeRef> for Asn1Time {
    fn eq(&self, other: &&'a Asn1TimeRef) -> bool {
        self.diff(other).is_ok_and(|t| t.days == 0 && t.secs == 0)
    }
}

impl PartialOrd for Asn1Time {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.compare(other).ok()
    }
}

impl PartialOrd<Asn1TimeRef> for Asn1Time {
    fn partial_cmp(&self, other: &Asn1TimeRef) -> Option<Ordering> {
        self.compare(other).ok()
    }
}

impl<'a> PartialOrd<&'a Asn1TimeRef> for Asn1Time {
    fn partial_cmp(&self, other: &&'a Asn1TimeRef) -> Option<Ordering> {
        self.compare(other).ok()
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::ASN1_STRING;
    fn drop = ffi::ASN1_STRING_free;
    /// Owned native ASN.1 string with checked UTF-8 conversion.
    pub struct Asn1String;
}

impl Asn1StringRef {
    /// Converts the ASN.1 representation to an owned UTF-8 string,
    /// preserving embedded NUL characters.
    ///
    /// # Errors
    ///
    /// The value is not a valid ASN.1 string, conversion fails, or it is not UTF-8.
    #[corresponds(ASN1_STRING_to_UTF8)]
    pub fn as_utf8(&self) -> Result<String, ErrorStack> {
        let mut output = crate::util::NativeBuffer::new();
        // SAFETY: self borrows a live native string. On success the native call
        // transfers an allocation containing exactly the reported bytes.
        let bytes = unsafe {
            let len = ffi::ASN1_STRING_to_UTF8(output.output(), self.as_ptr());
            let len = usize::try_from(len).map_err(|_| ErrorStack::get())?;
            output.copy(len)?
        };
        String::from_utf8(bytes).map_err(ErrorStack::internal_error)
    }

    /// Return the string as an array of bytes.
    ///
    /// The bytes do not directly correspond to UTF-8 encoding.  To interact with
    /// strings in rust, it is preferable to use [`as_utf8`]
    ///
    /// [`as_utf8`]: struct.Asn1String.html#method.as_utf8
    #[corresponds(ASN1_STRING_get0_data)]
    #[must_use = "Use the borrowed ASN.1 contents while the containing value remains alive."]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: the native string is live and immutably borrowed.
        // The data pointer, when non-null, remains valid for the reported length.
        unsafe {
            let ptr = ffi::ASN1_STRING_get0_data(self.as_ptr().cast());
            if ptr.is_null() {
                return &[];
            }
            slice::from_raw_parts(ptr, self.len())
        }
    }

    /// Returns the number of bytes in the string.
    #[corresponds(ASN1_STRING_length)]
    #[must_use = "Use the returned length or capacity to size buffers or validate input."]
    pub fn len(&self) -> usize {
        // SAFETY: the shared native string is live. A malformed native length
        // cannot become a gigantic Rust slice length.
        usize::try_from(unsafe { ffi::ASN1_STRING_length(self.as_ptr()) }).unwrap_or(0)
    }

    /// Determines if the string is empty.
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for Asn1StringRef {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_utf8() {
            Ok(openssl_string) => openssl_string.fmt(fmt),
            Err(_) => fmt.write_str("error"),
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::ASN1_INTEGER;
    fn drop = ffi::ASN1_INTEGER_free;
    fn clone = ffi::ASN1_INTEGER_dup;

    /// Owned ASN.1 integer, supporting arbitrarily large signed values.
    pub struct Asn1Integer;
}

impl Asn1Integer {
    /// Converts a bignum to an `Asn1Integer`.
    ///
    /// Corresponds to [`BN_to_ASN1_INTEGER`]. Also see
    /// [`BigNumRef::to_asn1_integer`].
    ///
    /// [`BN_to_ASN1_INTEGER`]: https://www.openssl.org/docs/man1.1.0/crypto/BN_to_ASN1_INTEGER.html
    /// [`BigNumRef::to_asn1_integer`]: ../bn/struct.BigNumRef.html#method.to_asn1_integer
    ///
    /// # Errors
    ///
    /// Returns an error if native allocation or integer conversion fails.
    pub fn from_bn(bn: &BigNumRef) -> Result<Self, ErrorStack> {
        bn.to_asn1_integer()
    }
}

impl Ord for Asn1IntegerRef {
    #[corresponds(ASN1_INTEGER_cmp)]
    fn cmp(&self, other: &Self) -> Ordering {
        // SAFETY: both native integers are live and immutable for comparison.
        let res = unsafe { ffi::ASN1_INTEGER_cmp(self.as_ptr(), other.as_ptr()) };
        res.cmp(&0)
    }
}

impl PartialOrd for Asn1IntegerRef {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd<Asn1Integer> for Asn1IntegerRef {
    fn partial_cmp(&self, other: &Asn1Integer) -> Option<Ordering> {
        Some(self.cmp(&**other))
    }
}

impl Eq for Asn1IntegerRef {}

impl PartialEq for Asn1IntegerRef {
    #[corresponds(ASN1_INTEGER_cmp)]
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl PartialEq<Asn1Integer> for Asn1IntegerRef {
    fn eq(&self, other: &Asn1Integer) -> bool {
        self.eq(&**other)
    }
}

impl Ord for Asn1Integer {
    fn cmp(&self, other: &Self) -> Ordering {
        Asn1IntegerRef::cmp(self, other)
    }
}

impl PartialOrd for Asn1Integer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd<Asn1IntegerRef> for Asn1Integer {
    fn partial_cmp(&self, other: &Asn1IntegerRef) -> Option<Ordering> {
        (**self).partial_cmp(other)
    }
}

impl Eq for Asn1Integer {}

impl PartialEq for Asn1Integer {
    fn eq(&self, other: &Self) -> bool {
        Asn1IntegerRef::eq(self, other)
    }
}

impl PartialEq<Asn1IntegerRef> for Asn1Integer {
    fn eq(&self, other: &Asn1IntegerRef) -> bool {
        Asn1IntegerRef::eq(self, other)
    }
}

impl Asn1IntegerRef {
    /// Converts the integer to a `BigNum`.
    #[corresponds(ASN1_INTEGER_to_BN)]
    pub fn to_bn(&self) -> Result<BigNum, ErrorStack> {
        // SAFETY: the source remains borrowed; null destination instructs
        // the native converter to allocate a new owned big integer.
        unsafe {
            cvt_p(ffi::ASN1_INTEGER_to_BN(self.as_ptr(), ptr::null_mut()))
                .map(|p| BigNum::from_ptr(p))
        }
    }

    /// Serializes the integer as DER contents, excluding tag and length.
    ///
    /// The result is a minimal, big-endian two's complement encoding.
    ///
    /// # Errors
    ///
    /// The integer's encoded length is not representable by the native API.
    #[corresponds(i2c_ASN1_INTEGER)]
    pub fn to_der_contents(&self) -> Result<Vec<u8>, ErrorStack> {
        // SAFETY: ASN1_INTEGER is immutable while shared-borrowed.
        // i2c_ASN1_INTEGER does not allocate if its output pointer is null.
        unsafe {
            let len = crate::cvt_nz(ffi::i2c_ASN1_INTEGER(self.as_ptr(), ptr::null_mut()))?.get();
            let mut bytes = vec![0; len];
            let mut output = bytes.as_mut_ptr();
            let written =
                crate::cvt_nz(ffi::i2c_ASN1_INTEGER(self.as_ptr(), &raw mut output))?.get();
            if written != len {
                return Err(ErrorStack::internal_error_str(
                    "inconsistent ASN.1 integer length",
                ));
            }
            Ok(bytes)
        }
    }

    /// Sets the ASN.1 value to the value of a signed 32-bit integer, for larger numbers
    /// see [`bn`].
    ///
    /// [`bn`]: ../bn/struct.BigNumRef.html#method.to_asn1_integer
    #[corresponds(ASN1_INTEGER_set)]
    pub fn set(&mut self, value: i32) -> Result<(), ErrorStack> {
        // SAFETY: the integer is exclusively borrowed, and i32 fits c_long
        // on every supported target.
        unsafe { cvt(ffi::ASN1_INTEGER_set(self.as_ptr(), c_long::from(value))) }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::ASN1_BIT_STRING;
    fn drop = ffi::ASN1_BIT_STRING_free;
    /// Owned ASN.1 bit string used for certificate signatures.
    pub struct Asn1BitString;
}

impl Asn1BitStringRef {
    /// Returns the Asn1BitString as a slice.
    #[corresponds(ASN1_STRING_get0_data)]
    #[must_use = "Use the borrowed ASN.1 contents while the containing value remains alive."]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: the native string is live and immutably borrowed.
        // The data pointer, when non-null, remains valid for the reported length.
        unsafe {
            let ptr = ffi::ASN1_STRING_get0_data(self.as_ptr().cast());
            if ptr.is_null() {
                return &[];
            }
            slice::from_raw_parts(ptr, self.len())
        }
    }

    /// Returns the Asn1BitString as a str, if possible.
    #[corresponds(ASN1_STRING_get0_data)]
    #[must_use = "Use the returned UTF-8 view, or handle invalid encoding."]
    pub fn to_str(&self) -> Option<&str> {
        str::from_utf8(self.as_slice()).ok()
    }

    /// Returns the number of bytes in the string.
    #[corresponds(ASN1_STRING_length)]
    #[must_use = "Use the returned length or capacity to size buffers or validate input."]
    pub fn len(&self) -> usize {
        // SAFETY: the borrowed native bit string remains live. Negative lengths
        // are invalid and must not be reinterpreted as large slice sizes.
        usize::try_from(unsafe { ffi::ASN1_STRING_length(self.as_ptr().cast_const()) }).unwrap_or(0)
    }

    /// Determines if the string is empty.
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::ASN1_OBJECT;
    fn drop = ffi::ASN1_OBJECT_free;

    /// Owned ASN.1 object identifier with named or dotted-decimal representation.
    pub struct Asn1Object;
}

// SAFETY: the native stack type matches native ASN1_OBJECT ownership references.
unsafe impl Stackable for Asn1Object {
    type StackType = ffi::stack_st_ASN1_OBJECT;
}

impl str::FromStr for Asn1Object {
    type Err = ErrorStack;

    /// Constructs an ASN.1 Object Identifier from a string representation of the OID.
    #[corresponds(OBJ_txt2obj)]
    fn from_str(txt: &str) -> Result<Self, ErrorStack> {
        ffi::init();

        let txt = CString::new(txt).map_err(ErrorStack::internal_error)?;
        // SAFETY: native parses the live NUL-terminated input and returns
        // a newly owned OID or null without retaining the input pointer.
        unsafe {
            let obj = cvt_p(ffi::OBJ_txt2obj(txt.as_ptr(), 0))?;
            Ok(Self::from_ptr(obj))
        }
    }
}

impl Asn1ObjectRef {
    /// Returns the NID associated with this OID.
    #[must_use = "Use the returned algorithm or parameter identity when selecting or reporting cryptographic settings."]
    pub fn nid(&self) -> Nid {
        // SAFETY: the native object remains borrowed and is not mutated.
        unsafe { Nid::from_raw(ffi::OBJ_obj2nid(self.as_ptr())) }
    }
}

impl fmt::Display for Asn1ObjectRef {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SAFETY: the live borrowed object remains available throughout both
        // native queries. A null output requests the required text width.
        let length = unsafe { ffi::OBJ_obj2txt(ptr::null_mut(), 0, self.as_ptr(), 0) };
        let Ok(length) = usize::try_from(length) else {
            return fmt.write_str("error");
        };
        let Some(capacity) = length.checked_add(1) else {
            return fmt.write_str("error");
        };
        let Ok(native_capacity) = c_int::try_from(capacity) else {
            return fmt.write_str("error");
        };
        let mut buf = Vec::new();
        if buf.try_reserve_exact(capacity).is_err() {
            return fmt.write_str("error");
        }
        // SAFETY: the allocation has capacity for the entire textual value
        // including its NUL terminator. Native writes no more than that bound.
        let written =
            unsafe { ffi::OBJ_obj2txt(buf.as_mut_ptr().cast(), native_capacity, self.as_ptr(), 0) };
        if usize::try_from(written).ok() != Some(length) {
            return fmt.write_str("error");
        }
        // SAFETY: OBJ_obj2txt initialized exactly length textual bytes and a
        // terminator, but the Rust String omits the latter. The data is ASCII
        // for registered names or canonical dotted-number OIDs.
        unsafe { buf.set_len(length) };
        fmt.write_str(str::from_utf8(&buf).unwrap_or("error"))
    }
}

impl fmt::Debug for Asn1ObjectRef {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bn::BigNum;
    use crate::nid::Nid;

    #[test]
    fn object_display_does_not_truncate_long_oid() {
        let oid = format!("2.25.{}", ["123456789"; 22].join("."));
        let parsed: Asn1Object = oid.parse().unwrap();
        assert_eq!(parsed.to_string(), oid);
    }

    #[test]
    fn utf8_preserves_embedded_nul() {
        // SAFETY: allocation returns an owned ASN1_STRING; the source bytes
        // remain readable throughout ASN1_STRING_set, which copies them.
        let value = unsafe {
            let value = Asn1String::from_ptr(
                cvt_p(ffi::ASN1_STRING_type_new(ffi::V_ASN1_UTF8STRING)).unwrap(),
            );
            let bytes = b"alpha\0omega";
            cvt(ffi::ASN1_STRING_set(
                value.as_ptr(),
                bytes.as_ptr().cast(),
                11,
            ))
            .unwrap();
            value
        };
        assert_eq!(value.as_utf8().unwrap(), "alpha\0omega");
    }

    /// Tests conversion between BigNum and Asn1Integer.
    #[test]
    fn bn_cvt() {
        fn roundtrip(bn: BigNum) {
            let large = Asn1Integer::from_bn(&bn).unwrap();
            assert_eq!(large.to_bn().unwrap(), bn);
        }

        roundtrip(BigNum::from_dec_str("1000000000000000000000000000000000").unwrap());
        roundtrip(-BigNum::from_dec_str("1000000000000000000000000000000000").unwrap());
        roundtrip(BigNum::from_u32(1234).unwrap());
        roundtrip(-BigNum::from_u32(1234).unwrap());
    }

    #[test]
    fn time_from_str() {
        "99991231235959Z".parse::<Asn1Time>().unwrap();

        let time: Asn1GeneralizedTime = "20250101120000Z".parse().unwrap();
        let display = time.to_string();
        assert!(
            display.contains("2025"),
            "expected year in display: {display}"
        );

        assert!(
            <Asn1GeneralizedTime as str::FromStr>::from_str("not a time").is_err(),
            "should fail for invalid input",
        );

        // GeneralizedTime that falls in UTCTime range should be accepted
        let time = Asn1Time::from_str_x509("20250101120000Z").unwrap();
        let display = time.to_string();
        assert!(
            display.contains("2025"),
            "expected year in display: {display}"
        );

        assert!(
            Asn1Time::from_str_x509("not a time").is_err(),
            "should fail for invalid input",
        );
    }

    #[test]
    fn large_day_offset_does_not_wrap_seconds() -> Result<(), ErrorStack> {
        let now = Asn1Time::days_from_now(0)?;
        let future = Asn1Time::days_from_now(50_000)?;
        let diff = now.diff(&future)?;
        // Both timestamps come from the current clock, so crossing a second
        // boundary can change only the sub-day part.
        assert!((49_999..=50_000).contains(&diff.days));
        assert!(Asn1Time::days_from_now(u32::MAX).is_err());
        Ok(())
    }

    #[test]
    fn fixed_width_timestamp_supports_dates_after_2038() -> Result<(), ErrorStack> {
        let actual = Asn1Time::from_unix(2_147_483_648)?;
        let expected = "20380119031408Z".parse::<Asn1Time>()?;
        assert_eq!(actual.to_string(), expected.to_string());
        Ok(())
    }

    #[test]
    fn time_from_unix() {
        let t = Asn1Time::from_unix(0).unwrap();
        assert_eq!("Jan  1 00:00:00 1970 GMT", t.to_string());
    }

    #[test]
    fn time_eq() {
        let a = "99991231235959Z".parse::<Asn1Time>().unwrap();
        let b = "99991231235959Z".parse::<Asn1Time>().unwrap();
        let c = "99991231235958Z".parse::<Asn1Time>().unwrap();
        let a_ref = a.as_ref();
        let b_ref = b.as_ref();
        let c_ref = c.as_ref();
        assert!(a == b);
        assert!(a != c);
        assert!(a == b_ref);
        assert!(a != c_ref);
        assert!(b_ref == a);
        assert!(c_ref != a);
        assert_eq!(a_ref, b_ref);
        assert_ne!(a_ref, c_ref);
    }

    #[test]
    fn time_ord() {
        let a = "99991231235959Z".parse::<Asn1Time>().unwrap();
        let b = <Asn1Time as str::FromStr>::from_str("99991231235959Z").unwrap();
        let c = "99991231235958Z".parse::<Asn1Time>().unwrap();
        let a_ref = a.as_ref();
        let b_ref = b.as_ref();
        let c_ref = c.as_ref();
        assert!(a >= b);
        assert!(a > c);
        assert!(b <= a);
        assert!(c < a);

        assert!(a_ref >= b);
        assert!(a_ref > c);
        assert!(b_ref <= a);
        assert!(c_ref < a);

        assert!(a >= b_ref);
        assert!(a > c_ref);
        assert!(b <= a_ref);
        assert!(c < a_ref);

        assert!(a_ref >= b_ref);
        assert!(a_ref > c_ref);
        assert!(b_ref <= a_ref);
        assert!(c_ref < a_ref);
    }

    #[test]
    fn object_from_str() {
        let object = "2.16.840.1.101.3.4.2.1".parse::<Asn1Object>().unwrap();
        assert_eq!(object.nid(), Nid::SHA256);
    }

    #[test]
    fn object_from_str_with_invalid_input() {
        "NOT AN OID"
            .parse::<Asn1Object>()
            .map(|object| object.to_string())
            .expect_err("parsing invalid OID should fail");
    }

    #[test]
    fn integer_eq_ord() {
        let make = |n: u32| Asn1Integer::from_bn(&BigNum::from_u32(n).unwrap()).unwrap();

        let a = make(1);
        let b = make(1);
        let c = make(2);

        assert!(a == b);
        assert!(a.as_ref() == b.as_ref());
        assert!(a != c);
        assert!(*a == *b);
        assert!(*a != *c);
        assert!(a == *b);
        assert!(*a == b);
        assert!(a <= b);
        assert!(a >= b);
        assert!(a < c);
        assert!(c > a);
        assert!(*a <= *b);
        assert!(*a >= *b);
        assert!(*a < *c);
        assert!(*c > *a);
        assert!(*a <= b);
        assert!(*c > a);
    }

    #[test]
    fn integer_to_owned() {
        let bn = BigNum::from_dec_str("1234567890").unwrap();
        let orig = Asn1Integer::from_bn(&bn).unwrap();
        let copy = orig.clone();
        assert!(
            orig == copy,
            "duplicated Asn1Integer should be equal to the original"
        );
    }

    #[test]
    fn integer_to_der_contents() {
        let cases: &[(&str, &[u8])] = &[
            ("0", &[0x00]),
            ("127", &[0x7f]),
            ("128", &[0x00, 0x80]),
            ("255", &[0x00, 0xff]),
            ("256", &[0x01, 0x00]),
            ("-1", &[0xff]),
            ("-128", &[0x80]),
            ("-129", &[0xff, 0x7f]),
            ("-255", &[0xff, 0x01]),
            ("-256", &[0xff, 0x00]),
            ("18446744073709551616", &[0x01, 0, 0, 0, 0, 0, 0, 0, 0]),
            ("-18446744073709551616", &[0xff, 0, 0, 0, 0, 0, 0, 0, 0]),
        ];
        for &(value, expected) in cases {
            let bn = BigNum::from_dec_str(value).unwrap();
            let integer = Asn1Integer::from_bn(&bn).unwrap();
            assert_eq!(integer.to_der_contents().unwrap(), expected, "{value}");
        }
    }
}
