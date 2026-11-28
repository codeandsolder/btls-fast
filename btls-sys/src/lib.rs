use std::os::raw::{c_int, c_uint};

// Only the build-generated bindings receive generated-code lint exceptions.
include!(concat!(env!("OUT_DIR"), "/bindings_module.rs"));

// explicitly require presence of some symbols to check if the bindings worked
pub use generated::{BIO_new, OPENSSL_free, SSL_ERROR_NONE}; // if these are missing, your include path is incorrect
pub use generated::{ERR_add_error_data, SSL_set1_groups, ssl_compliance_policy_t}; // if these are missing, your include path is incorrect or has a wrong version of boringssl
#[cfg(feature = "fips")]
pub use generated::{FIPS_mode, SSL_CTX_set_compliance_policy}; // your include path is incorrect or has a version of boringssl without FIPS support
#[cfg(feature = "mlkem")]
pub use generated::{MLKEM768_encap, MLKEM768_private_key_from_seed}; // your include path is incorrect or has a version of boringssl without mlkem support
#[cfg(feature = "rpk")]
pub use generated::{SSL_CREDENTIAL_new_raw_public_key_empty, SSL_CREDENTIAL_set1_spki}; // your include path is incorrect or has a version of boringssl without rpk support

#[cfg(not(feature = "fips"))]
pub use generated::{SSL_seal_app_data, SSL_seal_app_data_limits}; // your include path is incorrect or has a version of boringssl without patch 0011 (seal-app-data)

#[cfg(not(feature = "fips"))]
pub use generated::{SSL_CTX_set_ech_grease_callback, SSL_set_ech_grease_callback}; // your include path is incorrect or has a version of boringssl without patch 0013 (ech-grease-payload-policy)

pub use generated::*;
#[cfg(target_pointer_width = "64")]
#[expect(non_camel_case_types, reason = "Matches BoringSSL's C typedef.")]
pub type BN_ULONG = u64;
#[cfg(target_pointer_width = "32")]
#[expect(non_camel_case_types, reason = "Matches BoringSSL's C typedef.")]
pub type BN_ULONG = u32;

// Clang uses an unsigned underlying type for the anonymous error-library
// enum on Unix and a signed type on MSVC. Its C ABI is still a 32-bit integer.
impl ErrLib {
    /// Return the native library identifier for C functions taking an int.
    #[must_use = "The native library identifier is the result."]
    pub const fn as_signed(self) -> c_int {
        c_int::from_ne_bytes(self.0.to_ne_bytes())
    }

    /// Return the library identifier for unsigned packed-error arithmetic.
    #[must_use = "The unsigned library identifier is the result."]
    pub const fn as_unsigned(self) -> c_uint {
        c_uint::from_ne_bytes(self.0.to_ne_bytes())
    }
}

/// Pack the library and reason fields exactly as `BoringSSL`'s `ERR_PACK` macro.
/// `BoringSSL` does not encode a function identifier.
#[expect(non_snake_case, reason = "Mirrors the C macro name.")]
#[must_use = "The packed error code is the result of this operation."]
pub const fn ERR_PACK(lib: c_uint, reason: c_uint) -> c_uint {
    ((lib & 0xff) << 24) | (reason & 0xfff)
}

/// Extract the library field from a packed `BoringSSL` error.
#[expect(non_snake_case, reason = "Mirrors the C inline function name.")]
#[must_use = "The extracted library identifier is the result."]
pub const fn ERR_GET_LIB(code: c_uint) -> c_int {
    c_int::from_ne_bytes((code >> 24).to_ne_bytes())
}

/// Extract the reason field from a packed `BoringSSL` error.
#[expect(non_snake_case, reason = "Mirrors the C inline function name.")]
#[must_use = "The extracted reason identifier is the result."]
pub const fn ERR_GET_REASON(code: c_uint) -> c_int {
    c_int::from_ne_bytes((code & 0xfff).to_ne_bytes())
}

pub fn init() {
    // SAFETY: BoringSSL documents CRYPTO_library_init as an unconditional no-op.
    unsafe {
        CRYPTO_library_init();
    }
}

/// Initialize the C byte-string view, borrowing the bytes through a raw pointer.
///
/// The caller must keep the input alive for any later native use of the view.
#[inline]
#[must_use = "The initialized native byte-string view is the result."]
pub const fn cbs_init(data: &[u8]) -> CBS {
    CBS {
        data: data.as_ptr(),
        len: data.len(),
    }
}
