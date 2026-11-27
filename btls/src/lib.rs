//! Bindings to `BoringSSL`
//!
//! This crate provides a safe interface to the `BoringSSL` cryptography library.
//!
//! # Versioning
//!
//! ## Crate versioning
//!
//! The crate and all the related crates (FFI bindings, etc.) are released simultaneously and all
//! bumped to the same version disregard whether particular crate has any API changes or not.
//! However, semantic versioning guarantees still hold, as all the crate versions will be updated
//! based on the crate with most significant changes.
//!
//! ## `BoringSSL` version
//!
//! By default, the crate statically links against a pinned `BoringSSL` revision, vendored as a
//! submodule at `btls-sys/deps/boringssl`. The current pin is upstream tag `0.20260929.0`.
//! *Note*: any `BoringSSL` revision bumps will be released as a major version update of all crates.
//!
//! # Compilation and linking options
//!
//! ## Environment variables
//!
//! Native source, binary and toolchain-path overrides use `BORING_BSSL_` for
//! non-FIPS builds and `BORING_BSSL_FIPS_` for FIPS builds. Runtime library and
//! compiler launcher settings apply to both configurations.
//!
//! ## Support for pre-built binaries or custom source
//!
//! While this crate can build `BoringSSL` on its own, you may want to provide pre-built binaries instead.
//! Specify `BORING_BSSL{,_FIPS}_PATH` with the path to the binaries and set
//! `BORING_BSSL{,_FIPS}_ASSUME_PATCHED=1` to confirm that the archives and their
//! headers include all required patches for the selected features.
//!
//! For prebuilt binaries only, provide matching headers by setting `BORING_BSSL{,_FIPS}_INCLUDE_PATH`.
//!
//! _Notes_: The crate will look for headers in the`$BORING_BSSL{,_FIPS}_INCLUDE_PATH/openssl/`
//! folder, make sure to place your headers there.
//!
//! In alternative a different path for the `BoringSSL` source code directory can be specified by setting
//! `BORING_BSSL{,_FIPS}_SOURCE_PATH` pointing to a prepatched source tree, together with
//! `BORING_BSSL{,_FIPS}_ASSUME_PATCHED=1`. The build compiles it without modifying its sources.
//!
//! _Warning_: Patch confirmation is an assertion by the caller, not a verification of
//! the external build. The native revision, ABI, feature flags, patches, and headers must match.
//!
//! ## Building with a FIPS-validated module
//!
//! The `fips` feature enables the native FIPS build configuration for the
//! pinned source revision. Enabling this feature does not by itself establish
//! that the resulting binary is a validated cryptographic module. Deployment
//! must separately satisfy the relevant module certificate and security policy.
//!
//! The native mode can be checked with:
//!
//! ```bash
//! cargo test --features fips fips::is_enabled
//! ```
//!
//! ## Linking with a C++ standard library
//!
//! `BoringSSL` requires a C++ runtime. The `BORING_BSSL_RUST_CPPLIB` variable
//! can override the nonempty library name. By default, libc++ is selected on
//! Apple, `FreeBSD` and `OpenBSD` targets, the NDK's shared libc++ on Android,
//! and no explicit C++ runtime on MSVC. Linux GNU/musl source builds use
//! the actual CMake-selected C++ runtime; prebuilt libraries must match
//! the selected ABI.
//!
//! On Linux GNU or musl, executables that must not depend on a shared C++
//! standard library can enable `static-cxx-runtime` (also automatic for
//! Linux targets with Rust `crt-static`). The CMake-selected
//! target compiler determines whether GNU libstdc++ or LLVM libc++ is used.
//! The corresponding static archives are bundled into the Rust native
//! dependency. A missing or ambiguous runtime is an error, never a dynamic
//! fallback. With externally built BoringSSL, supply the matching static
//! runtime archives beside libssl/libcrypto; the compiler ABI must match.
//! Use the existing runtime-name override to disambiguate if both are
//! provided. Other targets should use their normal platform runtime.
//! This feature does not statically link libc or change its minimum ABI;
//! final executable distribution still needs a compatible build sysroot.
//!
//! # Optional patches
//!
//! ## Raw Public Key
//!
//! The crate can be compiled with [RawPublicKey](https://datatracker.ietf.org/doc/html/rfc7250)
//! support by turning on `rpk` compilation feature.
//!
//! ## Post-quantum cryptography
//!
//! Upstream `BoringSSL` supports and enables `X25519MLKEM768`, the post-quantum key agreement from
//! RFC 10024, by default. btls patches `BoringSSL` to additionally support:
//!
//! - `X25519Kyber768Draft00`, under codepoint `0x6399`. This is the pre-standard predecessor of
//!   `X25519MLKEM768`. Not recommended; it's being phased out.
//! - `P256Kyber768Draft00`, under codepoint `0xfe32`, which uses P-256 as the classical part.
//!   Not recommended; it's being phased out.

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate foreign_types;
extern crate btls_sys as ffi;
extern crate libc;

#[cfg(test)]
extern crate hex;

use std::ffi::{c_int, c_long, c_void};
use std::num::NonZeroUsize;

#[doc(inline)]
pub use crate::ffi::init;

use crate::error::ErrorStack;

#[macro_use]
mod macros;

mod bio;
#[macro_use]
mod util;
pub mod aead;
pub mod aes;
pub mod asn1;
pub mod base64;
pub mod bn;
pub mod chacha;
pub mod conf;
pub mod derive;
pub mod dh;
pub mod dsa;
pub mod ec;
pub mod ecdsa;
pub mod error;
pub mod ex_data;
pub mod fips;
pub mod hash;
pub mod hkdf;
pub mod hmac;
pub mod hpke;
pub mod memcmp;
#[cfg(feature = "mldsa")]
pub mod mldsa;
#[cfg(feature = "mlkem")]
pub mod mlkem;
pub mod nid;
pub mod pkcs12;
pub mod pkcs5;
pub mod pkey;
#[cfg(feature = "prf")]
pub mod prf;
pub mod rand;
pub mod rsa;
#[cfg(any(feature = "mldsa", feature = "mlkem"))]
mod secret_material;
pub mod sha;
pub mod sign;
pub mod srtp;
pub mod ssl;
pub mod stack;
pub mod string;
pub mod symm;
pub mod version;
pub mod x509;

#[cfg(feature = "rpk")]
const fn native_u8(value: c_int) -> u8 {
    let [low, high0, high1, high2] = value.to_le_bytes();
    // Native TLS certificate-type constants must fit without truncation.
    assert!(high0 == 0 && high1 == 0 && high2 == 0);
    low
}

const fn native_u16(value: c_int) -> u16 {
    let [low, high, upper_low, upper_high] = value.to_le_bytes();
    // These conversions occur only in compile-time native protocol constants.
    assert!(upper_low == 0 && upper_high == 0);
    u16::from_le_bytes([low, high])
}

fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt_0(r: usize) -> Result<(), ErrorStack> {
    if r == 0 {
        Err(ErrorStack::get())
    } else {
        Ok(())
    }
}

fn cvt_0i(r: c_int) -> Result<c_int, ErrorStack> {
    if r == 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt(r: c_int) -> Result<(), ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(())
    }
}

fn cvt_nz(r: c_int) -> Result<NonZeroUsize, ErrorStack> {
    usize::try_from(r)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(ErrorStack::get)
}

fn cvt_n(r: c_int) -> Result<c_int, ErrorStack> {
    if r < 0 { Err(ErrorStack::get()) } else { Ok(r) }
}

fn try_int<F, T>(from: F) -> Result<T, ErrorStack>
where
    F: TryInto<T> + Send + Sync + Copy + 'static,
    T: Send + Sync + Copy + 'static,
{
    from.try_into()
        .map_err(|_| ErrorStack::internal_error_str("int overflow"))
}

unsafe extern "C" fn free_data_box<T>(
    _parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut ffi::CRYPTO_EX_DATA,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if !ptr.is_null() {
        // SAFETY: the typed index registered this exact Box<T> destructor;
        // the native container transfers its owned allocation on cleanup.
        // Contain any application destructor panic at the C ABI boundary.
        let _ = crate::util::catch_native(|| unsafe { drop(Box::<T>::from_raw(ptr.cast::<T>())) });
    }
}
