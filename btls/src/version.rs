// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! Version and build metadata from the pinned native `BoringSSL` library.
//!
//! `BoringSSL` deliberately reports stable compatibility strings rather than
//! an OpenSSL release date or configure-time provenance.

use std::ffi::{CStr, c_int, c_ulong};

use crate::ffi::{
    OPENSSL_BUILT_ON, OPENSSL_CFLAGS, OPENSSL_DIR, OPENSSL_PLATFORM, OPENSSL_VERSION,
    OpenSSL_version, OpenSSL_version_num,
};

/// Returns the native compatibility version identifier without signed truncation.
#[must_use = "Use the returned native compatibility version for inspection or diagnostics."]
pub fn number() -> c_ulong {
    // SAFETY: this native constant-returning function has no inputs.
    unsafe { OpenSSL_version_num() }
}

// The pinned native implementation returns static NUL-terminated UTF-8
// string literals for every selector, including unknown selectors.
fn native_version_info(selector: c_int) -> &'static str {
    // SAFETY: OpenSSL_version returns a static string (see native crypto.cc).
    let data = unsafe { OpenSSL_version(selector) };
    if data.is_null() {
        return "not available";
    }
    // SAFETY: data points to a static NUL-terminated string returned by the
    // pinned native implementation, so it remains valid for program lifetime.
    unsafe { CStr::from_ptr(data) }
        .to_str()
        .unwrap_or("invalid native version metadata")
}

/// Returns the native library name (`BoringSSL` in the pinned implementation).
#[must_use = "Use the returned library name for inspection or diagnostics."]
pub fn version() -> &'static str {
    native_version_info(OPENSSL_VERSION)
}

/// Returns the native compiler metadata placeholder.
#[must_use = "Use the returned native build information for inspection or diagnostics."]
pub fn c_flags() -> &'static str {
    native_version_info(OPENSSL_CFLAGS)
}

/// Returns the native build-date placeholder.
#[must_use = "Use the returned native build information for inspection or diagnostics."]
pub fn built_on() -> &'static str {
    native_version_info(OPENSSL_BUILT_ON)
}

/// Returns the native build-platform placeholder.
#[must_use = "Use the returned native build information for inspection or diagnostics."]
pub fn platform() -> &'static str {
    native_version_info(OPENSSL_PLATFORM)
}

/// Returns the native OpenSSL directory placeholder.
#[must_use = "Use the returned native build information for inspection or diagnostics."]
pub fn dir() -> &'static str {
    native_version_info(OPENSSL_DIR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_compatibility_version_and_metadata() {
        assert!(number() > 0);
        assert_eq!(version(), "BoringSSL");
        assert!(c_flags().starts_with("compiler:"));
        assert!(built_on().starts_with("built on:"));
        assert!(platform().starts_with("platform:"));
        assert!(dir().starts_with("OPENSSLDIR:"));
    }
}
