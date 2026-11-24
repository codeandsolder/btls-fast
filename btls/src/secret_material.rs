//! Shared ownership for expanded native post-quantum private keys.

use std::fmt;
use std::mem::{self, MaybeUninit};
use std::sync::Arc;

use crate::{error::ErrorStack, ffi};

/// An immutable native key and its seed, erased on final release.
pub(crate) struct SecretMaterial<T, const N: usize> {
    pub(crate) seed: [u8; N],
    expanded: MaybeUninit<T>,
}

impl<T, const N: usize> SecretMaterial<T, N> {
    /// Initializes secrets directly in their final allocation, avoiding temporary
    /// expanded-key copies. The allocation is cleansed even if initialization fails.
    ///
    /// # Safety
    /// T must be an opaque native key representation without owned resources.
    /// The callback must initialize a valid native key on success and must not
    /// retain either pointer after returning.
    pub(crate) unsafe fn initialize(
        initialize: impl FnOnce(&mut [u8; N], *mut T) -> Result<(), ErrorStack>,
    ) -> Result<Arc<Self>, ErrorStack> {
        let mut owner = Arc::new(Self {
            seed: [0; N],
            expanded: MaybeUninit::zeroed(),
        });
        let unique = Arc::get_mut(&mut owner)
            .ok_or_else(|| ErrorStack::internal_error_str("new key allocation is shared"))?;
        initialize(&mut unique.seed, unique.expanded.as_mut_ptr())?;
        Ok(owner)
    }

    pub(crate) const fn expanded_ptr(&self) -> *const T {
        self.expanded.as_ptr()
    }
}

impl<T, const N: usize> Drop for SecretMaterial<T, N> {
    fn drop(&mut self) {
        // SAFETY: Both regions are exclusively owned writable storage, even
        // if native initialization failed. MaybeUninit does not drop T.
        unsafe {
            ffi::OPENSSL_cleanse(self.seed.as_mut_ptr().cast(), N);
            ffi::OPENSSL_cleanse(self.expanded.as_mut_ptr().cast(), mem::size_of::<T>());
        }
    }
}

impl<T, const N: usize> fmt::Debug for SecretMaterial<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretMaterial")
            .field("key", &"[redacted]")
            .finish()
    }
}
