macro_rules! private_key_from_pem {
    ($(#[$m:meta])* $n:ident, $(#[$m2:meta])* $n2:ident, $(#[$m3:meta])* $n3:ident, $t:ty, $f:path) => {
        from_pem!($(#[$m])* $n, $t, $f);

        $(#[$m2])*
        ///
        /// # Errors
        ///
        /// The passphrase contains NUL, the input is invalid, decryption fails, or allocation fails.
        pub fn $n2(pem: &[u8], passphrase: &[u8]) -> Result<$t, crate::error::ErrorStack> {
            // SAFETY: Both BIO input and C-string password live through synchronous
            // parsing. The native parser returns an owned object or null.
            unsafe {
                ffi::init();
                let bio = crate::bio::MemBioSlice::new(pem)?;
                let passphrase = ::std::ffi::CString::new(passphrase)
                    .map_err(crate::error::ErrorStack::internal_error)?;
                cvt_p($f(bio.as_ptr(),
                         ptr::null_mut(),
                         None,
                         passphrase.as_ptr().cast_mut().cast()))
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
            }
        }

        $(#[$m3])*
        ///
        /// # Errors
        ///
        /// Invalid input, an unsuccessful passphrase callback, or allocation failure.
        pub fn $n3<F>(pem: &[u8], callback: F) -> Result<$t, crate::error::ErrorStack>
            where F: FnOnce(&mut [u8]) -> Result<usize, crate::error::ErrorStack>
        {
            // SAFETY: CallbackState is exclusively borrowed for the native synchronous
            // parsing call, and its matching callback validates the output buffer.
            unsafe {
                ffi::init();
                let mut cb = crate::util::CallbackState::new(callback);
                let bio = crate::bio::MemBioSlice::new(pem)?;
                cvt_p($f(bio.as_ptr(),
                         ptr::null_mut(),
                         Some(crate::util::invoke_passwd_cb::<F>),
                         ptr::from_mut(&mut cb).cast()))
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
            }
        }
    }
}

macro_rules! private_key_to_pem {
    ($(#[$m:meta])* $n:ident, $(#[$m2:meta])* $n2:ident, $f:path) => {
        $(#[$m])*
        ///
        /// # Errors
        ///
        /// The object cannot be serialized or the native output allocation fails.
        pub fn $n(&self) -> Result<Vec<u8>, crate::error::ErrorStack> {
            // SAFETY: The borrowed native object remains valid. The owned memory BIO
            // receives output, which is copied before the BIO is released.
            unsafe {
                let bio = crate::bio::MemBio::new()?;
                cvt($f(bio.as_ptr(),
                        self.as_ptr(),
                        ptr::null(),
                        ptr::null_mut(),
                        -1,
                        None,
                        ptr::null_mut()))?;
                Ok(bio.get_buf()?.to_owned())
            }
        }

        $(#[$m2])*
        ///
        /// # Errors
        ///
        /// Unsupported encryption, invalid key data, oversized password or allocation failure.
        pub fn $n2(
            &self,
            cipher: crate::symm::Cipher,
            passphrase: &[u8]
        ) -> Result<Vec<u8>, crate::error::ErrorStack> {
            // SAFETY: The object and cipher are live; the passphrase pointer and
            // checked length describe a readable buffer. BIO owns the output.
            unsafe {
                let bio = crate::bio::MemBio::new()?;
                cvt($f(bio.as_ptr(),
                        self.as_ptr(),
                        cipher.as_ptr(),
                        passphrase.as_ptr().cast_mut().cast(),
                        crate::try_int(passphrase.len())?,
                        None,
                        ptr::null_mut()))?;
                Ok(bio.get_buf()?.to_owned())
            }
        }
    }
}

macro_rules! to_pem {
    ($(#[$m:meta])* $n:ident, $f:path) => {
        $(#[$m])*
        ///
        /// # Errors
        ///
        /// The object cannot be serialized or the native output allocation fails.
        pub fn $n(&self) -> Result<Vec<u8>, crate::error::ErrorStack> {
            // SAFETY: The borrowed native object remains valid. The owned memory BIO
            // receives output, which is copied before the BIO is released.
            unsafe {
                let bio = crate::bio::MemBio::new()?;
                cvt($f(bio.as_ptr(), self.as_ptr()))?;
                Ok(bio.get_buf()?.to_owned())
            }
        }
    }
}

macro_rules! to_der {
    ($(#[$m:meta])* $n:ident, $f:path) => {
        $(#[$m])*
        ///
        /// # Errors
        ///
        /// The native object cannot be serialized or its output allocation fails.
        pub fn $n(&self) -> Result<Vec<u8>, crate::error::ErrorStack> {
            let mut output = crate::util::NativeBuffer::new();
            // SAFETY: These are i2d_SAMPLE-compatible native encoders; passing
            // a null output slot requests an owned allocation with its actual
            // initialized byte count. self keeps the native input alive.
            unsafe {
                let len = crate::cvt_nz($f(
                    ::foreign_types::ForeignTypeRef::as_ptr(self),
                    output.output(),
                ))?;
                output.copy(len.get())
            }
        }
    };
}

macro_rules! from_der {
    ($(#[$m:meta])* $n:ident, $t:ty, $f:path, $len_ty:ty) => {
        $(#[$m])*
        ///
        /// # Errors
        ///
        /// The input length is not representable by the native decoder, the
        /// input is malformed, or it contains bytes after the decoded object.
        pub fn $n(der: &[u8]) -> Result<$t, crate::error::ErrorStack> {
            let len: $len_ty = crate::try_int(der.len())?;
            let mut input = der.as_ptr();
            crate::ffi::init();
            // SAFETY: The input is readable for len bytes. A null destination
            // requests a new native object; the decoder advances input over
            // the consumed bytes and transfers ownership of the result.
            unsafe {
                let decoded: $t = ::foreign_types::ForeignType::from_ptr(
                    crate::cvt_p($f(::std::ptr::null_mut(), &raw mut input, len))?,
                );
                if input != der.as_ptr().wrapping_add(der.len()) {
                    return Err(crate::error::ErrorStack::internal_error_str("trailing bytes after DER object"));
                }
                Ok(decoded)
            }
        }
    }
}

macro_rules! from_pem {
    ($(#[$m:meta])* $n:ident, $t:ty, $f:path) => {
        $(#[$m])*
        ///
        /// # Errors
        ///
        /// The PEM input is malformed, has an unsupported type, or allocation fails.
        pub fn $n(pem: &[u8]) -> Result<$t, crate::error::ErrorStack> {
            // SAFETY: The memory BIO borrows the input for the synchronous call.
            // A null destination requests a newly owned decoded object.
            unsafe {
                crate::init();
                let bio = crate::bio::MemBioSlice::new(pem)?;
                cvt_p($f(bio.as_ptr(), ::std::ptr::null_mut(), None, ::std::ptr::null_mut()))
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
            }
        }
    }
}

macro_rules! foreign_type_and_impl_send_sync {
    (
        $(#[$impl_attr:meta])*
        type CType = $ctype:ty;
        fn drop = $drop:expr;
        $(fn clone = $clone:expr;)*

        $(#[$owned_attr:meta])*
        pub struct $owned:ident;
    )
        => {
            foreign_type! {
                $(#[$impl_attr])*
                $(#[$owned_attr])*
                pub unsafe type $owned: Send + Sync {
                    type CType = $ctype;
                    fn drop = $drop;
                    $(fn clone = $clone;)*
                }
            }
        };
}

macro_rules! generic_foreign_type_and_impl_send_sync {
    (
        $(#[$impl_attr:meta])*
        type CType = $ctype:ty;
        fn drop = $drop:expr;

        $(#[$owned_attr:meta])*
        pub struct $owned:ident<T>;
        $(#[$borrowed_attr:meta])*
        pub struct $borrowed:ident<T>;
    ) => {
        $(#[$owned_attr])*
        pub struct $owned<T>(*mut $ctype, ::std::marker::PhantomData<fn() -> T>);

        $(#[$impl_attr])*
        // SAFETY: the owned wrapper stores the exact native pointer, transfers
        // ownership via into_ptr, and releases one owned reference through
        // the paired native free function. The reference wrapper has no data.
        unsafe impl<T> ::foreign_types::ForeignType for $owned<T> {
            type CType = $ctype;
            type Ref = $borrowed<T>;

            #[inline]
            unsafe fn from_ptr(ptr: *mut $ctype) -> $owned<T> {
                $owned(ptr, ::std::marker::PhantomData)
            }

            #[inline]
            fn as_ptr(&self) -> *mut $ctype {
                self.0
            }
        }

        impl<T> Drop for $owned<T> {
            #[inline]
            fn drop(&mut self) {
                // SAFETY: from_ptr requires an owned native reference, and
                // this destructor releases that reference exactly once.
                unsafe { $drop(self.0) }
            }
        }

        impl<T> ::std::ops::Deref for $owned<T> {
            type Target = $borrowed<T>;

            #[inline]
            fn deref(&self) -> &$borrowed<T> {
                // SAFETY: the owned native reference keeps the native key
                // alive throughout the returned borrow.
                unsafe { ::foreign_types::ForeignTypeRef::from_ptr(self.0) }
            }
        }

        impl<T> ::std::borrow::Borrow<$borrowed<T>> for $owned<T> {
            #[inline]
            fn borrow(&self) -> &$borrowed<T> {
                &**self
            }
        }

        impl<T> ::std::convert::AsRef<$borrowed<T>> for $owned<T> {
            #[inline]
            fn as_ref(&self) -> &$borrowed<T> {
                &**self
            }
        }

        $(#[$borrowed_attr])*
        pub struct $borrowed<T>(::foreign_types::Opaque, ::std::marker::PhantomData<fn() -> T>);

        $(#[$impl_attr])*
        // SAFETY: the opaque zero-sized wrapper preserves the native address
        // when constructed from a pointer; T is only a capability marker.
        unsafe impl<T> ::foreign_types::ForeignTypeRef for $borrowed<T> {
            type CType = $ctype;
        }

        // SAFETY: this macro wraps native key types whose owned references
        // can be released on any thread. T has no stored value.
        unsafe impl<T> Send for $owned<T> {}
        // SAFETY: the borrowed marker exposes no mutable native-key API;
        // the referenced key may be accessed on another thread.
        #[expect(clippy::non_send_fields_in_send_ty, reason = "Opaque intentionally lacks auto-Send; the native key type has an explicitly audited thread-safe contract")]
        unsafe impl<T> Send for $borrowed<T> {}
        // SAFETY: safe access after key construction is read-only, and
        // BoringSSL synchronizes native reference counts and internal caches.
        unsafe impl<T> Sync for $owned<T> {}
        // SAFETY: shared key references expose read-only operations with
        // the same native concurrency guarantees as the owned reference.
        unsafe impl<T> Sync for $borrowed<T> {}
    };
}

// Preserve each named native constant and its documentation without repeating
// the wrapper constructor in every declaration.
macro_rules! native_constants {
    ($( $(#[$attr:meta])* $name:ident = $value:expr; )*) => {
        $(
            $(#[$attr])*
            pub const $name: Self = Self($value);
        )*
    };
}
