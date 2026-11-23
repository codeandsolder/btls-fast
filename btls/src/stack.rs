use crate::ffi;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use libc::size_t;
use std::borrow::Borrow;
use std::convert::AsRef;
use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::ops::{Deref, Index, Range};

use crate::error::ErrorStack;
use crate::{cvt_0, cvt_p};

use crate::ffi::{
    sk_free as OPENSSL_sk_free, sk_new_null as OPENSSL_sk_new_null, sk_num as OPENSSL_sk_num,
    sk_pop as OPENSSL_sk_pop, sk_push as OPENSSL_sk_push, sk_value as OPENSSL_sk_value,
    _STACK as OPENSSL_STACK,
};

/// Trait implemented by types which can be placed in a stack.
///
/// # Safety
///
/// The associated native stack type must hold elements of this exact native
/// type. Every occupied element must be non-null and valid for shared access.
/// An owned stack holds one independently releasable ownership reference per
/// element (including no-op ownership of static native descriptors).
pub unsafe trait Stackable: ForeignType {
    /// The C stack type for this element.
    ///
    /// Generally called `stack_st_{ELEMENT_TYPE}`, normally hidden by the
    /// `STACK_OF(ELEMENT_TYPE)` macro in the OpenSSL API.
    type StackType;
}

/// An owned stack of `T`.
pub struct Stack<T: Stackable>(*mut T::StackType);

// SAFETY: the owned container and all its element ownership references move together.
unsafe impl<T: Stackable + Send> Send for Stack<T> {}
// SAFETY: shared container access is read-only; borrowed elements must support
// shared access across threads.
unsafe impl<T: Stackable + Sync> Sync for Stack<T> where T::Ref: Sync {}

impl<T> fmt::Debug for Stack<T>
where
    T: Stackable,
    T::Ref: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_list().entries(self).finish()
    }
}
impl<T: Stackable> Drop for Stack<T> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
        // SAFETY: all owned elements have been removed; this releases only
        // the now-empty native container.
        unsafe { OPENSSL_sk_free(self.0.cast()) };
    }
}

impl<T: Stackable> Stack<T> {
    /// Allocates an empty native stack.
    ///
    /// # Errors
    ///
    /// The native container allocation fails.
    pub fn new() -> Result<Self, ErrorStack> {
        ffi::init();
        // SAFETY: the constructor returns an owned empty native stack or null.
        let ptr = unsafe { cvt_p(OPENSSL_sk_new_null())? };
        Ok(Self(ptr.cast()))
    }

    /// Pushes an owned element onto the stack.
    ///
    /// # Errors
    ///
    /// The native container cannot allocate storage for the element.
    pub fn push(&mut self, data: T) -> Result<(), ErrorStack> {
        // SAFETY: self exclusively owns the container and data holds a matching
        // element ownership reference. Transfer it only after successful insertion.
        unsafe { cvt_0(OPENSSL_sk_push(self.0.cast(), data.as_ptr().cast()))? };
        let _ = data.into_ptr();
        Ok(())
    }

    /// Removes the last element and transfers its ownership reference.
    pub fn pop(&mut self) -> Option<T> {
        // SAFETY: only this owner can mutate the container. A non-null result
        // transfers the stored native ownership reference.
        unsafe {
            let ptr = OPENSSL_sk_pop(self.0.cast());
            if ptr.is_null() {
                None
            } else {
                Some(T::from_ptr(ptr.cast()))
            }
        }
    }
}

impl<T: Stackable> IntoIterator for Stack<T> {
    type IntoIter = IntoIter<T>;
    type Item = T;

    fn into_iter(self) -> IntoIter<T> {
        let it = IntoIter {
            stack: self.0,
            idxs: 0..self.len(),
        };
        mem::forget(self);
        it
    }
}

impl<T: Stackable> AsRef<StackRef<T>> for Stack<T> {
    fn as_ref(&self) -> &StackRef<T> {
        self
    }
}

impl<T: Stackable> Borrow<StackRef<T>> for Stack<T> {
    fn borrow(&self) -> &StackRef<T> {
        self
    }
}

// SAFETY: the wrapper preserves the exact native address and its owned element
// references; into_ptr transfers them without dropping.
unsafe impl<T: Stackable> ForeignType for Stack<T> {
    type CType = T::StackType;
    type Ref = StackRef<T>;

    #[inline]
    unsafe fn from_ptr(ptr: *mut T::StackType) -> Self {
        Self(ptr)
    }

    #[inline]
    fn as_ptr(&self) -> *mut T::StackType {
        self.0
    }
}

impl<T: Stackable> Deref for Stack<T> {
    type Target = StackRef<T>;

    fn deref(&self) -> &StackRef<T> {
        // SAFETY: self owns the container, which remains live throughout the borrow.
        unsafe { StackRef::from_ptr(self.0) }
    }
}

pub struct IntoIter<T: Stackable> {
    stack: *mut T::StackType,
    idxs: Range<size_t>,
}

impl<T: Stackable> Drop for IntoIter<T> {
    fn drop(&mut self) {
        for _ in &mut *self {}
        // SAFETY: every element ownership reference was transferred or released.
        // sk_free releases only the original container, not its elements.
        unsafe { OPENSSL_sk_free(self.stack.cast()) };
    }
}

impl<T: Stackable> IntoIter<T> {
    fn take_element(&mut self, next: impl FnOnce(&mut Range<usize>) -> Option<usize>) -> Option<T> {
        let index = next(&mut self.idxs)?;
        // SAFETY: the iterator exclusively owns the container, and both call
        // sites advance the disjoint shrinking range exactly once per index.
        // sk_free never releases the element pointers.
        Some(unsafe { T::from_ptr(OPENSSL_sk_value(self.stack.cast(), index).cast()) })
    }
}

impl<T: Stackable> Iterator for IntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        self.take_element(Iterator::next)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.idxs.size_hint()
    }
}

impl<T: Stackable> DoubleEndedIterator for IntoIter<T> {
    fn next_back(&mut self) -> Option<T> {
        self.take_element(DoubleEndedIterator::next_back)
    }
}

impl<T: Stackable> ExactSizeIterator for IntoIter<T> {}

pub struct StackRef<T: Stackable>(Opaque, PhantomData<fn() -> T>);

// SAFETY: StackRef exposes only shared element references, which must support
// concurrent access when the stack reference moves between threads.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "Opaque deliberately blocks auto-Send; native stack access remains shared and requires Sync elements"
)]
unsafe impl<T: Stackable> Send for StackRef<T> where T::Ref: Sync {}
// SAFETY: all safe access to a borrowed native stack is read-only.
unsafe impl<T: Stackable> Sync for StackRef<T> where T::Ref: Sync {}

// SAFETY: this opaque zero-sized wrapper preserves the native address and
// ForeignTypeRef's caller-supplied lifetime.
unsafe impl<T: Stackable> ForeignTypeRef for StackRef<T> {
    type CType = T::StackType;
}

impl<T: Stackable> StackRef<T> {
    fn as_stack(&self) -> *mut OPENSSL_STACK {
        self.as_ptr().cast()
    }

    /// Returns the number of items in the stack.
    #[must_use = "Use the returned length or capacity to size buffers or validate input."]
    pub fn len(&self) -> usize {
        // SAFETY: self borrows a live native stack throughout the call.
        unsafe { OPENSSL_sk_num(self.as_stack()) }
    }

    /// Determines if the stack is empty.
    #[must_use = "Use this predicate to decide how to handle the current value or connection."]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use = "Use the returned iterator or element to inspect the collection."]
    pub fn iter(&self) -> Iter<'_, T> {
        Iter {
            stack: self,
            idxs: 0..self.len(),
        }
    }

    /// Returns a reference to the element at the given index in the
    /// stack or `None` if the index is out of bounds
    #[must_use = "Use the returned iterator or element to inspect the collection."]
    pub fn get(&self, idx: usize) -> Option<&T::Ref> {
        if idx >= self.len() {
            return None;
        }
        // SAFETY: the explicit bounds check establishes an occupied index.
        Some(unsafe { self.element_unchecked(idx) })
    }

    // The caller must establish that idx is in bounds in this stack.
    unsafe fn element_unchecked(&self, idx: usize) -> &T::Ref {
        // SAFETY: the caller establishes bounds and Stackable guarantees the
        // live element of the matching type throughout the shared borrow.
        unsafe { T::Ref::from_ptr(OPENSSL_sk_value(self.as_stack(), idx).cast()) }
    }
}

impl<T: Stackable> Index<usize> for StackRef<T> {
    type Output = T::Ref;

    fn index(&self, index: usize) -> &T::Ref {
        // Index implements the standard Rust bounds-checked panic contract.
        assert!(index < self.len(), "native stack index out of bounds");
        // SAFETY: the check establishes an occupied index in the live stack.
        unsafe { self.element_unchecked(index) }
    }
}

impl<'a, T: Stackable> IntoIterator for &'a StackRef<T> {
    type Item = &'a T::Ref;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

impl<'a, T: Stackable> IntoIterator for &'a Stack<T> {
    type Item = &'a T::Ref;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

/// An iterator over the stack's contents.
pub struct Iter<'a, T: Stackable> {
    stack: &'a StackRef<T>,
    idxs: Range<size_t>,
}

impl<'a, T: Stackable> Iterator for Iter<'a, T> {
    type Item = &'a T::Ref;

    fn next(&mut self) -> Option<&'a T::Ref> {
        let index = self.idxs.next()?;
        // SAFETY: idxs was bounded by the length of the immutably borrowed stack.
        Some(unsafe { self.stack.element_unchecked(index) })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.idxs.size_hint()
    }
}

impl<'a, T: Stackable> DoubleEndedIterator for Iter<'a, T> {
    fn next_back(&mut self) -> Option<&'a T::Ref> {
        let index = self.idxs.next_back()?;
        // SAFETY: idxs was bounded by the length of the immutably borrowed stack.
        Some(unsafe { self.stack.element_unchecked(index) })
    }
}

impl<T: Stackable> ExactSizeIterator for Iter<'_, T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::X509;

    #[test]
    fn shared_elements_and_owned_removal() {
        let cert = X509::from_pem(include_bytes!("../test/cert.pem")).unwrap();
        let mut stack = Stack::new().unwrap();
        stack.push(cert.clone()).unwrap();
        stack.push(cert.clone()).unwrap();
        let first = stack.get(0).unwrap();
        let second = stack.get(1).unwrap();
        assert_eq!(first.as_ptr(), second.as_ptr());
        assert_eq!(first.as_ptr(), cert.as_ptr());
        assert!(stack.get(2).is_none());
        let removed = stack.pop().unwrap();
        assert_eq!(removed.as_ptr(), cert.as_ptr());
        let mut iter = stack.into_iter();
        assert_eq!(iter.next_back().unwrap().as_ptr(), cert.as_ptr());
        assert!(iter.next().is_none());
        assert!(!cert.to_der().unwrap().is_empty());
    }
}
