use crate::error::ErrorStack;
use libc::{c_int, c_void};
use std::any::TypeId;
use std::collections::HashMap;
use std::hash::Hash;
use std::marker::PhantomData;
use std::mem;
use std::sync::{Mutex, OnceLock};

/// A slot in a type's "extra data" structure.
///
/// It is parameterized over the type containing the extra data as well as the
/// type of the data in the slot.
pub struct Index<T, U>(c_int, PhantomData<fn(T, U) -> (T, U)>);

impl<T, U> Copy for Index<T, U> {}

impl<T, U> Clone for Index<T, U> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T, U> Index<T, U> {
    /// Creates an `Index` from a raw integer index.
    ///
    /// # Safety
    ///
    /// The index must have been allocated for the exact containing type and
    /// boxed data type, with a matching native free callback. Reserved native
    /// borrowed-pointer slots must not be represented as owned indices.
    #[must_use = "Use the wrapper returned for the supplied native representation."]
    pub const unsafe fn from_raw(idx: c_int) -> Self {
        Self(idx, PhantomData)
    }

    #[must_use = "The returned native representation is needed by the caller."]
    pub const fn as_raw(self) -> c_int {
        self.0
    }
}

// A dedicated typed native slot is registered on the first successful
// installation, not when a callback merely tries to read it. Failed native
// allocations can be retried.
pub(crate) struct IndexSlot<O, T> {
    index: OnceLock<Index<O, T>>,
    registration: Mutex<()>,
    allocate: fn() -> Result<Index<O, T>, ErrorStack>,
}

impl<O, T> IndexSlot<O, T> {
    pub const fn new(allocate: fn() -> Result<Index<O, T>, ErrorStack>) -> Self {
        Self {
            index: OnceLock::new(),
            registration: Mutex::new(()),
            allocate,
        }
    }

    pub fn get(&self) -> Option<Index<O, T>> {
        self.index.get().copied()
    }

    pub fn register(&self) -> Result<Index<O, T>, ErrorStack> {
        if let Some(index) = self.get() {
            return Ok(index);
        }
        let _lock = self
            .registration
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(index) = self.get() {
            return Ok(index);
        }
        let index = (self.allocate)()?;
        Ok(*self.index.get_or_init(|| index))
    }
}

// Native method tables use monomorphized callback entrypoints. Keep a
// separate typed slot for each role and callback type, and never allocate
// a new index from a callback lookup.
pub(crate) struct IndexRegistry<O, K> {
    indices: Mutex<HashMap<(K, TypeId), c_int>>,
    owner: PhantomData<fn(O) -> O>,
}

impl<O, K: Copy + Eq + Hash> IndexRegistry<O, K> {
    pub fn new() -> Self {
        Self {
            indices: Mutex::new(HashMap::new()),
            owner: PhantomData,
        }
    }

    pub fn register<T: 'static + Send + Sync>(
        &self,
        role: K,
        allocate: fn() -> Result<Index<O, T>, ErrorStack>,
    ) -> Result<Index<O, T>, ErrorStack> {
        let mut indices = self
            .indices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let idx = match indices.entry((role, TypeId::of::<T>())) {
            std::collections::hash_map::Entry::Occupied(entry) => *entry.get(),
            std::collections::hash_map::Entry::Vacant(entry) => *entry.insert(allocate()?.as_raw()),
        };
        // SAFETY: this key is inserted only by the allocator of the exact
        // owner/type pair. The role further distinguishes callback slots.
        Ok(unsafe { Index::from_raw(idx) })
    }

    pub fn get<T: 'static + Send + Sync>(&self, role: K) -> Option<Index<O, T>> {
        let indices = self
            .indices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let &idx = indices.get(&(role, TypeId::of::<T>()))?;
        // SAFETY: register establishes the exact native owner and boxed type.
        Some(unsafe { Index::from_raw(idx) })
    }
}

// The caller must establish a live, uniquely accessible native object, a
// matching typed ex-data slot, and a setter which transfers ownership only
// on success, leaving the slot unchanged on failure.
pub(crate) unsafe fn replace_boxed<T>(
    old: *mut c_void,
    data: T,
    install: impl FnOnce(*mut c_void) -> Result<(), ErrorStack>,
) -> Result<Option<T>, ErrorStack>
where
    T: 'static + Send + Sync,
{
    if !old.is_null() {
        // SAFETY: the caller guarantees exclusive access to the matching T.
        return Ok(Some(mem::replace(unsafe { &mut *old.cast::<T>() }, data)));
    }
    let data = Box::into_raw(Box::new(data));
    if let Err(error) = install(data.cast()) {
        // SAFETY: the native setter did not accept ownership.
        unsafe { drop(Box::from_raw(data)) };
        return Err(error);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct Track(Arc<AtomicUsize>);
    impl Drop for Track {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn failed_install_releases_box() {
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: no previous slot; the simulated setter fails without
        // retaining the pointer, exactly as the native allocation failure.
        let result = unsafe {
            replace_boxed(std::ptr::null_mut(), Track(drops.clone()), |_| {
                Err(ErrorStack::internal_error_str(
                    "simulated native allocation failure",
                ))
            })
        };
        assert!(result.is_err());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
