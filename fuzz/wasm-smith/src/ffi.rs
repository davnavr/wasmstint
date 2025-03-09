use std::ptr::NonNull;

#[repr(C)]
pub struct FfiSlice<T> {
    ptr: NonNull<T>,
    len: usize,
}

impl<T> FfiSlice<T> {
    pub const fn from_slice(b: &[T]) -> Self {
        Self {
            ptr: unsafe { NonNull::new_unchecked(b.as_ptr() as *mut T) },
            len: b.len(),
        }
    }

    pub const fn as_non_null_slice(self) -> NonNull<[T]> {
        NonNull::slice_from_raw_parts(self.ptr, self.len)
    }

    /// # Safety
    ///
    /// See [`NonNull::as_ref()`].
    pub const unsafe fn as_slice<'a>(self) -> &'a [T] {
        let slice = self.as_non_null_slice();
        unsafe { slice.as_ref() }
    }
}

impl<T> Clone for FfiSlice<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for FfiSlice<T> {}

#[repr(C)]
pub struct FfiVec<T> {
    items: FfiSlice<T>,
    capacity: usize,
    _phantom: std::marker::PhantomData<Vec<T>>,
}

impl<T> FfiVec<T> {
    pub fn new(v: Vec<T>) -> Self {
        let capacity = v.capacity();
        let len = v.len();
        let ptr = std::mem::ManuallyDrop::new(v).as_mut_ptr();
        Self {
            capacity,
            items: FfiSlice::<T> {
                len,
                ptr: unsafe { NonNull::<T>::new_unchecked(ptr) },
            },
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn to_vec(self) -> Vec<T> {
        let moved = std::mem::ManuallyDrop::new(self);
        unsafe {
            Vec::<T>::from_raw_parts(moved.items.ptr.as_ptr(), moved.items.len, moved.capacity)
        }
    }
}

impl<T> Drop for FfiVec<T> {
    fn drop(&mut self) {
        let to_drop: Self = std::mem::replace(self, Self::new(Vec::new()));
        _ = to_drop.to_vec();
    }
}

pub struct FfiUnstructured<'a> {
    ptr: NonNull<FfiSlice<u8>>,
    u: arbitrary::Unstructured<'a>,
}

impl FfiUnstructured<'_> {
    /// # Safety
    ///
    /// See [`NonNull::read()`] and [`NonNull::write()`].
    pub unsafe fn new(ptr: NonNull<FfiSlice<u8>>) -> Self {
        Self {
            ptr,
            u: arbitrary::Unstructured::new(unsafe { ptr.read().as_slice() }),
        }
    }
}

impl<'a> std::ops::Deref for FfiUnstructured<'a> {
    type Target = arbitrary::Unstructured<'a>;

    fn deref(&self) -> &Self::Target {
        &self.u
    }
}

impl std::ops::DerefMut for FfiUnstructured<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.u
    }
}

impl Drop for FfiUnstructured<'_> {
    fn drop(&mut self) {
        let bytes = FfiSlice::<u8>::from_slice(
            std::mem::replace(&mut self.u, arbitrary::Unstructured::new(&[])).take_rest(),
        );

        unsafe {
            self.ptr.write(bytes);
        }
    }
}
