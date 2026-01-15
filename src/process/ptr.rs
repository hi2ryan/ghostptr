
/// An abstraction for convenience, allowing for types such as
/// `usize`, `*const T`, `*mut T` to be utilized as an address.
pub trait AsPointer<T = u8> {
    fn as_ptr(self) -> *const T;
}

impl<T> AsPointer<T> for *const T {
    #[inline]
    fn as_ptr(self) -> *const T {
        self
    }
}

impl<T> AsPointer<T> for *mut T {
    #[inline]
    fn as_ptr(self) -> *const T {
        self as *const T
    }
}

impl<T> AsPointer<T> for usize {
    #[inline]
    fn as_ptr(self) -> *const T {
        self as *const T
    }
}
