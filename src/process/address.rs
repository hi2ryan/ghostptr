
/// An abstraction for convenience, allowing for types such as
/// `usize`, `*const T`, `*mut T` to be utilized as an address.
pub trait Address<T> {
    fn into_ptr(self) -> *const T;
}

impl<T> Address<T> for *const T {
    #[inline]
    fn into_ptr(self) -> *const T {
        self
    }
}

impl<T> Address<T> for *mut T {
    #[inline]
    fn into_ptr(self) -> *const T {
        self as *const T
    }
}

impl<T> Address<T> for usize {
    #[inline]
    fn into_ptr(self) -> *const T {
        self as *const T
    }
}
