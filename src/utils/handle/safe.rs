use core::{ops::Deref, fmt::Debug};

use crate::windows::{Handle, wrappers::nt_close};
use super::HandleObject;

/// A wrapper around a `Handle` which closes the handle once
/// it is dropped.
#[repr(transparent)]
pub struct SafeHandle(pub Handle);

impl SafeHandle {
    /// Creates a `HandleObject` from this handle, consuming itself.
    #[inline(always)]
    pub fn to_object(self) -> HandleObject {
        HandleObject::from_handle(self.0)
    }
}

impl From<Handle> for SafeHandle {
	#[inline(always)]
    fn from(value: Handle) -> Self {
        Self(value)
    }
}

impl Debug for SafeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SafeHandle({:#X})", self.0)
    }
}

impl Deref for SafeHandle {
    type Target = Handle;

	#[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        nt_close(self.0);
    }
}
