use crate::{Handle, HandleObject, ProcessError, Result, windows::wrappers::nt_close};
use core::{fmt::Debug, ops::Deref};

/// A wrapper around a `Handle` which closes the handle once
/// it is dropped.
#[repr(transparent)]
pub struct SafeHandle(pub Handle);

impl SafeHandle {
	/// Creates a `HandleObject` from this handle, consuming itself.
	#[inline(always)]
	pub fn object(self) -> HandleObject {
		HandleObject::from_handle(self.0)
	}
}

impl From<Handle> for SafeHandle {
    fn from(value: Handle) -> Self {
        Self(value)
    }
}

impl Debug for SafeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#X}", self.0)
    }
}

impl Deref for SafeHandle {
    type Target = Handle;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        nt_close(self.0);
    }
}

pub fn close_handle(handle: Handle) -> Result<()> {
    let status = nt_close(handle);
    if status != 0 {
        Err(ProcessError::NtStatus(status))
    } else {
        Ok(())
    }
}
