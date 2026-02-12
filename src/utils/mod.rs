use crate::constants::VIRTUAL_ADDRESS_RANGE;

pub mod handle;
pub mod ptr;

pub use handle::{HandleObject, SafeHandle};
pub use ptr::AsPointer;

use crate::{
    error::{ProcessError, Result},
    windows::{Handle, wrappers::nt_close},
};

pub type AddressRange = core::ops::Range<usize>;

pub fn close_handle(handle: Handle) -> Result<()> {
    let status = nt_close(handle);
    if status != 0 {
        Err(ProcessError::NtStatus(status))
    } else {
        Ok(())
    }
}

#[inline]
pub fn is_valid_address(address: usize) -> bool {
    VIRTUAL_ADDRESS_RANGE.contains(&address)
}
