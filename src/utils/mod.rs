use crate::{
    constants::VIRTUAL_ADDRESS_RANGE,
    windows::{
        structs::LoaderDataTableEntry,
        utils::{get_peb, unicode_to_string},
    },
};

pub mod debug_privilege;
pub use debug_privilege::{
    DebugPrivilegeGuard, disable_debug_privilege, enable_debug_privilege,
};

pub mod handle;
pub mod ptr;

pub use handle::{HandleObject, SafeHandle};
pub use ptr::AsPointer;

use crate::{
    error::{ProcessError, Result},
    windows::{Handle, wrappers::nt_close},
};

pub type AddressRange = core::ops::Range<usize>;

/// Closes a [`Handle`].
pub fn close_handle(handle: Handle) -> Result<()> {
    let status = nt_close(handle);
    if status != 0 {
        Err(ProcessError::NtStatus(status))
    } else {
        Ok(())
    }
}

/// Checks whether an `address` is within valid
/// usermode virtual address bounds.
#[inline]
pub fn is_valid_address(address: usize) -> bool {
    VIRTUAL_ADDRESS_RANGE.contains(&address)
}

/// Retrieves the base address of a module by its name.
/// If `name` is `None`, returns the base address of the current module.
/// Returns `None` if the module is not found.
pub fn get_module_base(name: Option<&str>) -> Option<*const u8> {
    unsafe {
        let peb = get_peb();
        let ldr = (*peb).ldr;

        let head = &(*ldr).in_memory_order_module_list;
        let mut current = head.next;

        while current != head {
            let entry = (current as usize
                - core::mem::offset_of!(
                    LoaderDataTableEntry,
                    in_memory_order_module_list
                )) as *const LoaderDataTableEntry;

            if let Some(name) = name {
                let dll_name = unicode_to_string(&(*entry).base_dll_name);
                if dll_name == name {
                    return Some((*entry).base_address);
                }

				current = (*current).next;
            } else {
				return Some((*entry).base_address);
			}
        }

        None
    }
}
