use core::mem::{self, offset_of};

use crate::{
    VectoredExceptionHandler,
    error::Result,
    vectored_handlers::{
        VectoredHandlerList, VectoredHandlerType,
        utils::{decode_pointer, encode_pointer, protection_write},
    },
    windows::{
        flags::FreeType,
        structs::{ListEntry, RtlVectorHandlerEntry},
    },
};

#[allow(unused_imports)]
use crate::{windows::flags::ProcessAccess, error::ProcessError};

#[derive(Clone)]
pub struct VectoredHandlerEntry<'process, 'list> {
    list: &'list VectoredHandlerList<'process>,
    handler_address: usize,

    pub raw_entry: *const RtlVectorHandlerEntry,
    pub handler_type: VectoredHandlerType,
}

impl<'process, 'list> VectoredHandlerEntry<'process, 'list> {
	/// Returns the handler of the entry as a [`usize`].
    #[inline(always)]
    pub fn handler_addr(&self) -> usize {
        self.handler_address
    }

	/// Returns the handler of the entry.
    #[inline(always)]
    pub fn handler(&self) -> VectoredExceptionHandler {
        unsafe {
            mem::transmute::<usize, VectoredExceptionHandler>(
                self.handler_address,
            )
        }
    }

	/// Writes the entry's handler address, encoding the pointer.
	///
	/// # Arguments
	/// `handler` The new vectored handler to set.
	///
	/// # Access Rights
    ///
    /// If this is a remote process,
    /// this method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_READ`],
    /// - [`ProcessAccess::VM_WRITE`],
	/// - [`ProcessAccess::VM_OPERATION`] **and**
    /// - [`ProcessAccess::QUERY_INFORMATION`] **or** [`ProcessAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if reading, protecting, or writing memory fails.
    pub fn set_handler(
        &self,
        handler: VectoredExceptionHandler,
    ) -> Result<()> {
        let encoded_handler =
            encode_pointer(handler as usize, self.list.cookie);

        protection_write(
            self.list.process,
            self.raw_entry as usize
                + offset_of!(RtlVectorHandlerEntry, encoded_handler),
            &encoded_handler,
        )
    }

	/// Reads (and decodes) the entry's handler address.
	///
	/// Only necessary if the caller believes the handler
	/// address has been modified. Otherwise, using
	/// [`VectoredHandlerEntry::handler`] or [`VectoredHandlerEntry::handler_addr`]
	/// would be more performant due to handler address caching.
    pub fn read_handler(&self) -> Result<VectoredExceptionHandler> {
        let encoded_handler_addr = (self.raw_entry as usize)
            + offset_of!(RtlVectorHandlerEntry, encoded_handler);
        let encoded_handler: usize =
            self.list.process.read_mem(encoded_handler_addr)?;

        let decoded_handler =
            decode_pointer(encoded_handler, self.list.cookie);
        Ok(unsafe {
            mem::transmute::<usize, VectoredExceptionHandler>(
                decoded_handler,
            )
        })
    }

	/// Removes the entry from the vectored handler list.
	///
	/// # Arguments
	/// - `free_entry` Frees the memory allocated to the internal RtlVectorHandlerEntry
	///
	/// # Access Rights
    ///
    /// If this is a remote process,
    /// this method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_READ`],
    /// - [`ProcessAccess::VM_WRITE`],
	/// - [`ProcessAccess::VM_OPERATION`] **and**
    /// - [`ProcessAccess::QUERY_INFORMATION`] **or** [`ProcessAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if reading, protecting, or writing memory fails.
    pub fn remove(&self, free_entry: bool) -> Result<()> {
        let process = self.list.process;
        let head_addr = self.list.list_head_addr(self.handler_type);

        let entry: ListEntry = process.read_mem(
            self.raw_entry as usize
                + offset_of!(RtlVectorHandlerEntry, list),
        )?;

        let prev = entry.prev as usize;
        let next = entry.next as usize;

        // change previous entry's next to next entry
        let prev_next_addr = if prev == head_addr {
            // prev points to list head; update head's next
            head_addr + offset_of!(ListEntry, next)
        } else {
            prev + offset_of!(RtlVectorHandlerEntry, list)
                + offset_of!(ListEntry, next)
        };
        protection_write(process, prev_next_addr, &next)?;

        // change next entry's prev to previous entry
        let next_prev_addr = if next == head_addr {
            // next points to list head; update head's tail
            head_addr + offset_of!(ListEntry, prev)
        } else {
            next + offset_of!(RtlVectorHandlerEntry, list)
                + offset_of!(ListEntry, prev)
        };
        protection_write(process, next_prev_addr, &prev)?;

        if free_entry {
			// free the entry
            process.free_mem(
                self.raw_entry as usize,
                size_of::<RtlVectorHandlerEntry>(),
                FreeType::RELEASE,
            )?;
        }

        Ok(())
    }

    #[inline(always)]
    pub(crate) fn from_raw_entry(
        list: &'list VectoredHandlerList<'process>,
        handler_type: VectoredHandlerType,
        raw_entry: *const RtlVectorHandlerEntry,
        handler_address: usize,
    ) -> Self {
        Self {
            list,
            raw_entry,
            handler_address,

            handler_type,
        }
    }
}
