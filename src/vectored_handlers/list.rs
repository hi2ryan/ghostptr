use core::mem::offset_of;

use crate::{
    AllocationType, MemoryProtection, Process, ProcessError,
    error::Result,
    vectored_handlers::{
        handler_type::VectoredHandlerType,
        iterator::VectoredHandlerIterator,
        utils::{
            encode_pointer, protection_write, vector_handler_list_offset,
        },
    },
    windows::{
        VectoredExceptionHandler,
        structs::{
            ListEntry, RtlVectorHandlerEntry, RtlVectorHandlerList,
        },
    },
};

#[allow(unused_imports)]
use crate::windows::flags::ProcessAccess;

/// Represents addresses used internally for vectored handlers.
#[derive(Default)]
pub struct HandlerEntryAddresses {
    /// The virtual address to write the vectored handler entry.
    /// The size of this allocation should be `40` (`0x28`) bytes or greater.
    ///
    /// If `None`, allocates memory for it.
    pub entry: Option<usize>,

    /// The virtual address to write the vectored handler ref count,
    /// stored in the entry as a pointer.
    /// The size of this allocation should be `8` (`0x8`) bytes or greater.
    ///
    /// If `None`, allocates memory for it.
    pub ref_count: Option<usize>,
}

/// Represents the vectored handlers in a process.
pub struct VectoredHandlerList<'process> {
    pub(crate) process: &'process Process,
    pub(crate) raw_list: *const RtlVectorHandlerList,
    pub(crate) cookie: u32,
}

impl<'process> VectoredHandlerList<'process> {
    /// Creates a [`VectoredHandlerList`] in a process.
    ///
    /// # Arguments
    /// `process` The process to read (and write) the vectored handler list from.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process,
    /// this method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_READ`],
    /// - [`ProcessAccess::VM_WRITE`], **and**
    /// - [`ProcessAccess::QUERY_INFORMATION`] **or** [`ProcessAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if reading or querying
    /// the process' ntdll.dll or cookie fails, potentially due to insufficient access.
    pub fn new(process: &'process Process) -> Result<Self> {
        let ntdll = process.get_module("ntdll.dll")?;
        let raw_list = ntdll.offset(vector_handler_list_offset())
            as *const RtlVectorHandlerList;
        let cookie = process.cookie()?;

        Ok(Self {
            process,
            raw_list,
            cookie,
        })
    }

    /// Adds a vectored handler entry to the process' list.
    ///
    /// # Arguments
    /// - `handler_type` The type of handler to add.
    /// - `addresses` The memory addresses used for writing the internal
    ///   data structures and appending to the list.
    /// - `handler_addr` The address of the vectored handler function.
    /// - `first` Whether to add the entry to the head of the list or the tail.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if reading or writing memory fails.
    pub fn add(
        &self,
        handler_type: VectoredHandlerType,
        addresses: HandlerEntryAddresses,
        handler_addr: VectoredExceptionHandler,
        first: bool,
    ) -> Result<()> {
        // if the entry address isnt provided, allocate memory for it
        let entry_address = match addresses.entry {
            Some(addr) => addr,
            None => {
                // fallback: allocate memory for the entry
                let allocation = self.process.alloc_mem(
                    None,
                    size_of::<RtlVectorHandlerEntry>(),
                    AllocationType::COMMIT | AllocationType::RESERVE,
                    MemoryProtection::READWRITE,
                )?;

                allocation.address
            }
        };

        // if the ref count address isnt provided, allocate memory for it
        let ref_count_address = match addresses.ref_count {
            Some(addr) => addr,
            None => {
                // fallback: allocate memory for the entry
                let allocation = self.process.alloc_mem(
                    None,
                    size_of::<u64>(),
                    AllocationType::COMMIT | AllocationType::RESERVE,
                    MemoryProtection::READWRITE,
                )?;
                allocation.address
            }
        } as *mut u64;

        // write ref count
        self.process.write_mem(ref_count_address, &1u64)?;

        let head_addr = self.list_head_addr(handler_type);
        let encoded_handler =
            encode_pointer(handler_addr as usize, self.cookie);

        if first {
            let old_head_entry_addr: usize =
                self.process.read_mem(head_addr)?;

            // create entry
            let entry = RtlVectorHandlerEntry {
                list: ListEntry {
                    next: old_head_entry_addr as *const _, // point to old head
                    prev: head_addr as *const _, // point back to list head
                },
                ref_count: ref_count_address,
                zero: 0,
                padding: 0,
                encoded_handler: encoded_handler as _,
            };

            // write entry
            self.process.write_mem(entry_address, &entry)?;

            // update head to point to new first entry
            protection_write(self.process, head_addr, &entry_address)?;

            // update old head's prev pointer to point to our new entry
            let old_head_prev_addr = old_head_entry_addr
                + offset_of!(RtlVectorHandlerEntry, list)
                + offset_of!(ListEntry, prev);
            protection_write(
                self.process,
                old_head_prev_addr,
                &entry_address,
            )?;
        } else {
            let tail_addr = head_addr + offset_of!(ListEntry, prev);

            let old_tail_entry_addr: usize =
                self.process.read_mem(tail_addr)?;

            // create entry
            let entry = RtlVectorHandlerEntry {
                list: ListEntry {
                    next: head_addr as *const _, // point to head
                    prev: old_tail_entry_addr as *const _, // point back to old tail
                },
                ref_count: ref_count_address,
                zero: 0,
                padding: 0,
                encoded_handler: encoded_handler as _,
            };

            // write entry
            self.process.write_mem(entry_address, &entry)?;

            // update tail to point to new first entry
            protection_write(self.process, tail_addr, &entry_address)?;

            // update old tail's next pointer to point to our new entry
            let old_tail_next_addr = old_tail_entry_addr
                + offset_of!(RtlVectorHandlerEntry, list)
                + offset_of!(ListEntry, next);
            protection_write(
                self.process,
                old_tail_next_addr,
                &entry_address,
            )?;
        }

        Ok(())
    }

	/// Adds a vectored handler entry to the head of the process' list.
    ///
    /// # Arguments
    /// - `handler_type` The type of handler to add.
    /// - `addresses` The memory addresses used for writing the internal
    ///   data structures and appending to the list.
    /// - `handler_addr` The address of the vectored handler function.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if reading or writing memory fails.
	#[inline(always)]
    pub fn add_first(
        &self,
        handler_type: VectoredHandlerType,
        addresses: HandlerEntryAddresses,
        handler_addr: VectoredExceptionHandler,
    ) -> Result<()> {
        self.add(handler_type, addresses, handler_addr, true)
    }

	/// Adds a vectored handler entry to the tail of the process' list.
    ///
    /// # Arguments
    /// - `handler_type` The type of handler to add.
    /// - `addresses` The memory addresses used for writing the internal
    ///   data structures and appending to the list.
    /// - `handler_addr` The address of the vectored handler function.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if reading or writing memory fails.
	#[inline(always)]
    pub fn add_last(
        &self,
        handler_type: VectoredHandlerType,
        addresses: HandlerEntryAddresses,
        handler_addr: VectoredExceptionHandler,
    ) -> Result<()> {
        self.add(handler_type, addresses, handler_addr, false)
    }

    /// Removes a vectored handler entry to the process' list.
    ///
    /// # Arguments
    /// - `handler_type` The type of handler to remove.
    /// - `handler_addr` The address of the vectored handler function.
    /// - `free_entry` Whether to free the entry's memory or not.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if reading or writing memory fails.
    pub fn remove(
        &self,
        handler_type: VectoredHandlerType,
        handler_addr: usize,
        free_entry: bool,
    ) -> Result<()> {
        let entry = self
            .iter(handler_type)?
            .find(|handler| handler.handler_addr() == handler_addr)
            .ok_or(ProcessError::VectoredHandlerNotFound(handler_addr))?;

        entry.remove(free_entry)
    }

    /// Iterates the vector handler list for a type of handler.
    ///
    /// # Arguments
    /// - `handler_type` The type of handler to iterate.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if reading or writing memory fails.
    #[inline(always)]
    pub fn iter<'handlers>(
        &'handlers self,
        handler_type: VectoredHandlerType,
    ) -> Result<VectoredHandlerIterator<'process, 'handlers>> {
        VectoredHandlerIterator::new(self, handler_type)
    }

    pub(crate) fn list_head_addr(
        &self,
        handler_type: VectoredHandlerType,
    ) -> usize {
        let list_offset = match handler_type {
            VectoredHandlerType::Exception => {
                offset_of!(RtlVectorHandlerList, veh_list)
            }
            VectoredHandlerType::Continue => {
                offset_of!(RtlVectorHandlerList, vch_list)
            }
        };
        self.raw_list as usize + list_offset
    }
}
