use core::ptr;

use crate::{
    HandleObject,
    error::{ProcessError, Result},
    windows::{
        constants::STATUS_INFO_LENGTH_MISMATCH,
        structs::{SystemHandleInformationEx, SystemHandleTableEntryInfoEx},
        wrappers::nt_query_system_information,
    },
};

pub struct HandleView {
    /// Pointer to the underlying kernel object.
    pub object_ptr: usize,

    /// Process ID that owns this handle.
    pub pid: u32,

    /// The handle value as seen in the owning process.
    pub handle: usize,

    /// The raw access mask of the object handle.
    pub access: u32,

    /// Loader backtrace index
    pub creator_backtrace_index: u16,

    /// The type identifier of the object
    pub object_type_index: u16,

    /// Handle attributes (e.g., PROTECT_FROM_CLOSE, INHERIT).
    pub attributes: u32,
}

impl HandleView {
	/// Creates a [`HandleObject`] from the underlying handle value.
    #[inline(always)]
    pub fn as_object(&self) -> HandleObject {
        HandleObject::from_handle(self.handle)
    }

    #[inline(always)]
    pub(crate) fn from_raw_entry(entry: &SystemHandleTableEntryInfoEx) -> Self {
        Self {
            object_ptr: entry.object,
            pid: entry.unique_process_id as u32,
            handle: entry.handle_value,
            access: entry.granted_access,
            creator_backtrace_index: entry.creator_backtrace_index,
            object_type_index: entry.object_type_index,
            attributes: entry.handle_attributes,
        }
    }
}

/// Iterates all system handles.
pub struct HandleIterator {
    _data: Box<[u8]>,
    ptr: *const SystemHandleTableEntryInfoEx,
    idx: usize,
    len: usize,
}

impl HandleIterator {
    pub fn new() -> Result<Self> {
        let mut size = 0u32;
        nt_query_system_information(
            0x40, // SystemExtendedHandleInformation
            ptr::null_mut(),
            size,
            &mut size,
        );

        loop {
            let mut data = vec![0u8; size as usize];
            let status = nt_query_system_information(
                0x40, // SystemExtendedHandleInformation
                data.as_mut_ptr().cast(),
                size as _,
                &mut size,
            );

            if status == STATUS_INFO_LENGTH_MISMATCH {
                // retry with the updated length
                continue;
            }

            if status != 0x0 {
                // error
                return Err(ProcessError::NtStatus(status));
            }

            // put it on the heap
            let data = data.into_boxed_slice();

            // Safety:
            // we checked if NtQuerySystemInformation syscall ntstatus
            // was successful, therefore it filled the buffer
            let (len, ptr) = unsafe {
                let info = &*data.as_ptr().cast::<SystemHandleInformationEx>();
                let count = info.number_of_handles;
                let ptr = info.handles.as_ptr();

                (count, ptr)
            };

            return Ok(Self {
                _data: data,
                ptr,
                idx: 0,
                len,
            });
        }
    }
}

impl Iterator for HandleIterator {
    type Item = HandleView;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.len {
            return None;
        }

        // Safety:
        // current < len, so this index is valid within the handles array
        let raw_entry = unsafe { &*self.ptr.add(self.idx) };
        self.idx += 1;

        Some(HandleView::from_raw_entry(raw_entry))
    }
}

impl ExactSizeIterator for HandleIterator {
    fn len(&self) -> usize {
        self.len - self.idx
    }
}

#[cfg(test)]
mod tests {
    use crate::{ProcessIterator, Result, iter::handle::HandleIterator};

    #[test]
    fn process_handles() -> Result<()> {
        let target_pid = ProcessIterator::new()?
            .find(|process| process.name == "Discord.exe")
            .map(|process| process.pid)
            .expect("discord not open");

        for handle in HandleIterator::new()?
            .filter(|handle| handle.pid == target_pid)
            .map(|handle| handle.as_object())
        {
            println!("{}", handle.type_name()?);
        }

        Ok(())
    }
}
