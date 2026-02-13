use core::ptr;

use crate::{
    Process, ProcessError, Result,
    iter::thread::ThreadView,
    windows::{
        constants::STATUS_INFO_LENGTH_MISMATCH, flags::ProcessAccess,
        structs::SystemProcessInformation, utils::unicode_to_string,
        wrappers::nt_query_system_information,
    },
};

/// Represents information regarding a system process
/// that has not been opened to a handle.
pub struct ProcessView {
    /// The process's unique identifier.
    pub pid: u32,

    /// The file name of the executable image.
    pub name: String,

    /// Threads running in the process.
    pub threads: Vec<ThreadView>,
}

impl core::fmt::Debug for ProcessView {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} ({}): {} threads",
            self.name,
            self.pid,
            self.threads.len()
        )
    }
}

impl ProcessView {
    #[inline(always)]
    pub fn open(&self, access: ProcessAccess) -> Result<Process> {
        Process::open(self.pid, access)
    }
}

/// Iterates all system processes.
pub struct ProcessIterator {
    _data: Box<[u8]>, // we need to keep this alive because ptr points to the data
    ptr: *const SystemProcessInformation,
    finished: bool,
}

impl ProcessIterator {
    pub fn new() -> Result<Self> {
        let mut size = 0u32;
        // first call to get the length of the buffer
        nt_query_system_information(
            0x05, // SystemProcessInformation
            ptr::null_mut(),
            size as _,
            &mut size,
        );

        loop {
            let mut data = vec![0u8; size as usize];
            let status = nt_query_system_information(
                0x05, // SystemProcessInformation
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

            // put data on the heap
            let data = data.into_boxed_slice();
            let ptr = data.as_ptr() as *const SystemProcessInformation;

            return Ok(Self {
                _data: data,
                ptr,
                finished: false,
            });
        }
    }

    pub fn find_first_named(name: &str) -> Result<ProcessView> {
        Self::new()?
            .find(|proc| proc.name == name)
            .ok_or(ProcessError::ProcessNotFound(name.to_string()))
    }
}

impl Iterator for ProcessIterator {
    type Item = ProcessView;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        // Safety:
        // self.ptr points into self._data which was initialized when
        // the struct was created and is valid for the entire lifetime duration
        let info = unsafe { &*self.ptr };

		// read basic information
        let pid = info.unique_process_id as u32;
        let name = unicode_to_string(&info.image_name);
        let thread_count = info.number_of_threads;

        if info.next_entry_offset == 0 {
            // finished
            self.finished = true;
        } else {
            // Safety:
            // we validated that next entry offset is non-zero, which, in that case
            // would be the end of the entries
            unsafe {
                self.ptr = self.ptr.byte_add(info.next_entry_offset as usize);
            }
        }

        // Safety:
        // we know the number of threads (SystemProcessInformation->number_of_threads)
        let threads =
            unsafe { core::slice::from_raw_parts(info.threads.as_ptr(), thread_count as usize) };

        // convert threads
        let threads = threads
            .iter()
            .map(|info| ThreadView::from_raw_system_thread_info(pid, info))
            .collect();

        Some(ProcessView {
            pid,
            name,
            threads,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::iter::process::ProcessIterator;

    #[test]
    fn iter_processes() {
        assert!(
            ProcessIterator::new()
                .expect("failed to create process iterator")
                .any(|process| process.name == "System"),
            "system process not found"
        );
    }
}
