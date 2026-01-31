use crate::{
    Process, ProcessError, Result,
    iter::thread::ThreadView,
    process::ProcessAccess,
    windows::{
        constants::STATUS_INFO_LENGTH_MISMATCH, structs::SystemProcessInformation,
        utils::unicode_to_string, wrappers::nt_query_system_information,
    },
};

/// Represents information regarding a system process
/// that has not been opened to a handle.
pub struct ProcessView {
    /// The process's unique identifier.
    pub pid: u32,

    /// The identifier of the process that created this process.
    /// Not updated and incorrectly refers to processes with recycled identifiers.
    pub parent_pid: u32,

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
    buffer: Vec<u8>,
    offset: usize,
    finished: bool,
}

impl ProcessIterator {
    pub fn new() -> Result<Self> {
        let mut size: usize = 0;

        loop {
            let mut buffer = vec![0u8; size];
            let mut ret_len: u32 = 0;

            let status = nt_query_system_information(
                0x05, // SystemProcessInformation
                buffer.as_mut_ptr() as _,
                size as _,
                &mut ret_len,
            );

            if status == STATUS_INFO_LENGTH_MISMATCH {
                // size is already updated with the size required
                // add 8kb just in case new processes are created as we are querying
                size += 0x2000;
                continue;
            }

            if status != 0x0 {
                // success
                return Err(ProcessError::NtStatus(status));
            }

            return Ok(Self {
                buffer,
                offset: 0,
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

        unsafe {
            let base = self.buffer.as_ptr();
            let spi = &*(base.add(self.offset) as *const SystemProcessInformation);

            let pid = spi.unique_process_id as u32;
            let parent_pid = spi.inherited_from_unique_process_id as u32;
            let name = unicode_to_string(&spi.image_name);
            let thread_count = spi.number_of_threads;

            // get next offset
            if spi.next_entry_offset == 0 {
                self.finished = true;
            } else {
                self.offset += spi.next_entry_offset as usize;
            }

            let threads = core::slice::from_raw_parts(spi.threads.as_ptr(), thread_count as usize);

            // convert SystemThreadInformation to ThreadView's
            let threads = threads
                .iter()
                .map(|&info| ThreadView {
                    start_address: info.start_address as usize,
                    tid: info.client_id.unique_thread as u32,
                    priority: info.priority,
                    base_priority: info.base_priority,
                    context_switches: info.context_switches,
                    state: info.state,
                    wait_reason: info.wait_reason,
                    pid,
                })
                .collect();

            Some(ProcessView {
                pid,
                parent_pid,
                name,
                threads,
            })
        }
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
