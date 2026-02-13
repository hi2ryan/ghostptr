use crate::{
    error::Result,
    process::thread::Thread,
    windows::{
        flags::ThreadAccess,
        structs::{SystemThreadInformation, ThreadState, ThreadWaitReason},
    },
};

/// Represents information regarding a process' thread
/// that has not been opened to a handle.
pub struct ThreadView {
    /// The initial start address of the thread.
    pub start_address: usize,

    /// The identifier of the process.
    pub pid: u32,

    /// The identifier of the thread.
    pub tid: u32,

    /// The dynamic priority of the thread.
    pub priority: i32,

    /// The starting priority of the thread.
    pub base_priority: i32,

    /// The total number of context switches performed.
    pub context_switches: u32,

    /// The current state of the thread.
    pub state: ThreadState,

    /// The current reason the thread is waiting.
    pub wait_reason: ThreadWaitReason,
}

impl ThreadView {
    /// Opens the thread with the desired access.
	#[inline(always)]
    pub fn open(&self, access: ThreadAccess) -> Result<Thread> {
        Thread::open(self.tid, access)
    }

	#[inline(always)]
    pub(crate) fn from_raw_system_thread_info(pid: u32, info: &SystemThreadInformation) -> Self {
        Self {
            start_address: info.start_address as usize,
            tid: info.client_id.unique_thread as u32,
            priority: info.priority,
            base_priority: info.base_priority,
            context_switches: info.context_switches,
            state: info.state,
            wait_reason: info.wait_reason,
            pid,
        }
    }
}
