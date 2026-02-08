use crate::{
    error::Result,
    process::thread::Thread,
    windows::{
        flags::ThreadAccess,
        structs::{ThreadState, ThreadWaitReason},
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
    /// Opens the thread.
    pub fn open(&self, access: ThreadAccess) -> Result<Thread> {
        Thread::open(self.tid, access)
    }
}
