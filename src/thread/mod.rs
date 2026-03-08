pub mod wait_result;
pub use wait_result::WaitResult;

pub mod apc;
pub use apc::QueuedUserAPCParameters;

use crate::{
    ProcessError, Result,
    process::utils::ExecutionTimes,
    utils::SafeHandle,
    windows::{
        Handle, NtStatus, PsApcRoutine,
        constants::{
            CURRENT_THREAD_HANDLE, STATUS_BUFFER_OVERFLOW,
            STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH,
        },
        flags::{QueueUserAPCFlags, ThreadAccess, ThreadContextFlags},
        structs::{
            ClientId, KernelUserTimes, ObjectAttributes,
            ThreadBasicInformation, ThreadContext, ThreadEnvBlock,
            UnicodeString,
        },
        syscalls::stubs::{
            nt_alert_thread, nt_close, nt_duplicate_object,
            nt_get_context_thread, nt_open_thread,
            nt_query_information_thread, nt_queue_apc_thread_ex_2,
            nt_resume_thread, nt_set_context_thread,
            nt_set_information_thread, nt_suspend_thread,
            nt_terminate_thread, nt_wait_for_single_object,
        },
    },
};
use core::{
    fmt::Display,
    mem::{ManuallyDrop, MaybeUninit},
    ptr,
    time::Duration,
};

/// Represents an open thread handle.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Thread(Handle);

impl Display for Thread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == CURRENT_THREAD_HANDLE {
            write!(f, "Thread(Current)")
        } else {
            write!(f, "Thread({:#X})", self.0)
        }
    }
}

impl Thread {
    const CURRENT: Self = Self(CURRENT_THREAD_HANDLE);

    /// Opens the currently running thread, using a pseudo handle (`-2`).
    #[inline(always)]
    pub fn current() -> Self {
        Self::CURRENT
    }

    /// Creates a `Thread` struct based on an already
    /// open thread `Handle`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `handle` is a valid, open thread handle,
    /// with the access mask that they want.
    /// The `Thread` struct will close the thread handle when it is dropped.
    pub unsafe fn from_handle(handle: Handle) -> Self {
        Self(handle)
    }

    /// Returns the underlying process handle.
    ///
    /// # Safety
    /// The handle will be closed as the [`Thread`] is dropped.
    pub unsafe fn handle(&self) -> Handle {
        self.0
    }

    /// Consumes the [`Thread`] and returns the underlying handle without closing it.
    #[inline]
    pub fn into_handle(self) -> Handle {
        let thread = ManuallyDrop::new(self);
        thread.0
    }

    /// Consumes the [`Thread`] and returns the a [`SafeHandle`] containing
    /// the underlying thread handle.
    #[inline]
    pub fn into_safe_handle(self) -> SafeHandle {
        let thread = ManuallyDrop::new(self);
        SafeHandle::from(thread.0)
    }

    /// Opens an existing thread.
	///
	/// # Arguments
	/// - `tid` The thread identifier.
	/// - `access` The thread access mask to open the thread with.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if the thread identifier
    /// or access mask is invalid.
    pub fn open(tid: u32, access: ThreadAccess) -> Result<Self> {
        let mut attributes = ObjectAttributes::default();
        let mut client_id = ClientId {
            unique_process: 0,
            unique_thread: tid as usize,
        };

        let mut handle = 0;
        let status = nt_open_thread(
            &mut handle,
            access.bits(),
            &mut attributes,
            &mut client_id,
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        Ok(Self(handle))
    }

    /// Duplicates the underlying thread handle, creating a new
    /// [`Thread`] struct wrapping around it.
    ///
    /// This method requires an object access mask beyond standard bounds
    /// like process access and thread access. Therefore, the desired access
    /// has been kept in its raw state as a `u32`. However, if the `access` is
    /// `None`, it will copy the handle's original access mask.
    ///
    /// # Access Rights
    ///
    /// If the `src_process` is a remote process, this method
    /// requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::DUP_HANDLE`](crate::windows::flags::ProcessAccess::DUP_HANDLE)
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if duplicating the handle fails,
    /// potentially due to insufficient access rights.
    pub fn duplicate(&self, access: Option<u32>) -> Result<Thread> {
        let mut new_handle: Handle = 0;
        let status = nt_duplicate_object(
            -1isize as Handle,
            self.0,
            -1isize as Handle,
            &mut new_handle,
            access.unwrap_or(0),
            0,
            // DUPLICATE_SAME_ACCESS if access is None
            if access.is_none() { 0x2 } else { 0 },
        );

        match status {
            0 => Ok(Thread(new_handle)),
            _ => Err(ProcessError::NtStatus(status)),
        }
    }

    /// Terminates the thread.
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::TERMINATE`]
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if the thread fails to terminate,
    /// potentially due to insufficient access rights.
    pub fn terminate(&self, exit_status: NtStatus) -> Result<()> {
        let status = nt_terminate_thread(self.0, exit_status);
        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }
        Ok(())
    }

    /// Waits for the thread to enter a signaled state (like termination).
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::SYNCHRONIZE`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Arguments
    ///
    /// - `timeout`:
    ///   An optional duration to wait.
    ///   - `None` waits indefinitely.
    ///   - `Some(duration)` waits up to `duration`.
    ///
    /// - `allow_apc`:
    ///   If `true`, the wait may return early due to queued APCs.
    ///
    /// # Returns
    ///
    /// - `Ok(WaitResult::Signaled)` if the thread terminated.
    /// - `Ok(WaitResult::Timeout)` if the timeout elapsed.
    /// - `Ok(WaitResult::Alerted)` if the thread was alerted.
    /// - `Ok(WaitResult::UserAPC)` if the thread executed an user APC.
    /// - `Err(ProcessError::NtStatus(...))` for NTSTATUS failures,
    ///   possibly due to insufficient access rights.
    ///
    pub fn wait(
        &self,
        timeout: Option<Duration>,
        allow_apc: bool,
    ) -> Result<WaitResult> {
        let timeout_ptr = if let Some(d) = timeout {
            let hundred_ns = d.as_nanos() as i64 / 100;
            let nt_timeout = -hundred_ns;
            &nt_timeout as *const i64
        } else {
            core::ptr::null()
        };

        let status = nt_wait_for_single_object(
            self.0,
            allow_apc as u8,
            timeout_ptr,
        );

        match status {
            0 => Ok(WaitResult::Signaled),
            0x00000102 => Ok(WaitResult::Timeout),
            0x00000101 => Ok(WaitResult::Alerted),
            0x000000C0 => Ok(WaitResult::UserAPC),
            _ => Err(ProcessError::NtStatus(status)),
        }
    }

    /// Suspends the thread.
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::SUSPEND_RESUME`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if the thread fails to suspend,
    /// potentially due to insufficient access rights.
    /// Otherwise, the previous number of thread suspensions is returned.
    pub fn suspend(&self) -> Result<u32> {
        let mut suspend_count = 0;
        let status = nt_suspend_thread(self.0, &mut suspend_count);

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }
        Ok(suspend_count)
    }

    /// Suspends the thread.
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::SUSPEND_RESUME`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if the thread fails to resume,
    /// potentially due to insufficient access rights.
    /// Otherwise, the previous number of thread suspensions is returned.
    pub fn resume(&self) -> Result<u32> {
        let mut suspend_count = 0;
        let status = nt_resume_thread(self.0, &mut suspend_count);

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }
        Ok(suspend_count)
    }

    /// Retrieves the context of the thread.
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::GET_CONTEXT`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to retrieve the thread's context,
    /// potentially due to insufficient access rights.
    /// Otherwise, the thread's context is returned.
    pub fn context(
        &self,
        flags: ThreadContextFlags,
    ) -> Result<ThreadContext> {
        let mut ctx = unsafe { core::mem::zeroed::<ThreadContext>() };
        ctx.context_flags = flags.bits();

        let status = nt_get_context_thread(self.0, &mut ctx);
        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        Ok(ctx)
    }

    /// Sets the context of the thread.
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::SET_CONTEXT`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to set the thread's context,
    /// potentially due to insufficient access rights.
    /// Otherwise, the thread's context is returned.
    pub fn set_context(&self, ctx: &ThreadContext) -> Result<()> {
        let status = nt_set_context_thread(self.0, ctx);
        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        Ok(())
    }

    /// Retrieves the unique identifier of the thread.
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::QUERY_INFORMATION`], **or**
    /// - [`ThreadAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to query the thread's
    /// TID, potentially due to insufficient access rights.
    /// Otherwise, the thread identifier is returned as an `u32`.
    #[inline(always)]
    pub fn tid(&self) -> Result<u32> {
        self.query_info()
            .map(|info| info.client_id.unique_thread as u32)
    }

    /// Retrieves the unique identifier of the process that the
    /// thread is running under.
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::QUERY_INFORMATION`], **or**
    /// - [`ThreadAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to query the thread's
    /// PID, potentially due to insufficient access rights.
    /// Otherwise, the process identifier is returned as an `u32`.
    #[inline(always)]
    pub fn pid(&self) -> Result<u32> {
        self.query_info()
            .map(|info| info.client_id.unique_process as u32)
    }

    /// Returns a pointer to the Thread Environment Block (TEB) of
    /// the thread.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method requires
    /// one of the following access rights:
    ///
    /// - [`ThreadAccess::QUERY_INFORMATION`], **or**
    /// - [`ThreadAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without one of these rights, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if querying basic process information fails,
    /// potentially due to insufficient access rights.
    ///
    /// # Example
    ///
    /// ```rust
    /// let process = Thread::open(tid, ThreadAccess::QUERY_LIMITED_INFORMATION)?;
    /// let teb_ptr = process.teb_ptr()?;
    /// println!("TEB: {:p}", teb_ptr);
    /// ```
    #[inline]
    pub fn teb_ptr(&self) -> Result<*mut ThreadEnvBlock> {
        self.query_info().map(|info| info.teb_base_address)
    }

    /// Retrieves the current priority of the thread
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::QUERY_INFORMATION`], **or**
    /// - [`ThreadAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to query the thread's
    /// current priority, potentially due to insufficient access rights.
    /// Otherwise, the thread's current priority is returned as an `i32`.
    #[inline(always)]
    pub fn priority(&self) -> Result<i32> {
        self.query_info().map(|info| info.priority)
    }

    /// Retrieves the base priority of the thread
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::QUERY_INFORMATION`], **or**
    /// - [`ThreadAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to query the thread's
    /// base priority, potentially due to insufficient access rights.
    /// Otherwise, the thread's base priority is returned as an `i32`.
    #[inline(always)]
    pub fn base_priority(&self) -> Result<i32> {
        self.query_info().map(|info| info.base_priority)
    }

    /// Retrieves the exit status of the thread
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::QUERY_INFORMATION`], **or**
    /// - [`ThreadAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to query the thread's
    /// exit status, potentially due to insufficient access rights.
    /// Otherwise, the thread's exit status is returned as a `NTSTATUS` (`i32`).
    #[inline(always)]
    pub fn exit_status(&self) -> Result<NtStatus> {
        self.query_info().map(|info| info.exit_status)
    }

    /// Retrieves the affinity mask of the thread
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::QUERY_INFORMATION`], **or**
    /// - [`ThreadAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to query the thread's
    /// affinity mask, potentially due to insufficient access rights.
    /// Otherwise, the thread's affinity mask is returned as a `usize`.
    #[inline(always)]
    pub fn affinity_mask(&self) -> Result<usize> {
        self.query_info().map(|info| info.affinity_mask)
    }

    /// Retrieves the start address of the thread
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::QUERY_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to query the thread's
    /// start address, potentially due to insufficient access rights.
    /// Otherwise, the thread's start address is returned as a `usize`.
    pub fn start_address(&self) -> Result<usize> {
        let mut start_address: usize = 0;
        let status = nt_query_information_thread(
            self.0,
            0x9, // ThreadQuerySetWin32StartAddress
            (&mut start_address as *mut usize).cast(),
            8,
            core::ptr::null_mut(),
        );

        match status {
            0 => Ok(start_address),
            _ => Err(ProcessError::NtStatus(status)),
        }
    }

    /// Retrieves creation and executions times for the thread.
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::QUERY_INFORMATION`], **or**
    /// - [`ThreadAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to query the thread's
    /// times, potentially due to insufficient access rights.
    pub fn times(&self) -> Result<ExecutionTimes> {
        let mut times = MaybeUninit::<KernelUserTimes>::uninit();
        let status = nt_query_information_thread(
            self.0,
            0x1, // ThreadTimes
            times.as_mut_ptr().cast(),
            size_of::<KernelUserTimes>() as u32,
            ptr::null_mut(),
        );

        match status {
            0 => {
                let raw_times = unsafe { times.assume_init() };
                Ok(ExecutionTimes::from(raw_times))
            }
            _ => Err(ProcessError::NtStatus(status)),
        }
    }

    /// Retrieves the description (name) assigned to the thread.
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::QUERY_INFORMATION`], **or**
    /// - [`ThreadAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to query the thread's
    /// description, potentially due to insufficient access rights.
    pub fn description(&self) -> Result<String> {
        // initially retrieve length
        let mut len = 0;
        nt_query_information_thread(
            self.0,
            0x26, // ThreadNameInformation
            ptr::null_mut(),
            len,
            &mut len,
        );

        let mut buf = vec![0u8; len as usize];
        loop {
            let status = nt_query_information_thread(
                self.0,
                0x26, // ThreadNameInformation
                buf.as_mut_ptr().cast(),
                len,
                &mut len,
            );

            match status {
                0 => {
                    // Safety:
                    // the NtQueryInformationThread syscall returned STATUS_SUCCESS
                    // and therefore filled the buffer
                    let unicode_name = unsafe {
                        &*(buf.as_ptr() as *const UnicodeString)
                    };
                    return Ok(unicode_name.as_string_lossy());
                }
                STATUS_INFO_LENGTH_MISMATCH
                | STATUS_BUFFER_TOO_SMALL
                | STATUS_BUFFER_OVERFLOW => {
                    buf.resize(len as usize, 0);
                    continue;
                }
                _ => return Err(ProcessError::NtStatus(status)),
            }
        }
    }

    /// Assigns a description (name) to a thread.
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::SET_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to set the thread's
    /// description, potentially due to insufficient access rights.
    pub fn set_description(&self, description: &str) -> Result<()> {
        let mut buf = description.encode_utf16().collect::<Vec<_>>();
        let length = (buf.len() * 2) as u16;
        let name = UnicodeString {
            length,
            max_length: length,
            buffer: buf.as_mut_ptr(),
        };

        let status = nt_set_information_thread(
            self.0,
            0x26, // ThreadNameInformation
            (&name as *const UnicodeString) as _,
            size_of::<UnicodeString>() as u32,
        );

        match status {
            0 => Ok(()),
            _ => Err(ProcessError::NtStatus(status)),
        }
    }

    /// Assigns a description (name) to a thread according to the
    /// `bytes` provided. This method exists solely to allow using
    /// non-`str` typed description. For example, this allows
    /// shellcode thread name-calling exploitation.
    ///
    /// However, the description will stop at a null terminator.
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::SET_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to set the thread's
    /// description, potentially due to insufficient access rights.
    pub fn set_description_bytes(&self, description: &[u8]) -> Result<()> {
        let length = description.len() as u16;
        let name = UnicodeString {
            length,
            max_length: length,
            buffer: description.as_ptr() as *mut u16,
        };

        let status = nt_set_information_thread(
            self.0,
            0x26, // ThreadNameInformation
            (&name as *const UnicodeString) as _,
            size_of::<UnicodeString>() as u32,
        );

        match status {
            0 => Ok(()),
            _ => Err(ProcessError::NtStatus(status)),
        }
    }

    /// Alerts and wakes the thread. Upon waking, the thread
    /// execute any pending user-mode APCs before returning to its caller.
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::ALERT`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to alert the thread,
    /// potentially due to insufficient access rights.
    pub fn alert(&self) -> Result<()> {
        let status = nt_alert_thread(self.0);
        match status {
            0 => Ok(()),
            _ => Err(ProcessError::NtStatus(status)),
        }
    }

    /// Queues a user-mode Asynchronous Procedure Call (APC) on the thread.
    ///
    /// # Access Rights
    ///
    /// This method requires the thread handle access mask to include:
    ///
    /// - [`ThreadAccess::SET_CONTEXT`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`ProcessError::NtStatus`] if it fails to queue the APC,
    /// potentially due to insufficient access rights.
    pub fn queue_apc(
        &self,
        flags: QueueUserAPCFlags,
        routine: PsApcRoutine,
        params: QueuedUserAPCParameters,
    ) -> Result<()> {
        let status = nt_queue_apc_thread_ex_2(
            self.0,
            0,
            flags as u32,
            routine,
            params.0 as _,
            params.1 as _,
            params.2 as _,
        );

        match status {
            0 => Ok(()),
            _ => Err(ProcessError::NtStatus(status)),
        }
    }

    pub(crate) fn query_info(&self) -> Result<ThreadBasicInformation> {
        let mut info = MaybeUninit::<ThreadBasicInformation>::uninit();
        let status = nt_query_information_thread(
            self.0,
            0x0, // ThreadBasicInformation
            info.as_mut_ptr().cast(),
            size_of::<ThreadBasicInformation>() as u32,
            ptr::null_mut(),
        );

        match status {
            0 => Ok(unsafe { info.assume_init() }),
            _ => Err(ProcessError::NtStatus(status)),
        }
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        if self.0 == CURRENT_THREAD_HANDLE {
            // handle is a pseudo handle
            return;
        }

        // cleanup: close thread handle
        nt_close(self.0);
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicBool, Ordering};

    use crate::*;

    #[test]
    fn query_thread_info() -> Result<()> {
        let process = ProcessIterator::new()?
            .find(|process| process.name == "Discord.exe")
            .expect("failed to find remote process");
        let thread_view = &process.threads[0];
        let tid = thread_view.tid;
        let pid = thread_view.pid;

        let thread = thread_view.open(ThreadAccess::QUERY_INFORMATION)?;

        assert_eq!(tid, thread.tid()?, "failed to get thread id");
        assert_eq!(pid, thread.pid()?, "failed to get process id");
        assert_ne!(
            thread.start_address()?,
            0,
            "failed to get thread start address"
        );

        Ok(())
    }

    #[test]
    fn suspend_resume_thread() -> Result<()> {
        let process = Process::open_first_named(
            "Discord.exe",
            ProcessAccess::QUERY_LIMITED_INFORMATION,
        )?;

        let threads = process.threads()?;
        let thread = threads[0].open(
            ThreadAccess::SUSPEND_RESUME
                | ThreadAccess::QUERY_LIMITED_INFORMATION,
        )?;

        let old_count = thread.suspend()?;
        let new_count = thread.resume()?;

        // the thread's suspension count should increase after suspending it.
        assert!(new_count > old_count, "failed to suspend/resume thread");

        Ok(())
    }

    #[test]
    fn thread_context() -> Result<()> {
        let process = Process::open_first_named(
            "Discord.exe",
            ProcessAccess::QUERY_LIMITED_INFORMATION,
        )?;

        let threads = process.threads()?;
        let thread = threads[0].open(ThreadAccess::GET_CONTEXT)?;

        let ctx = thread.context(ThreadContextFlags::CONTROL)?;
        assert_ne!(
            ctx.rip, 0,
            "failed to get thread context: invalid rip (flags: CONTROL)"
        );
        assert_ne!(
            ctx.rsp, 0,
            "failed to get thread context: invalid rsp (flags: CONTROL)"
        );
        assert_eq!(
            ctx.rcx, 0,
            "failed to get thread context: invalid rcx (flags: CONTROL)"
        );

        Ok(())
    }

    #[test]
    fn thread_description() -> Result<()> {
        const TEST_DESCRIPTION: &str = "test description";
        let thread = Thread::current();

        let orig_description = thread.description()?;
        assert_eq!(
            orig_description, "process::thread::tests::thread_description",
            "thread description mismatched"
        );

        thread.set_description(TEST_DESCRIPTION)?;
        let new_description = thread.description()?;

        assert_eq!(
            new_description, TEST_DESCRIPTION,
            "applied thread description mismatched"
        );

        thread.set_description(&orig_description)?;

        Ok(())
    }

    #[test]
    fn thread_apcs() -> Result<()> {
        let thread = Thread::current();

        static APC_CALLED: AtomicBool = AtomicBool::new(false);

        extern "system" fn apc_handler(
            arg1: *mut (),
            arg2: *mut (),
            arg3: *mut (),
        ) {
            assert!(arg1.is_null(), "arg1 should be null");
            assert!(arg2.is_null(), "arg2 should be null");
            assert!(arg3.is_null(), "arg3 should be null");

            APC_CALLED.store(true, Ordering::Relaxed);
        }

        extern "system" fn apc_ctx_handler(
            arg1: *mut (),
            ctx: *mut ApcCallbackDataContext,
            arg3: *mut (),
        ) {
            assert!(arg1.is_null(), "arg1 should be null");
            assert!(
                !ctx.is_null(),
                "ctx (ApcCallbackDataContext) should not be null"
            );
            assert!(arg3.is_null(), "arg3 should be null");

            let context_record = unsafe { (*ctx).context_record };
            assert!(
                !context_record.is_null(),
                "context_record should not be null"
            );

            let rip = unsafe { (*context_record).rip };
            assert!(rip != 0, "CONTEXT->Rip should not be null");

            APC_CALLED.store(true, Ordering::Relaxed);
        }

        // queue APC and wait for it to be executed
        thread.queue_apc(
            QueueUserAPCFlags::None,
            apc_handler,
            QueuedUserAPCParameters::default(),
        )?;
        thread.wait(None, true)?;
        assert!(
            APC_CALLED.load(Ordering::Relaxed),
            "apc routine was not called"
        );
        APC_CALLED.store(false, Ordering::Relaxed); // reset bool

        // queue special APC and trigger it with a syscall
        thread.queue_apc(
            QueueUserAPCFlags::Special,
            apc_handler,
            QueuedUserAPCParameters::default(),
        )?;
        let _ = close_handle(0); // close invalid handle for the purpose of triggering kernel->user transition
        assert!(
            APC_CALLED.load(Ordering::Relaxed),
            "special apc routine was not called"
        );
        APC_CALLED.store(false, Ordering::Relaxed); // reset bool

        thread.queue_apc(
            QueueUserAPCFlags::CallbackDataContext,
            unsafe {
                core::mem::transmute::<*const (), PsApcRoutine>(
                    apc_ctx_handler as *const (),
                )
            },
            QueuedUserAPCParameters::default(),
        )?;
        thread.wait(None, true)?;
        assert!(
            APC_CALLED.load(Ordering::Relaxed),
            "callback context apc routine was not called"
        );

        Ok(())
    }
}
