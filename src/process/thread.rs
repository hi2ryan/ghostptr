use crate::{
    ProcessError, Result,
    process::{ThreadAccess, ThreadContextFlags},
    windows::{
        Handle, NtStatus,
        constants::CURRENT_THREAD_HANDLE,
        structs::{ClientId, ObjectAttributes, ThreadBasicInformation, ThreadContext},
        wrappers::{
            nt_close, nt_duplicate_object, nt_get_context_thread, nt_open_thread,
            nt_query_information_thread, nt_resume_thread, nt_set_context_thread,
            nt_suspend_thread, nt_terminate_thread, nt_wait_for_single_object,
        },
    },
};
use core::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    Signaled,
    Timeout,
}

/// Represents an open thread handle.
pub struct Thread(Handle);

impl Thread {
    /// Opens the currently running thread, using a pseudo handle (`-2`).
    pub fn current() -> Self {
        Self(CURRENT_THREAD_HANDLE)
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

    pub unsafe fn handle(&self) -> Handle {
        self.0
    }

    /// Opens an existing thread.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`]
    /// if the an invalid PID, TID, or access mask is passed.
    pub fn open(pid: u32, tid: u32, access: ThreadAccess) -> Result<Self> {
        let mut client_id = ClientId {
            unique_process: pid as usize,
            unique_thread: tid as usize,
        };

        let mut attributes = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: 0,
            object_name: core::ptr::null_mut(),
            attributes: 0,
            security_descriptor: core::ptr::null_mut(),
            security_quality_of_service: core::ptr::null_mut(),
        };

        let mut handle = 0;
        let status = nt_open_thread(&mut handle, access.bits(), &mut attributes, &mut client_id);

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        Ok(Self(handle))
    }

    pub fn duplicate(&self) -> Result<Thread> {
        let mut new_handle: Handle = 0;
        let status = nt_duplicate_object(
            -1isize as Handle,
            self.0,
            -1isize as Handle,
            &mut new_handle,
            0,
            0,
            0x2, // DUPLICATE_SAME_ACCESS
        );

        if status != 0x0 {
            return Err(ProcessError::NtStatus(status));
        }
        Ok(Thread(new_handle))
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
    /// # Parameters
    ///
    /// - `timeout`:  
    ///   An optional duration to wait.  
    ///   - `None` waits indefinitely.  
    ///   - `Some(d)` waits up to `d`.  
    ///
    /// - `allow_apc`:  
    ///   If `true`, the wait may return early due to queued APCs.  
    ///
    /// # Returns
    ///
    /// - `Ok(WaitResult::Signaled)` if the thread terminated.
    /// - `Ok(WaitResult::Timeout)` if the timeout elapsed.
    /// - `Err(ProcessError::NtStatus(...))` for NTSTATUS failures,
    /// possibly due to insufficient access rights.
	///
    pub fn wait(&self, timeout: Option<Duration>, allow_apc: bool) -> Result<WaitResult> {
        let timeout_ptr = if let Some(d) = timeout {
            let hundred_ns = d.as_nanos() as i64 / 100;
            let nt_timeout = -hundred_ns;
            &nt_timeout as *const i64
        } else {
            core::ptr::null()
        };

        let status = nt_wait_for_single_object(self.0, allow_apc as u8, timeout_ptr);

        match status {
            0 => Ok(WaitResult::Signaled),
            0x00000102 => Ok(WaitResult::Timeout),
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
    pub fn context(&self, flags: ThreadContextFlags) -> Result<ThreadContext> {
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

    pub(crate) fn query_info(&self) -> Result<ThreadBasicInformation> {
        let mut return_len = 0;
        let mut info = unsafe { core::mem::zeroed::<ThreadBasicInformation>() };

        let status = nt_query_information_thread(
            self.0,
            0x0, // ThreadBasicInformation
            (&mut info as *mut ThreadBasicInformation).cast(),
            size_of::<ThreadBasicInformation>() as u32,
            &mut return_len,
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        Ok(info)
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        // cleanup: close thread handle
        nt_close(self.0);
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Process, ProcessAccess, RemoteProcess, Result, ThreadContextFlags,
        iter::process::ProcessIterator, process::ThreadAccess,
    };

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
        let process = RemoteProcess::open_first_named(
            "Discord.exe",
            ProcessAccess::QUERY_LIMITED_INFORMATION,
        )?;

        let threads = process.threads()?;
        let thread = threads[0]
            .open(ThreadAccess::SUSPEND_RESUME | ThreadAccess::QUERY_LIMITED_INFORMATION)?;

        let old_count = thread.suspend()?;
        let new_count = thread.resume()?;

        // the thread's suspension count should increase after suspending it.
        assert!(new_count > old_count, "failed to suspend/resume thread");

        Ok(())
    }

    #[test]
    fn thread_context() -> Result<()> {
        let process = RemoteProcess::open_first_named(
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
}
