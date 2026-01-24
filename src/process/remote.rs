use crate::{
    ExecutionTimes, Module, ProcessError, Result, ThreadAccess, ThreadCreationFlags, iter::{
        module::{ModuleIterOrder, ModuleIterator},
        process::ProcessIterator,
        thread::ThreadView,
    }, patterns::Scanner, process::{
        AllocationType, FreeType, MemoryProtection, Process, ptr::AsPointer, region::MemoryRegionIter, scan::MemScanIter, thread::Thread, utils::{AddressRange, MemoryAllocation, MemoryRegionInfo, ProcessHandleInfo, get_process_handle_info}
    }, windows::{
        Handle, NtStatus,
        flags::ProcessAccess,
        structs::{
            ClientId, KernelUserTimes, MemoryBasicInformation, ObjectAttributes, UnicodeString
        },
        utils::{query_process_basic_info, unicode_to_string_remote},
        wrappers::{
            nt_allocate_virtual_memory, nt_close, nt_create_thread_ex, nt_duplicate_object, nt_free_virtual_memory, nt_open_process, nt_protect_virtual_memory, nt_query_information_process, nt_query_virtual_memory, nt_read_virtual_memory, nt_terminate_process, nt_write_virtual_memory
        },
    }
};
use core::{mem::MaybeUninit, ptr};

/// Represents an open process handle.
pub struct RemoteProcess(Handle);

impl RemoteProcess {
    /// Opens the process with the `pid` with `access`
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `pid` is a valid process identifier.
    ///
    /// Otherwise, a [`ProcessError::NtStatus`] will be returned.
    pub fn open(pid: u32, access: ProcessAccess) -> Result<Self> {
        let mut client_id = ClientId {
            unique_process: pid as usize, // PID
            unique_thread: 0,
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
        let status = nt_open_process(&mut handle, access.bits(), &mut attributes, &mut client_id);

        if status != 0x0 {
            return Err(ProcessError::NtStatus(status));
        }
        Ok(Self(handle))
    }

    /// Opens the first process found matching the `name` with `access`
    pub fn open_first_named(name: &str, access: ProcessAccess) -> Result<Self> {
        let process = ProcessIterator::find_first_named(name)?;
        Self::open(process.pid, access)
    }

    /// Creates a `RemoteProcess` struct based on an already
    /// open process `Handle`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `handle` is a valid, open process handle,
    /// with the access mask that they want.
    /// The `RemoteProcess` struct will close the process handle when it is dropped.
    #[inline(always)]
    pub unsafe fn from_handle(handle: Handle) -> Self {
        Self(handle)
    }

    /// Duplicates the underlying process handle,
    /// returning a new `RemoteProcess` struct.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::DUP_HANDLE`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if duplicating the handle fails,
    /// potentially due to insufficient access rights.
    pub fn duplicate(&self) -> Result<RemoteProcess> {
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
        Ok(RemoteProcess(new_handle))
    }

    /// Retrieves the image path of the process.
    ///
    /// # Access Rights
    ///
    /// This method requires one of the following access rights:
    ///
    /// - [`ProcessAccess::QUERY_INFORMATION`], **or**
    /// - [`ProcessAccess::QUERY_LIMITED_INFORMATION`]
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
    /// let process = RemoteProcess::open(pid, ProcessAccess::QUERY_LIMITED_INFORMATION)?;
    /// let path = process.path()?;
    /// println!("Path: {}", path);
    /// ```
    pub fn path(&self) -> Result<String> {
        let peb_ptr = query_process_basic_info(self.0)?.peb_base_address;

        // PEB->ProcessParameters
        let params_ptr: usize = self.read_mem(peb_ptr as usize + 0x20)?;

        // RTL_USER_PROCESS_PARAMETERS->ImagePathName
        let image_path: UnicodeString = self.read_mem(params_ptr + 0x60)?;

        Ok(unicode_to_string_remote(self.0, &image_path))
    }

    /// Retrieves the image name of the process using its path.
    ///
    /// # Access Rights
    ///
    /// This method requires one of the following access rights:
    ///
    /// - [`ProcessAccess::QUERY_INFORMATION`], **or**
    /// - [`ProcessAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without one of these rights, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if querying basic process information fails.
    /// potentially due to insufficient access rights.
	/// 
	/// # Example
    ///
    /// ```rust
    /// let process = RemoteProcess::open(pid, ProcessAccess::QUERY_LIMITED_INFORMATION)?;
    /// let name = process.name()?;
    /// println!("Name: {}", name);
    /// ```
    #[inline]
    pub fn name(&self) -> Result<String> {
        let path = self.path()?;

        Ok(path.rsplit('\\').next().unwrap_or(&path).to_string())
    }

    /// Returns the process identifier (PID) of the process.
    ///
    /// # Access Rights
    ///
    /// This method requires one of the following access rights:
    ///
    /// - [`ProcessAccess::QUERY_INFORMATION`], **or**
    /// - [`ProcessAccess::QUERY_LIMITED_INFORMATION`]
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
    /// let process = RemoteProcess::open(pid, ProcessAccess::QUERY_LIMITED_INFORMATION)?;
    /// let pid = process.pid()?;
    /// println!("PID: {}", pid);
    /// ```
	#[rustfmt::skip]
    pub fn pid(&self) -> Result<u32> {
        query_process_basic_info(self.0)
			.map(|info| info.pid as u32)
    }
}

impl Process for RemoteProcess {
    /// Returns the underlying process handle.
    ///
    /// # Safety
    /// The handle will be closed as soon as the `RemoteProcess` struct is dropped.
    #[inline(always)]
    unsafe fn handle(&self) -> Handle {
        self.0
    }

	/// Queries the handles that the process has open.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::QUERY_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::NtStatus`] if querying handle information fails,
    /// potentially due to insufficient access rights.
    fn handles(&self) -> Result<Vec<ProcessHandleInfo<Self>>> {
		get_process_handle_info(self)
	}

    /// Terminates the process.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::TERMINATE`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if terminating the process fails,
    /// potentially due to insufficient access rights.
    fn terminate(&self, exit_status: NtStatus) -> Result<()> {
        let status = nt_terminate_process(self.0, exit_status);
        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }
        Ok(())
    }

	/// Retrieves creation and executions times for the process.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::QUERY_INFORMATION`], **or**
    /// - [`ProcessAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an `NTSTATUS` error.
    ///
    /// # Returns
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if it fails to query the process's
    /// times, potentially due to insufficient access rights.
	fn times(&self) -> Result<ExecutionTimes> {
		let mut times = MaybeUninit::<KernelUserTimes>::uninit();
		let status = nt_query_information_process(
			self.0,
			0x4, // ProcessTimes
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

    /// Lists the threads within the process.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::QUERY_INFORMATION`], **or**
    /// - [`ProcessAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if creating the thread fails,
    /// potentially due to insufficient access rights.
    fn threads(&self) -> Result<Vec<ThreadView>> {
        let pid = self.pid()?;
        let Some(process) = ProcessIterator::new()?.find(|view| view.pid == pid) else {
            return Err(ProcessError::ProcessNotFound(pid.to_string()));
        };

        Ok(process.threads)
    }

    /// Creates a thread in the process.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::CREATE_THREAD`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if creating the thread fails,
    /// potentially due to insufficient access rights.
    fn create_thread(
        &self,
        access: ThreadAccess,
        start_routine: *mut core::ffi::c_void,
        argument: *mut core::ffi::c_void,
        flags: ThreadCreationFlags,
    ) -> Result<Thread> {
        let mut handle: Handle = 0;

        let status = nt_create_thread_ex(
            &mut handle,
            access.bits(),
            core::ptr::null_mut(),
            self.0,
            start_routine,
            argument,
            flags as u32,
            0,
            0,
            0,
            core::ptr::null_mut(),
        );

        if status == 0 {
            Ok(unsafe { Thread::from_handle(handle) })
        } else {
            Err(ProcessError::NtStatus(status))
        }
    }

    /// Enumerates the modules within the process and finds the
    /// first loaded module (the main module)
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_READ`], **and**
    /// - [`ProcessAccess::QUERY_INFORMATION`], **or**
    /// - [`ProcessAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if the module enumeration fails,
    /// potentially due to insufficient access rights.
    #[inline(always)]
    fn main_module(&self) -> Result<Module<Self>> {
        self.modules(ModuleIterOrder::Load)?
            .next()
            .ok_or(ProcessError::MainModuleNotFound)
    }

    //// Enumerates the modules within the process and finds
	/// a module matching the `name` provided, **case-insensitive**.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_READ`], **and**
    /// - [`ProcessAccess::QUERY_INFORMATION`], **or**
    /// - [`ProcessAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if the module enumeration fails,
    /// potentially due to insufficient access rights.
    #[inline(always)]
    fn get_module(&self, name: &str) -> Result<Module<Self>> {
        self.modules(ModuleIterOrder::Load)?
            .find(|m| m.name.eq_ignore_ascii_case(name))
            .ok_or(ProcessError::ModuleNotFound(name.to_string()))
    }

    /// Lists the modules within the process.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_READ`], **and**
    /// - [`ProcessAccess::QUERY_INFORMATION`], **or**
    /// - [`ProcessAccess::QUERY_LIMITED_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if the module enumeration fails,
    /// potentially due to insufficient access rights.
    #[inline(always)]
    fn modules(&self, order: ModuleIterOrder) -> Result<ModuleIterator<RemoteProcess>> {
        ModuleIterator::new(&self, order)
    }

    /// Reads a value of type `T` from the process's memory.
    ///
    /// This method copies `size_of::<T>()` bytes from the target process
    /// into a local `T`. The address may be provided as
    /// any type implementing [`AsPointer<T>`], such as a raw pointer or integer address.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_READ`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if reading the memory fails,
    /// potentially due to insufficient access rights.
    ///
    /// # Example
    ///
    /// ```rust
    /// let value: u32 = process.read_mem(0x7FF6_1234_5678)?;
    /// println!("value: {}", value);
    /// ```
    fn read_mem<T: Copy>(&self, address: impl AsPointer<T>) -> Result<T> {
        let mut value = MaybeUninit::<T>::uninit();
        let mut bytes_read = 0;
        let bytes_to_read = size_of::<T>();

        let status = nt_read_virtual_memory(
            self.0,
            address.as_ptr() as _,
            value.as_mut_ptr().cast(),
            bytes_to_read,
            &mut bytes_read,
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        } else if bytes_read != bytes_to_read {
            // mismatch: partial read
            return Err(ProcessError::PartialRead(bytes_read));
        }

        Ok(unsafe { value.assume_init() })
    }

    /// Reads a slice of type `T` from the process's memory.
    ///
    /// This method copies `size_of::<T>() * len` bytes from the target process
    /// into a local `Vec<T>`. The address may be provided as
    /// any type implementing [`AsPointer<T>`], such as a raw pointer or integer address.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_READ`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if reading the memory fails,
    /// potentially due to insufficient access rights.
    fn read_slice<T: Copy>(&self, address: impl AsPointer<T>, len: usize) -> Result<Vec<T>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        let size = size_of::<T>() * len;
        let mut slice: Vec<T> = Vec::with_capacity(len);
        let mut bytes_read = 0;

        let status = nt_read_virtual_memory(
            self.0,
            address.as_ptr() as _,
            slice.as_mut_ptr().cast(),
            size,
            &mut bytes_read,
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        if bytes_read != size {
            return Err(ProcessError::PartialRead(bytes_read));
        }

		// SAFETY:
		// the NtReadVirtualMemory syscall returned how many bytes we read
		// therefore we know the length of the Vec
        unsafe {
            slice.set_len(len);
        }
        Ok(slice)
    }

    /// Reads a C string from the process' memory, continuing reading
    /// memory until it finds a null terminator.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_READ`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if reading the memory fails,
    /// potentially due to insufficient access rights.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory read is a proper c string
    /// with a null terminator. This method will continue reading memory
    /// until it finds a null terminator.
    fn read_c_string(&self, address: impl AsPointer<u8>, len: Option<usize>) -> Result<String> {
        let max_len;
        let mut buffer;
        if let Some(len) = len {
            max_len = len;
            buffer = Vec::with_capacity(len);
        } else {
            max_len = usize::MAX;
            buffer = Vec::new();
        }

        let mut offset = 0;
        let base_address = address.as_ptr() as usize;

        loop {
            // stop if we've already reached the max length
            if buffer.len() >= max_len {
                break;
            }

            let mut chunk = [0u8; 64];
            let mut bytes_read = 0;

            let status = nt_read_virtual_memory(
                self.0,
                (base_address + offset) as _,
                chunk.as_mut_ptr().cast(),
                64,
                &mut bytes_read,
            );

            if status != 0 {
                return Err(ProcessError::NtStatus(status));
            }

            if bytes_read == 0 {
                return Err(ProcessError::PartialRead(0));
            }

            let bytes = &chunk[..bytes_read];

            // check for null terminator
            if let Some(pos) = bytes.iter().position(|&b| b == 0) {
                let take = pos.min(max_len - buffer.len());
                buffer.extend_from_slice(&bytes[..take]);
                break;
            }

            // no null terminator found in this chunk
            let remaining = max_len - buffer.len();
            let take = bytes.len().min(remaining);

            buffer.extend_from_slice(&bytes[..take]);
            offset += take;

            if take < bytes.len() {
                // we hit max_len
                break;
            }
        }

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

    /// Writes a value of type `T` to the process's memory
    ///
    /// This method copies `size_of::<T>()` bytes to the address in the
    /// target process's memory. The address may be provided as
    /// any type implementing [`AsPointer<T>`], such as a raw pointer or integer address.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_WRITE`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if writing the memory fails,
    /// potentially due to insufficient access rights.
    fn write_mem<T>(&self, address: impl AsPointer<T>, value: &T) -> Result<()> {
        let mut bytes_written = 0;
        let bytes_to_write = size_of::<T>();

        let status = nt_write_virtual_memory(
            self.0,
            address.as_ptr() as _,
            (value as *const T).cast(),
            bytes_to_write,
            &mut bytes_written,
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        } else if bytes_written != bytes_to_write {
            // mismatch: partial write
            return Err(ProcessError::PartialWrite(bytes_written));
        }

        Ok(())
    }

    /// Writes a slice of type `T` to the process's memory
    ///
    /// This method copies `size_of::<T>() * value.len()` bytes to the address in the
    /// target process's memory. The address may be provided as
    /// any type implementing [`AsPointer<T>`], such as a raw pointer or integer address.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_WRITE`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if writing the memory fails,
    /// potentially due to insufficient access rights.
    fn write_slice<T>(&self, address: impl AsPointer<T>, value: &[T]) -> Result<()> {
        let mut bytes_written = 0;
        let bytes_to_write = size_of::<T>() * value.len();

        let status = nt_write_virtual_memory(
            self.0,
            address.as_ptr() as _,
            value.as_ptr().cast(),
            bytes_to_write,
            &mut bytes_written,
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        } else if bytes_written != bytes_to_write {
            // mismatch: partial write
            return Err(ProcessError::PartialWrite(bytes_written));
        }

        Ok(())
    }

    /// Queries information about a region of virtual memory in the process.
    ///
    /// The address may be provided as any type implementing [`AsPointer`],
    /// such as a raw pointer or integer address.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_READ`], **and**
    /// - [`ProcessAccess::QUERY_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if querying the memory fails,
    /// potentially due to insufficient access rights.
    fn query_mem(&self, address: impl AsPointer) -> Result<MemoryRegionInfo> {
        let mut memory_info: MaybeUninit<MemoryBasicInformation> = MaybeUninit::uninit();

        let status = nt_query_virtual_memory(
            self.0,
            address.as_ptr().cast(),
            0x0, // MemoryBasicInformation
            memory_info.as_mut_ptr().cast(),
            size_of::<MemoryBasicInformation>(),
            ptr::null_mut(),
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        let raw_info = unsafe { memory_info.assume_init() };
        Ok(MemoryRegionInfo::from(raw_info))
    }

    /// Changes the protection on a region of virtual memory in the process.
    /// Returns the region's previous protection.
    ///
    /// The address may be provided as any type implementing [`AsPointer`],
    /// such as a raw pointer or integer address.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_OPERATION`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if protecting the memory fails,
    /// potentially due to insufficient access rights.
    fn protect_mem(
        &self,
        address: impl AsPointer<u8>,
        size: usize,
        new_protection: MemoryProtection,
    ) -> Result<MemoryProtection> {
        let mut base_address = address.as_ptr().cast::<core::ffi::c_void>().cast_mut();
        let mut region_size = size;
        let mut prev_protection = new_protection.bits();

        let status = nt_protect_virtual_memory(
            self.0,
            &mut base_address,
            &mut region_size,
            new_protection.bits(),
            &mut prev_protection,
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        Ok(MemoryProtection::from_bits(prev_protection))
    }

    /// Reserves and/or commits a region of pages within the process's
    /// virtual memory.
    ///
    /// If `address` is not `None`, the region is allocated at the
    /// specified virtual address.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_OPERATION`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if allocating the memory fails,
    /// potentially due to insufficient access rights.
    fn alloc_mem(
        &self,
        address: Option<usize>,
        size: usize,
        r#type: AllocationType,
        protection: MemoryProtection,
    ) -> Result<MemoryAllocation<Self>> {
        let mut base_address = address.unwrap_or(0usize);
        let mut region_size = size;

        let status = nt_allocate_virtual_memory(
            self.0,
            &mut base_address,
            0,
            &mut region_size,
            r#type.bits(),
            protection.bits(),
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        Ok(MemoryAllocation {
            process: &self,

            address: base_address,

            // use original size because NtAllocateVirtualMemory
            // mutates region_size to be page size (0x1000)
            size: size,

            // will be SystemInfo.dwPageSize (0x1000)
            region_size,
        })
    }

    /// Frees allocated virtual memory in the process.
    ///
    /// The address may be provided as any type implementing [`AsPointer`],
    /// such as a raw pointer or integer address.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_OPERATION`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if freeing the memory fails,
    /// potentially due to insufficient access rights.
    fn free_mem(&self, address: impl AsPointer<u8>, size: usize, r#type: FreeType) -> Result<()> {
        let mut base_address = address.as_ptr().cast::<core::ffi::c_void>().cast_mut();
        let mut region_size = size;

        let status =
            nt_free_virtual_memory(self.0, &mut base_address, &mut region_size, r#type.bits());

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }
        Ok(())
    }

    /// Scans virtual memory in the process according to the `range`.
    ///
    /// # Access Rights
    ///
    /// This method requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_READ`], **and**
    /// - [`ProcessAccess::QUERY_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if reading the memory fails,
    /// potentially due to insufficient access rights.
    fn scan_mem<'a, S: Scanner>(
        &'a self,
        range: AddressRange,
        pattern: &'a S,
    ) -> MemScanIter<'a, Self, S> {
        MemScanIter::new(&self, range, pattern)
    }
    // fn scan_mem<S: Scanner>(&self, range: AddressRange, pattern: &S) -> Result<Vec<usize>> {
    //     Ok(self
    //         .mem_regions(range.clone())
    //         .into_iter()
    //         .flat_map(|info| {
    //             let mut results = Vec::new();
    // 			if !info.is_readable() {
    // 				return results.into_iter();
    // 			}

    // 			let region_start = info.base_address;
    //             let region_end = info.base_address.saturating_add(info.region_size);

    //             let start = range.start.max(region_start);
    //             let end = range.end.min(region_end);
    //             if start >= end {
    //                 return results.into_iter();
    //             }

    //             let read_size = end - start;
    //             if let Ok(region) = self.read_slice::<u8>(start, read_size) {
    //                 for offset in pattern.scan_bytes(&region) {
    //                     results.push(start + offset);
    //                 }
    //             }

    //             results.into_iter()
    //         })
    //         .collect())
    // }

    /// Returns an iterator over the memory regions that intersect `range`.
    ///
    /// # Access Rights
    ///
    /// This method
    /// requires the process handle access mask to include:
    ///
    /// - [`ProcessAccess::VM_READ`], **and**
    /// - [`ProcessAccess::QUERY_INFORMATION`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if reading or
    /// querying the memory fails, potentially due to insufficient access rights.
    #[inline(always)]
    fn mem_regions(&self, range: AddressRange) -> MemoryRegionIter<Self> {
        MemoryRegionIter::new(&self, range)
    }
}

impl Drop for RemoteProcess {
    fn drop(&mut self) {
        // cleanup: close handle
        nt_close(self.0);
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn open_process() {
        let _process = RemoteProcess::open_first_named("Discord.exe", ProcessAccess::ALL)
            .expect("failed to open remote process");
    }

    #[test]
    fn query_pid() {
        let view = ProcessIterator::new()
            .expect("failed to create process iterator")
            .find(|view| view.name == "Discord.exe")
            .expect("failed to find process (discord.exe)");
        let pid = view.pid;

        let process = RemoteProcess::open(pid, ProcessAccess::QUERY_LIMITED_INFORMATION)
            .expect("failed to open process");
        let proc_pid = process.pid().expect("failed to get pid of process");

        assert_eq!(pid, proc_pid)
    }

    #[test]
    fn iter_modules() -> Result<()> {
        let process = RemoteProcess::open_first_named("Discord.exe", ProcessAccess::ALL)?;
        let modules: Vec<Module<RemoteProcess>> =
            process.modules(ModuleIterOrder::default())?.collect();

        const MODULES: [&str; 4] = ["discord.exe", "ntdll.dll", "kernel32.dll", "kernelbase.dll"];
        for name in MODULES {
            assert!(
                modules
                    .iter()
                    .find(|m| m.name.eq_ignore_ascii_case(name))
                    .is_some(),
                "failed to find module in remote process: {}",
                name
            );
        }

        Ok(())
    }

    #[test]
    fn iter_handles() -> Result<()> {
        let access = ProcessAccess::QUERY_INFORMATION;
        let process = RemoteProcess::open_first_named("Discord.exe", access)?;

        let _handles = process.handles()?;

        // todo: make actually good test here

        Ok(())
    }

    #[test]
    fn duplicate_handle() {
        let process = RemoteProcess::open_first_named("Discord.exe", ProcessAccess::ALL)
            .expect("failed to open remote process");

        let duplicated = process.duplicate().expect("failed to duplicate process");

        // ensure that the handles aren't the same
        assert_ne!(unsafe { process.handle() }, unsafe { duplicated.handle() });
    }

    #[test]
    fn query_memory() -> Result<()> {
        let process = RemoteProcess::open_first_named("Discord.exe", ProcessAccess::ALL)?;

        let ntdll = process
            .modules(ModuleIterOrder::Load)?
            .skip(1)
            .next()
            .expect("failed to get first module of remote process");

        assert_eq!(ntdll.name, "ntdll.dll");

        let _info = process.query_mem(ntdll.base_address)?;

        // assert!(
        //     info.protection == MemoryProtection::EXECUTE_WRITECOPY
        //         && info.r#type == MemoryType::IMAGE
        //         && info.state == MemoryState::COMMIT,
        //     "invalid ntdll memory"
        // );

        Ok(())
    }

    #[test]
    fn protect_memory() -> Result<()> {
        let process = RemoteProcess::open_first_named("Discord.exe", ProcessAccess::ALL)?;

        // allocate new memory
        let allocation = process.alloc_mem(
            None,
            0x100,
            AllocationType::COMMIT | AllocationType::RESERVE,
            MemoryProtection::READONLY,
        )?;

        let new_protection = MemoryProtection::EXECUTE_READWRITE;
        let prev_protection = process.protect_mem(allocation.address, 0x100, new_protection)?;

        let queried_protection = process.query_mem(allocation.address)?.protection;
        assert_eq!(
            new_protection, queried_protection,
            "failed to modify protection on remote process memory allocation"
        );

        // reset memory protection
        process.protect_mem(allocation.address, 0x100, prev_protection)?;

        let queried_protection = process.query_mem(allocation.address)?.protection;
        assert_eq!(
            prev_protection, queried_protection,
            "failed to reset protection on remote process memory allocation"
        );

        process.free_mem(allocation.address, allocation.size, FreeType::RELEASE)
    }

    #[test]
    fn allocate_memory() -> Result<()> {
        let process = RemoteProcess::open_first_named("Discord.exe", ProcessAccess::ALL)?;

        let allocation = process.alloc_mem(
            None,
            0x100,
            AllocationType::COMMIT | AllocationType::RESERVE,
            MemoryProtection::EXECUTE_READWRITE,
        )?;

        assert_eq!(
            allocation.size, 0x100,
            "failed to allocate 0x100 bytes in remote process"
        );

        allocation.free(FreeType::RELEASE)
    }

    #[test]
    fn query_name() -> Result<()> {
        let process = RemoteProcess::open_first_named("Discord.exe", ProcessAccess::ALL)?;
        let queried_name = process.name()?;

        assert_eq!("Discord.exe", queried_name, "mismatched name");
        Ok(())
    }

    #[test]
    fn threads() -> Result<()> {
        let process = RemoteProcess::open_first_named("Discord.exe", ProcessAccess::ALL)?;
        let threads = process.threads()?;

        assert!(threads.len() > 0, "failed to get remote process threads");
        Ok(())
    }

    #[test]
    fn module_exports() -> Result<()> {
        let process = RemoteProcess::open_first_named("Discord.exe", ProcessAccess::ALL)?;

        let ntdll = process
            .modules(ModuleIterOrder::Load)?
            .skip(1)
            .next()
            .expect("failed to get first module of remote process");

        unsafe extern "system" {
            fn GetProcAddress(hmodule: usize, proc_name: *const u8) -> usize;
        }

        let addr = ntdll.get_export("NtOpenProcess")?;
        let addr2 = unsafe {
            let proc_name = b"NtOpenProcess\0";
            GetProcAddress(ntdll.base_address, proc_name.as_ptr())
        };

        assert_eq!(
            addr, addr2,
            "failed to get remote process ntdll export 'NtOpenProcess'"
        );

        Ok(())
    }

    #[test]
    fn pattern_scan() -> Result<()> {
        let process = RemoteProcess::open_first_named("Discord.exe", ProcessAccess::ALL)?;
        let ntdll = process
            .modules(ModuleIterOrder::Load)?
            .skip(1)
            .next()
            .expect("failed to get first module of remote process");

        let nt_open_process_addr = ntdll.get_export("NtOpenProcess")?;

        let ssn = crate::windows::syscalls::syscalls().nt_open_process;
        let ssn_bytes = ssn
            .to_le_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let pat = Pattern32::from_ida(&format!(
            "4c 8b d1 b8 {} f6 04 25 08 03 fe 7f 01 75 ?? 0f 05 c3 cd 2e c3",
            ssn_bytes
        ));

        let results = ntdll.scan_mem(&pat).collect::<Vec<usize>>();
        assert!(
            results.len() == 1,
            "failed to find match NtOpenProcess syscall pattern"
        );

        assert_eq!(
            results[0], nt_open_process_addr,
            "failed to find match NtOpenProcess syscall pattern"
        );

        Ok(())
    }

	#[test]
	fn times() -> Result<()> {
		let process = RemoteProcess::open_first_named("Discord.exe", ProcessAccess::QUERY_LIMITED_INFORMATION)?;
		let times = process.times()?;

		assert_eq!(times.exited_at, core::time::Duration::ZERO, "exited at time should be 0");
		assert!(times.created_at > core::time::Duration::ZERO, "creation time shouldn't be 0");

		Ok(())
	}
}
