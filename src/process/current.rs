use crate::{
    ProcessError, Result, ThreadAccess, ThreadCreateFlags,
    iter::{
        module::{ModuleIterOrder, ModuleIterator},
        process::ProcessIterator,
        thread::ThreadView,
    },
    process::{
        Address, AllocationType, FreeType, MemoryProtection, Process,
        module::Module,
        thread::Thread,
        utils::{MemoryInfo, MemoryRegion},
    },
    windows::{
        Handle, NtStatus,
        constants::CURRENT_PROCESS_HANDLE,
        structs::MemoryBasicInformation,
        utils::{current_process_id, current_process_image_path, unicode_to_string},
        wrappers::{
            nt_allocate_virtual_memory, nt_create_thread_ex, nt_free_virtual_memory,
            nt_protect_virtual_memory, nt_query_virtual_memory, nt_read_virtual_memory,
            nt_terminate_process, nt_write_virtual_memory,
        },
    },
};
use core::{mem::MaybeUninit, ptr};

/// Represents the current process
/// Using pseudo handle (`-1`)
pub struct CurrentProcess;

impl CurrentProcess {
    #[inline(always)]
    pub fn get() -> Self {
        Self
    }

    /// Retrieves the current process' unique identifier.
    #[inline(always)]
    pub fn pid(&self) -> u32 {
        return current_process_id();
    }

    /// Retrieves the current process' image path.
    #[inline]
    pub fn path(&self) -> String {
        let image_path = current_process_image_path();
        unicode_to_string(&image_path)
    }

    /// Retrieves the current process' image name through its path.
    #[inline]
    pub fn name(&self) -> String {
        let path = self.path();
        path.rsplit('\\').next().unwrap_or(&path).to_string()
    }
}

impl Process for CurrentProcess {
    /// Returns the pseudo handle (`-1`) of the current process.
    unsafe fn handle(&self) -> Handle {
        -1isize as Handle
    }

	/// Terminates the process.
    fn terminate(&self, exit_status: NtStatus) -> Result<()> {
        let status = nt_terminate_process(0, exit_status);
        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }
        Ok(())
    }

	/// Lists the threads within the process.
    fn threads(&self) -> Result<Vec<ThreadView>> {
        let pid = self.pid();
        let Some(process) = ProcessIterator::new()?.find(|view| view.pid == pid) else {
            return Err(ProcessError::ProcessNotFound(pid.to_string()));
        };

        Ok(process.threads)
    }

	/// Creates a thread in the process.
    fn create_thread(
        &self,
        access: ThreadAccess,
        start_routine: *mut core::ffi::c_void,
        argument: *mut core::ffi::c_void,
        flags: ThreadCreateFlags,
    ) -> Result<Thread> {
        let mut handle = 0;

        let status = nt_create_thread_ex(
            &mut handle,
            access.bits(),
            core::ptr::null_mut(),
            CURRENT_PROCESS_HANDLE,
            start_routine,
            argument,
            flags.bits(),
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
	#[inline]
    fn main_module(&self) -> Result<Module<Self>> {
        self.modules(ModuleIterOrder::Load)?
            .next()
            .ok_or(ProcessError::ModuleNotFound)
    }

	/// Enumerates the modules within the process and finds
	/// a module matching the `name` provided.
	#[inline]
	fn get_module(&self, name: &str) -> Result<Module<Self>> {
		self.modules(ModuleIterOrder::Load)?
            .find(|m| m.name == name)
            .ok_or(ProcessError::ModuleNotFound)
	}

	/// Lists the modules within the process.
    fn modules(&self, order: ModuleIterOrder) -> Result<ModuleIterator<Self>> {
        ModuleIterator::new(&self, order)
    }

	/// Reads a value of type `T` from the process's memory.
    ///
	/// This method copies `size_of::<T>()` bytes from the target process
    /// into a local `T`. The address may be provided as
    /// any type implementing [`Address<T>`], such as a raw pointer or integer address.
	/// 
	/// # Example
    ///
    /// ```rust
    /// let value: u32 = process.read_mem(0x7FF6_1234_5678)?;
    /// println!("value: {}", value);
    /// ```
    fn read_mem<T: Copy, A: Address<T>>(&self, address: A) -> Result<T> {
        let mut value = MaybeUninit::<T>::uninit();
        let mut bytes_read = 0;
        let bytes_to_read = size_of::<T>();

        let status = nt_read_virtual_memory(
            CURRENT_PROCESS_HANDLE,
            address.into_ptr() as _,
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
    /// any type implementing [`Address<T>`], such as a raw pointer or integer address.
    fn read_slice<T: Copy, A: Address<T>>(&self, address: A, len: usize) -> Result<Vec<T>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        let size = size_of::<T>() * len;
        let mut vec: Vec<MaybeUninit<T>> = Vec::with_capacity(len);
        let mut bytes_read = 0;

        let status = nt_read_virtual_memory(
            CURRENT_PROCESS_HANDLE,
            address.into_ptr() as _,
            vec.as_mut_ptr().cast(),
            size,
            &mut bytes_read,
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        if bytes_read != size {
            return Err(ProcessError::PartialRead(bytes_read));
        }

        unsafe {
            vec.set_len(len);
            Ok(ptr::read(&vec as *const _ as *const Vec<T>))
        }
    }

	/// Reads a C string from the process' memory, continuing reading
	/// memory until it finds a null terminator.
    fn read_c_string<A: Address<u8>>(&self, address: A) -> Result<String> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut offset = 0;
        let base_address = address.into_ptr() as usize;

        loop {
            let mut chunk = [0u8; 64];
            let mut bytes_read = 0;

            let status = nt_read_virtual_memory(
                CURRENT_PROCESS_HANDLE,
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

            // find the null terminator
            if let Some(pos) = chunk[..bytes_read].iter().position(|&b| b == 0) {
                buffer.extend_from_slice(&chunk[..pos]);
                break;
            } else {
                // null terminator not in this chunk
                buffer.extend_from_slice(&chunk[..bytes_read]);
                offset += bytes_read;
            }
        }

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

	/// Writes a value of type `T` to the process's memory
	/// 
	/// This method copies `size_of::<T>()` bytes to the address in the
	/// target process's memory. The address may be provided as
    /// any type implementing [`Address<T>`], such as a raw pointer or integer address.
    fn write_mem<T, A: Address<T>>(&self, address: A, value: &T) -> Result<()> {
        let mut bytes_written = 0;
        let bytes_to_write = size_of::<T>();

        let status = nt_write_virtual_memory(
            CURRENT_PROCESS_HANDLE,
            address.into_ptr() as _,
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
    /// any type implementing [`Address<T>`], such as a raw pointer or integer address.
	fn write_slice<T, A: Address<T>>(&self, address: A, value: &[T]) -> Result<()> {
		let mut bytes_written = 0;
        let bytes_to_write = size_of::<T>() * value.len();

        let status = nt_write_virtual_memory(
            CURRENT_PROCESS_HANDLE,
            address.into_ptr() as _,
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
	/// The address may be provided as any type implementing [`Address<u8>`],
	/// such as a raw pointer or integer address.
    fn query_mem<A: Address<u8>>(&self, address: A) -> Result<MemoryInfo> {
        let mut memory_info: MaybeUninit<MemoryBasicInformation> = MaybeUninit::uninit();

        let status = nt_query_virtual_memory(
            CURRENT_PROCESS_HANDLE,
            address.into_ptr().cast(),
            0x0, // MemoryBasicInformation
            memory_info.as_mut_ptr().cast(),
            size_of::<MemoryBasicInformation>(),
            ptr::null_mut(),
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        let raw_info = unsafe { memory_info.assume_init() };
        Ok(MemoryInfo::from(raw_info))
    }

	/// Changes the protection on a region of virtual memory in the process.
	/// Returns the region's previous protection.
	/// 
	/// The address may be provided as any type implementing [`Address<u8>`],
	/// such as a raw pointer or integer address.
	/// 
	/// The address may be provided as any type implementing [`Address<u8>`],
	/// such as a raw pointer or integer address.
    fn protect_mem<A: Address<u8>>(
        &self,
        address: A,
        size: usize,
        new_protection: super::MemoryProtection,
    ) -> Result<MemoryProtection> {
        let mut base_address = address.into_ptr().cast::<core::ffi::c_void>().cast_mut();
        let mut region_size = size;
        let mut prev_protection = new_protection.bits();

        let status = nt_protect_virtual_memory(
            CURRENT_PROCESS_HANDLE,
            &mut base_address,
            &mut region_size,
            new_protection.bits(),
            &mut prev_protection,
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        Ok(MemoryProtection::from_bits_retain(prev_protection))
    }

	/// Reserves and/or commits a region of pages within the process's
	/// virtual memory.
	/// 
	/// If `address` is not `None`, the region is allocated at the
	/// specified virtual address.
    fn alloc_mem(
        &self,
        address: Option<usize>,
        size: usize,
        r#type: AllocationType,
        protection: MemoryProtection,
    ) -> Result<MemoryRegion<Self>> {
        let mut base_address = address.unwrap_or(0);
        let mut region_size = size;

        let status = nt_allocate_virtual_memory(
            CURRENT_PROCESS_HANDLE,
            &mut base_address,
            0,
            &mut region_size,
            r#type.bits(),
            protection.bits(),
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        Ok(MemoryRegion {
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
	/// The address may be provided as any type implementing [`Address<u8>`],
	/// such as a raw pointer or integer address.
    fn free_mem<A: Address<u8>>(&self, address: A, size: usize, r#type: FreeType) -> Result<()> {
        let mut base_address = address.into_ptr().cast::<core::ffi::c_void>().cast_mut();
        let mut region_size = size;

        let status = nt_free_virtual_memory(
            CURRENT_PROCESS_HANDLE,
            &mut base_address,
            &mut region_size,
            r#type.bits(),
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        Result,
        iter::module::ModuleIterOrder,
        process::{Process, current::CurrentProcess},
    };

    #[test]
    fn get_current_pid() {
        assert_ne!(CurrentProcess.pid(), 0, "pid == 0");
    }

    #[test]
    fn get_current_name() {
        assert!(
            CurrentProcess.name().starts_with("ghostptr"),
            "failed to get current process name"
        )
    }

    #[test]
    fn iter_modules() -> Result<()> {
        let mut modules = CurrentProcess.modules(ModuleIterOrder::Load)?;

        assert!(
            modules.find(|m| m.name == "ntdll.dll").is_some(),
            "failed to iterate modules (didnt find ntdll)"
        );

        let main_module = modules.find(|m| m.name.starts_with("ghostptr"));
        assert!(main_module.is_some(), "failed to get main module");

        Ok(())
    }
}
