use crate::{
    ProcessError, Result, ThreadAccess, ThreadCreateFlags,
    iter::{
        module::{ModuleIterOrder, ModuleIterator},
        process::ProcessIterator,
        thread::ThreadView,
    },
    process::{
        Address, AllocationType, FreeType, MemoryProtection, Process, Scanner,
        module::Module,
        thread::Thread,
        utils::{AddressRange, MemoryInfo, MemoryRegion},
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
    #[inline(always)]
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
            .ok_or(ProcessError::MainModuleNotFound)
    }

    /// Enumerates the modules within the process and finds
    /// a module matching the `name` provided.
    #[inline]
    fn get_module(&self, name: &str) -> Result<Module<Self>> {
        self.modules(ModuleIterOrder::Load)?
            .find(|m| m.name == name)
            .ok_or(ProcessError::ModuleNotFound(name.to_string()))
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
        let bytes_to_read = size_of::<T>();
        let mut bytes_read: usize = 0;

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
        let mut slice: Vec<T> = Vec::with_capacity(len);
        let mut bytes_read = 0;

        let status = nt_read_virtual_memory(
            CURRENT_PROCESS_HANDLE,
            address.into_ptr() as _,
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

        unsafe {
            slice.set_len(len);
        }
        Ok(slice)
    }

    /// Reads a C string from the process' memory, continuing reading
    /// memory until it finds a null terminator.
    fn read_c_string<A: Address<u8>>(&self, address: A, len: Option<usize>) -> Result<String> {
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
        let base_address = address.into_ptr() as usize;

        loop {
            // stop if we've already reached the max length
            if buffer.len() >= max_len {
                break;
            }

            let mut chunk = [0u8; 64];
            let mut bytes_read: usize = 0;

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

    fn pattern_scan<S: Scanner>(&self, range: AddressRange, pattern: &S) -> Result<Vec<usize>> {
        let mut results = Vec::new();

        let mut curr_addr = range.start;
        let end_addr = range.start + range.size;

        loop {
            if curr_addr > end_addr {
                break;
            }

            let info = match self.query_mem(curr_addr) {
                Ok(info) => info,
                Err(_) => {
                    // query failed
                    // move a page forward
                    curr_addr += 0x1000;
                    continue;
                }
            };

            if info.region_size == 0 {
                break;
            }

            if !info.is_readable() {
                // skip unreadable region
                curr_addr += info.region_size;
                continue;
            }

            let read_size = info.region_size.min(end_addr - curr_addr);

            if let Ok(region) = self.read_slice::<u8, _>(curr_addr, read_size) {
                for offset in pattern.scan_bytes(&region) {
                    results.push(curr_addr + offset);
                }
            }

            curr_addr += info.region_size;
        }

        Ok(results)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        Module, Pattern32, Result,
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
        let modules: Vec<Module<CurrentProcess>> =
            CurrentProcess.modules(ModuleIterOrder::Load)?.collect();

        assert!(
            modules.iter().find(|m| m.name == "ntdll.dll").is_some(),
            "failed to iterate modules (didnt find ntdll)"
        );

        let main_module = modules.iter().find(|m| m.name.starts_with("ghostptr"));
        assert!(main_module.is_some(), "failed to get main module");

        Ok(())
    }

	#[test]
    fn module_exports() -> Result<()> {
        let ntdll = CurrentProcess
            .modules(ModuleIterOrder::Load)?
            .skip(1)
            .next()
            .expect("failed to get first module of remote process");
		
		unsafe extern "system" {
			fn GetProcAddress(module: usize, name: *const u8) -> usize;
		}
		
		let nt_open_process = ntdll.get_export("NtOpenProcess")?;
		let nt_open_process2 = unsafe { GetProcAddress(ntdll.base_address, b"NtOpenProcess\0".as_ptr()) };

		assert_eq!(nt_open_process, nt_open_process2, "failed to get current process' ntdll export: 'NtOpenProcess'");

		Ok(())
    }

    #[test]
    fn pattern_scan() -> Result<()> {
        let ntdll = CurrentProcess
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

        let results = ntdll.pattern_scan(&pat)?;
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
}
