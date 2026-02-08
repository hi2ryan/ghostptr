use crate::{
    AllocationType, ProcessError, Result,
    process::{FreeType, MemoryProtection, MemoryState, MemoryType, Process},
	utils::AddressRange,
    windows::{
        Handle,
        constants::{CURRENT_PROCESS_HANDLE, STATUS_INFO_LENGTH_MISMATCH},
        structs::{
            KernelUserTimes, MemoryBasicInformation, ProcessHandleEntry,
            PublicObjectTypeInformation, UnicodeString,
        },
        utils::unicode_to_string,
        wrappers::{nt_duplicate_object, nt_query_object},
    },
};
use core::time::Duration;

#[derive(Debug)]
pub struct ExecutionTimes {
    /// The creation time of the process or thread.
    pub created_at: Duration,

    /// The exit time of the process or thread.
    pub exited_at: Duration,

    /// The amount of time the process has executed in kernel mode.
    pub kernel_time: Duration,

    /// The amount of time the process has executed in user mode.
    pub user_time: Duration,
}

impl From<KernelUserTimes> for ExecutionTimes {
    fn from(value: KernelUserTimes) -> Self {
        Self {
            created_at: Duration::from_nanos(value.create_time.max(0) as u64 * 100),
            exited_at: Duration::from_nanos(value.exit_time.max(0) as u64 * 100),
            kernel_time: Duration::from_nanos(value.kernel_time.max(0) as u64 * 100),
            user_time: Duration::from_nanos(value.user_time.max(0) as u64 * 100),
        }
    }
}

/// Represents queried information regarding region of virtual memory.
#[derive(Debug, Clone)]
pub struct MemoryRegionInfo {
    /// The starting virtual address of this region.
    pub base_address: usize,

    /// The base address of the allocation that this region belongs to.
    pub allocation_base: usize,

    /// The protection flags that were specified when the allocation
    /// was originally created.
    ///
    /// This value does **not** change when the region's protection
    /// is modified.
    pub allocation_protection: MemoryProtection,

    /// The partition identifier for the memory region.
    pub partition_id: u16,

    /// The size of this region in bytes.
    pub region_size: usize,

    /// The current state of the memory region.
    pub state: MemoryState,

    /// The current access protection of the region.
    pub protection: MemoryProtection,

    /// The type of memory backing this region.
    pub r#type: MemoryType,
}

impl MemoryRegionInfo {
    /// Returns `true` if this region is accessible.
    ///
    /// A region is considered accessible if:
    /// - It is committed ([`MemoryState::COMMIT`])
    /// - It is **not** marked as `NOACCESS` ([`MemoryProtection::NOACCESS`])
    /// - It is **not** a guard page ([`MemoryProtection::GUARD`])
    ///
    /// This is a prerequisite for any read, write, or execute operation.
    #[inline(always)]
    pub fn is_accessible(&self) -> bool {
        self.state.contains(MemoryState::COMMIT)
            && !self
                .protection
                .intersects(MemoryProtection::NOACCESS | MemoryProtection::GUARD)
    }

    /// Returns `true` if this region can be safely read from.
    ///
    /// This implies:
    /// - The region is accessible
    /// - The protection flags include any readable permission
    #[inline(always)]
    pub fn is_readable(&self) -> bool {
        self.is_accessible() && self.protection.is_readable()
    }

    /// Returns `true` if this region can be written to.
    ///
    /// This implies:
    /// - The region is accessible
    /// - The protection flags allow writing, either directly or via
    ///   copy-on-write semantics
    #[inline(always)]
    pub fn is_writable(&self) -> bool {
        self.is_accessible() && self.protection.is_writable()
    }

    /// Returns `true` if this region contains executable code.
    ///
    /// This implies:
    /// - The region is accessible
    /// - The protection flags allow execution, with or without
    ///   read/write permissions
    #[inline(always)]
    pub fn is_executable(&self) -> bool {
        self.is_accessible() && self.protection.is_executable()
    }

    /// Returns the virtual address range covered by this memory region.
    #[inline(always)]
    pub fn virtual_range(&self) -> AddressRange {
        let end = self.base_address.saturating_add(self.region_size);
        self.base_address..end
    }
}

impl From<MemoryBasicInformation> for MemoryRegionInfo {
    #[inline(always)]
    fn from(value: MemoryBasicInformation) -> Self {
        Self {
            base_address: value.base_address as _,
            allocation_base: value.allocation_base as _,
            allocation_protection: MemoryProtection::from_bits(value.allocation_protection),
            partition_id: value.partition_id,
            region_size: value.region_size,
            state: MemoryState::from_bits(value.state),
            protection: MemoryProtection::from_bits(value.protection),
            r#type: MemoryType::from_bits(value.r#type),
        }
    }
}

/// Represents a handle that a process has opened.
#[derive(Debug, Clone)]
pub struct ProcessHandleInfo<'process> {
    pub(crate) process: &'process Process,

    /// The value of the handle.
    pub handle: Handle,

    /// The raw access mask of the object handle.
    pub access: u32,

    /// The type identifier of the object
    pub object_type: u32,

    /// The number of references to the handle.
    pub count: usize,

    /// The number of pointers to the handle.
    pub pointer_count: usize,

    /// The attributes of the handle.
    pub attributes: u32,
}

impl<'process> ProcessHandleInfo<'process> {
    /// Duplicates the handle.
    ///
    /// # Access Rights
    ///
    /// This method requires an object access mask beyond standard bounds
    /// like process access and thread access. Therefore, the desired access
    /// has been kept in its raw state as a `u32`. However, if the `access` is
    /// `None`, it will copy the handle's original access mask.
    pub fn duplicate_handle(&self, access: Option<u32>) -> Result<Handle> {
        let mut new_handle = 0;
        let source_handle = unsafe { self.process.handle() };

        let status = nt_duplicate_object(
            source_handle,
            self.handle,
            CURRENT_PROCESS_HANDLE,
            &mut new_handle,
            access.unwrap_or(0),
            0,
            // DUPLICATE_SAME_ACCESS if access is None
            if access.is_none() { 0x2 } else { 0 },
        );

        match status {
            0 => Ok(new_handle),
            _ => Err(ProcessError::NtStatus(status)),
        }
    }

    /// Retrieves the name of the object, if present.
    ///
    /// The name can include path separators ("\\").
    pub fn name(&self) -> Result<String> {
        // get required size of buffer
        let mut len = 0;
        let status = nt_query_object(
            self.handle,
            0x1, // ObjectNameInformation
            core::ptr::null_mut(),
            0,
            &mut len,
        );

        if status != STATUS_INFO_LENGTH_MISMATCH {
            return Err(ProcessError::NtStatus(status));
        }

        let mut unicode_name = UnicodeString {
            length: 0,
            max_length: 0,
            buffer: core::ptr::null(),
        };
        let status = nt_query_object(
            self.handle,
            0x1, // ObjectNameInformation
            (&mut unicode_name as *mut UnicodeString).cast(),
            len,
            &mut len,
        );

        match status {
            0 => Ok(unicode_to_string(&unicode_name)),
            _ => Err(ProcessError::NtStatus(status)),
        }
    }

    /// Retrieves the type name of the object.
    pub fn type_name(&self) -> Result<String> {
        // get required size of buffer
        let mut needed = 0u32;
        let status = nt_query_object(
            self.handle,
            2, // ObjectTypeInformation
            core::ptr::null_mut(),
            0,
            &mut needed,
        );

        if status != STATUS_INFO_LENGTH_MISMATCH {
            return Err(ProcessError::NtStatus(status));
        }

        let mut buf = vec![0u8; needed as usize];
        let status = nt_query_object(
            self.handle,
            2,
            buf.as_mut_ptr() as *mut _,
            needed,
            core::ptr::null_mut(),
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        let info = unsafe { &*(buf.as_ptr() as *const PublicObjectTypeInformation) };
        Ok(unicode_to_string(&info.type_name))
    }

    #[inline(always)]
    pub(crate) fn from_entry(
        process: &'process Process,
        entry: ProcessHandleEntry,
    ) -> ProcessHandleInfo<'process> {
        Self {
            process,
            handle: entry.handle,
            access: entry.access,
            object_type: entry.object_type_index,
            count: entry.count,
            pointer_count: entry.pointer_count,
            attributes: entry.handle_attributes,
        }
    }
}

/// Represents an allocated region in a process' memory.
#[derive(Debug, Clone)]
pub struct MemoryAllocation<'process> {
    pub(crate) process: &'process Process,

    /// The base address of the memory allocation.
    pub address: usize,

    /// The size of the memory allocation.
    pub size: usize,

    /// The region size of the allocated memory.
    pub region_size: usize,
}

impl<'process> MemoryAllocation<'process> {
    pub fn new(
        process: &'process Process,
        address: Option<usize>,
        size: usize,
        r#type: AllocationType,
        protection: MemoryProtection,
    ) -> Result<Self> {
        process.alloc_mem(address, size, r#type, protection)
    }

    #[inline(always)]
    pub fn free(&self, r#type: FreeType) -> Result<()> {
        self.process.free_mem(self.address, self.size, r#type)
    }

    #[inline(always)]
    pub fn write<T>(&self, offset: usize, value: &T) -> Result<()> {
        self.process.write_mem(self.address + offset, value)
    }

    #[inline(always)]
    pub fn read<T: Copy>(&self, offset: usize) -> Result<T> {
        self.process.read_mem(self.address + offset)
    }
}
