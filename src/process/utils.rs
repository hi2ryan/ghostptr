use core::ops::Range;
use crate::{
    HandleObject, ProcessError, Result, Scanner, process::{FreeType, MemoryProtection, MemoryState, MemoryType, Process}, windows::{
        Handle,
        constants::{CURRENT_PROCESS_HANDLE, STATUS_INFO_LENGTH_MISMATCH},
        structs::{
            MemoryBasicInformation, ProcessHandleEntry, PublicObjectTypeInformation, UnicodeString,
        },
        utils::unicode_to_string,
        wrappers::{nt_duplicate_object, nt_query_object},
    }
};

pub type AddressRange = Range<usize>;

#[derive(Debug, Clone)]
pub struct MemoryInfo {
    pub base_address: usize,
    pub allocation_base: usize,
    pub allocation_protection: MemoryProtection,
    pub partition_id: u16,
    pub region_size: usize,
    pub state: MemoryState,
    pub protection: MemoryProtection,
    pub r#type: MemoryType,
}

impl MemoryInfo {
    #[inline]
    pub fn is_readable(&self) -> bool {
        if self.state != MemoryState::COMMIT {
            return false;
        }

        let protection = self.protection;
        if protection.contains(MemoryProtection::NOACCESS)
            || protection.contains(MemoryProtection::GUARD)
        {
            return false;
        }

        protection.intersects(
            MemoryProtection::READONLY
                | MemoryProtection::READWRITE
                | MemoryProtection::WRITECOPY
                | MemoryProtection::EXECUTE_READ
                | MemoryProtection::EXECUTE_READWRITE
                | MemoryProtection::EXECUTE_WRITECOPY,
        )
    }
}

impl From<MemoryBasicInformation> for MemoryInfo {
    fn from(value: MemoryBasicInformation) -> Self {
        Self {
            base_address: value.base_address as _,
            allocation_base: value.allocation_base as _,
            allocation_protection: MemoryProtection::from_bits_retain(value.allocation_protection),
            partition_id: value.partition_id,
            region_size: value.region_size,
            state: MemoryState::from_bits_retain(value.state),
            protection: MemoryProtection::from_bits_retain(value.protection),
            r#type: MemoryType::from_bits_retain(value.r#type),
        }
    }
}

/// Represents a handle that a process has opened.
#[derive(Debug, Clone)]
pub struct ProcessHandleInfo<'a, P: Process + ?Sized> {
    pub(crate) process: &'a P,

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

impl<'a, P: Process> ProcessHandleInfo<'a, P> {
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

    pub(crate) fn from_entry(
        process: &'a P,
        entry: ProcessHandleEntry,
    ) -> ProcessHandleInfo<'a, P> {
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

impl<'a, P: Process> Into<HandleObject> for ProcessHandleInfo<'a, P> {
    fn into(self) -> HandleObject {
        HandleObject::from_handle(self.handle)
    }
}

/// Represents an allocated region in a process' memory.
#[derive(Debug, Clone)]
pub struct MemoryRegion<'a, P: Process + ?Sized> {
    pub(crate) process: &'a P,

    pub address: usize,
    pub size: usize,

    pub region_size: usize,
}

impl<'a, P: Process> MemoryRegion<'a, P> {
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
