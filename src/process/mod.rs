pub mod current;
pub mod ptr;
pub mod remote;
pub mod thread;
pub mod utils;
pub mod region;

pub use crate::{windows::flags::*};
use crate::{modules::Module, patterns::Scanner};
pub use region::MemoryRegionIter;
pub use current::CurrentProcess;
pub use ptr::AsPointer;
pub use remote::RemoteProcess;
pub use thread::Thread;
pub use utils::{AddressRange, MemoryRegionInfo, MemoryAllocation, ProcessHandleInfo};

use crate::{
    Result,
    iter::{
        module::{ModuleIterOrder, ModuleIterator},
        thread::ThreadView,
    },
    windows::{Handle, NtStatus},
};

pub trait Process {
    /// Returns the underlying process handle.
    ///
    /// # Safety
    /// If it is a remote process, the handle will be closed as soon
    /// as the `RemoteProcess` struct is dropped.
    unsafe fn handle(&self) -> Handle;

    /// Terminates the process.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
    /// requires the process handle access mask to include:
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
    fn terminate(&self, exit_status: NtStatus) -> Result<()>;

    /* THREADS */

    /// Lists the threads within the process.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
    /// requires the process handle access mask to include:
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
    fn threads(&self) -> Result<Vec<ThreadView>>;

    /// Creates a thread in the process.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
    /// requires the process handle access mask to include:
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
        flags: ThreadCreateFlags,
    ) -> Result<Thread>;

    /* MODULES */

    /// Enumerates the modules within the process and finds the
    /// first loaded module (the main module)
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
    /// requires the process handle access mask to include:
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
    fn main_module(&self) -> Result<Module<Self>>;

    /// Enumerates the modules within the process and finds
    /// a module matching the `name` provided.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
    /// requires the process handle access mask to include:
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
    fn get_module(&self, name: &str) -> Result<Module<Self>>;

    /// Lists the modules within the process.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
    /// requires the process handle access mask to include:
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
    fn modules(&self, order: ModuleIterOrder) -> Result<ModuleIterator<Self>>;

    /* MEMORY */

    /// Reads a value of type `T` from the process's memory.
    ///
    /// This method copies `size_of::<T>()` bytes from the target process
    /// into a local `T`. The address may be provided as
    /// any type implementing [`AsPointer<T>`], such as a raw pointer or integer address.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
    /// requires the process handle access mask to include:
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
    fn read_mem<T: Copy>(&self, address: impl AsPointer<T>) -> Result<T>;

    /// Reads a slice of type `T` from the process's memory.
    ///
    /// This method copies `size_of::<T>() * len` bytes from the target process
    /// into a local `Vec<T>`. The address may be provided as
    /// any type implementing [`AsPointer<T>`], such as a raw pointer or integer address.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
    /// requires the process handle access mask to include:
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
    fn read_slice<T: Copy>(&self, address: impl AsPointer<T>, len: usize) -> Result<Vec<T>>;

    /// Reads a C string from the process' memory, continuing reading
    /// memory until it finds a null terminator or reaches `len`.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
    /// requires the process handle access mask to include:
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
    /// until it finds a null terminator or, if `len` is not `None`, until it reaches `len`.
    fn read_c_string(&self, address: impl AsPointer, len: Option<usize>) -> Result<String>;

    /// Writes a value of type `T` to the process's memory
    ///
    /// This method copies `size_of::<T>()` bytes to the address in the
    /// target process's memory. The address may be provided as
    /// any type implementing [`AsPointer<T>`], such as a raw pointer or integer address.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
    /// requires the process handle access mask to include:
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
    fn write_mem<T>(&self, address: impl AsPointer<T>, value: &T) -> Result<()>;

    /// Writes a slice of type `T` to the process's memory
    ///
    /// This method copies `size_of::<T>() * value.len()` bytes to the address in the
    /// target process's memory. The address may be provided as
    /// any type implementing [`AsPointer<T>`], such as a raw pointer or integer address.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
    /// requires the process handle access mask to include:
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
    fn write_slice<T>(&self, address: impl AsPointer<T>, value: &[T]) -> Result<()>;

    /// Queries information about a region of virtual memory in the process.
    ///
    /// The address may be provided as any type implementing [`AsPointer`],
    /// such as a raw pointer or integer address.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
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
    /// Returns [`crate::ProcessError::NtStatus`] if querying the memory fails,
    /// potentially due to insufficient access rights.
    fn query_mem(&self, address: impl AsPointer) -> Result<MemoryRegionInfo>;

    /// Changes the protection on a region of virtual memory in the process.
    /// Returns the region's previous protection.
    ///
    /// The address may be provided as any type implementing [`AsPointer`],
    /// such as a raw pointer or integer address.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
    /// requires the process handle access mask to include:
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
        address: impl AsPointer,
        size: usize,
        new_protection: MemoryProtection,
    ) -> Result<MemoryProtection>;

    /// Reserves and/or commits a region of pages within the process's
    /// virtual memory.
    ///
    /// If `address` is not `None`, the region is allocated at the
    /// specified virtual address.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
    /// requires the process handle access mask to include:
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
    ) -> Result<MemoryAllocation<Self>>;

    /// Frees allocated virtual memory in the process.
    ///
    /// The address may be provided as any type implementing [`AsPointer`],
    /// such as a raw pointer or integer address.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
    /// requires the process handle access mask to include:
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
    fn free_mem(&self, address: impl AsPointer, size: usize, r#type: FreeType) -> Result<()>;

    /// Scans virtual memory in the process according to the `range`.
    ///
    /// # Access Rights
    ///
    /// If this is a remote process, this method
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
    /// Returns [`crate::ProcessError::NtStatus`] if reading the memory fails,
    /// potentially due to insufficient access rights.
    fn scan_mem<S: Scanner>(&self, range: AddressRange, pattern: &S) -> impl Iterator<Item = usize>;
	/// Returns an iterator over the memory regions that intersect `range`.
	/// 
	/// # Access Rights
    ///
    /// If this is a remote process, this method
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
	fn mem_regions(&self, range: AddressRange) -> MemoryRegionIter<Self>;
}
