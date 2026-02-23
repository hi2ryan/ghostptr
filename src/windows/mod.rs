pub use flags::ExceptionHandler;
pub use structs::{ExceptionPointers, ApcCallbackDataContext};

pub mod constants;
pub mod flags;
pub mod structs;
pub mod syscalls;
pub mod utils;
pub mod wrappers;

pub type Handle = usize;
pub type NtStatus = i32;

pub type DllEntryPoint = extern "system" fn(
    dll_handle: *const core::ffi::c_void,
    reason: u32,
    context: *const core::ffi::c_void,
);

pub type ProcessInstrumentationCallback = extern "system" fn(
    original_rsp: u64,
    return_address: u64,
    return_value: u64,
);

#[rustfmt::skip]
pub type VectoredExceptionHandler = extern "system" fn(
    exception_info: *mut ExceptionPointers,
) -> ExceptionHandler;

pub type PsApcRoutine = extern "system" fn(
    arg1: *mut core::ffi::c_void,
    arg2: *mut core::ffi::c_void,
    arg3: *mut core::ffi::c_void,
);

