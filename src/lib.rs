/*


           ▄▄
           ██                              ██                  ██
  ▄███▄██  ██▄████▄   ▄████▄   ▄▄█████▄  ███████   ██▄███▄   ███████    ██▄████
 ██▀  ▀██  ██▀   ██  ██▀  ▀██  ██▄▄▄▄ ▀    ██      ██▀  ▀██    ██       ██▀
 ██    ██  ██    ██  ██    ██   ▀▀▀▀██▄    ██      ██    ██    ██       ██
 ▀██▄▄███  ██    ██  ▀██▄▄██▀  █▄▄▄▄▄██    ██▄▄▄   ███▄▄██▀    ██▄▄▄    ██
  ▄▀▀▀ ██  ▀▀    ▀▀    ▀▀▀▀     ▀▀▀▀▀▀      ▀▀▀▀   ██ ▀▀▀       ▀▀▀▀    ▀▀
  ▀████▀▀                                          ██


*/

#[cfg(not(all(windows, target_arch = "x86_64")))]
#[cfg(not(docsrs))]
compile_error!("ghostptr only works for win64 atm");

mod constants;
mod windows;

pub mod error;
pub mod iter;
pub mod modules;
pub mod patterns;
pub mod process;
pub mod utils;

#[cfg(feature = "vectored_handlers")]
pub mod vectored_handlers;

#[cfg(feature = "rtti")]
pub mod rtti;

#[cfg(feature = "rtti")]
pub use rtti::{ModuleRTTIExt, RTTIObject};

pub use error::{ProcessError, Result};
pub use iter::{
    ModuleIterOrder, ModuleIterator, ProcessIterator, ProcessView,
    SystemModuleIterator, SystemModuleView, ThreadView,
};
pub use modules::{Export, Import, ImportType, Module, Section};
pub use patterns::{Pattern16, Pattern32, Scanner};
pub use process::{
    ExecutionTimes, MemScanIter, MemoryAllocation, MemoryRegionInfo,
    MemoryRegionIter, Process, ProcessHandleInfo, Thread,
};
pub use utils::{
    AddressRange, AsPointer, DebugPrivilegeGuard, HandleObject,
    SafeHandle, close_handle, disable_debug_privilege,
    enable_debug_privilege,
};

pub use windows::{
    DllEntryPoint, Handle, NtStatus, ProcessInstrumentationCallback,
    flags::*,
};

#[cfg(feature = "vectored_handlers")]
pub use vectored_handlers::{
    VectoredHandlerEntry, VectoredHandlerIterator, VectoredHandlerList,
    VectoredHandlerType, decode_pointer, encode_pointer,
};

#[cfg(feature = "vectored_handlers")]
pub use windows::{
    ExceptionHandler, ExceptionPointers, VectoredExceptionHandler,
};
