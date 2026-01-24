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

mod windows;

pub mod error;
pub mod iter;
pub mod misc;
pub mod modules;
pub mod patterns;
pub mod process;
pub mod utils;

#[cfg(feature = "rtti")]
pub mod rtti;

#[cfg(feature = "rtti")]
pub use rtti::*;

/* EXPORTS */
pub use error::{ProcessError, Result};
pub use iter::{ModuleIterOrder, ModuleIterator, ProcessIterator, ProcessView, ThreadView};
pub use misc::HandleObject;
pub use modules::*;
pub use patterns::{Pattern16, Pattern32, Scanner};
pub use process::{
    AddressRange, CurrentProcess, ExecutionTimes, MemScanIter, MemoryAllocation, MemoryRegionInfo,
    Process, ProcessHandleInfo, RemoteProcess, Thread,
};
pub use utils::{SafeHandle, close_handle};
pub use windows::{Handle, NtStatus, flags::*};
