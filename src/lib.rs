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
pub mod process;
pub mod utils;

/* EXPORTS */
pub use error::{ProcessError, Result};
pub use iter::{ModuleIterOrder, ModuleIterator, ProcessIterator, ProcessView, ThreadView};
pub use misc::HandleObject;
pub use process::{
    CurrentProcess, Export, MemoryInfo, MemoryRegion, Module, Pattern16, Pattern32, Process,
    ProcessHandleInfo, RemoteProcess, Scanner, Thread,
};
pub use utils::{SafeHandle, close_handle};
pub use windows::{Handle, NtStatus, flags::*};
