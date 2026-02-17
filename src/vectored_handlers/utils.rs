use core::ptr;
use std::sync::OnceLock;

use crate::{
    error::Result,
    process::Process,
    windows::{
        flags::MemoryProtection,
        utils::{get_export, get_module_base},
    },
};

/// The offset of LdrpVectorHandlerList relative to ntdll's module base
static VECTOR_HANDLER_LIST_OFFSET: OnceLock<usize> = OnceLock::new();

/// Retrieves the offset of LdrpVectorHandlerList from ntdll's module base.
///
/// If the offset is not already initialized (hasn't already been found),
/// retrieves RtlpAddVectoredHandler from RtlAddVectoredExceptionHandler
/// and scans for LdrpVectorHandlerList.
pub fn vector_handler_list_offset() -> usize {
    *VECTOR_HANDLER_LIST_OFFSET.get_or_init(|| {
        // get RtlAddVectoredExceptionHandler address
        let ntdll = get_module_base("ntdll.dll").unwrap();
        let add_fn_addr =
            get_export(ntdll, "RtlAddVectoredExceptionHandler").unwrap();

        // read RtlpAddVectoredHandler function base address
        let rtlp_add_vectored_handler = unsafe {
            // jmp RtlpAddVectoredHandler
            let jmp = (add_fn_addr as usize) + 3;
            let rel32_addr = (jmp + 1) as *const i32;
            let rel32 = ptr::read_unaligned(rel32_addr);
            (jmp + 5).wrapping_add(rel32 as isize as usize)
        };

        // scan RtlpAddVectoredHandler for
        // lea rdi, [rel LdrpVectorHandlerList]
        let mut address = rtlp_add_vectored_handler as *const u8;
        let list_address = loop {
            unsafe {
                if *address == 0x48
                    && *address.add(1) == 0x8D
                    && *address.add(2) == 0x3D
                {
                    // calculate displacement
                    let disp =
                        ptr::read_unaligned(address.add(3) as *const i32);
                    let lea_addr = address.add(7);

                    // LdrpVectorHandlerList
                    let list_address =
                        (lea_addr as isize + disp as isize) as usize;
                    break list_address;
                }

                address = address.add(1);
            }
        };

        let base_address = ntdll as usize;
        list_address - base_address
    })
}

/// Encodes a pointer using the process cookie (equivalent to RtlEncodePointer)
pub fn encode_pointer(ptr: usize, cookie: u32) -> usize {
    let shift = cookie & 0x3F;
    let xored = ptr ^ (cookie as usize);
    xored.rotate_right(shift)
}

/// Decodes a pointer using the process cookie (equivalent to RtlDecodePointer)
pub fn decode_pointer(encoded_ptr: usize, cookie: u32) -> usize {
    let shift = cookie & 0x3F;
    encoded_ptr.rotate_left(shift) ^ (cookie as usize)
}

/// Overrides the protection of the designated address to [`MemoryProtection::READWRITE`]
/// to write to it, then resets the memory back to its original protection.
pub fn protection_write<T>(
    process: &Process,
    address: usize,
    value: &T,
) -> Result<()> {
    let old_protection = process.protect_mem(
        address,
        size_of::<T>(),
        MemoryProtection::READWRITE,
    )?;
    process.write_mem(address, value)?;
    process
        .protect_mem(address, size_of::<T>(), old_protection)
        .map(|_| ())
}
