use super::structs::ProcessEnvBlock;
use crate::error::{ProcessError, Result};
use crate::windows::constants::{STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH};
use crate::windows::structs::{
    ImageDosHeader, ImageExportDirectory, ImageNtHeaders64, LdrModule, ProcessBasicInformation,
    UnicodeString,
};
use crate::windows::wrappers::{nt_query_information_process, nt_read_virtual_memory};
use core::arch::asm;

type Handle = usize;

#[inline(always)]
pub fn get_peb() -> *const ProcessEnvBlock {
    unsafe {
        let peb: *const ProcessEnvBlock;
        asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nomem, nostack, preserves_flags),
        );
        peb
    }
}

pub fn unicode_to_string(u: &UnicodeString) -> String {
    if u.buffer.is_null() || u.length == 0 {
        return String::new();
    }

	let len = (u.length / 2) as usize;
    let slice = unsafe { core::slice::from_raw_parts(u.buffer, len) };
    String::from_utf16_lossy(slice)
}

pub fn unicode_to_string_remote(process_handle: Handle, u: &UnicodeString) -> String {
    if u.buffer.is_null() || u.length == 0 {
        return String::new();
    }

    let len = (u.length / 2) as usize;
    let mut buf = vec![0u16; len];

    let status = nt_read_virtual_memory(
        process_handle,
        u.buffer as *const _,
        buf.as_mut_ptr() as *mut _,
        u.length as usize,
        core::ptr::null_mut(),
    );

    if status != 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf)
}

pub fn get_module_base(name: &str) -> Option<*const u8> {
    unsafe {
        let peb = get_peb();
        if peb.is_null() || (*peb).ldr.is_null() {
            return None;
        }

        let ldr = (*peb).ldr;

        let head = &(*ldr).in_memory_order_module_list;
        let mut current = head.next;

        while current != head {
            let entry = (current as usize
                - core::mem::offset_of!(LdrModule, in_memory_order_module_list))
                as *const LdrModule;
            let dll_name = unicode_to_string(&(*entry).base_dll_name);

            if dll_name.eq_ignore_ascii_case(name) {
                return Some((*entry).base_address);
            }
            current = (*current).next;
        }

        None
    }
}

pub fn get_export(base: *const u8, name: &str) -> Option<*const u8> {
    unsafe {
        let dos_header = base.cast::<ImageDosHeader>();
        let nt_headers = dos_header
            .cast::<u8>()
            .add((*dos_header).e_lfanew as usize)
            .cast::<ImageNtHeaders64>();

        let export_dir_rva = (*nt_headers).optional_header.data_directory[0].virtual_address;
        if export_dir_rva == 0 {
            return None;
        }

        let export_dir = (base as usize + export_dir_rva as usize) as *mut ImageExportDirectory;
        let number_of_names = (*export_dir).number_of_names;

        let address_of_names = base
            .add((*export_dir).address_of_names as usize)
            .cast::<u32>();
        let address_of_name_ordinals = base
            .add((*export_dir).address_of_name_ordinals as usize)
            .cast::<u16>();
        let address_of_functions = base
            .add((*export_dir).address_of_functions as usize)
            .cast::<u32>();

        let name_bytes = name.as_bytes();
        for i in 0..number_of_names {
            let name_rva = *address_of_names.add(i as usize);
            let name_ptr = base.add(name_rva as usize);

			let export_name = core::ffi::CStr::from_ptr(name_ptr.cast());
            if export_name.to_bytes() == name_bytes {
                let ordinal_index = *address_of_name_ordinals.add(i as usize) as usize;
                let func_rva = *address_of_functions.add(ordinal_index);
				return Some(base.add(func_rva as usize));
            }
        }

        None
    }
}

pub fn query_process_basic_info(handle: Handle) -> Result<ProcessBasicInformation> {
    let mut info = ProcessBasicInformation {
        exit_status: 0,
        peb_base_address: core::ptr::null_mut(),
        affinity_mask: 0,
        base_priority: 0,
        pid: 0,
        inherited_from_pid: 0,
    };
    let mut return_len = 0;

    let status = nt_query_information_process(
        handle,
        0x0, // ProcessBasicInformation
        (&mut info as *mut ProcessBasicInformation).cast(),
        size_of::<ProcessBasicInformation>() as u32,
        &mut return_len,
    );

    if status != 0 {
        return Err(ProcessError::NtStatus(status));
    }

    Ok(info)
}

pub fn query_process_handle_info(handle: Handle) -> Result<Vec<u8>> {
    let mut len: u32 = 0x100;

    loop {
        let mut info = vec![0u8; len as usize];
        let status = nt_query_information_process(
            handle,
            51, // ProcessHandleInformation
            info.as_mut_ptr().cast(),
            len,
            &mut len,
        );

        match status {
            s if s == STATUS_BUFFER_TOO_SMALL || s == STATUS_INFO_LENGTH_MISMATCH => {
                // mismatched length; retry with new length
                continue;
            }
            0x0 => return Ok(info),
            // some other error
            _ => return Err(ProcessError::NtStatus(status)),
        }
    }
}
