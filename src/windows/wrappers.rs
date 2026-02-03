#[cfg(feature = "windows")]
use crate::windows::structs::UnicodeString;
use crate::windows::structs::{PsAttributeList, ThreadContext};

use super::{
    Handle, NtStatus,
    structs::{ClientId, ObjectAttributes},
    syscalls::ntdll,
};
use core::{arch::asm, ffi::c_void};

#[cfg(feature = "windows")]
use super::syscalls::win32u;

/* SYSCALL WRAPPERS */

/// NtOpenProcess
#[inline(always)]
pub fn nt_open_process(
    process_handle: *mut Handle,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
    client_id: *mut ClientId,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_open_process;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") process_handle,
            in("rdx") desired_access,
            in("r8")  object_attributes,
            in("r9")  client_id,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        );
    }

    status
}

/// NtTerminateProcess
#[inline(always)]
pub fn nt_terminate_process(process_handle: Handle, exit_status: NtStatus) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_terminate_process;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") process_handle,
            in("rdx") exit_status,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        );
    }

    status
}

/// NtReadVirtualMemory
#[inline(always)]
pub fn nt_read_virtual_memory(
    process_handle: Handle,
    base_address: *const c_void,
    buffer: *mut c_void,
    bytes_to_read: usize,
    bytes_read: *mut usize,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_read_virtual_memory;

    unsafe {
        asm!(
            "sub rsp, 0x30",
            "mov [rsp + 0x28], {bytes_read}",

            "mov r10, rcx",
            "syscall",

            "add rsp, 0x30",

            in("rcx") process_handle,
            in("rdx") base_address,
            in("r8") buffer,
            in("r9") bytes_to_read,
            bytes_read = in(reg) bytes_read,

            in("rax") id,
            lateout("rax") status,
            clobber_abi("system"),
        );
    }

    status
}

/// NtWriteVirtualMemory
#[inline(always)]
pub fn nt_write_virtual_memory(
    process_handle: Handle,
    base_address: *const c_void,
    buffer: *const c_void,
    bytes_to_write: usize,
    bytes_written: *mut usize,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_write_virtual_memory;

    unsafe {
        asm!(
            "sub rsp, 0x30",
            "mov [rsp + 0x28], {bytes_written}",

            "mov r10, rcx",
            "syscall",

            "add rsp, 0x30",

            in("rcx") process_handle,
            in("rdx") base_address,
            in("r8") buffer,
            in("r9") bytes_to_write,
            bytes_written = in(reg) bytes_written,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        )
    };

    status
}

/// NtQueryVirtualMemory
#[inline(always)]
pub fn nt_query_virtual_memory(
    process_handle: Handle,
    base_address: *const c_void,
    info_class: u32,
    memory_info: *mut c_void,
    info_len: usize,
    return_len: *mut usize,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_query_virtual_memory;

    unsafe {
        asm!(
            "sub rsp, 0x38",
            "mov [rsp + 0x28], {info_len}",
            "mov [rsp + 0x30], {return_len}",

            "mov r10, rcx",
            "syscall",

            "add rsp, 0x38",

            in("rcx") process_handle,
            in("rdx") base_address,
            in("r8") info_class,
            in("r9") memory_info,

            info_len = in(reg) info_len,
            return_len = in(reg) return_len,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        )
    };

    status
}

/// NtProtectVirtualMemory
#[inline(always)]
pub fn nt_protect_virtual_memory(
    process_handle: Handle,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    new_protection: u32,
    old_protection: *mut u32,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_protect_virtual_memory;

    unsafe {
        asm!(
            "sub rsp, 0x30",
            "mov [rsp + 0x28], {old_protection}",

            "mov r10, rcx",
            "syscall",

            "add rsp, 0x30",

            in("rcx") process_handle,
            in("rdx") base_address,
            in("r8") region_size,
            in("r9") new_protection,
            old_protection = in(reg) old_protection,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        );
    };

    status
}

/// NtAllocateVirtualMemory
#[inline(always)]
pub fn nt_allocate_virtual_memory(
    process_handle: Handle,
    base_address: *mut usize,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protection: u32,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_allocate_virtual_memory;

    unsafe {
        asm!(
            "sub rsp, 0x38",
            "mov [rsp + 0x28], {allocation_type:e}",
            "mov [rsp + 0x30], {protection:e}",

            "mov r10, rcx",
            "syscall",

            "add rsp, 0x38",

            in("rcx") process_handle,
            in("rdx") base_address,
            in("r8") zero_bits,
            in("r9") region_size,
            allocation_type = in(reg) allocation_type,
            protection = in(reg) protection,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        );
    };

    status
}

/// NtFreeVirtualMemory
#[inline(always)]
pub fn nt_free_virtual_memory(
    process_handle: Handle,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    free_type: u32,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_free_virtual_memory;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") process_handle,
            in("rdx") base_address,
            in("r8") region_size,
            in("r9") free_type,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        )
    };

    status
}

/// NtOpenThread
#[inline(always)]
pub fn nt_open_thread(
    thread_handle: *mut Handle,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
    client_id: *mut ClientId,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_open_thread;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") thread_handle,
            in("rdx") desired_access,
            in("r8") object_attributes,
            in("r9") client_id,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        )
    };

    status
}

/// NtCreateThreadEx
#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub fn nt_create_thread_ex(
    thread_handle: *mut Handle,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
    process_handle: Handle,
    start_routine: *mut c_void,
    argument: *mut c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: *mut PsAttributeList,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_create_thread_ex;

    unsafe {
        asm!(
            "sub rsp, 0x60",
            "mov [rsp + 0x28], {start_routine}",
            "mov [rsp + 0x30], {argument}",
            "mov [rsp + 0x38], {create_flags:e}",
            "mov [rsp + 0x40], {zero_bits}",
            "mov [rsp + 0x48], {stack_size}",
            "mov [rsp + 0x50], {maximum_stack_size}",
            "mov [rsp + 0x58], {attribute_list}",

            "mov r10, rcx",
            "syscall",

            "add rsp, 0x60",

            in("rcx") thread_handle,
            in("rdx") desired_access,
            in("r8") object_attributes,
            in("r9") process_handle,

            start_routine = in(reg) start_routine,
            argument = in(reg) argument,
            create_flags = in(reg) create_flags,
            zero_bits = in(reg) zero_bits,
            stack_size = in(reg) stack_size,
            maximum_stack_size = in(reg) maximum_stack_size,
            attribute_list = in(reg) attribute_list,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        );
    }

    status
}

/// NtOpenThread
#[inline(always)]
pub fn nt_terminate_thread(thread_handle: Handle, exit_status: NtStatus) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_terminate_thread;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") thread_handle,
            in("rdx") exit_status,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        )
    };

    status
}

/// NtSuspendThread
#[inline(always)]
pub fn nt_suspend_thread(thread_handle: Handle, prev_suspend_count: *mut u32) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_suspend_thread;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") thread_handle,
            in("rdx") prev_suspend_count,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        )
    };

    status
}

/// NtSuspendThread
#[inline(always)]
pub fn nt_resume_thread(thread_handle: Handle, prev_suspend_count: *mut u32) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_resume_thread;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") thread_handle,
            in("rdx") prev_suspend_count,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        )
    };

    status
}

/// NtGetContextThread
#[inline(always)]
pub fn nt_get_context_thread(
    thread_handle: Handle,
    thread_context: *mut ThreadContext,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_get_context_thread;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") thread_handle,
            in("rdx") thread_context,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        )
    };

    status
}

/// NtGetContextThread
#[inline(always)]
pub fn nt_set_context_thread(
    thread_handle: Handle,
    thread_context: *const ThreadContext,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_set_context_thread;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") thread_handle,
            in("rdx") thread_context,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        )
    };

    status
}

/// NtQuerySystemInformation
#[inline(always)]
pub fn nt_query_system_information(
    class: u32,
    buffer: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_query_system_information;

    unsafe {
        asm!(
            "mov r10, rcx",				// syscall prep
            "syscall",

            in("rax") id,				// syscall id
            in("rcx") class,			// arg 1
            in("rdx") buffer,			// arg 2
            in("r8")  length,			// arg 3
            in("r9")  return_length,	// arg 4
            lateout("rax") status,		// ntstatus
            clobber_abi("system"),
        );
    };

    status
}

/// NtQueryInformationProcess
#[inline(always)]
pub fn nt_query_information_process(
    process_handle: Handle,
    process_information_class: u32,
    process_information: *mut c_void,
    process_information_length: u32,
    return_length: *mut u32,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_query_information_process;

    unsafe {
        asm!(
            "sub rsp, 0x30",
            "mov [rsp + 0x28], {return_len}",

            "mov r10, rcx",
            "syscall",

            "add rsp, 0x30",

            in("rax") id,
            in("rcx") process_handle,
            in("rdx") process_information_class,
            in("r8")  process_information,
            in("r9")  process_information_length,

            return_len = in(reg) return_length,

            lateout("rax") status,
            clobber_abi("system"),
        );
    }

    status
}

/// NtDuplicateObject
#[inline(always)]
pub fn nt_duplicate_object(
    source_process_handle: Handle,
    source_handle: Handle,
    target_process_handle: Handle,
    target_handle: *mut Handle,
    desired_access: u32,
    handle_attributes: u32,
    options: u32,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_duplicate_object;

    unsafe {
        asm!(
            "sub rsp, 0x40",

            "mov [rsp + 0x28], {desired_access:e}",
            "mov [rsp + 0x30], {handle_attributes:e}",
            "mov [rsp + 0x38], {options_arg:e}",

            "mov r10, rcx",
            "syscall",

            "add rsp, 0x40",

            in("rcx") source_process_handle,
            in("rdx") source_handle,
            in("r8") target_process_handle,
            in("r9") target_handle,

            desired_access = in(reg) desired_access,
            handle_attributes = in(reg) handle_attributes,
            options_arg = in(reg) options,
            // id = in(reg) id,

            in("rax") id,
            lateout("rax") status,
            clobber_abi("system"),
        )
    }

    status
}

/// NtQueryObject
#[inline(always)]
pub fn nt_query_object(
    handle: Handle,
    object_info_class: u32,
    object_info: *mut c_void,
    info_len: u32,
    return_len: *mut u32,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_query_object;

    unsafe {
        asm!(
            "sub rsp, 0x30",
            "mov [rsp + 0x28], {return_len}",

            "mov r10, rcx",
            "syscall",

            "add rsp, 0x30",

            in("rcx") handle,
            in("rdx") object_info_class,
            in("r8") object_info,
            in("r9") info_len,
            return_len = in(reg) return_len,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        );
    };

    status
}

/// NtWaitForSingleObject
#[inline(always)]
pub fn nt_wait_for_single_object(handle: Handle, alertable: u8, timeout: *const i64) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_wait_for_single_object;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") handle,
            in("rdx") alertable as usize,
            in("r8") timeout,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        );
    };

    status
}

/// NtQueryInformationThread
#[inline(always)]
pub fn nt_query_information_thread(
    thread_handle: Handle,
    thread_info_class: u32,
    thread_info: *mut c_void,
    thread_info_len: u32,
    return_len: *mut u32,
) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_query_information_thread;

    unsafe {
        asm!(
            "sub rsp, 0x30",
            "mov [rsp + 0x28], {return_len}",
            "mov r10, rcx",
            "syscall",
            "add rsp, 0x30",

            in("rcx") thread_handle,
            in("rdx") thread_info_class,
            in("r8") thread_info,
            in("r9") thread_info_len,
            return_len = in(reg) return_len,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        );
    }

    status
}

/// NtClose
#[inline(always)]
pub fn nt_close(handle: Handle) -> NtStatus {
    let status: NtStatus;
    let id = ntdll::syscalls().nt_close;

    unsafe {
        asm!(
            "mov r10, rcx",			// syscall prep
            "syscall",

            in("rax") id,			// syscall id
            in("rcx") handle,		// arg1
            lateout("rax") status,	// ntstatus
            clobber_abi("system"),
        );
    }

    status
}

/* win32u.dll SYSCALL WRAPPERS */

/// NtUserBuildHwndList
#[cfg(feature = "windows")]
#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub fn nt_user_build_hwnd_list(
    desktop_handle: Handle,
    parent_window_handle: Handle,
    include_children: i32,
    exclude_immersive: i32,
    thread_id: u32,
    hwnd_list_information_length: u32,
    hwnd_list_information: *mut core::ffi::c_void,
    return_length: *mut u32,
) -> NtStatus {
    let status: NtStatus;
    let id = win32u::syscalls().nt_user_build_hwnd_list;

    unsafe {
        asm!(
            "sub rsp, 0x48",

            "mov [rsp + 0x28], {thread_id:e}",
            "mov [rsp + 0x30], {hwnd_list_info_len:e}",
            "mov [rsp + 0x38], {hwnd_list_info}",
			"mov [rsp + 0x40], {return_len}",

            "mov r10, rcx",
            "syscall",

            "add rsp, 0x48",

            in("rcx") desktop_handle,
            in("rdx") parent_window_handle,
            in("r8") include_children,
            in("r9") exclude_immersive,

            thread_id = in(reg) thread_id,
            hwnd_list_info_len = in(reg) hwnd_list_information_length,
            hwnd_list_info = in(reg) hwnd_list_information,
			return_len = in(reg) return_length,

            in("rax") id,
            lateout("rax") status,
            clobber_abi("system"),
        )
    }

    status
}

/// NtUserQueryWindow
#[cfg(feature = "windows")]
#[inline(always)]
pub fn nt_user_query_window(
	hwnd: Handle,
	class: u32,
) -> u32 {
	let result: u32;
    let id = win32u::syscalls().nt_user_query_window;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") hwnd,
            in("rdx") class,

            in("rax") id,
            lateout("rax") result,
            clobber_abi("system"),
        );
    }

    result
}

/// NtUserInternalGetWindowText
#[cfg(feature = "windows")]
#[inline(always)]
pub fn nt_user_internal_get_window_text(
    hwnd: Handle,
    buffer: *mut u16,
    max_len: i32,
) -> NtStatus {
    let result: NtStatus;
    let id = win32u::syscalls().nt_user_internal_get_window_text;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") hwnd,
            in("rdx") buffer,
            in("r8")  max_len,

            in("rax") id,
            lateout("rax") result,
            clobber_abi("system"),
        );
    }

    result
}

/// NtUserGetClassName
#[cfg(feature = "windows")]
#[inline(always)]
pub fn nt_user_get_class_name(
    hwnd: Handle,                    // HWND
    real: i32,                       // BOOL
    class_name: *mut UnicodeString,  // PUNICODE_STRING
) -> i32 {
    let result: i32;
    let id = win32u::syscalls().nt_user_get_class_name;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") hwnd,
            in("rdx") real,
            in("r8")  class_name,

            in("rax") id,
            lateout("rax") result,
            clobber_abi("system"),
        );
    }

    result
}


