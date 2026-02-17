use crate::windows::structs::{
    PsAttributeList, ThreadContext, TokenPrivileges,
};

use super::{
    Handle, NtStatus,
    structs::{ClientId, ObjectAttributes},
    syscalls::syscalls,
};
use core::{arch::asm, ffi::c_void};

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
    let id = syscalls().nt_open_process;

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
pub fn nt_terminate_process(
    process_handle: Handle,
    exit_status: NtStatus,
) -> NtStatus {
    let status: NtStatus;
    let id = syscalls().nt_terminate_process;

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

/// NtSetInformationProcess
#[inline(always)]
pub fn nt_set_information_process(
    process_handle: Handle,
    process_info_class: u32,
    process_info: *mut c_void,
    info_len: u32,
) -> NtStatus {
    let status: NtStatus;
    let id = syscalls().nt_set_information_process;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") process_handle,
            in("rdx") process_info_class,
            in("r8") process_info,
            in("r9") info_len,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        )
    };

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
    let id = syscalls().nt_read_virtual_memory;

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
    let id = syscalls().nt_write_virtual_memory;

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
    let id = syscalls().nt_query_virtual_memory;

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
    let id = syscalls().nt_protect_virtual_memory;

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
    let id = syscalls().nt_allocate_virtual_memory;

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
    let id = syscalls().nt_free_virtual_memory;

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
    let id = syscalls().nt_open_thread;

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
    let id = syscalls().nt_create_thread_ex;

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
pub fn nt_terminate_thread(
    thread_handle: Handle,
    exit_status: NtStatus,
) -> NtStatus {
    let status: NtStatus;
    let id = syscalls().nt_terminate_thread;

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
pub fn nt_suspend_thread(
    thread_handle: Handle,
    prev_suspend_count: *mut u32,
) -> NtStatus {
    let status: NtStatus;
    let id = syscalls().nt_suspend_thread;

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
pub fn nt_resume_thread(
    thread_handle: Handle,
    prev_suspend_count: *mut u32,
) -> NtStatus {
    let status: NtStatus;
    let id = syscalls().nt_resume_thread;

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
    let id = syscalls().nt_get_context_thread;

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
    let id = syscalls().nt_set_context_thread;

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

/// NtSetInformationThread
#[inline(always)]
pub fn nt_set_information_thread(
    thread_handle: Handle,
    thread_info_class: u32,
    thread_info: *const c_void,
    info_len: u32,
) -> NtStatus {
    let status: NtStatus;
    let id = syscalls().nt_set_information_thread;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") thread_handle,
            in("rdx") thread_info_class,
            in("r8") thread_info,
            in("r9") info_len,

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
    let id = syscalls().nt_query_system_information;

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
    let id = syscalls().nt_query_information_process;

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
    let id = syscalls().nt_duplicate_object;

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
    let id = syscalls().nt_query_object;

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
pub fn nt_wait_for_single_object(
    handle: Handle,
    alertable: u8,
    timeout: *const i64,
) -> NtStatus {
    let status: NtStatus;
    let id = syscalls().nt_wait_for_single_object;

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
    let id = syscalls().nt_query_information_thread;

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

/// NtOpenProcessToken
#[inline(always)]
pub fn nt_open_process_token(
    process_handle: Handle,
    desired_access: u32,
    token_handle: *mut Handle,
) -> NtStatus {
    let status: NtStatus;
    let id = syscalls().nt_open_process_token;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") process_handle,
            in("rdx") desired_access,
            in("r8") token_handle,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        );
    }

    status
}

/// NtAdjustPrivilegeToken
#[inline(always)]
pub fn nt_adjust_privileges_token(
    token_handle: Handle,
    disable_all_privileges: u32,
    new_state: *mut TokenPrivileges,
    buffer_length: u32,
    previous_state: *mut TokenPrivileges,
    return_length: *mut u32,
) -> NtStatus {
    let status: NtStatus;
    let id = syscalls().nt_adjust_privileges_token;

    unsafe {
        asm!(
            "sub rsp, 0x38",
            "mov [rsp + 0x28], {previous_state}",
            "mov [rsp + 0x30], {return_length}",
            "mov r10, rcx",
            "syscall",
            "add rsp, 0x38",

            in("rcx") token_handle,
            in("rdx") disable_all_privileges,
            in("r8") new_state,
            in("r9") buffer_length,
            previous_state = in(reg) previous_state,
            return_length = in(reg) return_length,

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
    let id = syscalls().nt_close;

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",

            in("rcx") handle,

            in("rax") id,
            lateout("rax") status,

            clobber_abi("system"),
        );
    }

    status
}
