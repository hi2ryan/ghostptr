use std::sync::LazyLock;

use crate::windows::utils::{get_export_by_hash, get_ntdll_base};

static NTDLL_BASE: LazyLock<usize> =
    LazyLock::new(|| get_ntdll_base() as usize);
static SYSCALLS: LazyLock<Syscalls> = LazyLock::new(Syscalls::resolve);

/// Returns a reference to the resolved syscalls' IDs.
#[inline(always)]
pub fn syscalls() -> &'static Syscalls {
    &SYSCALLS
}

macro_rules! syscalls {
    ($($field:ident => $name:literal),* $(,)?) => {
        pub struct Syscalls {
            $(pub $field: u32,)*
        }

        impl Syscalls {
            pub fn resolve() -> Self {
                Self {
                    $($field: get_syscall_id($crate::windows::utils::fnv1a_hash($name.as_bytes())).unwrap(),)*
                }
            }
        }
    };
}

syscalls! {
    nt_open_process => "NtOpenProcess",
    nt_terminate_process => "NtTerminateProcess",
    nt_set_information_process => "NtSetInformationProcess",

    nt_read_virtual_memory => "NtReadVirtualMemory",
    nt_write_virtual_memory => "NtWriteVirtualMemory",
    nt_query_virtual_memory => "NtQueryVirtualMemory",
    nt_protect_virtual_memory => "NtProtectVirtualMemory",
    nt_allocate_virtual_memory => "NtAllocateVirtualMemory",
    nt_free_virtual_memory => "NtFreeVirtualMemory",

    nt_open_thread => "NtOpenThread",
    nt_create_thread_ex => "NtCreateThreadEx",
    nt_terminate_thread => "NtTerminateThread",
    nt_suspend_thread => "NtSuspendThread",
    nt_resume_thread => "NtResumeThread",
    nt_get_context_thread => "NtGetContextThread",
    nt_set_context_thread => "NtSetContextThread",
    nt_set_information_thread => "NtSetInformationThread",

    nt_query_system_information => "NtQuerySystemInformation",
    nt_query_information_process => "NtQueryInformationProcess",
    nt_query_information_thread => "NtQueryInformationThread",

    nt_duplicate_object => "NtDuplicateObject",
    nt_query_object => "NtQueryObject",
    nt_wait_for_single_object => "NtWaitForSingleObject",

    nt_open_process_token => "NtOpenProcessToken",
    nt_adjust_privileges_token => "NtAdjustPrivilegesToken",

    nt_close => "NtClose",
}

fn get_syscall_id(hash: u32) -> Option<u32> {
    get_export_by_hash(*NTDLL_BASE as _, hash).map(extract_syscall_id)?
}

/// Extracts the syscall ID from the function's prologue.
///
/// # Safety
/// The caller must ensure that `func` points to a valid syscall stub.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[inline(always)]
pub fn extract_syscall_id(func: *const u8) -> Option<u32> {
    unsafe {
        // mov r10, rcx
		// mov eax, imm32
        if *func == 0x4C
            && *func.add(1) == 0x8B
            && *func.add(2) == 0xD1
            && *func.add(3) == 0xB8
        {
            Some(*(func.add(4) as *const u32))
        } else {
            None
        }
    }
}
