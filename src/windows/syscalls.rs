use std::sync::LazyLock;

use crate::windows::utils::{get_export, get_module_base};

// static NTDLL_BASE: OnceLock<usize> = OnceLock::new();
static NTDLL_BASE: LazyLock<usize> = LazyLock::new(|| {
	get_module_base("ntdll.dll").expect("ntdll.dll not found") as usize
});
// static SYSCALLS: OnceLock<Syscalls> = OnceLock::new();
static SYSCALLS: LazyLock<Syscalls> = LazyLock::new(Syscalls::resolve);

#[inline(always)]
pub fn syscalls() -> &'static Syscalls {
    &*SYSCALLS
}

macro_rules! syscalls {
    ($($field:ident => $name:literal),* $(,)?) => {
        pub struct Syscalls {
            $(pub $field: u32,)*
        }

        impl Syscalls {
            pub fn resolve() -> Self {
                Self {
                    $($field: get_syscall_id($name).expect($name),)*
                }
            }
        }
    };
}

syscalls! {
    nt_open_process => "NtOpenProcess",
	nt_terminate_process => "NtTerminateProcess",
	
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

    nt_query_system_information => "NtQuerySystemInformation",
    nt_query_information_process => "NtQueryInformationProcess",
	nt_query_information_thread => "NtQueryInformationThread",

	nt_duplicate_object => "NtDuplicateObject",
	nt_query_object => "NtQueryObject",
	nt_wait_for_single_object => "NtWaitForSingleObject",

    nt_close => "NtClose",
}

fn get_syscall_id(name: &str) -> Option<u32> {
    get_export(*NTDLL_BASE as _, name).map(|address| extract_syscall_id(address))?
}

#[inline(always)]
fn extract_syscall_id(func: *const u8) -> Option<u32> {
    unsafe {
        // look for:
        // mov r10, rcx; mov eax, imm32
        if *func.add(3) == 0xB8 {
            Some(*(func.add(4) as *const u32))
        } else {
            None
        }
    }
}
