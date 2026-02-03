use core::ffi::CStr;

use crate::windows::{
    structs::{ImageDosHeader, ImageExportDirectory, ImageNtHeaders64, ImageSectionHeader},
    utils::{get_export, get_module_base},
};

macro_rules! syscalls {
    (
        module = $module:literal;
        $($field:ident => $name:literal),* $(,)?
    ) => {
        pub struct Syscalls {
            $(pub $field: u32,)*
        }

        // static SYSCALL_MODULE: ::std::sync::LazyLock<$crate::windows::syscalls::SyscallModule> =
        //     ::std::sync::LazyLock::new(|| {
        //         $crate::windows::syscalls::SyscallModule::new($module)
        //     });

        static SYSCALLS: ::std::sync::LazyLock<Syscalls> =
			::std::sync::LazyLock::new(|| {
				let module = $crate::windows::syscalls::SyscallModule::new($module);
				Syscalls::resolve(&module)
			});

        impl Syscalls {
            fn resolve(module: &$crate::windows::syscalls::SyscallModule) -> Self {
                Self {
                    $(
						$field: module.syscall_id($name).expect($name),
					)*
                }
            }
        }

        #[inline(always)]
        pub fn syscalls() -> &'static Syscalls {
            &SYSCALLS
        }
    };
}

pub mod ntdll {
    syscalls! {
        module = "ntdll.dll";

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
}

#[cfg(feature = "windows")]
pub mod win32u {
    syscalls! {
        module = "win32u.dll";

        nt_user_build_hwnd_list => "NtUserBuildHwndList",
        nt_user_query_window => "NtUserQueryWindow",
        nt_user_get_class_name => "NtUserGetClassName",
        nt_user_internal_get_window_text => "NtUserInternalGetWindowText",
    }
}

enum ModuleSource {
    Mapped { base: usize },
    Disk { image: Vec<u8> },
}

pub struct SyscallModule {
    source: ModuleSource,
}

impl SyscallModule {
    pub fn new(name: &'static str) -> Self {
        if let Some(base) = get_module_base(name) {
            return Self {
                source: ModuleSource::Mapped {
                    base: base as usize,
                },
            };
        }

        let path = format!(r"C:\Windows\System32\{}", name);
        let image =
            std::fs::read(&path).unwrap_or_else(|_| panic!("failed to read {} from disk", name));

        Self {
            source: ModuleSource::Disk { image },
        }
    }

    pub fn syscall_id(&self, name: &str) -> Option<u32> {
        match &self.source {
            ModuleSource::Mapped { base } => {
                get_export(*base as _, name).map(extract_syscall_id)?
            }
            ModuleSource::Disk { image } => extract_syscall_id_from_disk(image, name),
        }
    }
}

#[inline(always)]
fn extract_syscall_id(func: *const u8) -> Option<u32> {
    unsafe {
        // mov r10, rcx
        // mov eax, imm32
        if *func == 0x4C && *func.add(3) == 0xB8 {
            Some(*(func.add(4) as *const u32))
        } else {
            None
        }
    }
}

fn extract_syscall_id_from_disk(image: &[u8], name: &str) -> Option<u32> {
    unsafe {
        let dos_header = image.as_ptr() as *const ImageDosHeader;
        if (*dos_header).e_magic != 0x5A4D {
            return None;
        }

        let nt_headers =
            image.as_ptr().add((*dos_header).e_lfanew as usize) as *const ImageNtHeaders64;
        if (*nt_headers).signature != 0x00004550 {
            return None;
        }

        let first_section = (nt_headers as *const u8).add(size_of::<ImageNtHeaders64>())
            as *const ImageSectionHeader;

        let export_dir = (*nt_headers).optional_header.data_directory[0];
        if export_dir.virtual_address == 0 {
            return None;
        }

        let export_dir = image.as_ptr().add(rva_to_offset(
            export_dir.virtual_address,
            nt_headers,
            first_section,
        )?) as *const ImageExportDirectory;

        let names = image.as_ptr().add(rva_to_offset(
            (*export_dir).address_of_names,
            nt_headers,
            first_section,
        )?) as *const u32;

        let ords = image.as_ptr().add(rva_to_offset(
            (*export_dir).address_of_name_ordinals,
            nt_headers,
            first_section,
        )?) as *const u16;

        let funcs = image.as_ptr().add(rva_to_offset(
            (*export_dir).address_of_functions,
            nt_headers,
            first_section,
        )?) as *const u32;

        let name_bytes = name.as_bytes();
        for i in 0..(*export_dir).number_of_names {
            let name_rva = *names.add(i as usize);
            let name_ptr = image
                .as_ptr()
                .add(rva_to_offset(name_rva, nt_headers, first_section)?)
                as *const i8;

            let export_name = CStr::from_ptr(name_ptr);
            if export_name.to_bytes() != name_bytes {
                continue;
            }

            let ord = *ords.add(i as usize) as usize;
            let func_rva = *funcs.add(ord);
            let func = image
                .as_ptr()
                .add(rva_to_offset(func_rva, nt_headers, first_section)?);

            // mov r10, rcx
            // mov eax, imm32
            if *func == 0x4C && *func.add(3) == 0xB8 {
                let ssn = core::ptr::read_unaligned(func.add(4) as *const u32);
                println!("{} -> {:#X}", name, ssn);
				return Some(ssn);
            } else {
                return None;
            }
        }

        None
    }
}

fn rva_to_offset(
    rva: u32,
    nt_headers: *const ImageNtHeaders64,
    first_section: *const ImageSectionHeader,
) -> Option<usize> {
    unsafe {
        let count = (*nt_headers).file_header.number_of_sections;
        for i in 0..count {
            let s = &*first_section.add(i as usize);
            let start = s.virtual_address;
            let end = start + s.misc.virtual_size;
            if rva >= start && rva < end {
                return Some((rva - start + s.pointer_to_raw_data) as usize);
            }
        }
        None
    }
}
