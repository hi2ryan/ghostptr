use core::ffi::CStr;
use core::mem::offset_of;

use crate::{
    ProcessError, Result, SectionCharacteristics,
    process::{Process, Scanner, utils::AddressRange},
    windows::{
        DllEntryPoint,
        structs::{
            ImageDataDirectory, ImageDosHeader, ImageExportDirectory, ImageNtHeaders64, ImageOptionalHeader64, ImageSectionHeader
        },
    },
};

/// Represents an image section header from a PE module
#[derive(Debug)]
pub struct Section {
    pub name: String,
    pub size: u32,
    pub address: usize,
    pub characteristics: SectionCharacteristics,
}

impl Section {
    pub fn virtual_range(&self) -> AddressRange {
        let start = self.address;
        let size = self.size as usize;
        start..(start + size)
    }
}

/// Represents an exported symbol from a PE module's Export Address Table.
///
/// Exports can be:
/// 	- Named
/// 	- Ordinal-only (no name)
/// 	- Forwarded to another module
#[derive(Debug)]
pub struct Export {
    /// The name of the exported symbol, if present.
    pub name: Option<String>,

    /// The export ordinal.
    pub ordinal: u16,

    /// The resolved virtual address of the exported function.
    /// This will be `0` if the export is forwarded.
    pub address: usize,

    /// The forwarder target, if this export is forwarded.
    ///
    /// The ASCII string's format is:
    /// ```text
    /// MODULE.NAME
    /// MODULE.#ORDINAL
    /// ```
    pub forwarded_to: Option<String>,
}

/// A view of a module loaded in a process (local or remote).
#[derive(Debug)]
pub struct Module<'a, P: Process> {
    pub(crate) process: &'a P,

    /// Full path to the module.
    pub full_name: String,

    /// The file name of the module without the path.
    ///
    /// e.g. ntdll.dll, kernel32.dll
    pub name: String,

    /// Base address where the module is mapped in the process' memory.
    pub base_address: usize,

    /// Entry point of the module.
    pub entry_point: *const DllEntryPoint,

    /// The size of the image, in bytes, from the PE header.
    pub image_size: u32,

    /// Raw module flags from the LDR Module
    pub flags: u32,
}

impl<'a, P: Process> Module<'a, P> {
    /// Enumerates all exports from this module.
    ///
    /// Parses the PE headers in the target process, walks the export
    /// directory, and returns a list of [`Export`] entries. Both named and
    /// ordinal-only exports are included.
    ///
    /// For forwarded exports (where the export entry points *back* into the
    /// export directory), `forwarded_to` will be set and `address` will be `0`.
    ///
    /// # Errors
    /// - [`ProcessError::MalformedPE`] if the module appears to have no
    /// export directory or the PE headers are inconsistent.
    /// - [`ProcessError::NtStatus`] if reading memory fails.
    pub fn get_exports(&self) -> Result<Vec<Export>> {
        // self.base_address is the ImageDosHeader
        // e_lfanew is the rva to the ImageNtHeaders64
        let nt_headers_offset: u32 = self
            .process
            .read_mem(self.base_address + offset_of!(ImageDosHeader, e_lfanew))?;
        let nt_headers_ptr = self.base_address + nt_headers_offset as usize;

		let exp_data_dir: ImageDataDirectory = self.process.read_mem(nt_headers_ptr +
			offset_of!(ImageNtHeaders64, optional_header) +
			
			// we do not need to do any additional offsets from this point
			// because ImageOptionalHeader64->data_directory[0] is ImageDataDirectory
			// and ImageDataDirectory->virtual_address is the first property (0x0 offset)
			offset_of!(ImageOptionalHeader64, data_directory)
		)?;
        if exp_data_dir.virtual_address == 0 {
            return Err(ProcessError::MalformedPE);
        }

        let export_directory: ImageExportDirectory = self
            .process
            .read_mem(self.base_address + exp_data_dir.virtual_address as usize)?;
        if export_directory.number_of_functions == 0 {
            return Ok(vec![]);
        }

        // convert RVAs to VAs
        let (names, ordinals, functions) = self.resolve_exports(export_directory)?;

        let mut exports = Vec::with_capacity(functions.len());

        // push functions
        let ordinal_base = export_directory.base as u16;
        for (i, &func_rva) in functions.iter().enumerate() {
            let ordinal = ordinal_base + i as u16;
            let address = if func_rva != 0 {
                self.base_address + func_rva as usize
            } else {
                0
            };

            exports.push(Export {
                name: None,
                ordinal,
                address,
                forwarded_to: None,
            });
        }

        // name the exports
        for i in 0..export_directory.number_of_names as usize {
            let name_rva = names[i];
            if name_rva == 0 {
                continue;
            }

            let ordinal = ordinals[i] as usize;
            if ordinal >= exports.len() {
                continue;
            }

            let name_va = self.base_address + name_rva as usize;
            let name = self.process.read_c_string(name_va, None)?;

            exports[ordinal].name = Some(name);
        }

        // check for forwarded exports
        let exports_start = self.base_address + exp_data_dir.virtual_address as usize;
        let exports_end = exports_start + exp_data_dir.size as usize;

        // resolve forwarded exports
        for export in &mut exports {
            if export.address >= exports_start && export.address < exports_end {
                // points back to an export
                let forwarder = self.process.read_c_string(export.address, None)?;
                export.forwarded_to = Some(forwarder);
                export.address = 0;
            }
        }

        Ok(exports)
    }

    /// Looks up an exported procedure by name and returns its address.
    ///
    /// Walks the export directory of the module's PE header, searching for
    /// the name. Returns the function's VA within the target process, if found.
    ///
    /// Forwarded exports are **not** resolved by this method; if the name
    /// refers to a forwarder, you will receive the address of the forwarder
    /// string, not the final target.
    ///
    /// # Errors
    ///
    /// - [`ProcessError::MalformedPE`] if the export directory cannot be located.
    /// - [`ProcessError::ExportNotFound`] if no export with the given name exists in this module.
    /// - [`ProcessError::NtStatus`] if reading the memory fails.
    pub fn get_export(&self, name: &str) -> Result<usize> {
        let export_directory = self.get_export_dir()?;
        if export_directory.number_of_names == 0 {
            // no named exports, early return
            return Err(ProcessError::ExportNotFound(name.to_string()));
        }

        // convert RVAs to VAs
        let (names, ordinals, functions) = self.resolve_exports(export_directory)?;

        // iterate exported names
        for i in 0..export_directory.number_of_names as usize {
            let name_rva = names[i];
            let name_va = self.base_address + name_rva as usize;

            let export_name = self.process.read_c_string(name_va, None)?;
			if export_name == name {
                // got the export
                let ordinal = ordinals[i] as usize;
                let fn_rva = functions[ordinal];

                return Ok(self.base_address + fn_rva as usize);
            }
        }

        Err(ProcessError::ExportNotFound(name.to_string()))
    }

    pub fn sections(&self) -> Result<Vec<Section>> {
        let nt_headers = self.nt_headers()?;

        // ImageNtHeaders64->FileHeader 	 +0x4
        // ImageFileHeader->NumberOfSections +0x2
        let num_sections: u16 = self.process.read_mem(nt_headers + 0x4 + 0x2)?;

        // ImageNtHeaders64->FileHeader 	 	 +0x4
        // ImageFileHeader->SizeOfOptionalHeader +0x10
        let opt_header_size: u16 = self.process.read_mem(nt_headers + 0x4 + 0x10)?;
        let mut sections = Vec::with_capacity(num_sections as usize);

        // first section is after optional header (after ntheaders)
        let first_section = (nt_headers
            + offset_of!(ImageNtHeaders64, optional_header)
            + opt_header_size as usize) as *const ImageSectionHeader;

        let raw_sections = self
            .process
            .read_slice(first_section, num_sections as usize)?;

        // parse sections
        for section in raw_sections {
            if let Ok(c_name) = CStr::from_bytes_until_nul(&section.name) {
                let Ok(name_slice) = c_name.to_str() else {
                    continue;
                };

                let name = name_slice.to_owned();
                let address_rva = section.virtual_address;
                let address = self.base_address + address_rva as usize;
                let size = unsafe { section.misc.virtual_size };
                let characteristics =
                    SectionCharacteristics::from_bits_retain(section.characteristics);

                sections.push(Section {
                    name,
                    address: address,
                    size: size,
                    characteristics,
                })
            }
        }

        Ok(sections)
    }

    #[inline(always)]
    pub fn virtual_range(&self) -> AddressRange {
		self.base_address..(self.base_address + self.image_size as usize)
    }

    pub fn pattern_scan<S: Scanner>(&self, pattern: &S) -> Result<Vec<usize>> {
        self.process.scan_mem(self.virtual_range(), pattern)
    }

    fn nt_headers(&self) -> Result<usize> {
        // self.base_address is the ImageDosHeader
        // e_lfanew is the rva to the ImageNtHeaders64
        let nt_headers_offset: u32 = self
            .process
            .read_mem(self.base_address + offset_of!(ImageDosHeader, e_lfanew))?;

        let ptr = self.base_address + nt_headers_offset as usize;
        Ok(ptr)
    }

    fn get_export_dir(&self) -> Result<ImageExportDirectory> {
        let nt_headers_ptr = self.nt_headers()?;

        // ImageNtHeaders64->ImageOptionalHeader64      +0x18
        // ImageOptionalHeader64->ImageDataDirectory[0] +0x70
        // ImageDataDirectory->VirtualAddress		    +0x0
		let export_dir_rva: u32 = self.process.read_mem(nt_headers_ptr + 0x18 + 0x70)?;
	    if export_dir_rva == 0 {
            return Err(ProcessError::MalformedPE);
        }

        self.process
            .read_mem(self.base_address + export_dir_rva as usize)
    }

    fn resolve_exports(
        &self,
        export_directory: ImageExportDirectory,
    ) -> Result<(Vec<u32>, Vec<u16>, Vec<u32>)> {
        // convert RVAs to VAs
        let names_va = self.base_address + export_directory.address_of_names as usize;
        let ordinals_va = self.base_address + export_directory.address_of_name_ordinals as usize;
        let functions_va = self.base_address + export_directory.address_of_functions as usize;

        // read names, ordinals, & functions
        let names: Vec<u32> = self
            .process
            .read_slice(names_va, export_directory.number_of_names as usize)?;

        let ordinals: Vec<u16> = self
            .process
            .read_slice(ordinals_va, export_directory.number_of_names as usize)?;

        let functions: Vec<u32> = self
            .process
            .read_slice(functions_va, export_directory.number_of_functions as usize)?;

        Ok((names, ordinals, functions))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        iter::module::ModuleIterOrder,
        process::{Process, ProcessAccess, Result, remote::RemoteProcess},
    };

    #[test]
    fn get_remote_module_export() -> Result<()> {
        let process = RemoteProcess::open_first_named("Discord.exe", ProcessAccess::ALL_ACCESS)?;
        let ntdll = process
            .modules(ModuleIterOrder::Initialization)?
            .next()
            .unwrap();
        assert_eq!(ntdll.name, "ntdll.dll");

        // NtWriteVirtualMemory bytes
        const EXPECTED_BYTES: [u8; 24] = [
            // 0xFF is where the syscall number is
            0x4c, 0x8b, 0xd1, 0xb8, 0xFF, 0x00, 0x00, 0x00, 0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe,
            0x7f, 0x01, 0x75, 0x03, 0x0f, 0x05, 0xc3, 0xcd, 0x2e, 0xc3,
        ];

        let base_address = ntdll.get_export("NtWriteVirtualMemory")?;
        let fn_bytes = process.read_slice::<u8>(base_address, EXPECTED_BYTES.len())?;

        // match NtWriteVirtualMemory bytes
        for (&expected, &byte) in EXPECTED_BYTES.iter().zip(fn_bytes.iter()) {
            if expected == 0xFF {
                // ignore syscall number because they can differ between versions
                continue;
            }

            assert_eq!(
                expected, byte,
                "failed to find correct NtWriteVirtualMemory export: mismatched bytes"
            )
        }

        Ok(())
    }

    #[test]
    fn get_remote_module_sections() -> Result<()> {
        let process = RemoteProcess::open_first_named("Discord.exe", ProcessAccess::ALL_ACCESS)?;
        let ntdll = process
            .modules(ModuleIterOrder::Initialization)?
            .next()
            .unwrap();
        assert_eq!(ntdll.name, "ntdll.dll");

        let num_sections = ntdll.sections()?.len();
        assert_eq!(num_sections, 15, "mismatched ntdll section count");

        Ok(())
    }
}
