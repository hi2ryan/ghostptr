pub mod section;
pub mod export;
pub mod import;

pub use section::*;
pub use export::*;
pub use import::*;

use core::{mem::offset_of, ffi::CStr};
use crate::{
    MemScanIter, ProcessError, Result, Scanner, SectionCharacteristics, process::{MemoryRegionIter, Process, utils::AddressRange}, windows::{
        DllEntryPoint,
        structs::{
            ImageDataDirectory, ImageDosHeader, ImageExportDirectory, ImageImportDescriptor, ImageNtHeaders64, ImageOptionalHeader64, ImageSectionHeader
        },
    }
};

/// A view of a module loaded in a process (local or remote).
#[derive(Debug, Clone)]
pub struct Module<'process> {
    pub(crate) process: &'process Process,

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

impl<'process> Module<'process> {
	/// Returns the virtual address range covered by this module.
	#[inline(always)]
    pub fn virtual_range(&self) -> AddressRange {
		self.base_address..(self.base_address + self.image_size as usize)
    }

	/// Checks whether an address lies within the virtual address range of this module.
	#[inline(always)]
	pub fn contains(&self, address: &usize) -> bool {
		self.virtual_range().contains(address)
	}

	/// Offsets an RVA (relative virtual address) to a VA (virtual address)
	#[inline(always)]
	pub fn offset(&self, rva: usize) -> usize {
		self.base_address + rva
	}

	/// Scans virtual memory in the process according to the
	/// virtual address range covered by this module.
	#[inline(always)]
    pub fn scan_mem<'scanner, S: Scanner>(&self, scanner: &'scanner S) -> MemScanIter<'process, 'scanner, S> {
        self.process.scan_mem(self.virtual_range(), scanner)
    }

	/// Returns an iterator over the memory regions that intersect this module.
	#[inline(always)]
    pub fn mem_regions(&self) -> MemoryRegionIter<'process> {
        MemoryRegionIter::new(self.process, self.virtual_range())
    }

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
    ///   export directory or the PE headers are inconsistent.
    /// - [`ProcessError::NtStatus`] if reading memory fails.
    pub fn exports(&self) -> Result<Vec<Export>> {
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
    /// - [`ProcessError::NtStatus`] if reading memory fails.
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

	/// Parses and returns all imports from this PE module.
	///
	/// Walks the import directory of the module's PE header, reading
	/// all imported DLL names and their functions (by name or ordinal).
	///
	/// # Errors
	/// - [`ProcessError::MalformedPE`] if the module appears to have no
	///   import directory or the PE headers are invalid.
	/// - [`ProcessError::NtStatus`] if reading memory fails.
	pub fn imports(&self) -> Result<Vec<Import>> {
		let mut imports = Vec::new();
		
		// iterate import descriptors
		let mut curr_import = self.get_first_import_addr()?;
		loop {
			let descriptor: ImageImportDescriptor = self.process.read_mem(curr_import)?;
			if descriptor.original_first_thunk == 0 && descriptor.first_thunk == 0 {
				break;
			}

			// read the name of the imported dll
			let dll_name = self.process.read_c_string(
				self.base_address + descriptor.name as usize,
				None
			)?;

			let mut functions = Vec::new();

			// read initial thunk RVA
			let thunk_rva = if descriptor.original_first_thunk != 0 {
				descriptor.original_first_thunk
			} else {
				descriptor.first_thunk
			};

			// iterate thunks
			let mut curr_thunk = (self.base_address + thunk_rva as usize) as *const usize;
			loop {
				// read thunk value
				let thunk = self.process.read_mem(curr_thunk)?;
				if thunk == 0 {
					break;
				}

				let is_ordinal = (thunk & 0x8000000000000000) != 0;
				if is_ordinal {
					// ordinal import
					let ordinal = (thunk & 0xFFFF) as u16;
					functions.push(ImportType::Ordinal(ordinal));
				} else {
					// name import

					// thunk value is an RVA to import by name
					// skip the first 2 bytes (hint)
					let name_addr = self.base_address + thunk + size_of::<u16>();
					let name = self.process.read_c_string(name_addr, Some(256))?;
					functions.push(ImportType::Name(name));
				}

				curr_thunk = unsafe { curr_thunk.add(1) };
			}

			imports.push(Import { dll_name, functions });
			curr_import = unsafe { curr_import.add(1) };
		}

		Ok(imports)
	}

	/// Parses all image section headers of the module.
    pub fn sections<'module>(&'module self) -> Result<Vec<Section<'process, 'module>>> {
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
                    SectionCharacteristics::from_bits(section.characteristics);

                sections.push(Section {
					module: self,

                    name,
                    address,
                    size,
                    characteristics,
                })
            }
        }

        Ok(sections)
    }

	/// Parses all the image section headers of the module and
	/// searches for a matching section name.
	pub fn get_section<'module>(&'module self, name: &str) -> Result<Section<'process, 'module>> {
		if let Some(section) = self
			.sections()?
			.into_iter()
			.find(|s| s.name == name)
		{
			Ok(section)
		} else {
			Err(ProcessError::SectionNotFound(name.to_owned()))
		}
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

	fn get_first_import_addr(&self) -> Result<*const ImageImportDescriptor> {
        let nt_headers_ptr = self.nt_headers()?;

        // ImageNtHeaders64->ImageOptionalHeader64      +0x18
        // ImageOptionalHeader64->ImageDataDirectory    +0x70
		// ImageDataDirectory[1]                        +0x8
        // ImageDataDirectory->VirtualAddress		    +0x0
		let import_dir_rva: u32 = self.process.read_mem(nt_headers_ptr + 0x18 + 0x70 + 0x8)?;
	    if import_dir_rva == 0 {
            return Err(ProcessError::MalformedPE);
        }

        Ok((self.base_address + import_dir_rva as usize) as *const ImageImportDescriptor)
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
    use crate::*;

    #[test]
    fn get_remote_module_export() -> Result<()> {
        let process = Process::open_first_named("Discord.exe", ProcessAccess::ALL)?;
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
        let process = Process::open_first_named("Discord.exe", ProcessAccess::ALL)?;
        let ntdll = process
            .modules(ModuleIterOrder::Initialization)?
            .next()
            .unwrap();
        assert_eq!(ntdll.name, "ntdll.dll");

        let has_text_section = ntdll.sections()?.iter().any(|section| section.name == ".text");
        assert!(has_text_section, "no .text section found in remote ntdll.dll");

        Ok(())
    }

	#[test]
	fn get_module_imports() -> Result<()> {
		let process = Process::current();
		let kernel32 = process.get_module("kernel32.dll")?;
		let imports = kernel32.imports()?;

		assert!(!imports.is_empty(), "no imports found for kernel32.dll");

		let ntdll_imports = imports.iter().find(|import| import.dll_name == "ntdll.dll");
		assert!(ntdll_imports.is_some(), "ntdll.dll not found in kernel32.dll imports");
		assert!(
			ntdll_imports.unwrap().functions.contains(&ImportType::Name("NtClose".to_owned())),
			"NtClose not found in kernel32.dll imports from ntdll.dll"
		);

		Ok(())
	}
}
