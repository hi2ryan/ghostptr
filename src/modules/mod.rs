pub mod export;
pub mod import;
pub mod section;

pub use export::{Export, ExportIterator};
pub use import::{Import, ImportType};
pub use section::Section;

use crate::{
    MemScanIter, ProcessError, Result, Scanner, SectionCharacteristics,
    process::{MemoryRegionIter, Process},
    utils::AddressRange,
    windows::{
        DllEntryPoint,
        structs::{
            ImageDataDirectory, ImageDosHeader, ImageExportDirectory, ImageImportDescriptor,
            ImageNtHeaders64, ImageOptionalHeader64, ImageSectionHeader, LdrDllLoadReason,
            LdrModule,
        },
    },
};
use core::{ffi::CStr, mem::offset_of};

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

    /// Why the module was loaded.
    pub load_reason: ModuleLoadReason,

    /// Raw module flags from the LDR Module.
    flags: u32,
}

unsafe impl<'process> Send for Module<'process> {}
unsafe impl<'process> Sync for Module<'process> {}

impl<'process> Module<'process> {
    /// Returns the virtual address range covered by this module.
    ///
    /// # Example
    /// ```rust
    /// let range = module.virtual_range();
    /// println!("module is from {:#X} to {:#X}", range.start, range.end);
    /// ```
    #[inline(always)]
    pub fn virtual_range(&self) -> AddressRange {
        self.base_address..(self.base_address + self.image_size as usize)
    }

    /// Checks whether an address lies within the virtual address range of this module.
    ///
    /// # Example
    /// ```rust
    /// const RANDOM_OFFSET: usize = 0x30848F;
    /// let address = module.offset(DATA_OFFSET);
    /// let is_contained = module.contains(&address);
    /// println!("is offset inside module: {}", is_contained);
    /// ```
    #[inline(always)]
    pub fn contains(&self, address: &usize) -> bool {
        self.virtual_range().contains(address)
    }

    /// Offsets an RVA (relative virtual address) to a VA (virtual address)
    ///
    /// # Example
    /// ```rust
    /// const DATA_OFFSET: usize = 0x30848F;
    /// let addr = module.offset(DATA_OFFSET);
    /// if let Ok(data) = process.read_mem::<usize>(addr) {
    ///     println!("{:#X}", data);
    /// }
    /// ```
    #[inline(always)]
    pub fn offset(&self, rva: usize) -> usize {
        self.base_address + rva
    }

    /// Scans virtual memory in the process according to the
    /// virtual address range covered by this module.
    ///
    /// # Example
    /// ```rust
    /// let pattern = Pattern32::from_ida("48 8B ?? ?? ?? 48 85 C0");
    /// for address in module.scan_mem(&pattern) {
    ///     let offset = address - module.base_address;
    ///     println!("pattern hit at {:#X} | offset: {}", address, offset);
    /// }
    /// ```
    #[inline(always)]
    pub fn scan_mem<'scanner, S: Scanner>(
        &self,
        scanner: &'scanner S,
    ) -> MemScanIter<'process, 'scanner, S> {
        self.process.scan_mem(self.virtual_range(), scanner)
    }

    /// Returns an iterator over the memory regions that intersect this module.
    ///
    /// # Example
    /// ```rust
    /// for region in module.mem_regions() {
    ///     println!("region {:#X} has size {:#X}", region.base_address, region.size)
    /// }
    /// ```
    #[inline(always)]
    pub fn mem_regions(&self) -> MemoryRegionIter<'process> {
        MemoryRegionIter::new(self.process, self.virtual_range())
    }

    /// Returns `true` if this module is a regular DLL (as opposed to a data file or other image).
    ///
    /// Internally, this checks the `ImageDll` flag (bit 2) in the loader entry flags.
    /// This corresponds to the `ImageDll` field in `LDR_DATA_TABLE_ENTRY.Flags`.
    ///
    /// # Example
    /// ```rust
    /// if module.is_dll() {
    ///     println!("Module is a DLL!");
    /// }
    /// ```
    #[inline]
    pub fn is_dll(&self) -> bool {
        const IMAGE_DLL: u32 = 1 << 2;
        self.flags & IMAGE_DLL != 0
    }

    /// Returns `true` if this module is a .NET (managed) assembly.
    ///
    /// This checks the `CorImage` flag (bit 23) in the loader entry flags.
    /// `CorImage` is set for modules loaded by the CLR (Common Language Runtime),
    /// indicating that the module contains managed code.
    ///
    /// # Example
    /// ```rust
    /// if module.is_dotnet() {
    ///     println!("Module is a .NET assembly!");
    /// }
    /// ```
    #[inline]
    pub fn is_dotnet(&self) -> bool {
        const COR_IMAGE: u32 = 1 << 23;
        self.flags & COR_IMAGE != 0
    }

    /// Returns the raw 32-bit flags from the loader entry.
    ///
    /// These flags are the `Flags` field from `LDR_DATA_TABLE_ENTRY` and
    /// include information about the module type, loading state, and other internal loader data.
    ///
    /// # Example
    /// ```rust
    /// let flags = module.flags();
    /// println!("Raw loader flags: {:#034b}", flags);
    /// ```
    #[inline(always)]
    pub fn flags(&self) -> u32 {
        self.flags
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
    ///
    /// # Example
    /// ```rust
    /// for export in module.exports()? {
    ///     println!("export name: {:?} | ordinal: {} | address: {:#X}", export.name, export.ordinal, export.address);
    /// }
    /// ```
    pub fn exports<'module>(&'module self) -> Result<ExportIterator<'process, 'module>> {
        ExportIterator::new(self)
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
    ///
    /// # Example
    /// ```rust
    /// type LoadLibraryA = unsafe extern "system" fn(*const c_char) -> HMODULE;
    ///
    /// let addr = kernel32.get_export("LoadLibraryA")?;
    /// let load_library_a: LoadLibraryA = unsafe { std::mem::transmute(addr) };
    /// ```
    pub fn get_export(&self, name: &str) -> Result<usize> {
        self.exports()?
            .find(|export| {
                export
                    .name
                    .as_ref()
                    .is_some_and(|export_name| export_name == name)
            })
            .map(|export| export.address)
            .ok_or(ProcessError::ExportNotFound(name.to_owned()))
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
    ///
    /// # Example
    /// ```rust
    /// type LoadLibraryA = unsafe extern "system" fn(*const c_char) -> HMODULE;
    ///
    /// let addr = kernel32.get_export("LoadLibraryA")?;
    /// let load_library_a: LoadLibraryA = unsafe { std::mem::transmute(addr) };
    /// ```
    pub fn get_export_by_ordinal(&self, ordinal: u16) -> Result<usize> {
        self.exports()?
            .find(|export| export.ordinal == ordinal)
            .map(|export| export.address)
            .ok_or(ProcessError::ExportNotFound(format!("#{ordinal}")))
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
    ///
    /// # Example
    /// ```rust
    /// println!("{} import dump:", module.name);
    /// for import in module.imports()? {
    ///     let num_functions = import.functions.len();
    ///     println!("{} functions from {}", num_functions, import.dll_name);
    /// }
    /// ```
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
            let dll_name = self
                .process
                .read_c_string(self.base_address + descriptor.name as usize, None)?;

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

            imports.push(Import {
                dll_name,
                functions,
            });
            curr_import = unsafe { curr_import.add(1) };
        }

        Ok(imports)
    }

    /// Parses all image section headers of the module.
    ///
    /// # Errors
    /// - [`ProcessError::NtStatus`] if reading memory fails.
    ///
    /// # Example
    /// ```rust
    /// println!("sections of {}:", module.name);
    /// for section in module.sections()? {
    ///     println!("{} | size: {}", section.name, section.size);
    /// }
    /// ```
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
                let characteristics = SectionCharacteristics::from_bits(section.characteristics);

                sections.push(Section {
                    module: self,

                    name,
                    address,
                    size,
                    characteristics,

                    raw_data_size: section.size_of_raw_data,

                    raw_data_file_offset: section.pointer_to_raw_data,
                })
            }
        }

        Ok(sections)
    }

    /// Parses all the image section headers of the module and
    /// searches for a matching section name.
    ///
    /// /// # Errors
    /// - [`ProcessError::SectionNotFound`] if the section is not found.
    /// - [`ProcessError::NtStatus`] if reading memory fails.
    ///
    /// # Example
    /// ```rust
    /// let code_section = module.get_section(".text")?;
    /// println!("code lives at {:#X}", code_section.address);
    /// ```
    pub fn get_section<'module>(&'module self, name: &str) -> Result<Section<'process, 'module>> {
        if let Some(section) = self.sections()?.into_iter().find(|s| s.name == name) {
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

    pub(crate) fn export_directory(&self) -> Result<(ImageDataDirectory, ImageExportDirectory)> {
        let nt_headers_ptr = self.nt_headers()?;
        let exp_data_dir: ImageDataDirectory = self.process.read_mem(
            nt_headers_ptr +
			offset_of!(ImageNtHeaders64, optional_header) +

			// we do not need to do any additional offsets from this point
			// because ImageOptionalHeader64->data_directory[0] is ImageDataDirectory
			// and ImageDataDirectory->virtual_address is the first property (0x0 offset)
			offset_of!(ImageOptionalHeader64, data_directory),
        )?;

        let export_dir_rva = exp_data_dir.virtual_address;
        if export_dir_rva == 0 {
            return Err(ProcessError::MalformedPE);
        }

        let export_dir: ImageExportDirectory = self
            .process
            .read_mem(self.base_address + export_dir_rva as usize)?;

        Ok((exp_data_dir, export_dir))
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

    pub(crate) fn resolve_exports(
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

    pub(crate) fn from_raw_ldr_entry(process: &'process Process, ldr_entry: LdrModule) -> Self {
        let name = process
            .read_unicode_string(&ldr_entry.base_dll_name)
            .unwrap_or("???".to_owned());
        let full_name = process
            .read_unicode_string(&ldr_entry.full_dll_name)
            .unwrap_or("???".to_owned());

        Self {
            process,

            name,
            full_name,
            base_address: ldr_entry.base_address as usize,
            entry_point: ldr_entry.entry_point,
            image_size: ldr_entry.size_of_image,
            load_reason: ldr_entry.load_reason.into(),
            flags: ldr_entry.flags,
        }
    }
}

/// Represents the reasoning behind why a module was loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleLoadReason {
    /// The load reason is unknown.
    Unknown,
    /// Loaded because it is a static dependency of another module.
    StaticDependency,
    /// Loaded because it is a static forwarder dependency.
    StaticForwarderDependency,
    /// Loaded because it is a dynamic forwarder dependency.
    DynamicForwarderDependency,
    /// Loaded because it is a delay-loaded dependency.
    DelayloadDependency,
    /// Loaded explicitly via `LoadLibrary` or similar dynamic loading.
    DynamicLoad,
    /// Loaded as an image (typical normal module load).
    AsImageLoad,
    /// Loaded as data, not as a module image.
    AsDataLoad,
    /// Primary module for an enclave (Windows REDSTONE3+).
    EnclavePrimary,
    /// Dependency module for an enclave.
    EnclaveDependency,
    /// Loaded as a patch image (Windows 11+).
    PatchImage,
}

impl From<LdrDllLoadReason> for ModuleLoadReason {
    fn from(reason: LdrDllLoadReason) -> Self {
        match reason {
            LdrDllLoadReason::Unknown => ModuleLoadReason::Unknown,
            LdrDllLoadReason::StaticDependency => ModuleLoadReason::StaticDependency,
            LdrDllLoadReason::StaticForwarderDependency => {
                ModuleLoadReason::StaticForwarderDependency
            }
            LdrDllLoadReason::DynamicForwarderDependency => {
                ModuleLoadReason::DynamicForwarderDependency
            }
            LdrDllLoadReason::DelayloadDependency => ModuleLoadReason::DelayloadDependency,
            LdrDllLoadReason::DynamicLoad => ModuleLoadReason::DynamicLoad,
            LdrDllLoadReason::AsImageLoad => ModuleLoadReason::AsImageLoad,
            LdrDllLoadReason::AsDataLoad => ModuleLoadReason::AsDataLoad,
            LdrDllLoadReason::EnclavePrimary => ModuleLoadReason::EnclavePrimary,
            LdrDllLoadReason::EnclaveDependency => ModuleLoadReason::EnclaveDependency,
            LdrDllLoadReason::PatchImage => ModuleLoadReason::PatchImage,
        }
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

        let has_text_section = ntdll
            .sections()?
            .iter()
            .any(|section| section.name == ".text");
        assert!(
            has_text_section,
            "no .text section found in remote ntdll.dll"
        );

        Ok(())
    }

    #[test]
    fn get_module_imports() -> Result<()> {
        let process = Process::current();
        let kernel32 = process.get_module("kernel32.dll")?;
        let imports = kernel32.imports()?;

        assert!(!imports.is_empty(), "no imports found for kernel32.dll");

        let ntdll_imports = imports.iter().find(|import| import.dll_name == "ntdll.dll");
        assert!(
            ntdll_imports.is_some(),
            "ntdll.dll not found in kernel32.dll imports"
        );
        assert!(
            ntdll_imports
                .unwrap()
                .functions
                .contains(&ImportType::Name("NtClose".to_owned())),
            "NtClose not found in kernel32.dll imports from ntdll.dll"
        );

        Ok(())
    }

    #[test]
    fn get_forwarded_export() -> Result<()> {
        let process = Process::current();
        let kernel32 = process.get_module("kernel32.dll")?;
        let ntdll = process.get_module("ntdll.dll")?;

        let forwarded_address = kernel32.get_export("HeapAlloc")?;
        let address = ntdll.get_export("RtlAllocateHeap")?;

        assert_eq!(
            forwarded_address, address,
            "resolving forwarded export failed"
        );

        Ok(())
    }
}
