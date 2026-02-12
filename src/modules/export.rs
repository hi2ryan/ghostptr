use core::ops::Range;

use super::Module;
use crate::error::Result;

/// Represents an exported symbol from a PE module's Export Address Table.
///
/// Exports can be:
/// - Named
/// - Ordinal-only (no name)
/// - Forwarded to another module
#[derive(Debug, Clone)]
pub struct Export {
    /// The name of the exported symbol, if present.
    pub name: Option<String>,

    /// The export ordinal.
    pub ordinal: u16,

    /// The resolved virtual address of the exported function.
    pub address: usize,

    /// If this export was forwarded, contains the forwarder string.
    ///
    /// (e.g. "NTDLL.RtlAllocateHeap")
    pub forwarder: Option<String>,
}

pub struct ExportIterator<'process, 'module> {
    module: &'module Module<'process>,
    export_directory_range: Range<u32>,

    ordinal_base: u16,
    names: Vec<u32>,
    ordinals: Vec<u16>,
    functions: Vec<u32>,

    idx: usize,
}

impl<'process, 'module> ExportIterator<'process, 'module> {
    pub fn new(module: &'module Module<'process>) -> Result<Self> {
        let (export_data_dir, export_directory) = module.export_directory()?;
        let (names, ordinals, functions) = module.resolve_exports(export_directory)?;

        let export_directory_range = export_data_dir.virtual_address
            ..(export_data_dir.virtual_address + export_data_dir.size);

        let ordinal_base = export_directory.base as u16;

        Ok(Self {
            module,

            ordinal_base,
            export_directory_range,
            names,
            ordinals,
            functions,

            idx: 0,
        })
    }

    #[inline(always)]
    pub(crate) fn is_forwarded(&self, rva: u32) -> bool {
        self.export_directory_range.contains(&rva)
    }

    pub(crate) fn find_by_forwarder(&mut self, name: &str) -> Option<Export> {
        if let Some(ordinal_str) = name.strip_prefix("#") {
            let ordinal: u16 = ordinal_str.parse().ok()?;
            self.find(|export| export.ordinal == ordinal)
        } else {
            self.find(|export| {
                export
                    .name
                    .as_ref()
                    .is_some_and(|export_name| export_name == name)
            })
        }
    }
}

impl<'process, 'module> Iterator for ExportIterator<'process, 'module> {
    type Item = Export;

    fn next(&mut self) -> Option<Self::Item> {
        // retrieve function RVA
        let func_rva = match self.functions.get(self.idx) {
            Some(func_rva) => {
                let rva = *func_rva;
                if rva == 0 {
                    // skip invalid RVA's
                    return self.next();
                }
                rva
            }

            None => return None,
        };

        // resolve ordinal & VA
        let ordinal = self.ordinal_base + self.idx as u16;
        let mut address = self.module.base_address + func_rva as usize;

        // get export name (if it exists)
        let name = self
            .ordinals
            .iter()
            .position(|&ord| ord as usize == self.idx)
            .and_then(|name_index| {
                // resolve export RVA
                let name_rva = *self.names.get(name_index)? as usize;
                if name_rva == 0 {
                    return None;
                }

                // read export name
                let name_va = self.module.base_address + name_rva;
                self.module.process.read_c_string(name_va, None).ok()
            });

        // check if its forwarded
        let mut is_forward = self.is_forwarded(func_rva);
        let mut forwarder = None;

        // resolve forwarder chain
        while is_forward {
            // read forwarder string; format: NTDLL.RtlAllocateHeap
            let forwarder_str = match self.module.process.read_c_string(address, None) {
                Ok(s) => s,
                Err(_) => break,
            };

            if forwarder.is_none() {
                // store first forwarder string
                forwarder = Some(forwarder_str.clone());
            }

            if let Some(dot) = forwarder_str.rfind('.') {
                // read forwarder
                let module_str = &forwarder_str[..dot];
                if module_str.to_lowercase().starts_with("api-")
                    || module_str.to_lowercase().starts_with("ext-")
                {
					// TODO: implement parsing PEB->ApiSetMap
					// to resolve forwarded module
                    break;
                }

                let mut module_name = module_str.to_owned();
                let export_name = &forwarder_str[dot + 1..];

                // add .dll extension so we can find the module
                module_name.push_str(".dll");

                // find imported module
                let imported_module = match self.module.process.get_module(&module_name) {
                    Ok(module) => module,
                    Err(_) => break,
                };

                let mut exports = match imported_module.exports() {
                    Ok(exports) => exports,
                    Err(_) => break,
                };

                // find forwarded export
                match exports.find_by_forwarder(export_name) {
                    Some(forwarded_export) => {
                        address = forwarded_export.address;
                        let new_rva = (address - imported_module.base_address) as u32;
                        is_forward = exports.is_forwarded(new_rva);
                    }
                    None => break,
                }
            } else {
                break;
            }
        }

        self.idx += 1;
        Some(Export {
            name,
            ordinal,
            address,
            forwarder,
        })
    }
}
