use core::ops::Range;

use super::Module;
use crate::error::Result;

#[allow(unused_imports)]
use crate::error::ProcessError;

/// Represents an exported symbol from a PE module's EAT (Export Address Table).
///
/// Exports can be:
/// - Named
/// - Ordinal-only (no name)
/// - Forwarded to another module (however, the export's forwarded
///   address will be resolved)
#[derive(Debug, Clone)]
pub struct Export {
    /// The name of the exported symbol, if present.
    pub name: Option<String>,

    /// The export ordinal.
    pub ordinal: u16,

    /// The resolved virtual address of the exported function.
    pub address: usize,

    /// Data pertaining to how the export was forwarded.
    /// [`None`] if the export was not forwarded.
    pub forwarder: Option<ExportForwarder>,
}

/// Represents information about a forwarded export.
#[derive(Debug, Clone)]
pub struct ExportForwarder {
    /// The module forwarded to.
    ///
    /// e.g. `"ntdll.dll"`
    pub dll: String,

    /// The export forwarded to.
    ///
    /// e.g. `ForwardedBy::Name("RtlProtectHeap")`
    /// or `ForwardedBy::Ordinal(24)`
    pub export: ForwardedBy,
}

/// The method used in forwarding an export.
///
/// e.g. `ForwardedBy::Name("RtlProtectHeap")`
/// or `ForwardedBy::Ordinal(24)`
#[derive(Debug, Clone)]
pub enum ForwardedBy {
    /// Forwarded by ordinal.
    Ordinal(u16),

    /// Forwarded by name.
    Name(String),
}

/// An iterator over all exports from a module.
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
    /// Creates a [`ExportIterator`] over all exports from [`Module`] `module`
    ///
    /// # Arguments
    /// - `module` The module to parse exports from.
	///
	/// Parses the PE headers in the target process, walks the export
    /// directory, and returns a list of [`Export`] entries. Both named and
    /// ordinal-only exports are included.
    ///
    /// # Errors
    /// - [`ProcessError::MalformedPE`] if the module appears to have
	///   invalid PE headers.
	/// - [`ProcessError::NoExportDirectory`] if the module appears to have no
    ///   export directory (rva = 0).
    /// - [`ProcessError::NtStatus`] if reading memory fails.
    pub fn new(module: &'module Module<'process>) -> Result<Self> {
        // parse exports
        let (export_data_dir, export_directory) =
            module.export_directory()?;
        let (names, ordinals, functions) =
            module.resolve_exports(&export_directory)?;

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

    /// Checks whether an export's RVA is forwarded.
    ///
    /// # Arguments
    /// - `rva` The export's RVA to check.
    #[inline(always)]
    pub(crate) fn is_forwarded(&self, rva: u32) -> bool {
        self.export_directory_range.contains(&rva)
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
        let address = self.module.base_address + func_rva as usize;

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

        // build export
        let mut export = Export {
            name,
            ordinal,
            address,
            forwarder: None,
        };

        // check if its forwarded
        if self.is_forwarded(func_rva)
            && let Some((forwarder, address)) =
                self.module.resolve_forwarded_export(address)
        {
            // update export
            export.forwarder = Some(forwarder);
            export.address = address;
        }

        self.idx += 1;
        Some(export)
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_iter_exports() -> Result<()> {
        let process = Process::current();
        let module = process.get_module("kernel32.dll")?;

        const FORWARDED_NAME: &str = "AcquireSRWLockExclusive";

        assert!(
            module
                .exports()?
                .filter(|export| export.forwarder.is_some())
                .any(|export| export
                    .name
                    .as_ref()
                    .is_some_and(|name| name == FORWARDED_NAME)),
            "failed to find forwarded export through iterating exports"
        );

        Ok(())
    }
}
