use super::Module;
use crate::{
    AddressRange, MemScanIter, Scanner, process::MemoryRegionIter,
    windows::flags::SectionCharacteristics,
};

/// Represents an image section header from a PE module
#[derive(Clone, Debug)]
pub struct Section<'process, 'module> {
    pub(crate) module: &'module Module<'process>,

    /// The name of the section as defined in the PE header.
    ///
    /// Common examples include `.text`, `.data`, `.rdata`, and `.rsrc`.
    pub name: String,

    /// The virtual size of the section in bytes.
    ///
    /// This represents the size of the section when loaded into memory,
    /// not necessarily the size on disk.
    pub size: u32,

    /// The base virtual address of the section within the module.
    pub address: usize,

    /// The section characteristics flags.
    pub characteristics: SectionCharacteristics,
}

impl<'process, 'module> Section<'process, 'module> {
    /// Returns the virtual address range covered by this module section.
    #[inline(always)]
    pub fn virtual_range(&self) -> AddressRange {
        let end = self.address.saturating_add(self.size as usize);
        self.address..end
    }

    /// Checks whether an address lies within the virtual address range of this section.
    #[inline(always)]
    pub fn contains(&self, address: &usize) -> bool {
        self.virtual_range().contains(address)
    }

    /// Scans virtual memory in the process according to the
    /// virtual address range covered by this module.
    pub fn scan_mem<'scanner, S>(&self, pattern: &'scanner S) -> MemScanIter<'process, 'scanner, S>
    where
        S: Scanner + 'scanner,
    {
        self.module.process.scan_mem(self.virtual_range(), pattern)
    }

    /// Returns an iterator over the memory regions that intersect this section.
    #[inline(always)]
    pub fn mem_regions(&self) -> MemoryRegionIter<'process> {
        MemoryRegionIter::new(self.module.process, self.virtual_range())
    }
}
