use super::Module;
use crate::{AddressRange, Scanner, process::{MemoryRegionIter, Process}, windows::flags::SectionCharacteristics};

/// Represents an image section header from a PE module
#[derive(Debug)]
pub struct Section<'a, P: Process + ?Sized> {
    pub(crate) module: &'a Module<'a, P>,

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

impl<'a, P: Process> Section<'a, P> {
	/// Returns the virtual address range covered by this module section.
    #[inline(always)]
    pub fn virtual_range(&self) -> AddressRange {
        // let start = self.address;
        // let size = self.size as usize;
        let end = self.address.saturating_add(self.size as usize);
        self.address..end
    }

	/// Scans virtual memory in the process according to the
	/// virtual address range covered by this module.
	#[inline(always)]
    pub fn scan_mem<S: Scanner>(&self, pattern: &S) -> impl Iterator<Item = usize> {
        self.module.process.scan_mem(self.virtual_range(), pattern)
    }

	/// Returns an iterator over the memory regions that intersect this section.
    #[inline(always)]
    pub fn mem_regions(&self) -> MemoryRegionIter<P> {
        MemoryRegionIter::new(self.module.process, self.virtual_range())
    }
}
