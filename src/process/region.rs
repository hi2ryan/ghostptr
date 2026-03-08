use crate::{
    constants::PAGE_SIZE,
    process::{MemoryRegion, Process},
    utils::AddressRange,
};

/// Represents an iterator over the virtual memory regions
/// intersecting a provided range.
pub struct MemoryRegionIter<'process> {
    process: &'process Process,
    current_addr: usize,
    end_addr: usize,
}

impl<'process> MemoryRegionIter<'process> {
    /// Creates a new iterator over the virtual memory
    /// regions that intersect `range`.
    #[inline(always)]
    pub fn new(process: &'process Process, range: AddressRange) -> Self {
        Self {
            process,
            current_addr: range.start,
            end_addr: range.end,
        }
    }
}

impl<'process> Iterator for MemoryRegionIter<'process> {
    type Item = MemoryRegion;

    fn next(&mut self) -> Option<Self::Item> {
        let info = loop {
            if self.current_addr > self.end_addr {
                // beyond end address
                return None;
            }

            match self.process.query_mem(self.current_addr) {
                Ok(info) => break info,
                Err(_) => {
                    // query failed, move a page forward
                    self.current_addr += PAGE_SIZE;
                    continue;
                }
            }
        };

        if info.size == 0 {
            return None;
        }

        self.current_addr += info.size;
        Some(info)
    }
}
