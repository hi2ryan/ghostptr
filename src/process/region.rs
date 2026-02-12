use crate::{AddressRange, MemoryRegionInfo, Process, constants::PAGE_SIZE};

pub struct MemoryRegionIter<'process> {
    process: &'process Process,
    current_addr: usize,
    end_addr: usize,
}

impl<'process> MemoryRegionIter<'process> {
	#[inline]
    pub fn new(process: &'process Process, range: AddressRange) -> Self {
        Self {
            process,
            current_addr: range.start,
            end_addr: range.end,
        }
    }
}

impl<'process> Iterator for MemoryRegionIter<'process> {
    type Item = MemoryRegionInfo;

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
