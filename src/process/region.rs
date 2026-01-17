use crate::{AddressRange, MemoryRegionInfo, Process};

pub struct MemoryRegionIter<'a, P: Process + ?Sized> {
    process: &'a P,
    current_addr: usize,
    end_addr: usize,
}

impl<'a, P: Process> MemoryRegionIter<'a, P> {
    pub fn new(process: &'a P, range: AddressRange) -> Self {
        Self {
            process,
            current_addr: range.start,
            end_addr: range.end,
        }
    }
}

impl<'a, P: Process> Iterator for MemoryRegionIter<'a, P> {
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
                    self.current_addr += 0x1000;
                    continue;
                }
            }
        };

        if info.region_size == 0 {
            return None;
        }

		self.current_addr += info.region_size;
        Some(info)
    }
}
