use std::vec::IntoIter;

use crate::{AddressRange, Process, Scanner, process::MemoryRegionIter};

pub struct MemScanIter<'a, P: Process + ?Sized, S: Scanner> {
    process: &'a P,
    scanner: &'a S,
    range: AddressRange,
    regions: MemoryRegionIter<'a, P>,
	curr_region_start: usize,
    results: IntoIter<usize>,
}

impl<'a, P: Process, S: Scanner> MemScanIter<'a, P, S> {
    pub fn new(process: &'a P, range: AddressRange, scanner: &'a S) -> Self {
        let regions = process.mem_regions(range.clone());

        Self {
            process,

            results: Vec::new().into_iter(),

            regions,
			curr_region_start: 0,

            range,
            scanner,
        }
    }
}

impl<'a, P: Process, S: Scanner> Iterator for MemScanIter<'a, P, S> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // check if theres a result
            if let Some(offset) = self.results.next() {
                return Some(self.curr_region_start + offset);
            }

            let info = self.regions.next()?;
            if !info.is_readable() {
                continue;
            }

            let region_start = info.base_address;
            let region_end = info.base_address.saturating_add(info.region_size);

            let start = self.range.start.max(region_start);
            let end = self.range.end.min(region_end);
            if start >= end {
                continue;
            }

            // read region
            let read_size = end - start;
            let bytes = match self.process.read_slice::<u8>(start, read_size) {
                Ok(b) => b,
                Err(_) => continue,
            };

            // scan bytes
            let results = self.scanner.scan_bytes(&bytes).into_iter();
            self.curr_region_start = region_start;
			self.results = results;
        }
    }
}
