use crate::{AddressRange, Process, Scanner, process::MemoryRegionIter};

pub struct MemScanIter<'process, 'scanner, S: Scanner> {
    process: &'process Process,
    scanner: &'scanner S,

    range: AddressRange,
    regions: MemoryRegionIter<'process>,

	curr_region_start: usize,

    results: Vec<usize>,
	result_idx: usize,
}

impl<'process, 'scanner, S: Scanner> MemScanIter<'process, 'scanner, S> {
    pub fn new(process: &'process Process, range: AddressRange, scanner: &'scanner S) -> Self {
        let regions = process.mem_regions(range.clone());

        Self {
            process,

            results: Vec::new(),
			result_idx: 0,

            regions,
			curr_region_start: 0,

            range,
            scanner,
        }
    }
}

impl<'process, 'scanner, S: Scanner> Iterator for MemScanIter<'process, 'scanner, S> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
		// drain scanner results
		if self.result_idx < self.results.len() {
			let offset = self.results[self.result_idx];
			self.result_idx += 1;
			return Some(self.curr_region_start + offset);
		}

		// find first readable region
        for info in self.regions.by_ref() {
            if !info.is_readable() {
                continue;
            }

			// clamp region to provided address range
            let region_start = info.base_address;
            let region_end = info.base_address.saturating_add(info.size);

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
            self.results = self.scanner.scan_bytes(&bytes);
			self.result_idx = 0;
            self.curr_region_start = start;

			// return first result if present
			if !self.results.is_empty() {
				let offset = self.results[0];
            	self.result_idx = 1;
				return Some(self.curr_region_start + offset);
			}
        }

		None
    }
}
