use core::ops::Range;

pub const PAGE_SIZE: usize = 0x1000;
pub const MIN_VIRTUAL_ADDRESS: usize = 0x000000010000;
pub const MAX_VIRTUAL_ADDRESS: usize = 0x7FFFFFFFFFFF;
pub const VIRTUAL_ADDRESS_RANGE: Range<usize> = MIN_VIRTUAL_ADDRESS..MAX_VIRTUAL_ADDRESS;

