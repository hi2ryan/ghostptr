use super::{NtStatus, Handle};

pub const STATUS_INFO_LENGTH_MISMATCH: NtStatus = 0xC0000004u32 as NtStatus;
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC0000023u32 as NtStatus;
pub const STATUS_BUFFER_OVERFLOW: NtStatus = 0x80000005u32 as NtStatus;

pub const CURRENT_PROCESS_HANDLE: Handle = -1isize as Handle; // pseudo handle
pub const CURRENT_THREAD_HANDLE: Handle = -2isize as Handle; // pseudo handle
