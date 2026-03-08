use core::{ptr, slice};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeString {
    pub length: u16,
    pub max_length: u16,
    pub buffer: *mut u16,
}

impl Default for UnicodeString {
    fn default() -> Self {
        Self {
            length: 0,
            max_length: 0,
            buffer: ptr::null_mut(),
        }
    }
}

impl UnicodeString {
    pub fn as_string_lossy(&self) -> String {
        if self.buffer.is_null() || self.length == 0 {
            return String::new();
        }

        let len = (self.length / 2) as usize;
        let slice = unsafe { slice::from_raw_parts(self.buffer, len) };
        String::from_utf16_lossy(slice)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AnsiString {
    pub length: u16,
    pub max_length: u16,
    pub buffer: *mut u8,
}
