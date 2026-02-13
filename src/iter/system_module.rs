use crate::{
    error::{ProcessError, Result},
    windows::{
        constants::STATUS_INFO_LENGTH_MISMATCH,
        structs::{RtlProcessModuleInformation, RtlProcessModules},
        wrappers::nt_query_system_information,
    },
};
use core::ptr;

/// Represents information regarding a system module.
#[derive(Debug, Clone)]
pub struct SystemModuleView {
    pub name: String,
    pub full_name: String,

    pub image_base: usize,
    pub image_size: usize,
}

impl SystemModuleView {
    pub(crate) fn from_raw_module_info(info: &RtlProcessModuleInformation) -> Self {
        let file_name_offset = info.offset_to_file_name as usize;
		let path = info.full_path_name;

        let len = path.iter().position(|&c| c == 0).unwrap_or(path.len());

        let name = String::from_utf8_lossy(&path[file_name_offset..len]).to_string();
        let full_name = String::from_utf8_lossy(&path[..len]).to_string();

        let image_base = info.image_base as usize;
        let image_size = info.image_size as usize;

        Self {
            name,
            full_name,

            image_base,
            image_size,
        }
    }
}

/// Iterates all system modules.
pub struct SystemModuleIterator {
    data: Box<[u8]>,
    ptr: *const RtlProcessModuleInformation,

    idx: u32,
    len: u32,
}

impl SystemModuleIterator {
    pub fn new() -> Result<Self> {
        let mut size = 0u32;
        nt_query_system_information(
            0xB, // SystemModuleInformation
            ptr::null_mut(),
            size,
            &mut size,
        );

        loop {
            let mut data = vec![0u8; size as usize];
            let status = nt_query_system_information(
                0xB, // SystemModuleInformation
                data.as_mut_ptr().cast(),
                size as _,
                &mut size,
            );

            if status == STATUS_INFO_LENGTH_MISMATCH {
                // retry with the updated length
                continue;
            }

            if status != 0x0 {
                // error
                return Err(ProcessError::NtStatus(status));
            }

            // put it on the heap
            let data = data.into_boxed_slice();

            // Safety:
            // we checked if NtQuerySystemInformation syscall ntstatus
            // was successful, therefore it filled the buffer
            let (len, ptr) = unsafe {
                let info = &*data.as_ptr().cast::<RtlProcessModules>();
				let count = info.count;
				let ptr = info.modules.as_ptr();

				(count, ptr)
            };

            return Ok(Self {
                data,
                ptr,
                idx: 0,
                len,
            });
        }
    }
}

impl Iterator for SystemModuleIterator {
    type Item = SystemModuleView;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.len {
            return None;
        }

        // Safety:
        // current < len, so this index is valid within the modules array
        let raw_module = unsafe { &*self.ptr.add(self.idx as usize) };
        self.idx += 1;

        Some(SystemModuleView::from_raw_module_info(raw_module))
    }
}

impl ExactSizeIterator for SystemModuleIterator {
    fn len(&self) -> usize {
        (self.len - self.idx) as usize
    }
}

#[cfg(test)]
mod tests {
    use crate::{Result, iter::system_module::SystemModuleIterator};

    #[test]
    fn system_modules() -> Result<()> {
        for module in SystemModuleIterator::new()? {
            println!("{:?}", module);
        }

        Ok(())
    }
}
