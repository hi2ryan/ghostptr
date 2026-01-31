use crate::{
    Module, Result,
    process::Process,
    windows::{
        structs::{LdrModule, ListEntry, PebLoaderData, ProcessEnvBlock},
        utils::{query_process_basic_info, unicode_to_string_remote},
    },
};
use core::mem::offset_of;

#[derive(Default)]
pub enum ModuleIterOrder {
    Load,
    #[default]
    Memory,
    Initialization,
}

/// Iterates the modules of a process by
/// walking its PEB LDR doubly linked list
pub struct ModuleIterator<'process> {
    process: &'process Process,
    order: ModuleIterOrder,
    head: *const ListEntry,
    next: *const ListEntry,
}

impl<'process> ModuleIterator<'process> {
    pub fn new(process: &'process Process, order: ModuleIterOrder) -> Result<Self> {
        let handle = unsafe { process.handle() };

        // get PEB address
        let info = query_process_basic_info(handle)?;
        let peb_address = info.peb_base_address;

        // read PEB->LDR address
        let ldr_address: usize =
            process.read_mem(peb_address as usize + offset_of!(ProcessEnvBlock, ldr))?;

        let offset = match order {
            ModuleIterOrder::Load => offset_of!(PebLoaderData, in_load_order_module_list),
            ModuleIterOrder::Memory => offset_of!(PebLoaderData, in_memory_order_module_list),
            ModuleIterOrder::Initialization => {
                offset_of!(PebLoaderData, in_initialization_order_module_list)
            }
        };
        let head = (ldr_address + offset) as *const ListEntry;

        let head_entry: ListEntry = process.read_mem(head)?;
        let next = head_entry.next;

        Ok(Self {
            process,
            order,
            head,
            next,
        })
    }
}

impl<'process> Iterator for ModuleIterator<'process> {
    type Item = Module<'process>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next;
        if current == self.head {
            // because the ldr module linked list is circular
            // when we reach the head, we've reached the end
            return None;
        }

        let offset = match self.order {
            ModuleIterOrder::Load => offset_of!(LdrModule, in_load_order_module_list),
            ModuleIterOrder::Memory => {
                offset_of!(LdrModule, in_memory_order_module_list)
            }
            ModuleIterOrder::Initialization => {
                offset_of!(LdrModule, in_initialization_order_module_list)
            }
        };
        let entry = (current as usize - offset) as *const LdrModule;

        // read module
        let module: LdrModule = self.process.read_mem(entry).expect("failed to read mem");

        let handle = unsafe { self.process.handle() };
        let name = unicode_to_string_remote(handle, &module.base_dll_name);
        let full_name = unicode_to_string_remote(handle, &module.full_dll_name);

        // update next entry
        self.next = match self.order {
            ModuleIterOrder::Load => module.in_load_order_module_list.next,
            ModuleIterOrder::Memory => module.in_memory_order_module_list.next,
            ModuleIterOrder::Initialization => module.in_initialization_order_module_list.next,
        };

        Some(Module {
            process: self.process,

            name,
            full_name,
            base_address: module.base_address as _,
            entry_point: module.entry_point,
            image_size: module.size_of_image,
            flags: module.flags,
        })
    }
}
