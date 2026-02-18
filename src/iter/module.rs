use crate::{
    Module, Result,
    process::Process,
    windows::{
        structs::{LoaderDataTableEntry, ListEntry, PebLoaderData, ProcessEnvBlock},
        utils::query_process_basic_info,
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

    pub fn dlls(self) -> impl Iterator<Item = Module<'process>> {
        self.filter(|module| module.is_dll())
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
            ModuleIterOrder::Load => offset_of!(LoaderDataTableEntry, in_load_order_module_list),
            ModuleIterOrder::Memory => {
                offset_of!(LoaderDataTableEntry, in_memory_order_module_list)
            }
            ModuleIterOrder::Initialization => {
                offset_of!(LoaderDataTableEntry, in_initialization_order_module_list)
            }
        };
        let entry = (current as usize - offset) as *const LoaderDataTableEntry;

        // read module
        let module: LoaderDataTableEntry = self.process.read_mem(entry).expect("failed to read mem");

        // update next entry
        self.next = match self.order {
            ModuleIterOrder::Load => module.in_load_order_module_list.next,
            ModuleIterOrder::Memory => module.in_memory_order_module_list.next,
            ModuleIterOrder::Initialization => module.in_initialization_order_module_list.next,
        };

        Some(Module::from_raw_ldr_entry(self.process, module))
    }
}
