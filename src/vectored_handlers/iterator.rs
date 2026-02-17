use crate::{
    error::Result,
    vectored_handlers::{
        entry::VectoredHandlerEntry, handler_type::VectoredHandlerType,
        list::VectoredHandlerList, utils::decode_pointer,
    },
    windows::structs::{
        ListEntry, RtlVectorHandlerEntry, RtlVectorHandlerList,
    },
};
use core::mem::offset_of;

/// Represents an iterator over all the vectored handlers of a [`VectoredHandlerType`].
pub struct VectoredHandlerIterator<'process, 'list> {
    list: &'list VectoredHandlerList<'process>,
    handler_type: VectoredHandlerType,
    head: *const ListEntry,
    current: *const ListEntry,
}

impl<'process, 'list> VectoredHandlerIterator<'process, 'list> {
	/// Creates an iterator over all the vectored handlers of a [`VectoredHandlerType`].
	///
	/// # Arguments
	/// - `list` The [`VectoredHandlerList`] of the process.
	/// - `handler_type` The type of vectored handler.
    pub fn new(
        list: &'list VectoredHandlerList<'process>,
        handler_type: VectoredHandlerType,
    ) -> Result<Self> {
        // calculate offset of handler list based on the type
        let offset = match handler_type {
            VectoredHandlerType::Exception => {
                offset_of!(RtlVectorHandlerList, veh_list)
            }
            VectoredHandlerType::Continue => {
                offset_of!(RtlVectorHandlerList, vch_list)
            }
        };

		// read first entry address
        let head = (list.raw_list as usize + offset) as *const ListEntry;
        let current_addr = (head as usize + offset_of!(ListEntry, next))
            as *const *const ListEntry;
        let current = list.process.read_mem(current_addr)?;

        Ok(Self {
            list,
            head,
            current,
            handler_type,
        })
    }
}

impl<'process, 'list> Iterator
    for VectoredHandlerIterator<'process, 'list>
{
    type Item = VectoredHandlerEntry<'process, 'list>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current == self.head {
            // reached the end
            return None;
        }

        let process = self.list.process;

        // read the entry
        let raw_entry_addr = self.current as *const RtlVectorHandlerEntry;
        let raw_entry = process
            .read_mem::<RtlVectorHandlerEntry>(raw_entry_addr)
            .ok()?;

        self.current = raw_entry.list.next;

        // decode the encoded function address
        let handler_addr = decode_pointer(
            raw_entry.encoded_handler as usize,
            self.list.cookie,
        );

        Some(VectoredHandlerEntry::from_raw_entry(
            self.list,
            self.handler_type,
            raw_entry_addr,
            handler_addr,
        ))
    }
}
