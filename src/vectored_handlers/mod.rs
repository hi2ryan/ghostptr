pub mod handler_type;
pub use handler_type::VectoredHandlerType;

pub mod entry;
pub use entry::VectoredHandlerEntry;

pub mod iterator;
pub use iterator::VectoredHandlerIterator;

pub mod list;
pub use list::VectoredHandlerList;

pub mod utils;
pub use utils::{decode_pointer, encode_pointer};

#[cfg(test)]
mod tests {
    use crate::{
        ExceptionHandler, NtStatus, Process, ProcessAccess, Result,
        vectored_handlers::{
            VectoredHandlerType, list::HandlerEntryAddresses,
        },
        windows::{VectoredExceptionHandler, structs::ExceptionPointers},
    };
    use core::ptr;

    #[test]
    fn get_vehs_current() -> Result<()> {
        unsafe extern "system" {
            fn RtlAddVectoredExceptionHandler(
                first: u32,
                handler: VectoredExceptionHandler,
            ) -> *mut core::ffi::c_void;
        }

        extern "system" fn test_handler(
            _info: *mut ExceptionPointers,
        ) -> ExceptionHandler {
            ExceptionHandler::ContinueExecution
        }

        let node =
            unsafe { RtlAddVectoredExceptionHandler(1, test_handler) };
        assert_ne!(node, ptr::null_mut(), "failed to add VEH");

        let process = Process::current();
        let handlers = process.vectored_handlers()?;
        let exception_handlers = handlers
            .iter(VectoredHandlerType::Exception)?
            .collect::<Vec<_>>();

        let test_handler_addr = test_handler as *const () as usize;
        let first_handler_addr =
            exception_handlers.first().map(|entry| entry.handler_addr());

        assert_eq!(
            first_handler_addr,
            Some(test_handler_addr),
            "added VEH not found (first != added)"
        );

        Ok(())
    }

    #[test]
    fn get_vehs_remote() -> Result<()> {
        let process = Process::open_first_named(
            "Discord.exe",
            ProcessAccess::VM_READ
                | ProcessAccess::VM_WRITE
                | ProcessAccess::QUERY_LIMITED_INFORMATION,
        )?;

        let handlers = process.vectored_handlers()?;
        let exception_handlers = handlers
            .iter(VectoredHandlerType::Exception)?
            .collect::<Vec<_>>();

        assert!(
            !exception_handlers.is_empty(),
            "failed to get VEH's for remote process (Discord.exe)"
        );

        Ok(())
    }

    #[test]
    fn trigger_new_veh_current() -> Result<()> {
        let process = Process::current();
        let handlers = process.vectored_handlers()?;

        const STATUS_ACCESS_VIOLATION: NtStatus =
            0xC0000005u32 as NtStatus;

        extern "system" fn first_handler(
            exception_info_ptr: *mut ExceptionPointers,
        ) -> ExceptionHandler {
            unsafe {
                let info = &mut *exception_info_ptr;
                let context = &mut *info.context_record;
                let exception = &mut *info.exception_record;

                assert_eq!(
                    exception.exception_code, STATUS_ACCESS_VIOLATION,
                    "exception code isn't STATUS_ACCESS_VIOLATION"
                );

                // skip the instruction
                context.rip += 2;
            }
            ExceptionHandler::ContinueSearch
        }

        handlers.add(
            VectoredHandlerType::Exception,
            HandlerEntryAddresses::default(),
            first_handler,
            true,
        )?;

        #[allow(invalid_null_arguments)]
        unsafe {
            ptr::write(ptr::null_mut(), true)
        };

        Ok(())
    }

    #[test]
    fn manipulate_vectored_handlers_current() -> Result<()> {
        extern "system" fn test_handler(
            _pointers: *mut ExceptionPointers,
        ) -> ExceptionHandler {
            ExceptionHandler::ContinueExecution
        }

        extern "system" fn test_handler2(
            _pointers: *mut ExceptionPointers,
        ) -> ExceptionHandler {
            ExceptionHandler::ContinueExecution
        }

        let process = Process::current();
        let vectored_handlers = process.vectored_handlers()?;

        // add exception handler to the tail
        vectored_handlers.add(
            VectoredHandlerType::Exception,
            HandlerEntryAddresses::default(),
            test_handler,
            false,
        )?;

        // check if test_handler is at the tail
        assert!(
            vectored_handlers
                .iter(VectoredHandlerType::Exception)?
                .last()
                .is_some_and(|entry| ptr::fn_addr_eq(
                    entry.handler(),
                    test_handler as VectoredExceptionHandler
                )),
            "failed to add VectoredExceptionHandler to the tail"
        );

        // add exception handler #2 to the head
        vectored_handlers.add(
            VectoredHandlerType::Exception,
            HandlerEntryAddresses::default(),
            test_handler2,
            true,
        )?;

        let mut handler_iter =
            vectored_handlers.iter(VectoredHandlerType::Exception)?;
        let head_entry = handler_iter
            .next()
            .expect("failed to iterate VectoredExceptionHandlers");

        // check if test_handler2 is at the head
        assert!(
            ptr::fn_addr_eq(
                head_entry.handler(),
                test_handler2 as VectoredExceptionHandler
            ),
            "failed to add VectoredExceptionHandler to the head"
        );

        // check if test_handler is at the tail
        assert!(
            handler_iter.last().is_some_and(|entry| ptr::fn_addr_eq(
                entry.handler(),
                test_handler as VectoredExceptionHandler
            )),
            "failed to push VectoredExceptionHandler to the head"
        );

        // remove head entry
        head_entry
            .remove(true)
            .expect("failed to remove head VectoredExceptionHandler");

        // check if it still exists (it shouldnt)
        assert!(
            !vectored_handlers.iter(VectoredHandlerType::Exception)?.any(
                |entry| ptr::fn_addr_eq(
                    entry.handler(),
                    test_handler2 as VectoredExceptionHandler
                )
            ),
            "failed to remove head VectoredExceptionHandler"
        );

        // remove tail entry
        vectored_handlers
            .remove(
                VectoredHandlerType::Exception,
                test_handler as *const () as usize,
                true,
            )
            .expect("failed to remove tail VectoredExceptionHandler");

        // check if it still exists (it shouldnt)
        assert!(
            !vectored_handlers.iter(VectoredHandlerType::Exception)?.any(
                |entry| ptr::fn_addr_eq(
                    entry.handler(),
                    test_handler as VectoredExceptionHandler
                )
            ),
            "failed to remove tail VectoredExceptionHandler"
        );

        Ok(())
    }

    #[test]
    fn manipulate_vectored_handlers_remote() -> Result<()> {
        todo!()
    }
}
