use crate::{
    Process, ProcessError, Result, close_handle,
    windows::{
        Handle,
        constants::{CURRENT_PROCESS_HANDLE, STATUS_INFO_LENGTH_MISMATCH},
        structs::{ObjectBasicInformation, ProcessHandleEntry, PublicObjectTypeInformation, UnicodeString},
        utils::unicode_to_string,
        wrappers::{nt_duplicate_object, nt_query_object},
    },
};
use core::{mem::zeroed, ptr};

/// Represents an object with a handle.
/// Used to query information about the handle, such as
/// the type, name, and granted access of it.
#[repr(transparent)]
pub struct HandleObject(Handle);

impl HandleObject {
	/// Retrieves the underlying raw `Handle`.
    pub fn handle(&self) -> Handle {
        self.0
    }

	/// Creates `HandleObject` from the raw `handle`.
    pub fn from_handle(handle: Handle) -> Self {
        Self(handle)
    }

	/// Closes the handle.
    pub fn close(&self) -> Result<()> {
        close_handle(self.0)
    }

    /// Duplicates the handle.
    ///
    /// This method requires an object access mask beyond standard bounds
    /// like process access and thread access. Therefore, the desired access
    /// has been kept in its raw state as a `u32`. However, if the `access` is
    /// `None`, it will copy the handle's original access mask.
	/// 
	/// # Access Rights
    ///
    /// If the `src_process` is a remote process, this method
    /// requires the process handle access mask to include:
    ///
    /// - [`crate::ProcessAccess::DUP_HANDLE`]
    ///
    /// Without this right, the system call will fail with an
    /// `NTSTATUS` error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProcessError::NtStatus`] if duplicating the handle fails,
    /// potentially due to insufficient access rights.
    ///
    pub fn duplicate<P: Process>(&self, src_process: &P, access: Option<u32>) -> Result<Handle> {
        let mut new_handle = 0;
        let source_handle = unsafe { src_process.handle() };

        let status = nt_duplicate_object(
            source_handle,
            self.0,
            CURRENT_PROCESS_HANDLE,
            &mut new_handle,
            access.unwrap_or(0),
            0,
            // DUPLICATE_SAME_ACCESS if access is None
            if access.is_none() { 0x2 } else { 0 },
        );

        match status {
            0 => Ok(new_handle),
            _ => Err(ProcessError::NtStatus(status)),
        }
    }

	/// Retrieves the name of the object, if present.
    ///
    /// The name can include path separators ("\\").
    pub fn name(&self) -> Result<String> {
        // get required size of buffer
        let mut len = 0;
        let status = nt_query_object(
            self.0,
            0x1, // ObjectNameInformation
            core::ptr::null_mut(),
            0,
            &mut len,
        );

        if status != STATUS_INFO_LENGTH_MISMATCH {
            return Err(ProcessError::NtStatus(status));
        }

        let mut unicode_name = UnicodeString {
            length: 0,
            max_length: 0,
            buffer: core::ptr::null(),
        };
        let status = nt_query_object(
            self.0,
            0x1, // ObjectNameInformation
            (&mut unicode_name as *mut UnicodeString).cast(),
            len,
            &mut len,
        );

        match status {
            0 => Ok(unicode_to_string(&unicode_name)),
            _ => Err(ProcessError::NtStatus(status)),
        }
    }

    /// Retrieves the type name of the object.
    pub fn type_name(&self) -> Result<String> {
        // get required size of buffer
        let mut needed = 0u32;
        let status = nt_query_object(
            self.0,
            2, // ObjectTypeInformation
            core::ptr::null_mut(),
            0,
            &mut needed,
        );

        if status != STATUS_INFO_LENGTH_MISMATCH {
            return Err(ProcessError::NtStatus(status));
        }

        let mut buf = vec![0u8; needed as usize];
        let status = nt_query_object(
            self.0,
            2,
            buf.as_mut_ptr() as *mut _,
            needed,
            core::ptr::null_mut(),
        );

        if status != 0 {
            return Err(ProcessError::NtStatus(status));
        }

        let info = unsafe { &*(buf.as_ptr() as *const PublicObjectTypeInformation) };
        Ok(unicode_to_string(&info.type_name))
    }

    /// Retrieves the granted access mask of the object.
    pub fn access(&self) -> Result<u32> {
        let mut info = unsafe { zeroed::<ObjectBasicInformation>() };
        let status = nt_query_object(
            self.0,
            0x0, // ObjectBasicInformation
            (&mut info as *mut ObjectBasicInformation).cast(),
            size_of::<ObjectBasicInformation>() as u32,
            ptr::null_mut(),
        );

        if status != 0 {
            Err(ProcessError::NtStatus(status))
        } else {
            Ok(info.granted_access)
        }
    }
}

impl Into<Handle> for HandleObject {
    fn into(self) -> Handle {
        self.0
    }
}

impl From<Handle> for HandleObject {
    fn from(value: Handle) -> Self {
        Self(value)
    }
}

impl From<ProcessHandleEntry> for HandleObject {
    fn from(value: ProcessHandleEntry) -> Self {
        Self(value.handle)
    }
}
