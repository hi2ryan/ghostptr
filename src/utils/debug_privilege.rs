use crate::{
    error::{ProcessError, Result},
    windows::{
        constants::CURRENT_PROCESS_HANDLE,
        structs::{Luid, LuidAndAttributes, TokenPrivileges},
        wrappers::{nt_adjust_privileges_token, nt_close, nt_open_process_token},
    },
};

/// Sets the state of SeDebugPrivilege for the current process.
fn set_debug_privilege(enable: bool) -> Result<()> {
    use core::ptr;

    // open token
    let mut token_handle = 0usize;
    let status = nt_open_process_token(
        CURRENT_PROCESS_HANDLE,
        0x0020 | 0x0008, // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
        &mut token_handle,
    );

    if status != 0 {
        return Err(ProcessError::NtStatus(status));
    }

    let mut privileges = TokenPrivileges {
        privilege_count: 1,
        privileges: [LuidAndAttributes {
            luid: Luid {
                low_part: 0x14, // SE_DEBUG_PRIVILEGE
                high_part: 0,
            },
            attributes: if enable { 0x2 } else { 0 }, // SE_PRIVILEGE_ENABLED
        }],
    };

    let status = nt_adjust_privileges_token(
        token_handle,
        0,
        &mut privileges as *mut TokenPrivileges,
        size_of::<TokenPrivileges>() as u32,
        ptr::null_mut(),
        ptr::null_mut(),
    );

    nt_close(token_handle);

    match status {
        0 => Ok(()),
        _ => Err(ProcessError::NtStatus(status)),
    }
}

/// Enables SeDebugPrivilege for the current process.
#[inline(always)]
pub fn enable_debug_privilege() -> Result<()> {
    set_debug_privilege(true)
}

/// Disables SeDebugPrivilege for the current process.
#[inline(always)]
pub fn disable_debug_privilege() -> Result<()> {
    set_debug_privilege(false)
}

/// An abstraction around enabling SeDebugPrivilege, disabling it
/// on drop.
///
/// # Example
///
/// ```rust
///
/// unsafe extern "system" fn my_callback(original_rsp: u64, return_address: u64, return_value: u64) {
///     // do something here
/// }
///
/// fn set_callback(remote_process: &Process) -> Result<()> {
///     let _guard = DebugPrivilegeGuard::acquire()?;
///     remote_process.set_instrumentation_callback(my_callback)
/// }
/// ```
pub struct DebugPrivilegeGuard;

impl DebugPrivilegeGuard {
    /// Enables SeDebugPrivilege and returns a guard that will disable it on drop.
    pub fn acquire() -> Result<Self> {
        enable_debug_privilege()?;
        Ok(DebugPrivilegeGuard)
    }
}

impl Drop for DebugPrivilegeGuard {
    fn drop(&mut self) {
        let _ = disable_debug_privilege();
    }
}
