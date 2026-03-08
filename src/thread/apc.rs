use core::ptr;

/// The three arguments passed to a user-mode APC routine.
#[derive(Debug)]
pub struct QueuedUserAPCParameters(pub *mut (), pub *mut (), pub *mut ());

impl Default for QueuedUserAPCParameters {
    fn default() -> Self {
        Self(ptr::null_mut(), ptr::null_mut(), ptr::null_mut())
    }
}
