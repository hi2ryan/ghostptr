/// Represents the outcome of a thread wait operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    /// The waited-on object became signaled before the timeout elapsed.
    Signaled,

    /// The timeout elapsed before the object became signaled.
    Timeout,

    /// The wait was interrupted because the thread was alerted.
    Alerted,

    /// The wait was interrupted to deliver a queued user-mode APC.
    UserAPC,
}