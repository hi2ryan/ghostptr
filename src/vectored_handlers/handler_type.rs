
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VectoredHandlerType {
	/// Called when exceptions occur (before SEH's)
	///
	/// (AddVectoredExceptionHandler)
	Exception,

	/// Called after all exception handlers run, before continuing execution
	///
	/// (AddVectoredContinueHandler)
	Continue,
}
