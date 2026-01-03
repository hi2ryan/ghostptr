pub type Result<T> = core::result::Result<T, ProcessError>;

pub enum ProcessError {
    NtStatus(i32),
    ProcessNotFound(String),

    // memory
    PartialRead(usize),
    PartialWrite(usize),

    // modules
    ModuleNotFound,
    MalformedPE,
    ExportNotFound,
}

impl core::fmt::Display for ProcessError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProcessError::NtStatus(code) =>
				write!(f, "NTSTATUS(0x{:08X})", code),
            ProcessError::ProcessNotFound(name) =>
				write!(f, "Process not found: {name}"),

			// memory
			ProcessError::PartialRead(bytes_read) =>
				write!(f, "Partially read: {:#x} bytes", bytes_read),
			ProcessError::PartialWrite(bytes_written) =>
				write!(f, "Partially wrote: {:#x} bytes", bytes_written),

			// modules
			ProcessError::ModuleNotFound =>
				write!(f, "Failed to get module"),
			ProcessError::MalformedPE =>
				write!(f, "Malformed PE format"),
			ProcessError::ExportNotFound =>
				write!(f, "Export not found")
		}
    }
}

impl core::fmt::Debug for ProcessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

impl core::error::Error for ProcessError {}
