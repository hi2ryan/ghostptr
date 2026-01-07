use core::fmt::{Display, Debug};

pub type Result<T> = core::result::Result<T, ProcessError>;

pub enum ProcessError {
    NtStatus(i32),
    ProcessNotFound(String),

    // memory
    PartialRead(usize),
    PartialWrite(usize),

    // modules
    ModuleNotFound(String),
	MainModuleNotFound,
    MalformedPE,
    ExportNotFound(String),
}

impl Display for ProcessError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProcessError::NtStatus(code) =>
				write!(f, "NTSTATUS(0x{:08X})", code),
            ProcessError::ProcessNotFound(name) =>
				write!(f, "Process '{name} not found'"),

			// memory
			ProcessError::PartialRead(bytes_read) =>
				write!(f, "Partially read: {:#x} bytes", bytes_read),
			ProcessError::PartialWrite(bytes_written) =>
				write!(f, "Partially wrote: {:#x} bytes", bytes_written),

			// modules
			ProcessError::ModuleNotFound(name) =>
				write!(f, "Module '{name}' not found"),
			ProcessError::MainModuleNotFound =>
				write!(f, "Main module not found"),
			ProcessError::MalformedPE =>
				write!(f, "Malformed PE format"),
			ProcessError::ExportNotFound(name) =>
				write!(f, "Export '{name}' not found")
		}
    }
}

impl Debug for ProcessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(self, f)
    }
}

impl core::error::Error for ProcessError {}
