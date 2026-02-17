use crate::windows::NtStatus;
use core::fmt::{Debug, Display};

pub type Result<T> = core::result::Result<T, ProcessError>;

pub enum ProcessError {
    // basic
    NtStatus(NtStatus),

    // memory
    PartialRead(usize),
    PartialWrite(usize),
    InvalidUnicodeString,

    // modules
    MalformedPE,
    ForwardDepthExceeded,
    InvalidForwarderName(String),

    // ..NotFound's
    ProcessNotFound(String),
    MainModuleNotFound,
    ModuleNotFound(String),
    ExportNotFound(String),
    SectionNotFound(String),

    // rtti
    #[cfg(feature = "rtti")]
    TypeNotFound(String),

    // vectored handlers
	#[cfg(feature = "vectored_handlers")]
    VectoredHandlerNotFound(usize),
}

impl Display for ProcessError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
			// basic
            ProcessError::NtStatus(code) =>
				write!(f, "NTSTATUS(0x{:08X})", code),

			// memory
			ProcessError::PartialRead(bytes_read) =>
				write!(f, "Partially read: {:#x} bytes", bytes_read),
			ProcessError::PartialWrite(bytes_written) =>
				write!(f, "Partially wrote: {:#x} bytes", bytes_written),
			ProcessError::InvalidUnicodeString =>
				write!(f, "Attempt to read invalid unicode string"),

			// modules
			ProcessError::MalformedPE =>
				write!(f, "Malformed PE format"),
			ProcessError::ForwardDepthExceeded =>
				write!(f, "Exceeded recursive maximum forwarded export depth"),
			ProcessError::InvalidForwarderName(name) =>
				write!(f, "Invalid forwarder name: '{name}'"),

			// ..NotFound's
			ProcessError::ProcessNotFound(name) =>
				write!(f, "Process '{name} not found'"),
			ProcessError::ModuleNotFound(name) =>
				write!(f, "Module '{name}' not found"),
			ProcessError::MainModuleNotFound =>
				write!(f, "Main module not found"),
			ProcessError::ExportNotFound(name) =>
				write!(f, "Export '{name}' not found"),
			ProcessError::SectionNotFound(name) =>
				write!(f, "Section '{name}' not found"),

			// rtti
			#[cfg(feature = "rtti")]
			ProcessError::TypeNotFound(name)  =>
				write!(f, "RTTI Type '{name}' not found"),

			// vectored handlers
			#[cfg(feature = "vectored_handlers")]
			ProcessError::VectoredHandlerNotFound(handler_addr) =>
				write!(f, "Vectored Handler Entry of handler {:#X} not found", *handler_addr),
		}
    }
}

impl Debug for ProcessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(self, f)
    }
}

impl core::error::Error for ProcessError {}
