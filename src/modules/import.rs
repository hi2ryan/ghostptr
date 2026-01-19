
/// Represents all imports from a single DLL module.
#[derive(Debug)]
pub struct Import {
	/// The name of the DLL being imported from
	/// 
	/// (e.g.
	/// "kernel32.dll", "user32.dll")
	pub dll_name: String,

	/// List of functions imported from this DLL, either by name or ordinal
	pub functions: Vec<ImportType>,
}

/// Represents how a function is imported from a DLL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ImportType {
	/// Function imported by ordinal number.
	Ordinal(u16),

	/// Function imported by name.
	Name(String),
}
