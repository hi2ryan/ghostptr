mod structs;
mod module;

pub use structs::*;
pub use module::ModuleRTTIExt;

/// Represents a C++ object discovered in memory using RTTI.
pub struct RTTIObject {
	 /// Memory address of the object instance.
    pub address: usize,

	/// Address of the object's virtual function table.
    pub vf_table: usize,

	/// CompleteObjectLocator associated with this object.
    pub complete_object_locator: CompleteObjectLocator,

	/// Mangled C++ type name of the object.
    pub mangled_name: String,
}
