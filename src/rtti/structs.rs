
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CompleteObjectLocator {
	pub signature: u32,
	pub offset: u32,
	pub cd_offset: u32,
	pub type_descriptor_rva: i32,
	pub class_descriptor_rva: i32,
	pub self_rva: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TypeDescriptor {
	pub vf_table: usize,
	pub spare: usize,
	pub name: *const u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ClassHierarchyDescriptor {
	pub signature: u32,
	pub attributes: u32,
	pub num_base_classes: u32,
	pub base_class_array_rva: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BaseClassArray {
	pub base_class_descriptors: [u32; 1] // RVAs
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BaseClassDescriptor {
	pub type_descriptor_rva: i32,
	pub num_contained_bases: u32,
	pub r#where: PMD,
	pub attributes: u32,
	pub class_descriptor_rva: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PMD {
	pub m_disp: i32,
	pub p_disp: i32,
	pub v_disp: i32,
}
