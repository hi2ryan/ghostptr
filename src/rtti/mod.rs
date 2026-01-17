mod structs;

use structs::{CompleteObjectLocator, TypeDescriptor};

use crate::{
    Module, Pattern32,
    error::{ProcessError, Result},
    process::Process,
};
use core::mem::offset_of;

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

/// Extension trait for `Module` that enables RTTI methods.
pub trait ModuleRTTIExt {
	/// Finds all objects of a specific mangled type within this module.
    fn objects_with_type(&self, mangled: &str) -> Result<Vec<RTTIObject>>;
}

impl<'a, P: Process> ModuleRTTIExt for Module<'a, P> {
    fn objects_with_type(&self, mangled: &str) -> Result<Vec<RTTIObject>> {
        let sections = self.sections()?;

        // get .data & .rdata sections
        let data = sections
            .iter()
            .find(|section| section.name == ".data")
            .ok_or(ProcessError::SectionNotFound(".data".to_owned()))?;
        let rdata = sections
            .iter()
            .find(|section| section.name == ".rdata")
            .ok_or(ProcessError::SectionNotFound(".rdata".to_owned()))?;

        let mut results = Vec::new();

        // scan for mangled type name
        let type_pattern = Pattern32::literal(mangled.as_bytes());
        let Some(type_str_addr) = data.scan_mem(&type_pattern).next() else {
            return Ok(results);
        };

        // backtrack to the type descriptor
        // since we have TypeDescriptor->name
        let type_descriptor_va = type_str_addr - offset_of!(TypeDescriptor, name);

        // convert type descriptor VA to RVA
        let type_descriptor_rva = (type_descriptor_va - self.base_address) as u32;

        // find cross references to the type descriptor's RVA in .rdata
        let td_rva_pattern = Pattern32::literal(&(type_descriptor_rva as i32).to_le_bytes());
        for xref in rdata.scan_mem(&td_rva_pattern) {
            // backtrack to the CompleteObjectLocator
            // since we have the COL->type_descriptor_rva
            let col_ptr = xref - offset_of!(CompleteObjectLocator, type_descriptor_rva);

            // read the COL
            let col: CompleteObjectLocator = match self.process.read_mem(col_ptr) {
                Ok(col) => col,
                _ => continue,
            };

            // verify COL
            let expected_col_ptr = self.base_address + col.self_rva as usize;
            if col.signature != 1 || col_ptr != expected_col_ptr {
                continue;
            }

            // now find vtable reference to the COL
            let col_ptr_pattern = Pattern32::literal(&col_ptr.to_le_bytes());
            let Some(vf_table) = rdata.scan_mem(&col_ptr_pattern).next() else {
                continue;
            };

            // the object is always after the vtable
            let address = vf_table + 0x8;
            results.push(RTTIObject {
                mangled_name: mangled.to_owned(),
                address,
                vf_table,
                complete_object_locator: col,
            })
        }

        Ok(results)
    }
}
