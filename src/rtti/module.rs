use super::{RTTIObject, structs::*};
use crate::{
    MemScanIter, Section,
    error::{ProcessError, Result},
    modules::Module,
    patterns::Pattern32,
    process::{AsPointer, Process},
};
use core::mem::{offset_of, size_of};

const SIZE_PTR: usize = size_of::<usize>();

/// Extension trait for `Module` that enables RTTI methods.
pub trait ModuleRTTIExt<P: Process> {
    /// Returns a lazy iterator over all objects of a specific
    /// **mangled** type within this module.
    fn objects_with_type<'a>(&'a self, mangled_name: &'a str) -> Result<RTTIObjectIter<'a, P>>;

    /// Gets all unique RTTI type names found in this module.
    ///
    /// # Returns
    /// A `Vec` of mangled type names (e.g., ".?AVMyClass@@")
    ///
    /// # Example
    /// ```rust
    /// let types = module.get_all_types()?;
    /// for type_name in types {
    ///     println!("{}", demangle(&type_name));
    /// }
    /// ```
    fn get_all_types(&self) -> Result<Vec<String>>;

    /// Returns the RTTI **mangled** type name for an object at the given address.
	/// 
	/// # Example
    /// ```rust
    /// let address = module.base_address + 0x123456;
	/// if Some(name) = module.type_name_at(address)? {
	/// 	println!("Object at {:X} has RTTI type: {}", address, demangle(&name));
	/// }
    /// ```
    fn type_name_at(&self, address: impl AsPointer) -> Result<Option<String>>;

    /// Checks whether the object at `address` matches the given RTTI type.
	/// 
	/// # Example
    /// ```rust
    /// let address = module.base_address + 0x123456;
	/// if module.has_type_at(address)? {
	/// 	println!("Object at {:X} has RTTI type info", address);
	/// }
    /// ```
    fn has_type_at(&self, address: impl AsPointer) -> Result<bool>;
}

impl<'m, P: Process> ModuleRTTIExt<P> for Module<'m, P> {
    fn objects_with_type<'a>(&'a self, mangled_name: &'a str) -> Result<RTTIObjectIter<'a, P>> {
        // get .data & .rdata sections
        let data = self.get_section(".data")?;
        let rdata = self.get_section(".rdata")?;

        // scan for mangled type name
        let type_pattern = Pattern32::literal(mangled_name.as_bytes());
        let type_str_addr = match data.scan_mem(&type_pattern).next() {
            Some(addr) => addr,
            None => return Err(ProcessError::TypeNotFound(mangled_name.to_owned())),
        };

        // backtrack to the type descriptor
        // since we have TypeDescriptor->name
        let type_descriptor_va = type_str_addr - offset_of!(TypeDescriptor, name);

        // convert type descriptor VA to RVA
        let type_descriptor_rva = (type_descriptor_va - self.base_address) as i32;

        // use pattern to find cross references to the
        // type descriptor's RVA in .rdata later
        let td_rva_pattern = Pattern32::literal(&type_descriptor_rva.to_le_bytes());

        Ok(RTTIObjectIter::new(
            self,
            mangled_name.to_owned(),
            rdata,
            td_rva_pattern,
        ))
    }

    fn get_all_types(&self) -> Result<Vec<String>> {
        let rdata = self.get_section(".rdata")?;
        let mut type_names = Vec::new();

        // scan for CompleteObjectLocators by
        // looking for 1 which is the signature
        let col_sig_pattern = Pattern32::from_value(&1u32);
        for col_addr in rdata.scan_mem(&col_sig_pattern) {
            // since signature is the first field in the struct
            // we don't need to offset, this is just the COL's address (if valid)

            // read COL
            let col: CompleteObjectLocator = match self.process.read_mem(col_addr) {
                Ok(col) => col,
                _ => continue,
            };

            // validate COL
            let expected_addr =
                (self.base_address as isize).wrapping_add(col.self_rva as isize) as usize;
            if col_addr != expected_addr {
                continue;
            }

            // read TypeDescriptor->name
            let td_addr = (self.base_address as isize)
                .wrapping_add(col.type_descriptor_rva as isize) as usize;
            let name_addr = td_addr + offset_of!(TypeDescriptor, name);
            let type_name = match self.process.read_c_string(name_addr, Some(256)) {
                Ok(name) => name,
                _ => continue,
            };

            if !type_names.contains(&type_name) {
                // found new type name
                type_names.push(type_name)
            }
        }

        Ok(type_names)
    }

    fn type_name_at(&self, address: impl AsPointer) -> Result<Option<String>> {
        // read vftable ptr
        let address = address.as_ptr() as usize;
        let vf_ptr: usize = self.process.read_mem(address)?;

        let col_ptr_addr = match vf_ptr.checked_sub(SIZE_PTR) {
            Some(addr) => addr,
            None => return Ok(None),
        };

        // read the CompleteObjectLocator pointer at vftable[-1]
        let col_ptr: usize = self.process.read_mem(col_ptr_addr)?;

        // read the COL
        let col: CompleteObjectLocator = self.process.read_mem(col_ptr)?;

        // validate signature
        if col.signature != 1 {
            return Ok(None);
        }

        // validate COL pointer
        let expected_col_ptr =
            (self.base_address as isize).wrapping_add(col.self_rva as isize) as usize;
        if col_ptr != expected_col_ptr {
            return Ok(None);
        }

        // get TypeDescriptor->name pointer
        let type_desc_va =
            (self.base_address as isize).wrapping_add(col.type_descriptor_rva as isize) as usize;
        let name_ptr = type_desc_va + offset_of!(TypeDescriptor, name);

        // read type name
        let type_name = self.process.read_c_string(name_ptr, Some(256))?;
        Ok(Some(type_name))
    }

    fn has_type_at(&self, address: impl AsPointer) -> Result<bool> {
        // read vftable ptr
        let address = address.as_ptr() as usize;
        let vf_ptr: usize = self.process.read_mem(address)?;

        let col_ptr_addr = match vf_ptr.checked_sub(SIZE_PTR) {
            Some(addr) => addr,
            None => return Ok(false),
        };

        // read the CompleteObjectLocator pointer at vftable[-1]
        let col_ptr: usize = self.process.read_mem(col_ptr_addr)?;

        if col_ptr == 0 {
            // invalid COL pointer
            return Ok(false);
        }

        // read the COL
        let col: CompleteObjectLocator = self.process.read_mem(col_ptr)?;

        // validate signature
        if col.signature != 1 {
            return Ok(false);
        }

        // validate COL pointer
        let expected_col_ptr =
            (self.base_address as isize).wrapping_add(col.self_rva as isize) as usize;
        if col_ptr != expected_col_ptr {
            return Ok(false);
        }

        // ensure the TypeDescriptor is readable
        let type_desc_va =
            (self.base_address as isize).wrapping_add(col.type_descriptor_rva as isize) as usize;

        if self
            .process
            .read_mem::<TypeDescriptor>(type_desc_va)
            .is_err()
        {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Represents an iterator scanning for all
/// objecs of a specific mangled type within a module.
pub struct RTTIObjectIter<'a, P: Process + ?Sized> {
    module: &'a Module<'a, P>,
    rdata_section: Section<'a, P>,
    td_rva_pattern: Pattern32,
    xrefs: Option<MemScanIter<'a, P, Pattern32>>,
    mangled_name: String,
}

impl<'a, P: Process> RTTIObjectIter<'a, P> {
    #[inline(always)]
    pub(crate) fn new(
        module: &'a Module<'a, P>,
        mangled_name: String,
        rdata_section: Section<'a, P>,
        td_rva_pattern: Pattern32,
    ) -> Self {
        Self {
            module,
            mangled_name,
            rdata_section,
            td_rva_pattern,
            xrefs: None,
        }
    }
}

impl<'a, P: Process> Iterator for RTTIObjectIter<'a, P> {
    type Item = RTTIObject;

    fn next(&mut self) -> Option<Self::Item> {
        if self.xrefs.is_none() {
            unsafe {
                let pattern_ref: &'a Pattern32 = &*(&self.td_rva_pattern as *const Pattern32);
                self.xrefs = Some(self.rdata_section.scan_mem(pattern_ref));
            }
        }

        let xrefs = self.xrefs.as_mut().unwrap();
        while let Some(xref) = xrefs.next() {
            // backtrack to the CompleteObjectLocator
            // since we have the COL->type_descriptor_rva
            let col_ptr = xref - offset_of!(CompleteObjectLocator, type_descriptor_rva);

            // read the COL
            let col: CompleteObjectLocator = match self.module.process.read_mem(col_ptr) {
                Ok(col) => col,
                _ => continue,
            };

            // verify COL
            let expected_col_ptr = self.module.base_address + col.self_rva as usize;
            if col.signature != 1 || col_ptr != expected_col_ptr {
                continue;
            }

            // now find vtable reference to the COL
            let col_ptr_pattern = Pattern32::literal(&col_ptr.to_le_bytes());
            let Some(vf_table) = self.rdata_section.scan_mem(&col_ptr_pattern).next() else {
                continue;
            };

            // the object is always after the vtable
            let address = vf_table + 0x8;

            return Some(RTTIObject {
                mangled_name: self.mangled_name.clone(),
                address,
                vf_table,
                complete_object_locator: col,
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    pub fn djb2_hash(s: &str) -> u32 {
        let mut hash: u32 = 5381;
        for c in s.bytes() {
            hash = ((hash << 5).wrapping_add(hash)).wrapping_add(c as u32);
        }
        hash
    }

    #[test]
    fn get_rtti_types() -> Result<()> {
        const PROCESS_NAME_HASH: u32 = 0xfff1c74;

        let process = ProcessIterator::new()?
            .find(|p| djb2_hash(&p.name) == PROCESS_NAME_HASH)
            .map(|p| p.open(ProcessAccess::VM_READ | ProcessAccess::QUERY_INFORMATION))
            .expect("process not open")?;

        println!("pid:    {:08}", process.pid()?);
        println!("handle: {:08X}", unsafe { process.handle() });

        let module = process.main_module()?;

        let types = module.get_all_types()?;
        assert!(types.len() > 0, "no rtti types found");

        Ok(())
    }
}
