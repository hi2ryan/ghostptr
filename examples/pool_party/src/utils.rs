use ghostptr::{Handle, HandleObject, Process};

/// Hijacks a handle in the process.
pub fn hijack_handle(process: &Process, r#type: &str, access: u32) -> ghostptr::Result<Option<Handle>> {
    for handle_info in process.handles()? {
        if let Ok(raw_handle) = handle_info.duplicate_handle(Some(access)) {
            let handle = HandleObject::from(raw_handle);
            if let Ok(type_name) = handle.type_name() {
                if type_name != r#type {
                    let _ = handle.close();
                    continue;
                }

                return Ok(Some(raw_handle));
            } else {
                let _ = handle.close();
            }
        }
    }

    Ok(None)
}
