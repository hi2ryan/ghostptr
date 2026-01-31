/// Represents an exported symbol from a PE module's Export Address Table.
///
/// Exports can be:
/// - Named
/// - Ordinal-only (no name)
/// - Forwarded to another module
#[derive(Debug)]
pub struct Export {
    /// The name of the exported symbol, if present.
    pub name: Option<String>,

    /// The export ordinal.
    pub ordinal: u16,

    /// The resolved virtual address of the exported function.
    /// This will be `0` if the export is forwarded.
    pub address: usize,

    /// The forwarder target, if this export is forwarded.
    ///
    /// The ASCII string's format is:
    /// ```text
    /// MODULE.NAME
    /// MODULE.#ORDINAL
    /// ```
    pub forwarded_to: Option<String>,
}