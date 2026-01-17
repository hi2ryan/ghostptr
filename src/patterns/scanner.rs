/// A trait for scanning bytes for occurrences of a pattern.
pub trait Scanner {
    /// Scans a slice of bytes (`haystack`) for all non-overlapping matches
    /// of the underlying pattern.
    ///
    /// # Returns
    ///
    /// A `Vec<usize>` containing the starting offsets (indices into `haystack`)
    /// where the pattern was found. If no matches are found, the vector is empty.
    fn scan_bytes(&self, haystack: &[u8]) -> Vec<usize>;
}
