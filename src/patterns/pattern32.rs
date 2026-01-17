use super::{Scanner, utils::parse_ida_pattern};
use core::arch::x86_64::{
    __m256i, _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8, _mm256_or_si256,
};

/// A SIMD-accelerated pattern matcher using 256-bit (AVX2) chunks.
///
/// `Pattern32` stores the pattern as a sequence of 32-byte chunks.
pub struct Pattern32 {
    /// The 32-byte chunks of the pattern.
    chunks: Vec<PatternChunk32>,

    /// Total length of the pattern in bytes (including wildcards).
    len: usize,
}

/// A 256-bit (32-byte) chunk.
struct PatternChunk32 {
    /// The pattern bytes for this 32-byte chunk.
    bytes: __m256i,

    /// The mask controlling which bytes are treated as wildcards or literals.
    mask: __m256i,
}

impl Pattern32 {
    /// Creates a `Pattern32` from an IDA-style pattern.
    ///
    /// # Example
    /// ```rust
    /// let pat = Pattern32::from_ida("E8 ?? ?? 90 90 90");
    /// ```
    pub fn from_ida(pat: &str) -> Self {
        let (bytes, mask) = parse_ida_pattern(pat);
        Self::from_bytes(bytes, mask)
    }

    /// Creates a `Pattern32` from bytes without wildcards.
    ///
    /// # Example
    /// ```rust
    /// let pat = Pattern32::literal(b".?AV@DATA@@");
    /// ```
    pub fn literal(bytes: &[u8]) -> Self {
        let mask = vec![0x00; bytes.len()];
        Self::from_bytes(bytes.to_vec(), mask)
    }

    /// Creates a `Pattern32` from a code-style pattern
    ///
    /// # Example
    /// ```
    /// let pattern = Pattern32::from_byte_mask(
    ///     &[0x90, 0xE8, 0x09, 0x00],
    ///     &['x', 'x', '?', '?']
    /// );
    /// ```
    /// This will match memory sequences where the first two bytes are exactly `0x90 0xE8`
    /// and the next two bytes can be any value.
    ///
    /// # Panics
    /// Panics if `bytes` and `mask` have different lengths.
    pub fn from_byte_mask(bytes: &[u8], mask: &[char]) -> Self {
        assert_eq!(bytes.len(), mask.len(), "mismatched bytes & mask length");

        let not_mask = mask
            .iter()
            .map(|&c| if c == '?' { 0xFF } else { 0x00 })
            .collect();
        Self::from_bytes(bytes.to_vec(), not_mask)
    }

    fn from_bytes(bytes: Vec<u8>, mask: Vec<u8>) -> Self {
        let len = bytes.len();
        assert!(len > 0, "pattern cannot be empty");

        let mut chunks: Vec<PatternChunk32> = Vec::new();
        let mut i = 0;

        while i < len {
            let remaining = len - i;

            // take how many we have left capping at 32 bytes
            let take = remaining.min(32);

            // blocks must be 256-bits (32 bytes)
            let mut val_block = [0u8; 32];
            let mut mask_block = [0xFFu8; 32];

            // copy (max 32) bytes
            val_block[..take].copy_from_slice(&bytes[i..i + take]);
            mask_block[..take].copy_from_slice(&mask[i..i + take]);

            unsafe {
                // load 256-bit chunk
                let bytes = _mm256_loadu_si256(val_block.as_ptr() as *const __m256i);
                let mask = _mm256_loadu_si256(mask_block.as_ptr() as *const __m256i);

                chunks.push(PatternChunk32 { bytes, mask });
            }
            i += take;
        }

        Self { chunks, len }
    }
}

impl Scanner for Pattern32 {
    /// Scans a slice of bytes (`haystack`) for all non-overlapping matches
    /// of the underlying pattern.
    ///
    /// # Returns
    ///
    /// A `Vec<usize>` containing the starting offsets (indices into `haystack`)
    /// where the pattern was found. If no matches are found, the vector is empty.
    fn scan_bytes(&self, haystack: &[u8]) -> Vec<usize> {
        let haystack_len = haystack.len();
        let pattern_len = self.len;

        if pattern_len > haystack_len {
            // pattern bigger than the byte slice
            return vec![];
        }

        let mut offsets = vec![];
        let end = haystack_len - pattern_len;

        for i in 0..=end {
            let mut matched = true;

            for (chunk_idx, chunk) in self.chunks.iter().enumerate() {
                let offset = i + chunk_idx * 32;

                unsafe {
                    // convert the bytes to 256bit num (__m256i)
                    let ptr = haystack.as_ptr().add(offset) as *const __m256i;
                    let hay = _mm256_loadu_si256(ptr);

                    let eq = _mm256_cmpeq_epi8(hay, chunk.bytes);
                    let masked = _mm256_or_si256(eq, chunk.mask);

                    if _mm256_movemask_epi8(masked) != -1 {
                        matched = false;
                        break;
                    }
                }
            }

            if matched {
                offsets.push(i);
            }
        }

        offsets
    }
}

#[cfg(test)]
mod tests {
	use super::{Pattern32, Scanner};

    #[test]
    fn simple_exact_match() {
        let pat = Pattern32::from_ida("DE AD BE EF");
        let hay = b"\x00\xDE\xAD\xBE\xEF\x00";

        let hits = pat.scan_bytes(hay);
        assert_eq!(hits, vec![1]);
    }

    #[test]
    fn wildcard_middle() {
        let pat = Pattern32::from_ida("90 ?? 90");
        let hay = b"\x90\x11\x90\x90\x22\x90";
        let hits = pat.scan_bytes(hay);
        assert_eq!(hits, vec![0, 3]);
    }

    #[test]
    fn wildcard_edges() {
        let pat = Pattern32::from_ida("?? 11 22 ??");
        let hay = b"\x00\x11\x22\x00\xFF\x11\x22\xFF";

        let hits = pat.scan_bytes(hay);
        assert_eq!(hits, vec![0, 4]);
    }

    #[test]
    fn no_match() {
        let pat = Pattern32::from_ida("AA BB CC");
        let hay = b"\xAA\xBB\x00\xAA\x00\xCC";

        let hits = pat.scan_bytes(hay);
        assert!(hits.is_empty());
    }

    #[test]
    fn multiple_matches() {
        let pat = Pattern32::from_ida("41 42");
        let hay = b"XXABXXABXXAB";

        let hits = pat.scan_bytes(hay);
        assert_eq!(hits, vec![2, 6, 10]);
    }

    #[test]
    fn pattern_at_start() {
        let pat = Pattern32::from_ida("11 22 33");
        let hay = b"\x11\x22\x33\x44\x55";

        let hits = pat.scan_bytes(hay);
        assert_eq!(hits, vec![0]);
    }

    #[test]
    fn pattern_at_end() {
        let pat = Pattern32::from_ida("44 55 66");
        let hay = b"\x00\x11\x22\x44\x55\x66";

        let hits = pat.scan_bytes(hay);
        assert_eq!(hits, vec![3]);
    }

    #[test]
    fn pattern_longer_than_32_bytes() {
        // 40‑byte pattern → 2 chunks
        let pat = Pattern32::from_ida(
            "01 02 03 04 05 06 07 08 \
             09 0A 0B 0C 0D 0E 0F 10 \
             11 12 13 14 15 16 17 18 \
             19 1A 1B 1C 1D 1E 1F 20 \
             21 22 23 24 25 26 27 28",
        );

        // Insert pattern starting at offset 5
        let mut hay = vec![0u8; 5];
        hay.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        ]);
        hay.extend_from_slice(&[0xFF, 0xFF, 0xFF]);

        let hits = pat.scan_bytes(&hay);
        assert_eq!(hits, vec![5]);
    }

    #[test]
    fn pattern_not_aligned_to_32_bytes() {
        // 17‑byte pattern → 1 full chunk + padding
        let pat = Pattern32::from_ida(
            "AA BB CC DD EE FF 11 22 \
             33 44 55 66 77 88 99 AA BB",
        );

        let mut hay = vec![0u8; 10];
        hay.extend_from_slice(&[
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB,
        ]);
        hay.extend_from_slice(&[0x00, 0x00]);

        let hits = pat.scan_bytes(&hay);
        assert_eq!(hits, vec![10]);
    }

    #[test]
    fn wildcard_heavy_pattern() {
        // 8‑byte pattern with 6 wildcards
        let pat = Pattern32::from_ida("AA ?? ?? ?? ?? ?? BB CC");
        let hay = b"\xAA\x11\x22\x33\x44\x55\xBB\xCC";

        let hits = pat.scan_bytes(hay);
        assert_eq!(hits, vec![0]);
    }
}
