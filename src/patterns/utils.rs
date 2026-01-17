pub fn parse_ida_pattern(pat: &str) -> (Vec<u8>, Vec<u8>) {
    let mut bytes: Vec<u8> = Vec::new();
    let mut mask: Vec<u8> = Vec::new();

    for s in pat.split_ascii_whitespace() {
        if s.contains('?') {
            // wildcard
            bytes.push(0x00);
            mask.push(0xFF);
        } else {
            // hex byte
            let byte = u8::from_str_radix(s, 16).expect("failed to parse pattern hex byte");
            bytes.push(byte);
            mask.push(0x00);
        }
    }

    (bytes, mask)
}
