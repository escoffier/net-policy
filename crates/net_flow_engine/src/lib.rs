#[cxx::bridge(namespace = "net_flow")]
mod ffi {
    extern "Rust" {
        fn net_flow_engine_ffi_smoke() -> i32;
    }
}

fn net_flow_engine_ffi_smoke() -> i32 {
    42
}

const IPV4_HDR_MIN_LEN: usize = 20;

struct Ipv4Header {
    header_len: usize,
    protocol: u8,
    saddr: u32,
    daddr: u32,
}

fn parse_ipv4_header(bytes: &[u8]) -> Option<Ipv4Header> {
    if bytes.len() < IPV4_HDR_MIN_LEN {
        return None;
    }
    let ihl = (bytes[0] & 0x0F) as usize;
    let header_len = ihl * 4;
    // Deliberate deviation from the current C++ (see Global Constraints):
    // reject a header claiming more bytes than are actually present, instead
    // of trusting ihl unconditionally.
    if header_len < IPV4_HDR_MIN_LEN || bytes.len() < header_len {
        return None;
    }
    let protocol = bytes[9];
    let saddr = u32::from_ne_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let daddr = u32::from_ne_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    Some(Ipv4Header { header_len, protocol, saddr, daddr })
}

fn ipv4_to_string(ip: u32) -> String {
    let b = ip.to_ne_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

#[cfg(test)]
mod ipv4_tests {
    use super::*;

    // A minimal 20-byte IPv4 header (no options): version=4, ihl=5 (20 bytes),
    // protocol=TCP(6), saddr=10.0.0.1, daddr=10.0.0.2. Other fields (tos, total
    // length, id, flags/frag, ttl, checksum) are irrelevant to parsing and left
    // as zero/arbitrary filler.
    fn sample_ipv4_header(protocol: u8, ihl: u8) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0] = (4 << 4) | (ihl & 0x0F); // version=4, ihl
        b[9] = protocol;
        b[12..16].copy_from_slice(&[10, 0, 0, 1]); // saddr
        b[16..20].copy_from_slice(&[10, 0, 0, 2]); // daddr
        b
    }

    #[test]
    fn parse_ipv4_header_extracts_fields() {
        let bytes = sample_ipv4_header(6, 5);
        let h = parse_ipv4_header(&bytes).expect("should parse");
        assert_eq!(h.header_len, 20);
        assert_eq!(h.protocol, 6);
        assert_eq!(ipv4_to_string(h.saddr), "10.0.0.1");
        assert_eq!(ipv4_to_string(h.daddr), "10.0.0.2");
    }

    #[test]
    fn parse_ipv4_header_rejects_buffer_shorter_than_minimum() {
        let bytes = vec![0u8; 19]; // one byte short of the fixed 20-byte minimum
        assert!(parse_ipv4_header(&bytes).is_none());
    }

    #[test]
    fn parse_ipv4_header_with_options_reads_correct_header_len() {
        // ihl=6 -> 24-byte header (4 bytes of IP options after the fixed 20)
        let mut bytes = sample_ipv4_header(6, 6);
        bytes.extend_from_slice(&[0, 0, 0, 0]); // 4 bytes of options
        let h = parse_ipv4_header(&bytes).expect("should parse");
        assert_eq!(h.header_len, 24);
    }

    #[test]
    fn parse_ipv4_header_rejects_options_header_len_exceeding_buffer() {
        // ihl=6 claims a 24-byte header but only 20 bytes are actually present --
        // the deliberate deviation from the current C++ (see plan's Global
        // Constraints): reject rather than trust the claimed length.
        let bytes = sample_ipv4_header(6, 6);
        assert!(parse_ipv4_header(&bytes).is_none());
    }

    #[test]
    fn ipv4_to_string_formats_dotted_decimal() {
        let bytes = sample_ipv4_header(6, 5);
        let h = parse_ipv4_header(&bytes).unwrap();
        assert_eq!(ipv4_to_string(h.saddr), "10.0.0.1");
    }
}
