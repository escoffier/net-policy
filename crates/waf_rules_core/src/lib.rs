#[cxx::bridge(namespace = "waf_rules")]
mod ffi {
    struct CidrNetwork {
        network_ip: String,
        mask: u8,
    }

    struct RegexMatch {
        matched: bool,
        value: String,
    }

    extern "Rust" {
        fn is_ip_address(s: &str) -> bool;
        fn ipv4_network_address(ip: &str, mask: u8) -> String;
        fn ipv4_cidr_to_network(cidr: &str) -> CidrNetwork;
        fn regex_first_match(pattern: &str, haystack: &str) -> RegexMatch;
        fn match_domain(host: &str, domains: Vec<String>) -> bool;
        fn match_ignore_type(path: &str, ignored_suffixes: Vec<String>) -> bool;
        fn eval_bool_expr(expr: &str) -> bool;
    }
}

fn is_ip_address(s: &str) -> bool {
    let re = regex::RegexBuilder::new(
        r"^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])$"
    )
    .unicode(false)
    .build()
    .expect("static IP regex is valid");
    re.is_match(s)
}

fn ipv4_network_address(ip: &str, mask: u8) -> String {
    let mask = mask.min(32);
    let octets: Vec<u32> = ip.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    if octets.len() != 4 {
        return String::new();
    }
    let ip_bits = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    let mask_bits: u32 = if mask == 0 { 0 } else { 0xFFFF_FFFFu32 << (32 - mask as u32) };
    let network = ip_bits & mask_bits;
    format!(
        "{}.{}.{}.{}",
        (network >> 24) & 0xFF,
        (network >> 16) & 0xFF,
        (network >> 8) & 0xFF,
        network & 0xFF
    )
}

fn ipv4_cidr_to_network(cidr: &str) -> ffi::CidrNetwork {
    let (ip_part, mask) = match cidr.find('/') {
        Some(idx) => (&cidr[..idx], cidr[idx + 1..].parse().unwrap_or(32u8)),
        None => (cidr, 32u8),
    };
    ffi::CidrNetwork {
        network_ip: ipv4_network_address(ip_part, mask),
        mask,
    }
}

fn regex_first_match(pattern: &str, haystack: &str) -> ffi::RegexMatch {
    let re = match regex::Regex::new(pattern) {
        Ok(re) => re,
        Err(e) => {
            eprintln!("waf_rules_core: pattern failed to compile, treating as no-match: {pattern:?}: {e}");
            return ffi::RegexMatch { matched: false, value: String::new() };
        }
    };
    match re.find(haystack) {
        Some(m) => ffi::RegexMatch { matched: true, value: m.as_str().to_string() },
        None => ffi::RegexMatch { matched: false, value: String::new() },
    }
}

fn match_domain(_host: &str, _domains: Vec<String>) -> bool {
    unimplemented!()
}

fn match_ignore_type(_path: &str, _ignored_suffixes: Vec<String>) -> bool {
    unimplemented!()
}

fn eval_bool_expr(_expr: &str) -> bool {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::{is_ip_address, ipv4_cidr_to_network, ipv4_network_address};

    #[test]
    fn accepts_valid_dotted_quad() {
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("0.0.0.0"));
        assert!(is_ip_address("255.255.255.255"));
    }

    #[test]
    fn rejects_non_ip_strings() {
        assert!(!is_ip_address("example.com"));
        assert!(!is_ip_address("256.1.1.1"));
        assert!(!is_ip_address("1.2.3"));
        assert!(!is_ip_address("1.2.3.4.5"));
        assert!(!is_ip_address(""));
    }

    #[test]
    fn rejects_fullwidth_digits() {
        // Fullwidth digit "１" (U+FF11) should be rejected, matching C++ original ASCII-only semantics
        assert!(!is_ip_address("192.168.1.\u{FF11}"));
    }

    #[test]
    fn network_address_masks_correctly() {
        assert_eq!(ipv4_network_address("192.168.1.55", 24), "192.168.1.0");
        assert_eq!(ipv4_network_address("10.0.5.9", 8), "10.0.0.0");
        assert_eq!(ipv4_network_address("172.16.0.1", 32), "172.16.0.1");
    }

    #[test]
    fn network_address_handles_zero_mask() {
        // mask=0 should zero out all bits
        assert_eq!(ipv4_network_address("192.168.1.55", 0), "0.0.0.0");
    }

    #[test]
    fn network_address_clamps_out_of_range_masks() {
        // mask > 32 should be clamped to 32 (full address match)
        assert_eq!(ipv4_network_address("192.168.1.55", 33), "192.168.1.55");
        assert_eq!(ipv4_network_address("192.168.1.55", 255), "192.168.1.55");
    }

    #[test]
    fn cidr_to_network_splits_mask() {
        let result = ipv4_cidr_to_network("192.168.1.55/24");
        assert_eq!(result.network_ip, "192.168.1.0");
        assert_eq!(result.mask, 24);
    }

    #[test]
    fn cidr_to_network_defaults_to_slash_32() {
        let result = ipv4_cidr_to_network("10.1.2.3");
        assert_eq!(result.network_ip, "10.1.2.3");
        assert_eq!(result.mask, 32);
    }

    use super::regex_first_match;

    #[test]
    fn finds_first_match() {
        let result = regex_first_match(r"\d+", "abc123def456");
        assert!(result.matched);
        assert_eq!(result.value, "123");
    }

    #[test]
    fn reports_no_match() {
        let result = regex_first_match(r"\d+", "no digits here");
        assert!(!result.matched);
        assert_eq!(result.value, "");
    }

    #[test]
    fn invalid_pattern_fails_closed_instead_of_panicking() {
        // Backreferences aren't supported by the `regex` crate — this is
        // exactly the PCRE-incompatible case flagged in the Phase 1 preamble.
        let result = regex_first_match(r"(a)\1", "aa");
        assert!(!result.matched);
        assert_eq!(result.value, "");
    }
}
