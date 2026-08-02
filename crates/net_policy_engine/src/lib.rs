#[cxx::bridge(namespace = "policy_engine")]
mod ffi {
    extern "Rust" {
        fn policy_engine_ffi_smoke() -> i32;
    }
}

fn policy_engine_ffi_smoke() -> i32 {
    42
}

fn parse_cidr(cidr: &str) -> (String, i32) {
    let (ip_str, mask): (&str, i32) = match cidr.find('/') {
        Some(idx) => (&cidr[..idx], cidr[idx + 1..].parse().unwrap_or(32)),
        None => (cidr, 32),
    };
    let ip_u32: u32 = ip_str.parse::<std::net::Ipv4Addr>().map(u32::from).unwrap_or(0);
    let net_mask: u32 = (!0u32).wrapping_shl((32 - mask) as u32);
    let masked = ip_u32 & net_mask;
    (std::net::Ipv4Addr::from(masked).to_string(), mask)
}

fn ipv4_cidr_to_ip(ip: &str, mask: i32) -> String {
    let ip_u32: u32 = ip.parse::<std::net::Ipv4Addr>().map(u32::from).unwrap_or(0);
    let net_mask: u32 = (!0u32).wrapping_shl((32 - mask) as u32);
    std::net::Ipv4Addr::from(ip_u32 & net_mask).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_masks_to_network_address() {
        assert_eq!(parse_cidr("10.1.2.3/24"), ("10.1.2.0".to_string(), 24));
        assert_eq!(parse_cidr("192.168.5.9/16"), ("192.168.0.0".to_string(), 16));
    }

    #[test]
    fn parse_cidr_bare_ip_defaults_to_slash_32() {
        assert_eq!(parse_cidr("10.1.2.3"), ("10.1.2.3".to_string(), 32));
    }

    #[test]
    fn parse_cidr_slash_32_is_identity() {
        assert_eq!(parse_cidr("10.1.2.3/32"), ("10.1.2.3".to_string(), 32));
    }

    #[test]
    fn ipv4_cidr_to_ip_masks_to_network_address() {
        assert_eq!(ipv4_cidr_to_ip("10.1.2.3", 24), "10.1.2.0");
        assert_eq!(ipv4_cidr_to_ip("10.1.2.3", 32), "10.1.2.3");
    }
}
