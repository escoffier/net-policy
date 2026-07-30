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
    let re = regex::Regex::new(
        r"^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])$"
    )
    .expect("static IP regex is valid");
    re.is_match(s)
}

fn ipv4_network_address(_ip: &str, _mask: u8) -> String {
    unimplemented!()
}

fn ipv4_cidr_to_network(_cidr: &str) -> ffi::CidrNetwork {
    unimplemented!()
}

fn regex_first_match(_pattern: &str, _haystack: &str) -> ffi::RegexMatch {
    unimplemented!()
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
    use super::is_ip_address;

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
}
