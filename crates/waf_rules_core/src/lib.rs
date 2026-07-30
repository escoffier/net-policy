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

fn is_ip_address(_s: &str) -> bool {
    unimplemented!()
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
