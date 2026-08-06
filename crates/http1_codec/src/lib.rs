mod header_parser;
mod request_target;

#[cxx::bridge(namespace = "http1_codec")]
mod ffi {
    extern "Rust" {
        fn rust_ping() -> i32;
    }
}

fn rust_ping() -> i32 {
    42
}

#[cfg(test)]
mod tests {
    use super::rust_ping;

    #[test]
    fn ping_returns_42() {
        assert_eq!(rust_ping(), 42);
    }
}
