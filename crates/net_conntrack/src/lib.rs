#[cxx::bridge(namespace = "net_conntrack")]
mod ffi {
    extern "Rust" {
        fn ping() -> i32;
    }
}

fn ping() -> i32 {
    42
}
