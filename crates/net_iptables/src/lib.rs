#[cxx::bridge(namespace = "net_iptables")]
mod ffi {
    extern "Rust" {
        fn net_iptables_ffi_smoke() -> i32;
    }
}

fn net_iptables_ffi_smoke() -> i32 {
    42
}
