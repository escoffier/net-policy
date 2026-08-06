mod ffi_raw;

#[cxx::bridge(namespace = "net_conntrack")]
mod ffi {
    extern "Rust" {
    }
}
