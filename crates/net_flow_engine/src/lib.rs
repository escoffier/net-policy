#[cxx::bridge(namespace = "net_flow")]
mod ffi {
    extern "Rust" {
        fn net_flow_engine_ffi_smoke() -> i32;
    }
}

fn net_flow_engine_ffi_smoke() -> i32 {
    42
}
