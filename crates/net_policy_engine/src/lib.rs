#[cxx::bridge(namespace = "policy_engine")]
mod ffi {
    extern "Rust" {
        fn policy_engine_ffi_smoke() -> i32;
    }
}

fn policy_engine_ffi_smoke() -> i32 {
    42
}
