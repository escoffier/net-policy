#[cxx::bridge(namespace = "net_nfq")]
mod ffi {
    extern "Rust" {
        fn ping() -> i32;
    }
}

fn ping() -> i32 {
    // Touches both new dependencies so a build failure here means one of
    // them genuinely failed to compile/link, not that this function was
    // never exercised.
    let _ = nix::sched::CloneFlags::CLONE_NEWNET;
    42
}
