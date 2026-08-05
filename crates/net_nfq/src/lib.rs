mod netns;

#[cxx::bridge(namespace = "net_nfq")]
mod ffi {
    extern "Rust" {
        fn ping() -> i32;
        fn set_ns(pid: i32, base_path: &str) -> Result<()>;
    }
}

fn ping() -> i32 {
    let _ = nix::sched::CloneFlags::CLONE_NEWNET;
    42
}

fn set_ns(pid: i32, base_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    netns::set_ns(pid, base_path)
}
