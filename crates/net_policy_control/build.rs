fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let repo_root = std::path::Path::new(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/net_policy_control is two levels under the repo root");

    tonic_build::configure()
        .build_client(false)
        .compile(
            &[repo_root.join("proto/net_policy_control.proto")],
            &[repo_root.to_path_buf()],
        )
        .expect("failed to compile net_policy_control.proto");
}
