use nix::sched::{setns, unshare, CloneFlags};
use std::fs::File;

/// Mirrors `SetNs(int pid, char* basePath)` in `net-policy.cpp`: open the
/// target pid's network namespace file, `unshare(CLONE_NEWNET)`, then
/// `setns()` into it. `pid <= 0` is rejected up front, matching the C++
/// original's own guard.
pub fn set_ns(pid: i32, base_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if pid <= 0 {
        return Err("pid is error!".into());
    }
    let path = format!("{base_path}/proc/{pid}/ns/net");
    let file = File::open(&path).map_err(|e| format!("open {path} failed, err : {e}."))?;
    unshare(CloneFlags::CLONE_NEWNET).map_err(|e| format!("unshare net failed! err : {e}."))?;
    setns(file, CloneFlags::CLONE_NEWNET).map_err(|e| format!("set net ns failed, path : {path}, err : {e}."))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_positive_pid() {
        assert!(set_ns(0, "/").is_err());
        assert!(set_ns(-1, "/").is_err());
    }

    #[test]
    fn rejects_a_pid_whose_ns_file_does_not_exist() {
        // pid 1 exists in virtually every container, but this pid almost
        // certainly does not.
        let err = set_ns(999_999_999, "/").unwrap_err();
        assert!(err.to_string().contains("open"));
    }
}
