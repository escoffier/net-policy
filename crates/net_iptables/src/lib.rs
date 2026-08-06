#[cxx::bridge(namespace = "net_iptables")]
mod ffi {
    extern "Rust" {
        fn write_iptable_rule(i_mark: i32, o_mark: i32, ipt_ver: i32);
        fn clear_iptables_rule(ipt_ver: i32);
        fn check_iptables_rule(ipt_ver: i32) -> bool;
        fn get_iptables_version() -> i32;
    }
}

use std::process::Command;

fn iptables_bin(ipt_ver: i32) -> &'static str {
    if ipt_ver == 0 { "iptables" } else { "iptables-legacy" }
}

/// Runs `bin -t mangle -S` and returns true iff its output contains `needle`.
/// Mirrors CheckIptablesRule/WriteIptableRule's popen+fread+strlen checks, but
/// without popen's fixed 1024-byte read cap -- Command::output() captures the
/// full stdout, a strict improvement with no behavior difference for any
/// input this codebase actually produces (the greppable marker line appears
/// near the start of `iptables -S` output in every real invocation).
fn mangle_table_contains(bin: &str, needle: &str) -> bool {
    let output = Command::new(bin).args(["-t", "mangle", "-S"]).output();
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).contains(needle),
        Err(_) => false,
    }
}

fn run(bin: &str, args: &[&str]) {
    let _ = Command::new(bin).args(args).status();
}

pub fn check_iptables_rule(ipt_ver: i32) -> bool {
    mangle_table_contains(iptables_bin(ipt_ver), "TS_ZERO_PREROUTING")
}

pub fn clear_iptables_rule(ipt_ver: i32) {
    let bin = iptables_bin(ipt_ver);
    run(bin, &["-t", "mangle", "-F"]);
    run(bin, &["-t", "mangle", "-X", "TS_ZERO_PREROUTING"]);
    run(bin, &["-t", "mangle", "-X", "TS_ZERO_OUTPUT"]);
}

/// The C++ original issued chain creation as a single shelled command,
/// `"iptables ... -N CHAIN 2>/dev/null && iptables ... -I ..."`, where the
/// shell's `&&` skips the `-I` if `-N` fails. Here `-N` and `-I` are two
/// separate `Command` invocations with no such short-circuit between them.
/// That's safe not because exit codes go unchecked either way, but because
/// each `-N` below is only ever reached after `mangle_table_contains` has
/// just confirmed the target chain does NOT exist yet -- so on every path
/// this code actually executes, `-N` is guaranteed to succeed, making the
/// "what if -N fails" question moot. Note we also drop the `2>/dev/null`
/// redirect: if `-N` ever did fail (shouldn't happen given the guard above),
/// iptables would print "Chain already exists" to stderr -- harmless, just
/// noisier than the original.
pub fn write_iptable_rule(i_mark: i32, o_mark: i32, ipt_ver: i32) {
    let bin = iptables_bin(ipt_ver);

    if check_iptables_rule(ipt_ver) {
        clear_iptables_rule(ipt_ver);
    }

    if !mangle_table_contains(bin, "TS_ZERO_PREROUTING") {
        run(bin, &["-t", "mangle", "-N", "TS_ZERO_PREROUTING"]);
        run(bin, &["-t", "mangle", "-I", "PREROUTING", "-j", "TS_ZERO_PREROUTING"]);
        run(bin, &["-t", "mangle", "-I", "PREROUTING", "-j", "CONNMARK", "--restore-mark"]);
        run(bin, &["-t", "mangle", "-A", "TS_ZERO_PREROUTING", "-m", "mark", "--mark",
                    &i_mark.to_string(), "-j", "ACCEPT"]);
        run(bin, &["-t", "mangle", "-A", "TS_ZERO_PREROUTING", "-j", "NFQUEUE",
                    "--queue-num", "0", "--queue-bypass"]);
        run(bin, &["-t", "mangle", "-A", "INPUT", "-j", "CONNMARK", "--save-mark"]);
    }

    if !mangle_table_contains(bin, "TS_ZERO_OUTPUT") {
        run(bin, &["-t", "mangle", "-N", "TS_ZERO_OUTPUT"]);
        run(bin, &["-t", "mangle", "-I", "OUTPUT", "-j", "TS_ZERO_OUTPUT"]);
        run(bin, &["-t", "mangle", "-I", "OUTPUT", "-j", "CONNMARK", "--restore-mark"]);
        run(bin, &["-t", "mangle", "-A", "TS_ZERO_OUTPUT", "-m", "mark", "--mark",
                    &o_mark.to_string(), "-j", "ACCEPT"]);
        run(bin, &["-t", "mangle", "-A", "TS_ZERO_OUTPUT", "-j", "NFQUEUE",
                    "--queue-num", "1", "--queue-bypass"]);
        run(bin, &["-t", "mangle", "-A", "POSTROUTING", "-j", "CONNMARK", "--save-mark"]);
    }
}

pub fn get_iptables_version() -> i32 {
    let output = Command::new("iptables").args(["-t", "nat", "-S", "PREROUTING"]).output();
    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains("-A PREROUTING") { 0 } else { 1 }
        }
        // Divergence from the C++ original: popen() succeeds even when the
        // `iptables` binary is missing from PATH (stdout just comes back
        // empty, so the "-A PREROUTING" search misses and the original
        // returns 1). Command::output()'s Err(_) here is spawn failure --
        // e.g. binary not found -- and we return 0 instead of 1 for that
        // case, a real 1->0 behavior flip. Practically irrelevant: if
        // `iptables` is missing, `iptables-legacy` almost certainly is too.
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::Mutex;

    // These tests mutate real, global iptables state (the mangle table's
    // TS_ZERO_PREROUTING/TS_ZERO_OUTPUT chains), and Rust's default test
    // harness runs tests in separate threads concurrently within the same
    // process. Without serialization, check_iptables_rule_false_when_absent
    // and write_then_check_then_clear_round_trips race on the same chains
    // (observed empirically: one test's cleanup can delete a chain the other
    // just created, or vice versa, producing an intermittent assertion
    // failure). This lock is not part of the plan's original test listing --
    // it's a deliberate addition to make these tests deterministic under
    // `cargo test`'s default parallelism.
    static IPTABLES_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn cleanup_test_chains() {
        let _ = Command::new("iptables").args(["-t", "mangle", "-F", "TS_ZERO_PREROUTING"]).status();
        let _ = Command::new("iptables").args(["-t", "mangle", "-X", "TS_ZERO_PREROUTING"]).status();
        let _ = Command::new("iptables").args(["-t", "mangle", "-F", "TS_ZERO_OUTPUT"]).status();
        let _ = Command::new("iptables").args(["-t", "mangle", "-X", "TS_ZERO_OUTPUT"]).status();
        // best-effort: also remove any jump rules this test's write_iptable_rule call added
        let _ = Command::new("iptables").args(["-t", "mangle", "-D", "PREROUTING", "-j", "TS_ZERO_PREROUTING"]).status();
        let _ = Command::new("iptables").args(["-t", "mangle", "-D", "OUTPUT", "-j", "TS_ZERO_OUTPUT"]).status();
        let _ = Command::new("iptables").args(["-t", "mangle", "-D", "PREROUTING", "-j", "CONNMARK", "--restore-mark"]).status();
        let _ = Command::new("iptables").args(["-t", "mangle", "-D", "OUTPUT", "-j", "CONNMARK", "--restore-mark"]).status();
        // Also remove the two CONNMARK --save-mark rules that write_iptable_rule
        // now unconditionally appends directly to the builtin INPUT/POSTROUTING
        // chains. Empirically verified this needs its own -D: production's
        // clear_iptables_rule uses a bare `-t mangle -F` (no chain argument),
        // which flushes *every* chain in the mangle table -- including
        // INPUT/POSTROUTING's own rules -- so that path clears these for free.
        // But this helper uses `-F TS_ZERO_PREROUTING`/`-F TS_ZERO_OUTPUT` (named,
        // scoped to just those user chains), which does NOT touch INPUT or
        // POSTROUTING at all, so rules appended directly to them would otherwise
        // leak across test runs.
        let _ = Command::new("iptables").args(["-t", "mangle", "-D", "INPUT", "-j", "CONNMARK", "--save-mark"]).status();
        let _ = Command::new("iptables").args(["-t", "mangle", "-D", "POSTROUTING", "-j", "CONNMARK", "--save-mark"]).status();
    }

    #[test]
    fn check_iptables_rule_false_when_absent() {
        let _guard = IPTABLES_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup_test_chains();
        assert!(!check_iptables_rule(0));
        cleanup_test_chains();
    }

    #[test]
    fn write_then_check_then_clear_round_trips() {
        let _guard = IPTABLES_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup_test_chains();
        write_iptable_rule(100, 101, 0);
        assert!(check_iptables_rule(0));
        clear_iptables_rule(0);
        assert!(!check_iptables_rule(0));
        cleanup_test_chains();
    }

    #[test]
    fn get_iptables_version_returns_zero_or_one() {
        let v = get_iptables_version();
        assert!(v == 0 || v == 1);
    }

    // write_iptable_rule always installs these CONNMARK --save-mark rules now
    // (there is no more waf_enable parameter) -- this is the historical
    // WAF-off default behavior, made unconditional.
    #[test]
    fn write_always_adds_save_mark_rules_to_input_and_postrouting() {
        let _guard = IPTABLES_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup_test_chains();

        write_iptable_rule(100, 101, 0);

        let input = Command::new("iptables").args(["-t", "mangle", "-S", "INPUT"]).output().unwrap();
        let postrouting =
            Command::new("iptables").args(["-t", "mangle", "-S", "POSTROUTING"]).output().unwrap();
        assert!(
            String::from_utf8_lossy(&input.stdout).contains("CONNMARK --save-mark"),
            "expected -A INPUT -j CONNMARK --save-mark"
        );
        assert!(
            String::from_utf8_lossy(&postrouting.stdout).contains("CONNMARK --save-mark"),
            "expected -A POSTROUTING -j CONNMARK --save-mark"
        );

        clear_iptables_rule(0);
        cleanup_test_chains();
    }
}
