# Phase 6a: iptables Rules + Legacy Control Protocol Retirement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete the confirmed-dead legacy raw-socket JSON control protocol (port 9999), and migrate iptables rule management (`WriteIptableRule`/`ClearIptabelsRule`/`CheckIptablesRule`/`GetIptablesVersion`) to a new Rust crate, `net_iptables`.

**Architecture:** The legacy protocol deletion is pure C++ removal — `CtrlServer`, `ProcAcceptEvent`, `ParseRcvData`, `ParseRcvJson`, `ReadData`, and the `NetDataType`/`NET_DATA_TYPE` enum are deleted outright; every one of the 11 message types they dispatched already has a working gRPC equivalent (`grpc/control_dispatch.h`'s `GrpcDispatch*` family). The iptables functions are pure, stateless shell-outs to the `iptables`/`iptables-legacy` CLI (`system()`/`popen()` in C++, `std::process::Command` in Rust) — no opaque type, no per-instance state, the simplest possible `cxx` bridge shape (plain functions, scalar arguments/returns).

**Tech Stack:** Rust (`cxx` crate for FFI, `staticlib` crate type, Corrosion for CMake integration — same toolchain as `ffi_smoke`/`waf_rules_core`/`net_policy_control`/`net_policy_events`/`net_flow_engine`/`net_policy_engine`), C++17, Google Test.

**Reference spec:** `docs/superpowers/specs/2026-08-03-cpp-to-rust-phase6a-iptables-legacy-retirement-design.md`

## Global Constraints

- `ParseNetPolicy`, `ParseNodeCfg`, `DeletePolicy` (the free function, not `MicroSegEngine::DeletePolicy`), `AddNewHttpPolicy`, `AddNewPolicy`, `UpdateMark`, `dumpConnectons` are OUT OF SCOPE — do not delete or modify them. They are shared between the legacy protocol and the live gRPC dispatch path (e.g. `GrpcDispatchAddPolicyRule` builds a JSON string from protobuf fields and calls `ParseNetPolicy`, confirmed at `net-policy.cpp:2261-2270`) and remain load-bearing after this phase.
- `NetCtrlInfo`/`NET_CTRL_INFO` (the struct) is OUT OF SCOPE — it's `InitNfqueue`'s parameter type and is constructed inside `GrpcDispatchPodUp` too (`net-policy.cpp:1971`). Only the `NetDataType`/`NET_DATA_TYPE` enum and the `msg_type_` field's *usage* (confined to the deleted dispatch chain) go away — do not remove the `msg_type_` field itself from `NetCtrlInfo` unless it is confirmed to have zero remaining readers after Task 1's deletions (verify via grep, don't assume).
- `PostServer`, `CreatePostServer`, `ProcAcceptPostLinkEvent`, the port-8888 socket, and everything under `http/`/`waf/` are OUT OF SCOPE — `PostServer` is a completely different subsystem (WAF/match-event notifications pushed to pods), not part of the control-plane protocol being retired.
- `net-policy.cpp`'s `RunNetPolicyDaemon` main loop (the `while(1) { epoll_wait(...); ... }` block itself), the Rust gRPC control/event server bootstrap (`grpc_bridge::start_event_server`/`start_control_server`), `NFQ_RES_INFO`, `InitNfqueue`, `OpenNfque`, `OpenConntrack`, and `SetNs`/`OpenLocalNetNs`/`SetLocalNetNs` are OUT OF SCOPE — Phase 6b/6c territory. Task 1's edit to `RunNetPolicyDaemon` touches ONLY the lines specific to the legacy socket's own bootstrap (`zListenFd`/`unixEvent`/the `socket()`/`bind()`/`listen()`/`epoll_ctl` sequence for it) — read the current function body yourself before editing; do not touch anything else in it.
- Never `git worktree` inside the `net-policy-build-test` Docker container (bind-mounts the same host repo; has wiped the host's worktree registry before in this project's history) — build directly against the bind-mounted worktree path (verify the container's mount source with `docker inspect <container> --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}'` first).
- Verify every code snippet, line number, and `CMakeLists.txt` `SOURCES`/link-library list membership in this plan against the actual current source before editing — line numbers may have drifted since this plan was written.

---

### Task 1: Delete the legacy raw-socket JSON control protocol

**Files:**
- Modify: `net-policy.h` (remove `NetDataType`/`NET_DATA_TYPE`; remove `CtrlServer` class; remove `ctrl_server_` member and `CtrlSrv()` accessor from `DaemonContext`; remove `kNetPolicyAddr`/`kNetPolicyPort` constants if confirmed unused elsewhere)
- Modify: `net-policy.cpp` (remove `ParseRcvData`, `ParseRcvJson`, `ReadData`, `ProcAcceptEvent`, `CtrlServer::Accept`; remove the legacy socket's bootstrap block in `RunNetPolicyDaemon`)
- Modify: `CMakeLists.txt` (no source-file changes expected — this is all inside `net-policy.cpp`/`.h`, already in every target's `SOURCES`; only verify, don't assume)

**Interfaces:** None — this task has no Rust component and produces nothing later tasks depend on.

- [ ] **Step 1: Confirm the exact deletion scope**

```bash
grep -n '\bCtrlServer\b\|\bProcAcceptEvent\b\|\bParseRcvData\b\|\bParseRcvJson\b\|\bReadData\b' net-policy.h net-policy.cpp rule-detail.cpp grpc/control_dispatch.cc
grep -rn '\bNetDataType\b\|\bNET_DATA_TYPE\b' --include='*.h' --include='*.cc' --include='*.cpp' /Users/robbieqiu/workspace/net-policy
grep -n 'kNetPolicyAddr\|kNetPolicyPort' net-policy.h net-policy.cpp
```
Expected: every hit for the first two commands is inside `net-policy.h`/`net-policy.cpp`, and every one is inside the specific functions/class this task deletes (`CtrlServer`'s declaration/definition, `ProcAcceptEvent`, `ParseRcvData`, `ParseRcvJson`, `ReadData`, and the one call site each of `ProcAcceptEvent`/`CtrlServer::Accept` inside `RunNetPolicyDaemon`'s bootstrap and `CtrlServer::Accept` respectively). `kNetPolicyAddr`/`kNetPolicyPort` should only appear in their `net-policy.h` declaration and the one bind-address-construction site inside `RunNetPolicyDaemon`. If any command finds a hit outside what's described, stop and re-scope — don't delete something a real caller depends on.

- [ ] **Step 2: Read the current `RunNetPolicyDaemon` bootstrap block**

Read `net-policy.cpp`'s `RunNetPolicyDaemon` in full (search for `int RunNetPolicyDaemon`). Confirm it still resembles this shape (this plan's text may have drifted from current line numbers, but the logical structure should match):
```cpp
  // create socket
  zListenFd = socket(AF_INET, SOCK_STREAM, 0);
  if (zListenFd <= 0)
    GOTO_ERROR(err, "create unix socket failed! %s.", strerror(errno));
  // noblock
  fcntl(zListenFd, F_SETFL, fcntl(zListenFd, F_GETFL) | O_NONBLOCK);
  // socket address
  ret = setsockopt(zListenFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
  if (ret != 0)
    GOTO_ERROR(err, "set socket opt failed, %s", strerror(errno));
  // 设置服务器地址和端口
  address.sin_family = AF_INET;
  address.sin_port = htons(kNetPolicyPort);
  address.sin_addr.s_addr = inet_addr(kNetPolicyAddr.data());
  // bind socket address
  ret = bind(zListenFd, (struct sockaddr*)&address, sizeof(address));
  if (ret < 0)
    GOTO_ERROR(err, "bind server unix socket failed, %s!", strerror(errno));
  // listen sockfd
  ret = listen(zListenFd, 10);
  if (ret < 0)
    GOTO_ERROR(err, "listen the client connect request! err : %s.", strerror(errno));
  //
  daemon.Microseg().SetEfd(epfd);
```
and, later in the same function:
```cpp
  unixEvent.fd_ = zListenFd;
  unixEvent.epoll_in_func_ = ProcAcceptEvent;
  unixEvent.daemon_ = &daemon;
  // register epoll event
  ev.data.ptr = &unixEvent;
  ev.events = EPOLLIN;
  ret = epoll_ctl(epfd, EPOLL_CTL_ADD, zListenFd, &ev);
  if (ret < 0)
    GOTO_ERROR(err, "epoll ctl failed, %s.", strerror(errno));
```
and the cleanup path:
```cpp
err:
  if (zListenFd > 0)
    close(zListenFd);
  if (epfd > 0)
    close(epfd);
  return -1;
```
Note `daemon.Microseg().SetEfd(epfd)` is NOT part of the legacy socket's own setup (it just happens to be interleaved here) — it stays. Only the `zListenFd`-specific socket/bind/listen block and the `unixEvent`/`ProcAcceptEvent` epoll registration go away. `zListenFd`'s `close()` in the `err:` cleanup path also goes away (the variable itself is being removed), but `epfd`'s close stays.

- [ ] **Step 3: Delete the legacy protocol's code**

In `net-policy.cpp`, delete (in full): `ParseRcvData`, `ParseRcvJson`, `ReadData`, `ProcAcceptEvent`, `CtrlServer::Accept`. In `RunNetPolicyDaemon`, delete the `zListenFd` socket/bind/listen block and the `unixEvent`/`ProcAcceptEvent` epoll-registration block identified in Step 2, and remove `zListenFd` from the function's local variable declarations and the `err:` cleanup path. Remove the `int ParseRcvData(int32_t epoll_fd, int32_t fd, void* ptr);` forward declaration near the top of the file (search for it — it exists solely to let `CtrlServer::Accept`, itself being deleted, reference it before its later definition).

In `net-policy.h`: delete the `enum class NetDataType : int { ... }` block and its `using NET_DATA_TYPE = NetDataType;` alias. Delete the `class CtrlServer { ... };` declaration. In `DaemonContext`'s declaration, remove the `CtrlServer& CtrlSrv() { return ctrl_server_; }` accessor and the `CtrlServer ctrl_server_;` private member. If Step 1 confirmed `kNetPolicyAddr`/`kNetPolicyPort` have no other references, delete those two `inline constexpr` declarations too.

If `NetCtrlInfo::msg_type_` (and its `NetDataType` type) has zero remaining readers after these deletions (re-run the Step 1 grep to confirm), it's fine to leave the field declared in the struct (removing it isn't required — `NetCtrlInfo` itself is shared/out-of-scope per Global Constraints, and a genuinely dead field on an otherwise-live struct is a much smaller concern than the deleted dispatch code was). Do not remove the `NetCtrlInfo` struct itself or any of its other fields.

- [ ] **Step 4: Build and verify**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j$(nproc) net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -100"
```
Expected: clean build, zero new warnings under `-Wall -Werror`.

- [ ] **Step 5: Run existing tests**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && ./net_rule_test && ./net_rule_grpc_test"
```
Expected: all existing tests still pass — no test in either suite exercises the port-9999 path (confirm this is still true by grepping `tests/*.cc` for `9999`/`CtrlServer`/`ParseRcvData` before running, per due diligence, though none are expected).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Delete legacy raw-socket JSON control protocol (port 9999)

Every one of its 11 message types (kPodPid/kPodDie/kAddRule/kDelRule/
kAddWafRule/kDelWafRule/kHeapDump/kConfDump/kConnDump/kReset/kNodeCfg/
kLogLevel) already has a working gRPC dispatch equivalent in
grpc/control_dispatch.h, live-tested by GrpcRustControlEndToEndTest --
this finally realizes Phase 2's original stated intent that gRPC become
the sole control plane. The shared rule-mutation logic underneath
(ParseNetPolicy, ParseNodeCfg, etc.) is untouched; only the legacy
protocol's own dispatch shell (CtrlServer, ProcAcceptEvent, ParseRcvData,
ParseRcvJson, ReadData, NetDataType) is deleted."
```

---

### Task 2: Scaffold the `net_iptables` Rust crate and wire it into CMake

**Files:**
- Create: `crates/net_iptables/Cargo.toml`
- Create: `crates/net_iptables/src/lib.rs`
- Modify: `Cargo.toml` (repo root — add to workspace `members`)
- Modify: `CMakeLists.txt` (add `corrosion_add_cxxbridge` block, link into `net-rule` and `net_rule_grpc_test`)

**Interfaces:**
- Produces: an empty-but-real `#[cxx::bridge]` module (cxxbridge hard-errors on a module with zero bridge items) that Task 3 extends.

- [ ] **Step 1: Create the crate**

`crates/net_iptables/Cargo.toml`:
```toml
[package]
name = "net_iptables"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
cxx = "1"
```

`crates/net_iptables/src/lib.rs`:
```rust
#[cxx::bridge(namespace = "net_iptables")]
mod ffi {
    extern "Rust" {
        fn net_iptables_ffi_smoke() -> i32;
    }
}

fn net_iptables_ffi_smoke() -> i32 {
    42
}
```

- [ ] **Step 2: Add to the Cargo workspace**

Read the repo root `Cargo.toml`'s current `members` list first, then add `"crates/net_iptables"` alongside whatever is already there (`ffi_smoke`, `waf_rules_core`, `net_policy_control`, `net_policy_events`, `net_flow_engine`, `net_policy_engine`).

- [ ] **Step 3: Wire into CMake**

Find the last existing `corrosion_add_cxxbridge` block in `CMakeLists.txt` and add a new block immediately after it, in the same style:
```cmake
corrosion_add_cxxbridge(net_iptables_cxxbridge
  CRATE net_iptables
  FILES lib.rs
)
```
Add `net_iptables_cxxbridge` to `target_link_libraries(net-rule ...)` and `target_link_libraries(net_rule_grpc_test ...)`, alongside the existing cxxbridge crates (this crate's two consumers — `GrpcDispatchPodUp`, in `net-policy.cpp`, and `PolicyRule::ClearCfg`, in `rule-detail.cpp` — are both compiled into `net-rule` and `net_rule_grpc_test`, per Task 4). Update the comment above `set_target_properties(net-rule PROPERTIES LINK_FLAGS "-Wl,--allow-multiple-definition")` (and `net_rule_grpc_test`'s equivalent) that lists the cxxbridge crates needing the flag, to include `net_iptables_cxxbridge`.

- [ ] **Step 4: Build and verify**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j$(nproc) net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -80"
```
Expected: clean build, zero new warnings (excluding known-harmless Cargo jobserver messages).

- [ ] **Step 5: Commit**

```bash
git add crates/net_iptables Cargo.toml CMakeLists.txt
git commit -m "Scaffold net_iptables Rust crate and wire into CMake"
```

---

### Task 3: Port the four iptables functions to Rust

**Files:**
- Modify: `crates/net_iptables/src/lib.rs` (replace the Task 2 smoke stub with the real bridge + implementations)
- Create: `tests/net_iptables_ffi_test.cc` (C++ smoke test proving the FFI surface works, independent of the real C++ call sites — those are cut over in Task 4)
- Modify: `CMakeLists.txt` (add the new test file to `net_rule_grpc_test`'s `SOURCES`)

**Interfaces:**
- Produces: `net_iptables::write_iptable_rule(i32, i32, i32, bool)`, `net_iptables::clear_iptables_rule(i32)`, `net_iptables::check_iptables_rule(i32) -> bool`, `net_iptables::get_iptables_version() -> i32` — the seam Task 4 wires the real C++ call sites up to.

Read the C++ originals (`net-policy.cpp`, search for `WriteIptableRule`/`ClearIptabelsRule`/`CheckIptablesRule`/`GetIptablesVersion`) yourself before porting — line numbers may have drifted from what's quoted below.

The four originals, for reference (verify against the actual current file — this plan's line numbers may be stale):
```cpp
bool CheckIptablesRule(int ipt_ver) {
  const char* icheck = (ipt_ver == 0) ? "iptables -t mangle -S | grep TS_ZERO_PREROUTING"
                                      : "iptables-legacy -t mangle -S | grep TS_ZERO_PREROUTING";
  FILE* fp = popen(icheck, "r");
  if (!fp) return false;
  char buf[1024];
  int length = fread(buf, 1, sizeof(buf), fp);
  pclose(fp);
  if (length < 0) return false;
  if ((length == 0) || (strlen(buf) == 0)) return false;
  return true;
}

void ClearIptabelsRule(int ipt_ver) {
  const char* clear = (ipt_ver == 0) ? "iptables -t mangle -F" : "iptables-legacy -t mangle -F";
  const char* dichan = (ipt_ver == 0) ? "iptables -t mangle -X TS_ZERO_PREROUTING" : "iptables-legacy -t mangle -X TS_ZERO_PREROUTING";
  const char* dochan = (ipt_ver == 0) ? "iptables -t mangle -X TS_ZERO_OUTPUT" : "iptables-legacy -t mangle -X TS_ZERO_OUTPUT";
  system(clear);
  system(dichan);
  system(dochan);
}

void WriteIptableRule(int iMarkNum, int oMarkNum, int ipt_ver, bool waf_enable) {
  // ... builds several command strings per-branch (icreate/imark/ipass/infque, and the
  // output-direction equivalents ocreate/omark/opass/onfque), each conditioned on ipt_ver
  // (iptables vs iptables-legacy) and, for the *mark commands specifically, on waf_enable
  // (simark/somark are only built -- and only run -- when waf_enable is false).
  // If CheckIptablesRule(ipt_ver) is true, calls ClearIptabelsRule(ipt_ver) first.
  // Then: popens pcheck ("iptables -t mangle -S | grep TS_ZERO_PREROUTING"); if that grep
  // finds nothing (ret == 0 || strlen(buf) == 0), runs icreate, imark, a sprintf'd ipass
  // (with iMarkNum substituted into "%d"), infque, and simark (if waf_enable is false).
  // Repeats the identical shape for the output direction (ocheck/ocreate/omark/opass/
  // onfque/somark, oMarkNum).
}

int GetIptablesVersion() {
  FILE* fp = popen("iptables -t nat -S PREROUTING", "r");
  if (!fp) return 0;
  char buf[1024] = {};
  int ret = fread(buf, 1, sizeof(buf), fp);
  pclose(fp);
  if (ret < 0) return 0;
  std::string value = buf;
  if (value.find("-A PREROUTING") != std::string::npos) return 0;
  return 1;
}
```

- [ ] **Step 1: Replace the bridge module and implement the four functions**

```rust
#[cxx::bridge(namespace = "net_iptables")]
mod ffi {
    extern "Rust" {
        fn write_iptable_rule(i_mark: i32, o_mark: i32, ipt_ver: i32, waf_enable: bool);
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

pub fn write_iptable_rule(i_mark: i32, o_mark: i32, ipt_ver: i32, waf_enable: bool) {
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
        if !waf_enable {
            run(bin, &["-t", "mangle", "-A", "INPUT", "-j", "CONNMARK", "--save-mark"]);
        }
    }

    if !mangle_table_contains(bin, "TS_ZERO_OUTPUT") {
        run(bin, &["-t", "mangle", "-N", "TS_ZERO_OUTPUT"]);
        run(bin, &["-t", "mangle", "-I", "OUTPUT", "-j", "TS_ZERO_OUTPUT"]);
        run(bin, &["-t", "mangle", "-I", "OUTPUT", "-j", "CONNMARK", "--restore-mark"]);
        run(bin, &["-t", "mangle", "-A", "TS_ZERO_OUTPUT", "-m", "mark", "--mark",
                    &o_mark.to_string(), "-j", "ACCEPT"]);
        run(bin, &["-t", "mangle", "-A", "TS_ZERO_OUTPUT", "-j", "NFQUEUE",
                    "--queue-num", "1", "--queue-bypass"]);
        if !waf_enable {
            run(bin, &["-t", "mangle", "-A", "POSTROUTING", "-j", "CONNMARK", "--save-mark"]);
        }
    }
}

pub fn get_iptables_version() -> i32 {
    let output = Command::new("iptables").args(["-t", "nat", "-S", "PREROUTING"]).output();
    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains("-A PREROUTING") { 0 } else { 1 }
        }
        Err(_) => 0,
    }
}
```
Note: the C++ original builds each `-N ... 2>/dev/null && -I ...` pair as a single `system()`-invoked shell command string (relying on `&&` shell semantics and `2>/dev/null` to suppress the "chain already exists" error on retry). The Rust port above runs the `-N` (create chain) and `-I` (insert jump rule) as two separate `Command` invocations instead of shelling through `sh -c "... && ..."` — `-N`'s failure (chain already exists) doesn't prevent the `-I` from being attempted either way, since each `run()` call ignores its own exit status (mirroring the original's fire-and-forget `system()` calls, which also don't check `WEXITSTATUS`). This is a behavior-preserving simplification (no shell metacharacter parsing needed, avoids a `sh -c` layer entirely for these two lines) — call this out explicitly in the commit message per this project's established practice for flagging even small deliberate deviations, not folding them in silently.

- [ ] **Step 2: Write unit tests**

These are integration-style tests that invoke real `iptables` inside the build container (no netns isolation needed for these specific commands — `iptables -t mangle -S`/`-N`/`-F`/`-X` operate on the mangle table, which is safe to create/clear temporary chains in in a container test environment; use a uniquely-named test chain, not `TS_ZERO_PREROUTING` itself, to avoid colliding with anything else that might run `write_iptable_rule` in the same container):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

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
    }

    #[test]
    fn check_iptables_rule_false_when_absent() {
        cleanup_test_chains();
        assert!(!check_iptables_rule(0));
        cleanup_test_chains();
    }

    #[test]
    fn write_then_check_then_clear_round_trips() {
        cleanup_test_chains();
        write_iptable_rule(100, 101, 0, /*waf_enable=*/true);
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
}
```
If the build container's `iptables` binary requires privileges the test process doesn't have (verify empirically — this project's `net-policy-build-test` container likely already runs privileged, given it's meant to exercise real NFQ/netlink code elsewhere in this codebase, but confirm rather than assume), note this in your task report rather than silently skipping the tests.

- [ ] **Step 3: Run tests**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/crates/net_iptables && cargo test 2>&1 | tail -60"
```
Expected: all 3 tests pass. If they fail due to a permissions issue rather than a logic issue, report this — don't work around it by weakening the tests' assertions.

- [ ] **Step 4: Write the C++ smoke test**

`tests/net_iptables_ffi_test.cc`:
```cpp
#include <gtest/gtest.h>

#include "net_iptables_cxxbridge/lib.h"

TEST(NetIptablesFfiTest, GetIptablesVersionReturnsZeroOrOne) {
  int v = net_iptables::get_iptables_version();
  EXPECT_TRUE(v == 0 || v == 1);
}

TEST(NetIptablesFfiTest, CheckWriteClearRoundTrip) {
  net_iptables::clear_iptables_rule(0);  // best-effort pre-cleanup
  EXPECT_FALSE(net_iptables::check_iptables_rule(0));
  net_iptables::write_iptable_rule(100, 101, 0, /*waf_enable=*/true);
  EXPECT_TRUE(net_iptables::check_iptables_rule(0));
  net_iptables::clear_iptables_rule(0);
  EXPECT_FALSE(net_iptables::check_iptables_rule(0));
}
```
Add `tests/net_iptables_ffi_test.cc` to `net_rule_grpc_test`'s `SOURCES` list in `CMakeLists.txt`.

- [ ] **Step 5: Build and run**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j$(nproc) net_rule_grpc_test 2>&1 | tail -100"
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && ./net_rule_grpc_test --gtest_filter='NetIptablesFfiTest.*'"
```
Expected: clean build, both smoke tests pass. Run them 3+ times in a row to check for flakiness — these tests mutate real (test-scoped) iptables state, and any interaction with a concurrently-running test process sharing the same container's network namespace is worth catching now rather than in Task 4's cutover.

- [ ] **Step 6: Commit**

```bash
git add crates/net_iptables/src/lib.rs tests/net_iptables_ffi_test.cc CMakeLists.txt
git commit -m "Port iptables rule management to net_iptables

Deliberately simplifies WriteIptableRule's chain-creation commands (-N
then -I) into two separate Command invocations instead of a single
shelled-through '&& '-joined string -- behavior-preserving (the original
system() calls don't check exit status either, so the -N/-I split
changes nothing observable), avoids a sh -c layer. Command::output()
also removes popen's fixed 1024-byte read cap (fread into a stack
buffer), a strict improvement with no practical behavior difference for
the substring checks this code does."
```

---

### Task 4: Cutover — wire the real call sites to `net_iptables`, delete the old C++ functions

**Files:**
- Modify: `net-policy.cpp` (`GrpcDispatchPodUp`'s call to `WriteIptableRule`; `RunNetPolicyDaemon`'s call to `GetIptablesVersion`; delete `WriteIptableRule`, `ClearIptabelsRule`, `CheckIptablesRule`, `GetIptablesVersion`)
- Modify: `net-policy.h` (delete the `extern void ClearIptabelsRule(int ipt_ver);` forward declaration; add `#include "net_iptables_cxxbridge/lib.h"`)
- Modify: `rule-detail.cpp` (`PolicyRule::ClearCfg`'s call to `ClearIptabelsRule`)

**Interfaces:**
- Consumes: `net_iptables::write_iptable_rule`/`clear_iptables_rule`/`check_iptables_rule`/`get_iptables_version` (Task 3).

- [ ] **Step 1: Confirm the call sites**

```bash
grep -n '\bWriteIptableRule\b\|\bClearIptabelsRule\b\|\bCheckIptablesRule\b\|\bGetIptablesVersion\b' net-policy.h net-policy.cpp rule-detail.cpp
```
Expected (per this plan's earlier investigation, re-verify against current source): `WriteIptableRule`'s definition and one call site (`GrpcDispatchPodUp`, in `net-policy.cpp`); `ClearIptabelsRule`'s `extern` declaration (`net-policy.h`), definition (`net-policy.cpp`), and one call site (`PolicyRule::ClearCfg`, in `rule-detail.cpp`); `CheckIptablesRule`'s definition and its one call site inside `WriteIptableRule` itself (both being deleted together); `GetIptablesVersion`'s definition and one call site (`RunNetPolicyDaemon`'s `daemon.SetIptablesVersion(GetIptablesVersion())`, in `net-policy.cpp` — untouched by Task 1, still present). If any call site doesn't match, stop and re-scope.

- [ ] **Step 2: Update `net-policy.h`**

Delete the line `extern void ClearIptabelsRule(int ipt_ver);`. Add `#include "net_iptables_cxxbridge/lib.h"` near the file's other `*_cxxbridge/lib.h` includes (e.g. next to `net_policy_engine_cxxbridge/lib.h`).

- [ ] **Step 3: Update `net-policy.cpp`**

Delete the four function definitions (`CheckIptablesRule`, `ClearIptabelsRule`, `WriteIptableRule`, `GetIptablesVersion`) in full. Update `GrpcDispatchPodUp`'s body:
```cpp
      ret = InitNfqueue(epoll_fd, ctrl, *daemon);
      if (ret == 0)
        WriteIptableRule(1, 1, daemon->IptablesVersion(), daemon->WafEnabled());
```
becomes:
```cpp
      ret = InitNfqueue(epoll_fd, ctrl, *daemon);
      if (ret == 0)
        net_iptables::write_iptable_rule(1, 1, daemon->IptablesVersion(), daemon->WafEnabled());
```
Update `RunNetPolicyDaemon`'s `daemon.SetIptablesVersion(GetIptablesVersion())` line to `daemon.SetIptablesVersion(net_iptables::get_iptables_version())`.

- [ ] **Step 4: Update `rule-detail.cpp`**

Read the current call site (search for `ClearIptabelsRule` inside `rule-detail.cpp` — it should be inside `PolicyRule::ClearCfg`'s per-pod-resource teardown loop, immediately after a `SetNs(res->pid_, ...)` call). Confirm `rule-detail.cpp` already includes (directly or transitively via `net-policy.h`) whatever header declares `net_iptables::clear_iptables_rule` — if not, add `#include "net_iptables_cxxbridge/lib.h"`. Replace:
```cpp
    ClearIptabelsRule(ipt_ver);
```
with:
```cpp
    net_iptables::clear_iptables_rule(ipt_ver);
```

- [ ] **Step 5: Build and run everything**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j$(nproc) net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && ./net_rule_test && ./net_rule_grpc_test"
```
Expected: clean build under `-Wall -Werror` (zero new warnings — the old C++ iptables functions no longer exist anywhere), every test passes, including `NetIptablesFfiTest.*` (Task 3, now exercising what's actually wired into production) and the existing `GrpcRustControlEndToEndTest` suite's pod-lifecycle tests (unaffected in behavior, but the closest thing to an integration-level regression check for `GrpcDispatchPodUp`'s call path). Run `net_rule_grpc_test` at least 3 times to check for flakiness.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Cut over iptables rule management to the Rust crate; delete old C++ implementation"
```

---

## Definition of Done

- `docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j$(nproc)"` builds `net-rule`, `net_rule_test`, and `net_rule_grpc_test` with no new warnings under `-Wall -Werror`.
- `./net_rule_test` and `./net_rule_grpc_test` both pass in full.
- `CtrlServer`, `ProcAcceptEvent`, `ParseRcvData`, `ParseRcvJson`, `ReadData`, `NetDataType`/`NET_DATA_TYPE` no longer exist anywhere in the codebase; the port-9999 socket is no longer bound/listened/epoll-registered.
- `WriteIptableRule`, `ClearIptabelsRule`, `CheckIptablesRule`, `GetIptablesVersion` no longer exist as C++ functions; `GrpcDispatchPodUp`, `PolicyRule::ClearCfg`, and `RunNetPolicyDaemon` call the `net_iptables` Rust crate instead.
- `ParseNetPolicy`, `ParseNodeCfg`, `DeletePolicy` (free function), `AddNewHttpPolicy`, `AddNewPolicy`, `UpdateMark`, `dumpConnectons`, `NetCtrlInfo`, `PostServer`, and everything under `http/`/`waf/` required zero changes.
- `RunNetPolicyDaemon`'s epoll main loop, the Rust gRPC control/event server bootstrap, `NFQ_RES_INFO`, `InitNfqueue`, `OpenNfque`, `OpenConntrack`, and `SetNs`/`OpenLocalNetNs`/`SetLocalNetNs` are all unchanged from before this plan — deferred to Phase 6b/6c.
