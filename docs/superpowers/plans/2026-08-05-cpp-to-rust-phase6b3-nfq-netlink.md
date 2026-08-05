# Phase 6b-3: NFQ Netlink Mechanics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `libnetfilter_queue`'s C API with a new Rust crate (`net_nfq`, wrapping the `nfq` crate) for NFQ queue open/receive/verdict, port netns switching to Rust, and cut `input_nfq_cb`/`output_nfq_cb` over to the new crate — without changing either callback's decision logic.

**Architecture:** New crate `crates/net_nfq/` with two plain-Rust modules (`queue.rs`, `netns.rs`) behind one `#[cxx::bridge(namespace = "net_nfq")]` in `lib.rs`. `NFQ_RES_INFO` (`net-policy.h`) holds two `std::optional<rust::Box<net_nfq::NfqQueue>>` (one per direction) in place of its raw `nfq_q_handle*`/fd fields; its `nfct_*` (conntrack) fields are untouched, Phase 6c's territory. `input_nfq_cb`/`output_nfq_cb` drop their C-library callback signature for one taking the new queue + a per-packet message struct; every `nfq_set_verdict`/`nfq_set_verdict2` call site becomes a `queue.verdict(...)`/`queue.verdict_with_mark(...)` call — mechanical, not a restructuring.

**Tech Stack:** Rust (`nfq = "0.2"`, `nix = { version = "0.31", features = ["sched"] }`, `cxx = "1"`), C++17, `cxx`/Corrosion FFI bridge (existing project convention), Google Test.

## Global Constraints

- `input_nfq_cb`/`output_nfq_cb`'s decision logic (WAF/microseg dispatch, `MatchMicroPolicyRule`/`MatchHttpPolicyRule`, `DispatchWaf`/`DispatchMicroseg`/`MicrosegClose`/`MicrosegTouch`/`MicrosegTrack`) must not change — every task in this plan is a mechanical port of packet-id/payload extraction and verdict issuance, never a change to which verdict is chosen for which input.
- `nfq_get_nfmark(nfa)`'s early-accept fast path (marks already `kAllow`/`kAllowRsp` skip everything else) must be preserved exactly — it depends on a mark set by an *earlier* verdict surviving to be read on a *later* packet.
- `nfq_set_verdict` (no mark argument) and `nfq_set_verdict2` (explicit mark) are NOT the same operation — the 3-arg form leaves the packet's existing nfmark untouched; collapsing both into "always set mark, using 0 for the no-mark case" would forcibly zero marks that survive ACCEPT verdicts today. Preserve this distinction exactly.
- An empty/absent payload override means "kernel keeps the original, unmodified payload" (today's `data_len=0, pkg=NULL` calls) — not a zero-length payload replacement.
- `OpenConntrack`, `UpdateNetSession`, `SetAcceptMark`, and `NFQ_RES_INFO`'s `nfct_*` fields are out of scope — Phase 6c's territory. `InitNfqueue` keeps calling `OpenConntrack` inline, unmodified.
- No new threads, no new locking — this daemon's entire architecture runs one epoll thread (`RunNetPolicyDaemon`'s `while(1)`/`epoll_wait` loop); the new NFQ queues register into the same existing `epoll_ctl(EPOLL_CTL_ADD, ...)` set alongside the reaper timerfd, gRPC dispatch eventfd, and post-notification socket.
- Direct cutover, no shadow-run, no runtime toggle — matching every prior phase (6a/6b-1/6b-2) on this hot path.
- Build with `make -j2` in the `net-policy-build-test` container (NOT higher parallelism — known intermittent linker/archiver corruption under Rust compilation at higher `-j`; `rm -rf build/cargo` and retry at `-j2` if hit). Use a login shell (`bash -lc`) for direct `cargo`/`rustc` invocations.
- `NetNfqFfiTest` (this plan's new privileged test suite) requires `CAP_NET_ADMIN` — run via `docker run/exec --privileged` or `--cap-add=NET_ADMIN`, matching `NetIptablesFfiTest`'s existing convention. Degrade to skip-if-unsupported if the container can't actually complete a live NFQUEUE round-trip.

---

## Verified third-party API surface (do not deviate from these signatures — confirmed against docs.rs/crates.io before writing this plan)

**`nfq = "0.2"` (`nbdd0121/nfq-rs`, MIT/Apache-2.0):**
```rust
// Queue
pub fn Queue::open() -> std::io::Result<Queue>
pub fn Queue::bind(&mut self, queue_num: u16) -> std::io::Result<()>
pub fn Queue::set_copy_range(&mut self, queue_num: u16, range: u16) -> std::io::Result<()>
pub fn Queue::set_nonblocking(&mut self, nonblocking: bool)
pub fn Queue::recv(&mut self) -> std::io::Result<Message>   // ONE message per call
pub fn Queue::verdict(&mut self, msg: Message) -> std::io::Result<()>
impl std::os::fd::AsRawFd for Queue { fn as_raw_fd(&self) -> RawFd }

// Message
pub fn Message::get_packet_id(&self) -> u32
pub fn Message::get_payload(&self) -> &[u8]
pub fn Message::set_payload(&mut self, payload: impl Into<Vec<u8>>)
pub fn Message::get_nfmark(&self) -> u32
pub fn Message::set_nfmark(&mut self, mark: u32)
pub fn Message::set_verdict(&mut self, verdict: Verdict)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict { Drop, Accept, Queue(u16), Repeat, Stop }
```
Verdict issuance requires the original `Message` object back (`Queue::verdict` takes it by value), not just a packet id — `nfq`'s model is "mutate the `Message` you got from `recv()`, hand it back," unlike `libnetfilter_queue`'s id-only `nfq_set_verdict2`. This plan's `NfqQueue` wrapper (Task 3) keeps a `pending: HashMap<u32, nfq::Message>` populated by `recv_batch()` and consumed by `verdict`/`verdict_with_mark`, so the id-based C++-facing API this plan's design spec committed to is preserved without C++ ever needing to hold onto a `Message`.

There is no `bind_pf`/`unbind_pf` equivalent in this crate's API — expected, not a gap: modern `nfnetlink_queue` doesn't require the protocol-family registration dance `libnetfilter_queue`'s `nfq_bind_pf`/`nfq_unbind_pf` performed for older kernels.

**`nix = { version = "0.31", features = ["sched"] }`:**
```rust
pub fn nix::sched::unshare(flags: CloneFlags) -> nix::Result<()>
pub fn nix::sched::setns<Fd: AsFd>(fd: Fd, nstype: CloneFlags) -> nix::Result<()>
// CloneFlags::CLONE_NEWNET is a documented associated constant
```
`std::fs::File` implements `AsFd`, so a `File::open(path)` result can be passed to `setns` directly.

**`cxx = "1"` constraints confirmed against official docs before writing this plan:**
- `Option<T>` is **not** supported as a bridged type for any `T` (confirmed: absent from the main bindings table, listed under "pending bindings," not shipped). This plan's design spec described verdict issuance in terms of `mark: Option<u32>` — that is a semantic description, not literal bridge syntax; **Task 3 below encodes it as two separate bridge functions, `verdict` (no mark) and `verdict_with_mark` (explicit mark)**, which maps even more directly onto the real `nfq_set_verdict`/`nfq_set_verdict2` distinction than a boolean-flag parameter would.
- `rust::Box<T>` has **no default constructor** and cannot be null/empty — confirmed via cxx's own binding docs (move-construct/move-assign only). `NFQ_RES_INFO`'s queue fields therefore use `std::optional<rust::Box<net_nfq::NfqQueue>>`, not a bare `rust::Box<net_nfq::NfqQueue>`, since queue construction is fallible and happens after `NFQ_RES_INFO` itself already exists.
- `rust::Vec<T>` has both `const T* data() const` and `T* data()` (non-const) — confirmed. `msg.payload.data()` gives a mutable `uint8_t*`, which is what `rst_tcp_link`'s in-place payload rewrite needs.
- `Result<T>` (any `T` bridgeable, any Rust error type implementing `Display`) throws a C++ `rust::Error` (a `std::exception` subclass) on `Err`. `Result<Box<T>>` for a fallible constructor (`open_queue`) is a standard, documented cxx idiom.
- `self: &Type`/`self: &mut Type` bridge methods must match a *real inherent method* of that exact name and signature on the type — this plan's bridge methods on `NfqQueue` are therefore written directly against the bridge's own `NfqMessage`/`NfqVerdict` shared types (not translated through a separate cxx-agnostic struct), matching exactly how `net_flow_engine`'s and `net_policy_engine`'s existing bridges are structured in this codebase.

---

### Task 1: Scaffold the `net_nfq` crate and prove it builds/links

**Files:**
- Create: `crates/net_nfq/Cargo.toml`
- Create: `crates/net_nfq/src/lib.rs` (minimal bridge only — no `NfqQueue`/`set_ns` yet)
- Modify: `Cargo.toml:2` (workspace `members` list)
- Modify: `CMakeLists.txt:80-83` (add `corrosion_add_cxxbridge` block), `CMakeLists.txt:236` (net-rule's `target_link_libraries`), `CMakeLists.txt:238-246` (the `--allow-multiple-definition` comment's crate list), `CMakeLists.txt:316` (add test file to `net_rule_grpc_test`'s `SOURCES`), `CMakeLists.txt:342` (`net_rule_grpc_test`'s `target_link_libraries`), `CMakeLists.txt:344-346` (matching comment)
- Create: `tests/net_nfq_ffi_test.cc`

**Interfaces:**
- Produces: `net_nfq::ping() -> i32` (temporary smoke-test-only function, deleted in Task 3 once real functions exist to link-test against instead).

This task's only goal is proving the two new external crate dependencies (`nfq`, `nix`) compile and link inside this project's Cargo/Corrosion/CMake integration, before any real logic is built on top — mirroring this project's established "prove the toolchain before the logic moves" practice (see `crates/ffi_smoke`, added in Phase 0 for the same reason).

- [ ] **Step 1: Create the crate manifest**

`crates/net_nfq/Cargo.toml`:
```toml
[package]
name = "net_nfq"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
cxx = "1"
nfq = "0.2"
nix = { version = "0.31", features = ["sched"] }
```

- [ ] **Step 2: Add the crate to the Cargo workspace**

Edit `Cargo.toml` (repo root):
```toml
[workspace]
resolver = "2"
members = ["crates/ffi_smoke", "crates/waf_rules_core", "crates/net_policy_control", "crates/net_policy_events", "crates/net_flow_engine", "crates/net_policy_engine", "crates/net_iptables", "crates/net_nfq"]
```

- [ ] **Step 3: Write a minimal bridge to prove the build wires up**

`crates/net_nfq/src/lib.rs`:
```rust
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
```

- [ ] **Step 4: Wire the crate into CMakeLists.txt**

After the `net_iptables_cxxbridge` block (`CMakeLists.txt:80-83`), add:
```cmake
corrosion_add_cxxbridge(net_nfq_cxxbridge
  CRATE net_nfq
  FILES lib.rs
)
```

Add `net_nfq_cxxbridge` to `net-rule`'s `target_link_libraries` (`CMakeLists.txt:236`, right after `net_iptables_cxxbridge`), and update the explanatory comment immediately below it (`CMakeLists.txt:238-246`) to include `net_nfq_cxxbridge` in its list of crates needing `--allow-multiple-definition`.

Add `tests/net_nfq_ffi_test.cc` to `net_rule_grpc_test`'s `SOURCES` (`CMakeLists.txt:316`, after `tests/net_iptables_ffi_test.cc`), add `net_nfq_cxxbridge` to `net_rule_grpc_test`'s `target_link_libraries` (`CMakeLists.txt:342`), and update the matching comment (`CMakeLists.txt:344-346`).

- [ ] **Step 5: Write the smoke test**

`tests/net_nfq_ffi_test.cc`:
```cpp
// Placeholder suite for this plan's NFQ netlink port. Real (CAP_NET_ADMIN-
// gated) queue open/recv/verdict tests are added in Task 3.
#include <gtest/gtest.h>

#include "net_nfq_cxxbridge/lib.h"

TEST(NetNfqFfiTest, CrateLinksAndRuns) {
  EXPECT_EQ(net_nfq::ping(), 42);
}
```

- [ ] **Step 6: Build and run**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j2 net_rule_grpc_test 2>&1 | tail -100"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='NetNfqFfiTest.*'"
```
Expected: builds clean, `NetNfqFfiTest.CrateLinksAndRuns` passes.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml CMakeLists.txt crates/net_nfq tests/net_nfq_ffi_test.cc
git commit -m "Scaffold the net_nfq crate and wire it into the build

Proves the nfq and nix crates compile and link inside this project's
Cargo/Corrosion/CMake integration before any real NFQ logic is built on
top, matching the same toolchain-first practice ffi_smoke established
in Phase 0."
```

---

### Task 2: Port netns switching (`SetNs`) to Rust

**Files:**
- Modify: `crates/net_nfq/src/lib.rs` (add `set_ns` to the bridge)
- Create: `crates/net_nfq/src/netns.rs`
- Test: `crates/net_nfq/src/netns.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Produces: `net_nfq::set_ns(pid: i32, base_path: &str) -> Result<()>` — thrown `rust::Error` on failure, consumed by C++ via `try`/`catch`.
- Consumes: nothing from other tasks.

This task is fully self-contained and does not touch `net-policy.cpp`'s call sites yet — that happens in Task 4, alongside the rest of the cutover, since `SetNs`'s three call sites (`GrpcDispatchPodUp`, `NfQueData::ClearNfQueResource`'s teardown path — deleted in Task 5 since it's dead code, and `PolicyRule::ClearCfg`) don't need to move in lockstep with this function's own port.

- [ ] **Step 1: Write the netns module**

`crates/net_nfq/src/netns.rs`:
```rust
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
```

- [ ] **Step 2: Wire it into the bridge**

Edit `crates/net_nfq/src/lib.rs`:
```rust
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
```

- [ ] **Step 3: Run the Rust unit tests**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy && cargo test -p net_nfq 2>&1 | tail -30"
```
Expected: both tests pass.

- [ ] **Step 4: Build the C++ side and confirm nothing broke**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && make -j2 net_rule_grpc_test 2>&1 | tail -60"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='NetNfqFfiTest.*'"
```
Expected: still builds (nothing in C++ calls `net_nfq::set_ns` yet — that's Task 4), `NetNfqFfiTest.CrateLinksAndRuns` still passes.

- [ ] **Step 5: Commit**

```bash
git add crates/net_nfq
git commit -m "Port netns switching to Rust in net_nfq

set_ns mirrors SetNs's open()/unshare(CLONE_NEWNET)/setns() sequence
1:1 using the nix crate. Not yet wired into net-policy.cpp's call
sites -- that happens alongside the rest of the NFQ cutover (Task 4),
since it must land together with input_nfq_cb/output_nfq_cb's
signature change for the build to stay green at every step."
```

---

### Task 3: `NfqQueue` — open, receive, and verdict

**Files:**
- Modify: `crates/net_nfq/src/lib.rs` (add the full bridge)
- Create: `crates/net_nfq/src/queue.rs`
- Modify: `tests/net_nfq_ffi_test.cc` (replace the placeholder smoke test with real open/recv/verdict coverage)

**Interfaces:**
- Produces:
  - `net_nfq::open_queue(queue_num: u16) -> Result<Box<NfqQueue>>`
  - `NfqQueue::fd(&self) -> i32`
  - `NfqQueue::recv_batch(&mut self) -> Result<Vec<NfqMessage>>` where `NfqMessage { id: u32, payload: Vec<u8>, nfmark: u32 }`
  - `NfqQueue::verdict(&mut self, id: u32, v: NfqVerdict, payload: &[u8]) -> Result<()>` where `NfqVerdict { Accept, Drop }` — maps to `nfq_set_verdict` (mark untouched)
  - `NfqQueue::verdict_with_mark(&mut self, id: u32, v: NfqVerdict, mark: u32, payload: &[u8]) -> Result<()>` — maps to `nfq_set_verdict2` (mark explicitly set)
- Consumes: nothing from other tasks (Task 1's `ping` is deleted in this task, its job done).

- [ ] **Step 1: Write the queue module**

`crates/net_nfq/src/queue.rs`:
```rust
use crate::ffi::{NfqMessage, NfqVerdict};
use std::collections::HashMap;
use std::os::fd::AsRawFd;

pub struct NfqQueue {
    inner: nfq::Queue,
    // Verdict issuance in the `nfq` crate requires the original `Message`
    // object, not just its id (unlike libnetfilter_queue's id-only
    // nfq_set_verdict2). recv_batch() stashes each Message here, keyed by
    // its own packet id, so verdict()/verdict_with_mark() can look it back
    // up -- the C++-facing API stays id-based, matching every existing
    // nfq_set_verdict(2) call site's shape.
    pending: HashMap<u32, nfq::Message>,
}

impl NfqQueue {
    pub fn open(queue_num: u16) -> std::io::Result<Self> {
        let mut inner = nfq::Queue::open()?;
        inner.bind(queue_num)?;
        // 0xffff: full packet copies, matching nfq_set_mode(qh,
        // NFQNL_COPY_PACKET, 0xffff) in the C code this replaces.
        inner.set_copy_range(queue_num, 0xffff)?;
        inner.set_nonblocking(true);
        Ok(NfqQueue { inner, pending: HashMap::new() })
    }

    pub fn fd(&self) -> i32 {
        self.inner.as_raw_fd()
    }

    /// Drains every message currently available without blocking --
    /// mirrors nfq_handle_packet's behavior of dispatching every message
    /// found in one read() buffer, since a single epoll wakeup can carry
    /// more than one queued packet.
    pub fn recv_batch(&mut self) -> std::io::Result<Vec<NfqMessage>> {
        let mut out = Vec::new();
        loop {
            match self.inner.recv() {
                Ok(msg) => {
                    let ffi_msg = NfqMessage {
                        id: msg.get_packet_id(),
                        payload: msg.get_payload().to_vec(),
                        nfmark: msg.get_nfmark(),
                    };
                    self.pending.insert(ffi_msg.id, msg);
                    out.push(ffi_msg);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    pub fn verdict(&mut self, id: u32, v: NfqVerdict, payload: &[u8]) -> std::io::Result<()> {
        self.verdict_impl(id, v, None, payload)
    }

    pub fn verdict_with_mark(
        &mut self, id: u32, v: NfqVerdict, mark: u32, payload: &[u8],
    ) -> std::io::Result<()> {
        self.verdict_impl(id, v, Some(mark), payload)
    }

    fn verdict_impl(
        &mut self, id: u32, v: NfqVerdict, mark: Option<u32>, payload: &[u8],
    ) -> std::io::Result<()> {
        let mut msg = self.pending.remove(&id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no pending nfq message with id {id}"),
            )
        })?;
        if let Some(m) = mark {
            msg.set_nfmark(m);
        }
        // Empty slice means "no NFQA_PAYLOAD attribute at all" (kernel keeps
        // the original payload), matching today's data_len=0/pkg=NULL calls
        // -- not a zero-length payload override.
        if !payload.is_empty() {
            msg.set_payload(payload.to_vec());
        }
        msg.set_verdict(match v {
            NfqVerdict::Accept => nfq::Verdict::Accept,
            NfqVerdict::Drop => nfq::Verdict::Drop,
            _ => unreachable!("NfqVerdict has exactly two variants"),
        });
        self.inner.verdict(msg)
    }
}
```

- [ ] **Step 2: Replace the placeholder bridge with the real one**

Edit `crates/net_nfq/src/lib.rs` in full:
```rust
mod netns;
mod queue;

pub use queue::NfqQueue;

#[cxx::bridge(namespace = "net_nfq")]
mod ffi {
    pub struct NfqMessage {
        id: u32,
        payload: Vec<u8>,
        nfmark: u32,
    }

    pub enum NfqVerdict {
        Accept,
        Drop,
    }

    extern "Rust" {
        type NfqQueue;

        fn open_queue(queue_num: u16) -> Result<Box<NfqQueue>>;
        fn fd(self: &NfqQueue) -> i32;
        fn recv_batch(self: &mut NfqQueue) -> Result<Vec<NfqMessage>>;
        fn verdict(self: &mut NfqQueue, id: u32, v: NfqVerdict, payload: &[u8]) -> Result<()>;
        fn verdict_with_mark(
            self: &mut NfqQueue, id: u32, v: NfqVerdict, mark: u32, payload: &[u8],
        ) -> Result<()>;

        fn set_ns(pid: i32, base_path: &str) -> Result<()>;
    }
}

fn open_queue(queue_num: u16) -> Result<Box<NfqQueue>, std::io::Error> {
    Ok(Box::new(NfqQueue::open(queue_num)?))
}

fn set_ns(pid: i32, base_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    netns::set_ns(pid, base_path)
}
```
Note: `fd`/`recv_batch`/`verdict`/`verdict_with_mark` are declared with `self: &NfqQueue`/`self: &mut NfqQueue` in the bridge, which cxx resolves directly against `NfqQueue`'s own inherent methods from `queue.rs` (`pub use queue::NfqQueue;` brings the type into scope) — they need no separate top-level wrapper function, unlike `open_queue`/`set_ns` which construct/dispatch from outside the type.

`ping()` (Task 1) and the `#[cfg(test)]` `CloneFlags` touch in `ping()`'s body are deleted — `queue.rs`/`netns.rs` now exercise both new dependencies for real.

- [ ] **Step 3: Update the smoke test into a real integration test**

Replace `tests/net_nfq_ffi_test.cc` in full:
```cpp
// These tests open a real NFQUEUE (creating a scratch iptables NFQUEUE rule
// in the mangle table, matching net_iptables_ffi_test.cc's pattern), so
// they require CAP_NET_ADMIN -- run this binary via `docker run/exec
// --privileged` (or `--cap-add=NET_ADMIN`), not a plain unprivileged
// container/exec. See CLAUDE.md's Build Commands section.
//
// If the environment lacks the privilege or kernel support to actually
// bind/verdict a live queue, OpenRoundTrip is designed to report that as a
// GTEST_SKIP rather than a failure -- see its body.

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>

#include "net_nfq_cxxbridge/lib.h"

namespace {

// A scratch queue number unlikely to collide with anything else running in
// the test container.
constexpr uint16_t kTestQueueNum = 200;

bool InstallScratchNfqueueRule() {
  // -I (insert), not -A, so this rule is evaluated before any pre-existing
  // ones and reliably catches the test's own loopback ICMP traffic.
  int ret = std::system(
      "iptables -t mangle -I OUTPUT -p icmp -d 127.0.0.1 -j NFQUEUE "
      "--queue-num 200 --queue-bypass");
  return ret == 0;
}

void RemoveScratchNfqueueRule() {
  std::system(
      "iptables -t mangle -D OUTPUT -p icmp -d 127.0.0.1 -j NFQUEUE "
      "--queue-num 200 --queue-bypass");
}

}  // namespace

TEST(NetNfqFfiTest, OpenGivesAPositiveFd) {
  rust::Box<net_nfq::NfqQueue> queue = net_nfq::open_queue(kTestQueueNum);
  EXPECT_GT(queue->fd(), 0);
}

TEST(NetNfqFfiTest, RecvBatchOnAFreshQueueWithNoTrafficReturnsEmpty) {
  rust::Box<net_nfq::NfqQueue> queue = net_nfq::open_queue(kTestQueueNum);
  auto batch = queue->recv_batch();
  EXPECT_EQ(batch.size(), 0u);
}

TEST(NetNfqFfiTest, VerdictOnAnUnknownIdFails) {
  rust::Box<net_nfq::NfqQueue> queue = net_nfq::open_queue(kTestQueueNum);
  EXPECT_THROW(
      queue->verdict(999999, net_nfq::NfqVerdict::Accept, rust::Slice<const uint8_t>()),
      std::exception);
}

TEST(NetNfqFfiTest, OpenRoundTrip) {
  if (!InstallScratchNfqueueRule()) {
    GTEST_SKIP() << "could not install a scratch NFQUEUE rule -- container "
                    "likely lacks CAP_NET_ADMIN or nfnetlink_queue support";
  }
  rust::Box<net_nfq::NfqQueue> queue = net_nfq::open_queue(kTestQueueNum);

  // Trigger the rule: an ICMP echo request to loopback, sent from a
  // separate process so this test process's own send() doesn't race the
  // queue open above.
  std::system("ping -c 1 -W 1 127.0.0.1 > /dev/null 2>&1 &");

  rust::Vec<net_nfq::NfqMessage> batch;
  bool got_one = false;
  for (int i = 0; i < 50 && !got_one; i++) {
    batch = queue->recv_batch();
    if (batch.size() > 0) {
      got_one = true;
      break;
    }
    usleep(20000);  // 20ms
  }
  RemoveScratchNfqueueRule();

  if (!got_one) {
    GTEST_SKIP() << "no packet arrived on the scratch queue within 1s -- "
                    "container networking likely doesn't support a live "
                    "NFQUEUE round-trip";
  }
  ASSERT_GT(batch.size(), 0u);
  EXPECT_NO_THROW(
      queue->verdict(batch[0].id, net_nfq::NfqVerdict::Accept, rust::Slice<const uint8_t>()));
}
```

- [ ] **Step 4: Run the Rust side (no live kernel queue needed for these)**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy && cargo test -p net_nfq 2>&1 | tail -30"
```
Expected: the netns tests from Task 2 still pass; `queue.rs` has no `#[cfg(test)]` module of its own since its logic is exercised via the C++ integration test (opening a real queue isn't meaningfully unit-testable without a kernel).

- [ ] **Step 5: Build and run the C++ suite, in a privileged container**

```bash
docker exec --privileged net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j2 net_rule_grpc_test 2>&1 | tail -150"
docker exec --privileged net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='NetNfqFfiTest.*'"
```
Expected: `OpenGivesAPositiveFd`, `RecvBatchOnAFreshQueueWithNoTrafficReturnsEmpty`, and `VerdictOnAnUnknownIdFails` pass regardless of privilege level (they don't need a live traffic round-trip). `OpenRoundTrip` either passes or reports `GTEST_SKIP` with a clear reason — if it fails outright (not skips), investigate before proceeding: read the failure output, check `iptables -t mangle -S OUTPUT` was actually able to install the rule, and note in this task's report which outcome (pass or documented skip) was observed and why.

Also re-run without `--privileged` to confirm the suite still passes (with `OpenRoundTrip` skipping, and `OpenGivesAPositiveFd`/others either passing or also skipping if `open_queue` itself needs privilege to succeed at all — note in the report which of these tests turned out to need privilege vs. not):
```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='NetNfqFfiTest.*'"
```

- [ ] **Step 6: Commit**

```bash
git add crates/net_nfq tests/net_nfq_ffi_test.cc
git commit -m "Implement NfqQueue: open/fd/recv_batch/verdict on top of the nfq crate

Wraps nbdd0121/nfq-rs behind the same id-based verdict shape
nfq_set_verdict(2) already has, via a pending-message map (the nfq
crate's own verdict() needs the original Message object back, not
just an id). Two verdict-issuing functions, not one with an optional
mark, since cxx does not support Option<T> for a plain scalar --
verdict()/verdict_with_mark() map 1:1 onto nfq_set_verdict's and
nfq_set_verdict2's real distinction (mark left alone vs. explicitly
set), which collapsing into a single always-set-a-mark call would
have broken."
```

---

### Task 4: Cut `NFQ_RES_INFO`, `OpenNfque`, `AddEpollEvent`, `NfqueueRcvData`, `FreeResource`, and both callbacks over to `net_nfq`

**Files:**
- Modify: `net-policy.h` (`NFQ_RES_INFO` fields)
- Modify: `net-policy.cpp` (`OpenNfque`, `AddEpollEvent`, `NfqueueRcvData`, `InitNfqueue`, `input_nfq_cb`, `output_nfq_cb`, `GrpcDispatchPodUp`'s `SetNs` call)
- Modify: `rule-detail.cpp` (`NFQ_RES_INFO::Init`, `NFQ_RES_INFO::FreeResource`)

**Interfaces:**
- Consumes: `net_nfq::open_queue`, `NfqQueue::{fd, recv_batch, verdict, verdict_with_mark}`, `net_nfq::set_ns` (Tasks 2-3).

This is the highest-risk task in this plan — every one of `input_nfq_cb`/`output_nfq_cb`'s ~44 verdict-issuing return points must produce the identical verdict for the identical input before and after this task. It must land as one atomic change: once `OpenNfque` stops calling `nfq_create_queue` (which requires a C-signature callback pointer), `input_nfq_cb`/`output_nfq_cb` can no longer have their old signature, so splitting this into smaller independently-buildable pieces isn't possible without throwaway shim code.

- [ ] **Step 1: Re-confirm the exact current content before editing**

```bash
grep -n "static int input_nfq_cb\|static int output_nfq_cb\|^}" net-policy.cpp | awk -F: '$1>=550 && $1<=1080'
```
Read both functions' full current bodies in full (`net-policy.cpp:552-857` for `input_nfq_cb`, `net-policy.cpp:859-1075` for `output_nfq_cb`). If the content has drifted from what's quoted below, stop and reconcile before proceeding — this plan's quoted "before" state was read directly from `main` at the time this plan was written (commit `543b9ce`, immediately after Phase 6b-2 merged).

- [ ] **Step 2: `NFQ_RES_INFO`'s field change**

In `net-policy.h`, replace:
```cpp
    int input_fd_;
    int output_fd_;
    int poll_fd_;
    struct nfq_q_handle* input_que_  = nullptr;
    struct nfq_q_handle* output_que_ = nullptr;
    RcvEpollCb*          input_cb_   = nullptr;
    RcvEpollCb*          output_cb_  = nullptr;
```
with:
```cpp
    int poll_fd_;
    // Fallible to construct (queue open can fail) and freed explicitly by
    // FreeResource before this object's own destruction, so these cannot be
    // bare rust::Box<T> fields -- Box<T> has no default constructor and
    // cannot be null. std::optional represents "not yet opened"/"already
    // freed"; the Box it wraps, whenever engaged, is always a real queue.
    std::optional<rust::Box<net_nfq::NfqQueue>> input_queue_;
    std::optional<rust::Box<net_nfq::NfqQueue>> output_queue_;
    RcvEpollCb*          input_cb_   = nullptr;
    RcvEpollCb*          output_cb_  = nullptr;
```
Add `#include "net_nfq_cxxbridge/lib.h"` and `#include <optional>` near `net-policy.h`'s other includes (check they aren't already present before adding).

- [ ] **Step 3: `NFQ_RES_INFO::Init`/`FreeResource` (`rule-detail.cpp`)**

Replace:
```cpp
void NFQ_RES_INFO::Init() {
  this->pid_ = 0;
  this->input_fd_ = 0;
  this->output_fd_ = 0;
  this->pod_id_ = 0;
  this->poll_fd_ = 0;
  this->input_que_ = nullptr;
  this->output_que_ = nullptr;
  this->input_cb_ = nullptr;
  this->output_cb_ = nullptr;
  // nf conntrack
  this->nfct_ = nullptr;
  this->nfct_cb_ = nullptr;
  this->nfct_hd_ = nullptr;
  this->nfct_cb_hd_ = nullptr;
}
```
with:
```cpp
void NFQ_RES_INFO::Init() {
  this->pid_ = 0;
  this->pod_id_ = 0;
  this->poll_fd_ = 0;
  // input_queue_/output_queue_ default-construct as disengaged
  // std::optionals; no explicit reset needed here.
  this->input_cb_ = nullptr;
  this->output_cb_ = nullptr;
  // nf conntrack
  this->nfct_ = nullptr;
  this->nfct_cb_ = nullptr;
  this->nfct_hd_ = nullptr;
  this->nfct_cb_hd_ = nullptr;
}
```

Replace:
```cpp
void NFQ_RES_INFO::FreeResource(int efd) {
  struct epoll_event ev;
  struct nfq_q_handle* qh = NULL;

  /*close input fd*/
  if (this->input_fd_ > 0) {
    ev.data.fd = this->input_fd_;
    epoll_ctl(efd, EPOLL_CTL_DEL, this->input_fd_, &ev);
    close(this->input_fd_);
  }
  /*close output fd*/
  if (this->output_fd_ > 0) {
    ev.data.fd = this->output_fd_;
    epoll_ctl(efd, EPOLL_CTL_DEL, this->output_fd_, &ev);
    close(this->output_fd_);
  }
  /*destroy input queue*/
  if (this->input_que_) {
    qh = this->input_que_;
    nfq_close(qh->h);
    nfq_destroy_queue(qh);
  }
  /*destroy output queue*/
  if (this->output_que_) {
    qh = this->output_que_;
    nfq_close(qh->h);
    nfq_destroy_queue(qh);
  }
  if (this->input_cb_)
    delete this->input_cb_;
  if (this->output_cb_)
    delete this->output_cb_;
  if (this->nfct_)
    nfct_destroy(this->nfct_);
  if (this->nfct_cb_)
    nfct_destroy(this->nfct_cb_);
  if (this->nfct_hd_)
    nfct_close(this->nfct_hd_);
  if (this->nfct_cb_hd_)
    nfct_close(this->nfct_cb_hd_);
  /*print debug log*/
  LOG_I("free nfqueue resource, pid : %d", this->pid_);
}
```
with:
```cpp
void NFQ_RES_INFO::FreeResource(int efd) {
  struct epoll_event ev;

  /*unregister + close input queue*/
  if (this->input_queue_) {
    int fd = (*this->input_queue_)->fd();
    ev.data.fd = fd;
    epoll_ctl(efd, EPOLL_CTL_DEL, fd, &ev);
    this->input_queue_.reset();  // drops the Rust NfqQueue, closing its socket
  }
  /*unregister + close output queue*/
  if (this->output_queue_) {
    int fd = (*this->output_queue_)->fd();
    ev.data.fd = fd;
    epoll_ctl(efd, EPOLL_CTL_DEL, fd, &ev);
    this->output_queue_.reset();
  }
  if (this->input_cb_)
    delete this->input_cb_;
  if (this->output_cb_)
    delete this->output_cb_;
  if (this->nfct_)
    nfct_destroy(this->nfct_);
  if (this->nfct_cb_)
    nfct_destroy(this->nfct_cb_);
  if (this->nfct_hd_)
    nfct_close(this->nfct_hd_);
  if (this->nfct_cb_hd_)
    nfct_close(this->nfct_cb_hd_);
  /*print debug log*/
  LOG_I("free nfqueue resource, pid : %d", this->pid_);
}
```

- [ ] **Step 4: `OpenNfque` (`net-policy.cpp`)**

Replace the entire function:
```cpp
int OpenNfque(FLOW_DIR quenum, NFQ_RES_INFO* nfq_res) {
  int ret;
  struct nfq_handle* h = NULL;
  struct nfq_q_handle* qh = NULL;
  /*nfq open*/
  h = nfq_open();
  if (!h)
    RETURN_ERROR(-1, "nfq_open failed.");

  ret = nfq_unbind_pf(h, AF_INET);
  if (ret < 0)
    GOTO_ERROR(err, "nfq unbind pf failed.");

  ret = nfq_bind_pf(h, AF_INET);
  if (ret < 0)
    GOTO_ERROR(err, "fq bind pf failed.");

  if (quenum == FlowDir::kIngress) {
    qh = nfq_create_queue(h, static_cast<uint16_t>(quenum), &input_nfq_cb, (void*)nfq_res);
  } else {
    qh = nfq_create_queue(h, static_cast<uint16_t>(quenum), &output_nfq_cb, (void*)nfq_res);
  }
  if (!qh)
    GOTO_ERROR(err, "nfq create queue failed");

  ret = nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
  if (ret < 0)
    GOTO_ERROR(err, "nfq set mode failed.");

  /*save nfqueue handle*/
  if (quenum == FlowDir::kIngress) {
    nfq_res->input_fd_  = nfq_fd(h);
    nfq_res->input_que_ = qh;
  } else {
    nfq_res->output_fd_  = nfq_fd(h);
    nfq_res->output_que_ = qh;
  }
  /*return*/
  return 0;

err:
  if (h)
    nfq_close(h);
  if (qh)
    nfq_destroy_queue(qh);
  /*return*/
  return -1;
}
```
with:
```cpp
int OpenNfque(FLOW_DIR quenum, NFQ_RES_INFO* nfq_res) {
  try {
    rust::Box<net_nfq::NfqQueue> queue = net_nfq::open_queue(static_cast<uint16_t>(quenum));
    if (quenum == FlowDir::kIngress) {
      nfq_res->input_queue_.emplace(std::move(queue));
    } else {
      nfq_res->output_queue_.emplace(std::move(queue));
    }
    return 0;
  } catch (const std::exception& e) {
    RETURN_ERROR(-1, "net_nfq::open_queue failed, dir : %d, err : %s.",
                 static_cast<int>(quenum), e.what());
  }
}
```

- [ ] **Step 5: `AddEpollEvent` (`net-policy.cpp`)**

Replace:
```cpp
int AddEpollEvent(int zEvfd, NFQ_RES_INFO* nfq_res) {
  int ret;
  struct epoll_event ev;
  RCV_EPOLL_CB *nfqInput = nullptr, *nfqOutput = nullptr;

  nfqInput = new RCV_EPOLL_CB;
  nfqOutput = new RCV_EPOLL_CB;
  if (!nfqInput || !nfqOutput)
    GOTO_ERROR(err, "new nfqueue resource info memory failed, %s.", strerror(errno));
  /*copy data*/
  nfqInput->nfq_res_ = nfq_res;
  nfqOutput->nfq_res_ = nfq_res;
  /*set nonblock*/
  fcntl(nfq_res->input_fd_, F_SETFL, fcntl(nfq_res->input_fd_, F_GETFL) | O_NONBLOCK);
  fcntl(nfq_res->output_fd_, F_SETFL, fcntl(nfq_res->output_fd_, F_GETFL) | O_NONBLOCK);
  /*input queue event*/
  nfqInput->fd_ = nfq_res->input_fd_;
  nfqInput->epoll_in_func_ = NfqueueRcvData;
  // register epoll event
  ev.data.ptr = nfqInput;
  ev.events = EPOLLIN;
  ret = epoll_ctl(zEvfd, EPOLL_CTL_ADD, nfq_res->input_fd_, &ev);
  if (ret < 0)
    GOTO_ERROR(err, "add nfqueue handle to epoll failed, pid : %d, %s.", nfq_res->input_fd_,
               strerror(errno));
  /*output queue event*/
  nfqOutput->fd_ = nfq_res->output_fd_;
  nfqOutput->epoll_in_func_ = NfqueueRcvData;
  // register epoll event
  ev.data.ptr = nfqOutput;
  ev.events = EPOLLIN;
  ret = epoll_ctl(zEvfd, EPOLL_CTL_ADD, nfq_res->output_fd_, &ev);
  if (ret < 0)
    GOTO_ERROR(err, "add nfqueue handle to epoll failed, pid : %d, %s.", nfq_res->output_fd_,
               strerror(errno));
  /*print debug log*/
  LOG_I("pid : %d, inputfd : %d, outputfd : %d.", nfq_res->pid_, nfq_res->input_fd_, nfq_res->output_fd_);
  nfq_res->input_cb_  = nfqInput;
  nfq_res->output_cb_ = nfqOutput;
  /*return*/
  return 0;

err:
  if (nfqInput)
    delete nfqInput;
  if (nfqOutput)
    delete nfqOutput;
  return 9;
}
```
with:
```cpp
int AddEpollEvent(int zEvfd, NFQ_RES_INFO* nfq_res) {
  int ret;
  struct epoll_event ev;
  RCV_EPOLL_CB *nfqInput = nullptr, *nfqOutput = nullptr;
  int input_fd = (*nfq_res->input_queue_)->fd();
  int output_fd = (*nfq_res->output_queue_)->fd();

  nfqInput = new RCV_EPOLL_CB;
  nfqOutput = new RCV_EPOLL_CB;
  if (!nfqInput || !nfqOutput)
    GOTO_ERROR(err, "new nfqueue resource info memory failed, %s.", strerror(errno));
  /*copy data*/
  nfqInput->nfq_res_ = nfq_res;
  nfqOutput->nfq_res_ = nfq_res;
  // Nonblocking mode is set inside net_nfq::open_queue itself now (via
  // Queue::set_nonblocking) -- no separate fcntl() call needed here.
  /*input queue event*/
  nfqInput->fd_ = input_fd;
  nfqInput->epoll_in_func_ = NfqueueRcvData;
  // register epoll event
  ev.data.ptr = nfqInput;
  ev.events = EPOLLIN;
  ret = epoll_ctl(zEvfd, EPOLL_CTL_ADD, input_fd, &ev);
  if (ret < 0)
    GOTO_ERROR(err, "add nfqueue handle to epoll failed, pid : %d, %s.", input_fd,
               strerror(errno));
  /*output queue event*/
  nfqOutput->fd_ = output_fd;
  nfqOutput->epoll_in_func_ = NfqueueRcvData;
  // register epoll event
  ev.data.ptr = nfqOutput;
  ev.events = EPOLLIN;
  ret = epoll_ctl(zEvfd, EPOLL_CTL_ADD, output_fd, &ev);
  if (ret < 0)
    GOTO_ERROR(err, "add nfqueue handle to epoll failed, pid : %d, %s.", output_fd,
               strerror(errno));
  /*print debug log*/
  LOG_I("pid : %d, inputfd : %d, outputfd : %d.", nfq_res->pid_, input_fd, output_fd);
  nfq_res->input_cb_  = nfqInput;
  nfq_res->output_cb_ = nfqOutput;
  /*return*/
  return 0;

err:
  if (nfqInput)
    delete nfqInput;
  if (nfqOutput)
    delete nfqOutput;
  return 9;
}
```

- [ ] **Step 6: `NfqueueRcvData` (`net-policy.cpp`)**

Replace:
```cpp
int NfqueueRcvData(int32_t epoll_fd, int32_t fd, void* ptr) {
  int ret;
  char buf[65536];
  NFQ_RES_INFO* nfq_res = NULL;
  struct nfq_q_handle* qh;
  RCV_EPOLL_CB* nfqEvent = (RCV_EPOLL_CB*)ptr;
  if (!ptr)
    RETURN_ERROR(0, "the argument pointer is nil.");
  nfq_res = nfqEvent->nfq_res_;
  /*read data*/
  ret = read(fd, buf, sizeof(buf));
  if (ret <= 0) {
    if ((errno == 0) || (errno == EAGAIN) || (errno == EINTR))
      RETURN_WARN(0, "read data failed, fd : %d, %s.", fd, strerror(errno));
    close(fd);
    RETURN_ERROR(0, "read nfqueue data failed, ret : %d, fd : %d, pid : %d, %s.", ret, fd,
                 nfq_res->pid_, strerror(errno));
  }
  /*check buffer*/
  // if(ret == (int)sizeof(buf)) RETURN_ERROR(0, "read nfqueue data is overflow.");
  /*get nfq handle*/
  qh = nfq_res->input_que_;
  if (fd != nfq_res->input_fd_)
    qh = nfq_res->output_que_;
  /*parse nfqueue data*/
  nfq_handle_packet(qh->h, buf, ret);
  /*return*/
  return 0;
}
```
with:
```cpp
int NfqueueRcvData(int32_t epoll_fd, int32_t fd, void* ptr) {
  (void)epoll_fd;
  RCV_EPOLL_CB* nfqEvent = (RCV_EPOLL_CB*)ptr;
  if (!ptr)
    RETURN_ERROR(0, "the argument pointer is nil.");
  NFQ_RES_INFO* nfq_res = nfqEvent->nfq_res_;
  bool is_input = (fd == (*nfq_res->input_queue_)->fd());
  net_nfq::NfqQueue& queue = is_input ? **nfq_res->input_queue_ : **nfq_res->output_queue_;

  rust::Vec<net_nfq::NfqMessage> batch;
  try {
    batch = queue.recv_batch();
  } catch (const std::exception& e) {
    RETURN_ERROR(0, "nfq recv_batch failed, fd : %d, pid : %d, %s.", fd, nfq_res->pid_, e.what());
  }
  for (auto& msg : batch) {
    // input_nfq_cb/output_nfq_cb return void and let a verdict-issuing
    // call's exception propagate rather than catching at each of their ~22
    // call sites individually -- caught here, once per message, matching
    // this project's existing single-catch-around-dispatched-work pattern
    // (see DispatchGrpcRustQueueEvent's identical shape around item->work()).
    try {
      if (is_input)
        input_nfq_cb(nfq_res, queue, msg);
      else
        output_nfq_cb(nfq_res, queue, msg);
    } catch (const std::exception& e) {
      LOG_E("nfq callback threw, fd : %d, pid : %d, %s.", fd, nfq_res->pid_, e.what());
    }
  }
  return 0;
}
```
(`recv_batch` treats `WouldBlock`/`EAGAIN` as normal loop termination internally — see Task 3 — so unlike the old code there is no separate "no data yet" warning branch to reproduce here; an empty `batch` on a spurious wakeup is a normal, silent no-op.)

- [ ] **Step 7: `input_nfq_cb` — new signature and body**

Replace the function's signature and its top extraction block:
```cpp
static int input_nfq_cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa,
                        void* argv) {
  int id = 0;
  uint32_t mark;
  FLOW_DIR dir = FlowDir::kIngress;
  std::string rule_key;
  FiveTuple tuple;
  NET_POLICY_RULE rule_ret;
  struct nfqnl_msg_packet_hdr* ph;
  unsigned char* pkg;
  NFQ_RES_INFO* nfq_res = (NFQ_RES_INFO*)argv;
  DaemonContext* daemon = nfq_res->daemon_;

  ph = nfq_get_msg_packet_hdr(nfa);
  if (!ph)
    return 0;

  id = ntohl(ph->packet_id);
  // printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);

  mark = nfq_get_nfmark(nfa);
  if ((mark == static_cast<uint32_t>(NetPolicyRule::kAllow)) ||
      (mark == static_cast<uint32_t>(NetPolicyRule::kAllowRsp)))
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

  auto data_len = nfq_get_payload(nfa, &pkg);
  if (data_len < 0)
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

  // printf("payload_len=%d ", ret);
  if (data_len < (int)sizeof(struct iphdr))
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
```
with:
```cpp
static void input_nfq_cb(NFQ_RES_INFO* nfq_res, net_nfq::NfqQueue& queue, net_nfq::NfqMessage& msg) {
  uint32_t id = msg.id;
  unsigned char* pkg = msg.payload.data();
  int data_len = static_cast<int>(msg.payload.size());
  uint32_t mark = msg.nfmark;
  FLOW_DIR dir = FlowDir::kIngress;
  std::string rule_key;
  FiveTuple tuple;
  NET_POLICY_RULE rule_ret;
  DaemonContext* daemon = nfq_res->daemon_;

  if ((mark == static_cast<uint32_t>(NetPolicyRule::kAllow)) ||
      (mark == static_cast<uint32_t>(NetPolicyRule::kAllowRsp))) {
    queue.verdict(id, net_nfq::NfqVerdict::Accept, {});
    return;
  }

  if (data_len < (int)sizeof(struct iphdr)) {
    queue.verdict(id, net_nfq::NfqVerdict::Accept, {});
    return;
  }
```
Note 1: `nfq_get_msg_packet_hdr`/`nfq_get_payload` returning failure has no equivalent here — `msg` was already successfully constructed by `recv_batch()` (Task 3), so `id`/`payload` are always valid by construction; the `data_len < 0` check is dropped as unreachable (payload is a `Vec<u8>`, its `.size()` can't be negative).

Note 2: the function's return type changes from `int` to `void`. `queue.verdict`/`verdict_with_mark` are declared in the bridge as `-> Result<()>` (Task 3), which cxx maps to a C++ `void`-returning method that throws on failure -- `return queue.verdict(...)` (returning a `void` expression from a function declared to return `int`) does not compile, so every verdict call becomes two statements (`queue.verdict(...); return;`) instead of one `return queue.verdict(...);`. Exceptions are not caught inside this function at all -- they propagate to `NfqueueRcvData`'s single per-message `try`/`catch` (Step 6), matching this project's existing single-catch-around-dispatched-work pattern rather than wrapping each of this function's ~22 verdict call sites individually.

Then, for the rest of the function, translate every verdict call mechanically per this table (every other line is untouched):

| Old | New |
|---|---|
| `return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);` | `queue.verdict(id, net_nfq::NfqVerdict::Accept, {});`<br>`return;` |
| `return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);` | `queue.verdict(id, net_nfq::NfqVerdict::Drop, {});`<br>`return;` |
| `return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(X), 0, NULL);` | `queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept, static_cast<uint32_t>(X), {});`<br>`return;` |
| `return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(X), data_len, pkg);` | `queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept, static_cast<uint32_t>(X), {pkg, static_cast<size_t>(data_len)});`<br>`return;` |

Applying this table to every remaining return point, `input_nfq_cb`'s body from the `receive()` call onward becomes:
```cpp
  auto result = daemon->ConnMgr().receive(reinterpret_cast<const uint8_t*>(pkg), data_len,
                                          /*track_tcp=*/true);
  if (!result.tuple.recognized) {
    queue.verdict(id, net_nfq::NfqVerdict::Accept, {});
    return;
  }
  tuple.proto_        = result.tuple.proto;
  tuple.tot_len_      = result.tuple.tot_len;
  tuple.src_port_     = result.tuple.src_port;
  tuple.dst_port_     = result.tuple.dst_port;
  tuple.src_addr_u32_ = result.tuple.src_addr;
  tuple.dst_addr_u32_ = result.tuple.dst_addr;
  tuple.src_addr_     = net::ipv4ToString(result.tuple.src_addr);
  tuple.dst_addr_     = net::ipv4ToString(result.tuple.dst_addr);

  if (daemon->WafEnabled() && result.is_tcp) {
    auto status = daemon->ConnMgr().DispatchWaf(result.decision,
                                                reinterpret_cast<const uint8_t*>(pkg), data_len);
    if (status == net::NetStatus::Drop) {
      queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                               static_cast<uint32_t>(NetPolicyRule::kAllowReq),
                               {pkg, static_cast<size_t>(data_len)});
      return;
    }
  }

  if ((tuple.proto_ == IPPROTO_UDP) || (tuple.proto_ == IPPROTO_ICMP)) {
    rule_ret = MatchMicroPolicyRule(tuple, dir, rule_key, *daemon);
    if (rule_ret == NetPolicyRule::kDefault) {
      queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                               static_cast<uint32_t>(NetPolicyRule::kAllow), {});
      return;
    }
    daemon->PostSrv().SendMatchMsg(tuple, rule_ret, dir, rule_key);
    if (rule_ret == NetPolicyRule::kDeny) {
      LOG_D("input drop %s %s:%u -> %s:%u ", GetProtoString(tuple.proto_), tuple.src_addr_.c_str(),
            tuple.src_port_, tuple.dst_addr_.c_str(), tuple.dst_port_);
      queue.verdict(id, net_nfq::NfqVerdict::Drop, {});
      return;
    }
    queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                             static_cast<uint32_t>(NetPolicyRule::kAllow), {});
    return;
  }
  if (tuple.proto_ != IPPROTO_TCP) {
    queue.verdict(id, net_nfq::NfqVerdict::Accept, {});
    return;
  }

  const auto& decision = result.decision;
  const bool tracked   = daemon->ConnMgr().MicrosegTracked(decision);
  daemon->ConnMgr().MicrosegTouch(decision);
  const bool has_payload = ((decision.kind == 3) || (decision.kind == 4) || (decision.kind == 5)) &&
                           (data_len > static_cast<int>(decision.payload_offset));
  const bool syn = decision.syn;

  if (decision.kind == 0) {
    queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                             static_cast<uint32_t>(NetPolicyRule::kAllowReq), {});
    return;
  }

  daemon->ConnMgr().MicrosegClose(decision, reinterpret_cast<const uint8_t*>(pkg), data_len);

  if (tracked) {
    if (decision.kind == 2) {
      LOG_D("microseg-dp input data, delete conntrack info, src: %s:%d, dest : %s:%d",
            tuple.src_addr_.c_str(), tuple.src_port_, tuple.dst_addr_.c_str(), tuple.dst_port_);
      queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                               static_cast<uint32_t>(NetPolicyRule::kAllow), {});
      return;
    }
    if (!has_payload) {
      queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                               static_cast<uint32_t>(NetPolicyRule::kAllowReq), {});
      return;
    }
    if (syn) {
      queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                               static_cast<uint32_t>(NetPolicyRule::kAllowReq), {});
      return;
    }
    if (decision.kind == 4) {
      LOG_D("input - duplicated tcp segment");
      queue.verdict(id, net_nfq::NfqVerdict::Accept, {});
      return;
    }
    rule_key = daemon->ConnMgr().MicrosegRuleKey(decision).value_or(std::string());
  } else {
    if (!syn && !has_payload) {
      queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                               static_cast<uint32_t>(NetPolicyRule::kAllowReq), {});
      return;
    }
    rule_ret = MatchMicroPolicyRule(tuple, dir, rule_key, *daemon);
    if (rule_ret == NetPolicyRule::kDefault) {
      queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                               static_cast<uint32_t>(NetPolicyRule::kAllow), {});
      return;
    }
    auto http_rule = daemon->Microseg().InputHttpPolicy().find(rule_key);
    if ((http_rule == daemon->Microseg().InputHttpPolicy().end()) || (http_rule->second.empty())) {
      daemon->PostSrv().SendMatchMsg(tuple, rule_ret, dir, rule_key);
      if (rule_ret == NetPolicyRule::kDeny) {
        LOG_D("input drop %s %s:%u -> %s:%u ", GetProtoString(tuple.proto_), tuple.src_addr_.c_str(),
              tuple.src_port_, tuple.dst_addr_.c_str(), tuple.dst_port_);
        queue.verdict(id, net_nfq::NfqVerdict::Drop, {});
        return;
      }
      queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                               static_cast<uint32_t>(NetPolicyRule::kAllow), {});
      return;
    }
    if (syn) {
      LOG_D("microseg-dp  input sync, src: %s, dest : %s, data len : %d", tuple.src_addr_.c_str(),
            tuple.dst_addr_.c_str(), data_len);
      daemon->ConnMgr().MicrosegTrack(decision, rule_key);
      queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                               static_cast<uint32_t>(NetPolicyRule::kAllowReq), {});
      return;
    }
    daemon->ConnMgr().MicrosegTrack(decision, rule_key);
  }

  LOG_D("microseg-dp  input data, src: %s, dest : %s, data len : %d", tuple.src_addr_.c_str(),
        tuple.dst_addr_.c_str(), data_len);
  auto header = daemon->ConnMgr().DispatchMicroseg(decision, reinterpret_cast<const uint8_t*>(pkg),
                                                   data_len, rule_key);
  LOG_D("input method : %s, path : %s, host : %s, state : %d",
        header ? header->method_.c_str() : "", header ? header->path_.c_str() : "",
        header ? header->host_.c_str() : "", header ? static_cast<int>(header->parseState_) : -1);
  if (!header) {
    queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                             static_cast<uint32_t>(NetPolicyRule::kAllowReq), {});
    return;
  }
  auto http_rule = daemon->Microseg().InputHttpPolicy().find(rule_key);
  if (http_rule == daemon->Microseg().InputHttpPolicy().end()) {
    queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                             static_cast<uint32_t>(NetPolicyRule::kDefault), {});
    return;
  }
  rule_ret = MatchHttpPolicyRule(http_rule->second, *header);
  LOG_D("match input http rule : %d, key : %s", static_cast<int>(rule_ret), rule_key.c_str());
  if (rule_ret == NetPolicyRule::kDefault) {
    queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                             static_cast<uint32_t>(NetPolicyRule::kAllowReq), {});
    return;
  }
  daemon->PostSrv().SendMatchMsg(tuple, rule_ret, FlowDir::kIngress, rule_key);
  if (rule_ret == NetPolicyRule::kDeny)
    rst_tcp_link(pkg);
  queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                           static_cast<uint32_t>(NetPolicyRule::kAllowReq),
                           {pkg, static_cast<size_t>(data_len)});
}
```
All comments explaining *why* each branch does what it does (the `decision.kind`/`tracked`/`syn`/`has_payload` rationale) are preserved verbatim from the current source — only the signature, the top extraction block, and the verdict-issuing calls themselves changed. `mark` (the local variable read from `msg.nfmark`) is unused past the fast-path check, matching today's code exactly (the old `mark` local is likewise only read once).

Update the forward declaration/prototype of `input_nfq_cb` (if any exists above `OpenNfque`, which calls it indirectly via `net_nfq::open_queue`'s caller — check with `grep -n "input_nfq_cb\|output_nfq_cb" net-policy.cpp` for any prototype line separate from the definition) to match the new `void(NFQ_RES_INFO*, net_nfq::NfqQueue&, net_nfq::NfqMessage&)` signature.

- [ ] **Step 8: `output_nfq_cb` — the identical transformation**

Apply the exact same signature change (including the `int`→`void` return-type change and the "every verdict call becomes two statements, no per-call try/catch" rule from Step 7's Note 2) and verdict-call table to `output_nfq_cb`, preserving its existing direction-specific differences unchanged: `kAllowRsp`/`kAllowReq` swapped from `input_nfq_cb` (the fast-path mark check tests `kAllow`/`kAllowReq`, not `kAllow`/`kAllowRsp`), `OutputHttpPolicy()` in place of `InputHttpPolicy()`, `FlowDir::kEgress`, `"output"` in log strings, and the `rule_key`-in-log detail on its own SYN branch (`"microseg-dp output sync, rule key : %s, ..."`, which `input_nfq_cb`'s SYN branch log does not have). Signature:
```cpp
static void output_nfq_cb(NFQ_RES_INFO* nfq_res, net_nfq::NfqQueue& queue, net_nfq::NfqMessage& msg) {
```
Otherwise mechanically identical to Step 7's transformation, applied to `output_nfq_cb`'s current body (`net-policy.cpp:859-1075`, quoted in full in this task's Step 1).

- [ ] **Step 9: Update `SetNs` call sites**

In `GrpcDispatchPodUp` (`net-policy.cpp`), replace:
```cpp
    int ret = SetNs(ctrl.pid_, const_cast<char*>(kBasePath.data()));
```
with:
```cpp
    int ret = 0;
    try {
      // kBasePath is a std::string_view (net-policy.h:34); rust::Str has no
      // std::string_view constructor, only Str(const std::string&) and
      // Str(const char*, size_t) -- use the latter directly rather than
      // copying into a std::string first.
      net_nfq::set_ns(ctrl.pid_, rust::Str(kBasePath.data(), kBasePath.size()));
    } catch (const std::exception& e) {
      LOG_E("net_nfq::set_ns failed, pid : %d, err : %s.", ctrl.pid_, e.what());
      ret = -1;
    }
```
(`kBasePath`'s type was confirmed directly against `net-policy.h:34` while writing this plan — `inline constexpr std::string_view kBasePath = "/host";`.)

`PolicyRule::ClearCfg()`'s call path (`NfQueData::ClearNfQueResource`, `rule-detail.cpp:336-354`) is left untouched by this step — it is deleted outright in Task 5, since it has zero real callers.

- [ ] **Step 10: Delete now-fully-unused C netlink includes/usages if any remain**

```bash
grep -n "nfq_open\|nfq_bind_pf\|nfq_unbind_pf\|nfq_create_queue\|nfq_set_mode\|nfq_handle_packet\|nfq_get_msg_packet_hdr\|nfq_get_payload\|nfq_get_nfmark\|nfq_set_verdict\|nfq_close\|nfq_destroy_queue\|nfq_fd\b" net-policy.cpp net-policy.h rule-detail.cpp
```
Expected: zero remaining matches (`OpenConntrack`'s `nfct_*` calls are a different API family and are untouched — confirm any surviving `nfq_`-prefixed matches genuinely belong to conntrack, not NFQ, before concluding). If any real NFQ-API call sites remain, they were missed in Steps 4-9 — go back and convert them.

- [ ] **Step 11: Build and run, three times**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j2 net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_test && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*'"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*'"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*'"
```
Expected: clean build, all three runs green with identical pass counts (checking for flakiness, matching this project's practice on this exact hot path in every prior phase).

- [ ] **Step 12: Independently re-derive the before/after trace**

Before considering this task done: re-read the CURRENT (pre-this-task) `input_nfq_cb`/`output_nfq_cb` bodies one more time from `git show HEAD~1:net-policy.cpp` (the commit before this task's), and for each distinct return point, confirm the rewritten version (this task's actual diff, not just this plan's draft above) produces the identical verdict for the identical input scenario. Write this trace down in the task's report even though this plan's own draft above already attempted it — an independent re-derivation against the ACTUAL committed diff is the real verification, matching Phase 6b-2's practice on this same function pair.

- [ ] **Step 13: Commit**

```bash
git add net-policy.h net-policy.cpp rule-detail.cpp
git commit -m "Cut NFQ_RES_INFO, OpenNfque/AddEpollEvent/NfqueueRcvData/FreeResource,
and input_nfq_cb/output_nfq_cb over to net_nfq

Replaces libnetfilter_queue's C API (nfq_open/bind/create_queue/
set_mode/handle_packet/get_msg_packet_hdr/get_payload/get_nfmark/
set_verdict(2)/close/destroy_queue) with the net_nfq crate. Every one
of the ~44 verdict call sites in input_nfq_cb/output_nfq_cb is a
mechanical 1:1 swap -- the decision logic between them, and every
comment explaining it, is unchanged. NFQ_RES_INFO's conntrack fields
(nfct_*) and InitNfqueue's call into OpenConntrack are untouched,
Phase 6c's territory. SetNs's callers now go through net_nfq::set_ns.

[Document here: confirmation that the before/after verdict trace was
independently re-derived against this commit's actual diff, per this
task's Step 12 instruction.]"
```

---

### Task 5: Delete confirmed-dead netns-return and `ClearNfQueResource` code

**Files:**
- Modify: `net-policy.h` (`DaemonContext::LocalNetNsFd()`/`SetLocalNetNsFd()`, `local_net_ns_fd_`, `NfQueData::ClearNfQueResource` declaration)
- Modify: `net-policy.cpp` (`OpenLocalNetNs`, `SetLocalNetNs`, the `daemon.SetLocalNetNsFd(OpenLocalNetNs())` call in `RunNetPolicyDaemon`)
- Modify: `rule-detail.cpp` (`NfQueData::ClearNfQueResource` definition)

**Interfaces:** None — pure deletion of unreferenced code.

- [ ] **Step 1: Confirm zero callers, fresh**

```bash
grep -rn "OpenLocalNetNs\|SetLocalNetNs\|LocalNetNsFd\|local_net_ns_fd_\|ClearNfQueResource" --include="*.cpp" --include="*.h" --include="*.cc" .
```
Expected: only the definitions/declarations themselves (matching Phase 6b-1's review, which first flagged both as zero-caller and scoped their disposal to this phase). If anything new references them, STOP — do not delete; report what changed instead.

- [ ] **Step 2: Delete from `net-policy.h`**

Remove `int LocalNetNsFd() const { return local_net_ns_fd_; }`, `void SetLocalNetNsFd(int fd) { local_net_ns_fd_ = fd; }`, and the `local_net_ns_fd_` member from `DaemonContext`. Remove `NfQueData::ClearNfQueResource`'s declaration (`void ClearNfQueResource(int efd, int ipt_ver);`) from the `NfQueData` class.

- [ ] **Step 3: Delete from `net-policy.cpp`**

Remove `OpenLocalNetNs()` and `SetLocalNetNs(int fd)` in full. Remove the `daemon.SetLocalNetNsFd(OpenLocalNetNs());` call in `RunNetPolicyDaemon` (`net-policy.cpp:2158`).

- [ ] **Step 4: Delete from `rule-detail.cpp`**

Remove `NfQueData::ClearNfQueResource`'s definition (`rule-detail.cpp:336-354`) in full.

- [ ] **Step 5: Build and run**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && make -j2 net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -100"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_test && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*'"
```
Expected: clean build (confirms nothing else depended on the deleted symbols), same pass counts as Task 4's final run.

- [ ] **Step 6: Commit**

```bash
git add net-policy.h net-policy.cpp rule-detail.cpp
git commit -m "Delete confirmed-dead OpenLocalNetNs/SetLocalNetNs and ClearNfQueResource

Both flagged zero-caller by Phase 6b-1's review and scoped to whichever
phase owns netns/NFQ_RES_INFO lifecycle (this one). Re-confirmed via a
fresh repo-wide grep immediately before deleting."
```

---

### Task 6: Final verification

**Files:** None modified — verification only, plus this task's own report.

**Interfaces:** None.

- [ ] **Step 1: Confirm the C library surface is genuinely gone**

```bash
grep -rn "libnetfilter_queue\|nfq_q_handle\|nfq_data\|nfgenmsg\|nfqnl_msg_packet_hdr" net-policy.cpp net-policy.h rule-detail.cpp
```
Expected: zero matches (these types/headers were only ever needed by the now-deleted direct `libnetfilter_queue` API calls). `libnetfilter_queue` itself stays vendored and linked (`CMakeLists.txt`'s `add_subdirectory(libnetfilter_queue)`/`target_link_libraries(... libnetfilter_queue ...)`) — this plan does not remove the vendored library or its CMake wiring, only this project's own direct C calls into it; deleting the vendored submodule/link entirely is a follow-up once nothing in the dependency graph needs it (the `nfq` crate talks to the kernel via raw netlink sockets directly, not through this vendored library, so it may already be fully unreferenced — note in this task's report whether removing it looks safe, but do not remove it in this task, since confirming that is a broader check than this plan's scope).

- [ ] **Step 2: Full build and triple test run**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j2 net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_test && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*'"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*'"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*'"
docker exec --privileged net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='NetNfqFfiTest.*'"
```
Expected: all green, no flakiness, and the privileged run reports the actual pass/skip outcome for `OpenRoundTrip` (record which one in the report).

- [ ] **Step 3: Manual sanity check of the real daemon**

Run the real `net-rule` binary with an actual pod-like network namespace and confirm a real TCP connection through it produces the expected verdict, following Phase 6b-2's Task 6 precedent (its manual timerfd verification) for what this kind of check looks like in this project. Document the exact commands run and their output in this task's report — if a full pod-namespace setup isn't practical in the available environment, document what was actually checked (e.g., a real NFQUEUE round-trip against loopback traffic, matching this plan's `OpenRoundTrip` test but observed manually) and why a fuller check wasn't reachable here.

- [ ] **Step 4: Write the final report and commit if any cleanup was needed**

Write `.superpowers/sdd/<workspace-name>/task-6-report.md` (or wherever this plan's execution process's report convention points) summarizing: the C-library-surface grep result, all test run outcomes, the manual sanity check's actual output, and the libnetfilter_queue-vendoring removal assessment from Step 1. If Step 1 or Step 2 found something needing a code change, make it, re-run Step 2, and commit:
```bash
git add -A
git commit -m "Phase 6b-3 final verification: confirm libnetfilter_queue's direct
C API is fully retired from net-policy.cpp/.h/rule-detail.cpp"
```
If nothing needed changing, no commit is required for this task.

---

## Final State

- `libnetfilter_queue`'s C API is no longer called directly from `net-policy.cpp`/`.h`/`rule-detail.cpp` — all NFQ mechanics (open/bind/create/mode/receive/verdict) go through the new `net_nfq` Rust crate.
- `NFQ_RES_INFO` holds Rust-backed queue handles (`std::optional<rust::Box<net_nfq::NfqQueue>>`) for its NFQ half and unchanged raw C pointers for its conntrack half, cleanly split along the 6b-3/6c boundary until Phase 6c ports the latter.
- Netns switching (`SetNs`) is Rust-backed; the confirmed-dead "return to host namespace" machinery and `NfQueData::ClearNfQueResource` are deleted.
- `input_nfq_cb`/`output_nfq_cb`'s decision logic is byte-for-byte the same as before this phase — only the packet-id/payload/mark extraction at the top and the verdict mechanism at every return point changed.
- Remaining before Phase 6 is fully done: Phase 6c (conntrack, FFI-wrap approach) — untouched by this phase, planned separately when its turn comes.
