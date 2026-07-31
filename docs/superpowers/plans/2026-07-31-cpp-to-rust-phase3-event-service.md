# Phase 3: EventService Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the C++ `grpc++`-based `EventServiceImpl`/`EventBridge` with a
Rust `tonic` server hosting `NetPolicyEvents::SubscribeEvents` on the same
port (50052) it already occupies, per
`docs/superpowers/specs/2026-07-31-cpp-to-rust-phase3-event-service-design.md`.

**Architecture:** A new crate, `crates/net_policy_events`, owns a bounded
drop-oldest-on-overflow event queue and two `cxx` `extern "Rust"` publish
functions callable directly from the C++ epoll thread (no `DaemonContext`
coupling, no `GrpcDispatchQueue`-style handoff needed — this is a one-way
push, not a request/response dispatch). A dedicated `tokio` runtime on its
own OS thread hosts the `tonic` server; `SubscribeEvents` drains the queue
via a blocking loop and forwards events into the streaming response.
`PostServer::SendMatchMsg` and `PluginContext::onClose` are rewired to call
straight into Rust instead of the C++ `EventBridge`, which — along with
`EventServiceImpl` and `GrpcServer` — is deleted once the migration is
proven end-to-end.

**Tech Stack:** Rust, `cxx` 1.x, `tonic` 0.11, `prost` 0.12, `tokio` 1.x
(`rt-multi-thread`, `sync`, `net`), `tokio-stream` 0.1 (`net`), Corrosion
(CMake↔Cargo), Google Test (C++ side).

## Global Constraints

- No `.proto` changes — `proto/net_policy_events.proto` is the single
  source of truth for both the (soon-deleted) C++ codegen and the new Rust
  codegen, unchanged throughout this plan.
- `PostServer` (port 8888) and the port-9999 raw-socket protocol are
  completely out of scope — no file touched by this plan may change their
  behavior.
- Every C++→Rust string conversion that could carry attacker-influenceable
  bytes (`dst_ip`, `attacked_url`, `attack_load`, etc.) MUST be guarded by
  `IsValidUtf8` before crossing the `cxx` boundary — `rust::Str` throws
  `std::invalid_argument` on invalid UTF-8, and this call path has no
  enclosing `try`/`catch` (it's a direct call from the epoll thread, not
  routed through `GrpcDispatchQueue`). Skipping this guard is not
  acceptable in any task that adds a new FFI string crossing.
- `EventService`'s port (50052) does not change in this plan — only its
  underlying implementation. `ControlService` (port 50051) is untouched by
  this plan entirely.
- Server-start calls (`start_event_server`) must be placed as the LAST
  fallible step before `RunNetPolicyDaemon`'s main `epoll_wait` loop begins
  — the same lesson Phase 2's final review learned the hard way (a network-
  reachable use-after-free window if a later fallible step fails after the
  Rust server thread is already running).

---

## Task 1: Promote `IsValidUtf8` to a shared header

**Files:**
- Create: `common/utf8_check.h`
- Modify: `waf/rule.cc:14-28` (delete the anonymous-namespace `IsValidUtf8`
  definition, replace with an `#include`)
- Test: `tests/waf_rules_test.cc` (existing UTF-8 tests must still pass
  unchanged — this task proves the promotion didn't change behavior)

**Interfaces:**
- Produces: `inline bool IsValidUtf8(const std::string& s)` at global scope,
  usable from any `.cc`/`.cpp` file that includes `common/utf8_check.h`.

`waf/rule.cc`'s current lines 14-28:
```cpp
namespace {
// rust::Str requires valid UTF-8 and throws std::invalid_argument otherwise.
// Attacker-controlled HTTP bytes (path, Host, X-Forwarded-For, request
// body) carry no such guarantee, so every FFI call taking one must fail
// closed (treat as no-match) rather than let the exception escape
// uncaught and crash the daemon via std::terminate.
inline bool IsValidUtf8(const std::string &s) {
    try {
        (void)rust::Str(s);
        return true;
    } catch (const std::invalid_argument &) {
        return false;
    }
}
}  // namespace
```

`waf/rule.cc` currently includes `"waf_rules_core_cxxbridge/lib.h"` (line
12), which transitively provides `rust::Str` via `rust/cxx.h` — the new
shared header needs the same transitive availability, which any
`cxx`-bridge-generated header provides identically (it's `cxx`'s own
runtime header, not per-crate). Since `common/utf8_check.h` is a
standalone header included by files that may or may not already pull in a
`cxxbridge` header, declare its own include explicitly rather than relying
on transitive inclusion from whichever caller happens to already have one.

- [ ] **Step 1: Create the shared header**

```cpp
// common/utf8_check.h
#pragma once

#include <stdexcept>
#include <string>

#include "rust/cxx.h"

// rust::Str requires valid UTF-8 and throws std::invalid_argument
// otherwise. Attacker-controlled bytes (HTTP path/Host/X-Forwarded-For,
// request bodies, five-tuple-derived strings, WAF attack payloads) carry
// no such guarantee, so every call site constructing a rust::Str/rust::String
// from such data must check this first and fail closed (skip/no-match)
// rather than let the exception escape uncaught and crash the daemon via
// std::terminate. Kept at global scope (not inside a namespace) so
// existing bare-name call sites (waf/rule.cc) don't need to change when
// this moves out of its old anonymous namespace.
inline bool IsValidUtf8(const std::string& s) {
    try {
        (void)rust::Str(s);
        return true;
    } catch (const std::invalid_argument&) {
        return false;
    }
}
```

- [ ] **Step 2: Update `waf/rule.cc` to use the shared header**

Replace lines 14-28 (the anonymous namespace shown above) with:
```cpp
#include "common/utf8_check.h"
```
placed alongside `waf/rule.cc`'s existing `#include` block (after the
`"waf_rules_core_cxxbridge/lib.h"` include at line 12).

- [ ] **Step 3: Rebuild and confirm existing WAF UTF-8 tests still pass**

Build/test via the Docker container (this repo's C++ toolchain isn't
usable on macOS hosts — see any prior Phase 2 task report for the exact
`docker exec net-policy-build-test` incantations if unfamiliar):
```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir> && ./build/net_rule_grpc_test --gtest_filter='WafRulesTest.*'"
```
Expected: all `WafRulesTest.*` cases still pass, including
`MatchDomainReturnsFalseOnInvalidUtf8SrcInsteadOfCrashing`,
`IsIPAddressReturnsFalseOnInvalidUtf8InsteadOfCrashing`,
`MatchIgnoreTypeReturnsFalseOnInvalidUtf8SrcInsteadOfCrashing`,
`MatchDomainSkipsInvalidUtf8ConfigEntryInsteadOfCrashing`,
`MatchIgnoreTypeSkipsInvalidUtf8ConfigEntryInsteadOfCrashing`,
`MatchForceWhiteListSkipsInvalidUtf8IpInsteadOfCrashing`,
`MatchBlackWhiteListCidrSkipsInvalidUtf8IpInsteadOfCrashing`,
`Pcre2RegexReturnsNulloptOnInvalidUtf8SrcInsteadOfCrashing` — none of
these should change behavior, since `IsValidUtf8`'s logic is unchanged,
only its location moved.

- [ ] **Step 4: Commit**

```bash
git add common/utf8_check.h waf/rule.cc
git commit -m "Promote IsValidUtf8 to a shared header ahead of the EventService migration"
```

---

## Task 2: Scaffold `net_policy_events` crate — queue and publish functions

**Files:**
- Create: `crates/net_policy_events/Cargo.toml`
- Create: `crates/net_policy_events/build.rs`
- Create: `crates/net_policy_events/src/lib.rs`
- Modify: `Cargo.toml` (workspace root — add the new member)

**Interfaces:**
- Produces: `pub fn publish_policy_match(protocol: u8, action: i32, direction: i32, src_port: u16, dst_port: u16, src_ip: &str, dst_ip: &str, policy_name: &str)`
  and `pub fn publish_waf_attack(service_id: u64, res_name: &str, app_name: &str, res_kind: &str, k8s_namespace: &str, cluster_key: &str, action: &str, attack_ip: &str, attacked_app: &str, attack_load: &str, attack_time: i64, rule_id: i64, rule_name: &str, req_pkg: &str, rsp_pkg: &str, attack_type: &str, attacked_url: &str, rsp_content_type: &str)`
  — both declared in a `#[cxx::bridge(namespace = "grpc_bridge")]` module's
  `extern "Rust"` block, both safe `fn` (no raw pointers cross this
  boundary). Also produces the internal `EventQueue` type and its
  process-wide singleton accessor `queue() -> &'static EventQueue`, which
  Task 4's `SubscribeEvents` implementation will call `wait_and_pop` on.
- Consumes: nothing from earlier tasks in this plan.

This task is Rust-only — no `cxx`-to-C++ crossing is exercised yet (that's
Task 3, wiring into CMake) and no C++ code calls these functions yet
(Task 5/6). Verified here purely via `cargo test`.

- [ ] **Step 1: Add the crate to the workspace**

`Cargo.toml` (workspace root) currently reads:
```toml
[workspace]
resolver = "2"
members = ["crates/ffi_smoke", "crates/waf_rules_core", "crates/net_policy_control"]
```
Change to:
```toml
[workspace]
resolver = "2"
members = ["crates/ffi_smoke", "crates/waf_rules_core", "crates/net_policy_control", "crates/net_policy_events"]
```

- [ ] **Step 2: Create the crate manifest**

```toml
# crates/net_policy_events/Cargo.toml
[package]
name = "net_policy_events"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
cxx = "1"
tonic = "0.11"
prost = "0.12"
tokio = { version = "1", features = ["rt-multi-thread", "sync", "net"] }
tokio-stream = { version = "0.1", features = ["net"] }

[build-dependencies]
tonic-build = "0.11"
```

- [ ] **Step 3: Create the build script**

```rust
// crates/net_policy_events/build.rs
fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let repo_root = std::path::Path::new(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/net_policy_events is two levels under the repo root");

    tonic_build::configure()
        .build_client(false)
        .compile(
            &[repo_root.join("proto/net_policy_events.proto")],
            &[repo_root.to_path_buf()],
        )
        .expect("failed to compile net_policy_events.proto");
}
```

- [ ] **Step 4: Write the queue, mapping functions, and publish functions**

```rust
// crates/net_policy_events/src/lib.rs
pub mod proto {
    tonic::include_proto!("netpolicy.v1");
}

use proto::{PolicyEvent, PolicyMatchEvent, WafAttackEvent};
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::Duration;

#[cxx::bridge(namespace = "grpc_bridge")]
mod ffi {
    extern "Rust" {
        fn publish_policy_match(
            protocol: u8,
            action: i32,
            direction: i32,
            src_port: u16,
            dst_port: u16,
            src_ip: &str,
            dst_ip: &str,
            policy_name: &str,
        );

        fn publish_waf_attack(
            service_id: u64,
            res_name: &str,
            app_name: &str,
            res_kind: &str,
            k8s_namespace: &str,
            cluster_key: &str,
            action: &str,
            attack_ip: &str,
            attacked_app: &str,
            attack_load: &str,
            attack_time: i64,
            rule_id: i64,
            rule_name: &str,
            req_pkg: &str,
            rsp_pkg: &str,
            attack_type: &str,
            attacked_url: &str,
            rsp_content_type: &str,
        );
    }
}

const EVENT_QUEUE_CAPACITY: usize = 256;

struct EventQueue {
    inner: Mutex<VecDeque<PolicyEvent>>,
    condvar: Condvar,
}

impl EventQueue {
    fn new() -> Self {
        EventQueue { inner: Mutex::new(VecDeque::new()), condvar: Condvar::new() }
    }

    fn push(&self, event: PolicyEvent) {
        let mut guard = self.inner.lock().unwrap();
        if guard.len() >= EVENT_QUEUE_CAPACITY {
            guard.pop_front(); // drop oldest, matching grpc/event_bridge.cc's existing policy
        }
        guard.push_back(event);
        self.condvar.notify_one();
    }

    fn wait_and_pop(&self, timeout: Duration) -> Option<PolicyEvent> {
        let guard = self.inner.lock().unwrap();
        let (mut guard, result) = self
            .condvar
            .wait_timeout_while(guard, timeout, |q| q.is_empty())
            .unwrap();
        if result.timed_out() {
            return None;
        }
        guard.pop_front()
    }
}

static QUEUE: OnceLock<EventQueue> = OnceLock::new();

fn queue() -> &'static EventQueue {
    QUEUE.get_or_init(EventQueue::new)
}

// mirrors ProtoToL4Protocol, grpc/event_bridge.cc (deleted in Task 8) --
// IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_ICMP=1 (see <netinet/in.h>);
// proto values from net_policy_common.proto: UNSPECIFIED=0, TCP=1, UDP=2, ICMP=3
fn protocol_to_l4protocol(protocol: u8) -> i32 {
    match protocol {
        6 => 1,  // L4_PROTOCOL_TCP
        17 => 2, // L4_PROTOCOL_UDP
        1 => 3,  // L4_PROTOCOL_ICMP
        _ => 0,  // L4_PROTOCOL_UNSPECIFIED
    }
}

// mirrors NetPolicyRuleToProto -- NetPolicyRule (net-policy.h): kDeny=0,
// kAllow=1, kMark=2 (kAllowRsp=3/kAllowReq=4/kDefault=5 have no proto
// mapping and fall through to UNSPECIFIED, matching the C++ original's
// default case); PolicyAction (net_policy_common.proto): UNSPECIFIED=0, DENY=1, ALLOW=2, ALERT=3
fn net_policy_rule_to_proto(action: i32) -> i32 {
    match action {
        1 => 2, // POLICY_ACTION_ALLOW
        2 => 3, // POLICY_ACTION_ALERT
        0 => 1, // POLICY_ACTION_DENY
        _ => 0, // POLICY_ACTION_UNSPECIFIED
    }
}

// mirrors FlowDirToProto -- FlowDir (net-policy.h): kIngress=0, kEgress=1;
// FlowDirection (net_policy_common.proto): INGRESS=1, EGRESS=2 (no
// UNSPECIFIED=0 case needed here, matching the C++ original's plain ternary)
fn flow_dir_to_proto(direction: i32) -> i32 {
    if direction == 0 { 1 } else { 2 }
}

pub fn publish_policy_match(
    protocol: u8,
    action: i32,
    direction: i32,
    src_port: u16,
    dst_port: u16,
    src_ip: &str,
    dst_ip: &str,
    policy_name: &str,
) {
    let event = PolicyEvent {
        event: Some(proto::policy_event::Event::PolicyMatch(PolicyMatchEvent {
            protocol: protocol_to_l4protocol(protocol),
            action: net_policy_rule_to_proto(action),
            direction: flow_dir_to_proto(direction),
            src_port: src_port as u32,
            dst_port: dst_port as u32,
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            policy_name: policy_name.to_string(),
        })),
    };
    queue().push(event);
}

pub fn publish_waf_attack(
    service_id: u64,
    res_name: &str,
    app_name: &str,
    res_kind: &str,
    k8s_namespace: &str,
    cluster_key: &str,
    action: &str,
    attack_ip: &str,
    attacked_app: &str,
    attack_load: &str,
    attack_time: i64,
    rule_id: i64,
    rule_name: &str,
    req_pkg: &str,
    rsp_pkg: &str,
    attack_type: &str,
    attacked_url: &str,
    rsp_content_type: &str,
) {
    let event = PolicyEvent {
        event: Some(proto::policy_event::Event::WafAttack(WafAttackEvent {
            service_id,
            res_name: res_name.to_string(),
            app_name: app_name.to_string(),
            res_kind: res_kind.to_string(),
            k8s_namespace: k8s_namespace.to_string(),
            cluster_key: cluster_key.to_string(),
            action: action.to_string(),
            attack_ip: attack_ip.to_string(),
            attacked_app: attacked_app.to_string(),
            attack_load: attack_load.to_string(),
            attack_time,
            rule_id,
            rule_name: rule_name.to_string(),
            req_pkg: req_pkg.to_string(),
            rsp_pkg: rsp_pkg.to_string(),
            attack_type: attack_type.to_string(),
            attacked_url: attacked_url.to_string(),
            rsp_content_type: rsp_content_type.to_string(),
        })),
    };
    queue().push(event);
}
```

- [ ] **Step 5: Write unit tests**

Each test constructs its OWN `EventQueue` instance rather than going
through the shared `queue()` singleton — `cargo test` runs tests in
parallel by default (unlike GTest, which runs sequentially unless
configured otherwise), so sharing one process-wide queue across tests
would make them flaky/order-dependent. Add to the bottom of
`crates/net_policy_events/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_to_l4protocol_maps_known_values() {
        assert_eq!(protocol_to_l4protocol(6), 1);
        assert_eq!(protocol_to_l4protocol(17), 2);
        assert_eq!(protocol_to_l4protocol(1), 3);
        assert_eq!(protocol_to_l4protocol(99), 0);
    }

    #[test]
    fn net_policy_rule_to_proto_maps_known_values() {
        assert_eq!(net_policy_rule_to_proto(1), 2);
        assert_eq!(net_policy_rule_to_proto(2), 3);
        assert_eq!(net_policy_rule_to_proto(0), 1);
        assert_eq!(net_policy_rule_to_proto(99), 0);
    }

    #[test]
    fn flow_dir_to_proto_maps_known_values() {
        assert_eq!(flow_dir_to_proto(0), 1);
        assert_eq!(flow_dir_to_proto(1), 2);
    }

    #[test]
    fn event_queue_push_then_wait_and_pop_returns_event() {
        let q = EventQueue::new();
        q.push(PolicyEvent { event: None });
        assert!(q.wait_and_pop(Duration::from_millis(100)).is_some());
    }

    #[test]
    fn event_queue_wait_and_pop_times_out_when_empty() {
        let q = EventQueue::new();
        assert!(q.wait_and_pop(Duration::from_millis(50)).is_none());
    }

    #[test]
    fn event_queue_drops_oldest_when_full() {
        let q = EventQueue::new();
        for i in 0..(EVENT_QUEUE_CAPACITY + 1) {
            q.push(PolicyEvent {
                event: Some(proto::policy_event::Event::PolicyMatch(PolicyMatchEvent {
                    src_port: i as u32,
                    ..Default::default()
                })),
            });
        }
        let mut popped_ports = Vec::new();
        while let Some(ev) = q.wait_and_pop(Duration::from_millis(1)) {
            if let Some(proto::policy_event::Event::PolicyMatch(m)) = ev.event {
                popped_ports.push(m.src_port);
            }
        }
        assert_eq!(popped_ports.len(), EVENT_QUEUE_CAPACITY);
        // the oldest push (src_port == 0) must have been dropped, so the
        // first surviving entry is src_port == 1
        assert_eq!(popped_ports[0], 1);
    }
}
```

- [ ] **Step 6: Run the tests**

```bash
docker exec net-policy-build-test bash -lc "cd /tmp/<scratch-dir>/crates/net_policy_events && cargo test"
```
Expected: 6 tests pass (`protocol_to_l4protocol_maps_known_values`,
`net_policy_rule_to_proto_maps_known_values`,
`flow_dir_to_proto_maps_known_values`,
`event_queue_push_then_wait_and_pop_returns_event`,
`event_queue_wait_and_pop_times_out_when_empty`,
`event_queue_drops_oldest_when_full`).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml crates/net_policy_events/
git commit -m "Scaffold net_policy_events crate: event queue and publish functions"
```

---

## Task 3: Wire `net_policy_events` into CMake via Corrosion

**Files:**
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `crates/net_policy_events` (Task 2).
- Produces: a `net_policy_events_cxxbridge` CMake target that `net-rule` and
  `net_rule_grpc_test` can link against; the generated header becomes
  includable as `"net_policy_events_cxxbridge/lib.h"`.

Unlike `net_policy_control_cxxbridge` (which needed
`target_include_directories(... PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})`
because its bridge module does `include!("grpc/control_dispatch.h")`),
`net_policy_events`'s bridge module has no `unsafe extern "C++"` block at
all (Task 2's bridge only has an `extern "Rust"` block) — so it needs no
C++ header `include!()` and no extra include directory, matching
`waf_rules_core_cxxbridge`'s simpler pattern exactly (see the existing
comment at `CMakeLists.txt:60-62` contrasting the two).

- [ ] **Step 1: Add the Corrosion cxxbridge target**

After the existing `corrosion_add_cxxbridge(net_policy_control_cxxbridge ...)`
block (`CMakeLists.txt:56-63`), add:
```cmake
corrosion_add_cxxbridge(net_policy_events_cxxbridge
  CRATE net_policy_events
  FILES lib.rs
)
```

- [ ] **Step 2: Link the new target into both binaries**

In `target_link_libraries(net-rule ...)` (`CMakeLists.txt:178-198`), add
`net_policy_events_cxxbridge` alongside the existing
`net_policy_control_cxxbridge` line:
```cmake
target_link_libraries(net-rule
  libnfnetlink
  libnetfilter_queue
  libnetfilter_conntrack
  libnghttp2.a
  libpcre2-8.a
  libpcre2-posix.a
  fmt::fmt-header-only
  llhttp::llhttp_static
  glog.a
  gflags.a
  ${CMAKE_THREAD_LIBS_INIT}
  libunwind.a
  liblzma.a
  libz.a
  libtcmalloc_and_profiler.a
  gRPC::grpc++
  protobuf::libprotobuf
  waf_rules_core_cxxbridge
  net_policy_control_cxxbridge
  net_policy_events_cxxbridge
)
```
Do the identical addition to `target_link_libraries(net_rule_grpc_test ...)`
(`CMakeLists.txt:283-303`).

The existing `-Wl,--allow-multiple-definition` link flags on both targets
(`CMakeLists.txt:206`, `:305`) already cover this — they're not scoped to
a specific pair of crates, so a third `cxx`-using staticlib needs no
additional linker flag changes (tracked as a general concern in issue #12,
unrelated to this task).

- [ ] **Step 3: Confirm it builds**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net-rule net_rule_grpc_test 2>&1 | tail -60"
```
Expected: clean build under `-Wall -Werror`. The linker must successfully
resolve the new `net_policy_events_cxxbridge` static library; no new
undefined-reference or duplicate-symbol errors (the `--allow-multiple-
definition` flag already handles the expected `cxx` runtime-shim
duplication across three staticlib crates now, same mechanism as the
existing two).

- [ ] **Step 4: Commit**

```bash
git add CMakeLists.txt
git commit -m "Wire net_policy_events into CMake via Corrosion"
```

---

## Task 4: Implement `start_event_server` and `SubscribeEvents` streaming

**Files:**
- Modify: `crates/net_policy_events/src/lib.rs`
- Create: `tests/grpc_rust_events_e2e_test.cc`
- Modify: `CMakeLists.txt` (add the new test file to `net_rule_grpc_test`'s
  source list)

**Interfaces:**
- Consumes: `queue()`, `EventQueue::wait_and_pop` (Task 2).
- Produces: `unsafe fn start_event_server(port: u16) -> u16` (exposed via
  the same `#[cxx::bridge]` module's `extern "Rust"` block — `unsafe` here
  purely because starting a server twice would double-bind a listener and
  is meant to be called exactly once, matching the spirit of
  `start_control_server`'s single-call contract, even though this function
  itself takes no raw pointers).

This is the first task that actually starts a real server and lets a real
gRPC client receive a real event — verified with a temporary/ephemeral
dev port (`port=0`, letting the OS assign one, exactly like
`tests/grpc_rust_control_e2e_test.cc` already does for `ControlService`).
Nothing in production code calls `start_event_server` yet — that's Task 8's
cutover.

- [ ] **Step 1: Add the `NetPolicyEvents` trait implementation and server startup**

Add to `crates/net_policy_events/src/lib.rs` (after the `publish_waf_attack`
function, before the `#[cfg(test)]` module):

```rust
use proto::net_policy_events_server::{NetPolicyEvents, NetPolicyEventsServer};
use proto::SubscribeEventsRequest;
use std::pin::Pin;
use tokio_stream::{Stream, StreamExt};
use tonic::{transport::Server, Request, Response, Status};

struct EventServiceImpl;

#[tonic::async_trait]
impl NetPolicyEvents for EventServiceImpl {
    type SubscribeEventsStream =
        Pin<Box<dyn Stream<Item = Result<PolicyEvent, Status>> + Send + 'static>>;

    async fn subscribe_events(
        &self,
        _request: Request<SubscribeEventsRequest>,
    ) -> Result<Response<Self::SubscribeEventsStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel::<PolicyEvent>(16);
        tokio::task::spawn_blocking(move || {
            // Mirrors EventServiceImpl::SubscribeEvents's existing
            // while(!context->IsCancelled()) + 500ms-timeout loop
            // (grpc/event_service.cc, deleted in Task 8). There's no
            // direct cancellation-token equivalent to context->IsCancelled()
            // here; instead, blocking_send's failure (the Receiver was
            // dropped because the client disconnected and tonic tore down
            // the response stream) is the signal to stop, exactly mirroring
            // the C++ version's `if (!writer->Write(event)) break;`.
            loop {
                if let Some(event) = queue().wait_and_pop(Duration::from_millis(500)) {
                    if tx.blocking_send(event).is_err() {
                        break;
                    }
                }
            }
        });
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(Ok);
        Ok(Response::new(Box::pin(stream) as Self::SubscribeEventsStream))
    }
}

unsafe fn start_event_server(port: u16) -> u16 {
    let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
        rt.block_on(async move {
            let addr: std::net::SocketAddr =
                format!("0.0.0.0:{port}").parse().expect("invalid bind address");
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(_) => {
                    let _ = port_tx.send(0);
                    return;
                }
            };
            let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
            let _ = port_tx.send(bound_port);
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            let _ = Server::builder()
                .add_service(NetPolicyEventsServer::new(EventServiceImpl))
                .serve_with_incoming(incoming)
                .await;
        });
    });
    port_rx.recv().unwrap_or(0)
}
```

Add `start_event_server` to the `#[cxx::bridge]` module's `extern "Rust"`
block from Task 2:
```rust
        unsafe fn start_event_server(port: u16) -> u16;
```

- [ ] **Step 2: Write the end-to-end test**

This test calls `publish_policy_match`/`publish_waf_attack` directly (the
Rust functions themselves, via the generated `cxx` header) rather than
going through any C++ call site — those get wired in Tasks 5/6, and this
task's job is to prove the server/streaming plumbing works in isolation.

```cpp
// tests/grpc_rust_events_e2e_test.cc
#include <chrono>
#include <thread>

#include <gtest/gtest.h>
#include <grpcpp/grpcpp.h>

#include "net_policy_events_cxxbridge/lib.h"
#include "proto/net_policy_events.grpc.pb.h"

namespace {

// Mirrors GrpcRustControlEndToEndTest's SetUpTestSuite/TearDownTestSuite
// pattern (tests/grpc_rust_control_e2e_test.cc) -- the Rust event server
// binds once per process (no OnceLock re-entry guard needed here since
// start_event_server has no shared DaemonContext-style singleton state to
// protect, but starting two servers in the same process would still double-
// bind, so share one across the whole suite regardless).
class GrpcRustEventsEndToEndTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() {
    port_ = grpc_bridge::start_event_server(/*port=*/0);
    ASSERT_NE(port_, 0) << "rust event server failed to bind";
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  void SetUp() override {
    auto channel = grpc::CreateChannel("localhost:" + std::to_string(port_),
                                        grpc::InsecureChannelCredentials());
    stub_ = netpolicy::v1::NetPolicyEvents::NewStub(channel);
  }

  static uint16_t port_;
  std::unique_ptr<netpolicy::v1::NetPolicyEvents::Stub> stub_;
};

uint16_t GrpcRustEventsEndToEndTest::port_ = 0;

TEST_F(GrpcRustEventsEndToEndTest, SubscribeEventsReceivesPublishedPolicyMatch) {
  grpc::ClientContext ctx;
  netpolicy::v1::SubscribeEventsRequest req;
  req.set_client_id("test-client");
  auto reader = stub_->SubscribeEvents(&ctx, req);

  // give the server-side loop a moment to start polling before publishing
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  grpc_bridge::publish_policy_match(
      /*protocol=*/6, /*action=*/1, /*direction=*/0,
      /*src_port=*/1234, /*dst_port=*/80,
      "10.0.0.1", "10.0.0.2", "test-policy");

  netpolicy::v1::PolicyEvent event;
  ASSERT_TRUE(reader->Read(&event));
  ASSERT_TRUE(event.has_policy_match());
  const auto& match = event.policy_match();
  EXPECT_EQ(match.protocol(), netpolicy::v1::L4_PROTOCOL_TCP);
  EXPECT_EQ(match.action(), netpolicy::v1::POLICY_ACTION_ALLOW);
  EXPECT_EQ(match.direction(), netpolicy::v1::FLOW_DIRECTION_INGRESS);
  EXPECT_EQ(match.src_port(), 1234u);
  EXPECT_EQ(match.dst_port(), 80u);
  EXPECT_EQ(match.src_ip(), "10.0.0.1");
  EXPECT_EQ(match.dst_ip(), "10.0.0.2");
  EXPECT_EQ(match.policy_name(), "test-policy");

  ctx.TryCancel();
}

TEST_F(GrpcRustEventsEndToEndTest, SubscribeEventsReceivesPublishedWafAttack) {
  grpc::ClientContext ctx;
  netpolicy::v1::SubscribeEventsRequest req;
  req.set_client_id("test-client");
  auto reader = stub_->SubscribeEvents(&ctx, req);

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  grpc_bridge::publish_waf_attack(
      /*service_id=*/42, "res", "app", "kind", "ns", "cluster",
      "block", "1.2.3.4", "attacked-app", "load", /*attack_time=*/100,
      /*rule_id=*/7, "rule-name", "req", "rsp", "sqli", "url", "text/html");

  netpolicy::v1::PolicyEvent event;
  ASSERT_TRUE(reader->Read(&event));
  ASSERT_TRUE(event.has_waf_attack());
  const auto& attack = event.waf_attack();
  EXPECT_EQ(attack.service_id(), 42u);
  EXPECT_EQ(attack.res_name(), "res");
  EXPECT_EQ(attack.rule_id(), 7);
  EXPECT_EQ(attack.attacked_url(), "url");

  ctx.TryCancel();
}

// The server-side spawn_blocking loop has no direct C++-observable handle
// (unlike the old C++ EventServiceImpl, which ran on grpc++'s own thread
// pool where cancellation is entirely internal to that library too) -- the
// practical, externally-observable proxy for "the loop notices
// cancellation and exits promptly" is that the RPC itself actually
// terminates (grpc++ surfaces CANCELLED) rather than hanging forever.
TEST_F(GrpcRustEventsEndToEndTest, SubscribeEventsStopsAfterClientCancellation) {
  grpc::ClientContext ctx;
  netpolicy::v1::SubscribeEventsRequest req;
  req.set_client_id("cancel-test-client");
  auto reader = stub_->SubscribeEvents(&ctx, req);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  ctx.TryCancel();
  grpc::Status status = reader->Finish();
  // Finish() must return promptly (this test's own timeout, GTest's
  // default per-test deadline, is the backstop if it doesn't) with a
  // cancellation-shaped status rather than hang or report OK.
  EXPECT_EQ(status.error_code(), grpc::StatusCode::CANCELLED);
}

} // namespace
```

- [ ] **Step 3: Add the test file to CMake**

In `CMakeLists.txt`'s `net_rule_grpc_test` source list
(`CMakeLists.txt:248-281`), add `tests/grpc_rust_events_e2e_test.cc`
alongside `tests/grpc_rust_control_e2e_test.cc`:
```cmake
    tests/grpc_rust_control_e2e_test.cc
    tests/grpc_rust_events_e2e_test.cc
    tests/waf_rules_test.cc
```

- [ ] **Step 4: Build and run**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net_rule_grpc_test 2>&1 | tail -60"
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && ./net_rule_grpc_test --gtest_filter='GrpcRustEventsEndToEndTest.*'"
```
Expected: all three new tests pass (`SubscribeEventsReceivesPublishedPolicyMatch`,
`SubscribeEventsReceivesPublishedWafAttack`,
`SubscribeEventsStopsAfterClientCancellation`).

- [ ] **Step 5: Commit**

```bash
git add crates/net_policy_events/src/lib.rs tests/grpc_rust_events_e2e_test.cc CMakeLists.txt
git commit -m "Implement start_event_server and SubscribeEvents streaming"
```

---

## Task 5: Wire `PostServer::SendMatchMsg` to dual-publish

**Files:**
- Modify: `net-policy.cpp:368-397` (`PostServer::SendMatchMsg`)

**Interfaces:**
- Consumes: `grpc_bridge::publish_policy_match` (Task 4, via
  `net_policy_events_cxxbridge/lib.h`), `IsValidUtf8` (Task 1, via
  `common/utf8_check.h`).

`PostServer::SendMatchMsg`'s current body (`net-policy.cpp:368-397`):
```cpp
int PostServer::SendMatchMsg(FiveTuple& tuple, NetPolicyRule action, FlowDir dir,
                             const std::string& rule_key) {
  int ret, len;
  char buf[11] = {"#%% pre"};
  char data[1024];
  /*publish to gRPC subscribers unconditionally -- this must run before the
   *post_link_fd_ early-return below, since a gRPC-only deployment (no legacy
   *listener connected) would otherwise never see these events*/
  if (event_bridge_)
    event_bridge_->PublishPolicyMatch(tuple, action, dir, rule_key);
  if (post_link_fd_ <= 0)
    return 0;
  ...
```

This is a **dual-publish** step, not a cutover: the existing
`event_bridge_->PublishPolicyMatch(...)` call stays exactly as-is (the
C++ `EventService` on port 50052 keeps serving real subscribers
unaffected) — a second call to the new Rust function is added alongside
it. Both paths run; nothing observable changes for existing clients yet.
Task 8 removes the old call once the new path is proven and cut over.

- [ ] **Step 1: Add the dual-publish call, guarded by `IsValidUtf8`**

Replace:
```cpp
  /*publish to gRPC subscribers unconditionally -- this must run before the
   *post_link_fd_ early-return below, since a gRPC-only deployment (no legacy
   *listener connected) would otherwise never see these events*/
  if (event_bridge_)
    event_bridge_->PublishPolicyMatch(tuple, action, dir, rule_key);
```
with:
```cpp
  /*publish to gRPC subscribers unconditionally -- this must run before the
   *post_link_fd_ early-return below, since a gRPC-only deployment (no legacy
   *listener connected) would otherwise never see these events*/
  if (event_bridge_)
    event_bridge_->PublishPolicyMatch(tuple, action, dir, rule_key);
  /*dual-publish to the new Rust EventService during the migration (Phase 3)
   *-- see docs/superpowers/specs/2026-07-31-cpp-to-rust-phase3-event-service-design.md.
   *IsValidUtf8 guards every field that could carry attacker-influenceable
   *bytes: rust::Str throws on invalid UTF-8, and this call has no
   *enclosing try/catch (unlike the ControlService dispatch path, which
   *goes through GrpcDispatchQueue's closure boundary).*/
  if (IsValidUtf8(tuple.src_addr_) && IsValidUtf8(tuple.dst_addr_) && IsValidUtf8(rule_key)) {
    grpc_bridge::publish_policy_match(
        tuple.proto_, static_cast<int32_t>(action), static_cast<int32_t>(dir),
        tuple.src_port_, tuple.dst_port_, tuple.src_addr_, tuple.dst_addr_, rule_key);
  } else {
    LOG_W("skipped publishing policy match event to Rust EventService: invalid UTF-8 in tuple/rule_key");
  }
```

- [ ] **Step 2: Add the required includes**

`net-policy.cpp` needs `common/utf8_check.h` and
`net_policy_events_cxxbridge/lib.h` (mirroring how it already includes
`net_policy_control_cxxbridge/lib.h` at line 38). Add both near the
existing `#include "grpc/control_dispatch.h"` / `#include
"net_policy_control_cxxbridge/lib.h"` block (`net-policy.cpp:35-38`).

- [ ] **Step 3: Extend the e2e test to exercise this real call site**

Add to `tests/grpc_rust_events_e2e_test.cc` (the fixture from Task 4 has
no `DaemonContext`/epoll machinery, and `PostServer::SendMatchMsg` doesn't
need any either — it's a plain method call on a stack-local `PostServer`):
```cpp
TEST_F(GrpcRustEventsEndToEndTest, PostServerSendMatchMsgDualPublishesToRust) {
  grpc::ClientContext ctx;
  netpolicy::v1::SubscribeEventsRequest req;
  req.set_client_id("test-client");
  auto reader = stub_->SubscribeEvents(&ctx, req);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  PostServer server;
  FiveTuple tuple;
  tuple.proto_ = IPPROTO_TCP;
  tuple.src_port_ = 4321;
  tuple.dst_port_ = 443;
  tuple.src_addr_ = "192.168.1.1";
  tuple.dst_addr_ = "192.168.1.2";
  int ret = server.SendMatchMsg(tuple, NetPolicyRule::kDeny, FlowDir::kEgress, "dual-publish-test");
  EXPECT_EQ(ret, 0);

  netpolicy::v1::PolicyEvent event;
  ASSERT_TRUE(reader->Read(&event));
  ASSERT_TRUE(event.has_policy_match());
  const auto& match = event.policy_match();
  EXPECT_EQ(match.action(), netpolicy::v1::POLICY_ACTION_DENY);
  EXPECT_EQ(match.direction(), netpolicy::v1::FLOW_DIRECTION_EGRESS);
  EXPECT_EQ(match.src_ip(), "192.168.1.1");
  EXPECT_EQ(match.policy_name(), "dual-publish-test");

  ctx.TryCancel();
}
```
This requires `#include "net-policy.h"` to be added to
`tests/grpc_rust_events_e2e_test.cc` (for `PostServer`/`FiveTuple`/
`NetPolicyRule`/`FlowDir`).

- [ ] **Step 4: Build and run**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net_rule_grpc_test 2>&1 | tail -60"
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && ./net_rule_grpc_test --gtest_filter='GrpcRustEventsEndToEndTest.*:GrpcEventBridge.*'"
```
Expected: the new test passes, and the pre-existing
`tests/grpc_event_bridge_test.cc` cases (which test the OLD C++
`EventBridge` directly, still present and still wired via
`event_bridge_`) also still pass unchanged — this proves the dual-publish
didn't disturb the existing path.

- [ ] **Step 5: Commit**

```bash
git add net-policy.cpp tests/grpc_rust_events_e2e_test.cc
git commit -m "Dual-publish PostServer::SendMatchMsg events to the new Rust EventService"
```

---

## Task 6: Wire `PluginContext::onClose` (WAF attack) to dual-publish

**Files:**
- Modify: `waf/plugin.h` (declare a new free function)
- Modify: `waf/plugin.cc:141-143` (`PluginContext::onClose`; define the new
  free function)

**Interfaces:**
- Consumes: `grpc_bridge::publish_waf_attack` (Task 4), `IsValidUtf8`
  (Task 1).
- Produces: `void PublishWafAttackToRustEventService(Rules& rule_ctx, AttackedLog& log)`
  at global scope (declared in `waf/plugin.h`, alongside — not inside —
  the `namespace http { namespace extension { ... } }` blocks, matching
  `Rules`/`AttackedLog` themselves, which are also global-scope types).

`PluginContext::ruleArr`/`atlog` (`waf/plugin.h:41-42`) are **private**
members with no public accessor or setter — they're populated internally
by `PluginContext`'s own request/response-handling methods during real
HTTP inspection, which is far more test infrastructure than this task
needs. Rather than adding a test-only backdoor into `PluginContext` (a
public setter or a `friend` declaration that exists purely for this test),
extract the dual-publish logic into a standalone free function that takes
`Rules&`/`AttackedLog&` directly — both are plain structs with public
fields (confirmed: `Rules`'s fields like `app_id_`/`res_name_` and
`AttackedLog`'s fields are all public, per `waf/rule.h`), so a test can
construct them directly and call the function with no `PluginContext`
involved at all. `PluginContext::onClose()` becomes a thin caller of this
function, keeping today's production call site behavior identical.

`PluginContext::onClose`'s current relevant lines (`waf/plugin.cc:141-143`):
```cpp
  /*publish to gRPC subscribers too -- see grpc/event_bridge.h*/
  if (auto* eb = root_ctx_->GetEventBridge())
    eb->PublishWafAttack(ruleArr, atlog);
```

- [ ] **Step 1: Declare the free function in `waf/plugin.h`**

Add near the top of `waf/plugin.h`, after the existing `#include`s and
before the `namespace http { namespace extension {` block:
```cpp
// Dual-publishes a WAF attack event to the new Rust EventService (Phase 3
// migration) -- extracted as a free function (rather than inlined in
// PluginContext::onClose) so it's testable directly with a constructed
// Rules/AttackedLog, without needing to drive PluginContext's private
// ruleArr_/atlog_ state through a full HTTP request/response cycle.
void PublishWafAttackToRustEventService(Rules& rule_ctx, AttackedLog& log);
```

- [ ] **Step 2: Define the free function and call it from `onClose`**

In `waf/plugin.cc`, add the function definition (near the top of the file,
after includes, or directly above `PluginContext::onClose`):
```cpp
void PublishWafAttackToRustEventService(Rules& rule_ctx, AttackedLog& log) {
  /*Every string field here is attacker-influenceable (attack_load/
   *attacked_url come straight from the request being inspected), so all of
   *them must pass IsValidUtf8 before crossing into rust::Str -- unlike
   *Task 5's five-tuple fields (mostly network-layer-derived, lower risk),
   *these are HTTP-layer payload data. This call has no enclosing
   *try/catch, so a skipped guard here would abort the whole daemon on the
   *very thread that processes every HTTP connection.*/
  if (IsValidUtf8(rule_ctx.res_name_) && IsValidUtf8(rule_ctx.GetAppName()) &&
      IsValidUtf8(rule_ctx.res_kind_) && IsValidUtf8(rule_ctx.pod_namespace_) &&
      IsValidUtf8(rule_ctx.cluster_key_) && IsValidUtf8(log.action_) &&
      IsValidUtf8(log.attack_ip_) && IsValidUtf8(log.attacked_app_) &&
      IsValidUtf8(log.attack_load_) && IsValidUtf8(log.rule_name_) &&
      IsValidUtf8(log.req_pkg_) && IsValidUtf8(log.rsp_pkg_) &&
      IsValidUtf8(log.type_) && IsValidUtf8(log.attacked_url_) &&
      IsValidUtf8(log.rsp_content_type_)) {
    grpc_bridge::publish_waf_attack(
        rule_ctx.app_id_, rule_ctx.res_name_, rule_ctx.GetAppName(), rule_ctx.res_kind_,
        rule_ctx.pod_namespace_, rule_ctx.cluster_key_, log.action_, log.attack_ip_,
        log.attacked_app_, log.attack_load_, log.attack_time_, log.rule_id_,
        log.rule_name_, log.req_pkg_, log.rsp_pkg_, log.type_, log.attacked_url_,
        log.rsp_content_type_);
  } else {
    LOG_W("skipped publishing WAF attack event to Rust EventService: invalid UTF-8 in a field");
  }
}
```
Replace `PluginContext::onClose`'s lines 141-143:
```cpp
  /*publish to gRPC subscribers too -- see grpc/event_bridge.h*/
  if (auto* eb = root_ctx_->GetEventBridge())
    eb->PublishWafAttack(ruleArr, atlog);
```
with:
```cpp
  /*publish to gRPC subscribers too -- see grpc/event_bridge.h*/
  if (auto* eb = root_ctx_->GetEventBridge())
    eb->PublishWafAttack(ruleArr, atlog);
  /*dual-publish to the new Rust EventService during the migration (Phase 3)
   *-- see docs/superpowers/specs/2026-07-31-cpp-to-rust-phase3-event-service-design.md.*/
  PublishWafAttackToRustEventService(ruleArr, atlog);
```

- [ ] **Step 3: Add the required includes**

`waf/plugin.cc` needs `common/utf8_check.h` and
`net_policy_events_cxxbridge/lib.h`. Check the file's existing include
block and add both alongside its current `waf/rule.h`/`net-policy.h`
includes.

- [ ] **Step 4: Add the test**

Add to `tests/grpc_rust_events_e2e_test.cc` (requires `#include
"waf/plugin.h"`) — this constructs `Rules`/`AttackedLog` directly (both
are plain structs with public fields) and calls
`PublishWafAttackToRustEventService` directly, exercising exactly the
logic Step 2 added, with no `PluginContext`/`PluginRootContext`
construction needed at all:
```cpp
TEST_F(GrpcRustEventsEndToEndTest, PublishWafAttackToRustEventServiceSendsEvent) {
  grpc::ClientContext ctx;
  netpolicy::v1::SubscribeEventsRequest req;
  req.set_client_id("test-client");
  auto reader = stub_->SubscribeEvents(&ctx, req);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  Rules rule_ctx;
  rule_ctx.app_id_ = 99;
  rule_ctx.res_name_ = "test-resource";
  rule_ctx.res_kind_ = "Deployment";
  rule_ctx.pod_namespace_ = "test-ns";
  rule_ctx.cluster_key_ = "test-cluster";
  AttackedLog log;
  log.action_ = "block";
  log.attack_ip_ = "10.10.10.10";
  log.attacked_app_ = "victim-app";
  log.attack_load_ = "' OR 1=1 --";
  log.attack_time_ = 123456789;
  log.rule_id_ = 55;
  log.rule_name_ = "sqli-rule";
  log.req_pkg_ = "req-bytes";
  log.rsp_pkg_ = "rsp-bytes";
  log.type_ = "sqli";
  log.attacked_url_ = "/vulnerable/path";
  log.rsp_content_type_ = "text/html";

  PublishWafAttackToRustEventService(rule_ctx, log);

  netpolicy::v1::PolicyEvent event;
  ASSERT_TRUE(reader->Read(&event));
  ASSERT_TRUE(event.has_waf_attack());
  const auto& attack = event.waf_attack();
  EXPECT_EQ(attack.service_id(), 99u);
  EXPECT_EQ(attack.res_name(), "test-resource");
  EXPECT_EQ(attack.rule_id(), 55);
  EXPECT_EQ(attack.attacked_url(), "/vulnerable/path");

  ctx.TryCancel();
}

TEST_F(GrpcRustEventsEndToEndTest, PublishWafAttackToRustEventServiceSkipsInvalidUtf8) {
  grpc::ClientContext ctx;
  netpolicy::v1::SubscribeEventsRequest req;
  req.set_client_id("test-client");
  auto reader = stub_->SubscribeEvents(&ctx, req);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  Rules rule_ctx;
  rule_ctx.res_name_ = "test-resource";
  AttackedLog log;
  log.attacked_url_ = std::string("bad-url-\xFF-byte"); // invalid UTF-8

  // must not throw/crash -- the guard in PublishWafAttackToRustEventService
  // must catch this and skip publishing rather than let rust::Str's
  // throwing constructor escape uncaught
  PublishWafAttackToRustEventService(rule_ctx, log);

  // reader->Read() below blocks until either an event arrives (bug -- test
  // fails) or the stream ends. Since nothing should be published, nothing
  // will ever arrive on its own, so a background thread cancels the
  // context after a bounded window to unblock Read() with the expected
  // outcome -- joined (not detached) before the test returns, so nothing
  // touches ctx/reader/event after they go out of scope.
  std::thread canceller([&ctx] {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ctx.TryCancel();
  });
  netpolicy::v1::PolicyEvent event;
  bool got_event = reader->Read(&event);
  canceller.join();
  EXPECT_FALSE(got_event) << "expected no event to be published for invalid UTF-8 input";
}
```

- [ ] **Step 5: Build and run**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net_rule_grpc_test 2>&1 | tail -60"
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && ./net_rule_grpc_test --gtest_filter='GrpcRustEventsEndToEndTest.*:GrpcEventBridge.*:WafRulesTest.*'"
```
Expected: both new tests pass; existing `GrpcEventBridge.*` and
`WafRulesTest.*` cases are unaffected.

- [ ] **Step 6: Commit**

```bash
git add waf/plugin.h waf/plugin.cc tests/grpc_rust_events_e2e_test.cc
git commit -m "Dual-publish WAF attack events to the new Rust EventService"
```

---

## Task 7: Full end-to-end verification of the dual-publish period

**Files:**
- Modify: `tests/grpc_rust_events_e2e_test.cc` (review/consolidate, no new
  production code)

**Interfaces:**
- Consumes: everything from Tasks 1-6.

This task is a checkpoint, not new functionality: confirm the whole
dual-publish surface (both real call sites feeding both the old C++
`EventBridge` and the new Rust queue simultaneously) is solid before
Task 8 removes the old path irreversibly. No plan can fully anticipate
every interaction here, so this task's job is deliberately just running
everything together and looking for surprises.

- [ ] **Step 1: Run the full gRPC test binary together**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && ./net_rule_grpc_test 2>&1 | tail -80"
```
Expected: every test in the binary passes — `GrpcRustControlEndToEndTest.*`
(unaffected by this plan), `GrpcRustEventsEndToEndTest.*` (this plan's new
tests), `GrpcEventBridge.*` (old C++ `EventBridge`, still functioning
unchanged), `GrpcEndToEndTest.*` (the old control+event e2e suite,
including `SubscribeEventsStreamReceivesPublishedPolicyMatch` against the
still-live C++ `EventServiceImpl` on the real port 50052), `WafRulesTest.*`.

- [ ] **Step 2: Run it a second time to check for flakiness**

Since both the old and new event paths are now live simultaneously,
timing-sensitive interactions are the main risk here (e.g., two servers
both reading policy-match publishes at different points in the same test
run). Re-run the full binary once more:
```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && ./net_rule_grpc_test 2>&1 | tail -20"
```
Expected: identical pass result. If anything is flaky, investigate before
proceeding to Task 8 — a flaky dual-publish period is a strong signal that
something about the new path's interaction with the old one isn't fully
understood yet.

- [ ] **Step 3: No commit needed**

This task produces no code changes if everything passes — it's a
verification gate. If Step 2 surfaces a real issue, fix it as part of this
task and commit that fix with an appropriate message before moving to
Task 8.

---

## Task 8: Cutover — real port, delete the old C++ implementation

**Files:**
- Modify: `net-policy.cpp` (move `start_event_server` to its correct late
  position, delete `GrpcServer::Start()`/`WireEventBridge` call, delete
  `PostServer::SendMatchMsg`'s old `EventBridge` call, delete
  `PluginContext::onClose`'s old `EventBridge` call)
- Modify: `net-policy.h` (delete `PostServer::event_bridge_`/
  `SetEventBridge`, `DaemonContext::WireEventBridge`)
- Modify: `waf/plugin.h` (delete `PluginRootContext::event_bridge_`/
  `SetEventBridge`/`GetEventBridge`)
- Delete: `grpc/grpc_server.h`, `grpc/grpc_server.cc`
- Delete: `grpc/event_service.h`, `grpc/event_service.cc`
- Delete: `grpc/event_bridge.h`, `grpc/event_bridge.cc`
- Delete: `tests/grpc_event_bridge_test.cc`
- Modify: `tests/grpc_e2e_test.cc` (remove
  `SubscribeEventsStreamReceivesPublishedPolicyMatch` and any
  `GrpcServer`/`EventBridge` fixture wiring it depended on — verify what
  else in that file's fixture is now dead per the same "confirm before
  deleting" discipline Phase 2's cutover task used)
- Modify: `CMakeLists.txt` (remove the deleted files from both source
  lists)

**Interfaces:**
- Consumes: `start_event_server` (Task 4), the dual-publish call sites
  (Tasks 5, 6).

- [ ] **Step 1: Confirm nothing else depends on the C++ `EventBridge`/`GrpcServer`**

Before deleting anything, grep the whole tree for `GrpcServer`,
`EventServiceImpl`, `grpc_bridge::EventBridge`, `GetEventBridge`,
`SetEventBridge`, `WireEventBridge`, `g_grpc_server` — every remaining
reference must be inside the files this step lists for
deletion/modification. If something unexpected turns up, stop and
re-scope this step rather than deleting it out from under a caller this
plan didn't account for.

- [ ] **Step 2: Move `start_event_server` to the correct startup position and switch to the real port**

`net-policy.cpp`'s current startup sequence
(`net-policy.cpp:2555-2610` as of Phase 2's merge) calls
`g_grpc_server.Start()` (the OLD C++ EventService) EARLY — before the Rust
control-dispatch wake-fd setup and before the final `zListenFd` epoll_ctl
registration. This is the same class of bug Phase 2's final review found
and fixed for `start_control_server` (a later fallible step failing would
leave the server thread running against now-destroyed state) — fix it
here too rather than carrying it forward. Replace the block:
```cpp
  // start the gRPC event server (additive -- see grpc/grpc_server.h;
  // raw-socket servers above are untouched); the control service now lives
  // entirely in the Rust ControlService started below.
  ret = g_grpc_server.Start();
  if (ret != 0)
    GOTO_ERROR(err, "failed to start grpc event server.");
  daemon.WireEventBridge(&g_grpc_server.GetEventBridge());
```
by deleting it entirely from this early position, and instead add this
block immediately after the existing `start_control_server` block (which
already sits correctly, as the last fallible step before the main loop):
```cpp
  {
    uint16_t event_port = grpc_bridge::start_event_server(/*port=*/50052);
    if (event_port == 0)
      GOTO_ERROR(err, "failed to start rust event service.");
    LOG_I("rust event service listening on port %d", (int)event_port);
  }
```
The existing `net_policy_events_cxxbridge/lib.h` include (added in Task 5)
already makes `grpc_bridge::start_event_server` visible here.

- [ ] **Step 3: Remove the dual-publish call sites' old halves**

In `net-policy.cpp`'s `PostServer::SendMatchMsg`, delete:
```cpp
  if (event_bridge_)
    event_bridge_->PublishPolicyMatch(tuple, action, dir, rule_key);
```
leaving only the `IsValidUtf8`-guarded Rust call from Task 5. Do the
equivalent in `waf/plugin.cc`'s `PluginContext::onClose`, deleting:
```cpp
  if (auto* eb = root_ctx_->GetEventBridge())
    eb->PublishWafAttack(ruleArr, atlog);
```
leaving only the guarded Rust call from Task 6.

- [ ] **Step 4: Delete the obsolete wiring**

In `net-policy.h`: delete `PostServer::event_bridge_` and
`PostServer::SetEventBridge` (`net-policy.h:446, 450`); delete
`DaemonContext::WireEventBridge` (`net-policy.h:487-490`). In
`waf/plugin.h`: delete `PluginRootContext::event_bridge_`,
`SetEventBridge`, `GetEventBridge` (`waf/plugin.h:50, 61-62`). Remove the
now-unused `namespace grpc_bridge { class EventBridge; ... }` forward
declaration in `net-policy.h:148` if `EventBridge` is no longer referenced
anywhere in that file (check first — `GrpcDispatchQueue`'s forward
declaration on the same line must stay).

- [ ] **Step 5: Delete the old C++ files**

```bash
git rm grpc/grpc_server.h grpc/grpc_server.cc
git rm grpc/event_service.h grpc/event_service.cc
git rm grpc/event_bridge.h grpc/event_bridge.cc
git rm tests/grpc_event_bridge_test.cc
```

- [ ] **Step 6: Update `tests/grpc_e2e_test.cc`**

Read the file's current fixture (`SetUp`/`TearDown`) and delete
`SubscribeEventsStreamReceivesPublishedPolicyMatch` along with any
`GrpcServer`/`EventBridge`-specific setup it required — but first check
whether anything else in that file's shared fixture (e.g., a
`ControlService`-only test also declared in this file) still needs parts
of that same setup for unrelated reasons; if so, keep only what's still
needed, matching the "confirm what's still needed before deleting"
discipline Phase 2's Task 16 used for the analogous `tests/grpc_e2e_test.cc`
cleanup.

- [ ] **Step 7: Update `CMakeLists.txt`**

Remove `grpc/event_bridge.cc`, `grpc/event_service.cc`,
`grpc/grpc_server.cc` from both the `net-rule` (`SOURCES`,
`CMakeLists.txt:93-95`) and `net_rule_grpc_test`
(`CMakeLists.txt:273-275`) source lists. Remove
`tests/grpc_event_bridge_test.cc` from `net_rule_grpc_test`'s source list
(`CMakeLists.txt:277`).

- [ ] **Step 8: Build and run everything**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && ./net_rule_test && ./net_rule_grpc_test"
```
Expected: clean build under `-Wall -Werror`; every remaining test passes,
including `GrpcRustEventsEndToEndTest.*` (now exercising the production
path on the real port 50052) and whatever remains of `GrpcEndToEndTest.*`
after Step 6's cleanup.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "Cut over EventService to the Rust server; delete the old C++ implementation"
```

---

## Definition of Done

- `docker exec net-policy-build-test bash -lc "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc)"` builds
  `net-rule`, `net_rule_test`, and `net_rule_grpc_test` with no new
  warnings under `-Wall -Werror`.
- `./net_rule_test` and `./net_rule_grpc_test` both pass in full.
- `NetPolicyEvents::SubscribeEvents` is served by the Rust `tonic` server
  on port 50052; `NetPolicyControl` (port 50051) is unaffected.
- `grpc/grpc_server.{h,cc}`, `grpc/event_service.{h,cc}`,
  `grpc/event_bridge.{h,cc}`, and `tests/grpc_event_bridge_test.cc` no
  longer exist in the codebase.
- `PostServer` and `PluginRootContext` no longer have any `EventBridge*`
  member, accessor, or wiring — they call directly into
  `grpc_bridge::publish_policy_match`/`publish_waf_attack`.
- `PostServer` (port 8888) and the legacy raw-socket protocol (port 9999)
  are untouched and still function exactly as before this plan.
