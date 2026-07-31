# Phase 2: gRPC ControlService Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the C++ `grpc++`-based `ControlServiceImpl` with a Rust `tonic` server that terminates all 12 `NetPolicyControl` RPCs itself, calling into typed `cxx`-bridge C++ dispatch functions that preserve the existing epoll-thread-only mutation guarantee on `DaemonContext`.

**Architecture:** A new Rust crate (`crates/net_policy_control`) hosts a `tonic` server on its own `tokio` runtime/thread. Each RPC handler converts its request into `cxx`-compatible types, calls a C++ dispatch function via `tokio::task::spawn_blocking` (synchronous, blocks on a new closure-based work queue exactly like today's `EnqueueAndWait` blocks on `ControlWorkQueue`), and converts the result back into the `tonic` response. New code is built and tested independently, on a temporary development port, while the existing C++ `ControlServiceImpl`/`grpc++` path keeps running unaffected until the final cutover task swaps ports and deletes the old implementation.

**Tech Stack:** Rust `tonic` + `prost` + `tokio`, `cxx` (matching the pattern already established by `crates/ffi_smoke` and `crates/waf_rules_core`), existing `proto/net_policy_control.proto`/`net_policy_common.proto` (no `.proto` changes).

## Global Constraints

- No `.proto` changes — `proto/net_policy_control.proto` and `net_policy_common.proto` stay the single source of truth for both the (until-deleted) C++ codegen and the new Rust codegen.
- The shared legacy JSON-based parsing functions (`ParseNetPolicy`, `ParseConfiguration`, `RemoveWafRule`, `handleHeapProfile`, `dumpConnectons`, `ParseNodeCfg`) stay completely untouched — they're still used by the legacy raw-socket protocol, out of scope for this phase.
- `DaemonContext`'s policy/WAF/connection state stays single-writer: touched only from the epoll thread, exactly as today.
- C++ build stays C++17, `-Wall -Werror` for `net-rule`/`net_rule_grpc_test` (existing `CMakeLists.txt` constraint, unchanged by this plan).
- Build/test verification for every task runs inside the `net-policy-build-test` Docker container (bind-mounts the repo root at `/workspace/net-policy`), matching how Phase 0/1 verification worked. Use whichever worktree/checkout path is actually running inside the container for your session.
- Every Read/Edit/Write tool call in every dispatched task MUST use a full absolute path — never a bare relative filename. Multiple Phase 0/1 tasks lost work to subagents using relative paths that resolved against the wrong directory.
- KNOWN ENVIRONMENT QUIRK (recurred several times in Phase 0/1): the Docker container's bind mount has occasionally served a stale/truncated version of a just-edited file, causing a confusing compile error that doesn't match the real file content. If a compile error doesn't match what was actually written, try `docker restart net-policy-build-test` and retry before assuming the edit is wrong.
- Rollout is a single cutover (Task 16): the new Rust server and the old C++ `ControlServiceImpl` cannot both serve production traffic on port 50051 simultaneously, since gRPC's one-service-one-implementation-per-port model doesn't allow per-RPC incremental hosting. All RPC tasks before Task 16 build and test the new implementation on a temporary development port (`kNetPolicyControlDevPort = 50053`) without touching the still-running old path.

---

## File Structure

New files:
- `crates/net_policy_control/Cargo.toml`, `crates/net_policy_control/build.rs`, `crates/net_policy_control/src/lib.rs` — the new Rust crate.
- `grpc/control_dispatch.h`, `grpc/control_dispatch.cc` — `GrpcDispatchItem`/`GrpcDispatchQueue` (the new closure-based work queue) and the declarations of the 12 Rust-callable typed dispatch functions.
- `tests/grpc_rust_control_e2e_test.cc` — new E2E test suite targeting the Rust server, modeled on the existing `tests/grpc_e2e_test.cc`.

Modified files:
- `Cargo.toml` — add the new workspace member.
- `CMakeLists.txt` — `corrosion_add_cxxbridge` for the new crate; link into `net-rule` and the new test target.
- `net-policy.h` — add `DaemonContext::WireRustControlDispatch`/`RustControlDispatchQueue()`, mirroring the existing `WireGrpc`/`ControlWorkQueue()` pattern.
- `net-policy.cpp` — implement the 12 dispatch functions (mirroring `DispatchGrpcControlOp`'s per-case logic) and `DispatchGrpcRustQueueEvent`; wire startup in `RunNetPolicyDaemon` (Tasks 4-15 add pieces incrementally; Task 16 does the final port swap and deletes the old path).

Deleted in Task 16: `grpc/control_service.h`, `grpc/control_service.cc`, the `ControlOp` enum and old `ControlWorkItem`/`ControlWorkQueue` (`grpc/work_queue.h/.cc`, if `EventService` doesn't need them — verified in Task 16), `DispatchGrpcControlOp`, the `BuildXxxJson`/`ConvertXxxCJsonToProto` functions in `grpc/proto_json_bridge.cc` that only `ControlServiceImpl` used.

---

## Task 1: Scaffold the `net_policy_control` Rust crate with tonic/prost codegen

**Files:**
- Create: `crates/net_policy_control/Cargo.toml`
- Create: `crates/net_policy_control/build.rs`
- Create: `crates/net_policy_control/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

**Interfaces:**
- Produces: the crate compiles standalone (`cargo build -p net_policy_control`) and exposes the `tonic`/`prost`-generated Rust types for every message in `net_policy_control.proto`/`net_policy_common.proto` (no service implementation yet — that starts in Task 4).

- [ ] **Step 1: Add the crate to the workspace**

Modify `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["crates/ffi_smoke", "crates/waf_rules_core", "crates/net_policy_control"]
```

- [ ] **Step 2: Crate manifest**

Create `crates/net_policy_control/Cargo.toml`:

```toml
[package]
name = "net_policy_control"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
cxx = "1"
tonic = "0.11"
prost = "0.12"
tokio = { version = "1", features = ["rt-multi-thread", "sync"] }

[build-dependencies]
tonic-build = "0.11"
```

- [ ] **Step 3: build.rs codegen**

Create `crates/net_policy_control/build.rs`:

```rust
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
```

`--build_client(false)` is set because this crate only ever implements the server side; nothing in this repo needs a Rust gRPC client for this service. `tonic_build::configure().compile(...)` needs a `protoc` binary discoverable on `PATH` (or via the `PROTOC` env var) — the same one the existing C++ CMake build already requires and installs, so no new dependency should be needed inside the `net-policy-build-test` container. If codegen fails with a "protoc not found"-style error in Step 4 below, set `PROTOC=$(which protoc)` in the environment before running `cargo build` and note that in the report.

- [ ] **Step 4: Bridge module skeleton**

Create `crates/net_policy_control/src/lib.rs`:

```rust
pub mod proto {
    tonic::include_proto!("netpolicy.v1");
}
```

- [ ] **Step 5: Verify it builds**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo build -p net_policy_control"
```

Expected: succeeds, no errors. If `protoc` isn't found, retry with `PROTOC=$(which protoc) cargo build -p net_policy_control` and use that prefix in all subsequent `cargo build`/`cargo test` invocations for this crate throughout this plan.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/net_policy_control
git commit -m "Scaffold net_policy_control crate with tonic/prost codegen"
```

---

## Task 2: New closure-based dispatch queue (`GrpcDispatchItem`/`GrpcDispatchQueue`)

Pure C++, no Rust involved yet. This is the new work queue the 12 dispatch functions (Tasks 4-15) will push onto; it replaces the old `ControlWorkItem`/`ControlWorkQueue`'s protobuf-`Message*`-based shape (which can't cross the `cxx` boundary) with a `std::function<void()>` closure, so each dispatch function can capture whatever typed locals it needs.

**Files:**
- Create: `grpc/control_dispatch.h`
- Create: `grpc/control_dispatch.cc`
- Modify: `CMakeLists.txt` (add both new files to the `net-rule` and `net_rule_grpc_test` source lists)

**Interfaces:**
- Produces: `grpc_bridge::GrpcDispatchItem { std::function<void()> work; std::promise<void> done; }`, `grpc_bridge::GrpcDispatchQueue` with `explicit GrpcDispatchQueue(int wake_fd)`, `void Push(GrpcDispatchItem*)`, `std::vector<GrpcDispatchItem*> DrainAll()` — used by Task 4 onward's dispatch functions and by `DispatchGrpcRustQueueEvent` (Task 4).

- [ ] **Step 1: Write the header**

Create `grpc/control_dispatch.h`:

```cpp
#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <vector>

class DaemonContext; // forward declaration; full type in net-policy.h

namespace grpc_bridge {

/*One item per inbound Rust-originated control RPC. Allocated on the calling
 *(Rust/tokio blocking) thread's stack, pushed onto the queue by pointer, and
 *run only by the epoll thread (via DispatchGrpcRustQueueEvent in
 *net-policy.cpp) until `done` is fulfilled -- mirrors ControlWorkItem's
 *existing single-writer contract in grpc/work_queue.h, just with a closure
 *instead of a protobuf Message* (which can't cross the cxx boundary).*/
struct GrpcDispatchItem {
  std::function<void()> work;
  std::promise<void> done;
};

/*Thread-safe multi-producer/single-consumer queue: any number of tokio
 *blocking threads call Push(); exactly one consumer (the epoll loop, woken
 *via the eventfd passed at construction) calls DrainAll(). Mirrors
 *ControlWorkQueue's existing shape in grpc/work_queue.h exactly.*/
class GrpcDispatchQueue {
public:
  explicit GrpcDispatchQueue(int wake_fd);

  void Push(GrpcDispatchItem* item);        // calling (tokio blocking) thread
  std::vector<GrpcDispatchItem*> DrainAll(); // epoll thread only

private:
  int wake_fd_;
  std::mutex mutex_;
  std::deque<GrpcDispatchItem*> queue_;
};

} // namespace grpc_bridge
```

- [ ] **Step 2: Write the implementation**

Create `grpc/control_dispatch.cc`:

```cpp
#include "grpc/control_dispatch.h"

#include <sys/eventfd.h>
#include <unistd.h>

namespace grpc_bridge {

GrpcDispatchQueue::GrpcDispatchQueue(int wake_fd) : wake_fd_(wake_fd) {}

void GrpcDispatchQueue::Push(GrpcDispatchItem* item) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push_back(item);
  }
  uint64_t one = 1;
  ssize_t written = write(wake_fd_, &one, sizeof(one));
  (void)written; // best-effort wake; DrainAll's caller polls on a timeout regardless
}

std::vector<GrpcDispatchItem*> GrpcDispatchQueue::DrainAll() {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<GrpcDispatchItem*> drained(queue_.begin(), queue_.end());
  queue_.clear();
  return drained;
}

} // namespace grpc_bridge
```

- [ ] **Step 3: Wire into CMake**

In `CMakeLists.txt`, add `grpc/control_dispatch.cc` to the `SOURCES` list (near the other `grpc/*.cc` entries, around where `grpc/work_queue.cc` is listed) and to `net_rule_grpc_test`'s source list (same place its sibling `grpc/work_queue.cc` appears).

- [ ] **Step 4: Verify it builds**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j\$(nproc) net-rule 2>&1 | tail -60"
```

Expected: builds cleanly (nothing calls the new code yet, so this only proves it compiles and links).

- [ ] **Step 5: Commit**

```bash
git add grpc/control_dispatch.h grpc/control_dispatch.cc CMakeLists.txt
git commit -m "Add closure-based GrpcDispatchQueue for the Rust ControlService bridge"
```

---

## Task 3: Wire the crate into CMake via Corrosion

**Files:**
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `crates/net_policy_control` (Task 1), already a member of the Cargo workspace `corrosion_import_crate` already imports (set up in Phase 0).
- Produces: CMake target `net_policy_control_cxxbridge`, to be linked into `net-rule` and `net_rule_grpc_test` (Task 4 onward needs it once the bridge module has real content).

- [ ] **Step 1: Add the cxxbridge target**

In `CMakeLists.txt`, add next to the existing `ffi_smoke_cxxbridge`/`waf_rules_core_cxxbridge` blocks:

```cmake
corrosion_add_cxxbridge(net_policy_control_cxxbridge
  CRATE net_policy_control
  FILES lib.rs
)
```

`corrosion_import_crate(MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml)` (already present from Phase 0) automatically picks up the new workspace member — no change needed there.

- [ ] **Step 2: Link into `net-rule` and `net_rule_grpc_test`**

Add `net_policy_control_cxxbridge` to both targets' `target_link_libraries` calls, alongside the existing `waf_rules_core_cxxbridge` entries.

- [ ] **Step 3: Verify it builds**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j\$(nproc) net-rule net_rule_grpc_test 2>&1 | tail -80"
```

Expected: both build cleanly. The bridge module in `lib.rs` is still just the `proto` module from Task 1 (no `#[cxx::bridge]` yet), so `corrosion_add_cxxbridge` generates an essentially-empty header at this point — that's expected; this task only proves the CMake wiring itself is correct.

- [ ] **Step 4: Commit**

```bash
git add CMakeLists.txt
git commit -m "Wire net_policy_control into CMake via Corrosion"
```

---

## Task 4: First RPC end-to-end — `ResetConfig`

This is the foundational task: it proves the whole new pipeline works (Rust `tonic` server standing up on its own thread, a `cxx` call from Rust into C++, the new closure-based queue waking the epoll thread, the response round-tripping back through `tonic`) using the simplest possible RPC (`ResetConfig` takes no request fields at all). Every later RPC task follows the exact pattern this one establishes.

**Files:**
- Modify: `grpc/control_dispatch.h`, `grpc/control_dispatch.cc` (add `GrpcDispatchResetConfig` and `DispatchGrpcRustQueueEvent`)
- Modify: `net-policy.h` (add `DaemonContext::WireRustControlDispatch`/`RustControlDispatchQueue()`)
- Modify: `net-policy.cpp` (implement `GrpcDispatchResetConfig`; wire startup in `RunNetPolicyDaemon`)
- Modify: `crates/net_policy_control/src/lib.rs` (the `#[cxx::bridge]` module, `start_control_server`, the `ControlServiceImpl` struct with its first method)
- Modify: `crates/net_policy_control/Cargo.toml` (no change needed — deps already added in Task 1)
- Create: `tests/grpc_rust_control_e2e_test.cc`
- Modify: `CMakeLists.txt` (add the new test file to `net_rule_grpc_test`'s sources)

**Interfaces:**
- Produces (C++, callable from Rust via `cxx`): `int32_t grpc_bridge::GrpcDispatchResetConfig(DaemonContext* daemon, grpc_bridge::GrpcDispatchQueue* queue);` — returns the same status code `Rules::ClearCfg()`/`MicroSegEngine::ClearCfg()` returns today.
- Produces (Rust, callable from C++ via `cxx`): `fn start_control_server(daemon: *mut DaemonContext, queue: *mut GrpcDispatchQueue, epoll_fd: i32, dev_port: u16) -> u16;` — starts the `tonic` server on a background thread, returns the actually-bound port (0 on failure). `epoll_fd` is threaded through even though `ResetConfig` itself doesn't need it, because `GrpcDispatchPodUp` (Task 5) does — see that task for why it can't be obtained any other way.
- Later RPC tasks add one `GrpcDispatchXxx` function to `control_dispatch.h`/`.cc` + `net-policy.cpp`, one `ffi` bridge declaration, and one `ControlServiceImpl` method in `lib.rs`, following this exact shape.

- [ ] **Step 1: Extend `DaemonContext` (net-policy.h)**

Modify `net-policy.h`'s `DaemonContext` class. Find the existing `WireGrpc` method and `control_work_queue_` field (around where `grpc_bridge::ControlWorkQueue* control_work_queue_` is declared) and add alongside them:

```cpp
  /*non-owning; wired once at startup, mirrors WireGrpc's existing pattern
   *exactly -- see grpc/control_dispatch.h for GrpcDispatchQueue.*/
  void WireRustControlDispatch(grpc_bridge::GrpcDispatchQueue* q) { rust_dispatch_queue_ = q; }
  grpc_bridge::GrpcDispatchQueue* RustControlDispatchQueue() { return rust_dispatch_queue_; }
```

and add the forward declaration + member field near the existing `control_work_queue_` declaration:

```cpp
  grpc_bridge::GrpcDispatchQueue* rust_dispatch_queue_ = nullptr; // non-owning
```

Add `namespace grpc_bridge { class ControlWorkQueue; class EventBridge; class GrpcDispatchQueue; }` — extend the existing forward-declaration line (search for the existing `namespace grpc_bridge { class ControlWorkQueue; class EventBridge; }` line and add `class GrpcDispatchQueue;` to it).

- [ ] **Step 2: Add `GrpcDispatchResetConfig` and the epoll callback declaration**

Modify `grpc/control_dispatch.h`, adding after the `GrpcDispatchQueue` class (still inside `namespace grpc_bridge`):

```cpp
// Rust-callable dispatch functions. Each builds a closure capturing `daemon`
// by pointer, pushes it onto `queue`, blocks until the epoll thread
// (DispatchGrpcRustQueueEvent, net-policy.cpp) has run it, and returns the
// typed result. Implemented in net-policy.cpp, where DaemonContext's full
// definition and the legacy policy/WAF functions are already visible --
// mirrors where DispatchGrpcControlOp lives today.
int32_t GrpcDispatchResetConfig(DaemonContext* daemon, GrpcDispatchQueue* queue);

// Epoll callback (RcvCbFunc-shaped: int32_t(int32_t epoll_fd, int32_t fd,
// void* ptr)) for the Rust dispatch queue's wake eventfd. Drains `queue`
// (read from the registering RcvEpollCb, threaded through via `ptr`) and
// runs each item's closure on this (the epoll) thread. Implemented in
// net-policy.cpp since it needs RcvEpollCb's shape from net-policy.h.
int32_t DispatchGrpcRustQueueEvent(int32_t epoll_fd, int32_t fd, void* ptr);
```

- [ ] **Step 3: Implement `GrpcDispatchResetConfig` and `DispatchGrpcRustQueueEvent` (net-policy.cpp)**

Find `DispatchGrpcControlOp`'s `kResetConfig` case (`ret = daemon.Microseg().ClearCfg(); resp->set_status(ret);`) for reference, then add near it (or near `DispatchGrpcWorkQueueEvent`, whichever reads more naturally in context):

```cpp
namespace grpc_bridge {

int32_t GrpcDispatchResetConfig(DaemonContext* daemon, GrpcDispatchQueue* queue) {
  GrpcDispatchItem item;
  int32_t result = 1; // fail-closed default if the closure never runs
  item.work = [&]() {
    result = daemon->Microseg().ClearCfg();
  };
  std::future<void> future = item.done.get_future();
  queue->Push(&item);
  future.wait();
  return result;
}

int32_t DispatchGrpcRustQueueEvent(int32_t epoll_fd, int32_t fd, void* ptr) {
  (void)epoll_fd;
  auto* cb = static_cast<RcvEpollCb*>(ptr);
  GrpcDispatchQueue* queue = cb->daemon_->RustControlDispatchQueue();
  uint64_t drain;
  while (read(fd, &drain, sizeof(drain)) > 0) {
  }
  for (auto* item : queue->DrainAll()) {
    item->work();
    item->done.set_value();
  }
  return 0;
}

} // namespace grpc_bridge
```

Add `#include "grpc/control_dispatch.h"` near `net-policy.cpp`'s existing `#include "grpc/work_queue.h"`.

- [ ] **Step 4: Wire startup in `RunNetPolicyDaemon`**

Find where `g_grpc_server.Start()` / `daemon.WireGrpc(...)` / the `grpcWakeEvent` registration happens (around `net-policy.cpp:2285-2296`). Add, right after that block:

```cpp
  // --- Rust ControlService bridge (additive during Phase 2 development --
  // temporary dev port; production cutover happens in a later change) ---
  int rust_dispatch_wake_fd = eventfd(0, EFD_NONBLOCK);
  if (rust_dispatch_wake_fd < 0)
    GOTO_ERROR(err, "create rust control dispatch eventfd failed, %s.", strerror(errno));
  static grpc_bridge::GrpcDispatchQueue rust_dispatch_queue(rust_dispatch_wake_fd);
  daemon.WireRustControlDispatch(&rust_dispatch_queue);

  RCV_EPOLL_CB rustDispatchWakeEvent;
  rustDispatchWakeEvent.fd_ = rust_dispatch_wake_fd;
  rustDispatchWakeEvent.epoll_in_func_ = grpc_bridge::DispatchGrpcRustQueueEvent;
  rustDispatchWakeEvent.daemon_ = &daemon;
  ev.data.ptr = &rustDispatchWakeEvent;
  ev.events = EPOLLIN;
  ret = epoll_ctl(epfd, EPOLL_CTL_ADD, rust_dispatch_wake_fd, &ev);
  if (ret < 0)
    GOTO_ERROR(err, "epoll ctl failed for rust control dispatch wake fd, %s.", strerror(errno));

  {
    uint16_t bound_port = grpc_bridge::start_control_server(&daemon, &rust_dispatch_queue, epfd, /*dev_port=*/50053);
    if (bound_port == 0)
      GOTO_ERROR(err, "failed to start rust control service.");
    LOG_I("rust control service listening on port %d (dev)", (int)bound_port);
  }
```

`static grpc_bridge::GrpcDispatchQueue rust_dispatch_queue(...)` uses `static` storage duration (not stack-local like `daemon`/`g_grpc_server`) specifically because `rustDispatchWakeEvent` is itself a stack-local `RCV_EPOLL_CB` that goes out of scope at the end of this setup block in the existing code's style (matching `grpcWakeEvent`'s existing declaration) — but the pointer stored in `daemon`/registered with epoll must remain valid for the life of the process. Follow whatever pattern the existing `grpcWakeEvent`/`unixEvent`/`postEvent` locals actually use in the surrounding code (they appear to be declared together near the top of `RunNetPolicyDaemon` as `RCV_EPOLL_CB unixEvent, postEvent, grpcWakeEvent, *pstCbEv;` and live for the whole function) — add `rustDispatchWakeEvent` to that same declaration line instead of introducing a new local scoped only to this block, so its lifetime matches the others exactly. Adjust the snippet above accordingly when implementing.

`#include "grpc/control_dispatch.h"` and `#include "net_policy_control_cxxbridge/lib.h"` (or whatever the generated include path actually is — verify against the build output, following the pattern discovered in Phase 0 Task 4, where Corrosion names the header after the cxxbridge target, e.g. `waf_rules_core_cxxbridge/lib.h`) need to be added to `net-policy.cpp`'s includes.

- [ ] **Step 5: Rust bridge module and service implementation**

Replace `crates/net_policy_control/src/lib.rs` with:

```rust
pub mod proto {
    tonic::include_proto!("netpolicy.v1");
}

use proto::net_policy_control_server::{NetPolicyControl, NetPolicyControlServer};
use proto::{ResetConfigRequest, StatusResponse};
use std::sync::OnceLock;
use tonic::{transport::Server, Request, Response, Status};

#[cxx::bridge(namespace = "grpc_bridge")]
mod ffi {
    unsafe extern "C++" {
        include!("grpc/control_dispatch.h");

        type DaemonContext;
        type GrpcDispatchQueue;

        fn GrpcDispatchResetConfig(daemon: *mut DaemonContext, queue: *mut GrpcDispatchQueue) -> i32;
    }

    extern "Rust" {
        fn start_control_server(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            epoll_fd: i32,
            dev_port: u16,
        ) -> u16;
    }
}

/*Raw pointers into C++-owned, process-lifetime state (DaemonContext and the
 *dispatch queue), set once when the server starts. Safe to share across the
 *tokio worker threads that call into ffi::GrpcDispatchXxx: the pointers
 *themselves never change after start_control_server returns, and everything
 *they point at is either read-only from Rust's perspective or mutated only
 *on the C++ epoll thread inside the dispatch closures -- Rust never touches
 *DaemonContext's fields directly.*/
struct ServerState {
    daemon: usize, // DaemonContext* as usize; see with_daemon()/with_queue() below
    queue: usize,
    #[allow(dead_code)]
    epoll_fd: i32,
}
unsafe impl Send for ServerState {}
unsafe impl Sync for ServerState {}

static STATE: OnceLock<ServerState> = OnceLock::new();

fn daemon_ptr() -> *mut ffi::DaemonContext {
    STATE.get().expect("server state not initialized").daemon as *mut ffi::DaemonContext
}
fn queue_ptr() -> *mut ffi::GrpcDispatchQueue {
    STATE.get().expect("server state not initialized").queue as *mut ffi::GrpcDispatchQueue
}

struct ControlServiceImpl;

#[tonic::async_trait]
impl NetPolicyControl for ControlServiceImpl {
    async fn reset_config(
        &self,
        _request: Request<ResetConfigRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let status = tokio::task::spawn_blocking(|| unsafe {
            ffi::GrpcDispatchResetConfig(daemon_ptr(), queue_ptr())
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }
}

fn start_control_server(
    daemon: *mut ffi::DaemonContext,
    queue: *mut ffi::GrpcDispatchQueue,
    epoll_fd: i32,
    dev_port: u16,
) -> u16 {
    STATE
        .set(ServerState { daemon: daemon as usize, queue: queue as usize, epoll_fd })
        .unwrap_or_else(|_| panic!("start_control_server called more than once"));

    let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
        rt.block_on(async move {
            let addr = format!("0.0.0.0:{dev_port}").parse().expect("invalid bind address");
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
                .add_service(NetPolicyControlServer::new(ControlServiceImpl))
                .serve_with_incoming(incoming)
                .await;
        });
    });
    port_rx.recv().unwrap_or(0)
}
```

This needs one more dependency: add `tokio-stream = "0.1"` to `crates/net_policy_control/Cargo.toml`'s `[dependencies]` (needed for `serve_with_incoming`, which lets us bind the listener ourselves and read back the actual port — required since `dev_port` may be `0` in tests and `Server::builder().serve(addr)` alone doesn't hand back the OS-assigned port).

- [ ] **Step 6: Write the E2E test**

Create `tests/grpc_rust_control_e2e_test.cc`:

```cpp
#include <chrono>
#include <thread>

#include <gtest/gtest.h>
#include <grpcpp/grpcpp.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "grpc/control_dispatch.h"
#include "net-policy.h"
#include "net_policy_control_cxxbridge/lib.h"
#include "proto/net_policy_control.grpc.pb.h"

namespace {

class GrpcRustControlEndToEndTest : public ::testing::Test {
protected:
  void SetUp() override {
    epfd_ = epoll_create(32);
    ASSERT_GT(epfd_, 0);

    wake_fd_ = eventfd(0, EFD_NONBLOCK);
    ASSERT_GT(wake_fd_, 0);
    queue_ = std::make_unique<grpc_bridge::GrpcDispatchQueue>(wake_fd_);
    daemon_.WireRustControlDispatch(queue_.get());

    wake_cb_.fd_ = wake_fd_;
    wake_cb_.epoll_in_func_ = grpc_bridge::DispatchGrpcRustQueueEvent;
    wake_cb_.daemon_ = &daemon_;
    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.ptr = &wake_cb_;
    ASSERT_EQ(epoll_ctl(epfd_, EPOLL_CTL_ADD, wake_fd_, &ev), 0);

    stop_ = false;
    loop_thread_ = std::thread([this] { RunEpollLoop(); });

    uint16_t port = grpc_bridge::start_control_server(&daemon_, queue_.get(), epfd_, /*dev_port=*/0);
    ASSERT_NE(port, 0) << "rust control server failed to bind";

    auto channel = grpc::CreateChannel("localhost:" + std::to_string(port),
                                        grpc::InsecureChannelCredentials());
    stub_ = netpolicy::v1::NetPolicyControl::NewStub(channel);
  }

  void TearDown() override {
    stop_ = true;
    if (loop_thread_.joinable())
      loop_thread_.join();
    if (epfd_ > 0)
      close(epfd_);
  }

  void RunEpollLoop() {
    struct epoll_event events[8];
    while (!stop_) {
      int nfds = epoll_wait(epfd_, events, 8, /*timeout_ms=*/50);
      for (int i = 0; i < nfds; i++) {
        auto* cb = static_cast<RCV_EPOLL_CB*>(events[i].data.ptr);
        if (cb && cb->epoll_in_func_)
          cb->epoll_in_func_(epfd_, cb->fd_, cb);
      }
    }
  }

  int epfd_ = -1;
  int wake_fd_ = -1;
  RCV_EPOLL_CB wake_cb_ = {};
  DaemonContext daemon_;
  std::unique_ptr<grpc_bridge::GrpcDispatchQueue> queue_;
  std::atomic<bool> stop_{false};
  std::thread loop_thread_;
  std::unique_ptr<netpolicy::v1::NetPolicyControl::Stub> stub_;
};

TEST_F(GrpcRustControlEndToEndTest, ResetConfigReturnsOkStatus) {
  grpc::ClientContext ctx;
  netpolicy::v1::ResetConfigRequest req;
  netpolicy::v1::StatusResponse resp;
  grpc::Status status = stub_->ResetConfig(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_EQ(resp.status(), 0);
}

} // namespace
```

Note: the test gives the C++ epoll loop, the Rust `tokio` runtime, and the gRPC transport all a moment to actually be ready before the first RPC — if this test is flaky in practice (rare race between `start_control_server` returning and `serve_with_incoming` actually accepting connections), add a short `std::this_thread::sleep_for(std::chrono::milliseconds(50));` after `SetUp`'s channel creation, matching the existing `grpc_e2e_test.cc`'s streaming-test precedent of a brief sleep after starting a background operation.

- [ ] **Step 7: Wire into CMake**

Add `tests/grpc_rust_control_e2e_test.cc` to `net_rule_grpc_test`'s source list.

- [ ] **Step 8: Build and run**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j\$(nproc) net-rule net_rule_grpc_test 2>&1 | tail -100"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter=GrpcRustControlEndToEndTest.*"
```

Expected: build succeeds; `ResetConfigReturnsOkStatus` passes.

- [ ] **Step 9: Run the full existing suite to confirm no regression**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_test && ./net_rule_grpc_test"
```

Expected: all prior tests still pass, plus the new one.

- [ ] **Step 10: Commit**

```bash
git add net-policy.h net-policy.cpp grpc/control_dispatch.h grpc/control_dispatch.cc \
        crates/net_policy_control/src/lib.rs crates/net_policy_control/Cargo.toml \
        tests/grpc_rust_control_e2e_test.cc CMakeLists.txt
git commit -m "First Rust ControlService RPC end-to-end: ResetConfig"
```

---

## Task 5: `PodUp`

**Files:**
- Modify: `grpc/control_dispatch.h`, `grpc/control_dispatch.cc` — wait, `.cc` doesn't currently hold dispatch function bodies (they're in `net-policy.cpp` per Task 4's Step 3) — modify `net-policy.cpp` instead.
- Modify: `net-policy.cpp` (add `GrpcDispatchPodUp`)
- Modify: `grpc/control_dispatch.h` (declare `GrpcDispatchPodUp`)
- Modify: `crates/net_policy_control/src/lib.rs` (bridge declaration + `pod_up` method)
- Modify: `tests/grpc_rust_control_e2e_test.cc` (new test case)

**Interfaces:**
- Consumes: `epoll_fd` — threaded through from `start_control_server`'s existing `epoll_fd: i32` parameter (added in Task 4 specifically for this RPC; `ResetConfig` didn't need it, `PodUp` does, since the legacy `InitNfqueue(epoll_fd, ctrl, daemon)` call needs it).
- Produces: `int32_t grpc_bridge::GrpcDispatchPodUp(DaemonContext* daemon, GrpcDispatchQueue* queue, int32_t epoll_fd, int32_t pid, uint64_t pod_id);`

- [ ] **Step 1: Declare in `grpc/control_dispatch.h`**

Add next to `GrpcDispatchResetConfig`'s declaration:

```cpp
int32_t GrpcDispatchPodUp(DaemonContext* daemon, GrpcDispatchQueue* queue, int32_t epoll_fd,
                           int32_t pid, uint64_t pod_id);
```

- [ ] **Step 2: Implement in `net-policy.cpp`**

Reference `DispatchGrpcControlOp`'s `kPodUp` case for the exact logic to preserve (`SetNs`, `InitNfqueue`, `WriteIptableRule`). Add next to `GrpcDispatchResetConfig`:

```cpp
int32_t GrpcDispatchPodUp(DaemonContext* daemon, GrpcDispatchQueue* queue, int32_t epoll_fd,
                           int32_t pid, uint64_t pod_id) {
  GrpcDispatchItem item;
  int32_t result = 1;
  item.work = [&]() {
    NET_CTRL_INFO ctrl = {};
    ctrl.pid_ = pid;
    ctrl.pod_id_ = pod_id;
    int ret = SetNs(ctrl.pid_, const_cast<char*>(kBasePath.data()));
    if (ret == 0) {
      ret = InitNfqueue(epoll_fd, ctrl, *daemon);
      if (ret == 0)
        WriteIptableRule(1, 1, daemon->IptablesVersion(), daemon->WafEnabled());
    }
    result = ret;
  };
  std::future<void> future = item.done.get_future();
  queue->Push(&item);
  future.wait();
  return result;
}
```

Note the pre-existing asymmetry already flagged in `DispatchGrpcControlOp`'s own comment (it never restores the net namespace via `SetLocalNetNs` afterward, unlike the raw-socket path) — preserve that as-is; it's out of scope to fix here.

- [ ] **Step 3: Rust bridge declaration and handler**

In `crates/net_policy_control/src/lib.rs`, add to the `unsafe extern "C++"` block:

```rust
        fn GrpcDispatchPodUp(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            epoll_fd: i32,
            pid: i32,
            pod_id: u64,
        ) -> i32;
```

Add `use proto::PodUpRequest;` to the existing `use proto::{...}` line, and add to the `impl NetPolicyControl for ControlServiceImpl` block:

```rust
    async fn pod_up(
        &self,
        request: Request<PodUpRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let epoll_fd = STATE.get().expect("server state not initialized").epoll_fd;
        let status = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchPodUp(daemon_ptr(), queue_ptr(), epoll_fd, req.pid, req.pod_id)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }
```

(This is also why `ServerState.epoll_fd` was kept, not `#[allow(dead_code)]`-suppressed away — remove that attribute now that it has a real use.)

- [ ] **Step 4: Add the test case**

In `tests/grpc_rust_control_e2e_test.cc`, add:

```cpp
TEST_F(GrpcRustControlEndToEndTest, PodUpWithInvalidPidReturnsNonZeroStatus) {
  // A pid that doesn't exist makes SetNs fail deterministically without
  // requiring real container/netns setup in a test environment.
  grpc::ClientContext ctx;
  netpolicy::v1::PodUpRequest req;
  req.set_pid(999999);
  req.set_pod_id(1);
  netpolicy::v1::StatusResponse resp;
  grpc::Status status = stub_->PodUp(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_NE(resp.status(), 0);
}
```

- [ ] **Step 5: Build and run**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j\$(nproc) net-rule net_rule_grpc_test 2>&1 | tail -100"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter=GrpcRustControlEndToEndTest.*"
```

Expected: both `ResetConfigReturnsOkStatus` and `PodUpWithInvalidPidReturnsNonZeroStatus` pass.

- [ ] **Step 6: Commit**

```bash
git add net-policy.cpp grpc/control_dispatch.h crates/net_policy_control/src/lib.rs tests/grpc_rust_control_e2e_test.cc
git commit -m "Add PodUp RPC to the Rust ControlService"
```

---

## Task 6: `PodDown`

**Files:** same shape as Task 5 (`grpc/control_dispatch.h`, `net-policy.cpp`, `crates/net_policy_control/src/lib.rs`, `tests/grpc_rust_control_e2e_test.cc`).

**Interfaces:**
- Produces: `int32_t grpc_bridge::GrpcDispatchPodDown(DaemonContext* daemon, GrpcDispatchQueue* queue, int32_t epoll_fd, uint64_t pod_id);` (needs `epoll_fd` too — `DeleteNfQueRes(epoll_fd, pod_id)` takes it, per `DispatchGrpcControlOp`'s `kPodDown` case).

- [ ] **Step 1: Declare and implement**

`grpc/control_dispatch.h`:
```cpp
int32_t GrpcDispatchPodDown(DaemonContext* daemon, GrpcDispatchQueue* queue, int32_t epoll_fd,
                             uint64_t pod_id);
```

`net-policy.cpp` (reference `DispatchGrpcControlOp`'s `kPodDown` case):
```cpp
int32_t GrpcDispatchPodDown(DaemonContext* daemon, GrpcDispatchQueue* queue, int32_t epoll_fd,
                             uint64_t pod_id) {
  GrpcDispatchItem item;
  int32_t result = 1;
  item.work = [&]() {
    result = daemon->Microseg().DeleteNfQueRes(epoll_fd, pod_id);
  };
  std::future<void> future = item.done.get_future();
  queue->Push(&item);
  future.wait();
  return result;
}
```

- [ ] **Step 2: Rust bridge declaration and handler**

`lib.rs`, `unsafe extern "C++"` block:
```rust
        fn GrpcDispatchPodDown(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            epoll_fd: i32,
            pod_id: u64,
        ) -> i32;
```

`use proto::PodDownRequest;` added to the existing `use` line; new method:
```rust
    async fn pod_down(
        &self,
        request: Request<PodDownRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let epoll_fd = STATE.get().expect("server state not initialized").epoll_fd;
        let status = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchPodDown(daemon_ptr(), queue_ptr(), epoll_fd, req.pod_id)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }
```

- [ ] **Step 3: Add the test case**

```cpp
TEST_F(GrpcRustControlEndToEndTest, PodDownForUnknownPodReturnsNonZeroStatus) {
  grpc::ClientContext ctx;
  netpolicy::v1::PodDownRequest req;
  req.set_pod_id(999999);
  netpolicy::v1::StatusResponse resp;
  grpc::Status status = stub_->PodDown(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_NE(resp.status(), 0);
}
```

- [ ] **Step 4: Build, run, commit** (same commands as Task 5 Steps 5-6, filtering/adding this test name; commit message: "Add PodDown RPC to the Rust ControlService")

---

## Task 7: `DeletePolicyRule`

**Interfaces:**
- Produces: `int32_t grpc_bridge::GrpcDispatchDeletePolicyRule(DaemonContext* daemon, GrpcDispatchQueue* queue, rust::Str policy_name);` — first RPC in this plan needing a string parameter across the boundary; `rust::Str` implicitly converts from Rust `&str`, and on the C++ side converts to `std::string` via `std::string(policy_name)` (matching the conversion pattern already established in Phase 1's `waf/rule.cc`).

- [ ] **Step 1: Declare and implement**

`grpc/control_dispatch.h` — this file doesn't currently include `<rust/cxx.h>`; add `#include "rust/cxx.h"` near the top (needed for the `rust::Str` type in this and later string-taking declarations):

```cpp
int32_t GrpcDispatchDeletePolicyRule(DaemonContext* daemon, GrpcDispatchQueue* queue,
                                      rust::Str policy_name);
```

`net-policy.cpp` (reference `DispatchGrpcControlOp`'s `kDeletePolicyRule` case, which calls the free function `DeletePolicy(policy_name, daemon)`):
```cpp
int32_t GrpcDispatchDeletePolicyRule(DaemonContext* daemon, GrpcDispatchQueue* queue,
                                      rust::Str policy_name) {
  GrpcDispatchItem item;
  int32_t result = 1;
  std::string name(policy_name);
  item.work = [&]() {
    result = DeletePolicy(name, *daemon);
  };
  std::future<void> future = item.done.get_future();
  queue->Push(&item);
  future.wait();
  return result;
}
```

- [ ] **Step 2: Rust bridge declaration and handler**

```rust
        fn GrpcDispatchDeletePolicyRule(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            policy_name: &str,
        ) -> i32;
```

`use proto::DeletePolicyRuleRequest;` added; new method:
```rust
    async fn delete_policy_rule(
        &self,
        request: Request<DeletePolicyRuleRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let status = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchDeletePolicyRule(daemon_ptr(), queue_ptr(), &req.policy_name)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }
```

- [ ] **Step 3: Add the test case**

```cpp
TEST_F(GrpcRustControlEndToEndTest, DeletePolicyRuleForUnknownNameReturnsNonZeroStatus) {
  grpc::ClientContext ctx;
  netpolicy::v1::DeletePolicyRuleRequest req;
  req.set_policy_name("does-not-exist");
  netpolicy::v1::StatusResponse resp;
  grpc::Status status = stub_->DeletePolicyRule(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_NE(resp.status(), 0);
}
```

- [ ] **Step 4: Build, run, commit** (commit message: "Add DeletePolicyRule RPC to the Rust ControlService")

---

## Task 8: `DeleteWafRule`

**Interfaces:**
- Produces: `bool grpc_bridge::GrpcDispatchDeleteWafRule(DaemonContext* daemon, GrpcDispatchQueue* queue, rust::Vec<rust::String> pod_ips);` — first RPC needing a repeated-string field; converts to `std::vector<std::string>` in C++, then reuses the existing `grpc_bridge::BuildDeleteWafRuleJson`-equivalent shape internally, OR (simpler, avoiding any dependency on the old JSON-builder code that Task 16 will delete) builds a minimal JSON string directly matching what `Rules::RemoveWafRule` (in `waf/rule.h`/`.cc`) expects: `{"pod_ips": [...]}`.

- [ ] **Step 1: Declare and implement**

`grpc/control_dispatch.h`:
```cpp
bool GrpcDispatchDeleteWafRule(DaemonContext* daemon, GrpcDispatchQueue* queue,
                                rust::Vec<rust::String> pod_ips);
```

`net-policy.cpp` (reference `DispatchGrpcControlOp`'s `kDeleteWafRule` case and `waf/plugin.cc`'s `PluginRootContext::RemoveWafRule`, which expects a JSON object with a `"pod_ips"` array):
```cpp
bool GrpcDispatchDeleteWafRule(DaemonContext* daemon, GrpcDispatchQueue* queue,
                                rust::Vec<rust::String> pod_ips) {
  cJSON* root = cJSON_CreateObject();
  cJSON* ips = cJSON_CreateArray();
  for (const auto& ip : pod_ips) {
    cJSON_AddItemToArray(ips, cJSON_CreateString(std::string(ip).c_str()));
  }
  cJSON_AddItemToObject(root, "pod_ips", ips);
  char* json_c = cJSON_PrintUnformatted(root);
  std::string json(json_c);
  cJSON_free(json_c);
  cJSON_Delete(root);

  GrpcDispatchItem item;
  bool result = false;
  item.work = [&]() {
    result = daemon->WafRoot().RemoveWafRule(const_cast<char*>(json.c_str()));
  };
  std::future<void> future = item.done.get_future();
  queue->Push(&item);
  future.wait();
  return result;
}
```

`#include "cjson.h"` needs to already be visible in `net-policy.cpp` (it is, transitively via `net-policy.h`).

- [ ] **Step 2: Rust bridge declaration and handler**

```rust
        fn GrpcDispatchDeleteWafRule(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            pod_ips: Vec<String>,
        ) -> bool;
```

`use proto::DeleteWafRuleRequest;` added; new method:
```rust
    async fn delete_waf_rule(
        &self,
        request: Request<DeleteWafRuleRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let found = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchDeleteWafRule(daemon_ptr(), queue_ptr(), req.pod_ips)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status: if found { 0 } else { 1 }, uuid: String::new() }))
    }
```

- [ ] **Step 3: Add the test case**

```cpp
TEST_F(GrpcRustControlEndToEndTest, DeleteWafRuleForUnknownPodReturnsNonZeroStatus) {
  grpc::ClientContext ctx;
  netpolicy::v1::DeleteWafRuleRequest req;
  req.add_pod_ips("10.0.0.99");
  netpolicy::v1::StatusResponse resp;
  grpc::Status status = stub_->DeleteWafRule(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_NE(resp.status(), 0);
}
```

- [ ] **Step 4: Build, run, commit** (commit message: "Add DeleteWafRule RPC to the Rust ControlService")

---

## Task 9: `DumpHeapProfile`

**Interfaces:**
- Produces: `int32_t grpc_bridge::GrpcDispatchDumpHeapProfile(DaemonContext* daemon, GrpcDispatchQueue* queue, bool enable);` — per `DispatchGrpcControlOp`'s `kDumpHeapProfile` case, `admin::Heap::handleHeapProfile` expects a JSON `{"enable":"y"|"n"}` string.

- [ ] **Step 1: Declare and implement**

`grpc/control_dispatch.h`:
```cpp
int32_t GrpcDispatchDumpHeapProfile(DaemonContext* daemon, GrpcDispatchQueue* queue, bool enable);
```

`net-policy.cpp`:
```cpp
int32_t GrpcDispatchDumpHeapProfile(DaemonContext* daemon, GrpcDispatchQueue* queue, bool enable) {
  std::string json = std::string("{\"enable\":\"") + (enable ? "y" : "n") + "\"}";
  GrpcDispatchItem item;
  int32_t result = 1;
  item.work = [&]() {
    admin::Status status = admin::Heap::handleHeapProfile(json);
    result = (status == admin::Status::OK) ? 0 : 1;
  };
  std::future<void> future = item.done.get_future();
  queue->Push(&item);
  future.wait();
  return result;
}
```

(`daemon` is unused in this body — that's fine, `handleHeapProfile` doesn't need it, matching the existing `kDumpHeapProfile` case exactly; keep the parameter for signature consistency with every other dispatch function.)

- [ ] **Step 2: Rust bridge declaration and handler**

```rust
        fn GrpcDispatchDumpHeapProfile(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            enable: bool,
        ) -> i32;
```

`use proto::DumpHeapProfileRequest;` added; new method:
```rust
    async fn dump_heap_profile(
        &self,
        request: Request<DumpHeapProfileRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let status = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchDumpHeapProfile(daemon_ptr(), queue_ptr(), req.enable)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }
```

- [ ] **Step 3: Add the test case**

```cpp
TEST_F(GrpcRustControlEndToEndTest, DumpHeapProfileDisableReturnsOkStatus) {
  grpc::ClientContext ctx;
  netpolicy::v1::DumpHeapProfileRequest req;
  req.set_enable(false);
  netpolicy::v1::StatusResponse resp;
  grpc::Status status = stub_->DumpHeapProfile(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_EQ(resp.status(), 0);
}
```

- [ ] **Step 4: Build, run, commit** (commit message: "Add DumpHeapProfile RPC to the Rust ControlService")

---

## Task 10: `DumpConnections`

**Interfaces:**
- Produces: a `cxx` shared struct `DumpConnectionsResult { total: i64, items: Vec<String> }` and `grpc_bridge::DumpConnectionsResult GrpcDispatchDumpConnections(DaemonContext* daemon, GrpcDispatchQueue* queue, int32_t limit);` — first RPC with a non-scalar response, but still simple (no nested messages, just a count and a string list).

- [ ] **Step 1: Declare and implement**

`grpc/control_dispatch.h` — add the shared struct (must be declared where `cxx` codegen can see it; declare it here in the header, `cxx`'s bridge module in Rust mirrors it with matching field names/order):
```cpp
struct DumpConnectionsResult {
  int64_t total;
  std::vector<std::string> items;
};

DumpConnectionsResult GrpcDispatchDumpConnections(DaemonContext* daemon, GrpcDispatchQueue* queue,
                                                    int32_t limit);
```

`net-policy.cpp` (reference `DispatchGrpcControlOp`'s `kDumpConnections` case and `dumpConnectons`'s cJSON output shape — check `net-policy.cpp:1701-1718`, cited in the `.proto` file's comment for this RPC, for the exact field names before implementing; the JSON build step from `BuildDumpConnectionsJson` still needs a JSON string in, matching what `dumpConnectons(json, ...)` expects, likely `{"limit": N}`):
```cpp
DumpConnectionsResult GrpcDispatchDumpConnections(DaemonContext* daemon, GrpcDispatchQueue* queue,
                                                    int32_t limit) {
  std::string json = "{\"limit\":" + std::to_string(limit) + "}";
  GrpcDispatchItem item;
  DumpConnectionsResult result{};
  item.work = [&]() {
    cJSON* conns = dumpConnectons(json, daemon->ConnMgr());
    if (conns) {
      cJSON* total = cJSON_GetObjectItem(conns, "total");
      if (total)
        result.total = (int64_t)total->valuedouble;
      cJSON* items = cJSON_GetObjectItem(conns, "items");
      if (items) {
        int size = cJSON_GetArraySize(items);
        for (int i = 0; i < size; i++) {
          cJSON* entry = cJSON_GetArrayItem(items, i);
          if (entry && entry->valuestring)
            result.items.push_back(entry->valuestring);
        }
      }
      cJSON_Delete(conns);
    }
  };
  std::future<void> future = item.done.get_future();
  queue->Push(&item);
  future.wait();
  return result;
}
```

`"total"`/`"items"` are verified against `grpc/proto_json_bridge.cc`'s `ConvertConnectionsCJsonToProto` — the same function `DispatchGrpcControlOp`'s `kDumpConnections` case already uses to convert `dumpConnectons`'s output.

- [ ] **Step 2: Rust bridge declaration and handler**

```rust
        type DumpConnectionsResult;
```
add to the shared-struct section (before the `unsafe extern "C++"` function declarations — `cxx` shared structs are declared at the top level of the bridge module, not inside `extern` blocks):
```rust
    struct DumpConnectionsResult {
        total: i64,
        items: Vec<String>,
    }
```
and in `unsafe extern "C++"`:
```rust
        fn GrpcDispatchDumpConnections(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            limit: i32,
        ) -> DumpConnectionsResult;
```

`use proto::{DumpConnectionsRequest, DumpConnectionsResponse};` added; new method:
```rust
    async fn dump_connections(
        &self,
        request: Request<DumpConnectionsRequest>,
    ) -> Result<Response<DumpConnectionsResponse>, Status> {
        let req = request.into_inner();
        let result = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchDumpConnections(daemon_ptr(), queue_ptr(), req.limit)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(DumpConnectionsResponse { total: result.total, items: result.items }))
    }
```

- [ ] **Step 3: Add the test case**

```cpp
TEST_F(GrpcRustControlEndToEndTest, DumpConnectionsReturnsWithoutError) {
  grpc::ClientContext ctx;
  netpolicy::v1::DumpConnectionsRequest req;
  req.set_limit(10);
  netpolicy::v1::DumpConnectionsResponse resp;
  grpc::Status status = stub_->DumpConnections(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_GE(resp.total(), 0);
}
```

- [ ] **Step 4: Build, run, commit** (commit message: "Add DumpConnections RPC to the Rust ControlService")

---

## Task 11: `UpdateNodeConfig`

**Interfaces:**
- Produces: `int32_t grpc_bridge::GrpcDispatchUpdateNodeConfig(DaemonContext* daemon, GrpcDispatchQueue* queue, bool is_delete, rust::Vec<rust::String> node_ips);` — verified against `grpc/proto_json_bridge.cc`'s `BuildUpdateNodeConfigJson` (the function `DispatchGrpcControlOp`'s `kUpdateNodeConfig` case already calls before `ParseNodeCfg`): the JSON key is `"action"` with **string** value `"add"` or `"delete"` (not the proto enum's raw integer) and `"node_ips"` for the address list. `is_delete` is `true` when the proto request's `action` field equals `UpdateNodeConfigRequest::ACTION_DELETE`; anything else (including `ACTION_UNSPECIFIED`) maps to `"add"`, matching `BuildUpdateNodeConfigJson`'s existing `(action == ACTION_DELETE) ? "delete" : "add"` ternary exactly.

- [ ] **Step 1: Declare and implement**

`grpc/control_dispatch.h`:
```cpp
int32_t GrpcDispatchUpdateNodeConfig(DaemonContext* daemon, GrpcDispatchQueue* queue,
                                      bool is_delete, rust::Vec<rust::String> node_ips);
```

`net-policy.cpp`:
```cpp
int32_t GrpcDispatchUpdateNodeConfig(DaemonContext* daemon, GrpcDispatchQueue* queue,
                                      bool is_delete, rust::Vec<rust::String> node_ips) {
  cJSON* root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "action", is_delete ? "delete" : "add");
  cJSON* ips = cJSON_CreateArray();
  for (const auto& ip : node_ips) {
    cJSON_AddItemToArray(ips, cJSON_CreateString(std::string(ip).c_str()));
  }
  cJSON_AddItemToObject(root, "node_ips", ips);
  char* json_c = cJSON_PrintUnformatted(root);
  std::string json(json_c);
  cJSON_free(json_c);
  cJSON_Delete(root);

  GrpcDispatchItem item;
  int32_t result = 1;
  item.work = [&]() {
    result = ParseNodeCfg(const_cast<char*>(json.c_str()), *daemon);
  };
  std::future<void> future = item.done.get_future();
  queue->Push(&item);
  future.wait();
  return result;
}
```

- [ ] **Step 2: Rust bridge declaration and handler**

```rust
        fn GrpcDispatchUpdateNodeConfig(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            is_delete: bool,
            node_ips: Vec<String>,
        ) -> i32;
```

`use proto::UpdateNodeConfigRequest;` and `use proto::update_node_config_request::Action;` added; new method:
```rust
    async fn update_node_config(
        &self,
        request: Request<UpdateNodeConfigRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let is_delete = req.action == Action::Delete as i32;
        let status = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchUpdateNodeConfig(daemon_ptr(), queue_ptr(), is_delete, req.node_ips)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }
```

`update_node_config_request::Action` is `tonic-build`'s generated path for a nested enum defined inside a message (`UpdateNodeConfigRequest.Action` in the `.proto` file) — verify the exact generated module path against Task 1's codegen output if this doesn't compile as written; `prost`'s convention nests it under a snake_case module named after the containing message.

- [ ] **Step 3: Add the test case**

```cpp
TEST_F(GrpcRustControlEndToEndTest, UpdateNodeConfigAddReturnsOkStatus) {
  grpc::ClientContext ctx;
  netpolicy::v1::UpdateNodeConfigRequest req;
  req.set_action(netpolicy::v1::UpdateNodeConfigRequest::ACTION_ADD);
  req.add_node_ips("10.0.0.5");
  netpolicy::v1::StatusResponse resp;
  grpc::Status status = stub_->UpdateNodeConfig(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_EQ(resp.status(), 0);
}
```

- [ ] **Step 4: Build, run, commit** (commit message: "Add UpdateNodeConfig RPC to the Rust ControlService")

---

## Task 12: `SetLogLevel`

**Interfaces:**
- Produces: `int32_t grpc_bridge::GrpcDispatchSetLogLevel(DaemonContext* daemon, GrpcDispatchQueue* queue, int32_t level);` — the simplest remaining RPC: sets a global atomic (`g_log_level`), no `DaemonContext` state touched, but still routed through the queue for consistency with every other RPC (matching `DispatchGrpcControlOp`'s existing `kSetLogLevel` case, which also always returns `0`).

- [ ] **Step 1: Declare and implement**

`grpc/control_dispatch.h`:
```cpp
int32_t GrpcDispatchSetLogLevel(DaemonContext* daemon, GrpcDispatchQueue* queue, int32_t level);
```

`net-policy.cpp`:
```cpp
int32_t GrpcDispatchSetLogLevel(DaemonContext* daemon, GrpcDispatchQueue* queue, int32_t level) {
  (void)daemon;
  GrpcDispatchItem item;
  item.work = [&]() {
    g_log_level = level;
    LOG_I("set log level : %d", g_log_level.load());
  };
  std::future<void> future = item.done.get_future();
  queue->Push(&item);
  future.wait();
  return 0;
}
```

- [ ] **Step 2: Rust bridge declaration and handler**

```rust
        fn GrpcDispatchSetLogLevel(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            level: i32,
        ) -> i32;
```

`use proto::SetLogLevelRequest;` added; new method:
```rust
    async fn set_log_level(
        &self,
        request: Request<SetLogLevelRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let status = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchSetLogLevel(daemon_ptr(), queue_ptr(), req.level)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }
```

- [ ] **Step 3: Add the test case**

```cpp
TEST_F(GrpcRustControlEndToEndTest, SetLogLevelReturnsOkStatus) {
  grpc::ClientContext ctx;
  netpolicy::v1::SetLogLevelRequest req;
  req.set_level(2);
  netpolicy::v1::StatusResponse resp;
  grpc::Status status = stub_->SetLogLevel(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_EQ(resp.status(), 0);
}
```

- [ ] **Step 4: Build, run, commit** (commit message: "Add SetLogLevel RPC to the Rust ControlService")

---

## Task 13: `DumpConfig`

The first RPC with a genuinely nested response (`repeated PolicyRuleConfigEntry`, `repeated ContainerInfo`).

**Interfaces:**
- Produces: `cxx` shared structs `PolicyRuleConfigEntry` and `ContainerInfo`, plus `DumpConfigResult { inbound_rules: Vec<PolicyRuleConfigEntry>, outbound_rules: Vec<PolicyRuleConfigEntry>, containers: Vec<ContainerInfo>, tcp_connections: i64 }` and `grpc_bridge::DumpConfigResult GrpcDispatchDumpConfig(DaemonContext* daemon, GrpcDispatchQueue* queue, rust::Str policy_name);`.

- [ ] **Step 1: Verified field mapping**

`grpc/proto_json_bridge.cc`'s `ConvertConfigCJsonToProto` function (already called from `DispatchGrpcControlOp`'s `kDumpConfig` case) is the authoritative mapping from `MicroSegEngine::GetAllConfig`'s cJSON output to `netpolicy::v1::DumpConfigResponse`. Its exact key structure:
- `inbound_rules`/`outbound_rules`: arrays of objects with keys `policy_name` (string), `priority` (int), `direction` (string), `action` (string), `protocol` (string), `protocol_int` (int), `from_address` (string), `to_address` (string).
- `containers`: array of objects with keys `pid` (int), `pod_id` (number, read via `valuedouble` and cast to `uint64_t` since cJSON stores all numbers as `double`).
- `tcp_connections` is **not** a top-level key — it's nested: `config["tcp"]["tcp_connection"]` (a number, same `valuedouble`-cast pattern).

- [ ] **Step 2: Declare the shared structs and function**

`grpc/control_dispatch.h`:
```cpp
struct PolicyRuleConfigEntry {
  std::string policy_name;
  int32_t priority;
  std::string direction;
  std::string action;
  std::string protocol;
  int32_t protocol_int;
  std::string from_address;
  std::string to_address;
};
struct ContainerInfo {
  int32_t pid;
  uint64_t pod_id;
};
struct DumpConfigResult {
  std::vector<PolicyRuleConfigEntry> inbound_rules;
  std::vector<PolicyRuleConfigEntry> outbound_rules;
  std::vector<ContainerInfo> containers;
  int64_t tcp_connections;
};

DumpConfigResult GrpcDispatchDumpConfig(DaemonContext* daemon, GrpcDispatchQueue* queue,
                                          rust::Str policy_name);
```

- [ ] **Step 3: Implement in `net-policy.cpp`**

Following the field-by-field mapping found in `ConvertConfigCJsonToProto` (Step 1), implement:
```cpp
DumpConfigResult GrpcDispatchDumpConfig(DaemonContext* daemon, GrpcDispatchQueue* queue,
                                          rust::Str policy_name) {
  std::string name(policy_name);
  GrpcDispatchItem item;
  DumpConfigResult result{};
  item.work = [&]() {
    cJSON* config = daemon->Microseg().GetAllConfig(name, daemon->ConnMgr());
    if (!config) return;
    auto convert_entries = [](cJSON* array, std::vector<PolicyRuleConfigEntry>& out) {
      if (!array) return;
      int size = cJSON_GetArraySize(array);
      for (int i = 0; i < size; i++) {
        cJSON* e = cJSON_GetArrayItem(array, i);
        if (!e) continue;
        PolicyRuleConfigEntry entry{};
        cJSON* v;
        if ((v = cJSON_GetObjectItem(e, "policy_name")) && v->valuestring) entry.policy_name = v->valuestring;
        if ((v = cJSON_GetObjectItem(e, "priority"))) entry.priority = v->valueint;
        if ((v = cJSON_GetObjectItem(e, "direction")) && v->valuestring) entry.direction = v->valuestring;
        if ((v = cJSON_GetObjectItem(e, "action")) && v->valuestring) entry.action = v->valuestring;
        if ((v = cJSON_GetObjectItem(e, "protocol")) && v->valuestring) entry.protocol = v->valuestring;
        if ((v = cJSON_GetObjectItem(e, "protocol_int"))) entry.protocol_int = v->valueint;
        if ((v = cJSON_GetObjectItem(e, "from_address")) && v->valuestring) entry.from_address = v->valuestring;
        if ((v = cJSON_GetObjectItem(e, "to_address")) && v->valuestring) entry.to_address = v->valuestring;
        out.push_back(std::move(entry));
      }
    };
    convert_entries(cJSON_GetObjectItem(config, "inbound_rules"), result.inbound_rules);
    convert_entries(cJSON_GetObjectItem(config, "outbound_rules"), result.outbound_rules);
    cJSON* containers = cJSON_GetObjectItem(config, "containers");
    if (containers) {
      int size = cJSON_GetArraySize(containers);
      for (int i = 0; i < size; i++) {
        cJSON* c = cJSON_GetArrayItem(containers, i);
        if (!c) continue;
        ContainerInfo ci{};
        cJSON* v;
        if ((v = cJSON_GetObjectItem(c, "pid"))) ci.pid = v->valueint;
        if ((v = cJSON_GetObjectItem(c, "pod_id"))) ci.pod_id = (uint64_t)v->valuedouble;
        result.containers.push_back(ci);
      }
    }
    cJSON* tcp = cJSON_GetObjectItem(config, "tcp");
    if (tcp) {
      cJSON* conn = cJSON_GetObjectItem(tcp, "tcp_connection");
      if (conn) result.tcp_connections = (int64_t)conn->valuedouble;
    }
    cJSON_Delete(config);
  };
  std::future<void> future = item.done.get_future();
  queue->Push(&item);
  future.wait();
  return result;
}
```

- [ ] **Step 4: Rust bridge declarations and handler**

```rust
    struct PolicyRuleConfigEntry {
        policy_name: String,
        priority: i32,
        direction: String,
        action: String,
        protocol: String,
        protocol_int: i32,
        from_address: String,
        to_address: String,
    }
    struct ContainerInfo {
        pid: i32,
        pod_id: u64,
    }
    struct DumpConfigResult {
        inbound_rules: Vec<PolicyRuleConfigEntry>,
        outbound_rules: Vec<PolicyRuleConfigEntry>,
        containers: Vec<ContainerInfo>,
        tcp_connections: i64,
    }
```
and in `unsafe extern "C++"`:
```rust
        fn GrpcDispatchDumpConfig(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            policy_name: &str,
        ) -> DumpConfigResult;
```

`use proto::{DumpConfigRequest, DumpConfigResponse, PolicyRuleConfigEntry as ProtoConfigEntry, ContainerInfo as ProtoContainerInfo};` (aliased since the generated proto types and this task's new `cxx` shared struct types share names — `cxx`'s `ffi::PolicyRuleConfigEntry` vs. `proto::PolicyRuleConfigEntry`, disambiguated via the `ffi::` prefix already required for bridge types, but the `proto::` import needs the explicit rename to avoid a naming collision at the `use` site); new method:
```rust
    async fn dump_config(
        &self,
        request: Request<DumpConfigRequest>,
    ) -> Result<Response<DumpConfigResponse>, Status> {
        let req = request.into_inner();
        let result = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchDumpConfig(daemon_ptr(), queue_ptr(), &req.policy_name)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;

        let convert = |e: ffi::PolicyRuleConfigEntry| ProtoConfigEntry {
            policy_name: e.policy_name,
            priority: e.priority,
            direction: e.direction,
            action: e.action,
            protocol: e.protocol,
            protocol_int: e.protocol_int,
            from_address: e.from_address,
            to_address: e.to_address,
        };
        Ok(Response::new(DumpConfigResponse {
            inbound_rules: result.inbound_rules.into_iter().map(convert).collect(),
            outbound_rules: result.outbound_rules.into_iter().map(convert).collect(),
            containers: result
                .containers
                .into_iter()
                .map(|c| ProtoContainerInfo { pid: c.pid, pod_id: c.pod_id })
                .collect(),
            tcp_connections: result.tcp_connections,
        }))
    }
```

- [ ] **Step 5: Add the test case**

```cpp
TEST_F(GrpcRustControlEndToEndTest, DumpConfigForUnknownPolicyReturnsEmptyResult) {
  grpc::ClientContext ctx;
  netpolicy::v1::DumpConfigRequest req;
  req.set_policy_name("does-not-exist");
  netpolicy::v1::DumpConfigResponse resp;
  grpc::Status status = stub_->DumpConfig(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_EQ(resp.inbound_rules_size(), 0);
  EXPECT_EQ(resp.outbound_rules_size(), 0);
}
```

- [ ] **Step 6: Build, run, commit** (commit message: "Add DumpConfig RPC to the Rust ControlService")

---

## Task 14: `AddPolicyRule`

The most complex request shape: `repeated PolicyRuleSpec`, each with nested `repeated HttpMatchRule`, `repeated AddressEndpoint` (x2), `repeated PortRange`.

**Interfaces:**
- Produces: `cxx` shared structs mirroring `PolicyRuleSpec`/`HttpMatchRule`/`AddressEndpoint`/`PortRange`, and `int32_t grpc_bridge::GrpcDispatchAddPolicyRule(DaemonContext* daemon, GrpcDispatchQueue* queue, rust::Str policy_name, rust::Vec<PolicyRuleSpec> rules);`.

- [ ] **Step 1: Verified field mapping**

`grpc/proto_json_bridge.cc`'s `BuildAddPolicyRuleJson` (already called from `DispatchGrpcControlOp`'s `kAddPolicyRule` case) is the authoritative mapping. Its exact shape:
- `policy_name` (string), `rules` (array).
- Each rule: `action` — **string**, one of `"Allow"`/`"Alert"`/`"Deny"` (default), mapped from `PolicyAction` (`net_policy_common.proto`: `POLICY_ACTION_DENY=1`, `POLICY_ACTION_ALLOW=2`, `POLICY_ACTION_ALERT=3`) via `2→"Allow"`, `3→"Alert"`, anything else→`"Deny"`.
- `direction` — **string**, `"ingress"` when `FlowDirection == FLOW_DIRECTION_INGRESS` (`=1`), else `"egress"`.
- `protocol` — **string** (`"TCP"`/`"UDP"`/`"ICMP"`), **added to the JSON only when `protocol != L4_PROTOCOL_UNSPECIFIED` (`=0`)** — omit the key entirely for unspecified, don't emit an empty string.
- `http` (not `http_rules`) — array of `{host, method, path}`, **added only when the rule has at least one `HttpMatchRule`**.
- `from_addresses`/`to_addresses` — arrays of `{ip, pod_id}` (both fields, always present — `AddressEndpoint` has two fields per `net_policy_common.proto`, not just `ip`).
- `ports` — array of `{port, endPort}` (note: `endPort`, **camelCase**, not `end_port`) — **added only when the rule has at least one `PortRange`**.
- `priority` (number).

- [ ] **Step 2: Declare the shared structs and function**

`grpc/control_dispatch.h`:
```cpp
struct HttpMatchRule {
  std::string host;
  std::string method;
  std::string path;
};
struct AddressEndpoint {
  std::string ip;
  uint64_t pod_id;
};
struct PortRange {
  uint32_t port;
  uint32_t end_port;
};
struct PolicyRuleSpec {
  int32_t action;     // raw PolicyAction enum value (net_policy_common.proto)
  int32_t direction;  // raw FlowDirection enum value
  int32_t protocol;   // raw L4Protocol enum value; UNSPECIFIED (0) omits the JSON key
  std::vector<HttpMatchRule> http_rules;
  std::vector<AddressEndpoint> from_addresses;
  std::vector<AddressEndpoint> to_addresses;
  std::vector<PortRange> ports;
  int32_t priority;
};

int32_t GrpcDispatchAddPolicyRule(DaemonContext* daemon, GrpcDispatchQueue* queue,
                                    rust::Str policy_name, rust::Vec<PolicyRuleSpec> rules);
```

- [ ] **Step 3: Implement in `net-policy.cpp`**

`net-policy.cpp` already includes the protobuf headers that define `netpolicy::v1::PolicyAction`/`FlowDirection`/`L4Protocol` (via `DispatchGrpcControlOp`'s existing use of `netpolicy::v1::*Request` types), so the enum constants are used directly rather than hardcoding their integer values:

```cpp
namespace {
const char* PolicyActionToStr(int32_t action) {
  switch (static_cast<netpolicy::v1::PolicyAction>(action)) {
  case netpolicy::v1::POLICY_ACTION_ALLOW: return "Allow";
  case netpolicy::v1::POLICY_ACTION_ALERT: return "Alert";
  default:                                 return "Deny";
  }
}
const char* FlowDirectionToStr(int32_t direction) {
  return (static_cast<netpolicy::v1::FlowDirection>(direction) == netpolicy::v1::FLOW_DIRECTION_INGRESS)
             ? "ingress" : "egress";
}
const char* L4ProtocolToStr(int32_t protocol) {
  switch (static_cast<netpolicy::v1::L4Protocol>(protocol)) {
  case netpolicy::v1::L4_PROTOCOL_TCP:  return "TCP";
  case netpolicy::v1::L4_PROTOCOL_UDP:  return "UDP";
  case netpolicy::v1::L4_PROTOCOL_ICMP: return "ICMP";
  default:                              return "";
  }
}
cJSON* AddressEndpointToJsonRust(const grpc_bridge::AddressEndpoint& ep) {
  cJSON* obj = cJSON_CreateObject();
  cJSON_AddStringToObject(obj, "ip", std::string(ep.ip).c_str());
  cJSON_AddNumberToObject(obj, "pod_id", static_cast<double>(ep.pod_id));
  return obj;
}
} // namespace

int32_t GrpcDispatchAddPolicyRule(DaemonContext* daemon, GrpcDispatchQueue* queue,
                                    rust::Str policy_name, rust::Vec<PolicyRuleSpec> rules) {
  std::string name(policy_name);
  cJSON* root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "policy_name", name.c_str());

  cJSON* rules_array = cJSON_CreateArray();
  for (const auto& rule : rules) {
    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "action", PolicyActionToStr(rule.action));
    cJSON_AddStringToObject(r, "direction", FlowDirectionToStr(rule.direction));
    if (static_cast<netpolicy::v1::L4Protocol>(rule.protocol) != netpolicy::v1::L4_PROTOCOL_UNSPECIFIED)
      cJSON_AddStringToObject(r, "protocol", L4ProtocolToStr(rule.protocol));

    if (!rule.http_rules.empty()) {
      cJSON* http = cJSON_CreateArray();
      for (const auto& h : rule.http_rules) {
        cJSON* item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "host", std::string(h.host).c_str());
        cJSON_AddStringToObject(item, "method", std::string(h.method).c_str());
        cJSON_AddStringToObject(item, "path", std::string(h.path).c_str());
        cJSON_AddItemToArray(http, item);
      }
      cJSON_AddItemToObject(r, "http", http);
    }

    cJSON* from_arr = cJSON_CreateArray();
    for (const auto& ep : rule.from_addresses) cJSON_AddItemToArray(from_arr, AddressEndpointToJsonRust(ep));
    cJSON_AddItemToObject(r, "from_addresses", from_arr);

    cJSON* to_arr = cJSON_CreateArray();
    for (const auto& ep : rule.to_addresses) cJSON_AddItemToArray(to_arr, AddressEndpointToJsonRust(ep));
    cJSON_AddItemToObject(r, "to_addresses", to_arr);

    if (!rule.ports.empty()) {
      cJSON* ports = cJSON_CreateArray();
      for (const auto& p : rule.ports) {
        cJSON* item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "port", p.port);
        cJSON_AddNumberToObject(item, "endPort", p.end_port); // camelCase, see net-policy.cpp:1557
        cJSON_AddItemToArray(ports, item);
      }
      cJSON_AddItemToObject(r, "ports", ports);
    }

    cJSON_AddNumberToObject(r, "priority", rule.priority);
    cJSON_AddItemToArray(rules_array, r);
  }
  cJSON_AddItemToObject(root, "rules", rules_array);
  char* json_c = cJSON_PrintUnformatted(root);
  std::string json(json_c);
  cJSON_free(json_c);
  cJSON_Delete(root);

  GrpcDispatchItem item;
  int32_t result = 1;
  item.work = [&]() {
    result = ParseNetPolicy(const_cast<char*>(json.c_str()), *daemon);
    daemon->Microseg().PrintPolicyLog();
  };
  std::future<void> future = item.done.get_future();
  queue->Push(&item);
  future.wait();
  return result;
}
```

- [ ] **Step 4: Rust bridge declarations and handler**

```rust
    struct HttpMatchRule {
        host: String,
        method: String,
        path: String,
    }
    struct AddressEndpoint {
        ip: String,
        pod_id: u64,
    }
    struct PortRange {
        port: u32,
        end_port: u32,
    }
    struct PolicyRuleSpec {
        action: i32,
        direction: i32,
        protocol: i32,
        http_rules: Vec<HttpMatchRule>,
        from_addresses: Vec<AddressEndpoint>,
        to_addresses: Vec<AddressEndpoint>,
        ports: Vec<PortRange>,
        priority: i32,
    }
```
and in `unsafe extern "C++"`:
```rust
        fn GrpcDispatchAddPolicyRule(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            policy_name: &str,
            rules: Vec<PolicyRuleSpec>,
        ) -> i32;
```

`use proto::{AddPolicyRuleRequest, PolicyRuleSpec as ProtoRuleSpec, HttpMatchRule as ProtoHttpRule, AddressEndpoint as ProtoAddressEndpoint, PortRange as ProtoPortRange};`; new method:
```rust
    async fn add_policy_rule(
        &self,
        request: Request<AddPolicyRuleRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let rules: Vec<ffi::PolicyRuleSpec> = req
            .rules
            .into_iter()
            .map(|r: ProtoRuleSpec| ffi::PolicyRuleSpec {
                action: r.action,
                direction: r.direction,
                protocol: r.protocol,
                http_rules: r
                    .http_rules
                    .into_iter()
                    .map(|h: ProtoHttpRule| ffi::HttpMatchRule {
                        host: h.host,
                        method: h.method,
                        path: h.path,
                    })
                    .collect(),
                from_addresses: r
                    .from_addresses
                    .into_iter()
                    .map(|a: ProtoAddressEndpoint| ffi::AddressEndpoint { ip: a.ip, pod_id: a.pod_id })
                    .collect(),
                to_addresses: r
                    .to_addresses
                    .into_iter()
                    .map(|a: ProtoAddressEndpoint| ffi::AddressEndpoint { ip: a.ip, pod_id: a.pod_id })
                    .collect(),
                ports: r
                    .ports
                    .into_iter()
                    .map(|p: ProtoPortRange| ffi::PortRange { port: p.port, end_port: p.end_port })
                    .collect(),
                priority: r.priority,
            })
            .collect();
        let policy_name = req.policy_name;
        let status = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchAddPolicyRule(daemon_ptr(), queue_ptr(), &policy_name, rules)
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status, uuid: String::new() }))
    }
```

- [ ] **Step 5: Add the test case**

Reuse the existing `AddPolicyRuleOverRealChannelThenReadBackViaDumpConfig` test from `tests/grpc_e2e_test.cc` as the template (it already exercises `AddPolicyRule` + `DumpConfig` + `DeletePolicyRule` against the OLD C++ server) — write an equivalent against the new `GrpcRustControlEndToEndTest` fixture:

```cpp
TEST_F(GrpcRustControlEndToEndTest, AddPolicyRuleThenReadBackViaDumpConfig) {
  netpolicy::v1::AddPolicyRuleRequest add_req;
  add_req.set_policy_name("rust-e2e-test-policy");
  auto* rule = add_req.add_rules();
  rule->set_action(netpolicy::v1::POLICY_ACTION_ALLOW);
  rule->set_direction(netpolicy::v1::FLOW_DIRECTION_INGRESS);
  rule->set_priority(1);
  rule->add_from_addresses()->set_ip("192.168.0.1");
  rule->add_to_addresses()->set_ip("192.168.0.2");

  grpc::ClientContext add_ctx;
  netpolicy::v1::StatusResponse add_resp;
  grpc::Status status = stub_->AddPolicyRule(&add_ctx, add_req, &add_resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_EQ(add_resp.status(), 0);

  grpc::ClientContext dump_ctx;
  netpolicy::v1::DumpConfigRequest dump_req;
  dump_req.set_policy_name("rust-e2e-test-policy");
  netpolicy::v1::DumpConfigResponse dump_resp;
  status = stub_->DumpConfig(&dump_ctx, dump_req, &dump_resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  ASSERT_EQ(dump_resp.inbound_rules_size(), 1);
  EXPECT_EQ(dump_resp.inbound_rules(0).policy_name(), "rust-e2e-test-policy");

  grpc::ClientContext del_ctx;
  netpolicy::v1::DeletePolicyRuleRequest del_req;
  del_req.set_policy_name("rust-e2e-test-policy");
  netpolicy::v1::StatusResponse del_resp;
  status = stub_->DeletePolicyRule(&del_ctx, del_req, &del_resp);
  ASSERT_TRUE(status.ok());
  EXPECT_EQ(del_resp.status(), 0);
}
```

- [ ] **Step 6: Build, run, commit** (commit message: "Add AddPolicyRule RPC to the Rust ControlService")

---

## Task 15: `AddWafRule`

The other complex request shape: `repeated WafRule`, `repeated BlackWhiteListEntry`, several scalar fields.

**Interfaces:**
- Produces: `cxx` shared structs mirroring `WafRule`/`BlackWhiteListEntry`, and `bool grpc_bridge::GrpcDispatchAddWafRule(DaemonContext* daemon, GrpcDispatchQueue* queue, rust::Vec<rust::String> pod_ips, rust::Vec<WafRule> rules, rust::Vec<rust::String> domains, rust::Vec<rust::String> excluded_file_types, rust::Vec<rust::String> detect_headers, rust::Vec<BlackWhiteListEntry> black_white_lists, rust::Str uri, rust::Str mode, rust::Str name, rust::Str cluster_key, rust::Str k8s_namespace, rust::Str kind, rust::Str workload_name, uint64_t service_id);`

- [ ] **Step 1: Verified field mapping**

`grpc/proto_json_bridge.cc`'s `BuildAddWafRuleJson` (already called from `DispatchGrpcControlOp`'s `kAddWafRule` case) is the authoritative mapping, confirmed by reading it directly: all fields use their proto names as JSON keys **except** three quirks — `WafRule.description` writes to JSON key `"Description"` (capital D), the `domains` list writes to JSON key `"domain"` (singular), and `k8s_namespace` writes to JSON key `"namespace"`. These three are not optional details — the implementation below already reflects them; do not "simplify" them away when implementing.

- [ ] **Step 2: Declare the shared structs and function**

`grpc/control_dispatch.h`:
```cpp
struct WafRule {
  int64_t id;
  int64_t level;
  std::string type;
  std::string name;
  std::string expr;
  std::string mode;
  std::string description;
};
struct BlackWhiteListEntry {
  uint64_t id;
  std::string name;
  std::string expr;
  std::string mode;
};

bool GrpcDispatchAddWafRule(DaemonContext* daemon, GrpcDispatchQueue* queue,
                             rust::Vec<rust::String> pod_ips, rust::Vec<WafRule> rules,
                             rust::Vec<rust::String> domains,
                             rust::Vec<rust::String> excluded_file_types,
                             rust::Vec<rust::String> detect_headers,
                             rust::Vec<BlackWhiteListEntry> black_white_lists, rust::Str uri,
                             rust::Str mode, rust::Str name, rust::Str cluster_key,
                             rust::Str k8s_namespace, rust::Str kind, rust::Str workload_name,
                             uint64_t service_id);
```

- [ ] **Step 3: Implement in `net-policy.cpp`**

Build a JSON string matching `BuildAddWafRuleJson`'s exact shape (Step 1), including the `"namespace"`/`"Description"` key-name quirks, then call `daemon->WafRoot().ParseConfiguration(...)` exactly like `DispatchGrpcControlOp`'s `kAddWafRule` case does:

```cpp
bool GrpcDispatchAddWafRule(DaemonContext* daemon, GrpcDispatchQueue* queue,
                             rust::Vec<rust::String> pod_ips, rust::Vec<WafRule> rules,
                             rust::Vec<rust::String> domains,
                             rust::Vec<rust::String> excluded_file_types,
                             rust::Vec<rust::String> detect_headers,
                             rust::Vec<BlackWhiteListEntry> black_white_lists, rust::Str uri,
                             rust::Str mode, rust::Str name, rust::Str cluster_key,
                             rust::Str k8s_namespace, rust::Str kind, rust::Str workload_name,
                             uint64_t service_id) {
  cJSON* root = cJSON_CreateObject();
  cJSON* pod_ips_arr = cJSON_CreateArray();
  for (const auto& ip : pod_ips) cJSON_AddItemToArray(pod_ips_arr, cJSON_CreateString(std::string(ip).c_str()));
  cJSON_AddItemToObject(root, "pod_ips", pod_ips_arr);

  cJSON* rules_arr = cJSON_CreateArray();
  for (const auto& r : rules) {
    cJSON* ro = cJSON_CreateObject();
    cJSON_AddNumberToObject(ro, "id", (double)r.id);
    cJSON_AddNumberToObject(ro, "level", (double)r.level);
    cJSON_AddStringToObject(ro, "type", std::string(r.type).c_str());
    cJSON_AddStringToObject(ro, "name", std::string(r.name).c_str());
    cJSON_AddStringToObject(ro, "expr", std::string(r.expr).c_str());
    cJSON_AddStringToObject(ro, "mode", std::string(r.mode).c_str());
    cJSON_AddStringToObject(ro, "Description", std::string(r.description).c_str()); // capital D, see waf/plugin.cc:477
    cJSON_AddItemToArray(rules_arr, ro);
  }
  cJSON_AddItemToObject(root, "rules", rules_arr);

  cJSON* domains_arr = cJSON_CreateArray();
  for (const auto& d : domains) cJSON_AddItemToArray(domains_arr, cJSON_CreateString(std::string(d).c_str()));
  cJSON_AddItemToObject(root, "domain", domains_arr); // key is "domain" (singular), verified against BuildAddWafRuleJson

  cJSON* excl_arr = cJSON_CreateArray();
  for (const auto& e : excluded_file_types) cJSON_AddItemToArray(excl_arr, cJSON_CreateString(std::string(e).c_str()));
  cJSON_AddItemToObject(root, "excluded_file_types", excl_arr);

  cJSON* dh_arr = cJSON_CreateArray();
  for (const auto& h : detect_headers) cJSON_AddItemToArray(dh_arr, cJSON_CreateString(std::string(h).c_str()));
  cJSON_AddItemToObject(root, "detect_headers", dh_arr);

  cJSON* bwl_arr = cJSON_CreateArray();
  for (const auto& b : black_white_lists) {
    cJSON* bo = cJSON_CreateObject();
    cJSON_AddNumberToObject(bo, "id", (double)b.id);
    cJSON_AddStringToObject(bo, "name", std::string(b.name).c_str());
    cJSON_AddStringToObject(bo, "expr", std::string(b.expr).c_str());
    cJSON_AddStringToObject(bo, "mode", std::string(b.mode).c_str());
    cJSON_AddItemToArray(bwl_arr, bo);
  }
  cJSON_AddItemToObject(root, "black_white_lists", bwl_arr);

  cJSON_AddStringToObject(root, "uri", std::string(uri).c_str());
  cJSON_AddStringToObject(root, "mode", std::string(mode).c_str());
  cJSON_AddStringToObject(root, "name", std::string(name).c_str());
  cJSON_AddStringToObject(root, "cluster_key", std::string(cluster_key).c_str());
  cJSON_AddStringToObject(root, "namespace", std::string(k8s_namespace).c_str()); // wire key is "namespace", see .proto comment
  cJSON_AddStringToObject(root, "kind", std::string(kind).c_str());
  cJSON_AddStringToObject(root, "workload_name", std::string(workload_name).c_str());
  cJSON_AddNumberToObject(root, "service_id", (double)service_id);

  char* json_c = cJSON_PrintUnformatted(root);
  std::string json(json_c);
  cJSON_free(json_c);
  cJSON_Delete(root);

  GrpcDispatchItem item;
  bool result = false;
  item.work = [&]() {
    result = daemon->WafRoot().ParseConfiguration(const_cast<char*>(json.c_str()));
  };
  std::future<void> future = item.done.get_future();
  queue->Push(&item);
  future.wait();
  return result;
}
```

- [ ] **Step 4: Rust bridge declarations and handler**

```rust
    struct WafRule {
        id: i64,
        level: i64,
        r#type: String,
        name: String,
        expr: String,
        mode: String,
        description: String,
    }
    struct BlackWhiteListEntry {
        id: u64,
        name: String,
        expr: String,
        mode: String,
    }
```
(`r#type` because `type` is a Rust reserved word — `cxx` maps a Rust field named `r#type` to a C++ field named `type`; if `cxx` doesn't accept this transparently, rename the Rust-side field and adjust the C++ struct's field name to match instead, keeping both sides consistent.)

In `unsafe extern "C++"`:
```rust
        fn GrpcDispatchAddWafRule(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            pod_ips: Vec<String>,
            rules: Vec<WafRule>,
            domains: Vec<String>,
            excluded_file_types: Vec<String>,
            detect_headers: Vec<String>,
            black_white_lists: Vec<BlackWhiteListEntry>,
            uri: &str,
            mode: &str,
            name: &str,
            cluster_key: &str,
            k8s_namespace: &str,
            kind: &str,
            workload_name: &str,
            service_id: u64,
        ) -> bool;
```

`use proto::{AddWafRuleRequest, WafRule as ProtoWafRule, BlackWhiteListEntry as ProtoBwEntry};`; new method:
```rust
    async fn add_waf_rule(
        &self,
        request: Request<AddWafRuleRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let rules: Vec<ffi::WafRule> = req
            .rules
            .into_iter()
            .map(|r: ProtoWafRule| ffi::WafRule {
                id: r.id,
                level: r.level,
                r#type: r.r#type,
                name: r.name,
                expr: r.expr,
                mode: r.mode,
                description: r.description,
            })
            .collect();
        let black_white_lists: Vec<ffi::BlackWhiteListEntry> = req
            .black_white_lists
            .into_iter()
            .map(|b: ProtoBwEntry| ffi::BlackWhiteListEntry {
                id: b.id,
                name: b.name,
                expr: b.expr,
                mode: b.mode,
            })
            .collect();
        let (pod_ips, domains, excluded_file_types, detect_headers) =
            (req.pod_ips, req.domains, req.excluded_file_types, req.detect_headers);
        let (uri, mode, name, cluster_key, k8s_namespace, kind, workload_name, service_id) = (
            req.uri,
            req.mode,
            req.name,
            req.cluster_key,
            req.k8s_namespace,
            req.kind,
            req.workload_name,
            req.service_id,
        );
        let found = tokio::task::spawn_blocking(move || unsafe {
            ffi::GrpcDispatchAddWafRule(
                daemon_ptr(),
                queue_ptr(),
                pod_ips,
                rules,
                domains,
                excluded_file_types,
                detect_headers,
                black_white_lists,
                &uri,
                &mode,
                &name,
                &cluster_key,
                &k8s_namespace,
                &kind,
                &workload_name,
                service_id,
            )
        })
        .await
        .map_err(|e| Status::internal(format!("dispatch task panicked: {e}")))?;
        Ok(Response::new(StatusResponse { status: if found { 0 } else { 1 }, uuid: String::new() }))
    }
```

- [ ] **Step 5: Add the test case**

```cpp
TEST_F(GrpcRustControlEndToEndTest, AddWafRuleWithMinimalFieldsReturnsOkStatus) {
  grpc::ClientContext ctx;
  netpolicy::v1::AddWafRuleRequest req;
  req.add_pod_ips("10.0.0.7");
  req.set_mode("passthrough");
  req.set_name("rust-e2e-waf-test");
  netpolicy::v1::StatusResponse resp;
  grpc::Status status = stub_->AddWafRule(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_EQ(resp.status(), 0);
}
```

- [ ] **Step 6: Build, run, commit** (commit message: "Add AddWafRule RPC to the Rust ControlService")

---

## Task 16: Cutover — swap ports, delete the old C++ ControlService

All 12 RPCs are implemented and tested on the development port (50053). This task performs the single production cutover: the Rust server takes over port 50051, `EventService` moves to a new port on the existing C++ server, and the old `ControlServiceImpl`/`DispatchGrpcControlOp`/`ControlWorkQueue` mechanism is deleted.

**Files:**
- Modify: `grpc/grpc_server.h`, `grpc/grpc_server.cc` — remove `ControlServiceImpl`, `control_work_queue_`; keep only `EventServiceImpl`; change the default port to 50052.
- Delete: `grpc/control_service.h`, `grpc/control_service.cc`.
- Modify: `grpc/work_queue.h`, `grpc/work_queue.cc` — remove `ControlOp`, `ControlWorkItem`, `ControlWorkQueue`, `DispatchGrpcControlOp`'s declaration, `DispatchGrpcWorkQueueEvent`'s declaration (verify first, per Step 1, whether anything besides the deleted `ControlServiceImpl` still needs these).
- Modify: `net-policy.cpp` — remove `DispatchGrpcControlOp`, `DispatchGrpcWorkQueueEvent`; change `start_control_server`'s `dev_port` argument from `50053` to the real port; remove the old `g_grpc_server`/`ControlWorkQueue` wiring for control (keep whatever `EventBridge` wiring `EventService` still needs).
- Modify: `grpc/proto_json_bridge.h`, `grpc/proto_json_bridge.cc` — remove the `BuildXxxJson`/`ConvertXxxCJsonToProto` functions that only `ControlServiceImpl`/`DispatchGrpcControlOp` used (verify per Step 1 which ones `EventService` doesn't touch).
- Delete: `tests/grpc_e2e_test.cc`'s `AddPolicyRuleOverRealChannelThenReadBackViaDumpConfig` test (the old-server equivalent of Task 14's new test) and `tests/grpc_control_service_test.cc` (tests `ControlServiceImpl` directly) — keep `SubscribeEventsStreamReceivesPublishedPolicyMatch` and anything else exercising `EventService`.
- Modify: `CMakeLists.txt` — remove the deleted files from both source lists.

**Interfaces:**
- Consumes: every `GrpcDispatchXxx` function from Tasks 4-15 (unchanged — this task only changes what port the Rust server binds and what still runs alongside it).

- [ ] **Step 1: Confirm what `EventService` actually needs before deleting anything**

Read `grpc/event_service.h/.cc` and `grpc/event_bridge.h/.cc` in full. Confirm:
- Whether `EventServiceImpl`'s constructor or any method references `ControlWorkQueue` (it shouldn't, per `grpc_server.h`'s existing comment that `control_work_queue_`/`event_bridge_` are separate members) — if it does, keep whatever it needs instead of deleting it.
- Which functions in `proto_json_bridge.{h,cc}` `EventService`/`EventBridge` call, if any (likely none — `EventBridge::PublishPolicyMatch`/`PublishWafAttack` probably build `PolicyEvent`/`AttackEvent` protos directly rather than going through cJSON) — keep any that are actually shared.

Do not delete anything in later steps that this check shows is still needed.

- [ ] **Step 2: Change the Rust server's port to production (50051)**

In `net-policy.cpp`, change `start_control_server(&daemon, &rust_dispatch_queue, epfd, /*dev_port=*/50053)` to `start_control_server(&daemon, &rust_dispatch_queue, epfd, /*dev_port=*/50051)`. Rename the parameter from `dev_port` to `port` in both the Rust `start_control_server` signature (`crates/net_policy_control/src/lib.rs`) and its `grpc/control_dispatch.h` mentions/comments, since it's no longer a temporary development port.

- [ ] **Step 3: Move `EventService` to port 50052**

In `grpc/grpc_server.h`, change `inline constexpr int kGrpcPort = 50051;` to `inline constexpr int kGrpcPort = 50052;` and update the comment above it (currently says "port for the new gRPC control/event server" — update to reflect it's now event-only).

- [ ] **Step 4: Remove `ControlServiceImpl` from `GrpcServer`**

In `grpc/grpc_server.h`: remove the `#include "grpc/control_service.h"` line, the `ControlServiceImpl control_service_;` member, the `control_work_queue_` member and `GetControlWorkQueue()` accessor, and the constructor-comment references to them. In `grpc/grpc_server.cc`: remove `control_service_` from the constructor's initializer list and from wherever it's registered with `grpc::ServerBuilder` (via `builder.RegisterService(&control_service_)` or similar — read the actual `Start()` implementation to find the exact line).

- [ ] **Step 5: Delete `control_service.{h,cc}`**

```bash
git rm grpc/control_service.h grpc/control_service.cc
```

Remove both from `CMakeLists.txt`'s source lists.

- [ ] **Step 6: Remove the old work-queue/dispatch mechanism**

In `grpc/work_queue.h`: remove `ControlOp`, `ControlWorkItem`, `ControlWorkQueue`, the `DispatchGrpcControlOp`/`DispatchGrpcWorkQueueEvent` declarations. In `grpc/work_queue.cc`: remove `ControlWorkQueue`'s method implementations. If Step 1 found `EventBridge` needs anything from this file, keep only that.

In `net-policy.cpp`: remove `DispatchGrpcControlOp`'s full implementation and `DispatchGrpcWorkQueueEvent`'s implementation. In `RunNetPolicyDaemon`: remove the old `grpcWakeEvent` registration block (the one wired to `DispatchGrpcWorkQueueEvent`) and `daemon.WireGrpc(&g_grpc_server.GetControlWorkQueue(), ...)` — replace with whatever reduced wiring `EventService` alone still needs (likely just the `EventBridge` pointer, so `WireGrpc`'s signature may shrink to just take an `EventBridge*`, or get renamed to something like `WireEventBridge` — check `DaemonContext::WireGrpc`'s current two-parameter signature in `net-policy.h` and adjust it and every call site consistently).

- [ ] **Step 7: Clean up `proto_json_bridge`**

Per Step 1's findings, remove `BuildAddPolicyRuleJson`, `BuildAddWafRuleJson`, `BuildDeleteWafRuleJson`, `BuildDumpHeapProfileJson`, `BuildDumpConnectionsJson`, `BuildUpdateNodeConfigJson`, `ConvertConfigCJsonToProto`, `ConvertConnectionsCJsonToProto` from `grpc/proto_json_bridge.h`/`.cc` (these were only ever called from `DispatchGrpcControlOp`, now deleted) — keep anything Step 1 showed `EventService`/`EventBridge` still uses.

- [ ] **Step 8: Remove superseded tests**

```bash
git rm tests/grpc_control_service_test.cc
```

In `tests/grpc_e2e_test.cc`, remove the `AddPolicyRuleOverRealChannelThenReadBackViaDumpConfig` test (superseded by Task 14's `AddPolicyRuleThenReadBackViaDumpConfig` against the new server) — keep `SubscribeEventsStreamReceivesPublishedPolicyMatch` and the fixture, since `EventService` still needs coverage. If the fixture (`GrpcEndToEndTest::SetUp`) references anything deleted in Steps 4-6 (e.g. `daemon_.WireGrpc(&server_.GetControlWorkQueue(), ...)`), update it to match the reduced `WireGrpc`/`WireEventBridge` signature from Step 6.

Remove both deleted test files from `CMakeLists.txt`'s `net_rule_grpc_test` source list.

- [ ] **Step 9: Build and run everything**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j\$(nproc) net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_test && ./net_rule_grpc_test"
```

Expected: clean build under `-Wall -Werror`; every remaining test passes, including all `GrpcRustControlEndToEndTest.*` cases (now effectively the production ControlService, since it's bound to 50051) and `GrpcEndToEndTest.SubscribeEventsStreamReceivesPublishedPolicyMatch` (still exercising `EventService`, now on port 50052).

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "Cut over ControlService to the Rust server; delete the old C++ implementation"
```

---

## Definition of Done

- `docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j\$(nproc)"` builds `net-rule`, `net_rule_test`, and `net_rule_grpc_test` with no new warnings under `-Wall -Werror`.
- `./net_rule_test` and `./net_rule_grpc_test` both pass in full.
- All 12 `NetPolicyControl` RPCs are served by the Rust `tonic` server on port 50051; `NetPolicyEvents` (`EventService`) is unaffected in behavior, now on port 50052.
- `grpc/control_service.{h,cc}`, the `ControlOp` enum, `ControlWorkItem`/`ControlWorkQueue`, and `DispatchGrpcControlOp` no longer exist in the codebase.
- The legacy raw-socket protocol (port 9999) is untouched and still functions exactly as before this plan — `ParseNetPolicy`/`ParseConfiguration`/`RemoveWafRule`/`handleHeapProfile`/`dumpConnectons`/`ParseNodeCfg` are byte-for-byte unchanged.
