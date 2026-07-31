# net-policy: C++ → Rust Migration Phase 2 — gRPC ControlService Design

## Overview

This is the design for **Phase 2** of the `net-policy` C++→Rust migration (see the
overall roadmap: `docs/superpowers/specs/2026-07-29-cpp-to-rust-migration-design.md`,
Phase 0/1 implementation plan: `docs/superpowers/plans/2026-07-30-cpp-to-rust-phase0-phase1.md`,
both complete and merged to `main`).

The roadmap's Phase 2 row bundles three different pieces: the request/response
`ControlService` (12 RPCs), the streaming `EventBridge`/`EventService`, and
retiring the legacy raw-socket control protocol (port 9999). This document
scopes **only the `ControlService`** — the biggest architectural unknown (an
async Rust `tonic` server coexisting with the daemon's single-threaded epoll
event loop, and the interop direction reversing from Phase 1's "C++ calls
Rust" to "Rust calls C++") gets proven on the simpler, synchronous RPC surface
first. `EventBridge` streaming and legacy-protocol retirement are deferred to
their own future designs once this lands.

## Goals

- Replace the C++ `grpc++`-based `ControlServiceImpl` with a Rust `tonic`
  server that terminates the gRPC connection itself (not just glue called
  from C++), for all 12 `NetPolicyControl` RPCs.
- Preserve the single-writer guarantee on `DaemonContext`'s policy/WAF/connection
  state: it stays touched only from the epoll thread, exactly as today.
- Keep the shared legacy JSON-based parsing functions (`ParseNetPolicy`,
  `ParseConfiguration`, `RemoveWafRule`, `handleHeapProfile`, `dumpConnectons`,
  `ParseNodeCfg`) completely untouched, since the legacy raw-socket protocol
  still calls them directly and is out of scope for this phase.
- No `.proto` changes — `proto/net_policy_control.proto` and
  `net_policy_common.proto` stay the single source of truth for both the
  existing C++ codegen (until deleted) and the new Rust codegen.

## Architecture

The Rust `tonic` server becomes the sole implementation of `NetPolicyControl`
on port 50051. Each RPC handler converts its `tonic`-decoded request into
`cxx`-bridge-compatible types, calls a C++ dispatch function, and converts the
typed C++ result back into the `tonic` response.

**Consequence worth being explicit about**: unlike Phase 1, where individual
WAF functions moved to Rust one at a time while the surrounding C++ kept
running, a single gRPC *service* cannot be split so that some RPCs are served
by `grpc++` and others by `tonic` on the same port — they are one service
definition, served by exactly one implementation at a time. This phase is
therefore an **all-12-RPCs-at-once cutover**, not an incremental per-RPC
strangler pattern. Staging happens at the deployment/environment level (e.g.
canary one environment), not per-RPC.

`EventService` is unaffected in behavior — it keeps running exactly as today,
just rebound from port 50051 to port 50052 on the existing C++ `grpc++`
server, since it can no longer share a port with the new Rust server. This
requires updating whatever config points `EventService` subscribers at their
port.

## C++-side restructuring

- **`ControlWorkItem`** (`grpc/work_queue.h`) changes from
  `{op, request: Message*, response: Message*, status, done}` to a
  closure-based shape: `{work: std::function<void()>, done: std::promise<void>}`.
  Each new dispatch function builds a lambda capturing its typed local C++
  variables by reference, pushes it onto `ControlWorkQueue`, blocks on the
  future, then reads the results after the epoll thread has run the closure.
  This removes the need for protobuf `Message*` (which cannot cross the `cxx`
  boundary) and removes the `ControlOp` enum and the central
  `DispatchGrpcControlOp` switch.
- **12 new typed dispatch functions** replace `DispatchGrpcControlOp`'s 12
  case-blocks — one function per RPC, each taking `cxx`-compatible parameters
  (primitives, `String`, `Vec<String>`, or a small `cxx` shared struct for the
  handful of RPCs with nested/repeated fields, e.g. `AddPolicyRule` and
  `AddWafRule`) and returning a typed result. They stay in `net-policy.cpp`,
  matching the existing precedent (`DispatchGrpcControlOp` lives there today
  specifically for direct `DaemonContext` access) — each function's body is
  essentially today's case-block content unchanged, just with its own
  signature instead of a `switch` arm.
- Dispatch functions that call an already-JSON-based legacy function
  (`ParseNetPolicy`, `ParseConfiguration`, `RemoveWafRule`,
  `handleHeapProfile`, `dumpConnectons`, `ParseNodeCfg`) keep building a JSON
  string from their typed parameters in C++, exactly like
  `grpc_bridge::BuildAddPolicyRuleJson` etc. do today — just fed by
  `cxx`-typed parameters instead of a protobuf object. This keeps the shared
  legacy parsing functions, and the raw-socket path that also calls them,
  completely untouched.
- **Deleted as dead code** once the cutover is complete: `grpc/control_service.{h,cc}`
  (`ControlServiceImpl`), the `ControlOp` enum, `DispatchGrpcControlOp`, and
  the `grpc_bridge::BuildXxxJson`/`ConvertXxxCJsonToProto` functions in
  `proto_json_bridge.cc` that only `ControlServiceImpl` used (functions
  `EventService` still needs, if any, stay). `GrpcServer` (`grpc_server.h/cc`)
  shrinks to own only `EventServiceImpl` and its new port.

## Rust-side structure & type mapping

- New workspace crate, `crates/net_policy_control` (`crate-type = ["staticlib"]`,
  matching `crates/ffi_smoke` and `crates/waf_rules_core`, since it links into
  `net-rule`). Depends on `tonic`, `prost`, `tokio` (multi-threaded runtime),
  `cxx`.
- `build.rs` runs `tonic-build`/`prost-build` against the existing
  `proto/net_policy_control.proto` + `net_policy_common.proto` (same source of
  truth as today's C++ codegen — no proto changes) to generate the Rust
  request/response types and the `NetPolicyControl` service trait.
- One struct implements the generated service trait; each of the 12 methods:
  extracts fields from the `tonic::Request<T>`, converts them to `cxx`-bridge
  types, calls the corresponding C++ dispatch function **wrapped in
  `tokio::task::spawn_blocking`** (the `cxx` call is synchronous and blocks on
  the existing epoll-thread handoff — exactly like today's `grpc++` handler
  thread already does via `future.wait()`, so this preserves current blocking
  behavior rather than introducing new latency, but `spawn_blocking` keeps it
  from stalling `tokio`'s async worker pool under concurrent load), then
  converts the typed C++ result back into the `tonic::Response<T>`.
- The `tonic` server runs on a dedicated `tokio` runtime, started once
  alongside the rest of daemon startup (in `main.cpp`/`RunNetPolicyDaemon`,
  mirroring how `GrpcServer::Start()` is called today) — its own OS thread(s),
  entirely separate from the epoll thread's single-threaded model.

## Testing & validation

- The existing `GrpcEndToEndTest` suite (`tests/grpc_e2e_test.cc`) already
  tests `ControlService` over a real gRPC channel against the C++
  implementation — these become the template for the Rust server's tests:
  same RPC calls, same assertions on observable C++ state (`DumpConfig`,
  connection counts, etc.), just pointed at the new Rust-hosted server
  instead.
- Since state-mutation logic itself does not change (only the
  transport/dispatch-signature layer moves), the main regression risk is in
  the type-conversion boundary (`cxx` parameter marshaling, proto field
  defaults/optionality translating correctly into the typed C++ parameters)
  rather than in policy/WAF logic — tests should focus there.
- Rollout is a single cutover per the port-sharing constraint above: once the
  Rust server passes its test suite, `grpc_server.cc` stops registering
  `ControlServiceImpl` and the old C++ implementation is deleted in the same
  change (no meaningful way to run both against the same port simultaneously
  in production).
- The legacy raw-socket protocol keeps running unchanged in this phase
  (explicitly deferred) — `ParseNetPolicy`/`ParseConfiguration`/etc. still
  serve it directly, and Phase 2's new typed C++ dispatch functions call the
  exact same shared functions, so raw-socket behavior is unaffected either
  way.

## Deferred to future phases

- `EventBridge`/`EventService` streaming migration to Rust.
- Retiring the legacy raw-socket protocol (port 9999) entirely.
- Eliminating the internal JSON round-trip inside the shared legacy parsing
  functions (`ParseNetPolicy` etc.) — deferred because those functions are
  still shared with the raw-socket path; revisit once that path is retired.
