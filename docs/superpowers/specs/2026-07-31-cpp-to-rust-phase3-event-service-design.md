# net-policy: C++ → Rust Migration Phase 3 — EventService Design

## Overview

This is the design for **Phase 3** of the `net-policy` C++→Rust migration (see
the overall roadmap: `docs/superpowers/specs/2026-07-29-cpp-to-rust-migration-design.md`,
Phase 0/1: `docs/superpowers/plans/2026-07-30-cpp-to-rust-phase0-phase1.md`,
Phase 2 (gRPC `ControlService`): `docs/superpowers/specs/2026-07-31-cpp-to-rust-phase2-grpc-control-service-design.md`,
all complete and merged to `main`).

Phase 2's design explicitly deferred two pieces of control-plane work to
future phases: migrating `EventBridge`/`EventService` streaming to Rust, and
retiring the legacy raw-socket control protocol (port 9999). This document
scopes **only the `EventService` migration** — retiring the raw-socket
protocol remains deferred to its own future phase, and the legacy one-way
push channel (`PostServer`, port 8888) — which today runs alongside
`EventService`, sending byte-for-byte the same notifications — is also
explicitly out of scope here.

## Goals

- Replace the C++ `grpc++`-based `EventServiceImpl`/`EventBridge` with a Rust
  `tonic` server hosting the `NetPolicyEvents` service's one RPC,
  `SubscribeEvents`, on the same port (50052) it already occupies.
- Preserve external behavior exactly: the same bounded (256), drop-oldest-
  on-overflow event queue semantics; the same competing-consumer (not
  fan-out/broadcast) behavior across concurrent `SubscribeEvents` calls,
  matching the proto's existing "one active call == one logical listener"
  contract; the same event shapes (`PolicyMatchEvent`, `WafAttackEvent`).
- `PostServer` (port 8888) and the port-9999 raw-socket protocol keep
  running completely unchanged — no client-visible contract change anywhere
  except which process implements `EventService` internally.
- Close the gap in Phase 2's final review's threat model: any C++→Rust
  string conversion at this new FFI boundary must not be able to abort the
  daemon on attacker-influenceable bytes (the exact bug class found and
  fixed in `DumpConnections`/`DumpConfig` during Phase 2).

## Architecture

A new crate, `crates/net_policy_events` (`crate-type = ["staticlib"]`,
wired into `net-rule`/`net_rule_grpc_test` via Corrosion, mirroring
`crates/net_policy_control`'s CMake integration exactly) — its own
`Cargo.toml`, its own `tonic-build`/`prost` codegen against
`proto/net_policy_events.proto` + `net_policy_common.proto` (independent of
`net_policy_control`'s codegen of the same shared `net_policy_common.proto`
— this mirrors how the C++ side already treats each `.proto` file's
generated code as independent, linking against `net_policy_common.pb.cc` as
a separately-compiled shared unit).

A new entry point, `start_event_server(epoll_fd: i32, port: u16) -> u16`,
mirrors `start_control_server`'s shape (own OS thread, own dedicated `tokio`
runtime, port-bound-before-return synchronization via a channel) but takes
**no `DaemonContext` pointer** — `SubscribeEvents` never touches policy/WAF
state, only the event queue, so this crate has zero coupling to
`DaemonContext` or the single-writer invariant that governs
`net_policy_control`.

`GrpcServer`, `EventServiceImpl`, and `EventBridge` (all C++) are deleted
entirely once the cutover lands, the same way `ControlServiceImpl`/
`ControlWorkQueue` were deleted in Phase 2. `PostServer::event_bridge_` and
`PluginContext`'s WAF-attack publish call site are rewired to call new
`cxx` `extern "Rust"` functions directly instead of the C++ `EventBridge`.

Kept on separate ports from `net_policy_control` (50051/50052 stay split)
even though both are now Rust-hosted — avoids a second breaking port change
for anything that already adapted to Phase 2's split (tracked in issue #16).

## Components & Data Flow

**Publish path** (called synchronously from the C++ epoll thread — must
never block or take a lock for long): two new `cxx` `extern "Rust"`
functions, `publish_policy_match(protocol: u8, action: i32, direction: i32,
src_port: u16, dst_port: u16, src_ip: &str, dst_ip: &str, policy_name: &str)`
and `publish_waf_attack(...)` (one param per `WafAttackEvent` field — all
scalars/`&str`, no enum mapping needed there since those fields are already
strings/ints in the source structs). Both are safe `fn` (no raw pointers
cross this boundary, unlike `net_policy_control`'s dispatch functions, so no
`unsafe` is needed). `publish_policy_match` re-implements
`ProtoToL4Protocol`/`NetPolicyRuleToProto`/`FlowDirToProto`'s exact match
arms in Rust — a direct behavioral port, cross-referenced against the C++
originals, not a shared-enum bridge (consistent with how Phase 2 already
treats proto enums as plain `i32` throughout). Both build a
`proto::PolicyEvent` and push it into a Rust-owned bounded (256, matching
today's `kEventQueueCapacity`), drop-oldest-on-overflow queue
(`Mutex<VecDeque<PolicyEvent>>` + `Condvar`), stored behind a `OnceLock`
initialized synchronously before `start_event_server` returns to its
caller — mirroring `start_control_server`'s existing port-handoff-blocks-
until-ready pattern, so the queue is guaranteed to exist before the epoll
loop (and thus any publish call) can begin.

**Subscribe path**: `subscribe_events` drives a `spawn_blocking` loop that
calls a synchronous `wait_and_pop(timeout)` (mirroring
`EventServiceImpl::SubscribeEvents`'s existing `while(!context->IsCancelled())`
+ 500ms-timeout structure almost line-for-line) and forwards each popped
event via `Sender::blocking_send` into a `tokio::sync::mpsc` channel whose
`Receiver` becomes the streaming response body via `ReceiverStream`. A
`blocking_send` failure (client disconnected, tonic dropped the `Receiver`)
breaks the loop — the same shape as today's
`if (!writer->Write(event)) break;`. Competing-consumer semantics (one
shared queue, not fan-out/broadcast) are preserved unchanged, matching the
proto's existing "one active call == one logical listener" comment.

## Error Handling

The most important design decision here, surfaced directly by Phase 2's
final review: `rust::Str` (what `cxx` uses for `&str` parameters) validates
UTF-8 **at construction time on the C++ side** and throws
`std::invalid_argument` if invalid — the exact mechanism behind both the
Phase 0/1 WAF DoS and Phase 2's `DumpConnections`/`DumpConfig` crash. Here
the risk is structurally worse: `publish_policy_match`/`publish_waf_attack`
are called **directly** from `PostServer::SendMatchMsg`/
`PluginContext::onClose` on the epoll thread — there is no
`GrpcDispatchQueue`-style closure boundary to wrap in `try`/`catch` the way
Phase 2's fix did. Several fields carry attacker-influenceable bytes
(`dst_ip`, `attacked_url`, `attack_load`, etc.). An invalid-UTF-8 byte in
any of them would throw on the very thread that processes all packets, with
nothing catching it — a guaranteed fail-open daemon abort, introduced from
day one rather than found in review.

**Fix, baked into the design rather than deferred to a later review round:**
reuse Phase 0/1's `IsValidUtf8()` C++ helper at each call site, immediately
before constructing the `rust::Str` arguments. If any field is invalid,
skip publishing that one event (log a warning) rather than passing invalid
bytes across. This is consistent with the subsystem's existing
"best-effort, no ack, drop under backpressure" semantics — dropping one
malformed event is a smaller behavior change than the queue's existing
drop-oldest-on-overflow policy, which already accepts event loss as normal.

The `wait_and_pop`/`Condvar` machinery inside `spawn_blocking` is plain
Rust-to-Rust internally, so no additional exception boundary is needed
there — the only crossing point that needs the `IsValidUtf8` guard is the
C++-to-Rust publish call.

## Testing & Rollout

Same single-cutover constraint as Phase 2: gRPC's one-service-one-
implementation model means `EventService` can't be split between C++ and
Rust implementations mid-migration — this is an all-at-once cutover, not a
runtime-toggle canary, exactly like the `ControlService` migration.

- **Unit tests** move into the new `net_policy_events` crate itself
  (`cargo test`): the queue's drop-oldest-on-overflow behavior, the
  enum-mapping functions' correctness, and `IsValidUtf8`-guard behavior get
  tested as plain Rust tests — this supersedes `tests/grpc_event_bridge_test.cc`'s
  three existing cases (`PublishPolicyMatchThenWaitAndPopReturnsEvent`,
  `WaitAndPopTimesOutWhenQueueEmpty`, `QueueDropsOldestWhenFullAndLogsWarning`),
  which test `EventBridge` (C++) directly and get deleted once it's gone —
  matching how Phase 2 deleted `grpc_control_service_test.cc` once
  `ControlServiceImpl` was superseded.
- **End-to-end tests**: a new `tests/grpc_rust_events_e2e_test.cc`,
  mirroring `grpc_rust_control_e2e_test.cc`'s `SetUpTestSuite`/
  `TearDownTestSuite` shared-server pattern — start the real Rust event
  server, call the real C++ publish call sites (or a thin test-only
  equivalent), and assert `SubscribeEvents`'s stream actually receives the
  expected `PolicyEvent`. Also worth one cancellation test (client drops
  mid-stream, server-side loop must exit promptly rather than hang).
- **Build/test verification**: same process as Phase 2 — independent
  Docker-container rebuilds from `git archive` at every task and before
  each review, not just implementer self-report.
- **Rollout**: `PostServer` (port 8888) and the port-9999 raw-socket
  protocol are untouched and keep running exactly as today; the design's
  only production-facing change is that `EventService`'s actual
  implementation swaps from C++ to Rust on the already-existing port 50052
  — no port change, no client-visible contract change.

## Deferred to future phases

- Retiring the legacy raw-socket control protocol (port 9999) entirely.
- Retiring `PostServer` (port 8888), the legacy one-way push channel that
  currently duplicates `EventService`'s notifications.
- Merging `ControlService`/`EventService` back onto a single port — both
  are Rust-hosted after this phase, so the one-service-per-port constraint
  that originally forced the split no longer strictly applies, but
  consolidating now would be a second breaking port change in short
  succession for anything that already adapted to Phase 2's split.
- Eliminating the internal JSON round-trip inside the shared legacy parsing
  functions (`ParseNetPolicy` etc.) — still deferred, unrelated to this
  phase; those functions aren't touched by the `EventService` migration at
  all.
