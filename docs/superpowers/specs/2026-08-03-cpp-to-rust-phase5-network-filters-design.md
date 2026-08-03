# net-policy: Phase 5 — Network Filters Migration Design

## Overview

Phase 5 of the C++→Rust migration (see the [overall roadmap](2026-07-29-cpp-to-rust-migration-design.md)) migrates the IPv4/TCP packet-layer parsing and per-flow connection tracking currently in `net/ip.cc` (`ipv4`) and `net/tcp.cc` (`Tcp`/`Tcp::Tcb`) to a new Rust crate, `net_flow_engine`. This is the layer that turns a raw NFQ packet into "which TCP flow is this, is it new/data/closing, where does the payload start" — sitting between NFQ packet capture (`net-policy.cpp`, Phase 6 scope) and the HTTP/WAF inspection stack (`http/`, `waf/`, not yet migrated).

The original roadmap described this phase's scope as `net/filter.*`, `net/ip.*`, `net/tcp.*`, `net/udp.*`, `net/utility.*`, `net/connection_manager.h`, noting only that it "operates on packet buffers already handed up from NFQ; no direct netlink dependency, so it can move before Phase 6." That's true, but it doesn't mention a real coupling this spec had to resolve: `Tcp::receive` doesn't just do TCP header parsing and connection-tracking bookkeeping — in the same function body, on every packet, it also directly drives the still-C++ HTTP filter chain (`http::HttpFilterManager`, `http::Connection`), which isn't in scope for this phase (HTTP codecs are their own, larger, not-yet-scheduled phase). This spec's Architecture section describes the seam that lets the TCP/IP parsing and flow-tracking state machine move to Rust now without touching HTTP-layer code at all.

This spec also confirms two additional roadmap-adjacent findings from reading the actual code:
- `net/filter.{h,cc}` (`NetworkFilterManager`/`NetworkFilterBase`) is dead code — compiled into every target's `SOURCES` list but never instantiated or called anywhere outside its own two files. (Not to be confused with the unrelated, very much live `http::HttpFilterManager` in `http/filter.h`.)
- `net/udp.{h,cc}` (`Udp`) is also dead code — `ipv4`'s protocol dispatch table wires UDP to `nullptr`, and `Udp` doesn't even implement its `IPProtocol` interface's pure virtuals (`stat()`, `connections()`), so it isn't instantiable as written.

Both are deleted rather than migrated, the same treatment Phase 4 gave the confirmed-dead `policy/engine.{h,cc}`.

## Goals

- Move IPv4 header parsing and protocol dispatch (`ipv4::receive`) and TCP header parsing plus the TCB/connection-tracking state machine (`Tcp::receive`'s SYN/FIN/RST lifecycle, `ConnectionID`-keyed flow table) to Rust.
- Preserve exact behavior: which packets open a new flow, which close one, where the TCP payload begins (`hdrLen` from `tcp_hdr->doff * 4`), and the peer-connection auto-creation quirk (a SYN on one direction also seeds a TCB for the reverse `ConnectionID`, sharing one `filter_manager`) — verified via a differential test against the real C++ implementation, not manual re-derivation.
- Keep `net::ConnectionManager`'s public interface (`receive`, `stat`, `connections`) unchanged in signature — every caller (`net-policy.cpp`'s two `ConnMgr().receive(...)` call sites, `admin/profile.cc`'s dump path) needs zero changes beyond what Architecture below describes for the `receive` call sites specifically.
- Delete the confirmed-dead `net/filter.{h,cc}` and `net/udp.{h,cc}`.

## Non-Goals (deferred to later phases)

- **The HTTP/WAF filter chain itself** (`http::HttpFilterManager`, `http::Connection`, `onNewConnection`/`onData`/`onClose`/`processData`/`setTCPSegment`) — stays in C++ untouched. This is the not-yet-scheduled HTTP codec phase from the original roadmap (its "3a/b/c").
- **`seastar::net::packet`** (`http/packet.hh`/`.cc`, `http/temporary_buffer.hh`, `http/deleter.hh` — this project's own vendored zero-copy buffer type, not the real Seastar library; every `#include <seastar/...>` in those files is commented out) — stays a C++-only type. Rust never touches it; see Architecture.
- **NFQ/netlink** (`net-policy.cpp`'s main loop, raw packet capture) — unchanged; Phase 6 in the original roadmap.
- **`net/connection_manager.h`, `net/stream.h`, `net/utility.h`'s `NetStatus`/`NetworkStat` types** — these are thin C++ glue/POD types that stay as C++ declarations; only `net/utility.cc`'s one real function (`ipv4ToString`) and the actual parsing/tracking logic move. (`ConnectionManager` itself becomes a thinner wrapper — see Architecture — but keeps its class identity and header location.)
- **`net/ip_protocol.h`'s `IPProtocol` interface is NOT a non-goal — it's deleted.** It's a virtual interface implemented only by `Tcp` and `Udp`, both deleted by this phase (Task 1 deletes `Udp`, the cutover task deletes `Tcp`); once neither implementer nor `ipv4`'s `l4_[256]` dispatch table (the interface's only consumer) exists, it becomes newly-orphaned dead code as a direct result of this phase, not pre-existing dead code — delete it in the same task that deletes `Tcp`, don't leave it behind for a future review to catch.

## Architecture

**The key simplification: Rust takes raw packet bytes, not the C++ packet object.** At both real call sites (`net-policy.cpp`, the input and output NFQ callbacks), the C++ code already has the raw NFQ buffer as `(unsigned char* pkg, int data_len)` *before* it constructs a `seastar::net::packet` — the construction (`seastar::net::packet::from_static_data((char*)pkg, data_len)`) exists only to satisfy `ConnectionManager::receive`'s current parameter type. Since Phase 5 is moving the code that would otherwise consume that packet object (`ipv4::receive`, `Tcp::receive`), there's no reason to build it at all for this call path anymore: the new entry point takes `(const uint8_t* pkg, size_t len)` directly. This means the `cxx` bridge for this phase never needs to represent `seastar::net::packet` on the Rust side — the single most complex C++ type in scope is simply bypassed, not bridged.

**Ownership split for the TCB.** Today, `Tcp::Tcb` bundles two things that don't need to travel together: pure TCP-layer state (`seq_`, `server_side_`) and an HTTP-layer object (`http_`, a `shared_ptr<http::Connection>`). Phase 5 splits them:
- Rust's `FlowEngine` owns a `ConnectionId → FlowState { seq, server_side }` map — the full SYN/FIN/RST state machine, exactly mirroring today's `tcbs_`/`ConnectionID`/`ConnectionIDHash` — with no knowledge of HTTP types.
- `net::ConnectionManager` (C++, still in `net/connection_manager.h`) gains a new `ConnectionID → shared_ptr<http::Connection>` map — the same key type used today, holding only what Rust doesn't own. This is new code, but it is a strict subset of what `Tcp`/`Tcb` already did; nothing about how `http::Connection`/`HttpFilterManager` are constructed or invoked changes.

**One call per packet.** `ConnectionManager::receive` becomes:
```cpp
NetStatus ConnectionManager::receive(const uint8_t* pkg, size_t len) {
  auto decision = engine_->on_packet(pkg, len);
  switch (decision.kind) {
    case PacketKind::Ignore: return NetStatus::OK;
    case PacketKind::NewConnection: /* construct filter_manager, http::Connection(s), as today */ ...
    case PacketKind::Closed: /* look up http map by decision.conn_id, onClose(), erase */ ...
    case PacketKind::Data: /* look up http map, seastar::net::packet::from_static_data(pkg, len) trimmed by decision.payload_offset, setTCPSegment/onData/processData exactly as today */ ...
  }
}
```
This mirrors Phase 4's FFI-granularity principle ("one call per logical operation, not one call per current C++ method") — `ipv4::receive`'s IPv4-header-then-dispatch and `Tcp::receive`'s TCP-header-then-TCB-lookup collapse into the single `on_packet` call, internally doing both layers of parsing in Rust. The returned `PacketDecision` shared struct carries everything the C++ side needs to replay today's exact HTTP-layer call sequence: `kind` (discriminant), `conn_id`/`peer_conn_id` (the same `ConnectionID` shape, now a `cxx` shared struct), `peer_is_new` (mirrors today's `peer_it == tcbs_.end()` check — whether the reverse-direction TCB was newly created too, which decides whether a second `http::Connection` gets constructed), `from`/`to`/`from_port`/`to_port`, and `payload_offset` (byte offset into the original `(pkg, len)` buffer where the TCP payload begins — C++ still constructs `seastar::net::packet` at this one remaining point, exactly as `net-policy.cpp` does today, just later and only when `kind == Data`).

Only `Data`-kind decisions ever reach the HTTP `onData`/`processData` calls that can return `NetStatus::Drop` — the pure parsing/tracking logic in Rust never itself produces a `Drop` verdict, matching today's behavior exactly (nothing in `ipv4::receive`/`Tcp::receive`'s non-HTTP-calling branches ever returns `NetStatus::Drop`).

**Ownership model.** `FlowEngine` is owned per-`ConnectionManager`-instance via `rust::Box`, constructed in `ConnectionManager`'s constructor alongside the (unchanged) `http_filter_factory_` reference — the same instance-owned pattern Phase 4 used for `RustPolicyEngine`, for the same reason: `DaemonContext::connection_manager_` is a plain member (confirmed by reading `net-policy.h:490-491`), not a singleton, and test binaries construct multiple `DaemonContext`s.

**`stat()`/`connections()`.** These become thin calls into `FlowEngine` (`engine_->live_connection_count()`, `engine_->connection_strings()`), replacing today's `Tcp::stat()`/`Tcp::connections()` which iterate `tcbs_`. Output format (the `"ip:port,ip:port"` strings `Tcp::connections()` builds via `ipv4ToString`) is preserved exactly — `admin/profile.cc`'s `CONN_DUMP` path and the existing `net_rule_grpc_test`'s `DumpConnectionsReturnsWithoutError` test are unaffected in behavior, just now backed by Rust state.

**UTF-8 / unsafe-FFI notes.** No string data crosses this boundary — `ConnectionId`'s fields are plain integers (`u32` addresses, `u16` ports), so the `IsValidUtf8` guard pattern from every prior phase doesn't apply here. The raw-pointer parameter (`*const u8`, `len`) follows the `unsafe extern "C++"`/`unsafe fn` precedent already established in Phase 2's `net_policy_control` bridge (`unsafe fn GrpcDispatchResetConfig(daemon: *mut DaemonContext, ...)`); Rust only reads within `[pkg, pkg+len)`, bounds-checked against `len` before every header-field access, mirroring the length checks `ipv4::receive`/`Tcp::receive` already perform (`packet.len() < sizeof(iphdr)`, `if (!th)`/`hdrLen < TCP_HDR_LEN`).

## Testing & Rollout

**Dead code removal is independent and goes first.** Deleting `net/filter.{h,cc}` and `net/udp.{h,cc}` doesn't depend on anything else in this phase (confirmed zero external references — see Overview) and shrinks the surface the rest of the phase has to reason about. It's its own task/commit, not folded into the cutover.

**Pure-parsing correctness via ordinary unit tests, not a differential harness.** IPv4/TCP header field extraction (`ihl`, `doff`, address/port byte order, the `hdrLen < TCP_HDR_LEN` and `packet.len() < sizeof(iphdr)` bounds checks) is deterministic arithmetic with no legacy-quirk ambiguity to replicate — Rust unit tests with hand-constructed byte arrays (mirroring `waf_rules_core`'s testing style) are sufficient, the same reasoning Phase 4 used for its own CIDR-helper unit tests before layering the differential harness on top for the genuinely stateful/quirky matching logic.

**Differential test for the TCB state machine.** This is where legacy behavior (the peer-TCB auto-creation quirk, exact FIN/RST-triggers-double-erase behavior, SYN-without-prior-state handling) needs bug-for-bug replication, verified rather than re-derived. The harness constructs a real, unmodified `net::ConnectionManager` (backed by a real but filter-less `http::HttpFilterFactory` — `HttpFilterFactory()` is default-constructible with an empty filter list per `http/http_filter_factory.h`, so this exercises the *real* TCB lifecycle code with no WAF/HTTP-inspection side effects to control for) side-by-side with the new `FlowEngine`, feeds both the same sequences of synthetic raw IPv4+TCP byte buffers (SYN, data, FIN/RST, out-of-order edge cases like data-before-SYN and a stray RST-without-existing-TCB), and asserts, after each packet, that `ConnectionManager::connections()` (old path) and `FlowEngine`'s equivalent connection-set accessor (new path) report the same live-flow set. This checks the state-machine's observable behavior (which flows exist) without needing to inspect or mock deep HTTP-layer call arguments, since HTTP behavior itself isn't changing in this phase.

**Cutover.** Once both test tiers pass:
1. Add the new `(const uint8_t*, size_t)`-taking `ConnectionManager::receive` overload backed by `FlowEngine`, update `net-policy.cpp`'s two call sites to pass `(pkg, data_len)` directly instead of constructing a `seastar::net::packet`, and add the `ConnectionID → shared_ptr<http::Connection>` map to `ConnectionManager`.
2. Delete `net/ip.{h,cc}` (`ipv4`), `net/tcp.{h,cc}` (`Tcp`/`Tcb`/`ConnectionID`/`ConnectionIDHash`), and the old `ConnectionManager::receive(seastar::net::packet)` overload.
3. Delete the differential test file, following Phase 4's precedent — once there's one implementation, a comparison test no longer makes sense; ongoing correctness is covered by `FlowEngine`'s Rust unit tests plus the existing `net_rule_test`/`net_rule_grpc_test` C++ integration tests (`ConnectionManagerTest.onData`, `DumpConnectionsReturnsWithoutError`) that already exercise this path end-to-end.

This is a **direct cutover**, not a shadow-run period — same rationale as Phase 4: this sits on the enforcement hot path (a dropped or misrouted TCP segment is a correctness bug, not a side effect safe to duplicate), and the differential suite is a pure, I/O-free, trivially-fuzzable oracle for exactly this class of bug.

## Final State

`net_flow_engine` is a new Rust crate, instance-owned (via `rust::Box`) inside `net::ConnectionManager`, performing IPv4/TCP header parsing and TCB/flow-tracking state. `net::ConnectionManager` retains a small `ConnectionID → shared_ptr<http::Connection>` map and continues to drive the unchanged HTTP/WAF filter chain exactly as `Tcp::receive` does today, now triggered by `FlowEngine`'s returned `PacketDecision` instead of doing its own TCP state machine inline. `seastar::net::packet` is untouched and never crosses the Rust boundary. `net/filter.{h,cc}` and `net/udp.{h,cc}` are deleted as confirmed dead code. `net/ip.{h,cc}` and `net/tcp.{h,cc}` are deleted once the differential suite passes and the cutover lands.
