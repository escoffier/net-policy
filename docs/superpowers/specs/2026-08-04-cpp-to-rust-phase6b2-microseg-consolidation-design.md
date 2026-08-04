# Phase 6b-2: Microsegmentation TCP-Tracking Consolidation Design

## Overview

Phase 6b-1 unified L3-L4 five-tuple parsing and made `net::ConnectionManager` (backed by the Rust `net_flow_engine` crate) the single source of TCB (TCP connection) decisions for the WAF path. It deliberately left a second, independent TCP-tracking implementation untouched: microsegmentation's hand-rolled SYN/FIN/RST/sequence-number state machine, embedded directly in `input_nfq_cb`/`output_nfq_cb` (`net-policy.cpp`), backed by two C++ `std::map`s — `MicroSegEngine::TcpCtInput()`/`TcpCtOutput()`.

This redundancy predates the C++→Rust migration entirely: `net_flow_engine`'s TCB tracker (WAF) and microsegmentation's hand-rolled tracker independently reimplement the same core state machine (SYN → track flow, FIN/RST → untrack, data → sequence-ordered reassembly) for the same packets, just for two different consumers (WAF's full HTTP filter/plugin pipeline vs. microsegmentation's lightweight host/path/method extraction for L7 policy matching). Phase 6b-1's design spec flagged this explicitly and scoped it out; this phase is that deferred work.

Two scoping decisions were made before this spec was written (via the same design-spec-then-plan process as every prior phase):

1. **Data structure shape:** microsegmentation's tracked-connection state moves from two `std::map<TcpFourTupleV4, ConnectionPtr>`s split by NFQ queue direction, to a `ConnectionID`-keyed scheme mirroring `net::ConnectionManager::http_conns_` exactly (one entry per side of a flow, keyed by `conn_id`/`peer_conn_id`). This is the more invasive of two options considered, chosen over "keep two directional maps, just swap the driver" specifically to make WAF and microsegmentation structurally symmetric consumers of the same decision, rather than perpetuating two different keying schemes in the codebase.
2. **Reaper scope:** the "TCB entries only removed on FIN/RST, no timeout eviction" characteristic already exists today in microsegmentation's own tracker, in production, with zero relation to this migration (confirmed: nothing anywhere wholesale-clears `tcp_ct_input_`/`tcp_ct_output_`, not even on pod-down). Rather than carrying this forward unexamined, this phase adds a timeout-based reaper to the now-shared `net_flow_engine::FlowEngine` — expanding this phase's scope beyond pure consolidation, by explicit choice, since the code is already being touched.

## Goals

- Retire microsegmentation's hand-rolled SYN/FIN/RST detection in `input_nfq_cb`/`output_nfq_cb`, replacing it with a dispatch on `net::ConnectionManager::ReceiveResult::decision.kind` — the same decision WAF already consumes via `DispatchWaf`.
- Retire microsegmentation's hand-rolled sequence-number duplicate-segment detection (`tcp_seq < tcp_it->second->getTcpSeq()`), moving it into `net_flow_engine`'s `FlowEngine` itself — finally making `FlowState::seq` a real, read field (today it is write-only, kept only for structural parity with the old C++ `Tcb::seq_`).
- Replace `MicroSegEngine::TcpCtInput()`/`TcpCtOutput()` (two `std::map<TcpFourTupleV4, http::ConnectionPtr>`s, keyed by queue direction) with a single `ConnectionID`-keyed map, owned by `net::ConnectionManager`, populated by a new `DispatchMicroseg`-style method that mirrors `DispatchWaf`'s shape.
- Eliminate the `offset`/`tcphdr` manual-reconstruction block Phase 6b-1 added to `input_nfq_cb`/`output_nfq_cb` (the `memcpy(&tcphdr, pkg + result.tuple.ip_header_len, sizeof(tcphdr))` + manual `doff`-based `offset` arithmetic), by extending `PacketDecision` so `ip_header_len`/`payload_offset` are populated for every `kind` (today only `Data` gets real values; `NewConnection`/`Closed` are zeroed) and exposing `seq` directly.
- Add a timeout-based reaper to `FlowEngine`'s TCB table (`tcbs: HashMap<ConnectionId, FlowState>`), driven by a `timerfd`-based periodic wakeup added to the daemon's existing single-threaded `epoll_wait` loop — no new threads, no new locking, matching every architectural constraint respected by every prior phase.
- Verify zero behavior change for well-formed traffic on both consumers (WAF and microsegmentation), matching the verification bar set by every prior phase in this migration.

## Non-Goals

- `MatchMicroPolicyRule`/`MatchNetPolicyRule`'s reverse-match business logic (comparing forward vs. reverse-direction policy priority) is unchanged — this phase only changes how the resulting `rule_key` is *tracked* across subsequent packets on the same flow, not how it's computed.
- `MatchHttpPolicyRule`, `InputHttpPolicy()`/`OutputHttpPolicy()` selection (still purely a function of which NFQ callback is executing, `input_nfq_cb` vs `output_nfq_cb` — confirmed independent of the TcpCtInput/TcpCtOutput→ConnectionID keying change) are unchanged.
- `PostServer::SendMatchMsg`, `rst_tcp_link` are unchanged.
- WAF's own `HandleNewConnection`/`HandleClosed`/`HandleData`/`DispatchWaf` logic is unchanged — this phase adds a sibling consumer, not a replacement.
- NFQ netlink mechanics (`NFQ_RES_INFO`, `InitNfqueue`, `OpenNfque`, `AddEpollEvent`, `NfqueueRcvData`), conntrack (`OpenConntrack`, `UpdateNetSession`, `SetAcceptMark`), and netns switching remain out of scope — Phase 6b-3/6c territory. The only change to the epoll loop itself is adding one new `timerfd` fd to the existing `epoll_ctl(EPOLL_CTL_ADD, ...)` set, registered alongside (not replacing) the NFQ fds.
- The reaper's eviction timeout value is a judgment call made in this spec (see Architecture), not re-litigated as a user-facing scoping decision — it is easily adjustable in the implementation plan/review if it turns out wrong.

## Architecture

### 1. `PacketDecision` extensions (`crates/net_flow_engine/src/lib.rs`)

Add `seq: u32` to the `PacketDecision` FFI struct (meaningful for `NewConnection` and `Data`, not `Closed`). Populate `ip_header_len`/`payload_offset` for **every** `kind`, not just `Data` — `on_packet_internal` already computes `ip_header_len`/`payload_offset` unconditionally near its top (lines 412-413 in the current source) before branching on TCB state; the existing code only *attaches* them to the returned decision for the `Data` branch. Attach them to `NewConnection` and `Closed` too (for `Closed`, they're 0 today because the old C++ never needed them at FIN/RST time either — keep that as-is, it's still correct: no consumer needs payload access on a Closed decision).

This closes the gap that forces `input_nfq_cb`/`output_nfq_cb` to memcpy their own `struct tcphdr` today: once every decision carries `ip_header_len`/`payload_offset`/`seq`, the C++ side never needs to look at the TCP header itself — `net::ConnectionManager::receive()` has already parsed it once (via `net_flow::parse_five_tuple` for the five-tuple, and `on_packet` for the TCB decision) and can hand back everything the downstream consumers need.

### 2. Duplicate-segment detection moves into `FlowEngine` (`crates/net_flow_engine/src/lib.rs`)

Today, `FlowState::seq` is set on SYN (`seq: tcp.seq.wrapping_add(1)`) but never read — duplicate-segment detection is done entirely in C++ (`tcp_it->second->getTcpSeq()` compared against the current packet's `ntohl(tcphdr.seq)`, only inside microsegmentation's data-handling path; WAF's `net::ConnectionManager::HandleData` does no such check today).

Move this into `on_packet_internal`: on a `Data`-kind decision (TCB entry exists, not FIN/RST), compare the packet's `tcp.seq` against the tracked `FlowState::seq`. If the packet's sequence number is behind the tracked value (a duplicate/retransmitted segment), return a decision the C++ caller can recognize as "duplicate, skip" rather than `Data`. The cleanest shape: extend `PacketKind` with a fourth variant, `DuplicateData` (or keep `Data` and add a `bool is_duplicate` field to `PacketDecision` — pick whichever keeps the FFI struct's `#[derive(Default)]` semantics clean during implementation; a `bool` defaulting to `false` is likely simpler than a fifth enum discriminant crossing the FFI boundary, but both are viable, decide in the implementation plan). On a non-duplicate `Data` decision, advance `FlowState::seq` by the payload length (mirroring the old C++'s `setTcpSeq(tcp_seq + payload_len)`) — this requires `on_packet_internal` to know the payload length, which it already computes as part of deriving `payload_offset` (`bytes.len() - payload_offset`).

This is squarely within the "Rust owns netlink/TCP mechanics, C++ owns business logic" boundary established at the start of Phase 6b's planning: sequence-ordered duplicate detection is TCP mechanics, not HTTP-policy business logic, and both consumers (WAF and microsegmentation) benefit from it being centralized rather than only microsegmentation implementing it today.

**Note:** WAF's `HandleData` currently has no duplicate-segment guard at all. Once this lands, WAF gets one for free (a behavior change, technically — but a corrective one, since duplicate/retransmitted TCP segments being fed twice into `setTCPSegment`/HTTP parsing was already a latent gap on the WAF path). Flag this explicitly in the implementation's commit message per this project's practice of not silently resolving cross-cutting behavior changes — do not silently absorb it as "no behavior change," it is a real (and desirable) one for WAF specifically.

### 3. `ConnectionManager` gains a second map and a `DispatchMicroseg` method (`net/connection_manager.h`)

```cpp
class ConnectionManager {
public:
  struct ReceiveResult {
    net_flow::SharedFiveTuple tuple;
    net_flow::PacketDecision decision;
    bool is_tcp;
  };

  // unchanged: receive(pkg, len, track_tcp) -> ReceiveResult

  // unchanged: DispatchWaf(decision, pkg, len) -> NetStatus

  // NEW: mirrors DispatchWaf's shape, but for microsegmentation's simpler
  // per-flow state (a rule_key plus TCP-sequence bookkeeping, not a full
  // HttpFilterManager pipeline). `rule_key` must already be resolved by the
  // caller (via MatchMicroPolicyRule) before a NewConnection decision is
  // dispatched here -- this method does not perform policy matching itself,
  // matching DispatchWaf's existing division of labor (ConnectionManager
  // owns tracking state; policy matching stays the caller's job).
  //
  // Returns the reconstructed HTTP header state for the caller to run
  // MatchHttpPolicyRule against, or std::nullopt if this decision doesn't
  // produce one (NewConnection, Closed, Duplicate, or a Data packet whose
  // HTTP parse isn't Done yet).
  std::optional<http::Header> DispatchMicroseg(const net_flow::PacketDecision& decision,
                                                const uint8_t* pkg, size_t len,
                                                const std::string& rule_key);

private:
  // unchanged: HandleNewConnection/HandleClosed/HandleData (WAF), http_conns_

  // NEW: microsegmentation's own per-flow state, deliberately a SEPARATE map
  // from http_conns_ (not merged into it) -- WAF can be disabled independently
  // of microsegmentation, and the two payloads differ (WAF's Connection is
  // HttpFilterManager-driven; microseg's just needs a rule_key + the TCP
  // sequence/duplicate bookkeeping now owned by FlowEngine itself). Both maps
  // are populated from the SAME underlying decision, keeping them referentially
  // consistent without coupling their lifecycles.
  std::unordered_map<ConnectionID, http::ConnectionPtr, ConnectionIDHash> microseg_conns_;
};
```

`DispatchMicroseg`'s internal shape mirrors `DispatchWaf`'s switch on `decision.kind`, but simpler: `NewConnection` constructs a `Connection(rule_key)` (today's existing constructor, unchanged) and inserts it (plus the peer entry if `peer_is_new`, matching `HandleNewConnection`'s existing pattern) into `microseg_conns_`; `Closed` erases both `conn_id` and `peer_conn_id` entries; `Data`/duplicate calls the tracked `Connection::onData()` (unchanged method) using `decision.payload_offset` directly (no more manual `pkg + offset` — this IS the offset) and returns the resulting `http::Header` for the caller to match against `InputHttpPolicy()`/`OutputHttpPolicy()`, exactly as today; a duplicate decision returns `std::nullopt` without touching `onData()` at all (mirrors the old `tcp_seq < getTcpSeq()` early-return).

### 4. `input_nfq_cb`/`output_nfq_cb` rewrite (`net-policy.cpp`)

The whole hand-rolled block — `ct_key` construction, the `switch (tuple.proto_) { case IPPROTO_TCP: ... }` SYN/FIN/RST/ACK detection, the manual `offset`/`tcphdr` reconstruction, `TcpCtInput()`/`TcpCtOutput()` lookups, `setTcpSeq`/`getTcpSeq` duplicate checks — collapses to:

1. Call `MatchMicroPolicyRule` up front (unchanged call, unchanged signature) whenever `result.decision.kind == NewConnection` (mirrors today's "only match policy once, at SYN/first-sight" behavior — note today's code actually calls `MatchMicroPolicyRule` on *every* not-yet-tracked packet, not strictly only SYNs, because `found` starts false and the `TcpCtInput()`/`TcpCtOutput()` lookup can miss for reasons other than "never seen a SYN" (e.g., a non-TCP protocol, or a TCP ACK arriving before a SYN was ever tracked) — preserve this: for UDP/ICMP, and for a TCP packet whose decision is `Data`/`Duplicate` but has no existing `microseg_conns_` entry (the flow was never tracked, e.g., the daemon started mid-connection), still call `MatchMicroPolicyRule` exactly as today, not only on `NewConnection`).
2. For `NewConnection`: dispatch to `DispatchMicroseg` with the freshly-matched `rule_key`.
3. For `Data`/`Duplicate`/`Closed` on an already-tracked flow: dispatch to `DispatchMicroseg` (no rule_key needed — it reads it back from the tracked `Connection::getRuleKey()`, unchanged from today).
4. If `DispatchMicroseg` returns a `Header`, run `MatchHttpPolicyRule` against it exactly as today.

UDP/ICMP packets still bypass all TCB dispatch (mirrors today's `case IPPROTO_UDP: case IPPROTO_ICMP: break;`), going straight to `MatchMicroPolicyRule` + `SendMatchMsg`, unchanged.

This is the highest-risk part of this phase — full parity with today's control flow (which mixes "is this flow tracked," "is this the first sight of this five-tuple," "was a rule already matched for it," and "which direction's HTTP policy dict to check" in one dense block) must be preserved exactly for well-formed traffic. The implementation plan must include a step that traces every one of today's return paths (the ones already read and quoted in Phase 6b-1's plan) against the new dispatch shape before writing code, not just after.

### 5. Reaper (`crates/net_flow_engine/src/lib.rs` + `net-policy.cpp`'s epoll loop)

- `FlowState` gains a `last_seen: Instant` (or a monotonic tick counter, if `std::time::Instant` proves awkward to reason about in tests — decide in the implementation plan) field, updated on every packet that touches an entry (SYN, Data, duplicate check).
- `FlowEngine` gains an `evict_stale(now, timeout) -> Vec<ConnectionId>` method (or similar), sweeping `tcbs` and removing entries older than `timeout`, returning what was evicted (so the C++ side can also clear the corresponding `microseg_conns_`/`http_conns_` entries — the FFI boundary needs a way to report evicted IDs, not just silently drop them Rust-side, or the C++-side maps go stale/leak in the opposite direction).
- Default timeout: 5 minutes. Rationale: this tracker's only purpose is reconstructing in-flight HTTP request/response headers for policy matching, not general TCP connection tracking — real HTTP client/server idle timeouts are typically in the tens of seconds to low minutes (e.g. common proxy defaults cluster around 60-300s), so 5 minutes gives comfortable slack without holding stale entries indefinitely. Make it a compile-time or config-driven constant, not hardcoded inline, so it can be tuned without another design pass.
- Trigger: a `timerfd_create(CLOCK_MONOTONIC, ...)` fd, armed with `timerfd_settime` for a periodic interval (e.g. every 60s — independent of the 5-minute entry timeout; a shorter sweep interval just bounds how stale an evictable entry can get before it's actually swept), added to the existing `epoll_ctl(EPOLL_CTL_ADD, epfd, ...)` set alongside the NFQ fds in whatever init path sets those up. Its callback calls into `FlowEngine::evict_stale` (via a new FFI entry point) and clears the corresponding `microseg_conns_`/`http_conns_` entries in `ConnectionManager`.
- This is the one piece of this phase that's genuinely new capability, not a port — implement and test it with real time-manipulation in the Rust unit tests (inject a fake clock or accept an explicit `now: Instant` parameter to `evict_stale` rather than reading the system clock internally, so tests don't need real sleeps).

## Testing & Rollout

- Rust unit tests: extend `flow_engine_tests` for the new `seq`-based duplicate detection (send a SYN, then replay an already-seen sequence number, confirm the decision reflects "duplicate" and the tracked `seq` doesn't regress) and for `evict_stale` (inject entries with controlled `last_seen` values, advance a fake clock, confirm only stale entries are evicted, confirm live entries survive).
- C++ FFI smoke tests for the extended `PacketDecision` fields (`seq`, and `ip_header_len`/`payload_offset` now populated for `NewConnection` too).
- `ConnectionManagerCutoverTest`-style tests for `DispatchMicroseg`, exercising the full SYN → data → HTTP-header-reconstruction → FIN lifecycle against a real `ConnectionManager`, structurally mirroring the existing WAF-path tests.
- A dedicated end-to-end trace, written up as a test or at minimum a manually-verified walkthrough (matching the rigor of Phase 6b-1's final review, which hand-traced a TCP SYN through the whole callback): confirm a TCP SYN → HTTP request → policy match sequence through `input_nfq_cb` produces the identical verdict sequence before and after this phase, for both an allow and a deny rule.
- Reaper: a test that simulates the timerfd firing (calling the eviction path directly, not actually waiting on a real timer) and confirms both `FlowEngine`'s `tcbs` and `ConnectionManager`'s `microseg_conns_`/`http_conns_` maps shrink correctly, with no dangling `Connection` objects left referencing an evicted ID.
- As with every prior phase on this hot path: direct cutover, no shadow-run — matching the established rationale (this is packet-verdict logic; a shadow-run comparison adds complexity without a clear way to safely observe divergence on production traffic).

## Final State

- Microsegmentation and WAF share one TCB tracker (`net_flow_engine::FlowEngine`) and one five-tuple parser (`net_flow::parse_five_tuple`), each with their own lightweight per-flow state map (`ConnectionManager::http_conns_` for WAF, `ConnectionManager::microseg_conns_` for microsegmentation), both populated from the same `ReceiveResult` per packet.
- `input_nfq_cb`/`output_nfq_cb` no longer contain any hand-rolled TCP state detection, sequence-number comparison, or manual header re-parsing — they dispatch on `decision.kind` and consult `MatchMicroPolicyRule`/`MatchHttpPolicyRule` exactly as before.
- `net_flow_engine`'s TCB table has a real, tested eviction path, closing a pre-existing (not migration-introduced) unbounded-growth characteristic that both consumers now share responsibility for triggering cleanup on.
- Remaining before Phase 6b is fully done: Phase 6b-3 (NFQ netlink mechanics, `NFQ_RES_INFO` lifecycle, netns switching) — untouched by this phase, planned separately when its turn comes.
