# Phase 6b-2: Microsegmentation TCP-Tracking Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Retire microsegmentation's independent, hand-rolled SYN/FIN/RST/sequence-number TCP state machine (`MicroSegEngine::TcpCtInput()`/`TcpCtOutput()`, plus the corresponding block in `input_nfq_cb`/`output_nfq_cb`) in favor of the same `net::ConnectionManager`/`net_flow_engine` TCB tracking WAF already uses — via a new `ConnectionManager::DispatchMicroseg` sibling to the existing `DispatchWaf`, keyed by `ConnectionID` exactly like WAF's `http_conns_`. Add a timeout-based reaper to the now-shared `FlowEngine` TCB table, closing a pre-existing (not migration-introduced) unbounded-growth characteristic while this code is already being touched.

**Architecture:** See `docs/superpowers/specs/2026-08-04-cpp-to-rust-phase6b2-microseg-consolidation-design.md` for the full design rationale. This plan refines two points discovered during more precise tracing while writing task specs — both are corrections to the design spec's Architecture section #1, not scope changes:

1. **`PacketDecision` does NOT need `seq` exposed, nor `ip_header_len`/`payload_offset` extended to `NewConnection`/`Closed`.** Tracing the current C++'s SYN/FIN/RST branches precisely shows neither ever touches packet payload bytes or needs a raw sequence number in C++ once duplicate-detection moves into Rust (see Task 1) — `Connection::setTcpSeq`/`getTcpSeq`/`tcp_seq_` become entirely dead code after this phase (confirmed via full-repo grep: used nowhere outside `input_nfq_cb`/`output_nfq_cb`'s microseg block). `ip_header_len`/`payload_offset` are only ever needed on `Data`-kind decisions, which already carry them correctly since Phase 5/6b-1 — no FFI struct field changes needed for these.
2. **Two new `PacketKind` variants are needed instead: `Duplicate` and `UnknownData`.** `Duplicate` (kind 4) is the sequence-based dedup decision. `UnknownData` (kind 5) is a new decision `on_packet_internal` returns for a non-SYN, non-RST TCP packet on a flow it isn't tracking — today's Rust code silently returns `None`/Ignore for this case; this phase makes it an explicit, distinguishable decision so microsegmentation's **late-binding recovery** (start HTTP tracking mid-stream for a flow whose SYN was never seen, if a policy still needs header inspection — a real, load-bearing behavior in the current C++, confirmed reachable and intentional, not dead code) can be preserved without WAF's behavior changing (`DispatchWaf` gets an explicit case for kind 5 that's a no-op, matching its current implicit behavior exactly).

## Global Constraints

- **The "found" semantics must be preserved exactly.** In the current C++, "found" means "there is an existing tracked `Connection` for this five-tuple in `TcpCtInput()`/`TcpCtOutput()`" — NOT "is this TCP flow known to the TCB tracker." A flow can be fully tracked by the TCB state machine (SYN seen, entry exists) while having NO tracked `Connection` in microseg's map, because at SYN time `MatchMicroPolicyRule` found no HTTP policy requiring inspection, so no `Connection` was ever created for it (see the current code's early-return in the `!found` block: `if ((http_rule == end()) || proto==UDP || proto==ICMP || http_rule->second.empty()) { ...return early, no Connection created... }`). Consequently, **`MatchMicroPolicyRule` is called again on every subsequent packet of such a flow, not just once at SYN time** — this is current, intentional-if-wasteful behavior, and this phase must not silently change it. The post-consolidation design mirrors this via two separate `ConnectionManager` calls: `MicrosegTracked(decision)` (pure lookup, no mutation) determines whether to skip straight to `DispatchMicroseg`'s tracked-entry path or re-run `MatchMicroPolicyRule` first, exactly matching today's `found`/`!found` split.
- **`Connection::setTcpSeq`/`getTcpSeq`/`tcp_seq_` become fully dead code after this phase** (moved into `FlowState::seq` in Rust — see Task 1). Do NOT delete them from `http/connection.h` in this plan — `Connection` is a shared class also used by WAF's `HandleNewConnection`/`HandleData` path (which never used these members), and removing dead members from a shared class is a separate, unrelated cleanup, out of scope here. Leave a note in the final task's report flagging this as a follow-up opportunity.
- **`TcpFourTupleV4`/`TCP_FOUR_TUPLE_V4`, `MicroSegEngine::TcpCtInput()`/`TcpCtOutput()`, and their backing `tcp_ct_input_`/`tcp_ct_output_` maps become fully unreferenced once Task 5 lands.** Task 7 confirms this and deletes them — do not delete them in earlier tasks even if they look unused mid-plan; confirm via grep first, matching this project's established practice (Phase 6b-1's `parse_package` retirement).
- **RST on an unknown flow does not get the `UnknownData` treatment — a deliberate, documented narrowing from today's C++.** `on_packet_internal`'s existing `if tcp.rst { return None; }` for unknown flows (Phase 5, unchanged) means `UnknownData` is returned only for "not SYN, not RST" on an unknown flow. Today's C++ does not special-case RST in its equivalent "not found" branch, so in principle a bare RST arriving on an untracked flow could today trigger microseg's late-binding path too. This is judged to be a negligible, almost-certainly-inconsequential difference (a RST carries essentially never any parseable HTTP payload — `onData()` would fail to reach `ParseState::Done` regardless, so the observable policy verdict is unaffected either way) and the resulting design is cleaner. Flag this explicitly in the final task's commit message per this project's practice of not silently resolving quirks — do not treat it as something to "fix" by also making RST trigger `UnknownData`.
- **WAF's `DispatchWaf` gains two explicit new cases (kind 4 `Duplicate`, kind 5 `UnknownData`), both `return NetStatus::OK` (no-op).** For `Duplicate`, this is a *new, desirable* behavior change for WAF — it did not have any retransmitted-segment guard before this phase (confirmed via grep: no sequence-number check anywhere in `net/connection_manager.h`'s `HandleData`). Flag this explicitly in Task 1's commit message; do not silently absorb it as "no behavior change for WAF" — it is a real, if minor and corrective, one. For `UnknownData`, this exactly matches WAF's current implicit behavior (today, `on_packet_internal` returns `None`/Ignore for this case, and `DispatchWaf`'s existing `default:` handles kind 0 the same way `NetStatus::OK` would for an explicit case) — genuinely zero behavior change for WAF, just made explicit instead of falling through `default:`.
- **UDP/ICMP packets never enter TCB dispatch at all**, in the old code or the new — they go straight to `MatchMicroPolicyRule` + `SendMatchMsg`, exactly as today. Do not route them through `DispatchMicroseg`/`MicrosegTracked` in any way.
- **Direct cutover, no shadow-run** — matching every prior phase's rationale on this hot path.
- Verify every code snippet, line number, and file structure in this plan against the actual current source before editing — line numbers may have drifted since this plan was written.
- Follow the memory-pressure build guidance from Phase 6b-1: always build with `-j2` in the `net-policy-build-test` container (7.7GB RAM; higher parallelism during Rust compilation causes intermittent linker/archiver corruption, a known flake — `rm -rf build/cargo` and retry at `-j2` if hit). Use a login shell (`bash -lc`) for direct `cargo`/`rustc` invocations outside the CMake build.

---

### Task 1: Extend `net_flow_engine`'s TCB state machine — duplicate detection and the `UnknownData` decision

**Files:**
- Modify: `crates/net_flow_engine/src/lib.rs` (`FlowState`, `PacketKind`, `on_packet_internal`, the `on_packet` FFI wrapper, the `ffi::PacketDecision` bridge struct's doc comment)

**Interfaces:**
- Consumes: nothing new.
- Produces: `PacketKind::Duplicate` (FFI kind 4), `PacketKind::UnknownData` (FFI kind 5); `FlowState::seq` becomes a real, read field (drop its `#[allow(dead_code)]`); `on_packet_internal` gains a `now: Instant` parameter (Rust-internal only — the FFI-facing `on_packet(pkg, len)` signature is UNCHANGED, it calls `Instant::now()` internally) so tests can control time without sleeping, in preparation for Task 2's reaper.

Read the current `crates/net_flow_engine/src/lib.rs` in full before starting (paths/line numbers below are current as of this plan's writing but re-verify).

- [ ] **Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod flow_engine_tests` block (find it — it already has `syn_creates_new_connection_and_peer`, `fin_closes_both_directions`, etc.; add alongside, reusing whatever packet-construction helpers already exist there, e.g. `SynPacket`/`DataPacket`/`FinPacket`-equivalent Rust helpers — check the existing helper names before duplicating them):

```rust
#[test]
fn duplicate_segment_is_recognized_and_does_not_regress_tracked_seq() {
    let mut engine = FlowEngine::new();
    let t0 = Instant::now();

    let syn = syn_packet(1000); // adjust to this file's actual helper signature
    let d1 = engine.on_packet_internal(&syn, t0).expect("syn decision");
    assert_eq!(d1.kind, PacketKind::NewConnection);

    // First data segment: seq 1001, say 10 bytes of payload.
    let data1 = data_packet(1001, b"0123456789");
    let d2 = engine.on_packet_internal(&data1, t0).expect("data decision");
    assert_eq!(d2.kind, PacketKind::Data);

    // Replay the SAME segment (retransmission) -- must be recognized as
    // Duplicate, and must NOT advance the tracked seq past what data1 already
    // advanced it to.
    let d3 = engine.on_packet_internal(&data1, t0).expect("duplicate decision");
    assert_eq!(d3.kind, PacketKind::Duplicate);

    // A genuinely new segment continuing from where data1 left off must still
    // be accepted as Data (proves the duplicate check didn't corrupt tracked state).
    let data2 = data_packet(1011, b"abcde");
    let d4 = engine.on_packet_internal(&data2, t0).expect("second data decision");
    assert_eq!(d4.kind, PacketKind::Data);
}

#[test]
fn non_syn_non_rst_on_unknown_flow_returns_unknown_data() {
    let mut engine = FlowEngine::new();
    let t0 = Instant::now();

    // A bare data/ACK packet with no prior SYN ever seen for this flow.
    let data = data_packet(5000, b"GET / HTTP/1.1\r\n");
    let decision = engine.on_packet_internal(&data, t0).expect("unknown-data decision");
    assert_eq!(decision.kind, PacketKind::UnknownData);
    // payload_offset/ip_header_len must still be populated -- microseg's
    // late-binding path needs them to extract the payload.
    assert!(decision.payload_offset > 0);
}

#[test]
fn rst_on_unknown_flow_is_still_ignored_not_unknown_data() {
    // Deliberate, documented narrowing from the old C++ (see plan's Global
    // Constraints) -- RST on an unknown flow stays a no-op, not UnknownData.
    let mut engine = FlowEngine::new();
    let t0 = Instant::now();
    let rst = rst_packet(); // adjust to this file's actual helper
    assert!(engine.on_packet_internal(&rst, t0).is_none());
}
```

Adjust the packet-construction calls above to match whatever helpers already exist in this test module (do not invent new ones if equivalent helpers are already present — check `syn_creates_new_connection_and_peer` and the data/fin tests for the actual helper names and signatures before writing this step for real).

- [ ] **Step 2: Run to verify the tests fail**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/.worktrees/<worktree-name>/crates/net_flow_engine && cargo test flow_engine_tests 2>&1 | tail -60"
```
Expected: compile errors (`PacketKind::Duplicate`/`UnknownData` don't exist, `on_packet_internal` doesn't take a second argument).

- [ ] **Step 3: Implement**

Add `use std::time::Instant;` near the top of the file if not already present.

Update `FlowState`:
```rust
struct FlowState {
    seq: u32,
    server_side: bool,
    last_seen: Instant,
}
```
(Drop the `#[allow(dead_code)]` attribute and its explanatory comment above the struct — `seq` is now genuinely read by the duplicate check below, and `last_seen` is genuinely read by Task 2's reaper. `server_side` remains write-only/unused — keep whatever the current comment says about it, trimmed to no longer claim `seq` is also write-only.)

Update `PacketKind`:
```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PacketKind {
    NewConnection,
    Closed,
    Data,
    /// A retransmitted/already-seen TCP segment on a tracked flow -- the
    /// packet's sequence number is behind the flow's tracked seq. Mirrors
    /// the old C++ microseg code's `tcp_seq < getTcpSeq()` check (plain
    /// numeric comparison, not RFC 1982 wraparound-safe -- a faithful port
    /// of the old behavior, not a new design choice; see plan Task 1).
    Duplicate,
    /// A non-SYN, non-RST TCP packet on a flow this engine isn't tracking
    /// (e.g. the daemon attached to a pod after some of its connections
    /// were already established, so no SYN was ever seen). WAF has no
    /// recovery path for this and treats it as a no-op. Microsegmentation
    /// uses it to attempt late-binding: match a policy for this five-tuple
    /// and, if an HTTP policy applies, start tracking from this packet
    /// onward -- mirroring the pre-existing C++ microseg behavior exactly.
    UnknownData,
}
```

Update `ffi::PacketDecision`'s doc comment (the `#[cxx::bridge]` module, near the top of the file):
```rust
    #[derive(Default)]
    struct PacketDecision {
        /// 0 = Ignore, 1 = NewConnection, 2 = Closed, 3 = Data, 4 = Duplicate,
        /// 5 = UnknownData
        kind: i32,
        // ... (rest unchanged)
    }
```

Add the new kind constants near `KIND_DATA`:
```rust
const KIND_DUPLICATE: i32 = 4;
const KIND_UNKNOWN_DATA: i32 = 5;
```

Update the `on_packet` FFI wrapper's kind mapping:
```rust
let kind = match d.kind {
    PacketKind::NewConnection => KIND_NEW_CONNECTION,
    PacketKind::Closed => KIND_CLOSED,
    PacketKind::Data => KIND_DATA,
    PacketKind::Duplicate => KIND_DUPLICATE,
    PacketKind::UnknownData => KIND_UNKNOWN_DATA,
};
```
and thread `Instant::now()` into the call:
```rust
unsafe fn on_packet(&mut self, pkg: *const u8, len: usize) -> ffi::PacketDecision {
    let bytes = std::slice::from_raw_parts(pkg, len);
    match self.on_packet_internal(bytes, Instant::now()) {
        // ... unchanged match arms below this line
```

Rewrite `on_packet_internal`:
```rust
fn on_packet_internal(&mut self, bytes: &[u8], now: Instant) -> Option<PacketDecision> {
    let ip = parse_ipv4_header(bytes)?;
    if ip.protocol != IPPROTO_TCP {
        return None;
    }
    let tcp_bytes = &bytes[ip.header_len..];
    let tcp = parse_tcp_header(tcp_bytes)?;

    let id = ConnectionId {
        local_ip: ip.saddr,
        foreign_ip: ip.daddr,
        local_port: tcp.source,
        foreign_port: tcp.dest,
    };
    let peer_id = ConnectionId {
        local_ip: ip.daddr,
        foreign_ip: ip.saddr,
        local_port: tcp.dest,
        foreign_port: tcp.source,
    };
    let ip_header_len = ip.header_len as u32;
    let payload_offset = (ip.header_len + tcp.header_len) as u32;

    if let Some(state) = self.tcbs.get(&id) {
        if tcp.fin || tcp.rst {
            self.tcbs.remove(&id);
            self.tcbs.remove(&peer_id);
            return Some(PacketDecision {
                kind: PacketKind::Closed,
                conn_id: id,
                peer_conn_id: peer_id,
                peer_is_new: false,
                ip_header_len: 0,
                payload_offset: 0,
            });
        }
        if tcp.seq < state.seq {
            // Duplicate/retransmitted segment -- do not advance tracked seq,
            // do not update last_seen (an entry that only ever receives
            // retransmits of old data is not "active" for reaper purposes;
            // this mirrors treating it as if this packet never fully arrived).
            return Some(PacketDecision {
                kind: PacketKind::Duplicate,
                conn_id: id,
                peer_conn_id: peer_id,
                peer_is_new: false,
                ip_header_len,
                payload_offset,
            });
        }
        let payload_len = (bytes.len() - payload_offset as usize) as u32;
        let state = self.tcbs.get_mut(&id).expect("checked above");
        state.seq = tcp.seq.wrapping_add(payload_len);
        state.last_seen = now;
        return Some(PacketDecision {
            kind: PacketKind::Data,
            conn_id: id,
            peer_conn_id: peer_id,
            peer_is_new: false,
            ip_header_len,
            payload_offset,
        });
    }

    // Unknown flow.
    if tcp.rst {
        return None; // unchanged from Phase 5 -- see plan's Global Constraints
                      // for why this is NOT extended to UnknownData
    }
    if tcp.syn {
        self.tcbs.insert(id, FlowState { seq: tcp.seq.wrapping_add(1), server_side: true, last_seen: now });
        let peer_is_new = !self.tcbs.contains_key(&peer_id);
        if peer_is_new {
            self.tcbs.insert(peer_id, FlowState { seq: 0, server_side: false, last_seen: now });
        }
        return Some(PacketDecision {
            kind: PacketKind::NewConnection,
            conn_id: id,
            peer_conn_id: peer_id,
            peer_is_new,
            ip_header_len: 0,
            payload_offset: 0,
        });
    }
    // Neither RST nor SYN on an unknown flow -- previously a silent no-op
    // (returned None); now an explicit UnknownData decision so microseg's
    // late-binding recovery can use it. ip_header_len/payload_offset ARE
    // populated here (unlike NewConnection/Closed) because microseg needs
    // them to extract the payload for its onData() call.
    Some(PacketDecision {
        kind: PacketKind::UnknownData,
        conn_id: id,
        peer_conn_id: peer_id,
        peer_is_new: false,
        ip_header_len,
        payload_offset,
    })
}
```

Note: `NewConnection`'s `PacketDecision` still carries `ip_header_len: 0, payload_offset: 0` (unchanged from before this task) — confirmed in this plan's opening refinement notes that the SYN path never needs payload access.

- [ ] **Step 4: Run to verify the tests pass**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/.worktrees/<worktree-name>/crates/net_flow_engine && cargo test 2>&1 | tail -100"
```
Expected: all tests pass, including every pre-existing test (`syn_creates_new_connection_and_peer`, `fin_closes_both_directions`, `ack_on_unknown_flow_is_ignored`, etc. — the last of these specifically exercises the OLD "bare ACK on unknown flow" behavior; confirm it still passes, since its assertion should now be about `UnknownData` if it was asserting `None`/Ignore before — read it and update its assertion if this task's change affects what it checks, documenting the update in this task's commit message rather than silently leaving a stale assertion).

- [ ] **Step 5: Commit**

```bash
git add crates/net_flow_engine/src/lib.rs
git commit -m "Add duplicate-segment detection and UnknownData decision to net_flow_engine's TCB tracker

FlowState::seq becomes a real, read field (was write-only parity stub
since Phase 5) -- duplicate-segment detection moves from microseg's
hand-rolled C++ comparison into the shared Rust TCB tracker, giving
WAF a retransmission guard it did not have before (new, desirable
behavior for WAF specifically -- flagged per project convention, not
silently absorbed as a non-change).

UnknownData (kind 5) makes explicit a case on_packet_internal
previously handled by silently returning None: a non-SYN, non-RST
packet on an untracked flow. WAF's behavior for this case is
unchanged (DispatchWaf's new explicit case for kind 5 is a no-op,
matching the old implicit default-case behavior exactly);
microsegmentation (Phase 6b-2, later tasks) uses it to preserve its
existing late-binding recovery path. RST on an unknown flow is
deliberately NOT extended to UnknownData -- see the plan's Global
Constraints for the documented, low-impact narrowing this represents
versus the old C++'s not-found branch."
```

---

### Task 2: Add a timeout-based reaper to `FlowEngine`

**Files:**
- Modify: `crates/net_flow_engine/src/lib.rs` (`FlowEngine`, new `evict_stale`/`evict_stale_connections` methods; `ffi` bridge module)

**Interfaces:**
- Consumes: `FlowState::last_seen` (Task 1).
- Produces: `net_flow::evict_stale_connections() -> Vec<SharedConnectionId>` (new FFI method on `FlowEngine`) — consumed by Task 6's timerfd wiring.

- [ ] **Step 1: Write the failing tests**

Add to `flow_engine_tests`:
```rust
#[test]
fn evict_stale_removes_only_entries_past_the_timeout() {
    let mut engine = FlowEngine::new();
    let t0 = Instant::now();

    let syn_a = syn_packet(100); // flow A, will go stale
    engine.on_packet_internal(&syn_a, t0);

    let t1 = t0 + Duration::from_secs(60);
    let syn_b = syn_packet_for(/* different five-tuple */); // flow B, stays fresh
    engine.on_packet_internal(&syn_b, t1);

    let t2 = t1 + Duration::from_secs(600); // well past any reasonable timeout for flow A, not for flow B
    let evicted = engine.evict_stale(t2, Duration::from_secs(300));

    // Flow A's SYN was at t0 (600+60=660s before t2) -- stale. Flow B's SYN
    // was at t1 (600s before t2) -- also stale by a 300s timeout in this
    // example; adjust the timeline above so exactly flow A is evicted and
    // flow B survives, to make the test discriminating. (Pick concrete
    // numbers when implementing so the two flows land on opposite sides of
    // the timeout boundary -- the illustrative values here are placeholders.)
    assert!(!evicted.is_empty());
    assert_eq!(engine.live_connection_count(), /* whatever count reflects only flow B (+ its peer) surviving */ 2);
}

#[test]
fn evict_stale_returns_both_sides_of_an_evicted_flow() {
    let mut engine = FlowEngine::new();
    let t0 = Instant::now();
    let syn = syn_packet(100);
    let decision = engine.on_packet_internal(&syn, t0).unwrap();

    let evicted = engine.evict_stale(t0 + Duration::from_secs(9999), Duration::from_secs(300));
    // Both conn_id and peer_conn_id should be gone.
    assert!(evicted.contains(&decision.conn_id));
    assert!(evicted.contains(&decision.peer_conn_id));
    assert_eq!(engine.live_connection_count(), 0);
}
```
Adjust exact helper calls/signatures to match Task 1's actual test helpers.

- [ ] **Step 2: Run to verify the tests fail**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/.worktrees/<worktree-name>/crates/net_flow_engine && cargo test evict_stale 2>&1 | tail -60"
```

- [ ] **Step 3: Implement**

Add `use std::time::Duration;` if not already present.

```rust
impl FlowEngine {
    // ... existing methods ...

    /// Removes TCB entries whose `last_seen` is at least `timeout` behind
    /// `now`, returning the IDs removed (both `id` and any `peer_id` whose
    /// entry was also stale -- note a peer entry is evicted independently by
    /// its OWN last_seen, not automatically alongside its counterpart, since
    /// each side of a flow accrues activity independently, e.g. a
    /// long-lived one-directional stream).
    fn evict_stale(&mut self, now: Instant, timeout: Duration) -> Vec<ConnectionId> {
        let stale: Vec<ConnectionId> = self
            .tcbs
            .iter()
            .filter(|(_, state)| now.duration_since(state.last_seen) >= timeout)
            .map(|(id, _)| *id)
            .collect();
        for id in &stale {
            self.tcbs.remove(id);
        }
        stale
    }
}

/// Sweep interval and entry timeout are independent: the timeout is how old
/// an entry must be to be evicted; the caller (Task 6, C++) decides how
/// often to call this. 5 minutes: this tracker exists only to reconstruct
/// in-flight HTTP headers for policy matching, not general connection
/// tracking -- real HTTP client/server idle timeouts are typically tens of
/// seconds to low minutes, so this gives comfortable slack. Tune via this
/// constant if it proves wrong in practice, not via a design change.
const STALE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);

/// # Safety: none -- no raw pointers, safe to call directly (unlike
/// on_packet/parse_five_tuple).
fn evict_stale_connections(engine: &mut FlowEngine) -> Vec<ffi::SharedConnectionId> {
    engine
        .evict_stale(Instant::now(), STALE_CONNECTION_TIMEOUT)
        .into_iter()
        .map(Into::into)
        .collect()
}
```

Add to the `extern "Rust" { ... }` block in the `#[cxx::bridge]` module:
```rust
        fn evict_stale_connections(engine: &mut FlowEngine) -> Vec<SharedConnectionId>;
```
Note the free-function-taking-`&mut FlowEngine` shape (not a method via `self: &mut FlowEngine`) — either is valid cxx syntax; pick whichever matches this file's existing convention more closely once you're editing it (compare against how `on_packet`/`live_connection_count` are declared) and use that consistently; if the file already exclusively uses the `self: &mut FlowEngine` method style for `FlowEngine`-bound functions, prefer `fn evict_stale_connections(self: &mut FlowEngine) -> Vec<SharedConnectionId>;` and adjust the implementation above from a free function to a method accordingly (`impl FlowEngine { fn evict_stale_connections(&mut self) -> Vec<ffi::SharedConnectionId> { ... } }`) for consistency.

- [ ] **Step 4: Run to verify the tests pass**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/.worktrees/<worktree-name>/crates/net_flow_engine && cargo test 2>&1 | tail -100"
```

- [ ] **Step 5: Commit**

```bash
git add crates/net_flow_engine/src/lib.rs
git commit -m "Add timeout-based TCB eviction to net_flow_engine

Closes a pre-existing (not migration-introduced) unbounded-growth
characteristic: TCB entries were previously removed only on FIN/RST,
with no timeout path -- confirmed via the Phase 6b-2 design spec's
research that this already existed in microsegmentation's own
tracker in production, unrelated to this migration. evict_stale takes
an explicit `now`/`timeout` rather than reading the system clock
internally, so it's directly unit-testable without real sleeps; the
production FFI entry point (evict_stale_connections) supplies
Instant::now() and a fixed 5-minute timeout."
```

---

### Task 3: Wire the new decision kinds and the reaper into the cxx bridge — FFI smoke tests

**Files:**
- Modify: `tests/net_flow_engine_ffi_test.cc` (smoke tests for `Duplicate`/`UnknownData` kinds appearing over FFI, and for `evict_stale_connections`)

**Interfaces:**
- Consumes: everything from Tasks 1-2 (already FFI-wired there — this task is verification-only, no new Rust/bridge code).

- [ ] **Step 1: Write the tests**

Add to `tests/net_flow_engine_ffi_test.cc`, in the `NetFlowEngineFfiTest` suite (find existing helpers `SynPacket()`, `DataPacket()`, `FinPacket()` and reuse them):

```cpp
TEST(NetFlowEngineFfiTest, DuplicateSegmentReturnsKind4) {
  auto engine = net_flow::new_flow_engine();
  auto syn = SynPacket();
  engine->on_packet(syn.data(), syn.size());
  auto data = DataPacket(/*syn=*/false, "hello");
  auto d1 = engine->on_packet(data.data(), data.size());
  ASSERT_EQ(d1.kind, 3);  // Data
  auto d2 = engine->on_packet(data.data(), data.size());  // replay
  EXPECT_EQ(d2.kind, 4);  // Duplicate
}

TEST(NetFlowEngineFfiTest, NonSynNonRstOnUnknownFlowReturnsKind5) {
  auto engine = net_flow::new_flow_engine();
  auto data = DataPacket(/*syn=*/false, "GET / HTTP/1.1\r\n");  // no prior SYN
  auto decision = engine->on_packet(data.data(), data.size());
  EXPECT_EQ(decision.kind, 5);  // UnknownData
  EXPECT_GT(decision.payload_offset, 0u);
}

TEST(NetFlowEngineFfiTest, EvictStaleConnectionsIsCallableAndReturnsEmptyForFreshFlows) {
  auto engine = net_flow::new_flow_engine();
  auto syn = SynPacket();
  engine->on_packet(syn.data(), syn.size());
  // Freshly created -- nothing should be evicted yet (the FFI entry point
  // uses a fixed multi-minute production timeout; this test only confirms
  // the call is wired correctly end-to-end, not the timeout value itself,
  // which is exercised by Task 2's Rust unit tests with an injected clock).
  auto evicted = net_flow::evict_stale_connections(*engine);
  EXPECT_TRUE(evicted.empty());
}
```
Adjust exact call shape (`evict_stale_connections(*engine)` vs. `engine->evict_stale_connections()`) to match whichever bridge declaration style Task 2 actually landed on.

- [ ] **Step 2: Build and run**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j2 net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && ./net_rule_grpc_test --gtest_filter='NetFlowEngineFfiTest.*'"
```
Expected: clean build, all smoke tests pass (existing ones plus the 3 new ones).

- [ ] **Step 3: Commit**

```bash
git add tests/net_flow_engine_ffi_test.cc
git commit -m "Add FFI smoke tests for net_flow_engine's Duplicate/UnknownData decisions and the reaper entry point"
```

---

### Task 4: `ConnectionManager` gains `microseg_conns_` and the `MicrosegTracked`/`DispatchMicroseg` pair; `DispatchWaf` gets explicit cases for the new kinds

**Files:**
- Modify: `net/connection_manager.h`
- Modify: `tests/net_flow_engine_ffi_test.cc` (new `ConnectionManagerCutoverTest`-style tests for the microseg path)

**Interfaces:**
- Consumes: `net_flow::PacketDecision` (kinds 0-5, Tasks 1-3), `net::ConnectionID`/`ConnectionIDHash` (`net/utility.h`, pre-existing).
- Produces: `ConnectionManager::MicrosegTracked(const net_flow::PacketDecision&) const -> bool`, `ConnectionManager::DispatchMicroseg(const net_flow::PacketDecision&, const uint8_t*, size_t, const std::string&) -> std::optional<http::Header>` — consumed by Task 5's callback rewrite.

Read `net/connection_manager.h` in full before starting — this task adds alongside `http_conns_`/`DispatchWaf`, does not modify them (except `DispatchWaf`'s switch, see below).

- [ ] **Step 1: Write the failing tests**

Add to `tests/net_flow_engine_ffi_test.cc`, in a new suite mirroring `ConnectionManagerCutoverTest`'s existing shape (reuse its packet-construction helpers):

```cpp
TEST(ConnectionManagerMicrosegTest, NewConnectionThenDataProducesHeaderWhenTracked) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  auto syn = SynPacket();
  auto syn_result = mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);
  ASSERT_EQ(syn_result.decision.kind, 1);  // NewConnection
  EXPECT_FALSE(mgr.MicrosegTracked(syn_result.decision));  // not tracked yet
  auto header1 = mgr.DispatchMicroseg(syn_result.decision, syn.data(), syn.size(), "some-rule-key");
  EXPECT_FALSE(header1.has_value());  // SYN itself never produces a Header

  auto data = DataPacket(/*syn=*/false, "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n");
  auto data_result = mgr.receive(data.data(), data.size(), /*track_tcp=*/true);
  ASSERT_EQ(data_result.decision.kind, 3);  // Data
  ASSERT_TRUE(mgr.MicrosegTracked(data_result.decision));  // now tracked, from the SYN above
  auto header2 = mgr.DispatchMicroseg(data_result.decision, data.data(), data.size(), /*unused, already tracked*/"");
  ASSERT_TRUE(header2.has_value());
  EXPECT_EQ(header2->host_, "example.com");
}

TEST(ConnectionManagerMicrosegTest, ClosedErasesBothSides) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  auto syn = SynPacket();
  auto syn_result = mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);
  mgr.DispatchMicroseg(syn_result.decision, syn.data(), syn.size(), "some-rule-key");
  ASSERT_TRUE(mgr.MicrosegTracked(syn_result.decision));

  auto fin = FinPacket();
  auto fin_result = mgr.receive(fin.data(), fin.size(), /*track_tcp=*/true);
  ASSERT_EQ(fin_result.decision.kind, 2);  // Closed
  mgr.DispatchMicroseg(fin_result.decision, fin.data(), fin.size(), "");
  EXPECT_FALSE(mgr.MicrosegTracked(fin_result.decision));
}

TEST(ConnectionManagerMicrosegTest, UntrackedFlowReportsNotTracked) {
  // A flow this ConnectionManager has never seen a NewConnection/UnknownData
  // dispatch for -- MicrosegTracked must report false so the caller knows to
  // run MatchMicroPolicyRule again (mirrors the old C++'s `found` semantics).
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);
  auto data = DataPacket(/*syn=*/false, "irrelevant");
  auto result = mgr.receive(data.data(), data.size(), /*track_tcp=*/true);
  EXPECT_FALSE(mgr.MicrosegTracked(result.decision));
}
```

- [ ] **Step 2: Run to verify the tests fail**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j2 net_rule_grpc_test 2>&1 | tail -150"
```
Expected: compile errors (`MicrosegTracked`/`DispatchMicroseg` don't exist yet).

- [ ] **Step 3: Implement**

In `net/connection_manager.h`, add (alongside the existing `private:` members and public methods — place `microseg_conns_` next to `http_conns_`, and the two new public methods next to `DispatchWaf`):

```cpp
public:
  // ... existing receive(), DispatchWaf() ...

  // Pure lookup: does a tracked microseg Connection already exist for this
  // decision's conn_id? Mirrors the old C++'s `tcp_it != TcpCtInput().end()`
  // check (renamed `found`). Callers use this BEFORE deciding whether to
  // re-run policy matching (see net-policy.cpp's input_nfq_cb/output_nfq_cb,
  // Task 5) -- a flow can be fully tracked by the TCB state machine while
  // having no tracked microseg Connection, if no HTTP policy applied to it
  // at NewConnection/UnknownData time. Never mutates state.
  bool MicrosegTracked(const net_flow::PacketDecision& decision) const {
    return microseg_conns_.find(ToConnectionID(decision.conn_id)) != microseg_conns_.end();
  }

  // Mirrors the old C++ microseg block's per-kind handling, keyed by
  // ConnectionID instead of a queue-direction-specific TcpFourTupleV4 map.
  // `rule_key` is only consulted for NewConnection/UnknownData (the caller
  // must have already run MatchMicroPolicyRule for those -- see Task 5);
  // for Data/Duplicate/Closed on an already-tracked entry, the entry's own
  // stored rule_key (via Connection::getRuleKey()) is authoritative and the
  // passed-in rule_key is ignored, mirroring the old
  // `rule_key = tcp_it->second->getRuleKey();` overwrite.
  //
  // Returns the reconstructed HTTP header once a Data- or UnknownData-kind
  // packet completes an HTTP parse (ParseState::Done), for the caller to run
  // MatchHttpPolicyRule against -- std::nullopt for every other case
  // (NewConnection, Closed, Duplicate, an incomplete parse, or a Data-kind
  // packet with no matching entry -- Data never inserts on a miss, only
  // UnknownData does; see case 3 vs case 5 below).
  std::optional<http::Header> DispatchMicroseg(const net_flow::PacketDecision& decision,
                                                const uint8_t* pkg, size_t len,
                                                const std::string& rule_key) {
    auto id = ToConnectionID(decision.conn_id);
    switch (decision.kind) {
      case 0:  // Ignore -- should not be reached for TCP; defensive no-op.
        return std::nullopt;
      case 1: {  // NewConnection (SYN): insert only. A SYN never carries
                 // payload worth extracting, so this case -- unlike case 5
                 // below -- never attempts onData(). `microseg_conns_[id] =`
                 // unconditionally overwrites any stale entry that might
                 // already exist for this id: this is only possible if an
                 // earlier UnknownData-triggered late-binding (case 5)
                 // created an entry for a flow Rust's OWN tcbs table never
                 // held (since Rust only creates entries on SYN -- see Task
                 // 1), and a genuinely new SYN later reuses the same
                 // five-tuple. Starting fresh on a real SYN is correct in
                 // that scenario; do not try to "merge" with the stale
                 // entry.
        microseg_conns_[id] = std::make_unique<http::Connection>(rule_key);
        auto peer_id = ToConnectionID(decision.peer_conn_id);
        if (decision.peer_is_new) {
          microseg_conns_[peer_id] = std::make_unique<http::Connection>(rule_key);
        }
        return std::nullopt;  // SYN itself never produces a Header.
      }
      case 5: {  // UnknownData: late-binding. UNLIKE case 1, this packet DOES
                 // carry real payload (there was no separate SYN packet to
                 // "use up" first), so this case inserts on first sight AND
                 // always attempts extraction in the same call -- including
                 // on every SUBSEQUENT packet of this same flow, since
                 // on_packet_internal has no way to ever promote an
                 // untracked-by-Rust flow to a "known" state (only a SYN
                 // creates a tcbs entry -- Task 1) -- every later packet on
                 // a flow that started this way keeps arriving as
                 // UnknownData too, forever, not Data. This single case must
                 // therefore handle both "first sight" and "already
                 // late-bound, here's more data" without the caller needing
                 // to distinguish them (see Task 5's dispatch, which for
                 // this exact reason calls DispatchMicroseg for kind 5
                 // EXACTLY ONCE, the same as every other kind -- never
                 // paired with a separate insert-only pre-call the way
                 // kind 1 sometimes is).
        auto it = microseg_conns_.find(id);
        if (it == microseg_conns_.end()) {
          microseg_conns_[id] = std::make_unique<http::Connection>(rule_key);
          auto peer_id = ToConnectionID(decision.peer_conn_id);
          if (microseg_conns_.find(peer_id) == microseg_conns_.end()) {
            microseg_conns_[peer_id] = std::make_unique<http::Connection>(rule_key);
          }
          it = microseg_conns_.find(id);
        }
        auto data = std::string_view(reinterpret_cast<const char*>(pkg) + decision.payload_offset,
                                      len - decision.payload_offset);
        const auto& header = it->second->onData(data);
        if (header.parseState_ != http::ParseState::Done) {
          return std::nullopt;
        }
        return header;
      }
      case 2: {  // Closed
        microseg_conns_.erase(id);
        microseg_conns_.erase(ToConnectionID(decision.peer_conn_id));
        return std::nullopt;
      }
      case 3: {  // Data
        auto it = microseg_conns_.find(id);
        if (it == microseg_conns_.end()) {
          return std::nullopt;  // untracked -- caller's MicrosegTracked check
                                 // should have already routed around calling
                                 // this with a rule_key in this situation;
                                 // defensive no-op if reached anyway.
        }
        auto data = std::string_view(reinterpret_cast<const char*>(pkg) + decision.payload_offset,
                                      len - decision.payload_offset);
        const auto& header = it->second->onData(data);
        if (header.parseState_ != http::ParseState::Done) {
          return std::nullopt;
        }
        return header;  // copies out of the Connection-owned reference -- safe
                         // past this call regardless of the Connection's lifetime.
      }
      case 4:  // Duplicate -- retransmitted segment, skip (mirrors the old
               // `tcp_seq < getTcpSeq()` early return).
        return std::nullopt;
      default:
        return std::nullopt;
    }
  }

private:
  // ... existing ToConnectionID, HandleNewConnection/HandleClosed/HandleData ...

  std::unordered_map<ConnectionID, http::ConnectionPtr, ConnectionIDHash> microseg_conns_;
```

Verify `#include <optional>` and `#include <string_view>` are present (add if missing) and that `http::ParseState`/`http::Header` are visible (via the existing `#include "http/connection.h"`, which pulls in `http/codec.h`'s `Header`/`ParseState` transitively — confirm by checking `http/connection.h`'s own includes; add an explicit `#include "http/codec.h"` if the transitive chain doesn't already reach it cleanly).

Update `DispatchWaf`'s switch to add explicit cases for kinds 4 and 5 (see Global Constraints for why):
```cpp
  NetStatus DispatchWaf(const net_flow::PacketDecision& decision, const uint8_t* pkg, size_t len) {
    switch (decision.kind) {
      case 0:  // Ignore
        return NetStatus::OK;
      case 1:  // NewConnection
        return HandleNewConnection(decision);
      case 2:  // Closed
        return HandleClosed(decision);
      case 3:  // Data
        return HandleData(decision, pkg, len);
      case 4:  // Duplicate -- new for WAF: a retransmission guard it didn't
               // have before this phase (see plan Task 1's commit message).
        return NetStatus::OK;
      case 5:  // UnknownData -- matches WAF's pre-existing implicit behavior
               // for this case exactly (previously fell into `default:` via
               // kind 0/Ignore; now explicit).
        return NetStatus::OK;
      default:
        return NetStatus::OK;
    }
  }
```

- [ ] **Step 4: Build and run**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j2 net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && ./net_rule_test && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*'"
```
Expected: clean build, all tests pass, including the new `ConnectionManagerMicrosegTest` suite and every pre-existing `ConnectionManagerCutoverTest`.

- [ ] **Step 5: Commit**

```bash
git add net/connection_manager.h tests/net_flow_engine_ffi_test.cc
git commit -m "Add ConnectionManager::MicrosegTracked/DispatchMicroseg, ConnectionID-keyed microseg_conns_

Mirrors DispatchWaf's shape but keyed and populated identically to
http_conns_, replacing the queue-direction-specific TcpFourTupleV4
maps microsegmentation used before this phase (not yet wired into
input_nfq_cb/output_nfq_cb -- that's Task 5). DispatchWaf gains
explicit cases for the two new decision kinds from Task 1."
```

---

### Task 5: Rewrite `input_nfq_cb`/`output_nfq_cb` to use the unified dispatch

**Files:**
- Modify: `net-policy.cpp` (`input_nfq_cb`, `output_nfq_cb`)

**Interfaces:**
- Consumes: `ConnectionManager::MicrosegTracked`/`DispatchMicroseg` (Task 4).

This is the highest-risk task in this plan — full production packet-verdict parity must be preserved. Read both functions' exact current content in full before editing (this plan's earlier research may have drifted). Read this plan's Global Constraints section again immediately before starting this task — the "found" semantics section is the crux of this task.

- [ ] **Step 1: Re-confirm the exact current control flow**

```bash
grep -n "TcpCtInput\|TcpCtOutput\|struct tcphdr tcphdr\|memcpy(&tcphdr" net-policy.cpp
```
Diff what you see against this plan's understanding (both callbacks share an identical shape apart from `TcpCtInput()`/`TcpCtOutput()`, `kAllowReq`/`kAllowRsp`, and `InputHttpPolicy()`/`OutputHttpPolicy()`/`FlowDir::kIngress`/`kEgress`). If drifted meaningfully, stop and re-read before proceeding.

- [ ] **Step 2: Rewrite `input_nfq_cb`**

Replace everything from the `// Reconstruct offset/tcphdr...` comment block (Phase 6b-1's manual reconstruction, now fully retired) through the end of the function with:

```cpp
  if (daemon->WafEnabled() && result.is_tcp) {
    auto status = daemon->ConnMgr().DispatchWaf(result.decision, reinterpret_cast<const uint8_t*>(pkg), data_len);
    if (status == net::NetStatus::Drop) {
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), data_len, pkg);
    }
  }

  if (tuple.proto_ == IPPROTO_UDP || tuple.proto_ == IPPROTO_ICMP) {
    // Unchanged from before this phase: UDP/ICMP never enter TCB dispatch.
    rule_ret = MatchMicroPolicyRule(tuple, dir, rule_key, *daemon);
    if (rule_ret == NetPolicyRule::kDefault)
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllow), 0, NULL);
    daemon->PostSrv().SendMatchMsg(tuple, rule_ret, dir, rule_key);
    if (rule_ret == NetPolicyRule::kDeny) {
      LOG_D("input drop %s %s:%u -> %s:%u ", GetProtoString(tuple.proto_), tuple.src_addr_.c_str(),
            tuple.src_port_, tuple.dst_addr_.c_str(), tuple.dst_port_);
      return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllow), 0, NULL);
  }
  if (tuple.proto_ != IPPROTO_TCP) {
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);  // unrecognized-but-not-UDP/ICMP -- unchanged `default:` behavior
  }

  // TCP from here on. `result.decision.kind` classifies this packet
  // (NewConnection/Closed/Data/Duplicate/UnknownData/Ignore); `is_tcp`
  // guarantees `receive()` actually ran the TCB state machine on it (i.e.
  // track_tcp was true -- if WafEnabled() is false, result.decision stays
  // default-constructed/kind 0, and TCB-dependent microseg tracking cannot
  // run either; this is an existing constraint from Phase 6b-1's
  // track_tcp gate, unrelated to this task, carried forward unchanged: a
  // WAF-disabled deployment does not get microsegmentation's per-connection
  // HTTP tracking either, since both consumers now share the same gate).
  //
  // IMPORTANT: DispatchMicroseg is called EXACTLY ONCE per packet, at the
  // bottom of this function, for every kind that reaches there (Data,
  // UnknownData, and the practically-unreachable NewConnection-while-tracked
  // case -- see Task 4's case 1/5 split for why each kind's ConnectionManager-
  // side logic is safe to call exactly once regardless of prior tracked
  // state). The only kinds that return EARLY, before reaching that single
  // call, are NewConnection (which explicitly calls DispatchMicroseg itself,
  // since a SYN's own insert must not also attempt extraction -- see Task 4's
  // case 1, which never extracts), Closed, and Duplicate. Do not add a second
  // DispatchMicroseg call anywhere in the kind==NewConnection path below --
  // doing so would run onData() twice on the same UnknownData packet's bytes
  // if kind checks are ever restructured carelessly; this was caught and
  // fixed during this plan's own drafting (see this task's header comment).
  if (!daemon->ConnMgr().MicrosegTracked(result.decision)) {
    /*match rule*/
    rule_ret = MatchMicroPolicyRule(tuple, dir, rule_key, *daemon);
    if (rule_ret == NetPolicyRule::kDefault)
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllow), 0, NULL);
    auto http_rule = daemon->Microseg().InputHttpPolicy().find(rule_key);
    if (http_rule == daemon->Microseg().InputHttpPolicy().end() || http_rule->second.empty()) {
      daemon->PostSrv().SendMatchMsg(tuple, rule_ret, dir, rule_key);
      if (rule_ret == NetPolicyRule::kDeny) {
        LOG_D("input drop %s %s:%u -> %s:%u ", GetProtoString(tuple.proto_), tuple.src_addr_.c_str(),
              tuple.src_port_, tuple.dst_addr_.c_str(), tuple.dst_port_);
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
      }
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllow), 0, NULL);
    }
    // An HTTP policy applies.
    if (result.decision.kind == 1 /* NewConnection */) {
      // SYN: insert only (Task 4's case 1 never extracts -- a SYN carries no
      // payload worth inspecting), and return immediately. This is the ONLY
      // place in this function that calls DispatchMicroseg for a
      // NewConnection decision -- do not also let it reach the bottom call.
      daemon->ConnMgr().DispatchMicroseg(result.decision, reinterpret_cast<const uint8_t*>(pkg), data_len, rule_key);
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), 0, NULL);
    }
    // UnknownData (kind 5): do NOT call DispatchMicroseg here. Fall through
    // to the single shared call at the bottom of this function -- Task 4's
    // case 5 handles both "first sight" (insert) and extraction in that one
    // call, since (unlike a SYN) this packet carries real payload data.
  } else if (result.decision.kind == 2 /* Closed */) {
    daemon->ConnMgr().DispatchMicroseg(result.decision, reinterpret_cast<const uint8_t*>(pkg), data_len, "");
    LOG_D("microseg-dp input data, delete conntrack info, src: %s:%d, dest : %s:%d",
          tuple.src_addr_.c_str(), tuple.src_port_, tuple.dst_addr_.c_str(), tuple.dst_port_);
    return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllow), 0, NULL);
  } else if (result.decision.kind == 4 /* Duplicate */) {
    LOG_D("input - duplicated tcp segment");
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
  }
  // Reaches here for: Data (kind 3, the common case), UnknownData (kind 5,
  // whether first sight or a later packet of an already-late-bound flow --
  // see the comment above), and the practically-unreachable
  // NewConnection-while-already-tracked case (kind 1 falling through this
  // else-if chain because none of its conditions match 1 -- safe: Task 4's
  // case 1 will simply re-insert and return std::nullopt, and this function
  // then returns kAllowReq below exactly as it would for genuinely-untracked
  // Data with no policy). Exactly one DispatchMicroseg call for all of these.
  auto header = daemon->ConnMgr().DispatchMicroseg(result.decision, reinterpret_cast<const uint8_t*>(pkg), data_len, rule_key);
  LOG_D("input method : %s, path : %s, host : %s, state : %d",
        header ? header->method_.c_str() : "", header ? header->path_.c_str() : "",
        header ? header->host_.c_str() : "", header ? static_cast<int>(header->parseState_) : -1);
  if (!header) {
    return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), 0, NULL);
  }
  auto http_rule = daemon->Microseg().InputHttpPolicy().find(rule_key);
  if (http_rule == daemon->Microseg().InputHttpPolicy().end())
    return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kDefault), 0, NULL);
  rule_ret = MatchHttpPolicyRule(http_rule->second, *header);
  LOG_D("match input http rule : %d, key : %s", static_cast<int>(rule_ret), rule_key.c_str());
  if (rule_ret == NetPolicyRule::kDefault)
    return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), 0, NULL);
  daemon->PostSrv().SendMatchMsg(tuple, rule_ret, FlowDir::kIngress, rule_key);
  if (rule_ret == NetPolicyRule::kDeny)
    rst_tcp_link(pkg);
  return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), data_len, pkg);
```

**This rewrite is dense and was drafted from a careful trace of the current code, but it is exactly the kind of restructuring that hides subtle control-flow mistakes.** Before moving on: re-read the CURRENT (pre-this-task) `input_nfq_cb` one more time, line by line, and for each of its distinct return points, confirm the rewritten version produces the identical verdict for the identical input scenario. Write this trace down in the task's report even if the plan's own draft above already attempted it — an independent re-derivation is the actual verification, not just checking the draft compiles. Pay special attention to:
- The `found`/`MicrosegTracked` branch structure — the old code's `switch` fell through to a SHARED `if (!found) { ... }` block for TCP, UDP, and ICMP alike; this rewrite handles UDP/ICMP earlier and separately (functionally identical, since the old UDP/ICMP branches never reached the tcp_seq/onData code below the shared block either — confirm this claim against the actual old code, don't just trust this plan).
- **Exactly one `DispatchMicroseg` call per packet.** This is the single easiest mistake to reintroduce while implementing this task (an earlier draft of this very plan had it: calling `DispatchMicroseg` once inside the `!MicrosegTracked` branch for `UnknownData`, then falling through to the bottom's call too, running `onData()` on the same bytes twice). Before considering this task done, grep the finished function body for `DispatchMicroseg` and manually confirm every one of its call sites sits on a mutually exclusive control-flow path from every other one — there should be exactly 3 call sites in each function (`NewConnection`'s own early-return call, `Closed`'s call, and the single bottom shared call), and no execution path can reach two of them for the same packet.
- The `NewConnection`-while-already-tracked case (falling through the else-if chain to the bottom shared call, since kind 1 doesn't match the `Closed`/`Duplicate` conditions) has no real equivalent in the old code (the old code's SYN check was purely `tcphdr.syn != 0`, evaluated only inside the `tcp_it == end()` branch — the old code could not observe "SYN on an already-tracked flow" as a distinct case at all). Confirm Task 4's case 1 handles being invoked in this state safely (re-insert, return `std::nullopt`, no extraction) and that this function then returns `kAllowReq` for it, same as it would for genuinely-untracked `Data` with no applicable policy — this is a defensive-correctness check, not a behavior this plan expects to actually observe in production, since `on_packet_internal` never returns `NewConnection` for an `id` already in `self.tcbs`.

- [ ] **Step 3: Rewrite `output_nfq_cb` identically**

Same transformation, with `output_nfq_cb`'s existing direction-specific differences preserved: `TcpCtOutput()`→`MicrosegTracked`/`DispatchMicroseg` (same calls, same `ConnectionManager` instance — there's only one), `kAllowRsp` in place of `kAllowReq` everywhere, `OutputHttpPolicy()` in place of `InputHttpPolicy()`, `FlowDir::kEgress`, `"output"` in place of `"input"` in log strings.

- [ ] **Step 4: Delete the now-unused `struct tcphdr tcphdr;`, `TCP_FOUR_TUPLE_V4 ct_key;`, and `std::map<TCP_FOUR_TUPLE_V4, http::ConnectionPtr>::iterator tcp_it;` locals from both functions**

Confirm via grep within each function body that nothing else references them post-rewrite before deleting.

- [ ] **Step 5: Build and run everything**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j2 net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && ./net_rule_test && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*'"
```
Run the grpc test suite at least 3 times to check for flakiness, matching Phase 6b-1's practice on this same hot path.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Cut input_nfq_cb/output_nfq_cb over to ConnectionManager's unified microseg dispatch

Retires the hand-rolled SYN/FIN/RST/sequence-number TCP state
detection and the Phase 6b-1 manual offset/tcphdr reconstruction hack
in favor of dispatching on decision.kind, exactly mirroring DispatchWaf's
existing shape. [Document here: confirmation that the found/!found
control-flow trace was independently re-derived and matches, per this
task's Step 2 instruction.]"
```

---

### Task 6: Wire a timerfd-based reaper trigger into the daemon's epoll loop

**Files:**
- Modify: `net-policy.cpp` (`RunNetPolicyDaemon`; a new epoll callback)
- Modify: `net/connection_manager.h` (a new `ConnectionManager::EvictStale()` method clearing both `http_conns_` and `microseg_conns_` for evicted IDs)

**Interfaces:**
- Consumes: `net_flow::evict_stale_connections` (Task 2).

- [ ] **Step 1: Add `ConnectionManager::EvictStale()`**

In `net/connection_manager.h`, alongside `DispatchWaf`/`DispatchMicroseg`:
```cpp
  // Called periodically (Task 6, RunNetPolicyDaemon's epoll loop) to sweep
  // stale TCB entries out of the shared Rust engine and clear the
  // corresponding entries from both this class's own per-flow maps, so
  // neither leaks a Connection object referencing an ID the Rust engine no
  // longer tracks.
  void EvictStale() {
    for (const auto& shared_id : engine_->evict_stale_connections()) {
      ConnectionID id{shared_id.local_ip, shared_id.foreign_ip, shared_id.local_port, shared_id.foreign_port};
      http_conns_.erase(id);
      microseg_conns_.erase(id);
    }
  }
```
Confirm `engine_->evict_stale_connections()` matches Task 2's actual declared call shape (method vs. free function taking `&mut FlowEngine`) — adjust to `net_flow::evict_stale_connections(*engine_)` if Task 2 landed on the free-function style.

- [ ] **Step 2: Add a `RcvEpollCb`-based timerfd callback**

In `net-policy.cpp`, near `input_nfq_cb`/`output_nfq_cb` or in a clearly-labeled new section:
```cpp
static int32_t ReaperTimerEvent(int32_t /*epoll_fd*/, int32_t fd, void* ptr) {
  uint64_t expirations;
  // Required for a timerfd: read() clears its "ready" state; without this,
  // level-triggered epoll would re-fire immediately on every wait.
  if (read(fd, &expirations, sizeof(expirations)) != sizeof(expirations)) {
    return 0;  // spurious wakeup or error -- nothing to do
  }
  auto* cb = reinterpret_cast<RCV_EPOLL_CB*>(ptr);
  cb->daemon_->ConnMgr().EvictStale();
  return 0;
}
```
Confirm the exact `RcvCbFunc` signature (`int32_t(*)(int32_t epoll_fd, int32_t fd, void* ptr)`) and return-value convention against the live `net-policy.h`/other callbacks (e.g. `grpc_bridge::DispatchGrpcRustQueueEvent`'s actual return statement) before finalizing — match its error-handling style.

- [ ] **Step 3: Wire it into `RunNetPolicyDaemon`**

Find the existing block that sets up `rustDispatchWakeEvent`/`rust_dispatch_wake_fd` (search for `eventfd(0, EFD_NONBLOCK)`). Immediately after it, add:
```cpp
  // --- Reaper timer (Phase 6b-2): periodic sweep of stale TCB/microseg state ---
  int reaper_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  if (reaper_timer_fd < 0)
    GOTO_ERROR(err, "create reaper timerfd failed, %s.", strerror(errno));
  {
    // Sweep interval is independent of the entry timeout (5 minutes,
    // net_flow_engine's STALE_CONNECTION_TIMEOUT) -- a shorter interval just
    // bounds how stale an evictable entry can get before it's actually
    // swept. 60s chosen as a reasonable default; tune independently of the
    // entry timeout if needed.
    struct itimerspec its = {};
    its.it_value.tv_sec = 60;
    its.it_interval.tv_sec = 60;
    ret = timerfd_settime(reaper_timer_fd, 0, &its, nullptr);
    if (ret < 0)
      GOTO_ERROR(err, "arm reaper timerfd failed, %s.", strerror(errno));
  }
  RCV_EPOLL_CB reaperEvent;
  reaperEvent.fd_ = reaper_timer_fd;
  reaperEvent.epoll_in_func_ = ReaperTimerEvent;
  reaperEvent.daemon_ = &daemon;
  ev.data.ptr = &reaperEvent;
  ev.events = EPOLLIN;
  ret = epoll_ctl(epfd, EPOLL_CTL_ADD, reaper_timer_fd, &ev);
  if (ret < 0)
    GOTO_ERROR(err, "epoll ctl failed for reaper timer fd, %s.", strerror(errno));
```
Verify `#include <sys/timerfd.h>` is present in `net-policy.cpp` (add if missing). Verify the `RCV_EPOLL_CB reaperEvent;` declaration's placement doesn't run afoul of this function's existing `GOTO_ERROR`/`goto err`-based error handling (C++ allows jumping over a variable declaration only if it has no non-trivial initializer that would be skipped — `RcvEpollCb` is a plain aggregate with no constructor per its `net-policy.h` definition, so a `goto` from an earlier `GOTO_ERROR` jumping past this declaration is fine, matching the pattern already used for `postEvent`/`rustDispatchWakeEvent`/`pstCbEv` above it — confirm this reasoning against how the file already declares `RCV_EPOLL_CB postEvent, rustDispatchWakeEvent, *pstCbEv;` all at the top of the function in one block, rather than inline where first used; if so, move `reaperEvent`'s declaration up to that same top-of-function block for consistency rather than leaving it declared inline, to avoid any doubt).

- [ ] **Step 4: Build and run**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j2 net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && ./net_rule_test && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*'"
```
This task's C++ changes to `RunNetPolicyDaemon` are not exercised by the existing test binaries directly (no test spins up the full daemon) — confirm the build succeeds and existing tests are unaffected; add a note in this task's report about how the timerfd wiring itself was manually sanity-checked (e.g. a local run of `net-rule` showing the periodic `EvictStale()` calls via a temporary debug log line, removed before commit, or via `strace`/`ltrace` confirming the timerfd fires and the callback runs) since no automated test covers `RunNetPolicyDaemon`'s epoll loop itself.

- [ ] **Step 5: Commit**

```bash
git add net-policy.cpp net/connection_manager.h
git commit -m "Wire a periodic timerfd-driven reaper sweep into the daemon's epoll loop

No new threads or locking -- the reaper runs on the same single
epoll thread as every other callback, matching this daemon's
architecture throughout every prior phase of this migration."
```

---

### Task 7: Final verification — end-to-end traces, delete retired TCP-tracking types

**Files:**
- Possibly modify: `net-policy.h` (delete `TcpFourTupleV4`/`TCP_FOUR_TUPLE_V4`, `MicroSegEngine::TcpCtInput()`/`TcpCtOutput()`, `tcp_ct_input_`/`tcp_ct_output_` if confirmed unreferenced)
- Create or extend: `tests/net_flow_engine_ffi_test.cc` (end-to-end allow/deny traces through the real callback-shaped call sequence)

**Interfaces:** None new — this task verifies the whole phase's final state.

- [ ] **Step 1: Confirm `TcpFourTupleV4`/`TcpCtInput`/`TcpCtOutput` are fully unreferenced**

```bash
grep -n "TcpFourTupleV4\|TCP_FOUR_TUPLE_V4\|TcpCtInput\|TcpCtOutput\|tcp_ct_input_\|tcp_ct_output_" net-policy.h net-policy.cpp rule-detail.cpp
```
If the only remaining references are the type/method definitions themselves (zero call sites), delete them from `net-policy.h`. If anything else still references them, stop and reconcile with Task 5 rather than leaving dead code in place unexplained.

- [ ] **Step 2: Add end-to-end integration tests**

Using the existing `ConnectionManagerMicrosegTest`/`ConnectionManagerCutoverTest` infrastructure, add tests that exercise a SYN → HTTP request → policy match sequence for both an allow and a deny rule_key, confirming `DispatchMicroseg`'s returned `Header` drives the same verdict shape `MatchHttpPolicyRule` would have produced against the old `TcpCtInput`-based path (structurally mirroring, not literally reusing, whatever assertions existed in the deleted code's own historical tests, if any existed — check `tests/` for any pre-existing microseg-specific test file before writing these from scratch).

- [ ] **Step 3: Build and run the full suite one more time**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j2 net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && ./net_rule_test && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*'"
```
Run the grpc suite at least 3 times.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "Verify Phase 6b-2's microseg consolidation end-to-end; retire TcpFourTupleV4/TcpCtInput/TcpCtOutput"
```

---

## Definition of Done

- `MicroSegEngine::TcpCtInput()`/`TcpCtOutput()` and `TcpFourTupleV4` are gone; microsegmentation's per-flow state lives in `ConnectionManager::microseg_conns_`, keyed identically to `http_conns_`.
- `input_nfq_cb`/`output_nfq_cb` contain no hand-rolled TCP SYN/FIN/RST/sequence-number detection, no manual packet header re-parsing (`struct tcphdr`, `memcpy`) — both dispatch on `net_flow::PacketDecision::kind`.
- `net_flow_engine`'s `FlowEngine` has a real, tested eviction path (`evict_stale`/`evict_stale_connections`), driven by a `timerfd` on the daemon's existing single-threaded epoll loop — no new threads, no new locking.
- Duplicate-segment detection is centralized in Rust; WAF gets this guard for free (flagged explicitly, not silently absorbed).
- Microsegmentation's late-binding recovery (start HTTP tracking for a flow whose SYN was never seen) is preserved via the new `UnknownData` decision kind, with WAF's behavior for that case unchanged.
- `Connection::setTcpSeq`/`getTcpSeq`/`tcp_seq_` are confirmed dead code (not deleted in this phase — flagged as a follow-up).
- Every Phase 5/6b-1 test continues to pass; new tests cover the duplicate/UnknownData/reaper paths and the full microseg dispatch lifecycle.
- Remaining before Phase 6b is fully done: Phase 6b-3 (NFQ netlink mechanics, `NFQ_RES_INFO` lifecycle, netns switching) — untouched by this phase.
