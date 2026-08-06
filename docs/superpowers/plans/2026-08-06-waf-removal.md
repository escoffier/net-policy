# WAF Feature Removal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete the WAF (Web Application Firewall) feature from the daemon in full — `waf/plugin.{h,cc}`, `waf/rule.{h,cc}`, the `crates/waf_rules_core/` Rust crate, the `AddWafRule`/`DeleteWafRule` gRPC RPCs, the `WafAttackEvent` event message, the `POLICY_WAF_ENABLE` runtime toggle, and every call site that wires WAF into the packet path, the control plane, and the build — leaving microsegmentation's independent HTTP-inspection path (`DispatchMicroseg`) completely untouched.

**Architecture:** WAF and microsegmentation are independent sibling dispatch paths inside `net::ConnectionManager` (`DispatchWaf`/`http_conns_` vs. `DispatchMicroseg`/`microseg_conns_`), not a shared mechanism — confirmed by direct reading of both paths during design. Removal proceeds outward from that innermost point (`ConnectionManager`) through the packet-processing call sites, the control-plane RPC surface, `DaemonContext`'s wiring, and finally the WAF source files and build config themselves, so that every intermediate state after a task still builds and every test still passes.

**Tech Stack:** C++17 (`-Wall -Werror`), Rust (via `cxx` bridges through Corrosion/CMake), Google Test, `tonic`/`prost` gRPC, protobuf.

## Global Constraints

- C++17, `-Wall -Werror` — every task's edits must build clean under the existing `PRIVATE_CXX_FLAGS` in `CMakeLists.txt`.
- **No compatibility shim, no deprecation window, no stubbed RPCs returning success.** This is a direct, hard cutover matching every prior phase's style. A client calling `AddWafRule`/`DeleteWafRule` after this lands gets a real gRPC "method not found," not silent success.
- `net_iptables::write_iptable_rule`'s two `if !waf_enable { ... }` blocks become **unconditional** (not removed) — this exactly matches today's default behavior (`WafEnabled()` defaults to `false`), so no deployment that wasn't explicitly setting `POLICY_WAF_ENABLE=true` observes any iptables-rule change.
- **No differential harness, no shadow-run, no runtime toggle.** This is deletion of an already-well-isolated feature, not new decision logic.
- Routine (non-privileged) `net_rule_grpc_test` runs use: `./build/net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*'` (single leading dash, colon-separated).
- Build via `mkdir -p build && cd build && cmake .. && make -j2` (never higher parallelism — a known linker/archiver memory-pressure flake at higher `-j`).
- Source of truth for scope: `docs/superpowers/specs/2026-08-06-waf-removal-design.md` (committed, user-approved). Any conflict between this plan and that spec's stated Goals/Non-Goals is the human partner's call, not the implementer's.

---

### Task 1: Retarget WAF-coupled regression tests onto the microseg path

**Files:**
- Modify: `tests/net_flow_engine_ffi_test.cc`

**Interfaces:**
- Consumes: `net::ConnectionManager::MicrosegTrack(decision, rule_key)`, `MicrosegTracked(decision) const -> bool`, `DispatchMicroseg(decision, pkg, len, rule_key) -> std::optional<http::Header>`, `MicrosegClose(decision, pkg, len) -> bool`, `microsegConnectionCount() const -> size_t` — all pre-existing on `net::ConnectionManager` (`net/connection_manager.h`), untouched by this task.
- Produces: nothing new for later tasks — this task only removes this file's last two dependencies on `DispatchWaf`/`http_conns_`/`httpConnectionCount()`, which Task 2 deletes from `net::ConnectionManager`. After this task, `tests/net_flow_engine_ffi_test.cc` has zero references to any WAF-only API.

This task is independent of every other task and safe to do first: it doesn't touch any WAF production code, only this test file.

- [ ] **Step 1: Remove the `CapturingFilter`-based test and its now-unused helper class**

Open `tests/net_flow_engine_ffi_test.cc`. Delete the comment block and `CapturingFilter` class (the `TEST`-adjacent explanation of the old `HandleData` two-step-trim bug, and the class itself) — this is everything between the anonymous `namespace {` that opens right after `ParseFiveTupleRecognizesTcpToo` and the `DataPacket()` helper function, i.e. delete this whole block:

```cpp
// Regression test for a bug the reviewer of Task 7 (the ConnectionManager/
// FlowEngine cutover) caught: HandleData used to call setTCPSegment() on the
// packet BEFORE trimming off the IP header, so the HTTP filter chain (and
// waf/plugin.cc's ModifyNetPackets, which casts TCPSegment::base_ directly to
// struct tcphdr*) would see -- and, for some WAF actions, write into -- the
// tail of the live IP header instead of the real TCP header. This test
// captures exactly what setTCPSegment() and onData() are handed and checks
// they start at the TCP header / payload respectively, not earlier.
class CapturingFilter : public http::HttpFilterBase {
public:
  http::FilterStatus onRequestHeaders(http::RequestHeaderMap&, bool) override {
    return http::FilterStatus::Continue;
  }
  http::FilterStatus onRequestBody(seastar::net::packet&, bool) override {
    return http::FilterStatus::Continue;
  }
  http::FilterStatus onResponseBody(seastar::net::packet&, bool) override {
    return http::FilterStatus::Continue;
  }
  http::FilterStatus onResponseHeaders(http::RequestHeaderMap&, bool) override {
    return http::FilterStatus::Continue;
  }
  http::FilterStatus onNewConnection(const net::ConnectionInfo&) override {
    return http::FilterStatus::Continue;
  }
  http::FilterStatus onData(seastar::net::packet& data) override {
    on_data_bytes_.assign(data.get_header(0, data.len()), data.len());
    return http::FilterStatus::Continue;
  }
  http::FilterStatus onClose() override {
    close_called_ = true;
    return http::FilterStatus::Continue;
  }
  size_t getConnectionID() const override { return 0; }
  void setTCPSegment(char* p, size_t size) override {
    tcp_segment_bytes_.assign(p, size);
  }
  http::TCPSegment& getTcpSegment() override { return tcp_segment_; }

  std::string tcp_segment_bytes_;
  std::string on_data_bytes_;
  http::TCPSegment tcp_segment_{};
  bool close_called_ = false;
};

```

Keep the `DataPacket()` and `FinPacket()` helper functions right after it — later tests in this same file (`ConnectionManagerMicrosegTest`, `ConnectionManagerReaperTest`, etc.) still use both.

- [ ] **Step 2: Delete the two WAF-coupled `TEST`s**

Delete `TEST(ConnectionManagerCutoverTest, HandleDataPassesTcpHeaderStartNotIpHeaderStartToFilters)` in full:

```cpp
TEST(ConnectionManagerCutoverTest, HandleDataPassesTcpHeaderStartNotIpHeaderStartToFilters) {
  http::HttpFilterFactory factory;
  auto captured_filter = std::make_shared<CapturingFilter>();
  factory.registerFilter([captured_filter](size_t, uint32_t, uint32_t) {
    return std::static_pointer_cast<http::HttpFilterBase>(captured_filter);
  });

  net::ConnectionManager mgr(factory);

  auto syn = DataPacket(/*syn=*/true, "");
  auto syn_result = mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);
  ASSERT_TRUE(syn_result.is_tcp);
  ASSERT_EQ(mgr.DispatchWaf(syn_result.decision, syn.data(), syn.size()), net::NetStatus::OK);

  const std::string payload = "GET /x";
  auto data_pkt = DataPacket(/*syn=*/false, payload);
  // DataPacket() defaults its TCP sequence number to 0, same as the SYN
  // packet above -- which would make the engine treat this as a
  // retransmission of the SYN (Duplicate, kind 4) rather than the next
  // segment (Data, kind 3), per Task 1's duplicate-segment detection. The
  // SYN consumes sequence number 0, so the next real segment must carry
  // seq=1. TCP sequence number is at byte offset 24 (20-byte IP header + 4
  // bytes into the TCP header).
  uint32_t seq_be = htonl(1);
  std::memcpy(data_pkt.data() + 24, &seq_be, sizeof(seq_be));
  // Deliberately not asserting on the return value here: HandleData's final
  // OK-vs-Drop result additionally depends on http::Connection::processData's
  // llhttp-based HTTP detection for these arbitrary bytes, which is unrelated
  // to (and, independently of this test, order-dependent/flaky across runs
  // for reasons predating this change -- llhttp state is not perfectly
  // process-order-independent for partial, non-CRLF-terminated input) the
  // ip_header_len/setTCPSegment fix this test exists to check. Both
  // setTCPSegment and onData (below) run unconditionally before that
  // HTTP-parse-dependent branch, so they're unaffected either way.
  auto data_result = mgr.receive(data_pkt.data(), data_pkt.size(), /*track_tcp=*/true);
  ASSERT_TRUE(data_result.is_tcp);
  mgr.DispatchWaf(data_result.decision, data_pkt.data(), data_pkt.size());

  // setTCPSegment must see the TCP header first -- source port 1234 (wire
  // bytes 0x04 0xD2) -- NOT the IP header (which would start with 0x45, the
  // version/ihl byte, if the IP-header trim were missing or applied too late).
  ASSERT_GE(captured_filter->tcp_segment_bytes_.size(), 2u);
  EXPECT_EQ(static_cast<uint8_t>(captured_filter->tcp_segment_bytes_[0]), 0x04);
  EXPECT_EQ(static_cast<uint8_t>(captured_filter->tcp_segment_bytes_[1]), 0xD2);
  // Size handed to setTCPSegment is [TCP header + payload], i.e. original
  // packet length minus the 20-byte IP header -- not the full 40+payload.
  EXPECT_EQ(captured_filter->tcp_segment_bytes_.size(), 20u + payload.size());

  // onData (after the second trim, past the TCP header too) must see exactly
  // the payload.
  EXPECT_EQ(captured_filter->on_data_bytes_, payload);
}

```

Then delete the comment block and `TEST(ConnectionManagerCutoverTest, HandleClosedInvokesOnCloseAndRemovesBothConnections)` right after it, in full:

```cpp
// Regression coverage for the connection-close and peer-creation paths in
// net::ConnectionManager. Task 6's differential test harness used to exercise
// these paths (FIN/close, peer-connection creation) against the real C++
// implementation, but was correctly deleted in Task 7 once there was only one
// implementation left to compare. Nothing replaced that coverage for the new
// glue in HandleNewConnection/HandleClosed -- this test closes that gap by
// checking, through the real net::ConnectionManager (not just the Rust
// engine), that:
//   1. A SYN creates BOTH the flow's own entry and its peer's entry in the
//      C++-side connection table (HandleNewConnection's peer_is_new branch).
//   2. A subsequent FIN invokes onClose() on the (shared) HttpFilterManager.
//   3. That same FIN removes BOTH the flow's own entry and its peer's entry
//      from the C++-side connection table (HandleClosed must not erase only
//      its own ConnectionID).
TEST(ConnectionManagerCutoverTest, HandleClosedInvokesOnCloseAndRemovesBothConnections) {
  http::HttpFilterFactory factory;
  auto captured_filter = std::make_shared<CapturingFilter>();
  factory.registerFilter([captured_filter](size_t, uint32_t, uint32_t) {
    return std::static_pointer_cast<http::HttpFilterBase>(captured_filter);
  });

  net::ConnectionManager mgr(factory);

  auto syn = SynPacket();
  auto syn_result = mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);
  ASSERT_TRUE(syn_result.is_tcp);
  ASSERT_EQ(mgr.DispatchWaf(syn_result.decision, syn.data(), syn.size()), net::NetStatus::OK);
  // Both the server-side (1234->80) and the auto-created peer (80->1234)
  // entries must be present -- this is the check that would catch
  // HandleNewConnection dropping its peer_is_new branch.
  EXPECT_EQ(mgr.httpConnectionCount(), 2u);
  EXPECT_FALSE(captured_filter->close_called_);

  auto fin = FinPacket();
  auto fin_result = mgr.receive(fin.data(), fin.size(), /*track_tcp=*/true);
  ASSERT_TRUE(fin_result.is_tcp);
  ASSERT_EQ(mgr.DispatchWaf(fin_result.decision, fin.data(), fin.size()), net::NetStatus::OK);

  EXPECT_TRUE(captured_filter->close_called_);
  // Both entries must be gone -- this is the check that would catch
  // HandleClosed erasing only its own ConnectionID and leaking its peer's.
  EXPECT_EQ(mgr.httpConnectionCount(), 0u);
}

```

Leave `TEST(ConnectionManagerCutoverTest, ReceiveReturnsFiveTupleForUdpWithoutWafDispatch)` and `TEST(ConnectionManagerCutoverTest, TcpPacketWithTrackingOffDoesNotEnterTcbTable)` (the two remaining tests in the `ConnectionManagerCutoverTest` suite) untouched for now — they're handled in the next step.

- [ ] **Step 2b: Fix the stale `WafEnabled()` reference in `TcpPacketWithTrackingOffDoesNotEnterTcbTable`'s comment**

This test doesn't call any WAF API, but its comment references a method (`daemon->WafEnabled()`) that Task 4 deletes — fix it now so it doesn't describe a symbol that's about to stop existing. Replace:

```cpp
// Regression coverage for receive()'s `track_tcp` gate, on the only input for
// which that flag is actually the deciding factor: a TCP packet. (The UDP test
// above cannot cover this -- for UDP, `is_tcp` is already false, so the
// `&& track_tcp` conjunct in `if (result.is_tcp && track_tcp)` never decides
// anything and dropping it would not fail that test.)
//
// The gate exists because net_flow_engine's FlowEngine has no timeout/reaper:
// entries leave the TCB table only on a FIN/RST for an already-tracked flow.
// net-policy.cpp passes daemon->WafEnabled() here, and waf_enable_ defaults to
// false, so tracking TCP unconditionally would grow that table without bound in
// the default deployment. Asserting on stat().tcp_conn_ (the Rust engine's live
// TCB count) is what makes this test observe that actual resource-leak
// scenario, rather than just restating the flag it was passed.
```

with:

```cpp
// Regression coverage for receive()'s `track_tcp` gate, on the only input for
// which that flag is actually the deciding factor: a TCP packet. (The UDP test
// above cannot cover this -- for UDP, `is_tcp` is already false, so the
// `&& track_tcp` conjunct in `if (result.is_tcp && track_tcp)` never decides
// anything and dropping it would not fail that test.)
//
// Production (input_nfq_cb/output_nfq_cb) always passes `true` now -- the flag
// stays on receive()'s signature only as this test seam. Asserting on
// stat().tcp_conn_ (the Rust engine's live TCB count) is what makes this test
// observe that a `track_tcp=false` caller really does leave the TCB table
// untouched, rather than just restating the flag it was passed.
```

The rest of that test's body is unchanged.

- [ ] **Step 3: Insert the two rewritten regression tests**

Insert the following two new tests immediately after the anonymous `namespace { ... }  // namespace` block that defines `SynAckPacket()`/`ReverseFinPacket()`, and before the comment `// Regression test for Critical #1 of Task 5's review: ...`. (That anonymous namespace is easy to find: it's the one right after `ConnectionManagerMicrosegTest.UnknownDataLateBindsAndExtractsHeaderInOneCall`.)

```cpp
// Regression test, retargeted from the WAF-era HandleData onto the
// microsegmentation path after WAF removal (see
// docs/superpowers/specs/2026-08-06-waf-removal-design.md). Originally this
// proved ConnectionManager::HandleData trimmed the packet to the TCP header
// (not the IP header) before handing it to the WAF's filter chain via
// setTCPSegment. DispatchMicroseg's onData path is a single trim by
// decision.payload_offset rather than HandleData's two-step
// ip_header_len-then-payload_offset trim, but the same offset-correctness
// property applies: DataPacket() places non-HTTP bytes (the fabricated TCP
// header, byte offsets 20-39) exactly where they would leak into the parse
// if payload_offset were wrong. If DispatchMicroseg ever trimmed short of
// the real payload start, llhttp would see those bytes before "GET" and
// never reach ParseState::Done, so the header below would come back empty
// instead of the exact values asserted.
TEST(ConnectionManagerMicrosegTest, DataPassesPayloadOffsetNotTcpHeaderStartToParser) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  auto syn = SynPacket();
  auto syn_result = mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);
  ASSERT_EQ(syn_result.decision.kind, 1);  // NewConnection
  mgr.MicrosegTrack(syn_result.decision, "some-rule-key");

  const std::string payload = "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n";
  auto data_pkt = DataPacket(/*syn=*/false, payload);
  // DataPacket() defaults its TCP sequence number to 0, same as the SYN
  // packet above -- the SYN consumes sequence number 0, so the next real
  // segment must carry seq=1 or the engine classifies it as a Duplicate
  // (kind 4) retransmission of the SYN, not the next Data segment (kind 3).
  // TCP sequence number is at byte offset 24 (20-byte IP header + 4 bytes
  // into the TCP header).
  uint32_t seq_be = htonl(1);
  std::memcpy(data_pkt.data() + 24, &seq_be, sizeof(seq_be));
  auto data_result = mgr.receive(data_pkt.data(), data_pkt.size(), /*track_tcp=*/true);
  ASSERT_TRUE(data_result.is_tcp);
  ASSERT_EQ(data_result.decision.kind, 3);  // Data

  auto header =
      mgr.DispatchMicroseg(data_result.decision, data_pkt.data(), data_pkt.size(), "some-rule-key");
  ASSERT_TRUE(header.has_value());
  EXPECT_EQ(header->method_, "GET");
  EXPECT_EQ(header->path_, "/x");
  EXPECT_EQ(header->host_, "example.com");
}

// Regression test, retargeted from the WAF-era HandleClosed onto the
// microsegmentation path after WAF removal (see
// docs/superpowers/specs/2026-08-06-waf-removal-design.md). Originally this
// proved HandleClosed tore down BOTH directions' http_conns_ entries from a
// single Closed dispatch, not just the dispatching direction's own.
// DispatchMicroseg's case 2 (routed through MicrosegClose) has the same
// both-directions-erased invariant -- it erases both `conn_id` and
// `peer_conn_id` unconditionally -- proven here by tracking both directions
// explicitly, then closing from just one, and checking neither survives.
TEST(ConnectionManagerMicrosegTest, MicrosegCloseErasesBothDirectionsFromASingleDispatch) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  auto syn = SynPacket();
  auto syn_result = mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);
  ASSERT_EQ(syn_result.decision.kind, 1);  // NewConnection
  mgr.MicrosegTrack(syn_result.decision, "ingress-key");

  auto syn_ack = SynAckPacket();
  auto syn_ack_result = mgr.receive(syn_ack.data(), syn_ack.size(), /*track_tcp=*/true);
  mgr.MicrosegTrack(syn_ack_result.decision, "egress-key");

  ASSERT_TRUE(mgr.MicrosegTracked(syn_result.decision));
  ASSERT_TRUE(mgr.MicrosegTracked(syn_ack_result.decision));
  ASSERT_EQ(mgr.microsegConnectionCount(), 2u);

  auto fin = FinPacket();
  auto fin_result = mgr.receive(fin.data(), fin.size(), /*track_tcp=*/true);
  ASSERT_EQ(fin_result.decision.kind, 2);  // Closed
  EXPECT_TRUE(mgr.MicrosegClose(fin_result.decision, fin.data(), fin.size()));

  EXPECT_FALSE(mgr.MicrosegTracked(syn_result.decision));
  EXPECT_FALSE(mgr.MicrosegTracked(syn_ack_result.decision));
  EXPECT_EQ(mgr.microsegConnectionCount(), 0u);
}

```

- [ ] **Step 4: Build and run the full test suite**

```bash
cd build && make -j2 && cd ..
./build/net_rule_grpc_test --gtest_filter='ConnectionManagerCutoverTest.*:ConnectionManagerMicrosegTest.*'
```

Expected: all tests in both suites PASS. `ConnectionManagerCutoverTest` now has exactly 2 tests (`ReceiveReturnsFiveTupleForUdpWithoutWafDispatch`, `TcpPacketWithTrackingOffDoesNotEnterTcbTable`) — down from 4. `ConnectionManagerMicrosegTest` has 2 more tests than before (the two new ones).

- [ ] **Step 5: Commit**

```bash
git add tests/net_flow_engine_ffi_test.cc
git commit -m "Retarget WAF-coupled regression tests onto the microseg path

Preparatory step for WAF removal: the two DispatchWaf/http_conns_-based
regression tests in tests/net_flow_engine_ffi_test.cc are rewritten against
DispatchMicroseg/microseg_conns_, preserving the properties they proved
(payload-offset correctness; both-directions-torn-down-once on close) so
this coverage isn't lost when WAF's dispatch machinery is deleted."
```

---

### Task 2: Remove WAF dispatch from `net::ConnectionManager` and the NFQ callbacks

**Files:**
- Modify: `net/connection_manager.h`
- Modify: `net/utility.h`
- Modify: `net-policy.cpp`

**Interfaces:**
- Consumes: nothing new.
- Produces: `net::ConnectionManager` with exactly one HTTP-inspection-shaped dispatch path (`DispatchMicroseg`) — `DispatchWaf`, `HandleNewConnection`, `HandleClosed`, `HandleData`, `CloseHttpConn`, `http_conns_`, and `httpConnectionCount()` no longer exist. `net::NetStatus` (in `net/utility.h`) no longer exists — it had no remaining callers after this task. `input_nfq_cb`/`output_nfq_cb` in `net-policy.cpp` no longer call `daemon->WafEnabled()` or `DispatchWaf`. `DaemonContext::WafEnabled()`/`WafRoot()` still exist after this task (Task 4 removes them) — `RunNetPolicyDaemon`'s filter registration, the two `GrpcDispatchAddWafRule`/`GrpcDispatchDeleteWafRule` functions, and the `write_iptable_rule` call site still use them and are untouched here.

Depends on Task 1 (which removed the test file's last calls to `DispatchWaf`/`http_conns_`/`httpConnectionCount()` — without that, this task would break the test build).

- [ ] **Step 1: Update `receive()`'s doc comment in `net/connection_manager.h`**

Replace:

```cpp
  // Parses the packet's five-tuple (all of TCP/UDP/ICMP) -- always, since L3-L4
  // policy matching needs it on every packet -- and, when `track_tcp` is set
  // and the packet is TCP, additionally advances the Rust engine's TCB state
  // machine. Deliberately does NOT dispatch to the WAF; the caller decides
  // whether to, via DispatchWaf below.
  //
  // `track_tcp` originally existed to preserve a resource-lifetime property:
  // FlowEngine had no timeout/reaper, entries left the TCB table only on a
  // FIN/RST for an already-tracked flow, and on_packet was only ever reached
  // behind net-policy.cpp's `daemon->WafEnabled()` guard (waf_enable_ defaults
  // to false), so tracking unconditionally would have grown that table without
  // bound in the default deployment.
  //
  // Both halves of that rationale are now gone: FlowEngine has a timeout
  // reaper, and microsegmentation's per-connection HTTP tracking is driven by
  // the same PacketDecision the WAF is, so gating it on the WAF would silently
  // disable L7 microsegmentation policy whenever the WAF is off. Production
  // callers (input_nfq_cb/output_nfq_cb) therefore pass `true`; the flag stays
  // on the signature because tests still use it to assert the untracked
  // behavior. Do NOT gate the five-tuple parse or `is_tcp` on it either way.
```

with:

```cpp
  // Parses the packet's five-tuple (all of TCP/UDP/ICMP) -- always, since L3-L4
  // policy matching needs it on every packet -- and, when `track_tcp` is set
  // and the packet is TCP, additionally advances the Rust engine's TCB state
  // machine.
  //
  // `track_tcp` originally existed to preserve a resource-lifetime property,
  // back when the only consumer of the TCB state machine was the now-removed
  // WAF feature and FlowEngine had no timeout/reaper: tracking unconditionally
  // would have grown that table without bound whenever WAF was off (its
  // default). FlowEngine has a timeout reaper now, so that rationale no
  // longer applies -- production callers (input_nfq_cb/output_nfq_cb) pass
  // `true` unconditionally, since microsegmentation's per-connection HTTP
  // tracking (DispatchMicroseg below) depends on the same PacketDecision. The
  // flag stays on the signature because tests still use it to assert the
  // untracked behavior. Do NOT gate the five-tuple parse or `is_tcp` on it
  // either way.
```

- [ ] **Step 2: Delete `DispatchWaf` from `net/connection_manager.h`**

Delete this method in full (it sits right after `receive()`, before the `MicrosegTracked` comment):

```cpp
  // Unchanged logic from the old internal Handle{NewConnection,Data,Closed}
  // dispatch -- only the call site moved, from inside receive() to here, an
  // explicitly-invoked public method. Callers should only call this for TCP
  // (ReceiveResult::is_tcp); a default-constructed decision (kind 0, Ignore)
  // is handled as a no-op regardless.
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

- [ ] **Step 3: Update `EvictStale`'s overview comment**

In the comment block right before `void EvictStale() {`, delete the final paragraph (the one starting `` `http_conns_` (WAF) deliberately gets no equivalent age sweep... ``) and fix the "neither map" wording in point 1, since only one map (`microseg_conns_`) is left. Replace:

```cpp
  //  1. The Rust engine's own TCB table. `evict_stale_connections()` drops
  //     entries whose last packet is older than the timeout and hands back
  //     their IDs; whatever this class holds for those IDs goes with them, so
  //     neither map keeps a Connection referencing a flow the engine no longer
  //     tracks.
  //
  //  2. `microseg_conns_` entries the engine can never report. A flow the
  //     daemon never saw a SYN for (it attached to a pod mid-connection, or was
  //     restarted while connections were live) is NEVER inserted into the
  //     engine's `tcbs` -- only the SYN branch of on_packet_internal inserts --
  //     so every packet on it arrives as UnknownData forever and its ID can
  //     never appear in evict_stale_connections()' output. But DispatchMicroseg
  //     case 5 late-binds a microseg_conns_ entry for exactly that flow. Source
  //     1 alone therefore leaks every late-bound flow permanently, for the
  //     lifetime of the daemon. Hence the second loop: microseg entries carry
  //     their own last_seen (refreshed by MicrosegTouch on every packet) and
  //     age out on it, whether or not the engine ever knew about them.
  //
  // `http_conns_` (WAF) deliberately gets no equivalent age sweep, because it
  // has no late-bound entries to leak: it is only ever inserted into by
  // HandleNewConnection, i.e. kind 1, whose conn_id and peer_conn_id are BOTH
  // in `tcbs` by construction (the SYN branch inserts both -- peer_is_new is
  // false precisely when the peer was already there). Source 1 covers all of
  // them. DispatchWaf's case 5 is a no-op and never inserts.
```

with:

```cpp
  //  1. The Rust engine's own TCB table. `evict_stale_connections()` drops
  //     entries whose last packet is older than the timeout and hands back
  //     their IDs; whatever this class holds for those IDs goes with them, so
  //     microseg_conns_ keeps no entry referencing a flow the engine no longer
  //     tracks.
  //
  //  2. `microseg_conns_` entries the engine can never report. A flow the
  //     daemon never saw a SYN for (it attached to a pod mid-connection, or was
  //     restarted while connections were live) is NEVER inserted into the
  //     engine's `tcbs` -- only the SYN branch of on_packet_internal inserts --
  //     so every packet on it arrives as UnknownData forever and its ID can
  //     never appear in evict_stale_connections()' output. But DispatchMicroseg
  //     case 5 late-binds a microseg_conns_ entry for exactly that flow. Source
  //     1 alone therefore leaks every late-bound flow permanently, for the
  //     lifetime of the daemon. Hence the second loop: microseg entries carry
  //     their own last_seen (refreshed by MicrosegTouch on every packet) and
  //     age out on it, whether or not the engine ever knew about them.
```

- [ ] **Step 4: Remove the `CloseHttpConn` call from `EvictStale`'s engine-driven sweep**

Replace:

```cpp
  void EvictStale(std::chrono::steady_clock::time_point now,
                  std::chrono::steady_clock::duration timeout) {
    for (const auto& shared_id : engine_->evict_stale_connections()) {
      ConnectionID id{shared_id.local_ip, shared_id.foreign_ip, shared_id.local_port,
                      shared_id.foreign_port};
      // Same teardown a FIN/RST gets (HandleClosed): the WAF's onClose is what
      // emits a connection's accumulated attack report, so erasing the entry
      // without it would silently drop that report for any connection that
      // timed out instead of closing cleanly. Erasing the peer alongside it --
      // also HandleClosed's behavior -- is additionally what keeps onClose to
      // exactly ONE call per connection when both directions go stale in the
      // same sweep, since the two directions share one HttpFilterManager.
      //
      // KNOWN, ACCEPTED ASYMMETRY -- WAF INSPECTION IS NOT RECOVERABLE AFTER A
      // REAP, MICROSEGMENTATION'S IS. Flagged explicitly here rather than
      // silently absorbed, matching how this phase documented its other
      // deliberate behavior changes (the RST-on-unknown-flow narrowing, the new
      // duplicate-segment guard WAF gained for free).
      //
      // http_conns_ is (re-)inserted ONLY by HandleNewConnection, reachable
      // only from DispatchWaf case 1 (NewConnection), which requires a SYN on a
      // flow not already in the engine's `tcbs`. Once this sweep evicts a
      // connection, the engine has dropped its TCB too, so every later packet
      // on that still-live socket arrives as kind 5 (UnknownData) -- and
      // DispatchWaf's case 5 is deliberately a no-op per this phase's plan
      // (Global Constraints), never late-binding the way DispatchMicroseg's
      // case 5 does. So a connection that goes idle past the timeout (a
      // keep-alive HTTP connection-pool socket is the realistic case) loses WAF
      // inspection permanently, for the whole remainder of its life; only
      // microsegmentation re-binds, via its own case 5.
      //
      // This is NEW with this phase -- there was no reaper before it, so no
      // connection was ever evicted while live. It is accepted rather than
      // fixed because a late-binding WAF path is a genuine design change (WAF
      // state is a whole HttpFilterManager with connection-scoped context, not
      // microseg's single re-derivable rule_key), out of scope for the fix wave
      // that documented it. If it needs fixing later, the shape is a DispatchWaf
      // case 5 that reconstructs a filter manager mid-stream -- with its own
      // decision about what onNewConnection means for a connection whose start
      // was never observed.
      CloseHttpConn(id, PeerOf(id));
      microseg_conns_.erase(id);
    }
```

with:

```cpp
  void EvictStale(std::chrono::steady_clock::time_point now,
                  std::chrono::steady_clock::duration timeout) {
    for (const auto& shared_id : engine_->evict_stale_connections()) {
      ConnectionID id{shared_id.local_ip, shared_id.foreign_ip, shared_id.local_port,
                      shared_id.foreign_port};
      microseg_conns_.erase(id);
    }
```

- [ ] **Step 5: Delete `httpConnectionCount()`**

Delete, in full:

```cpp
  // Exposes the size of the C++-side connection table (distinct from the Rust
  // engine's own flow table reported by connections()/stat() above). Used by
  // tests to verify HandleClosed/HandleNewConnection keep both the flow's own
  // entry and its peer's entry in sync with the Rust engine's lifecycle
  // decisions.
  size_t httpConnectionCount() const { return http_conns_.size(); }

```

Keep the comment/method right after it (`// Same, for the microsegmentation map. ...` / `size_t microsegConnectionCount() const { ... }`) untouched.

- [ ] **Step 6: Delete `CloseHttpConn`, `PeerOf`, `HandleNewConnection`, `HandleClosed`, `HandleData`, and the `http_conns_` member**

Delete `PeerOf` (it becomes dead code — `CloseHttpConn` was its only caller, and that's deleted in this same step):

```cpp
  // The reverse-direction ID: local and foreign swapped, exactly how
  // on_packet_internal derives peer_conn_id from conn_id.
  static ConnectionID PeerOf(const ConnectionID& id) {
    return ConnectionID{id.foreign_ip_, id.local_ip_, id.foreign_port_, id.local_port_};
  }

```

Delete `CloseHttpConn`:

```cpp
  // Shared by HandleClosed (FIN/RST) and EvictStale (idle timeout): run the
  // WAF's connection-close hook once, then drop both directions' entries.
  void CloseHttpConn(const ConnectionID& id, const ConnectionID& peer_id) {
    auto it = http_conns_.find(id);
    if (it != http_conns_.end()) {
      it->second->httpFilterManager()->onClose();
      http_conns_.erase(it);
    }
    http_conns_.erase(peer_id);
  }

```

Delete `HandleNewConnection`, `HandleClosed`, and `HandleData` in full:

```cpp
  NetStatus HandleNewConnection(const net_flow::PacketDecision& decision) {
    auto id = ToConnectionID(decision.conn_id);
    auto peer_id = ToConnectionID(decision.peer_conn_id);
    auto hashFunc = ConnectionIDHash();
    auto hash_key = hashFunc(id);
    auto filter_manager = std::make_shared<http::HttpFilterManager>(
        filter_factory_, hash_key, decision.conn_id.local_ip, decision.conn_id.foreign_ip);

    net::ConnectionInfo connInfo{
        net::ipv4ToString(decision.conn_id.local_ip), net::ipv4ToString(decision.conn_id.foreign_ip),
        decision.conn_id.local_port, decision.conn_id.foreign_port};
    if (http::FilterStatus::StopIteration == filter_manager->onNewConnection(connInfo)) {
      LOG(INFO) << "terminate connection processing";
    }
    auto http_server_conn = std::make_shared<http::Connection>(true, filter_manager);
    http_conns_[id] = http_server_conn;

    if (decision.peer_is_new) {
      auto http_client_conn = std::make_shared<http::Connection>(false, filter_manager);
      http_conns_[peer_id] = http_client_conn;
    }
    return NetStatus::OK;
  }

  NetStatus HandleClosed(const net_flow::PacketDecision& decision) {
    CloseHttpConn(ToConnectionID(decision.conn_id), ToConnectionID(decision.peer_conn_id));
    return NetStatus::OK;
  }

  NetStatus HandleData(const net_flow::PacketDecision& decision, const uint8_t* pkg, size_t len) {
    auto id = ToConnectionID(decision.conn_id);
    auto it = http_conns_.find(id);
    if (it == http_conns_.end()) {
      return NetStatus::OK;
    }
    auto p = seastar::net::packet::from_static_data(reinterpret_cast<const char*>(pkg), len);
    // setTCPSegment's contract requires the packet to already start at the TCP
    // header (see waf/plugin.cc's ModifyNetPackets, which casts the stored
    // pointer directly to `struct tcphdr*`). This mirrors the old (deleted)
    // ipv4::receive, which always stripped the IP header before Tcp::receive
    // (and thus setTCPSegment) ever saw the packet. Trimming by the combined
    // payload_offset before setTCPSegment -- or not trimming at all before it
    // -- would feed it IP-header bytes and corrupt a live packet on the
    // waf/plugin.cc ModifyNetPackets code path. Do NOT collapse this into a
    // single trim_front(payload_offset) call.
    p.trim_front(decision.ip_header_len);
    it->second->httpFilterManager()->setTCPSegment(p);
    p.trim_front(decision.payload_offset - decision.ip_header_len);
    if (http::FilterStatus::StopIteration == it->second->httpFilterManager()->onData(p)) {
      return NetStatus::OK;
    }
    auto filterStatus = it->second->processData(std::move(p));
    if (filterStatus == http::FilterStatus::DropPkt || filterStatus == http::FilterStatus::StopIteration) {
      return NetStatus::Drop;
    }
    return NetStatus::OK;
  }

```

- [ ] **Step 7: Update the `KNOWN LIMITATION` comment and delete `http_conns_`**

Replace:

```cpp
  // KNOWN LIMITATION -- LOOPBACK TRAFFIC COLLIDES IN BOTH MAPS BELOW.
  //
  // Both maps are keyed by ConnectionID alone, which is derived purely from the
  // packet's (saddr, daddr, sport, dport) -- it carries no notion of which NFQ
  // queue, and therefore which direction, the packet was captured on.
  // crates/net_iptables installs its NFQUEUE jumps on mangle PREROUTING and
  // mangle OUTPUT with no `lo`/loopback exclusion, so a 127.0.0.1 -> 127.0.0.1
  // packet is delivered to BOTH input_nfq_cb and output_nfq_cb with identical
  // bytes, yielding the SAME ConnectionID in both callbacks. For localhost or
  // sidecar traffic under an L7 microseg or WAF policy, the two directions then
  // share one entry: one direction's rule_key (looked up in InputHttpPolicy)
  // and half-parsed llhttp state can be handed to the other (which would look
  // its key up in OutputHttpPolicy), i.e. cross-direction contamination.
  //
  // This is a real regression from the pre-Phase-6b-2 design, which kept two
  // separate direction-keyed maps (MicroSegEngine::TcpCtInput()/TcpCtOutput())
  // that could not collide. It predates the callback cutover -- it arrived with
  // the single ConnectionID-keyed microseg_conns_ -- and is recorded here, in
  // the code, deliberately: the SDD ledger that first flagged it is deleted
  // when this branch merges. Non-loopback traffic is unaffected, since the two
  // directions of such a flow have genuinely distinct ConnectionIDs.
  //
  // The fix, when it is done, is to key both maps by (ConnectionID, direction)
  // -- roughly 40 lines, touching every call site in net-policy.cpp -- or to
  // exclude `lo` at the iptables layer. Do not paper over it by mutating shared
  // entries defensively at the use sites.
  std::unordered_map<ConnectionID, std::shared_ptr<http::Connection>, ConnectionIDHash> http_conns_;
  std::unordered_map<ConnectionID, MicrosegEntry, ConnectionIDHash> microseg_conns_;
```

with:

```cpp
  // KNOWN LIMITATION -- LOOPBACK TRAFFIC COLLIDES IN THE MAP BELOW.
  //
  // microseg_conns_ is keyed by ConnectionID alone, which is derived purely
  // from the packet's (saddr, daddr, sport, dport) -- it carries no notion of
  // which NFQ queue, and therefore which direction, the packet was captured
  // on. crates/net_iptables installs its NFQUEUE jumps on mangle PREROUTING
  // and mangle OUTPUT with no `lo`/loopback exclusion, so a 127.0.0.1 ->
  // 127.0.0.1 packet is delivered to BOTH input_nfq_cb and output_nfq_cb with
  // identical bytes, yielding the SAME ConnectionID in both callbacks. For
  // localhost or sidecar traffic under an L7 microsegmentation policy, the
  // two directions then share one entry: one direction's rule_key (looked up
  // in InputHttpPolicy) and half-parsed llhttp state can be handed to the
  // other (which would look its key up in OutputHttpPolicy), i.e.
  // cross-direction contamination.
  //
  // This is a real regression from the pre-Phase-6b-2 design, which kept two
  // separate direction-keyed maps (MicroSegEngine::TcpCtInput()/TcpCtOutput())
  // that could not collide. It predates the callback cutover -- it arrived with
  // the single ConnectionID-keyed microseg_conns_ -- and is recorded here, in
  // the code, deliberately: the SDD ledger that first flagged it is deleted
  // when this branch merges. Non-loopback traffic is unaffected, since the two
  // directions of such a flow have genuinely distinct ConnectionIDs.
  //
  // The fix, when it is done, is to key microseg_conns_ by (ConnectionID,
  // direction) -- roughly 40 lines, touching every call site in
  // net-policy.cpp -- or to exclude `lo` at the iptables layer. Do not paper
  // over it by mutating shared entries defensively at the use sites.
  std::unordered_map<ConnectionID, MicrosegEntry, ConnectionIDHash> microseg_conns_;
```

- [ ] **Step 8: Delete the now-dead `NetStatus` enum from `net/utility.h`**

After Steps 1-7, `net::NetStatus` has zero remaining references anywhere in the repo except the two `net-policy.cpp` call sites deleted in the next step. Delete it from `net/utility.h`:

```cpp
enum class NetStatus {
    OK,
    Drop
};

```

(Leave everything else in `net/utility.h` — `NetworkStat`, `ConnectionID`, `ipv4ToString`, etc. — untouched.)

- [ ] **Step 9: Remove the `DispatchWaf` call and comment from `input_nfq_cb` in `net-policy.cpp`**

Replace:

```cpp
  // `track_tcp` is now unconditionally true. Until this phase it was
  // WafEnabled(), because the WAF was the only consumer of the TCB state
  // machine and FlowEngine had no reaper -- tracking with the WAF off (the
  // default, waf_enable_ = false) would have grown the TCB table without
  // bound. Both halves of that rationale are gone: microsegmentation's
  // per-connection HTTP tracking is now driven by the same decision (see the
  // TCP block below), so leaving the gate in place would have silently
  // disabled L7 microsegmentation policy in every WAF-off deployment -- a
  // functional regression, not a carried-forward constraint, since the
  // hand-rolled state machine this phase retires ran regardless of the WAF.
  // Unbounded growth is instead handled by FlowEngine's timeout reaper (added
  // earlier in this phase; wired to a timerfd on the epoll loop by the task
  // that follows this one). Note DispatchWaf below is still WAF-gated, so the
  // WAF's own behavior is unchanged either way.
  auto result = daemon->ConnMgr().receive(reinterpret_cast<const uint8_t*>(pkg), data_len,
                                          /*track_tcp=*/true);
```

with:

```cpp
  // `track_tcp` is unconditionally true: microsegmentation's per-connection
  // HTTP tracking depends on the same PacketDecision (see the TCP block
  // below), and unbounded TCB growth is bounded by FlowEngine's timeout
  // reaper (the timerfd armed in RunNetPolicyDaemon), not by gating tracking
  // itself.
  auto result = daemon->ConnMgr().receive(reinterpret_cast<const uint8_t*>(pkg), data_len,
                                          /*track_tcp=*/true);
```

Then delete this block entirely (it sits right after the `tuple.dst_addr_ = ...` line and the commented-out `LOG_V(...)` debug lines, right before the `if ((tuple.proto_ == IPPROTO_UDP) ...)` block):

```cpp
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

```

- [ ] **Step 10: Remove the `DispatchWaf` call and comment from `output_nfq_cb` in `net-policy.cpp`**

Replace:

```cpp
  // `track_tcp` is unconditionally true -- see input_nfq_cb's identical call
  // for why this is no longer gated on WafEnabled().
  auto result = daemon->ConnMgr().receive(reinterpret_cast<const uint8_t*>(pkg), data_len,
                                          /*track_tcp=*/true);
```

with:

```cpp
  // `track_tcp` is unconditionally true -- see input_nfq_cb's identical call
  // for the rationale.
  auto result = daemon->ConnMgr().receive(reinterpret_cast<const uint8_t*>(pkg), data_len,
                                          /*track_tcp=*/true);
```

Then delete this block entirely (same shape as `input_nfq_cb`'s, right before its own `if ((tuple.proto_ == IPPROTO_UDP) ...)` block):

```cpp
  if (daemon->WafEnabled() && result.is_tcp) {
    auto status = daemon->ConnMgr().DispatchWaf(result.decision,
                                                reinterpret_cast<const uint8_t*>(pkg), data_len);
    if (status == net::NetStatus::Drop) {
      // LOG_D("drop pkt: %p", pkg);
      queue.verdict_with_mark(id, net_nfq::NfqVerdict::Accept,
                              static_cast<uint32_t>(NetPolicyRule::kAllowRsp),
                              {pkg, static_cast<size_t>(data_len)});
      return;
    }
  }

```

- [ ] **Step 11: Build and run the full test suite**

```bash
cd build && make -j2 && cd ..
./build/net_rule_test
./build/net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*'
```

Expected: full build succeeds, both binaries report 0 failures. (`daemon->WafEnabled()`/`daemon->WafRoot()` still exist and are still used elsewhere in `net-policy.cpp` at this point — that's expected, Task 4 removes them.)

- [ ] **Step 12: Commit**

```bash
git add net/connection_manager.h net/utility.h net-policy.cpp
git commit -m "Remove WAF dispatch from ConnectionManager and the NFQ callbacks

DispatchWaf, HandleNewConnection, HandleClosed, HandleData, CloseHttpConn,
http_conns_, and httpConnectionCount() are deleted from net::ConnectionManager
-- microsegmentation's DispatchMicroseg/microseg_conns_ path is untouched.
The now-dead net::NetStatus enum and PeerOf helper go with them. Both NFQ
callbacks in net-policy.cpp no longer gate on daemon->WafEnabled() or call
DispatchWaf."
```

---

### Task 3: Remove the WAF gRPC control-plane surface

**Files:**
- Modify: `proto/net_policy_control.proto`
- Modify: `proto/net_policy_events.proto`
- Modify: `crates/net_policy_control/src/lib.rs`
- Modify: `crates/net_policy_events/src/lib.rs`
- Modify: `grpc/control_dispatch.h`
- Modify: `net-policy.cpp`
- Modify: `tests/grpc_rust_control_e2e_test.cc`
- Modify: `tests/grpc_rust_events_e2e_test.cc`

**Interfaces:**
- Consumes: nothing new.
- Produces: no `AddWafRule`/`DeleteWafRule` RPC, no `WafAttackEvent` message, no `GrpcDispatchAddWafRule`/`GrpcDispatchDeleteWafRule` C++ functions, no `add_waf_rule`/`delete_waf_rule`/`publish_waf_attack` Rust handlers. `daemon->WafRoot()` still exists after this task (used only by `RunNetPolicyDaemon`'s filter registration now) — Task 4 removes it.

This must land as one commit: the proto messages, the Rust bridge declarations, the C++ definitions, and the test references are mutually dependent — a partial removal breaks the build.

- [ ] **Step 1: Remove the WAF RPCs and messages from `proto/net_policy_control.proto`**

Delete these two lines from the `service NetPolicyControl { ... }` block:

```proto
  rpc AddWafRule(AddWafRuleRequest)             returns (StatusResponse);          // NetDataType::kAddWafRule
  rpc DeleteWafRule(DeleteWafRuleRequest)       returns (StatusResponse);          // NetDataType::kDelWafRule
```

Delete these four messages in full:

```proto
// mirrors Rule, waf/rule.h:55-65 (fields set by ParseConfiguration, waf/plugin.cc:462-481)
message WafRule {
  int64  id          = 1;
  int64  level       = 2;
  string type        = 3;
  string name        = 4;
  string expr        = 5;
  string mode        = 6;
  string description = 7;  // JSON key on the wire is "Description" (capital D), waf/plugin.cc:477
}
// mirrors BWList's fields as read by ParseConfiguration, waf/plugin.cc:532-545
// (BWList itself has additional fields -- action_/desc_/oprexpr_/rtype_/rdata_ -- that
// ParseConfiguration never populates from JSON; they are intentionally omitted here too)
message BlackWhiteListEntry {
  uint64 id   = 1;
  string name = 2;
  string expr = 3;
  string mode = 4;
}
// mirrors the full field set ParseConfiguration reads, waf/plugin.cc:427-581
message AddWafRuleRequest {
  repeated string pod_ips = 1;
  repeated WafRule rules = 2;
  repeated string domains = 3;
  repeated string excluded_file_types = 4;
  repeated string detect_headers = 5;
  repeated BlackWhiteListEntry black_white_lists = 6;
  string uri = 7;
  string mode = 8;           // default action, Rules::AddDefAction
  string name = 9;           // app name
  string cluster_key = 10;
  string k8s_namespace = 11; // JSON key on the wire is "namespace"
  string kind = 12;
  string workload_name = 13;
  uint64 service_id = 14;
}
message DeleteWafRuleRequest {
  repeated string pod_ips = 1;  // waf/plugin.cc:621+ (pod_ips only)
}
```

- [ ] **Step 2: Remove `WafAttackEvent` from `proto/net_policy_events.proto`**

Replace:

```proto
message PolicyEvent {
  oneof event {
    PolicyMatchEvent policy_match = 1;
    WafAttackEvent   waf_attack   = 2;
  }
}
```

with:

```proto
message PolicyEvent {
  oneof event {
    PolicyMatchEvent policy_match = 1;
  }
}
```

Delete the `WafAttackEvent` message in full:

```proto
// mirrors the envelope + attacked_log[0] object built in PluginContext::onClose
// (waf/plugin.cc:100-142) before being handed to PluginRootContext::HttpPost.
message WafAttackEvent {
  // envelope fields (waf/plugin.cc:112-118)
  uint64 service_id    = 1;
  string res_name      = 2;
  string app_name      = 3;
  string res_kind      = 4;
  string k8s_namespace = 5;  // JSON key on the wire is "namespace"
  string cluster_key   = 6;
  // attack detail fields (waf/plugin.cc:123-134, AttackedLog struct waf/rule.h)
  string action           = 7;
  string attack_ip        = 8;
  string attacked_app     = 9;
  string attack_load      = 10;
  int64  attack_time      = 11;
  int64  rule_id          = 12;
  string rule_name        = 13;
  string req_pkg          = 14;
  string rsp_pkg          = 15;
  string attack_type      = 16;  // AttackedLog::type_
  string attacked_url     = 17;
  string rsp_content_type = 18;
}
```

- [ ] **Step 3: Remove WAF from `crates/net_policy_control/src/lib.rs`**

In the `use proto::{...}` import list, remove `AddWafRuleRequest`, `BlackWhiteListEntry as ProtoBwEntry`, `DeleteWafRuleRequest`, and `WafRule as ProtoWafRule`. Replace:

```rust
use proto::{
    AddPolicyRuleRequest, AddWafRuleRequest, AddressEndpoint as ProtoAddressEndpoint,
    BlackWhiteListEntry as ProtoBwEntry, ContainerInfo as ProtoContainerInfo,
    DeletePolicyRuleRequest, DeleteWafRuleRequest, DumpConfigRequest, DumpConfigResponse,
    DumpConnectionsRequest, DumpConnectionsResponse, DumpHeapProfileRequest,
    HttpMatchRule as ProtoHttpRule, PodDownRequest, PodUpRequest,
    PolicyRuleConfigEntry as ProtoConfigEntry, PolicyRuleSpec as ProtoRuleSpec, PortRange as ProtoPortRange,
    ResetConfigRequest, SetLogLevelRequest, StatusResponse, UpdateNodeConfigRequest,
    WafRule as ProtoWafRule,
};
```

with:

```rust
use proto::{
    AddPolicyRuleRequest, AddressEndpoint as ProtoAddressEndpoint,
    ContainerInfo as ProtoContainerInfo,
    DeletePolicyRuleRequest, DumpConfigRequest, DumpConfigResponse,
    DumpConnectionsRequest, DumpConnectionsResponse, DumpHeapProfileRequest,
    HttpMatchRule as ProtoHttpRule, PodDownRequest, PodUpRequest,
    PolicyRuleConfigEntry as ProtoConfigEntry, PolicyRuleSpec as ProtoRuleSpec, PortRange as ProtoPortRange,
    ResetConfigRequest, SetLogLevelRequest, StatusResponse, UpdateNodeConfigRequest,
};
```

Delete the `WafRule` and `BlackWhiteListEntry` cxx-bridge structs:

```rust
    struct WafRule {
        id: i64,
        level: i64,
        // `type` is a Rust reserved keyword, so the Rust-side field must be
        // written as the raw identifier `r#type`. Without an explicit
        // #[cxx_name], cxx's C++ codegen emits the Rust field's `to_string()`
        // verbatim -- "r#type" -- as the generated C++ struct member name,
        // which is not a valid C++ identifier and fails to compile.
        // #[cxx_name = "type"] is required to get the (valid, and
        // conventional -- see the `r.type` usage in net-policy.cpp's
        // GrpcDispatchAddWafRule) plain `type` member on the C++ side.
        // Verified empirically against this repo's pinned cxx 1.0.198 by
        // building a standalone throwaway crate and inspecting the generated
        // header.
        #[cxx_name = "type"]
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

Delete the `GrpcDispatchDeleteWafRule` extern decl:

```rust
        unsafe fn GrpcDispatchDeleteWafRule(
            daemon: *mut DaemonContext,
            queue: *mut GrpcDispatchQueue,
            pod_ips: Vec<String>,
        ) -> bool;

```

Delete the `GrpcDispatchAddWafRule` extern decl:

```rust
        unsafe fn GrpcDispatchAddWafRule(
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

Delete the `add_waf_rule` handler in full:

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

Delete the `delete_waf_rule` handler in full:

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

- [ ] **Step 4: Remove WAF from `crates/net_policy_events/src/lib.rs`**

Replace:

```rust
use proto::{PolicyEvent, PolicyMatchEvent, WafAttackEvent};
```

with:

```rust
use proto::{PolicyEvent, PolicyMatchEvent};
```

Delete the `publish_waf_attack` extern decl from the cxx bridge:

```rust
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

```

Delete the `publish_waf_attack` implementation in full:

```rust
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

- [ ] **Step 5: Remove the WAF declarations from `grpc/control_dispatch.h`**

Delete:

```cpp
bool GrpcDispatchDeleteWafRule(DaemonContext* daemon, GrpcDispatchQueue* queue,
                                rust::Vec<rust::String> pod_ips);

```

Delete the comment and forward decls right before `GrpcDispatchAddWafRule`, plus the declaration itself:

```cpp
// Full definitions generated by cxx bridge codegen (from the shared structs
// declared in crates/net_policy_control/src/lib.rs's bridge module) in
// net_policy_control_cxxbridge/lib.h -- string/vector fields there are
// rust::String / rust::Vec<T>, not std::string / std::vector<T>. Only
// forward-declared here so this header's function declaration is
// self-contained; net-policy.cpp sees the complete types via its earlier
// #include of that generated header.
struct WafRule;
struct BlackWhiteListEntry;

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

- [ ] **Step 6: Remove `GrpcDispatchDeleteWafRule`/`GrpcDispatchAddWafRule` from `net-policy.cpp`**

Delete `GrpcDispatchDeleteWafRule` in full:

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

Delete `GrpcDispatchAddWafRule` in full:

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
  cJSON_AddItemToObject(root, "domain", domains_arr); // key is "domain" (singular), matches ParseConfiguration's expected schema

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

- [ ] **Step 7: Remove the WAF tests from `tests/grpc_rust_control_e2e_test.cc`**

Delete the comment and `TEST_F` in full:

```cpp
// PluginRootContext::RemoveWafRule (waf/plugin.cc) parses the JSON, then for
// each pod IP in the "pod_ips" array does waf_rules_.erase(ip) -- a no-op on
// std::map when the key isn't present -- and unconditionally returns true as
// long as the "pod_ips" key itself was present. So an unknown pod IP is
// still a "success" from RemoveWafRule's perspective, and
// GrpcDispatchDeleteWafRule (net-policy.cpp) maps that to status 0, not an
// error, matching the pattern already seen in DeletePolicyRule/PodDown for
// other "not found" inputs.
TEST_F(GrpcRustControlEndToEndTest, DeleteWafRuleForUnknownPodReturnsZeroStatus) {
  grpc::ClientContext ctx;
  netpolicy::v1::DeleteWafRuleRequest req;
  req.add_pod_ips("10.0.0.99");
  netpolicy::v1::StatusResponse resp;
  grpc::Status status = stub_->DeleteWafRule(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_EQ(resp.status(), 0);
}

```

Delete the other `TEST_F` in full:

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

- [ ] **Step 8: Remove the WAF tests and include from `tests/grpc_rust_events_e2e_test.cc`**

Delete the include:

```cpp
#include "waf/plugin.h"
```

(Remove the now-empty blank line this leaves behind if any, keeping the remaining `#include`s tidy.)

Delete `TEST_F(GrpcRustEventsEndToEndTest, SubscribeEventsReceivesPublishedWafAttack)` in full:

```cpp
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
  reader->Finish(); // ignore the returned status -- we intentionally cancelled
  // Give the server-side spawn_blocking loop time to notice the torn-down
  // stream (via a failed blocking_send) and exit before the next TEST_F
  // starts a new SubscribeEvents call against the same shared global
  // queue -- otherwise this test's now-stale loop can race the next
  // test's loop for the next published event and steal it. 500ms is the
  // loop's own wait_and_pop timeout; add a safety margin.
  std::this_thread::sleep_for(std::chrono::milliseconds(600));
}

```

Delete `TEST_F(GrpcRustEventsEndToEndTest, PublishWafAttackToRustEventServiceSendsEvent)` in full:

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

```

Delete `TEST_F(GrpcRustEventsEndToEndTest, PublishWafAttackToRustEventServiceSkipsInvalidUtf8)` in full:

```cpp
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

`TEST_F(GrpcRustEventsEndToEndTest, SubscribeEventsReceivesPublishedPolicyMatch)`, `SubscribeEventsStopsAfterClientCancellation`, and `PostServerSendMatchMsgDualPublishesToRust` are untouched.

- [ ] **Step 9: Regenerate `Cargo.lock` and build**

```bash
cargo check --workspace
cd build && cmake .. && make -j2 && cd ..
```

- [ ] **Step 10: Run the full test suite**

```bash
./build/net_rule_test
./build/net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*'
```

Expected: full build succeeds, both binaries report 0 failures. `net_rule_grpc_test`'s test count has dropped by 5 relative to Task 2's end state (2 from `grpc_rust_control_e2e_test.cc`, 3 from `grpc_rust_events_e2e_test.cc`).

- [ ] **Step 11: Commit**

```bash
git add proto/net_policy_control.proto proto/net_policy_events.proto \
        crates/net_policy_control/src/lib.rs crates/net_policy_events/src/lib.rs \
        grpc/control_dispatch.h net-policy.cpp \
        tests/grpc_rust_control_e2e_test.cc tests/grpc_rust_events_e2e_test.cc \
        Cargo.lock
git commit -m "Remove the WAF gRPC control-plane surface

Deletes AddWafRule/DeleteWafRule (RPCs and their request/message types) from
net_policy_control.proto, WafAttackEvent from net_policy_events.proto, the
corresponding Rust handlers (add_waf_rule/delete_waf_rule/publish_waf_attack)
and cxx-bridge declarations, and the C++ GrpcDispatchAddWafRule/
GrpcDispatchDeleteWafRule dispatch functions. Direct cutover, no compat
shim: a client calling either RPC now gets a real gRPC method-not-found."
```

---

### Task 4: Remove `DaemonContext`'s WAF wiring and the iptables `waf_enable` coupling

**Files:**
- Modify: `net-policy.h`
- Modify: `net-policy.cpp`
- Modify: `log.h`
- Modify: `crates/net_iptables/src/lib.rs`
- Modify: `tests/net_iptables_ffi_test.cc`

**Interfaces:**
- Consumes: nothing new.
- Produces: `DaemonContext` with no `waf_root_`/`WafRoot()`/`WafEnabled()`/`SetWafEnabled()`/`waf_enable_`. `net_iptables::write_iptable_rule(i_mark: i32, o_mark: i32, ipt_ver: i32)` — 3 arguments, unconditionally installs the `CONNMARK --save-mark` rules (matching today's default `WafEnabled() == false` behavior for every deployment). No more `#include "waf/plugin.h"` in `net-policy.h` — `waf/plugin.h` itself still exists (Task 5 deletes it) but nothing includes it anymore after this task.

Depends on Task 3 (which removed the last two callers of `daemon->WafRoot()` — `GrpcDispatchAddWafRule`/`GrpcDispatchDeleteWafRule` — leaving only `RunNetPolicyDaemon`'s filter registration, which this task also removes).

- [ ] **Step 1: Remove `#include "waf/plugin.h"` from `net-policy.h`**

Delete this line from the `#include` block:

```cpp
#include "waf/plugin.h"
```

- [ ] **Step 2: Remove `DaemonContext`'s WAF members in `net-policy.h`**

Replace:

```cpp
class DaemonContext
{
public:
    DaemonContext() : connection_manager_(http_filter_factory_) {
        waf_root_.SetPostFd(post_server_.FdPtr());
    }
    DaemonContext(const DaemonContext&) = delete;
    DaemonContext& operator=(const DaemonContext&) = delete;

    /*---- already-encapsulated instances ----*/
    MicroSegEngine&                     Microseg()   { return microseg_; }
    net::ConnectionManager&             ConnMgr()    { return connection_manager_; }
    PostServer&                         PostSrv()    { return post_server_; }
    http::extension::PluginRootContext& WafRoot()    { return waf_root_; }
    http::HttpFilterFactory&            HttpFilters(){ return http_filter_factory_; }

    /*---- former raw-scalar globals (g_log_level stays a separate atomic global) ----*/
    bool WafEnabled() const           { return waf_enable_; }
    void SetWafEnabled(bool v)        { waf_enable_ = v; }
    int  IptablesVersion() const      { return ipt_ver_; }
    void SetIptablesVersion(int v)    { ipt_ver_ = v; }

    /*non-owning; wired once at startup -- see grpc/control_dispatch.h for
     *GrpcDispatchQueue.*/
    void WireRustControlDispatch(grpc_bridge::GrpcDispatchQueue* q) { rust_dispatch_queue_ = q; }
    grpc_bridge::GrpcDispatchQueue* RustControlDispatchQueue() { return rust_dispatch_queue_; }

private:
    bool waf_enable_      = false;
    int  ipt_ver_         = 0;

    http::HttpFilterFactory              http_filter_factory_;      // must precede connection_manager_
    net::ConnectionManager               connection_manager_;
    MicroSegEngine                       microseg_;
    PostServer                           post_server_;
    http::extension::PluginRootContext   waf_root_;

    grpc_bridge::GrpcDispatchQueue* rust_dispatch_queue_ = nullptr; // non-owning
};
```

with:

```cpp
class DaemonContext
{
public:
    DaemonContext() : connection_manager_(http_filter_factory_) {}
    DaemonContext(const DaemonContext&) = delete;
    DaemonContext& operator=(const DaemonContext&) = delete;

    /*---- already-encapsulated instances ----*/
    MicroSegEngine&                     Microseg()   { return microseg_; }
    net::ConnectionManager&             ConnMgr()    { return connection_manager_; }
    PostServer&                         PostSrv()    { return post_server_; }
    http::HttpFilterFactory&            HttpFilters(){ return http_filter_factory_; }

    /*---- former raw-scalar globals (g_log_level stays a separate atomic global) ----*/
    int  IptablesVersion() const      { return ipt_ver_; }
    void SetIptablesVersion(int v)    { ipt_ver_ = v; }

    /*non-owning; wired once at startup -- see grpc/control_dispatch.h for
     *GrpcDispatchQueue.*/
    void WireRustControlDispatch(grpc_bridge::GrpcDispatchQueue* q) { rust_dispatch_queue_ = q; }
    grpc_bridge::GrpcDispatchQueue* RustControlDispatchQueue() { return rust_dispatch_queue_; }

private:
    int  ipt_ver_         = 0;

    http::HttpFilterFactory              http_filter_factory_;      // must precede connection_manager_
    net::ConnectionManager               connection_manager_;
    MicroSegEngine                       microseg_;
    PostServer                           post_server_;

    grpc_bridge::GrpcDispatchQueue* rust_dispatch_queue_ = nullptr; // non-owning
};
```

- [ ] **Step 3: Remove the now-dead `PostServer::FdPtr()` in `net-policy.h`**

`FdPtr()`'s only caller was the constructor line just deleted in Step 2. Replace:

```cpp
/*post-notification server — owns the client fd and sends match/WAF events*/
class PostServer
{
public:
    ~PostServer() { if (post_link_fd_ > 0) close(post_link_fd_); }
    /*accept a new client; closes any previously connected fd*/
    void Accept(int client_fd);
    /*send a policy-match notification; returns 0 on success, -1 on error*/
    int  SendMatchMsg(FiveTuple& tuple, NetPolicyRule action, FlowDir dir,
                      const std::string& rule_key);
    /*return pointer to the fd so the WAF plugin can write directly*/
    int* FdPtr() { return &post_link_fd_; }

private:
    int post_link_fd_ = 0;
};
```

with:

```cpp
/*post-notification server — owns the client fd and sends policy-match events*/
class PostServer
{
public:
    ~PostServer() { if (post_link_fd_ > 0) close(post_link_fd_); }
    /*accept a new client; closes any previously connected fd*/
    void Accept(int client_fd);
    /*send a policy-match notification; returns 0 on success, -1 on error*/
    int  SendMatchMsg(FiveTuple& tuple, NetPolicyRule action, FlowDir dir,
                      const std::string& rule_key);

private:
    int post_link_fd_ = 0;
};
```

- [ ] **Step 4: Remove the `PluginContext` filter registration from `RunNetPolicyDaemon` in `net-policy.cpp`**

Delete:

```cpp
  daemon.HttpFilters().registerFilter(
      [root = &daemon.WafRoot()](size_t id, uint32_t from,
                                  uint32_t to) -> std::shared_ptr<http::HttpFilterBase> {
        return std::make_shared<http::extension::PluginContext>(id, from, to, root);
      });

```

Leave the `LogFilter` registration right before it untouched.

- [ ] **Step 5: Remove the `POLICY_WAF_ENABLE` env var read from `RunNetPolicyDaemon`**

Delete:

```cpp
  /*get waf env*/
  log_level_env = getenv(POLICY_WAF_ENABLE);
  if (log_level_env)
    daemon.SetWafEnabled(strcmp(log_level_env, "true") == 0);
```

- [ ] **Step 6: Update the reaper-timer comment in `RunNetPolicyDaemon`**

Replace:

```cpp
  // --- Reaper timer (Phase 6b-2): periodic sweep of stale TCB/microseg state ---
  // This is what bounds the memory the TCP-tracking path consumes. It became
  // load-bearing rather than merely tidy when the microsegmentation cutover
  // dropped the old WafEnabled() gate on receive()'s track_tcp: TCB tracking
  // now runs on every TCP connection in every deployment, including the default
  // WAF-off one (see input_nfq_cb's comment on that argument), so without this
  // timer both the Rust engine's TCB table and ConnectionManager's own per-flow
  // maps would grow without bound for the daemon's lifetime.
```

with:

```cpp
  // --- Reaper timer (Phase 6b-2): periodic sweep of stale TCB/microseg state ---
  // This is what bounds the memory the TCP-tracking path consumes. It became
  // load-bearing when microsegmentation's cutover made receive()'s track_tcp
  // unconditional (see input_nfq_cb's comment on that argument): TCB tracking
  // now runs on every TCP connection in every deployment, so without this
  // timer both the Rust engine's TCB table and ConnectionManager's own per-flow
  // maps would grow without bound for the daemon's lifetime.
```

- [ ] **Step 7: Drop the `WafEnabled()` argument from the `write_iptable_rule` call site**

Replace:

```cpp
        net_iptables::write_iptable_rule(1, 1, daemon->IptablesVersion(), daemon->WafEnabled());
```

with:

```cpp
        net_iptables::write_iptable_rule(1, 1, daemon->IptablesVersion());
```

- [ ] **Step 8: Remove `POLICY_WAF_ENABLE` from `log.h`**

Delete:

```cpp
#define POLICY_WAF_ENABLE "POLICY_WAF_ENABLE"
```

(Leave `#define POLICY_LOG_LEVEL "POLICY_LOG_LEVEL"` untouched.)

- [ ] **Step 9: Drop `write_iptable_rule`'s `waf_enable` parameter in `crates/net_iptables/src/lib.rs`**

Replace the cxx bridge decl:

```rust
        fn write_iptable_rule(i_mark: i32, o_mark: i32, ipt_ver: i32, waf_enable: bool);
```

with:

```rust
        fn write_iptable_rule(i_mark: i32, o_mark: i32, ipt_ver: i32);
```

Replace the function itself:

```rust
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
```

with:

```rust
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
```

- [ ] **Step 10: Update `crates/net_iptables/src/lib.rs`'s own tests**

Fix `cleanup_test_chains`'s comment (drop the `waf_enable=false`-specific framing since the rules are now always installed):

```rust
        // Also remove the two CONNMARK --save-mark rules that write_iptable_rule
        // appends directly to the builtin INPUT/POSTROUTING chains when called
        // with waf_enable=false. Empirically verified this needs its own -D:
        // production's clear_iptables_rule uses a bare `-t mangle -F` (no chain
        // argument), which flushes *every* chain in the mangle table -- including
        // INPUT/POSTROUTING's own rules -- so that path clears these for free.
        // But this helper uses `-F TS_ZERO_PREROUTING`/`-F TS_ZERO_OUTPUT` (named,
        // scoped to just those user chains), which does NOT touch INPUT or
        // POSTROUTING at all, so rules appended directly to them would otherwise
        // leak across test runs.
```

with:

```rust
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
```

Fix `write_then_check_then_clear_round_trips`'s call site:

```rust
        write_iptable_rule(100, 101, 0, /*waf_enable=*/true);
```

with:

```rust
        write_iptable_rule(100, 101, 0);
```

Replace `write_with_waf_disabled_adds_save_mark_rules` in full (renamed — there's no longer a `waf_enable` concept to be "disabled"; it now documents the unconditional behavior):

```rust
    // Production's actual default: DaemonContext::waf_enable_ defaults to
    // false, and GrpcDispatchPodUp passes daemon->WafEnabled() straight
    // through to write_iptable_rule. Before this test, every existing test
    // called write_iptable_rule with waf_enable=true, leaving the
    // `if !waf_enable { ... "-A INPUT/POSTROUTING -j CONNMARK --save-mark" }`
    // branches -- the ones production actually exercises by default --
    // completely uncovered.
    #[test]
    fn write_with_waf_disabled_adds_save_mark_rules() {
        let _guard = IPTABLES_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup_test_chains();

        write_iptable_rule(100, 101, 0, /*waf_enable=*/false);

        let input = Command::new("iptables").args(["-t", "mangle", "-S", "INPUT"]).output().unwrap();
        let postrouting =
            Command::new("iptables").args(["-t", "mangle", "-S", "POSTROUTING"]).output().unwrap();
        assert!(
            String::from_utf8_lossy(&input.stdout).contains("CONNMARK --save-mark"),
            "expected -A INPUT -j CONNMARK --save-mark when waf_enable=false"
        );
        assert!(
            String::from_utf8_lossy(&postrouting.stdout).contains("CONNMARK --save-mark"),
            "expected -A POSTROUTING -j CONNMARK --save-mark when waf_enable=false"
        );

        clear_iptables_rule(0);
        cleanup_test_chains();
    }
```

with:

```rust
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
```

- [ ] **Step 11: Fix the call site in `tests/net_iptables_ffi_test.cc`**

Replace:

```cpp
  net_iptables::write_iptable_rule(100, 101, 0, /*waf_enable=*/true);
```

with:

```cpp
  net_iptables::write_iptable_rule(100, 101, 0);
```

- [ ] **Step 12: Build and run the full test suite**

```bash
cd build && make -j2 && cd ..
./build/net_rule_test
./build/net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*'
cargo build --workspace
```

Expected: full build succeeds (including `waf/plugin.cc`/`waf/rule.cc`, which are unaffected by this task and still compile — they're only deleted in Task 5), both gtest binaries report 0 failures. If running in a privileged container (`CAP_NET_ADMIN`), also run:

```bash
cargo test -p net_iptables
```

Expected: `check_iptables_rule_false_when_absent`, `write_then_check_then_clear_round_trips`, `get_iptables_version_returns_zero_or_one`, and `write_always_adds_save_mark_rules_to_input_and_postrouting` all PASS.

- [ ] **Step 13: Commit**

```bash
git add net-policy.h net-policy.cpp log.h crates/net_iptables/src/lib.rs tests/net_iptables_ffi_test.cc Cargo.lock
git commit -m "Remove DaemonContext's WAF wiring and the iptables waf_enable coupling

DaemonContext no longer has waf_root_/WafRoot()/WafEnabled()/SetWafEnabled().
RunNetPolicyDaemon no longer registers the WAF filter or reads
POLICY_WAF_ENABLE. net_iptables::write_iptable_rule drops its waf_enable
parameter -- the CONNMARK --save-mark rules it used to install only when WAF
was off now install unconditionally, matching every deployment's existing
default behavior exactly."
```

---

### Task 5: Delete the WAF feature's remaining files and build wiring

**Files:**
- Delete: `waf/plugin.h`, `waf/plugin.cc`, `waf/rule.h`, `waf/rule.cc`
- Delete: `crates/waf_rules_core/` (entire directory)
- Delete: `tests/waf_rules_test.cc`
- Modify: `Cargo.toml`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: nothing new.
- Produces: no `waf/` directory, no `waf_rules_core` crate, no `waf_rules_core_cxxbridge` CMake target, no `libpcre2-8.a`/`libpcre2-posix.a` link lines anywhere. This is the last task that touches WAF-specific source — after this task, `grep -ri waf` across the tracked source tree returns nothing except historical references in `docs/superpowers/specs/` and the `CLAUDE.md`/master-roadmap edits Task 6 makes.

Depends on Task 4 (which removed `net-policy.h`'s `#include "waf/plugin.h"` and `RunNetPolicyDaemon`'s use of the `PluginContext` type — without that, deleting `waf/plugin.h` here would break the build) and Task 3 (which removed `tests/grpc_rust_events_e2e_test.cc`'s `#include "waf/plugin.h"` and its `Rules`/`AttackedLog`/`PublishWafAttackToRustEventService` usages).

- [ ] **Step 1: Delete the WAF source files**

```bash
git rm waf/plugin.h waf/plugin.cc waf/rule.h waf/rule.cc
git rm -r crates/waf_rules_core
git rm tests/waf_rules_test.cc
```

- [ ] **Step 2: Remove `waf_rules_core` from `Cargo.toml`'s workspace members**

Replace:

```toml
members = ["crates/ffi_smoke", "crates/waf_rules_core", "crates/net_policy_control", "crates/net_policy_events", "crates/net_flow_engine", "crates/net_policy_engine", "crates/net_iptables", "crates/net_nfq", "crates/net_conntrack"]
```

with:

```toml
members = ["crates/ffi_smoke", "crates/net_policy_control", "crates/net_policy_events", "crates/net_flow_engine", "crates/net_policy_engine", "crates/net_iptables", "crates/net_nfq", "crates/net_conntrack"]
```

- [ ] **Step 3: Remove the `waf_rules_core_cxxbridge` CMake target**

Delete:

```cmake
corrosion_add_cxxbridge(waf_rules_core_cxxbridge
  CRATE waf_rules_core
  FILES lib.rs
)

```

- [ ] **Step 4: Remove `waf/plugin.cc`/`waf/rule.cc` from `net-rule`'s `SOURCES`**

Replace:

```cmake
set(SOURCES
    net/utility.cc
    http/header.cc
    http/http_filter_factory.cc
    http/codec.cc
    http/packet.cc
    http/filter.cc
    http/http1/http_parser.c
    http/http1/codec.cc
    http/http2/codec.cc
    http/url.cc
    http/http_inspector.cc
    http/connection.cc
    cjson.c
    http/extension/log.cc
    admin/profile.cc
    main.cpp
    net-policy.cpp
    rule-detail.cpp
    waf/plugin.cc
    waf/rule.cc
    grpc/control_dispatch.cc
)
```

with:

```cmake
set(SOURCES
    net/utility.cc
    http/header.cc
    http/http_filter_factory.cc
    http/codec.cc
    http/packet.cc
    http/filter.cc
    http/http1/http_parser.c
    http/http1/codec.cc
    http/http2/codec.cc
    http/url.cc
    http/http_inspector.cc
    http/connection.cc
    cjson.c
    http/extension/log.cc
    admin/profile.cc
    main.cpp
    net-policy.cpp
    rule-detail.cpp
    grpc/control_dispatch.cc
)
```

- [ ] **Step 5: Remove `libpcre2-8.a`/`libpcre2-posix.a`/`waf_rules_core_cxxbridge` from `net-rule`'s `target_link_libraries`**

Replace:

```cmake
target_link_libraries(net-rule
  libnfnetlink
  libnetfilter_queue
  # net_conntrack (Rust) calls libnetfilter_conntrack's C API directly, and
  # corrosion emits libnet_conntrack.a at the very end of the link line, after
  # every entry this list can place. Plain archive semantics -- an archive only
  # satisfies references the linker has already seen to its left -- would
  # therefore leave those nfct_* references undefined. --whole-archive pulls the
  # archive's members in unconditionally, which is order-independent. Before
  # Phase 6c every nfct_* reference came from net-policy.cpp.o, ahead of all
  # archives, so plain ordering happened to be enough.
  -Wl,--whole-archive
  libnetfilter_conntrack
  -Wl,--no-whole-archive
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
  net_flow_engine_cxxbridge
  net_policy_engine_cxxbridge
  net_iptables_cxxbridge
  net_nfq_cxxbridge
  net_conntrack_cxxbridge
)
```

with:

```cmake
target_link_libraries(net-rule
  libnfnetlink
  libnetfilter_queue
  # net_conntrack (Rust) calls libnetfilter_conntrack's C API directly, and
  # corrosion emits libnet_conntrack.a at the very end of the link line, after
  # every entry this list can place. Plain archive semantics -- an archive only
  # satisfies references the linker has already seen to its left -- would
  # therefore leave those nfct_* references undefined. --whole-archive pulls the
  # archive's members in unconditionally, which is order-independent. Before
  # Phase 6c every nfct_* reference came from net-policy.cpp.o, ahead of all
  # archives, so plain ordering happened to be enough.
  -Wl,--whole-archive
  libnetfilter_conntrack
  -Wl,--no-whole-archive
  libnghttp2.a
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
  net_policy_control_cxxbridge
  net_policy_events_cxxbridge
  net_flow_engine_cxxbridge
  net_policy_engine_cxxbridge
  net_iptables_cxxbridge
  net_nfq_cxxbridge
  net_conntrack_cxxbridge
)
```

- [ ] **Step 6: Update the `--allow-multiple-definition` comment after `net-rule`'s link-flags line**

Replace:

```cmake
# waf_rules_core_cxxbridge, net_policy_control_cxxbridge, net_policy_events_cxxbridge,
# net_flow_engine_cxxbridge, net_policy_engine_cxxbridge, net_iptables_cxxbridge, net_nfq_cxxbridge,
# and net_conntrack_cxxbridge are separate Rust staticlib crates that all depend on the `cxx` crate; since each
```

with:

```cmake
# net_policy_control_cxxbridge, net_policy_events_cxxbridge, net_flow_engine_cxxbridge,
# net_policy_engine_cxxbridge, net_iptables_cxxbridge, net_nfq_cxxbridge, and
# net_conntrack_cxxbridge are separate Rust staticlib crates that all depend on the `cxx` crate; since each
```

(Leave the rest of that comment paragraph, and `set_target_properties(net-rule PROPERTIES LINK_FLAGS ...)` itself, unchanged.)

- [ ] **Step 7: Remove `libpcre2-8.a`/`libpcre2-posix.a` from `net_rule_test`'s `target_link_libraries`**

Replace:

```cmake
target_link_libraries(net_rule_test 
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
ffi_smoke_cxxbridge
GTest::gtest_main)
```

with:

```cmake
target_link_libraries(net_rule_test 
libnfnetlink 
libnetfilter_queue 
libnetfilter_conntrack 
libnghttp2.a 
fmt::fmt-header-only
llhttp::llhttp_static 
glog.a 
gflags.a 
${CMAKE_THREAD_LIBS_INIT}
libunwind.a
liblzma.a
libz.a
ffi_smoke_cxxbridge
GTest::gtest_main)
```

- [ ] **Step 8: Remove `waf/plugin.cc`/`waf/rule.cc`/`tests/waf_rules_test.cc` from `net_rule_grpc_test`'s `SOURCES`**

Replace:

```cmake
add_executable(net_rule_grpc_test
    net/utility.cc
    cjson.c
    http/header.cc
    http/codec.cc
    http/packet.cc
    http/http_filter_factory.cc
    http/filter.cc
    http/http1/http_parser.c
    http/http1/codec.cc
    http/http2/codec.cc
    http/url.cc
    http/http_inspector.cc
    http/connection.cc
    http/extension/log.cc
    admin/profile.cc
    net-policy.cpp
    rule-detail.cpp
    waf/plugin.cc
    waf/rule.cc
    grpc/control_dispatch.cc
    ${NET_POLICY_PROTO_GENERATED_SRCS}
    ${NET_POLICY_EVENTS_PROTO_GENERATED_SRCS}
    tests/grpc_rust_control_e2e_test.cc
    tests/grpc_rust_events_e2e_test.cc
    tests/waf_rules_test.cc
    tests/net_flow_engine_ffi_test.cc
    tests/net_policy_engine_ffi_test.cc
    tests/net_iptables_ffi_test.cc
    tests/net_nfq_ffi_test.cc
    tests/net_conntrack_ffi_test.cc
)
```

with:

```cmake
add_executable(net_rule_grpc_test
    net/utility.cc
    cjson.c
    http/header.cc
    http/codec.cc
    http/packet.cc
    http/http_filter_factory.cc
    http/filter.cc
    http/http1/http_parser.c
    http/http1/codec.cc
    http/http2/codec.cc
    http/url.cc
    http/http_inspector.cc
    http/connection.cc
    http/extension/log.cc
    admin/profile.cc
    net-policy.cpp
    rule-detail.cpp
    grpc/control_dispatch.cc
    ${NET_POLICY_PROTO_GENERATED_SRCS}
    ${NET_POLICY_EVENTS_PROTO_GENERATED_SRCS}
    tests/grpc_rust_control_e2e_test.cc
    tests/grpc_rust_events_e2e_test.cc
    tests/net_flow_engine_ffi_test.cc
    tests/net_policy_engine_ffi_test.cc
    tests/net_iptables_ffi_test.cc
    tests/net_nfq_ffi_test.cc
    tests/net_conntrack_ffi_test.cc
)
```

- [ ] **Step 9: Remove `libpcre2-8.a`/`libpcre2-posix.a`/`waf_rules_core_cxxbridge` from `net_rule_grpc_test`'s `target_link_libraries`**

Replace:

```cmake
target_link_libraries(net_rule_grpc_test
  libnfnetlink
  libnetfilter_queue
  # net_conntrack (Rust) calls libnetfilter_conntrack's C API directly, and
  # corrosion emits libnet_conntrack.a at the very end of the link line, after
  # every entry this list can place. Plain archive semantics -- an archive only
  # satisfies references the linker has already seen to its left -- would
  # therefore leave those nfct_* references undefined. --whole-archive pulls the
  # archive's members in unconditionally, which is order-independent. Before
  # Phase 6c every nfct_* reference came from net-policy.cpp.o, ahead of all
  # archives, so plain ordering happened to be enough.
  -Wl,--whole-archive
  libnetfilter_conntrack
  -Wl,--no-whole-archive
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
  net_flow_engine_cxxbridge
  net_policy_engine_cxxbridge
  net_iptables_cxxbridge
  net_nfq_cxxbridge
  net_conntrack_cxxbridge
  GTest::gtest_main)
# See the matching comment on net-rule's LINK_FLAGS above (applies to waf_rules_core_cxxbridge,
# net_policy_control_cxxbridge, net_policy_events_cxxbridge, net_flow_engine_cxxbridge,
# net_policy_engine_cxxbridge, net_iptables_cxxbridge, net_nfq_cxxbridge, and net_conntrack_cxxbridge).
```

with:

```cmake
target_link_libraries(net_rule_grpc_test
  libnfnetlink
  libnetfilter_queue
  # net_conntrack (Rust) calls libnetfilter_conntrack's C API directly, and
  # corrosion emits libnet_conntrack.a at the very end of the link line, after
  # every entry this list can place. Plain archive semantics -- an archive only
  # satisfies references the linker has already seen to its left -- would
  # therefore leave those nfct_* references undefined. --whole-archive pulls the
  # archive's members in unconditionally, which is order-independent. Before
  # Phase 6c every nfct_* reference came from net-policy.cpp.o, ahead of all
  # archives, so plain ordering happened to be enough.
  -Wl,--whole-archive
  libnetfilter_conntrack
  -Wl,--no-whole-archive
  libnghttp2.a
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
  net_policy_control_cxxbridge
  net_policy_events_cxxbridge
  net_flow_engine_cxxbridge
  net_policy_engine_cxxbridge
  net_iptables_cxxbridge
  net_nfq_cxxbridge
  net_conntrack_cxxbridge
  GTest::gtest_main)
# See the matching comment on net-rule's LINK_FLAGS above (applies to
# net_policy_control_cxxbridge, net_policy_events_cxxbridge, net_flow_engine_cxxbridge,
# net_policy_engine_cxxbridge, net_iptables_cxxbridge, net_nfq_cxxbridge, and net_conntrack_cxxbridge).
```

- [ ] **Step 10: Regenerate `Cargo.lock`, do a clean build, and run the full test suite**

```bash
cargo check --workspace
rm -rf build && mkdir build && cd build && cmake .. && make -j2 && cd ..
./build/net_rule_test
./build/net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*'
```

A clean rebuild (not incremental) here specifically catches stale references to the deleted `waf_rules_core_cxxbridge` CMake target that an incremental build's cache could otherwise mask. Expected: build succeeds, both binaries report 0 failures. `net_rule_grpc_test`'s test count has dropped by exactly 16 relative to Task 3's end state (`tests/waf_rules_test.cc`'s 16 `TEST`s, now gone with the file).

- [ ] **Step 11: Confirm no WAF references remain in tracked source**

```bash
grep -rli waf --include="*.cc" --include="*.cpp" --include="*.h" --include="*.hh" \
  --include="*.rs" --include="*.proto" --include="CMakeLists.txt" --include="Cargo.toml" . \
  | grep -v '^\./docs/superpowers/'
```

Expected: no output. (Historical mentions inside `docs/superpowers/specs/` and `docs/superpowers/plans/` are expected and excluded — those are point-in-time design records, not live code.)

- [ ] **Step 12: Commit**

The `waf/`, `crates/waf_rules_core/`, and `tests/waf_rules_test.cc` deletions are already staged from Step 1's `git rm`. Stage the remaining edits and commit:

```bash
git add Cargo.toml Cargo.lock CMakeLists.txt
git commit -m "Delete the WAF feature's remaining files and build wiring

Removes waf/plugin.{h,cc}, waf/rule.{h,cc}, the crates/waf_rules_core Rust
crate, tests/waf_rules_test.cc, and every CMakeLists.txt/Cargo.toml
reference to them -- including the now-fully-vestigial libpcre2-8.a/
libpcre2-posix.a link lines, whose only real caller (waf/rule.cc's
Pcre2Regex) was already Rust-backed. No WAF feature exists anywhere in the
codebase after this commit."
```

---

### Task 6: Update documentation

**Files:**
- Modify: `CLAUDE.md`
- Modify: `docs/superpowers/specs/2026-07-29-cpp-to-rust-migration-design.md`

**Interfaces:**
- Consumes: nothing new.
- Produces: no documentation change to code behavior — pure doc accuracy.

Independent of every other task's code; sequenced last only so it can describe the truly-final state, but could run any time after Task 5.

- [ ] **Step 1: Remove `pcre2` from `CLAUDE.md`'s build-deps line**

Replace:

```markdown
The build uses C++17, enforces `-Wall -Werror`, and links against llhttp, nghttp2, pcre2, glog, gflags, gperftools, and libunwind. Netlink submodules (libmnl, libnetfilter_queue, libnetfilter_conntrack, libnfnetlink) are vendored under the repo root.
```

with:

```markdown
The build uses C++17, enforces `-Wall -Werror`, and links against llhttp, nghttp2, glog, gflags, gperftools, and libunwind. Netlink submodules (libmnl, libnetfilter_queue, libnetfilter_conntrack, libnfnetlink) are vendored under the repo root.
```

- [ ] **Step 2: Update the architecture overview sentence**

Replace:

```markdown
This is a **kernel-integrated network policy enforcement daemon** for containerized workloads (Kubernetes-style pods). It intercepts packets via Linux Netfilter (NFQ), applies Layer 3-4 policy rules, and performs Layer 7 HTTP inspection and WAF filtering.
```

with:

```markdown
This is a **kernel-integrated network policy enforcement daemon** for containerized workloads (Kubernetes-style pods). It intercepts packets via Linux Netfilter (NFQ), applies Layer 3-4 policy rules, and performs Layer 7 HTTP inspection for microsegmentation policy.
```

- [ ] **Step 3: Update the data-flow diagram**

Replace:

```
    └──── HTTP Inspection (Layer 7) ──── WAF rule evaluation ─── NF_ACCEPT / NF_DROP
```

with:

```
    └──── HTTP Inspection (Layer 7) ──── microsegmentation policy match ─── NF_ACCEPT / NF_DROP
```

- [ ] **Step 4: Remove the WAF System row from the components table**

Delete this row entirely:

```markdown
| **WAF System** | `waf/plugin.{h,cc}`, `waf/rule.{h,cc}` | PCRE2 regex pattern matching; `PluginRootContext` owns global rules, `PluginContext` is per-connection |
```

- [ ] **Step 5: Remove `AddWafRule`/`DeleteWafRule` from the gRPC RPC surface list**

Replace:

```markdown
- **`NetPolicyControl`** (port 50051, served by the Rust `net_policy_control`
  crate, dispatched into C++ via `grpc/control_dispatch.h`): `PodUp` / `PodDown`
  — pod lifecycle events; `AddPolicyRule` / `DeletePolicyRule` — network policy
  CRUD; `AddWafRule` / `DeleteWafRule` — WAF rule CRUD; `DumpHeapProfile` /
  `DumpConfig` / `DumpConnections` — debugging; `ResetConfig` /
  `UpdateNodeConfig` / `SetLogLevel` — runtime config.
```

with:

```markdown
- **`NetPolicyControl`** (port 50051, served by the Rust `net_policy_control`
  crate, dispatched into C++ via `grpc/control_dispatch.h`): `PodUp` / `PodDown`
  — pod lifecycle events; `AddPolicyRule` / `DeletePolicyRule` — network policy
  CRUD; `DumpHeapProfile` / `DumpConfig` / `DumpConnections` — debugging;
  `ResetConfig` / `UpdateNodeConfig` / `SetLogLevel` — runtime config.
```

- [ ] **Step 6: Add a correction note to the master roadmap doc**

In `docs/superpowers/specs/2026-07-29-cpp-to-rust-migration-design.md`, insert the following immediately after the Phase Breakdown table's last row (`| **7. Decommission** | ... | Rust-only build going forward. |`) and before the blank line that precedes `## Validation Strategy (per phase)`:

```markdown

> **Update (2026-08-06):** Phase 1 above ("WAF rule/regex engine") and the
> WAF-adjacent portions of Phase 2 and Phase 7 did not happen as written.
> Instead, the entire WAF feature (`waf/plugin.{h,cc}`, `waf/rule.{h,cc}`,
> the `waf_rules_core` Rust crate, the `AddWafRule`/`DeleteWafRule`/
> `WafAttackEvent` control-plane surface, and the `POLICY_WAF_ENABLE`
> runtime toggle) was deleted outright rather than migrated to Rust — a
> deliberate scope decision made independently of this roadmap. See
> `docs/superpowers/specs/2026-08-06-waf-removal-design.md` for the full
> rationale. No other phase in this roadmap depended on WAF's Rust target,
> so this does not affect the rest of the plan.
```

- [ ] **Step 7: Commit**

```bash
git add CLAUDE.md docs/superpowers/specs/2026-07-29-cpp-to-rust-migration-design.md
git commit -m "Update documentation for WAF removal

CLAUDE.md's architecture overview, data-flow diagram, component table, gRPC
RPC list, and build-deps line no longer mention WAF/pcre2. The master
roadmap doc gets a correction note recording that WAF was removed rather
than migrated, so its stated end-state stays accurate."
```

---

### Task 7: Full-repo verification build and test run

**Files:** none (verification only).

**Interfaces:**
- Consumes: the complete, merged state of Tasks 1-6.
- Produces: a confirmed-green branch ready for the final whole-branch review.

- [ ] **Step 1: Clean rebuild**

```bash
rm -rf build && mkdir build && cd build && cmake .. && make -j2 && cd ..
cargo check --workspace
```

Expected: both succeed with no errors or warnings-as-errors.

- [ ] **Step 2: Run `net_rule_test` three times**

```bash
for i in 1 2 3; do ./build/net_rule_test || echo "RUN $i FAILED"; done
```

Expected: all three runs report 0 failures, same test count as `main` before this branch (this binary's `SOURCES`/tests were never touched by this plan — only its `target_link_libraries` changed in Task 5).

- [ ] **Step 3: Run `net_rule_grpc_test` three times with the routine filter**

```bash
for i in 1 2 3; do
  ./build/net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*' \
    || echo "RUN $i FAILED"
done
```

Expected: all three runs report 0 failures. Total test count is exactly 21 fewer than on `main` before this branch: 16 from `tests/waf_rules_test.cc` (deleted wholesale), 2 from `tests/grpc_rust_control_e2e_test.cc` (`DeleteWafRuleForUnknownPodReturnsZeroStatus`, `AddWafRuleWithMinimalFieldsReturnsOkStatus`), 3 from `tests/grpc_rust_events_e2e_test.cc` (`SubscribeEventsReceivesPublishedWafAttack`, `PublishWafAttackToRustEventServiceSendsEvent`, `PublishWafAttackToRustEventServiceSkipsInvalidUtf8`) — `tests/net_flow_engine_ffi_test.cc`'s count is unchanged (Task 1 removed 2, added 2). Confirm with:

```bash
./build/net_rule_grpc_test --gtest_list_tests | grep -ic waf
```

Expected: `0`.

- [ ] **Step 4: If running in a privileged container (`CAP_NET_ADMIN`), run the privileged suites too**

```bash
./build/net_rule_grpc_test --gtest_filter='NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*'
cargo test -p net_iptables
cargo test -p net_nfq
cargo test -p net_conntrack
```

Expected: all pass. (Skip this step entirely, and note it as skipped, if the environment lacks `CAP_NET_ADMIN` — matching this project's established practice for these suites.)

- [ ] **Step 5: Confirm the Final State from the design spec**

```bash
grep -rli waf --include="*.cc" --include="*.cpp" --include="*.h" --include="*.hh" \
  --include="*.rs" --include="*.proto" --include="CMakeLists.txt" --include="Cargo.toml" . \
  | grep -v '^\./docs/superpowers/'
git status
```

Expected: the `grep` produces no output; `git status` shows a clean tree with all six prior tasks' commits present.

- [ ] **Step 6: Report**

No commit for this task (verification only). Report the three run counts (Steps 2-3), whether Step 4 ran or was skipped and why, and the confirmation from Step 5, then proceed to the final whole-branch review per `superpowers:subagent-driven-development`.
