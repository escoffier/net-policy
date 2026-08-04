# Phase 6b-1: Unified Packet Parsing and Connection Decision Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `net_flow_engine`/`net::ConnectionManager` the single, canonical packet-parsing and TCB-decision service for the whole daemon — extending `net_flow_engine` to parse five-tuples for TCP/UDP/ICMP (not just TCP), and redesigning `ConnectionManager::receive` to return that decision to its caller instead of driving WAF dispatch internally — eliminating the double-parse where `parse_package` (L3-L4 policy matching) and `net_flow_engine` (WAF's TCB tracking) independently parse the same packet bytes.

**Architecture:** `net_flow_engine` gains a new, stateless five-tuple-parsing entry point (`parse_five_tuple`) alongside its existing stateful TCP-only `on_packet` (TCB tracking, unchanged). `net::ConnectionManager::receive` changes from `NetStatus receive(pkg, len)` (drives WAF dispatch internally) to `ReceiveResult receive(pkg, len)` (returns the parsed five-tuple + TCB decision; WAF dispatch becomes a separate, caller-invoked `DispatchWaf` method using the same logic, unchanged, just relocated). `input_nfq_cb`/`output_nfq_cb` call `ConnMgr().receive` once, unconditionally, replacing `parse_package` entirely, and invoke `DispatchWaf` only when `WafEnabled() && is_tcp` — exactly the gating condition already in place today.

**Tech Stack:** Rust (`cxx` crate for FFI, same `net_flow_engine` crate from Phase 5), C++17, Google Test.

**Reference spec:** `docs/superpowers/specs/2026-08-04-cpp-to-rust-phase6b1-unified-packet-decision-design.md`

## Global Constraints

- `MicroSegEngine::TcpCtInput()`/`TcpCtOutput()`, `parse_package`'s TCP-specific reassembly logic in `input_nfq_cb`/`output_nfq_cb` (the code AFTER the L3-L4 policy-match block that does its own SYN/FIN/RST tracking via `TcpCtInput`/`TcpCtOutput` for microsegmentation's HTTP-rule matching), `MatchHttpPolicyRule`, `InputHttpPolicy()`/`OutputHttpPolicy()` are OUT OF SCOPE — Phase 6b-2's territory. This phase only changes where the `FiveTuple` fed into `MatchNetPolicyRule`/`MatchMicroPolicyRule` comes from (replacing `parse_package`'s output), not microsegmentation's own separate TCP tracking.
- `NFQ_RES_INFO`, `InitNfqueue`, `OpenNfque`, `AddEpollEvent`, `NfqueueRcvData`, `OpenConntrack`, `UpdateNetSession`, `SetAcceptMark`, `SetNs`/`OpenLocalNetNs`/`SetLocalNetNs` are OUT OF SCOPE — Phase 6b-3/6c territory. This phase's edits to `input_nfq_cb`/`output_nfq_cb` touch ONLY the five-tuple-acquisition and WAF-dispatch block near the top of each function (replacing `parse_package` + the `WafEnabled()`-gated `ConnMgr().receive()` call) — read the current function bodies yourself before editing; do not touch anything else in them.
- `PostServer::SendMatchMsg`, the conntrack-mark fast-path, and the policy-match verdict logic itself (`MatchMicroPolicyRule`'s reverse-match, `MatchNetPolicyRule`) are OUT OF SCOPE — unchanged business logic, just now fed a `FiveTuple` from a different source.
- `net_flow_engine`'s existing `on_packet`/`FlowEngine` (TCP TCB tracking, from Phase 5) is UNCHANGED by this phase — the new five-tuple parsing is a separate, additional, stateless entry point (`&self`, not `&mut self`; no TCB side effects), not a modification to `on_packet`'s existing behavior. Every existing Phase 5 test must continue to pass unmodified.
- The pre-existing quirk in `parse_package`'s caller (`net-policy.cpp:638-639`/`822-823`: `nfq_set_verdict` is called on parse failure with no `return`, so execution falls through using a partially-unset `tuple`) must be explicitly addressed in Task 4, not silently carried forward or silently fixed — read the exact current control flow, decide replicate-bug-for-bug vs. fix-now, and document the decision in the commit message, per this project's established practice (see the design spec's own note on this, and prior phases' handling of similar quirks — e.g. Phase 4's CIDR `mask == 0` case, Phase 5's IPv4-header-length bounds check).
- `tuple.tot_len_` (the IP total-length field) has no real behavioral consumer today beyond a pass-through copy in `FiveTuple::ReverseTuple` and dead/commented-out debug-log lines (confirmed via full-repo grep before this plan was written) — but is trivial to preserve for exact fidelity with `parse_package`'s current output, so Task 1 exposes it rather than dropping it.
- Never `git worktree` inside the `net-policy-build-test` Docker container (bind-mounts the same host repo; has wiped the host's worktree registry before in this project's history) — build directly against the bind-mounted worktree path (verify the container's mount source with `docker inspect <container> --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}'` first).
- Verify every code snippet, line number, and file structure in this plan against the actual current source before editing — this plan was written against a specific commit; line numbers may have drifted, and every prior phase in this migration has found real drift between a plan's assumptions and current source at implementation time.

---

### Task 1: Extend `net_flow_engine` with a stateless five-tuple parser for TCP/UDP/ICMP

**Files:**
- Modify: `crates/net_flow_engine/src/lib.rs` (add `parse_udp_header`, extend the crate with a new `FiveTupleResult`-shaped internal type and a `parse_five_tuple_internal` function; do not modify `on_packet_internal`, `parse_tcp_header`, or any existing TCB-tracking code)

**Interfaces:**
- Consumes: `parse_ipv4_header` (Phase 5, unchanged — already extracts `header_len`/`protocol`/`saddr`/`daddr`; this task additionally needs the IP header's `tot_len` field, which `parse_ipv4_header` does not currently expose — extend `Ipv4Header` with a `tot_len: u16` field, extracted from bytes 2-3 of the IP header, big-endian, mirroring the C++ `ntohs(iph->tot_len)`).
- Produces: `FiveTupleResult { proto: u8, tot_len: u16, ip_header_len: u32, src_port: u16, dst_port: u16, src_addr: u32, dst_addr: u32, recognized: bool }`, `fn parse_five_tuple_internal(bytes: &[u8]) -> FiveTupleResult` — consumed by Task 2's FFI wrapper.

**Note on `ip_header_len`:** confirmed by reading the live `input_nfq_cb`/`output_nfq_cb` (net-policy.cpp) before writing this plan: the downstream microseg TCP-tracking block (OUT OF SCOPE for this phase, see Global Constraints) depends on two locals that `parse_package` currently populates as side effects — `int offset` (`data_len <= offset` guards, `value = pkg + offset`, several log lines) and `struct tcphdr tcphdr` (`.syn`/`.fin`/`.rst`/`.seq` read directly, e.g. `if (tcphdr.syn != 0)`, `ntohl(tcphdr.seq)`). Neither is dead code — both are load-bearing for every TCP packet, SYN through data through FIN. Since this phase's new parse replaces `parse_package` (Task 4), it must still leave the caller able to reconstruct `offset`/`tcphdr` for the code Task 4 is NOT allowed to touch. `ip_header_len` is the one extra fact needed to do that cheaply in C++ (see Task 4 Step 3) — TCP/UDP header lengths and flags are then trivial, protocol-aware, wire-format-only computations the caller already knows how to do (they're copies of what `parse_package` did), so this plan deliberately does NOT also push `offset`/tcphdr-equivalent fields through the Rust FFI boundary — that would expand this phase's Rust surface into territory (TCP flag semantics for microseg's own tracking) explicitly deferred to Phase 6b-2, which will likely delete this sliver entirely by reusing `PacketDecision`'s existing `ip_header_len`/`payload_offset` fields once it migrates the TCP-tracking block itself onto the unified decision.

Read `net/utility.cc`'s deleted `Udp::receive`/`net/udp.cc` history if useful context (Phase 5 confirmed `net::Udp` dead and deleted it), and `net-policy.cpp`'s `parse_package` (search for it — the reference implementation this task's Rust code must match field-for-field) yourself before implementing — this task is a faithful, additive port of `parse_package`'s UDP/ICMP branches (its TCP branch is intentionally NOT replicated here; TCP five-tuple extraction already exists via `parse_tcp_header`, consumed differently by `on_packet_internal`).

- [ ] **Step 1: Write the failing tests**

Add to `crates/net_flow_engine/src/lib.rs`:
```rust
#[cfg(test)]
mod five_tuple_tests {
    use super::*;

    fn ipv4_header_with_tot_len(protocol: u8, saddr: [u8; 4], daddr: [u8; 4], tot_len: u16) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0] = (4 << 4) | 5;
        b[2..4].copy_from_slice(&tot_len.to_be_bytes());
        b[9] = protocol;
        b[12..16].copy_from_slice(&saddr);
        b[16..20].copy_from_slice(&daddr);
        b
    }

    fn udp_header(source: u16, dest: u16, length: u16) -> Vec<u8> {
        let mut b = vec![0u8; 8];
        b[0..2].copy_from_slice(&source.to_be_bytes());
        b[2..4].copy_from_slice(&dest.to_be_bytes());
        b[4..6].copy_from_slice(&length.to_be_bytes());
        // bytes 6..8 (checksum) left zero -- unused by parsing
        b
    }

    #[test]
    fn parses_udp_five_tuple() {
        let ip = ipv4_header_with_tot_len(17 /* UDP */, [10, 0, 0, 1], [10, 0, 0, 2], 28);
        let udp = udp_header(1234, 80, 8);
        let mut packet = ip;
        packet.extend_from_slice(&udp);

        let result = parse_five_tuple_internal(&packet);
        assert!(result.recognized);
        assert_eq!(result.proto, 17);
        assert_eq!(result.tot_len, 28);
        assert_eq!(result.ip_header_len, 20);
        assert_eq!(result.src_port, 1234);
        assert_eq!(result.dst_port, 80);
        assert_eq!(ipv4_to_string(result.src_addr), "10.0.0.1");
        assert_eq!(ipv4_to_string(result.dst_addr), "10.0.0.2");
    }

    #[test]
    fn parses_icmp_five_tuple_with_zero_ports() {
        // ICMP has no ports -- parse_package's precedent sets both to 0,
        // not derived from any header field. No ICMP-specific body bytes
        // needed; only the IP header's protocol field matters.
        let ip = ipv4_header_with_tot_len(1 /* ICMP */, [10, 0, 0, 1], [10, 0, 0, 2], 20);

        let result = parse_five_tuple_internal(&ip);
        assert!(result.recognized);
        assert_eq!(result.proto, 1);
        assert_eq!(result.src_port, 0);
        assert_eq!(result.dst_port, 0);
    }

    #[test]
    fn parses_tcp_five_tuple_too() {
        // Task 4's caller needs a five-tuple for TCP as well as UDP/ICMP
        // (policy matching runs for every protocol) -- this function must
        // handle TCP even though on_packet_internal's separate TCB-tracking
        // path also parses TCP headers for a different purpose.
        let ip = ipv4_header_with_tot_len(6 /* TCP */, [10, 0, 0, 1], [10, 0, 0, 2], 40);
        let mut packet = ip;
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[12] = 5 << 4;
        packet.extend_from_slice(&tcp);

        let result = parse_five_tuple_internal(&packet);
        assert!(result.recognized);
        assert_eq!(result.proto, 6);
        assert_eq!(result.src_port, 1234);
        assert_eq!(result.dst_port, 80);
    }

    #[test]
    fn unrecognized_protocol_is_not_recognized() {
        let ip = ipv4_header_with_tot_len(47 /* GRE, arbitrary unhandled proto */, [10, 0, 0, 1], [10, 0, 0, 2], 20);
        let result = parse_five_tuple_internal(&ip);
        assert!(!result.recognized);
    }

    #[test]
    fn truncated_buffer_is_not_recognized() {
        let result = parse_five_tuple_internal(&[0u8; 5]);
        assert!(!result.recognized);
    }
}
```

- [ ] **Step 2: Run to verify the tests fail**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/crates/net_flow_engine && cargo test five_tuple 2>&1 | tail -60"
```
Expected: compile error, `parse_five_tuple_internal`/`FiveTupleResult` not defined (and `Ipv4Header.tot_len` not found).

- [ ] **Step 3: Implement**

First, extend `Ipv4Header` (find its current declaration in `crates/net_flow_engine/src/lib.rs`) with the `tot_len` field, and `parse_ipv4_header` to populate it:
```rust
struct Ipv4Header {
    header_len: usize,
    protocol: u8,
    saddr: u32,
    daddr: u32,
    tot_len: u16,  // new -- IP total length, bytes 2-3, big-endian
}
```
In `parse_ipv4_header`'s body, add (matching the existing style — read the current function first, this is one additional line alongside the existing field extractions):
```rust
let tot_len = u16::from_be_bytes([bytes[2], bytes[3]]);
```
and add `tot_len` to the `Some(Ipv4Header { ... })` construction.

Then add the new five-tuple parser:
```rust
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const UDP_HDR_LEN: usize = 8;

struct FiveTupleResult {
    proto: u8,
    tot_len: u16,
    ip_header_len: u32,
    src_port: u16,
    dst_port: u16,
    src_addr: u32,
    dst_addr: u32,
    recognized: bool,
}

impl Default for FiveTupleResult {
    fn default() -> Self {
        FiveTupleResult { proto: 0, tot_len: 0, ip_header_len: 0, src_port: 0, dst_port: 0, src_addr: 0, dst_addr: 0, recognized: false }
    }
}

/// Mirrors parse_package (net-policy.cpp): extracts a five-tuple for any of
/// TCP, UDP, or ICMP. Unlike on_packet_internal (Phase 5, TCP-only, stateful
/// TCB tracking), this is a stateless, protocol-agnostic parse for L3-L4
/// policy matching -- no connection-tracking side effects, no `&mut self`.
fn parse_five_tuple_internal(bytes: &[u8]) -> FiveTupleResult {
    let Some(ip) = parse_ipv4_header(bytes) else {
        return FiveTupleResult::default();
    };
    let payload = &bytes[ip.header_len..];
    let (src_port, dst_port) = match ip.protocol {
        IPPROTO_TCP => {
            let Some(tcp) = parse_tcp_header(payload) else {
                return FiveTupleResult::default();
            };
            (tcp.source, tcp.dest)
        }
        IPPROTO_UDP => {
            if payload.len() < UDP_HDR_LEN {
                return FiveTupleResult::default();
            }
            let source = u16::from_be_bytes([payload[0], payload[1]]);
            let dest = u16::from_be_bytes([payload[2], payload[3]]);
            (source, dest)
        }
        IPPROTO_ICMP => (0, 0),
        _ => return FiveTupleResult::default(),
    };
    FiveTupleResult {
        proto: ip.protocol,
        tot_len: ip.tot_len,
        ip_header_len: ip.header_len as u32,
        src_port,
        dst_port,
        src_addr: ip.saddr,
        dst_addr: ip.daddr,
        recognized: true,
    }
}
```
Note: `parse_tcp_header`'s `TcpHeader` struct (Phase 5) already has public-enough-within-crate `source`/`dest` fields — confirm the exact field names against the current struct before using them; this plan's earlier phases named them `source`/`dest` (matching `net-policy.cpp`'s `tcph->source`/`tcph->dest` naming), verify this hasn't drifted.

- [ ] **Step 4: Run to verify the tests pass**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/crates/net_flow_engine && cargo test 2>&1 | tail -80"
```
Expected: all tests pass, including every pre-existing Phase 5 test (unaffected by this addition).

- [ ] **Step 5: Commit**

```bash
git add crates/net_flow_engine/src/lib.rs
git commit -m "Add stateless TCP/UDP/ICMP five-tuple parsing to net_flow_engine

Extends Ipv4Header with tot_len (needed for FiveTuple parity with the
C++ parse_package it replaces; otherwise unused today beyond a
pass-through copy in FiveTuple::ReverseTuple). New parse_five_tuple_internal
is intentionally stateless and separate from on_packet_internal's TCB
tracking -- policy matching needs a five-tuple for every protocol,
connection tracking only exists for TCP."
```

---

### Task 2: Wire `parse_five_tuple` into the cxx bridge and add an FFI smoke test

**Files:**
- Modify: `crates/net_flow_engine/src/lib.rs` (add `SharedFiveTuple` to the `#[cxx::bridge]` module, add the `parse_five_tuple` FFI-facing function)
- Modify: `tests/net_flow_engine_ffi_test.cc` (add smoke tests for the new entry point)

**Interfaces:**
- Consumes: `parse_five_tuple_internal`, `FiveTupleResult` (Task 1).
- Produces: `net_flow::SharedFiveTuple` (C++-visible shared struct), `net_flow::parse_five_tuple(pkg: *const u8, len: usize) -> SharedFiveTuple` — the seam Task 4 wires `input_nfq_cb`/`output_nfq_cb`'s replacement of `parse_package` up to (via `ConnectionManager`, per Task 3 — this task only builds the standalone FFI surface, Task 3 wires it into `ConnectionManager`'s new contract).

`SharedFiveTuple` carries `ip_header_len` (see Task 1's note on why) so Task 4's caller can reconstruct `offset`/`tcphdr` for the out-of-scope downstream block without a second parse pass.

- [ ] **Step 1: Add the shared struct and FFI function to the bridge module**

Find the current `#[cxx::bridge(namespace = "net_flow")]` module in `crates/net_flow_engine/src/lib.rs` (it already has `SharedConnectionId`, `PacketDecision`, and the `extern "Rust"` block with `new_flow_engine`/`on_packet`/`live_connection_count`/`connection_strings`). Add:
```rust
#[derive(Default)]
struct SharedFiveTuple {
    proto: u8,
    tot_len: u16,
    ip_header_len: u32,
    src_port: u16,
    dst_port: u16,
    src_addr: u32,
    dst_addr: u32,
    recognized: bool,
}
```
and, inside the existing `extern "Rust" { ... }` block, alongside the existing functions:
```rust
        unsafe fn parse_five_tuple(pkg: *const u8, len: usize) -> SharedFiveTuple;
```

- [ ] **Step 2: Implement the FFI-facing function**

```rust
/// # Safety
/// `pkg` must point to at least `len` readable bytes; the caller owns that
/// buffer for the duration of this call. Mirrors on_packet's existing
/// safety contract (Phase 5) -- same raw-pointer FFI precedent.
unsafe fn parse_five_tuple(pkg: *const u8, len: usize) -> ffi::SharedFiveTuple {
    let bytes = std::slice::from_raw_parts(pkg, len);
    let result = parse_five_tuple_internal(bytes);
    ffi::SharedFiveTuple {
        proto: result.proto,
        tot_len: result.tot_len,
        ip_header_len: result.ip_header_len,
        src_port: result.src_port,
        dst_port: result.dst_port,
        src_addr: result.src_addr,
        dst_addr: result.dst_addr,
        recognized: result.recognized,
    }
}
```
Note this is a plain free function (not a method on `FlowEngine`) — it needs no `&self`/`&mut self`, since `parse_five_tuple_internal` is stateless. Place it alongside `new_flow_engine`, not inside `impl FlowEngine`.

- [ ] **Step 3: Build and fix compile errors**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j$(nproc) net_flow_engine_cxxbridge 2>&1 | tail -100"
```

- [ ] **Step 4: Write the smoke tests**

Add to `tests/net_flow_engine_ffi_test.cc` (find the existing `SynPacket()` helper and `NetFlowEngineFfiTest` suite; add alongside):
```cpp
namespace {

std::vector<uint8_t> UdpPacket() {
  std::vector<uint8_t> p(28, 0);  // 20-byte IP + 8-byte UDP
  p[0] = (4 << 4) | 5;
  p[2] = 0x00; p[3] = 0x1C;  // tot_len = 28
  p[9] = 17;  // UDP
  p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 1;
  p[16] = 10; p[17] = 0; p[18] = 0; p[19] = 2;
  p[20] = 0x04; p[21] = 0xD2;  // source port 1234
  p[22] = 0x00; p[23] = 0x50;  // dest port 80
  return p;
}

std::vector<uint8_t> IcmpPacket() {
  std::vector<uint8_t> p(20, 0);
  p[0] = (4 << 4) | 5;
  p[9] = 1;  // ICMP
  p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 1;
  p[16] = 10; p[17] = 0; p[18] = 0; p[19] = 2;
  return p;
}

}  // namespace

TEST(NetFlowEngineFfiTest, ParseFiveTupleRecognizesUdp) {
  auto pkt = UdpPacket();
  auto tuple = net_flow::parse_five_tuple(pkt.data(), pkt.size());
  EXPECT_TRUE(tuple.recognized);
  EXPECT_EQ(tuple.proto, 17);
  EXPECT_EQ(tuple.ip_header_len, 20);
  EXPECT_EQ(tuple.src_port, 1234);
  EXPECT_EQ(tuple.dst_port, 80);
}

TEST(NetFlowEngineFfiTest, ParseFiveTupleRecognizesIcmpWithZeroPorts) {
  auto pkt = IcmpPacket();
  auto tuple = net_flow::parse_five_tuple(pkt.data(), pkt.size());
  EXPECT_TRUE(tuple.recognized);
  EXPECT_EQ(tuple.proto, 1);
  EXPECT_EQ(tuple.src_port, 0);
  EXPECT_EQ(tuple.dst_port, 0);
}

TEST(NetFlowEngineFfiTest, ParseFiveTupleRecognizesTcpToo) {
  auto pkt = SynPacket();  // existing helper, already defined in this file
  auto tuple = net_flow::parse_five_tuple(pkt.data(), pkt.size());
  EXPECT_TRUE(tuple.recognized);
  EXPECT_EQ(tuple.proto, 6);
}
```

- [ ] **Step 5: Build and run**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j$(nproc) net_rule_grpc_test 2>&1 | tail -100"
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && ./net_rule_grpc_test --gtest_filter='NetFlowEngineFfiTest.*'"
```
Expected: clean build, all smoke tests pass (existing ones plus the 3 new ones).

- [ ] **Step 6: Commit**

```bash
git add crates/net_flow_engine/src/lib.rs tests/net_flow_engine_ffi_test.cc
git commit -m "Wire parse_five_tuple into the net_flow_engine cxx bridge"
```

---

### Task 3: Redesign `ConnectionManager`'s contract to return decisions instead of driving WAF dispatch internally

**Files:**
- Modify: `net/connection_manager.h` (`receive`'s return type and body; relocate `HandleNewConnection`/`HandleData`/`HandleClosed` from `private` to `public` and rename to reflect their new caller-invoked role)
- Modify: `tests/net_flow_engine_ffi_test.cc` (`ConnectionManagerCutoverTest`'s two existing tests — update call sites to the new contract shape; assertions about WAF-observable behavior must not change)

**Interfaces:**
- Consumes: `net_flow::parse_five_tuple` (Task 2), `net_flow::PacketDecision` (Phase 5, unchanged).
- Produces: `net::ConnectionManager::ReceiveResult` (new struct: `FiveTuple tuple; net_flow::PacketDecision decision; bool is_tcp;`), `ConnectionManager::receive(pkg, len) -> ReceiveResult`, `ConnectionManager::DispatchWaf(const net_flow::PacketDecision&, const uint8_t*, size_t) -> NetStatus` — the seam Task 4 wires `input_nfq_cb`/`output_nfq_cb` up to.

This is the highest-risk task in this plan — it changes the call boundary of already-shipped, production WAF-dispatch code. Read `net/connection_manager.h`'s exact current content (already quoted in full in this plan's reference design spec's Architecture section, but re-read the live file — it may have drifted) before editing.

- [ ] **Step 1: Confirm nothing else depends on `ConnectionManager::receive`'s current signature**

```bash
grep -rn 'ConnMgr()\.receive\|ConnectionManager::receive\|\.receive(reinterpret_cast<const uint8_t' --include='*.h' --include='*.cc' --include='*.cpp' /Users/robbieqiu/workspace/net-policy
```
Expected: hits only in `input_nfq_cb`/`output_nfq_cb` (`net-policy.cpp`) and test files (`tests/net_flow_engine_ffi_test.cc`'s `ConnectionManagerCutoverTest`). If anything else calls `receive`, stop and re-scope — this task's signature change must account for every real caller.

- [ ] **Step 2: Confirm `ReceiveResult` avoids the circular-include problem**

`net-policy.h` already `#include`s `net/connection_manager.h` (confirm via `grep -n '#include "net/connection_manager.h"' net-policy.h`), so `net/connection_manager.h` cannot `#include "net-policy.h"` back to get `FiveTuple` (net-policy.h's class, used for L3-L4 policy matching). Step 3 below sidesteps this deliberately: `ReceiveResult::tuple` is typed as `net_flow::SharedFiveTuple` (the raw FFI struct from Task 2 — already available via `net_flow_engine_cxxbridge/lib.h`, which `net/connection_manager.h` already includes transitively for `PacketDecision`), not `net::FiveTuple`. Constructing an actual `net::FiveTuple` from a `SharedFiveTuple` happens in Task 4, inside `net-policy.cpp`, which already includes both headers — no circular-include problem there. Do not change `ReceiveResult::tuple`'s type to `net::FiveTuple` while implementing Step 3; if you find yourself wanting to, that's a sign you've reintroduced the circular include this step exists to avoid.

- [ ] **Step 3: Rewrite `net/connection_manager.h`**

```cpp
#pragma once

#include <glog/logging.h>
#include <memory>
#include <unordered_map>
#include <utility>

#include "http/connection.h"
#include "http/http_filter_factory.h"
#include "http/packet.hh"
#include "net/stream.h"
#include "net/utility.h"
#include "net_flow_engine_cxxbridge/lib.h"

namespace net {

class ConnectionManager {
public:
  // Populated for every recognized protocol (TCP/UDP/ICMP); `decision` and
  // `is_tcp` are only meaningful when `is_tcp` is true (net_flow_engine only
  // performs TCB tracking for TCP -- see net_flow_engine's parse_five_tuple
  // vs on_packet split).
  struct ReceiveResult {
    // Populated by the caller from SharedFiveTuple's fields -- see Task 4
    // for exactly how net-policy.h's FiveTuple gets constructed from this;
    // ConnectionManager itself only needs to hand back the raw parsed
    // fields, not construct a FiveTuple (avoiding the header-ordering
    // problem from Step 2).
    net_flow::SharedFiveTuple tuple;
    net_flow::PacketDecision decision;
    bool is_tcp;
  };

  explicit ConnectionManager(http::HttpFilterFactory& filter_factory)
      : filter_factory_(filter_factory), engine_(net_flow::new_flow_engine()) {}

  ReceiveResult receive(const uint8_t* pkg, size_t len) {
    ReceiveResult result{};
    result.tuple = net_flow::parse_five_tuple(pkg, len);
    result.is_tcp = result.tuple.recognized && (result.tuple.proto == 6 /* IPPROTO_TCP */);
    if (result.is_tcp) {
      result.decision = engine_->on_packet(pkg, len);
    }
    return result;
  }

  // Unchanged logic from the old internal Handle{NewConnection,Data,Closed}
  // (Phase 5) -- only the call site moved, from inside receive() to here,
  // an explicitly-invoked public method. Caller must only call this when
  // decision.kind != 0 (Ignore) and only for TCP (ReceiveResult::is_tcp).
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
      default:
        return NetStatus::OK;
    }
  }

  NetworkStat stat() { NetworkStat st{}; st.tcp_conn_ = engine_->live_connection_count(); return st; }

  std::vector<std::string> connections() {
    auto rust_conns = engine_->connection_strings();
    std::vector<std::string> conns;
    conns.reserve(rust_conns.size());
    for (const auto& s : rust_conns) {
      conns.emplace_back(std::string(s));
    }
    return conns;
  }

  size_t httpConnectionCount() const { return http_conns_.size(); }

private:
  static ConnectionID ToConnectionID(const net_flow::SharedConnectionId& id) {
    return ConnectionID{id.local_ip, id.foreign_ip, id.local_port, id.foreign_port};
  }

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
    auto id = ToConnectionID(decision.conn_id);
    auto peer_id = ToConnectionID(decision.peer_conn_id);
    auto it = http_conns_.find(id);
    if (it != http_conns_.end()) {
      it->second->httpFilterManager()->onClose();
      http_conns_.erase(it);
    }
    http_conns_.erase(peer_id);
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
    // header -- see waf/plugin.cc's ModifyNetPackets. Do NOT collapse this
    // into a single trim_front(payload_offset) call. (Unchanged from Phase 5's
    // Task 7 fix -- see net/connection_manager.h's git history if this
    // comment's rationale needs re-deriving.)
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

  http::HttpFilterFactory& filter_factory_;
  rust::Box<net_flow::FlowEngine> engine_;
  std::unordered_map<ConnectionID, std::shared_ptr<http::Connection>, ConnectionIDHash> http_conns_;
};

}  // namespace net
```
Note: `HandleNewConnection`/`HandleClosed`/`HandleData` stay `private` (only `DispatchWaf` moved to `public`) — the caller only needs the single `DispatchWaf` entry point, matching the "one call per logical operation" FFI-granularity principle this migration has used throughout, applied here at a pure-C++ boundary too.

- [ ] **Step 4: Update the existing `ConnectionManagerCutoverTest` tests to the new contract**

Read the current two tests in `tests/net_flow_engine_ffi_test.cc` (`HandleDataPassesTcpHeaderStartNotIpHeaderStartToFilters`, `HandleClosedInvokesOnCloseAndRemovesBothConnections`). Both currently call `manager.receive(pkt.data(), pkt.size())` expecting a `NetStatus` return and rely on it driving WAF dispatch internally. Update each call site to the new two-step shape:
```cpp
auto result = manager.receive(pkt.data(), pkt.size());
ASSERT_TRUE(result.is_tcp);
auto status = manager.DispatchWaf(result.decision, pkt.data(), pkt.size());
```
Do not change what either test asserts about `CapturingFilter`'s observations or `httpConnectionCount()` — only the two-step call shape changes; the WAF-observable behavior these tests check must be byte-for-byte identical to before this task.

- [ ] **Step 5: Do not build or commit yet**

`net-policy.cpp`'s `input_nfq_cb`/`output_nfq_cb` still call the OLD `receive` signature at this point — `net-rule`/`net_rule_grpc_test` will NOT compile cleanly until Task 4's cutover lands. Rather than introduce a throwaway compatibility shim, Task 4 completes the cutover and both file groups are built, tested, and committed together as a single commit at the end of Task 4. Proceed directly to Task 4 with these changes staged but uncommitted.

---

### Task 4: Cutover — update `input_nfq_cb`/`output_nfq_cb` to the unified path, remove `parse_package`'s role

**Files:**
- Modify: `net-policy.cpp` (`input_nfq_cb` and `output_nfq_cb`'s five-tuple-acquisition and WAF-dispatch block; construct `FiveTuple` from `ConnectionManager::ReceiveResult`; reconstruct `offset`/`tcphdr` for the downstream microseg block)
- Commit together with Task 3's staged, uncommitted changes to `net/connection_manager.h` and `tests/net_flow_engine_ffi_test.cc` (see Task 3 Step 5 — the two tasks share one build/test/commit cycle since Task 3 alone doesn't compile).

**Interfaces:**
- Consumes: `net::ConnectionManager::ReceiveResult`, `ConnectionManager::DispatchWaf` (Task 3).

This is the highest-risk task in this plan — it changes the real production packet-processing hot path for both directions, including the downstream microseg TCP-tracking block's two load-bearing locals (`offset`, `tcphdr`) that this plan's earlier research confirmed are NOT dead code (read directly out of the live `net-policy.cpp` before this plan was finalized — see below). The code in this task's steps was written against that live read; re-verify against current source before applying, since this plan may have been written some time before you execute it.

**Ground truth this task's code is written against** (`net-policy.cpp`, `input_nfq_cb`, confirmed live before this plan was finalized):
```cpp
  ret = parse_package(pkg, tuple, &tcphdr, offset);
  if (ret != kNfMatchRule)
    nfq_set_verdict(qh, id, ret, 0, NULL);      // <-- no return: the quirk
  if (daemon->WafEnabled() && (tuple.proto_ == IPPROTO_TCP)) {
    auto status = daemon->ConnMgr().receive(reinterpret_cast<const uint8_t*>(pkg), data_len);
    if (status == net::NetStatus::Drop) {
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), data_len, pkg);
    }
  }
  /*tcp four tuple*/
  ct_key.dst_port_ = tuple.dst_port_;
  /* ... ct_key.{src_port_,dst_addr_,src_addr_} similarly ... */
  switch (tuple.proto_) {
  case IPPROTO_TCP:
    tcp_it = daemon->Microseg().TcpCtInput().find(ct_key);
    if (tcp_it == daemon->Microseg().TcpCtInput().end()) {
      if (tcphdr.syn != 0) break;
      if (data_len <= offset) return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), 0, NULL);
      break;
    }
    found = true;
    if ((tcphdr.fin == 1) || (tcphdr.rst == 1)) { /* erase, return kAllow */ }
    if (data_len <= offset) return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), 0, NULL);
    break;
  case IPPROTO_UDP: case IPPROTO_ICMP: break;
  default: return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
  }
  /* ... */
  auto tcp_seq = ntohl(tcphdr.seq);
  if (tcphdr.syn == 1) { /* ... */ }
  /* ... */
  value = pkg + offset;
  /* ... */
  auto payload_len = data_len - offset;
```
`offset` and `tcphdr.{syn,fin,rst,seq}` are read all the way through to the bottom of the function (both `input_nfq_cb` and, symmetrically, `output_nfq_cb`). This block is the OUT-OF-SCOPE downstream microseg logic (Global Constraints) — this task must keep feeding it exactly the same `offset`/`tcphdr` values `parse_package` used to produce, without touching the block's own logic.

- [ ] **Step 1: Re-confirm the exact current control flow before editing**

```bash
grep -n 'parse_package\|ConnMgr()\.receive\|kNfMatchRule' net-policy.cpp
```
Diff what you see against the "Ground truth" block above. If the actual current code has drifted meaningfully (not just line numbers), stop and re-read the full functions before proceeding — this task changes verdict-issuing logic on live traffic.

- [ ] **Step 2: Decide how to handle the `parse_package` no-`return` quirk**

Analysis already done for you, so this is a documented choice, not open-ended research: `parse_package`'s failure path (`ret != kNfMatchRule`) only happens when `iph->version != 4` or the protocol isn't TCP/UDP/ICMP. In the old code, `tuple.proto_` stays at its default-constructed value (0) on failure, which does not match `IPPROTO_TCP`/`_UDP`/`_ICMP` in the switch below — so the fall-through quirk's practical effect is always the same: the switch's `default: return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);` branch fires almost immediately afterward. The two `nfq_set_verdict` calls on the same packet `id` (the quirky one, then the switch's `default:` one) are redundant but not distinguishable in outcome from a single early return. Given this, an early `return` after the verdict call is strictly safer (avoids issuing two verdicts for one packet id, a pattern nfnetlink does not expect) and behaviorally equivalent for every real packet — recommended. Whichever you choose, state it explicitly in this task's commit message per this project's established practice of not silently resolving quirks.

- [ ] **Step 3: Update `input_nfq_cb`**

Replace the `parse_package` call, the four `ct_key.*` lines' upstream tuple/offset/tcphdr sourcing, and the `WafEnabled()`-gated `ConnMgr().receive()` block with:
```cpp
  auto result = daemon->ConnMgr().receive(reinterpret_cast<const uint8_t*>(pkg), data_len);
  if (!result.tuple.recognized) {
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
  }
  tuple.proto_        = result.tuple.proto;
  tuple.tot_len_       = result.tuple.tot_len;
  tuple.src_port_      = result.tuple.src_port;
  tuple.dst_port_      = result.tuple.dst_port;
  tuple.src_addr_u32_  = result.tuple.src_addr;
  tuple.dst_addr_u32_  = result.tuple.dst_addr;
  tuple.src_addr_      = net::ipv4ToString(result.tuple.src_addr);
  tuple.dst_addr_      = net::ipv4ToString(result.tuple.dst_addr);

  // Reconstruct offset/tcphdr for the downstream microseg TCP-tracking block
  // (out of scope for this phase -- see Global Constraints and this task's
  // "Ground truth" note above). Mirrors parse_package's old arithmetic
  // exactly; result.tuple.ip_header_len is the one extra fact the new parse
  // exposes to make this possible without a second full parse pass.
  //
  // Note: this memcpy/cast is safe against truncated packets in a way
  // parse_package's old direct pointer cast was not -- ConnectionManager's
  // parse_five_tuple only reports proto_==IPPROTO_TCP with recognized=true
  // after confirming data_len >= ip_header_len + sizeof(struct tcphdr) (and
  // the equivalent for UDP's fixed 8-byte header), whereas parse_package
  // dereferenced tcph/udph with no bounds check beyond the initial
  // sizeof(struct iphdr) guard. Not a behavior change on well-formed
  // traffic; strictly safer on malformed/truncated packets. Worth a mention
  // in the commit message, not a functional change to flag as a quirk.
  offset = static_cast<int>(result.tuple.ip_header_len);
  if (tuple.proto_ == IPPROTO_TCP) {
    memcpy(&tcphdr, pkg + result.tuple.ip_header_len, sizeof(tcphdr));
    offset += tcphdr.doff << 2;
  } else if (tuple.proto_ == IPPROTO_UDP) {
    offset += sizeof(struct udphdr);
  }
  // ICMP (and anything else `recognized` covers): offset stays at
  // ip_header_len, matching parse_package.

  if (daemon->WafEnabled() && result.is_tcp) {
    auto status = daemon->ConnMgr().DispatchWaf(result.decision, reinterpret_cast<const uint8_t*>(pkg), data_len);
    if (status == net::NetStatus::Drop) {
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), data_len, pkg);
    }
  }
```
`net::ipv4ToString` is declared in `net/utility.h` (confirmed already present and included transitively via `net/connection_manager.h`) and produces the same dotted-decimal format `parse_package`'s `inet_ntop`-based construction did — verified via `net/utility.cc`. Delete the old `parse_package(pkg, tuple, &tcphdr, offset)` call and the now-unused `ret` local (the `int id = 0, ret, offset;` declaration line needs `ret` dropped but `offset` kept). Keep the `struct tcphdr tcphdr;` declaration — it's populated by the `memcpy` above instead of by `parse_package`.

The rest of the function (the `switch (tuple.proto_)` block through the end) is unchanged — do not touch it; it now runs against `offset`/`tcphdr`/`tuple` values sourced from `ConnectionManager` instead of `parse_package`, with no shape change to those variables.

- [ ] **Step 4: Update `output_nfq_cb` identically**

Apply the same change to `output_nfq_cb` (confirmed structurally identical to `input_nfq_cb` for this block via a live read before this plan was finalized) — same replacement, with two direction-specific differences already present in the surrounding code that must NOT change: the WAF-drop verdict uses `kAllowRsp` (not `kAllowReq`), and `daemon->Microseg().TcpCtOutput()` (not `TcpCtInput()`) is used by the unchanged downstream block below your edit.

- [ ] **Step 5: Build and run everything**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j$(nproc) net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec --privileged net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && ./net_rule_test && ./net_rule_grpc_test"
```
Expected: clean build under `-Wall -Werror`, every test passes (including Task 3's updated `ConnectionManagerCutoverTest` tests, built here for the first time since Task 3 deferred its own build). Run `net_rule_grpc_test` at least 3 times to check for flakiness.

- [ ] **Step 6: Commit**

```bash
git add net/connection_manager.h tests/net_flow_engine_ffi_test.cc net-policy.cpp
git commit -m "Cut input_nfq_cb/output_nfq_cb over to ConnectionManager's unified receive/DispatchWaf

Combines Task 3's ConnectionManager contract redesign with Task 4's caller
cutover in one commit since the intermediate state (redesigned
ConnectionManager, old call sites) doesn't compile. [Document here: which
choice was made for the parse_package no-return quirk (Step 2), and note
the incidental bounds-check improvement in offset/tcphdr reconstruction
for malformed/truncated packets.]"
```

---

### Task 5: Final verification — new integration coverage, confirm `parse_package` fully retired

**Files:**
- Create or extend: `tests/net_flow_engine_ffi_test.cc` (integration-level test exercising the full `input_nfq_cb`-shaped call sequence through real `ConnectionManager`)
- Possibly modify: `net-policy.cpp` (delete `parse_package` itself, if Task 4 left it with zero remaining callers)

**Interfaces:** None new — this task verifies the whole phase's final state.

- [ ] **Step 1: Confirm `parse_package`'s remaining reachability**

```bash
grep -n 'parse_package' net-policy.cpp
```
Task 4 reconstructs `offset`/`tcphdr` directly from `ConnectionManager::ReceiveResult` (see Task 4 Step 3), so `parse_package` should have zero remaining call sites at this point — its only reference should be its own definition. Delete the function. If it turns out to still have a caller, that means Task 4 wasn't completed as planned — stop and go fix Task 4 rather than leaving `parse_package` in place as a workaround.

- [ ] **Step 2: Add an integration test exercising the full caller-orchestration shape**

Add to `tests/net_flow_engine_ffi_test.cc`, using the existing `ConnectionManagerCutoverTest`/`CapturingFilter` infrastructure:
```cpp
TEST(ConnectionManagerCutoverTest, ReceiveReturnsFiveTupleForUdpWithoutWafDispatch) {
  http::HttpFilterFactory filter_factory;
  net::ConnectionManager manager(filter_factory);

  std::vector<uint8_t> udp_pkt(28, 0);
  udp_pkt[0] = (4 << 4) | 5;
  udp_pkt[9] = 17;  // UDP
  udp_pkt[12] = 10; udp_pkt[13] = 0; udp_pkt[14] = 0; udp_pkt[15] = 1;
  udp_pkt[16] = 10; udp_pkt[17] = 0; udp_pkt[18] = 0; udp_pkt[19] = 2;
  udp_pkt[20] = 0x04; udp_pkt[21] = 0xD2;
  udp_pkt[22] = 0x00; udp_pkt[23] = 0x50;

  auto result = manager.receive(udp_pkt.data(), udp_pkt.size());
  EXPECT_TRUE(result.tuple.recognized);
  EXPECT_EQ(result.tuple.proto, 17);
  EXPECT_FALSE(result.is_tcp);
  // decision.kind should be left default (0/Ignore) -- on_packet was never
  // called for a non-TCP packet.
  EXPECT_EQ(result.decision.kind, 0);
}
```

- [ ] **Step 3: Build and run the full suite one more time**

```bash
docker exec net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && cmake .. && make -j$(nproc) net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec --privileged net-policy-build-test bash -c "cd /workspace/net-policy/.worktrees/<worktree-name>/build && ./net_rule_test && ./net_rule_grpc_test"
```
Run `net_rule_grpc_test` at least 3 times.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "Verify Phase 6b-1's unified packet-decision path end-to-end"
```

---

## Definition of Done

- `net_flow_engine` exposes `parse_five_tuple`, a stateless TCP/UDP/ICMP five-tuple parser, alongside its unchanged TCP-only `on_packet`.
- `net::ConnectionManager::receive` returns a `ReceiveResult` (five-tuple + TCB decision); WAF dispatch is a separate, explicitly-invoked `DispatchWaf` method carrying the exact same logic Phase 5 shipped.
- `input_nfq_cb`/`output_nfq_cb` call `ConnMgr().receive` once, unconditionally, for every packet — `parse_package` is either deleted (if fully unreferenced) or clearly flagged as still needed for a specific, documented reason deferred to Phase 6b-2.
- Every Phase 5 test (`ConnectionManagerCutoverTest`, `NetFlowEngineFfiTest`, `PolicyEngineFfiTest`, and the broader `net_rule_test`/`net_rule_grpc_test` suites) passes with WAF-observable behavior unchanged.
- `MicroSegEngine::TcpCtInput()`/`TcpCtOutput()`, `NFQ_RES_INFO`, `InitNfqueue`, netns switching, and conntrack are all unchanged from before this plan — deferred to Phase 6b-2/6b-3/6c.
