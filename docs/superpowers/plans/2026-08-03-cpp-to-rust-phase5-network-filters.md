# Phase 5: Network Filters Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate IPv4/TCP packet-layer parsing and per-flow (TCB) connection tracking (`net/ip.cc`'s `ipv4`, `net/tcp.cc`'s `Tcp`/`Tcb`) from C++ to a new Rust crate, `net_flow_engine`, verified via a differential test against the real C++ implementation before cutover; delete the confirmed-dead `net/filter.{h,cc}` and `net/udp.{h,cc}`.

**Architecture:** `net::ConnectionManager` (`net/connection_manager.h`) keeps its public shape (`receive`/`stat`/`connections`), but its `receive` entry point changes from taking a `seastar::net::packet` to taking a raw `(const uint8_t*, size_t)` buffer — the exact raw NFQ bytes, taken directly at the two `net-policy.cpp` call sites instead of first wrapping them in a packet object. Internally, `ConnectionManager` owns an opaque `rust::Box<FlowEngine>` (one call per packet: `on_packet`) plus a new, small `ConnectionID → shared_ptr<http::Connection>` map — a strict subset of what `Tcp::Tcb` used to hold, since Rust now owns the pure TCP/IP parsing and flow-state-machine half. `FlowEngine`'s returned `PacketDecision` tells `ConnectionManager` which of today's HTTP-layer call sequences to replay (unchanged HTTP/WAF code, just relocated to the call site). `seastar::net::packet` is never represented in Rust.

**Tech Stack:** Rust (`cxx` crate for FFI, `staticlib` crate type, Corrosion for CMake integration — same toolchain as `net_policy_engine`/`waf_rules_core`/`net_policy_control`/`net_policy_events`), C++17, Google Test.

**Reference spec:** `docs/superpowers/specs/2026-08-03-cpp-to-rust-phase5-network-filters-design.md`

## Global Constraints

- `seastar::net::packet` (`http/packet.hh`/`.cc`) is never bridged to Rust and never appears in `net_flow_engine`'s FFI surface — Rust's `on_packet` takes a raw `(*const u8, usize)` pointer/length instead. C++ constructs a `seastar::net::packet` (via `seastar::net::packet::from_static_data`) only at the one remaining point that still needs it: handing payload bytes to the unchanged HTTP filter chain when `PacketDecision::kind == Data`.
- `http::HttpFilterManager`, `http::Connection`, `http::HttpFilterFactory`, and everything under `http/`/`waf/` are OUT OF SCOPE — do not modify them beyond what's explicitly listed in a task's Files section. `ConnectionManager`'s new `ConnectionID → shared_ptr<http::Connection>` map calls the exact same HTTP-layer constructors/methods `Tcp::receive` calls today, in the same order, with the same arguments.
- NFQ/netlink (`net-policy.cpp`'s main loop, epoll wiring, `admin/profile.cc`) is OUT OF SCOPE beyond the two `ConnMgr().receive(...)` call sites this plan's Task 7 updates.
- `ConnectionID`'s address fields (`local_ip_`/`foreign_ip_`, and this crate's Rust equivalents `local_ip`/`foreign_ip`) are raw network-byte-order 32-bit values, exactly as `struct iphdr::saddr`/`daddr` are in C — never byte-swapped, only ever compared/hashed as opaque bits or formatted back to dotted-decimal. Read them in Rust via `u32::from_ne_bytes` (reinterpreting the 4 raw header bytes as a native `u32`, the same thing a C struct-member read does on a given build) — NOT `from_be_bytes` — and format them back via `.to_ne_bytes()` in `ipv4_to_string`, so the two operations round-trip consistently on whatever single platform builds and runs the binary. Port numbers (`local_port_`/`foreign_port_`) ARE host-byte-order (mirroring the C++ code's `ntohs(...)` calls) — read those via `u16::from_be_bytes`.
- TCP flag/data-offset bits are read directly from the wire-format byte layout (RFC 793: byte 12 = data-offset in the high nibble + reserved bits in the low nibble; byte 13 = `CWR ECE URG ACK PSH RST SYN FIN`, FIN as the low bit), NOT by replicating `struct tcphdr`'s C bitfield layout — the RFC wire-format reading is portable and unambiguous, where a bitfield-layout port would depend on compiler-specific packing assumptions. Task 4's differential test is what actually confirms this produces identical flow-tracking behavior to the real C++ code's `tcp_hdr->doff`/`->fin`/`->syn`/`->rst` bitfield reads on this project's actual build platform — verify empirically, don't just trust the RFC reasoning in isolation.
- **Known, deliberate deviation, flagged not silently resolved:** `ipv4::receive`'s current C++ only checks `packet.len() < sizeof(iphdr)` (a fixed 20-byte check) before calling `packet.trim_front(ihl * 4)` — it never validates that the packet is actually as long as `ihl * 4` claims when `ihl > 5` (options present). Whether that's an exploitable OOB in the vendored packet type's `trim_front` isn't verified here. Since Rust manually parses raw bytes with no packet-object safety net, `parse_ipv4_header` (Task 3) bounds-checks against the *actual* claimed header length, not just the fixed 20-byte minimum, and returns `None` (packet ignored) if the buffer is shorter than `ihl * 4` claims. This is a strictly more defensive behavior change on malformed/truncated packets only — call it out in Task 3's commit message, don't fold it in silently.
- Never `git worktree` inside the `net-policy-build-test` Docker container (bind-mounts the same host repo; has wiped the host's worktree registry before in this project's history) — use `git archive <commit> | tar -x -C /tmp/<unique-dir>` if you need an isolated checkout inside the container, or build directly against the bind-mounted worktree path if the container's mount source is the repo root (verify with `docker inspect <container> --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}'` first).
- Verify every code snippet, line number, and CMakeLists.txt `SOURCES` list membership in this plan against the actual current source before editing — this repo's `CMakeLists.txt` defines three targets (`net-rule`, `net_rule_test`, `net_rule_grpc_test`) with different `SOURCES` lists; as of this writing `net_rule_test` deliberately excludes `net/ip.cc`/`net/tcp.cc`/`net/udp.cc` (the same way it excludes `rule-detail.cpp`) while `net-rule` and `net_rule_grpc_test` include them — confirm this hasn't drifted before wiring the new crate into any target's link list.

---

### Task 1: Delete the confirmed-dead `net/filter.{h,cc}` and `net/udp.{h,cc}`

**Files:**
- Delete: `net/filter.h`, `net/filter.cc`, `net/udp.h`, `net/udp.cc`
- Modify: `CMakeLists.txt` (remove `net/filter.cc` and `net/udp.cc` from every `SOURCES` list that has them)
- Modify: `net/utility.h`, `net/tcp.cc` — both `#include "net/filter.h"` directly (confirmed by `grep -rln '#include "net/filter\.h"'`) without using anything `net/filter.h` declares (`NetworkFilterManager`/`NetworkFilterBase`/`addFilter` — Step 1's grep below finds zero real users of these). Deleting `net/filter.h` without removing these two include lines leaves a dangling include: `net/tcp.cc` isn't deleted until Task 7, so it would break the build for the entire span between this task and Task 7 if left in place.

**Interfaces:** None — this task has no Rust component and produces nothing later tasks depend on. It's independent and goes first only to shrink the surface the rest of the phase has to reason about.

- [ ] **Step 1: Confirm both are genuinely dead, and find every dangling include**

```bash
grep -rn '\bNetworkFilterManager\b\|\bNetworkFilterBase\b\|\baddFilter\b' --include='*.h' --include='*.hh' --include='*.cc' --include='*.cpp' /Users/robbieqiu/workspace/net-policy | grep -v 'net/filter\.\|http/filter\.\|http/codec\.\|http/connection\.\|http/http1/codec\.\|http/http2/codec\.'
grep -rn '\bnet::Udp\b\|"net/udp\.h"\|"udp\.h"' --include='*.h' --include='*.hh' --include='*.cc' --include='*.cpp' /Users/robbieqiu/workspace/net-policy | grep -v 'net/udp\.'
grep -rln '#include "net/filter\.h"' --include='*.h' --include='*.hh' --include='*.cc' --include='*.cpp' /Users/robbieqiu/workspace/net-policy | grep -v 'net/filter\.'
```
Expected: the first two commands produce zero output (all hits are inside the files being deleted, or are the unrelated `http::HttpFilterManager`/`ConnectionImpl::addFilter` family, which this task does not touch). The third command is expected to print `net/utility.h` and `net/tcp.cc` — both need their `#include "net/filter.h"` line removed in Step 2 (neither uses anything from it). If the first two commands find a real external reference, or the third finds a file other than these two, stop and re-scope.

- [ ] **Step 2: Delete the files, remove the dangling includes, and their build-system references**

```bash
git rm net/filter.h net/filter.cc net/udp.h net/udp.cc
```
In `net/utility.h` and `net/tcp.cc`, delete the `#include "net/filter.h"` line (confirmed unused by both in Step 1). Open `CMakeLists.txt`, find every `SOURCES` list containing `net/filter.cc` and/or `net/udp.cc` (there should be entries in `net-rule`'s and `net_rule_grpc_test`'s lists, per Global Constraints' note on `net_rule_test` already excluding the deeper `net/` files — but verify directly, don't assume `net/filter.cc`'s membership matches `net/ip.cc`'s, since `net/filter.cc` is dead code that may have a different footprint than the live `ipv4`/`Tcp` classes), and remove those two lines from each.

- [ ] **Step 3: Build and verify**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -80"
```
Expected: clean build, zero new warnings under `-Wall -Werror`.

- [ ] **Step 4: Run existing tests**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && ./net_rule_test && ./net_rule_grpc_test"
```
Expected: all existing tests still pass (this task changes no live behavior).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Delete dead net/filter.{h,cc} (NetworkFilterManager) and net/udp.{h,cc} (Udp)"
```

---

### Task 2: Scaffold the `net_flow_engine` Rust crate and wire it into CMake

**Files:**
- Create: `crates/net_flow_engine/Cargo.toml`
- Create: `crates/net_flow_engine/src/lib.rs`
- Modify: `Cargo.toml` (repo root — add to workspace `members`)
- Modify: `CMakeLists.txt` (add `corrosion_add_cxxbridge` block, link into `net-rule` and `net_rule_grpc_test` — NOT `net_rule_test`, per Global Constraints)

**Interfaces:**
- Produces: an empty-but-real `#[cxx::bridge]` module (cxxbridge hard-errors on a module with zero bridge items) that later tasks extend.

- [ ] **Step 1: Create the crate**

`crates/net_flow_engine/Cargo.toml`:
```toml
[package]
name = "net_flow_engine"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
cxx = "1"
```

`crates/net_flow_engine/src/lib.rs`:
```rust
#[cxx::bridge(namespace = "net_flow")]
mod ffi {
    extern "Rust" {
        fn net_flow_engine_ffi_smoke() -> i32;
    }
}

fn net_flow_engine_ffi_smoke() -> i32 {
    42
}
```

- [ ] **Step 2: Add to the Cargo workspace**

Read the repo root `Cargo.toml`'s current `members` list first, then add `"crates/net_flow_engine"` alongside whatever is already there (`ffi_smoke`, `waf_rules_core`, `net_policy_control`, `net_policy_events`, `net_policy_engine`).

- [ ] **Step 3: Wire into CMake**

Find the last existing `corrosion_add_cxxbridge` block in `CMakeLists.txt` (there should be one each for `ffi_smoke_cxxbridge`, `waf_rules_core_cxxbridge`, `net_policy_control_cxxbridge`, `net_policy_events_cxxbridge`, `net_policy_engine_cxxbridge`) and add a new block immediately after it, in the same style:
```cmake
corrosion_add_cxxbridge(net_flow_engine_cxxbridge
  CRATE net_flow_engine
  FILES lib.rs
)
```
Add `net_flow_engine_cxxbridge` to `target_link_libraries(net-rule ...)` and `target_link_libraries(net_rule_grpc_test ...)`, alongside the existing cxxbridge crates. Do NOT add it to `net_rule_test`'s link list. Update the comment above `set_target_properties(net-rule PROPERTIES LINK_FLAGS "-Wl,--allow-multiple-definition")` that lists the cxxbridge crates needing the flag, to include `net_flow_engine_cxxbridge`.

- [ ] **Step 4: Build and verify**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -80"
```
Expected: clean build, zero new warnings (excluding the known-harmless Cargo jobserver messages — grep for `warning|error` excluding lines containing `jobserver`).

- [ ] **Step 5: Commit**

```bash
git add crates/net_flow_engine Cargo.toml CMakeLists.txt
git commit -m "Scaffold net_flow_engine Rust crate and wire into CMake"
```

---

### Task 3: Port IPv4 header parsing and the `ipv4ToString` helper to Rust

**Files:**
- Modify: `crates/net_flow_engine/src/lib.rs` (add `parse_ipv4_header`, `ipv4_to_string` — pure functions, private to the crate, not exposed over FFI yet)

**Interfaces:**
- Produces: `struct Ipv4Header { header_len: usize, protocol: u8, saddr: u32, daddr: u32 }`, `fn parse_ipv4_header(bytes: &[u8]) -> Option<Ipv4Header>`, `fn ipv4_to_string(ip: u32) -> String` — consumed by Task 4.

Read `net/ip.cc`'s `ipv4::receive` and `net/utility.cc`'s `ipv4ToString` yourself before porting (line numbers may have drifted from what's quoted in the design spec).

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod ipv4_tests {
    use super::*;

    // A minimal 20-byte IPv4 header (no options): version=4, ihl=5 (20 bytes),
    // protocol=TCP(6), saddr=10.0.0.1, daddr=10.0.0.2. Other fields (tos, total
    // length, id, flags/frag, ttl, checksum) are irrelevant to parsing and left
    // as zero/arbitrary filler.
    fn sample_ipv4_header(protocol: u8, ihl: u8) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0] = (4 << 4) | (ihl & 0x0F); // version=4, ihl
        b[9] = protocol;
        b[12..16].copy_from_slice(&[10, 0, 0, 1]); // saddr
        b[16..20].copy_from_slice(&[10, 0, 0, 2]); // daddr
        b
    }

    #[test]
    fn parse_ipv4_header_extracts_fields() {
        let bytes = sample_ipv4_header(6, 5);
        let h = parse_ipv4_header(&bytes).expect("should parse");
        assert_eq!(h.header_len, 20);
        assert_eq!(h.protocol, 6);
        assert_eq!(ipv4_to_string(h.saddr), "10.0.0.1");
        assert_eq!(ipv4_to_string(h.daddr), "10.0.0.2");
    }

    #[test]
    fn parse_ipv4_header_rejects_buffer_shorter_than_minimum() {
        let bytes = vec![0u8; 19]; // one byte short of the fixed 20-byte minimum
        assert!(parse_ipv4_header(&bytes).is_none());
    }

    #[test]
    fn parse_ipv4_header_with_options_reads_correct_header_len() {
        // ihl=6 -> 24-byte header (4 bytes of IP options after the fixed 20)
        let mut bytes = sample_ipv4_header(6, 6);
        bytes.extend_from_slice(&[0, 0, 0, 0]); // 4 bytes of options
        let h = parse_ipv4_header(&bytes).expect("should parse");
        assert_eq!(h.header_len, 24);
    }

    #[test]
    fn parse_ipv4_header_rejects_options_header_len_exceeding_buffer() {
        // ihl=6 claims a 24-byte header but only 20 bytes are actually present --
        // the deliberate deviation from the current C++ (see plan's Global
        // Constraints): reject rather than trust the claimed length.
        let bytes = sample_ipv4_header(6, 6);
        assert!(parse_ipv4_header(&bytes).is_none());
    }

    #[test]
    fn ipv4_to_string_formats_dotted_decimal() {
        let bytes = sample_ipv4_header(6, 5);
        let h = parse_ipv4_header(&bytes).unwrap();
        assert_eq!(ipv4_to_string(h.saddr), "10.0.0.1");
    }
}
```

- [ ] **Step 2: Run to verify the tests fail**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/crates/net_flow_engine && cargo test 2>&1 | tail -40"
```
Expected: compile error, `parse_ipv4_header`/`ipv4_to_string`/`Ipv4Header` not found.

- [ ] **Step 3: Implement**

```rust
const IPV4_HDR_MIN_LEN: usize = 20;

struct Ipv4Header {
    header_len: usize,
    protocol: u8,
    saddr: u32,
    daddr: u32,
}

fn parse_ipv4_header(bytes: &[u8]) -> Option<Ipv4Header> {
    if bytes.len() < IPV4_HDR_MIN_LEN {
        return None;
    }
    let ihl = (bytes[0] & 0x0F) as usize;
    let header_len = ihl * 4;
    // Deliberate deviation from the current C++ (see Global Constraints):
    // reject a header claiming more bytes than are actually present, instead
    // of trusting ihl unconditionally.
    if header_len < IPV4_HDR_MIN_LEN || bytes.len() < header_len {
        return None;
    }
    let protocol = bytes[9];
    let saddr = u32::from_ne_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let daddr = u32::from_ne_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    Some(Ipv4Header { header_len, protocol, saddr, daddr })
}

fn ipv4_to_string(ip: u32) -> String {
    let b = ip.to_ne_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}
```

- [ ] **Step 4: Run to verify the tests pass**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/crates/net_flow_engine && cargo test 2>&1 | tail -40"
```
Expected: all 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/net_flow_engine/src/lib.rs
git commit -m "Port IPv4 header parsing and ipv4ToString to net_flow_engine

Deliberately more defensive than the current C++: rejects a header whose
declared IHL claims more bytes than the buffer actually contains, rather
than trusting it unconditionally (the current ipv4::receive only checks
against the fixed 20-byte minimum). See plan's Global Constraints."
```

---

### Task 4: Port TCP header parsing and the TCB/flow-tracking state machine to Rust

**Files:**
- Modify: `crates/net_flow_engine/src/lib.rs` (add `parse_tcp_header`, `ConnectionId`, `FlowState`, `PacketKind`, `PacketDecision` (internal, pre-FFI shape), `FlowEngine` and its `on_packet_internal`/`live_connection_count`/`connection_strings` methods)

**Interfaces:**
- Consumes: `parse_ipv4_header`, `ipv4_to_string` (Task 3).
- Produces: `FlowEngine`, `PacketDecision`, `PacketKind`, `ConnectionId` — consumed by Task 5's cxx bridge.

Read `net/tcp.h`/`net/tcp.cc` (`ConnectionID`, `ConnectionIDHash`, `Tcp::Tcb`, `Tcp::receive`, `Tcp::stat`, `Tcp::connections`) yourself before porting — this task ports everything in `Tcp::receive` EXCEPT the HTTP-layer calls (`filter_manager`/`http::Connection`/`onNewConnection`/`onData`/`onClose`/`setTCPSegment`/`handlePayload`), which stay in C++ and are wired up in Task 7.

- [ ] **Step 1: Define the data model and TCP header parser**

```rust
use std::collections::HashMap;

const TCP_HDR_MIN_LEN: usize = 20;
const IPPROTO_TCP: u8 = 6;

struct TcpHeader {
    header_len: usize,
    source: u16,
    dest: u16,
    seq: u32,
    syn: bool,
    fin: bool,
    rst: bool,
}

/// Reads TCP header fields directly from wire-format bytes (RFC 793), not by
/// replicating struct tcphdr's C bitfield layout -- see the plan's Global
/// Constraints for why, and Task 6's differential test for the empirical
/// check that this matches the real C++ code's behavior on this platform.
fn parse_tcp_header(bytes: &[u8]) -> Option<TcpHeader> {
    if bytes.len() < TCP_HDR_MIN_LEN {
        return None;
    }
    let source = u16::from_be_bytes([bytes[0], bytes[1]]);
    let dest = u16::from_be_bytes([bytes[2], bytes[3]]);
    let seq = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let doff = (bytes[12] >> 4) as usize;
    let header_len = doff * 4;
    if header_len < TCP_HDR_MIN_LEN || bytes.len() < header_len {
        return None;
    }
    let flags = bytes[13];
    let fin = flags & 0x01 != 0;
    let syn = flags & 0x02 != 0;
    let rst = flags & 0x04 != 0;
    Some(TcpHeader { header_len, source, dest, seq, syn, fin, rst })
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct ConnectionId {
    local_ip: u32,
    foreign_ip: u32,
    local_port: u16,
    foreign_port: u16,
}

struct FlowState {
    seq: u32,
    server_side: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PacketKind {
    Ignore,
    NewConnection,
    Closed,
    Data,
}

struct PacketDecision {
    kind: PacketKind,
    conn_id: ConnectionId,
    peer_conn_id: ConnectionId,
    /// mirrors Tcp::receive's `peer_it == tcbs_.end()` check -- whether the
    /// reverse-direction flow entry was newly created by this packet too
    /// (only meaningful when kind == NewConnection).
    peer_is_new: bool,
    /// byte offset into the ORIGINAL (ip header included) buffer where the
    /// TCP payload begins; only meaningful when kind == Data.
    payload_offset: u32,
}

pub struct FlowEngine {
    tcbs: HashMap<ConnectionId, FlowState>,
}
```

- [ ] **Step 2: Port `Tcp::receive`'s state machine**

```rust
impl FlowEngine {
    fn new() -> Self {
        FlowEngine { tcbs: HashMap::new() }
    }

    /// Mirrors ipv4::receive + Tcp::receive combined: parses the IPv4 header,
    /// dispatches non-TCP protocols as a no-op (mirroring l4_[iph->protocol]
    /// being null for ICMP/UDP/other in the current C++), then parses the TCP
    /// header and runs the TCB lifecycle state machine exactly as
    /// Tcp::receive does, minus the HTTP-layer calls (Task 7 wires those up
    /// in C++, driven by this method's return value).
    fn on_packet_internal(&mut self, bytes: &[u8]) -> Option<PacketDecision> {
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
        let payload_offset = (ip.header_len + tcp.header_len) as u32;

        if self.tcbs.contains_key(&id) {
            if tcp.fin || tcp.rst {
                self.tcbs.remove(&id);
                self.tcbs.remove(&peer_id);
                return Some(PacketDecision {
                    kind: PacketKind::Closed,
                    conn_id: id,
                    peer_conn_id: peer_id,
                    peer_is_new: false,
                    payload_offset: 0,
                });
            }
            return Some(PacketDecision {
                kind: PacketKind::Data,
                conn_id: id,
                peer_conn_id: peer_id,
                peer_is_new: false,
                payload_offset,
            });
        }

        // Unknown flow.
        if tcp.rst {
            return None; // mirrors: log + return OK, no state change
        }
        if tcp.syn {
            self.tcbs.insert(id, FlowState { seq: tcp.seq.wrapping_add(1), server_side: true });
            let peer_is_new = !self.tcbs.contains_key(&peer_id);
            if peer_is_new {
                self.tcbs.insert(peer_id, FlowState { seq: 0, server_side: false });
            }
            return Some(PacketDecision {
                kind: PacketKind::NewConnection,
                conn_id: id,
                peer_conn_id: peer_id,
                peer_is_new,
                payload_offset: 0,
            });
        }
        // Neither RST nor SYN on an unknown flow (e.g. a bare ACK arriving
        // before we saw the SYN) -- no-op, mirrors the commented-out ACK
        // branch in the current C++.
        None
    }

    fn live_connection_count(&self) -> usize {
        self.tcbs.len()
    }

    /// Mirrors Tcp::connections(): one "local_ip:local_port,foreign_ip:foreign_port"
    /// string per tracked flow, in both directions (each SYN inserts up to two
    /// map entries -- one per direction -- and both are reported here, exactly
    /// as the current C++ iterates the full tcbs_ map).
    fn connection_strings(&self) -> Vec<String> {
        self.tcbs
            .keys()
            .map(|id| {
                format!(
                    "{}:{},{}:{}",
                    ipv4_to_string(id.local_ip),
                    id.local_port,
                    ipv4_to_string(id.foreign_ip),
                    id.foreign_port
                )
            })
            .collect()
    }
}
```

- [ ] **Step 3: Write unit tests**

```rust
#[cfg(test)]
mod flow_engine_tests {
    use super::*;

    fn ipv4_header(protocol: u8, saddr: [u8; 4], daddr: [u8; 4]) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0] = (4 << 4) | 5;
        b[9] = protocol;
        b[12..16].copy_from_slice(&saddr);
        b[16..20].copy_from_slice(&daddr);
        b
    }

    fn tcp_segment(
        source: u16, dest: u16, seq: u32, syn: bool, fin: bool, rst: bool, payload: &[u8],
    ) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0..2].copy_from_slice(&source.to_be_bytes());
        b[2..4].copy_from_slice(&dest.to_be_bytes());
        b[4..8].copy_from_slice(&seq.to_be_bytes());
        b[12] = 5 << 4; // doff=5 (20 bytes, no options)
        let mut flags = 0u8;
        if fin { flags |= 0x01; }
        if syn { flags |= 0x02; }
        if rst { flags |= 0x04; }
        b[13] = flags;
        b.extend_from_slice(payload);
        b
    }

    fn packet(ip_hdr: Vec<u8>, tcp_seg: Vec<u8>) -> Vec<u8> {
        let mut p = ip_hdr;
        p.extend_from_slice(&tcp_seg);
        p
    }

    #[test]
    fn syn_creates_new_connection_and_peer() {
        let mut engine = FlowEngine::new();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp = tcp_segment(1234, 80, 1000, true, false, false, &[]);
        let decision = engine.on_packet_internal(&packet(ip, tcp)).expect("should decide");
        assert_eq!(decision.kind, PacketKind::NewConnection);
        assert!(decision.peer_is_new);
        assert_eq!(engine.live_connection_count(), 2); // both directions tracked
    }

    #[test]
    fn second_syn_on_established_peer_does_not_recreate_peer() {
        let mut engine = FlowEngine::new();
        let ip_fwd = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp_fwd = tcp_segment(1234, 80, 1000, true, false, false, &[]);
        engine.on_packet_internal(&packet(ip_fwd, tcp_fwd)).unwrap();

        // A SYN in the reverse direction, on a flow the first SYN already seeded.
        let ip_rev = ipv4_header(6, [10, 0, 0, 2], [10, 0, 0, 1]);
        let tcp_rev = tcp_segment(80, 1234, 2000, true, false, false, &[]);
        let decision = engine.on_packet_internal(&packet(ip_rev, tcp_rev)).expect("should decide");
        assert_eq!(decision.kind, PacketKind::NewConnection);
        assert!(!decision.peer_is_new);
    }

    #[test]
    fn data_packet_on_established_flow_reports_payload_offset() {
        let mut engine = FlowEngine::new();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp_syn = tcp_segment(1234, 80, 1000, true, false, false, &[]);
        engine.on_packet_internal(&packet(ip.clone(), tcp_syn)).unwrap();

        let tcp_data = tcp_segment(1234, 80, 1001, false, false, false, b"hello");
        let decision = engine.on_packet_internal(&packet(ip, tcp_data)).expect("should decide");
        assert_eq!(decision.kind, PacketKind::Data);
        assert_eq!(decision.payload_offset, 40); // 20-byte IP + 20-byte TCP header
    }

    #[test]
    fn fin_closes_both_directions() {
        let mut engine = FlowEngine::new();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp_syn = tcp_segment(1234, 80, 1000, true, false, false, &[]);
        engine.on_packet_internal(&packet(ip.clone(), tcp_syn)).unwrap();
        assert_eq!(engine.live_connection_count(), 2);

        let tcp_fin = tcp_segment(1234, 80, 1001, false, true, false, &[]);
        let decision = engine.on_packet_internal(&packet(ip, tcp_fin)).expect("should decide");
        assert_eq!(decision.kind, PacketKind::Closed);
        assert_eq!(engine.live_connection_count(), 0);
    }

    #[test]
    fn rst_on_unknown_flow_is_ignored() {
        let mut engine = FlowEngine::new();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp_rst = tcp_segment(1234, 80, 1000, false, false, true, &[]);
        assert!(engine.on_packet_internal(&packet(ip, tcp_rst)).is_none());
        assert_eq!(engine.live_connection_count(), 0);
    }

    #[test]
    fn ack_on_unknown_flow_is_ignored() {
        let mut engine = FlowEngine::new();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp_ack = tcp_segment(1234, 80, 1000, false, false, false, &[]);
        assert!(engine.on_packet_internal(&packet(ip, tcp_ack)).is_none());
        assert_eq!(engine.live_connection_count(), 0);
    }

    #[test]
    fn non_tcp_protocol_is_ignored() {
        let mut engine = FlowEngine::new();
        let ip = ipv4_header(1 /* ICMP */, [10, 0, 0, 1], [10, 0, 0, 2]);
        assert!(engine.on_packet_internal(&ip).is_none());
    }

    #[test]
    fn connection_strings_reports_both_directions() {
        let mut engine = FlowEngine::new();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp = tcp_segment(1234, 80, 1000, true, false, false, &[]);
        engine.on_packet_internal(&packet(ip, tcp)).unwrap();
        let mut conns = engine.connection_strings();
        conns.sort();
        assert_eq!(conns, vec!["10.0.0.1:1234,10.0.0.2:80", "10.0.0.2:80,10.0.0.1:1234"]);
    }
}
```

- [ ] **Step 4: Run tests**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/crates/net_flow_engine && cargo test 2>&1 | tail -80"
```
Expected: all tests pass (5 from Task 3 + 8 from this task).

- [ ] **Step 5: Commit**

```bash
git add crates/net_flow_engine/src/lib.rs
git commit -m "Port TCP header parsing and TCB flow-tracking state machine to Rust"
```

---

### Task 5: Wire the `cxx` bridge and add a C++ smoke test

**Files:**
- Modify: `crates/net_flow_engine/src/lib.rs` (add the `#[cxx::bridge]` module, replacing Task 2's smoke stub)
- Create: `tests/net_flow_engine_ffi_test.cc` (standalone smoke test — proves the FFI surface works end-to-end, independent of `ConnectionManager`, which isn't wired up until Task 7)
- Modify: `CMakeLists.txt` (add the new test file to `net_rule_grpc_test`'s `SOURCES`)

**Interfaces:**
- Consumes: `FlowEngine`, `PacketDecision`, `PacketKind`, `ConnectionId` (Task 4).
- Produces: `net_flow::SharedConnectionId`, `net_flow::PacketDecision` (C++-visible shared structs), `net_flow::FlowEngine` (opaque Rust type), `net_flow::new_flow_engine() -> std::unique_ptr<FlowEngine>`, and its methods — the seam Task 7 wires `ConnectionManager` up to.

Follow the same opaque-Rust-type pattern Phase 4 established for `RustPolicyEngine` (`Box<T>` returned from Rust maps to `std::unique_ptr<T>` in C++).

- [ ] **Step 1: Replace the bridge module**

Replace `crates/net_flow_engine/src/lib.rs`'s `#[cxx::bridge]` module (from Task 2) with:
```rust
#[cxx::bridge(namespace = "net_flow")]
mod ffi {
    #[derive(Default)]
    struct SharedConnectionId {
        local_ip: u32,
        foreign_ip: u32,
        local_port: u16,
        foreign_port: u16,
    }

    #[derive(Default)]
    struct PacketDecision {
        /// 0 = Ignore, 1 = NewConnection, 2 = Closed, 3 = Data
        kind: i32,
        conn_id: SharedConnectionId,
        peer_conn_id: SharedConnectionId,
        peer_is_new: bool,
        payload_offset: u32,
    }

    extern "Rust" {
        type FlowEngine;

        fn new_flow_engine() -> Box<FlowEngine>;
        unsafe fn on_packet(self: &mut FlowEngine, pkg: *const u8, len: usize) -> PacketDecision;
        fn live_connection_count(self: &FlowEngine) -> usize;
        fn connection_strings(self: &FlowEngine) -> Vec<String>;
    }
}
```

- [ ] **Step 2: Add the FFI-facing conversions and entry points**

```rust
const KIND_IGNORE: i32 = 0;
const KIND_NEW_CONNECTION: i32 = 1;
const KIND_CLOSED: i32 = 2;
const KIND_DATA: i32 = 3;

impl From<ConnectionId> for ffi::SharedConnectionId {
    fn from(id: ConnectionId) -> Self {
        ffi::SharedConnectionId {
            local_ip: id.local_ip,
            foreign_ip: id.foreign_ip,
            local_port: id.local_port,
            foreign_port: id.foreign_port,
        }
    }
}

fn new_flow_engine() -> Box<FlowEngine> {
    Box::new(FlowEngine::new())
}

impl FlowEngine {
    /// # Safety
    /// `pkg` must point to at least `len` readable bytes; the caller (the
    /// still-C++ NFQ callback in net-policy.cpp) owns that buffer for the
    /// duration of this call and does not mutate it concurrently.
    unsafe fn on_packet(&mut self, pkg: *const u8, len: usize) -> ffi::PacketDecision {
        let bytes = std::slice::from_raw_parts(pkg, len);
        match self.on_packet_internal(bytes) {
            None => ffi::PacketDecision { kind: KIND_IGNORE, ..Default::default() },
            Some(d) => {
                let kind = match d.kind {
                    PacketKind::Ignore => KIND_IGNORE,
                    PacketKind::NewConnection => KIND_NEW_CONNECTION,
                    PacketKind::Closed => KIND_CLOSED,
                    PacketKind::Data => KIND_DATA,
                };
                ffi::PacketDecision {
                    kind,
                    conn_id: d.conn_id.into(),
                    peer_conn_id: d.peer_conn_id.into(),
                    peer_is_new: d.peer_is_new,
                    payload_offset: d.payload_offset,
                }
            }
        }
    }
}
```
`ffi::SharedConnectionId::default()`/`ffi::PacketDecision::default()` require `#[derive(Default)]` on both shared structs (already added in Step 1) — both contain only `Default`-able field types (integers, `bool`, and a nested `Default`-able struct).

- [ ] **Step 3: Build and fix compile errors**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net_flow_engine_cxxbridge 2>&1 | tail -100"
```
Iterate until clean. If `cxx`'s exact generated-header path or macro syntax doesn't match what's written here, check the resolved `cxx` version (`grep -A2 '^name = "cxx"' Cargo.lock` from the repo root) and adjust to match — this project has hit `cxx`-version-specific syntax issues before (Phase 2's `#[cxx_name = "type"]` reserved-keyword lesson, noted in `crates/net_policy_control/src/lib.rs`).

- [ ] **Step 4: Write the smoke test**

`tests/net_flow_engine_ffi_test.cc`:
```cpp
#include <gtest/gtest.h>

#include <cstring>

#include "net_flow_engine_cxxbridge/lib.h"

namespace {

// A minimal 20-byte IPv4 header + 20-byte TCP header (no options, no
// payload), SYN set. saddr=10.0.0.1, daddr=10.0.0.2, sport=1234, dport=80.
std::vector<uint8_t> SynPacket() {
  std::vector<uint8_t> p(40, 0);
  p[0] = (4 << 4) | 5;  // version=4, ihl=5
  p[9] = 6;             // protocol=TCP
  p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 1;   // saddr
  p[16] = 10; p[17] = 0; p[18] = 0; p[19] = 2;   // daddr
  p[20] = 0x04; p[21] = 0xD2;  // source port 1234
  p[22] = 0x00; p[23] = 0x50;  // dest port 80
  p[32] = 5 << 4;  // doff=5
  p[33] = 0x02;    // SYN
  return p;
}

}  // namespace

TEST(NetFlowEngineFfiTest, SynPacketCreatesNewConnection) {
  auto engine = net_flow::new_flow_engine();
  auto pkt = SynPacket();
  auto decision = engine->on_packet(pkt.data(), pkt.size());
  EXPECT_EQ(decision.kind, 1);  // NewConnection
  EXPECT_TRUE(decision.peer_is_new);
  EXPECT_EQ(engine->live_connection_count(), 2u);
}

TEST(NetFlowEngineFfiTest, NoConnectionsInitially) {
  auto engine = net_flow::new_flow_engine();
  EXPECT_EQ(engine->live_connection_count(), 0u);
  EXPECT_TRUE(engine->connection_strings().empty());
}

TEST(NetFlowEngineFfiTest, ConnectionStringsFormatsBothDirections) {
  auto engine = net_flow::new_flow_engine();
  auto pkt = SynPacket();
  engine->on_packet(pkt.data(), pkt.size());
  auto conns = engine->connection_strings();
  ASSERT_EQ(conns.size(), 2u);
}
```

Add `tests/net_flow_engine_ffi_test.cc` to `net_rule_grpc_test`'s `SOURCES` list in `CMakeLists.txt`.

- [ ] **Step 5: Build and run**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net_rule_grpc_test 2>&1 | tail -100"
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && ./net_rule_grpc_test --gtest_filter='NetFlowEngineFfiTest.*'"
```
Expected: clean build, all 3 smoke tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/net_flow_engine/src/lib.rs tests/net_flow_engine_ffi_test.cc CMakeLists.txt
git commit -m "Wire net_flow_engine cxx bridge; add FFI smoke test"
```

---

### Task 6: Build the differential test harness

**Files:**
- Create: `tests/net_flow_engine_differential_test.cc`
- Modify: `CMakeLists.txt` (add to `net_rule_grpc_test`'s `SOURCES`)

**Interfaces:**
- Consumes: the real, unmodified C++ `net::ConnectionManager`/`net::ipv4`/`net::Tcp` (`net/connection_manager.h`, `net/ip.h`, `net/tcp.h` — still live at this point, not yet cut over), and `net_flow::FlowEngine` via `net_flow_engine_cxxbridge/lib.h` (Task 5).

Per the design spec's Testing & Rollout section: feed identical sequences of synthetic raw IPv4+TCP byte buffers to both the real C++ `ConnectionManager` (backed by a real but filter-less `http::HttpFilterFactory`) and the new `FlowEngine`, and assert their live-flow sets agree after every packet.

- [ ] **Step 1: Write the packet generator**

```cpp
#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <random>
#include <vector>

#include "net/connection_manager.h"
#include "net_flow_engine_cxxbridge/lib.h"

namespace {

std::vector<uint8_t> BuildPacket(uint8_t protocol, uint32_t saddr, uint32_t daddr,
                                  uint16_t sport, uint16_t dport, uint32_t seq,
                                  bool syn, bool fin, bool rst,
                                  const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> p(40, 0);
  p[0] = (4 << 4) | 5;
  p[9] = protocol;
  std::memcpy(&p[12], &saddr, 4);
  std::memcpy(&p[16], &daddr, 4);
  uint16_t sport_be = htons(sport);
  uint16_t dport_be = htons(dport);
  std::memcpy(&p[20], &sport_be, 2);
  std::memcpy(&p[22], &dport_be, 2);
  uint32_t seq_be = htonl(seq);
  std::memcpy(&p[24], &seq_be, 4);
  p[32] = 5 << 4;
  uint8_t flags = 0;
  if (fin) flags |= 0x01;
  if (syn) flags |= 0x02;
  if (rst) flags |= 0x04;
  p[33] = flags;
  p.insert(p.end(), payload.begin(), payload.end());
  return p;
}

struct SyntheticEvent {
  uint32_t saddr, daddr;
  uint16_t sport, dport;
  bool syn, fin, rst;
};

std::vector<SyntheticEvent> GenerateFlowLifecycle(std::mt19937& rng, int num_flows) {
  std::uniform_int_distribution<int> octet(1, 254);
  std::uniform_int_distribution<int> port_dist(1024, 65000);
  std::vector<SyntheticEvent> events;
  for (int i = 0; i < num_flows; i++) {
    uint32_t saddr = 0, daddr = 0;
    auto* sb = reinterpret_cast<uint8_t*>(&saddr);
    auto* db = reinterpret_cast<uint8_t*>(&daddr);
    sb[0] = 10; sb[1] = 0; sb[2] = 0; sb[3] = static_cast<uint8_t>(octet(rng));
    db[0] = 10; db[1] = 0; db[2] = 0; db[3] = static_cast<uint8_t>(octet(rng));
    uint16_t sport = static_cast<uint16_t>(port_dist(rng));
    uint16_t dport = 80;
    events.push_back({saddr, daddr, sport, dport, true, false, false});   // SYN
    events.push_back({saddr, daddr, sport, dport, false, false, false}); // data
    events.push_back({saddr, daddr, sport, dport, false, true, false});  // FIN
  }
  return events;
}

}  // namespace
```

- [ ] **Step 2: Write the comparison harness**

```cpp
namespace {

std::vector<std::string> SortedConnections(net::ConnectionManager& mgr) {
  auto conns = mgr.connections();
  std::sort(conns.begin(), conns.end());
  return conns;
}

std::vector<std::string> SortedConnections(net_flow::FlowEngine& engine) {
  auto conns = engine.connection_strings();
  std::sort(conns.begin(), conns.end());
  return conns;
}

}  // namespace

TEST(NetFlowEngineDifferentialTest, FlowLifecycleMatchesCppAcrossManyFlows) {
  std::mt19937 rng(0xC0FFEE);  // fixed seed -- reproducible failures
  auto events = GenerateFlowLifecycle(rng, /*num_flows=*/50);

  http::HttpFilterFactory filter_factory;  // default-constructed: zero registered filters
  net::ConnectionManager cpp_mgr(filter_factory);
  auto rust_engine = net_flow::new_flow_engine();

  int mismatches = 0;
  for (size_t i = 0; i < events.size(); i++) {
    const auto& e = events[i];
    auto pkt = BuildPacket(6, e.saddr, e.daddr, e.sport, e.dport, 1000, e.syn, e.fin, e.rst, {});

    cpp_mgr.receive(seastar::net::packet::from_static_data(
        reinterpret_cast<char*>(pkt.data()), pkt.size()));
    rust_engine->on_packet(pkt.data(), pkt.size());

    auto cpp_conns = SortedConnections(cpp_mgr);
    auto rust_conns = SortedConnections(*rust_engine);
    if (cpp_conns != rust_conns) {
      mismatches++;
      ADD_FAILURE() << "event " << i << ": live-connection sets disagree";
    }
  }
  EXPECT_EQ(mismatches, 0) << mismatches << "/" << events.size() << " events disagreed";
}

TEST(NetFlowEngineDifferentialTest, RstOnUnknownFlowIsIgnoredByBoth) {
  http::HttpFilterFactory filter_factory;
  net::ConnectionManager cpp_mgr(filter_factory);
  auto rust_engine = net_flow::new_flow_engine();

  auto pkt = BuildPacket(6, 0x0100000A, 0x0200000A, 1234, 80, 1000,
                         /*syn=*/false, /*fin=*/false, /*rst=*/true, {});
  cpp_mgr.receive(seastar::net::packet::from_static_data(
      reinterpret_cast<char*>(pkt.data()), pkt.size()));
  rust_engine->on_packet(pkt.data(), pkt.size());

  EXPECT_TRUE(cpp_mgr.connections().empty());
  EXPECT_EQ(rust_engine->live_connection_count(), 0u);
}

TEST(NetFlowEngineDifferentialTest, DataBeforeSynIsIgnoredByBoth) {
  http::HttpFilterFactory filter_factory;
  net::ConnectionManager cpp_mgr(filter_factory);
  auto rust_engine = net_flow::new_flow_engine();

  auto pkt = BuildPacket(6, 0x0100000A, 0x0200000A, 1234, 80, 1000,
                         /*syn=*/false, /*fin=*/false, /*rst=*/false, {1, 2, 3});
  cpp_mgr.receive(seastar::net::packet::from_static_data(
      reinterpret_cast<char*>(pkt.data()), pkt.size()));
  rust_engine->on_packet(pkt.data(), pkt.size());

  EXPECT_TRUE(cpp_mgr.connections().empty());
  EXPECT_EQ(rust_engine->live_connection_count(), 0u);
}
```
Note: `net::ConnectionManager::receive` and `net::ConnectionManager::connections()` are called here at their *current* (pre-cutover) signatures — this test exercises the real, unmodified C++ path as the comparison oracle. Task 7's cutover changes `receive`'s signature; this differential test file is deleted as part of that same task, per the design spec (a comparison test stops making sense once there's only one implementation).

- [ ] **Step 3: Wire into CMake and build**

Add `tests/net_flow_engine_differential_test.cc` to `net_rule_grpc_test`'s `SOURCES` list.
```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net_rule_grpc_test 2>&1 | tail -100"
```

- [ ] **Step 4: Run and fix any real discrepancies**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && ./net_rule_grpc_test --gtest_filter='NetFlowEngineDifferentialTest.*'"
```
If this fails: read the failure output carefully (which event index, what disagreed), reproduce it as a minimal Rust unit test in `crates/net_flow_engine/src/lib.rs`, and determine whether it's a real Rust-side bug (fix it, matching the C++ behavior) or a case covered by this plan's already-flagged deliberate deviations (the IPv4-header-length bounds check). Don't silently absorb a new, un-flagged discrepancy either way. Re-run at least 3 times in a row to build confidence before moving on, since this suite gates an irreversible cutover in Task 7.

- [ ] **Step 5: Commit**

```bash
git add tests/net_flow_engine_differential_test.cc CMakeLists.txt
git commit -m "Add differential test harness comparing C++ and Rust flow tracking"
```
(If Step 4 required fixes to `crates/net_flow_engine/src/lib.rs`, include those in this commit or a preceding one with a message explaining what was wrong and why the fix is correct.)

---

### Task 7: Cutover — wire `ConnectionManager` to `FlowEngine`, delete old C++ IP/TCP code

**Files:**
- Modify: `net/connection_manager.h` (`ConnectionManager`'s `receive` signature and body; add the `ConnectionID → shared_ptr<http::Connection>` map)
- Modify: `net-policy.cpp` (both `ConnMgr().receive(...)` call sites — pass `(pkg, data_len)` directly instead of constructing a `seastar::net::packet`)
- Delete: `net/ip.h`, `net/ip.cc`, `net/tcp.h`, `net/tcp.cc`, `net/ip_protocol.h`
- Delete: `tests/net_flow_engine_differential_test.cc`
- Modify: `CMakeLists.txt` (remove `net/ip.cc`/`net/tcp.cc` and the differential test file from `SOURCES` lists)

**Interfaces:**
- Consumes: `net_flow::FlowEngine`/`new_flow_engine`/`SharedConnectionId`/`PacketDecision` (Task 5).

This is the highest-risk task in the plan — it's an irreversible-in-spirit cutover (recoverable via git, but production-facing). Read every file's actual current content before editing; do not trust this plan's line numbers.

- [ ] **Step 1: Confirm nothing else depends on the old classes**

```bash
grep -rn '\bnet::ipv4\b\|\bnet::Tcp\b\|\bnet::ConnectionID\b\|\bConnectionIDHash\b' --include='*.h' --include='*.cc' --include='*.cpp' /Users/robbieqiu/workspace/net-policy | grep -v '/net/ip\.\|/net/tcp\.'
grep -rn '\bIPProtocol\b' --include='*.h' --include='*.cc' --include='*.cpp' /Users/robbieqiu/workspace/net-policy | grep -v '/net/ip_protocol\.h\|/net/ip\.h\|/net/tcp\.h\|/net/udp\.h'
```
Every remaining hit must be inside a file this task explicitly modifies. `IPProtocol` (`net/ip_protocol.h`) should show zero hits outside its own declaration and the two now-deleted-or-being-deleted implementers (`Tcp`, already-deleted `Udp`) — it's a virtual interface with no other consumer once `ipv4`'s `l4_` dispatch table goes away in this same task, so it's deleted alongside `Tcp`, not left behind (see Global Constraints / design spec Non-Goals). If something unexpected turns up, stop and re-scope.

- [ ] **Step 2: Move `ConnectionID`/`ConnectionIDHash` into `net/utility.h`, then rewrite `ConnectionManager` in `net/connection_manager.h`**

`ConnectionID`/`ConnectionIDHash` (`net/tcp.h`) are plain structs with no logic tying them to `Tcp` — they're about to be needed by `net/connection_manager.h` after `net/tcp.h` is deleted later in this same task, so move their declarations into `net/utility.h` first (read `net/tcp.h`'s current declarations of both before moving them verbatim — they should match this plan's earlier Task 4 excerpt, but confirm), alongside the existing `NetStatus`/`NetworkStat`. Leave `net/tcp.h` itself in place for now — Step 4 deletes it once this step's edits compile.

Then read `net/connection_manager.h`'s current content (it should still resemble what's quoted in the design spec, but confirm) and replace it with:
```cpp
#pragma once

#include <glog/logging.h>
#include <memory>
#include <unordered_map>
#include <utility>

#include "http/connection.h"
#include "http/http_filter_factory.h"
#include "http/packet.hh"
#include "net/stream.h"   // ConnectionInfo -- direct include; after this task
                           // deletes net/tcp.h (which used to provide it
                           // transitively) and Task 1 removed net/utility.h's
                           // now-dangling include of the deleted net/filter.h
                           // (which also used to chain to it), nothing else
                           // in net/ pulls this in anymore
#include "net/utility.h"  // now also declares ConnectionID / ConnectionIDHash
#include "net_flow_engine_cxxbridge/lib.h"

namespace net {

class ConnectionManager {
public:
  explicit ConnectionManager(http::HttpFilterFactory& filter_factory)
      : filter_factory_(filter_factory), engine_(net_flow::new_flow_engine()) {}

  NetStatus receive(const uint8_t* pkg, size_t len) {
    auto decision = engine_->on_packet(pkg, len);
    switch (decision.kind) {
      case 0:  // Ignore
        return NetStatus::OK;
      case 1:  // NewConnection
        return HandleNewConnection(decision, pkg, len);
      case 2:  // Closed
        return HandleClosed(decision);
      case 3:  // Data
        return HandleData(decision, pkg, len);
      default:
        return NetStatus::OK;
    }
  }

  NetworkStat stat() { NetworkStat st{}; st.tcp_conn_ = engine_->live_connection_count(); return st; }

  std::vector<std::string> connections() { return engine_->connection_strings(); }

private:
  static ConnectionID ToConnectionID(const net_flow::SharedConnectionId& id) {
    return ConnectionID{id.local_ip, id.foreign_ip, id.local_port, id.foreign_port};
  }

  NetStatus HandleNewConnection(const net_flow::PacketDecision& decision, const uint8_t* pkg, size_t len) {
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
    it->second->httpFilterManager()->setTCPSegment(p);
    p.trim_front(decision.payload_offset);
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
- [ ] **Step 3: Update `net-policy.cpp`'s two call sites**

Read the current call sites (`net-policy.cpp`, search for `ConnMgr().receive`) to confirm they still match:
```cpp
auto status =
    daemon->ConnMgr().receive(seastar::net::packet::from_static_data((char*)pkg, data_len));
```
Replace both occurrences with:
```cpp
auto status = daemon->ConnMgr().receive(reinterpret_cast<const uint8_t*>(pkg), data_len);
```

- [ ] **Step 4: Delete `net/ip.{h,cc}`, `net/tcp.{h,cc}`, and the now-orphaned `net/ip_protocol.h`; update CMakeLists.txt**

```bash
git rm net/ip.h net/ip.cc net/tcp.h net/tcp.cc net/ip_protocol.h
git rm tests/net_flow_engine_differential_test.cc
```
Remove `net/ip.cc` and `net/tcp.cc` from every `SOURCES` list in `CMakeLists.txt` that has them (`net-rule`, `net_rule_grpc_test` — confirm `net_rule_test` never had them, per Global Constraints; `net/ip_protocol.h` is header-only and was never in a `SOURCES` list). Remove `tests/net_flow_engine_differential_test.cc` from `net_rule_grpc_test`'s `SOURCES`.

- [ ] **Step 5: Build and run everything**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && ./net_rule_test && ./net_rule_grpc_test"
```
Expected: clean build under `-Wall -Werror` (zero new warnings — `net::ipv4`/`net::Tcp` no longer exist anywhere, so this should compile without them), every test passes, including `NetFlowEngineFfiTest.*` (Task 5, now exercising what's actually wired into production) and `ConnectionManagerTest.onData`/`DumpConnectionsReturnsWithoutError` (existing tests, unaffected by this task's changes in behavior, but the closest thing to an integration-level regression check for this cutover). Run `net_rule_grpc_test` at least 3 times to check for flakiness.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Cut over TCP/IP flow tracking to the Rust engine; delete old C++ implementation"
```

---

## Definition of Done

- `docker exec net-policy-build-test bash -lc "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc)"` builds `net-rule`, `net_rule_test`, and `net_rule_grpc_test` with no new warnings under `-Wall -Werror`.
- `./net_rule_test` and `./net_rule_grpc_test` both pass in full.
- `net::ipv4`, `net::Tcp`, `net::Tcp::Tcb`, `net::NetworkFilterManager`, `net::NetworkFilterBase`, `net::Udp`, `net::IPProtocol` no longer exist as C++ classes; `net::ConnectionManager` delegates all IPv4/TCP parsing and flow tracking to `net_flow::FlowEngine` via an owned `rust::Box`.
- `net/filter.{h,cc}`, `net/udp.{h,cc}`, `net/ip.{h,cc}`, `net/tcp.{h,cc}`, `net/ip_protocol.h` no longer exist in the codebase.
- `seastar::net::packet` is never constructed or referenced inside `net_flow_engine` or its FFI surface — it appears only in `net::ConnectionManager::HandleData`, at the single point payload bytes are handed to the unchanged HTTP filter chain.
- `http::HttpFilterManager`, `http::Connection`, `http::HttpFilterFactory`, and everything under `http/`/`waf/` required zero changes.
