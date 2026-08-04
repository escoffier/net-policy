use std::time::{Duration, Instant};

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

    #[derive(Default)]
    struct PacketDecision {
        /// 0 = Ignore, 1 = NewConnection, 2 = Closed, 3 = Data, 4 = Duplicate,
        /// 5 = UnknownData
        kind: i32,
        conn_id: SharedConnectionId,
        peer_conn_id: SharedConnectionId,
        peer_is_new: bool,
        /// Byte length of the IPv4 header alone -- separate from
        /// `payload_offset` (IP + TCP header combined). Only meaningful when
        /// `kind == Data` (kind 3). C++'s HandleData (net/connection_manager.h)
        /// MUST trim the packet by exactly this amount before calling
        /// `setTCPSegment`, and by `payload_offset - ip_header_len` after --
        /// matching `setTCPSegment`'s contract that its input packet already
        /// starts at the TCP header (see waf/plugin.cc's ModifyNetPackets,
        /// which casts the stored pointer directly to `struct tcphdr*`).
        /// Trimming by the combined `payload_offset` before `setTCPSegment`,
        /// or not trimming at all before it, corrupts live packets.
        ip_header_len: u32,
        payload_offset: u32,
        /// Whether this packet has the TCP SYN flag set. Populated for every
        /// kind that carries a parsed TCP header (1-5); false for kind 0
        /// (Ignore), where no decision fields are meaningful at all.
        ///
        /// This is NOT redundant with `kind == NewConnection`. NewConnection
        /// additionally requires the flow to be absent from the TCB table, so
        /// two very common SYN-flagged packet classes are not kind 1: a
        /// SYN-ACK (its direction's entry was already seeded by the initiating
        /// SYN, so it arrives as Data) and a SYN retransmission (same seq as
        /// the tracked one, so it arrives as Duplicate). The C++ callbacks'
        /// microsegmentation path must treat all three alike -- it is
        /// reconstructing the old `tcphdr.syn != 0` test, which was blind to
        /// TCB state.
        syn: bool,
    }

    extern "Rust" {
        type FlowEngine;

        fn new_flow_engine() -> Box<FlowEngine>;
        unsafe fn on_packet(self: &mut FlowEngine, pkg: *const u8, len: usize) -> PacketDecision;
        fn live_connection_count(self: &FlowEngine) -> usize;
        fn connection_strings(self: &FlowEngine) -> Vec<String>;
        fn evict_stale_connections(self: &mut FlowEngine) -> Vec<SharedConnectionId>;
        fn stale_connection_timeout_secs() -> u64;

        unsafe fn parse_five_tuple(pkg: *const u8, len: usize) -> SharedFiveTuple;
    }
}

const KIND_IGNORE: i32 = 0;
const KIND_NEW_CONNECTION: i32 = 1;
const KIND_CLOSED: i32 = 2;
const KIND_DATA: i32 = 3;
const KIND_DUPLICATE: i32 = 4;
const KIND_UNKNOWN_DATA: i32 = 5;

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

impl FlowEngine {
    /// # Safety
    /// `pkg` must point to at least `len` readable bytes; the caller (the
    /// still-C++ NFQ callback in net-policy.cpp) owns that buffer for the
    /// duration of this call and does not mutate it concurrently.
    unsafe fn on_packet(&mut self, pkg: *const u8, len: usize) -> ffi::PacketDecision {
        let bytes = std::slice::from_raw_parts(pkg, len);
        match self.on_packet_internal(bytes, Instant::now()) {
            None => ffi::PacketDecision { kind: KIND_IGNORE, ..Default::default() },
            Some(d) => {
                let kind = match d.kind {
                    PacketKind::NewConnection => KIND_NEW_CONNECTION,
                    PacketKind::Closed => KIND_CLOSED,
                    PacketKind::Data => KIND_DATA,
                    PacketKind::Duplicate => KIND_DUPLICATE,
                    PacketKind::UnknownData => KIND_UNKNOWN_DATA,
                };
                ffi::PacketDecision {
                    kind,
                    conn_id: d.conn_id.into(),
                    peer_conn_id: d.peer_conn_id.into(),
                    peer_is_new: d.peer_is_new,
                    ip_header_len: d.ip_header_len,
                    payload_offset: d.payload_offset,
                    syn: d.syn,
                }
            }
        }
    }
}

const IPV4_HDR_MIN_LEN: usize = 20;

struct Ipv4Header {
    header_len: usize,
    protocol: u8,
    saddr: u32,
    daddr: u32,
    tot_len: u16,
}

fn parse_ipv4_header(bytes: &[u8]) -> Option<Ipv4Header> {
    if bytes.len() < IPV4_HDR_MIN_LEN {
        return None;
    }
    let ihl = (bytes[0] & 0x0F) as usize;
    let header_len = ihl * 4;
    // Three deliberate deviations from the current C++ (see Global
    // Constraints), all in the same spirit -- strictly more defensive than
    // the C++, malformed-packet-only, and with no effect on well-formed
    // traffic:
    //   1. `header_len < IPV4_HDR_MIN_LEN` (i.e. ihl < 5): reject an IHL that
    //      claims a header shorter than the fixed 20-byte minimum, instead of
    //      trusting ihl unconditionally.
    //   2. `bytes.len() < header_len`: reject a header claiming more bytes
    //      than are actually present in the buffer.
    //   3. parse_tcp_header below applies the analogous bounds check against
    //      the buffer length it's handed, whereas the old C++ only checked
    //      the fixed minimum TCP header length, not the claimed doff length.
    if header_len < IPV4_HDR_MIN_LEN || bytes.len() < header_len {
        return None;
    }
    let protocol = bytes[9];
    let saddr = u32::from_ne_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let daddr = u32::from_ne_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let tot_len = u16::from_be_bytes([bytes[2], bytes[3]]);
    Some(Ipv4Header { header_len, protocol, saddr, daddr, tot_len })
}

fn ipv4_to_string(ip: u32) -> String {
    let b = ip.to_ne_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

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
    // `bytes.len() < header_len` is deliberate deviation #3 documented on
    // parse_ipv4_header above: reject a doff claiming more bytes than the
    // buffer actually has, instead of only checking against the fixed
    // TCP_HDR_MIN_LEN as the old C++ did.
    if header_len < TCP_HDR_MIN_LEN || bytes.len() < header_len {
        return None;
    }
    let flags = bytes[13];
    let fin = flags & 0x01 != 0;
    let syn = flags & 0x02 != 0;
    let rst = flags & 0x04 != 0;
    Some(TcpHeader { header_len, source, dest, seq, syn, fin, rst })
}

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
        FiveTupleResult {
            proto: 0,
            tot_len: 0,
            ip_header_len: 0,
            src_port: 0,
            dst_port: 0,
            src_addr: 0,
            dst_addr: 0,
            recognized: false,
        }
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

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct ConnectionId {
    local_ip: u32,
    foreign_ip: u32,
    local_port: u16,
    foreign_port: u16,
}

// `server_side` is written but never read -- this mirrors the old C++'s
// Tcb::server_side_, which is also write-only. A faithful port, not a bug;
// kept for parity with the C++ TCB and for future use. `seq` and `last_seen`
// are now genuinely read: `seq` by the duplicate-segment check below, and
// `last_seen` by Task 2's reaper.
struct FlowState {
    seq: u32,
    server_side: bool,
    last_seen: Instant,
}

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

struct PacketDecision {
    kind: PacketKind,
    conn_id: ConnectionId,
    peer_conn_id: ConnectionId,
    /// mirrors Tcp::receive's `peer_it == tcbs_.end()` check -- whether the
    /// reverse-direction flow entry was newly created by this packet too
    /// (only meaningful when kind == NewConnection).
    peer_is_new: bool,
    /// byte length of the IPv4 header alone (i.e. where the TCP header
    /// begins in the ORIGINAL buffer); only meaningful when kind == Data.
    ip_header_len: u32,
    /// byte offset into the ORIGINAL (ip header included) buffer where the
    /// TCP payload begins; only meaningful when kind == Data.
    payload_offset: u32,
    /// the packet's raw TCP SYN flag -- see ffi::PacketDecision::syn for why
    /// this is distinct from `kind == NewConnection`.
    syn: bool,
}

pub struct FlowEngine {
    tcbs: HashMap<ConnectionId, FlowState>,
}

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
                    syn: tcp.syn,
                });
            }
            if tcp.seq < state.seq {
                // Duplicate/retransmitted segment -- do not advance tracked
                // seq, do not update last_seen (an entry that only ever
                // receives retransmits of old data is not "active" for
                // reaper purposes; this mirrors treating it as if this
                // packet never fully arrived).
                return Some(PacketDecision {
                    kind: PacketKind::Duplicate,
                    conn_id: id,
                    peer_conn_id: peer_id,
                    peer_is_new: false,
                    ip_header_len,
                    payload_offset,
                    syn: tcp.syn,
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
                syn: tcp.syn,
            });
        }

        // Unknown flow.
        if tcp.rst {
            return None; // unchanged from Phase 5 -- deliberately NOT
                          // extended to UnknownData; see plan's Global
                          // Constraints for why.
        }
        if tcp.syn {
            self.tcbs.insert(
                id,
                FlowState { seq: tcp.seq.wrapping_add(1), server_side: true, last_seen: now },
            );
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
                syn: true,
            });
        }
        // Neither RST nor SYN on an unknown flow -- previously a silent
        // no-op (returned None); now an explicit UnknownData decision so
        // microseg's late-binding recovery can use it. ip_header_len/
        // payload_offset ARE populated here (unlike NewConnection/Closed)
        // because microseg needs them to extract the payload for its
        // onData() call.
        Some(PacketDecision {
            kind: PacketKind::UnknownData,
            conn_id: id,
            peer_conn_id: peer_id,
            peer_is_new: false,
            syn: tcp.syn,
            ip_header_len,
            payload_offset,
        })
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

    /// Removes TCB entries whose `last_seen` is at least `timeout` behind
    /// `now`, returning the IDs removed. Note a peer entry is evicted
    /// independently by its OWN `last_seen`, not automatically alongside its
    /// counterpart, since each side of a flow accrues activity independently
    /// (e.g. a long-lived one-directional stream).
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

    /// # Safety: none -- no raw pointers, safe to call directly (unlike
    /// on_packet/parse_five_tuple).
    fn evict_stale_connections(&mut self) -> Vec<ffi::SharedConnectionId> {
        self.evict_stale(Instant::now(), STALE_CONNECTION_TIMEOUT)
            .into_iter()
            .map(Into::into)
            .collect()
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

/// The entry-age threshold `evict_stale_connections` applies, in seconds.
///
/// Exposed over FFI because the C++ side has to age out flow state this
/// engine's `tcbs` table can never contain: a flow the daemon never saw a SYN
/// for is never inserted into `tcbs` (only the SYN branch of
/// `on_packet_internal` inserts), so every packet on it arrives as
/// `UnknownData` forever and it can never appear in `evict_stale_connections`'
/// output -- yet C++'s microsegmentation map late-binds an entry for exactly
/// that flow. That sweep lives in C++ (net/connection_manager.h's
/// `ConnectionManager::EvictStale`) because the state being swept is C++'s;
/// this getter exists so it applies the SAME timeout rather than a second,
/// independently-drifting copy of the number.
fn stale_connection_timeout_secs() -> u64 {
    STALE_CONNECTION_TIMEOUT.as_secs()
}

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
        let now = Instant::now();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp = tcp_segment(1234, 80, 1000, true, false, false, &[]);
        let decision = engine.on_packet_internal(&packet(ip, tcp), now).expect("should decide");
        assert_eq!(decision.kind, PacketKind::NewConnection);
        assert!(decision.peer_is_new);
        assert_eq!(engine.live_connection_count(), 2); // both directions tracked
    }

    #[test]
    fn syn_on_the_auto_created_peer_placeholder_is_treated_as_data() {
        // A verified quirk of the real C++ Tcp::receive, replicated bug-for-bug
        // (not re-derived from first principles): the forward SYN below inserts
        // a TCB for A->B AND, since no B->A entry exists yet, an auto-created
        // placeholder TCB for B->A too (so a future response has somewhere to
        // land) -- keyed by the EXACT ConnectionID a genuine B->A SYN would use.
        // So a real SYN arriving in the reverse direction finds that placeholder
        // already present, takes the "known flow" branch (which only checks
        // FIN/RST, never SYN), and is treated as a Data packet -- NOT a second
        // NewConnection. This was verified by hand-tracing net/tcp.cc's
        // ConnectionID field mapping, not assumed.
        let mut engine = FlowEngine::new();
        let now = Instant::now();
        let ip_fwd = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp_fwd = tcp_segment(1234, 80, 1000, true, false, false, &[]);
        engine.on_packet_internal(&packet(ip_fwd, tcp_fwd), now).unwrap();

        let ip_rev = ipv4_header(6, [10, 0, 0, 2], [10, 0, 0, 1]);
        let tcp_rev = tcp_segment(80, 1234, 2000, true, false, false, &[]);
        let decision =
            engine.on_packet_internal(&packet(ip_rev, tcp_rev), now).expect("should decide");
        assert_eq!(decision.kind, PacketKind::Data);
        // ...but it IS still a SYN-flagged packet, and consumers reconstructing
        // the old C++ microseg path's `tcphdr.syn != 0` test must be able to
        // see that. Checking `kind == NewConnection` instead would classify
        // every SYN-ACK in the system as an ordinary data segment.
        assert!(decision.syn);
    }

    #[test]
    fn syn_retransmission_is_duplicate_but_still_reports_syn() {
        // A retransmitted SYN carries the same seq as the original, which the
        // duplicate check (tcp.seq < state.seq, state.seq being seq+1) catches
        // before anything looks at flags -- so it arrives as Duplicate, not
        // NewConnection. Same rationale as the SYN-ACK case above: a consumer
        // reconstructing `tcphdr.syn != 0` must still see the flag, otherwise
        // a DENY policy that blocked the first SYN would silently let the
        // retransmit through and the handshake would complete.
        let mut engine = FlowEngine::new();
        let now = Instant::now();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let syn = tcp_segment(1234, 80, 1000, true, false, false, &[]);

        let first = engine
            .on_packet_internal(&packet(ip.clone(), syn.clone()), now)
            .expect("should decide");
        assert_eq!(first.kind, PacketKind::NewConnection);
        assert!(first.syn);

        let retransmit =
            engine.on_packet_internal(&packet(ip, syn), now).expect("should decide");
        assert_eq!(retransmit.kind, PacketKind::Duplicate);
        assert!(retransmit.syn);
    }

    #[test]
    fn non_syn_packets_do_not_report_syn() {
        // Negative control for the two tests above -- without this, `syn: true`
        // hard-coded everywhere would pass them both.
        let mut engine = FlowEngine::new();
        let now = Instant::now();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let syn = tcp_segment(1234, 80, 1000, true, false, false, &[]);
        engine.on_packet_internal(&packet(ip.clone(), syn), now).unwrap();

        let data = tcp_segment(1234, 80, 1001, false, false, false, b"hello");
        let d = engine.on_packet_internal(&packet(ip.clone(), data), now).expect("should decide");
        assert_eq!(d.kind, PacketKind::Data);
        assert!(!d.syn);

        let fin = tcp_segment(1234, 80, 1006, false, true, false, &[]);
        let d = engine.on_packet_internal(&packet(ip, fin), now).expect("should decide");
        assert_eq!(d.kind, PacketKind::Closed);
        assert!(!d.syn);
    }

    #[test]
    fn data_packet_on_established_flow_reports_payload_offset() {
        let mut engine = FlowEngine::new();
        let now = Instant::now();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp_syn = tcp_segment(1234, 80, 1000, true, false, false, &[]);
        engine.on_packet_internal(&packet(ip.clone(), tcp_syn), now).unwrap();

        let tcp_data = tcp_segment(1234, 80, 1001, false, false, false, b"hello");
        let decision =
            engine.on_packet_internal(&packet(ip, tcp_data), now).expect("should decide");
        assert_eq!(decision.kind, PacketKind::Data);
        assert_eq!(decision.ip_header_len, 20);
        assert_eq!(decision.payload_offset, 40); // 20-byte IP + 20-byte TCP header
    }

    #[test]
    fn fin_closes_both_directions() {
        let mut engine = FlowEngine::new();
        let now = Instant::now();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp_syn = tcp_segment(1234, 80, 1000, true, false, false, &[]);
        engine.on_packet_internal(&packet(ip.clone(), tcp_syn), now).unwrap();
        assert_eq!(engine.live_connection_count(), 2);

        let tcp_fin = tcp_segment(1234, 80, 1001, false, true, false, &[]);
        let decision = engine.on_packet_internal(&packet(ip, tcp_fin), now).expect("should decide");
        assert_eq!(decision.kind, PacketKind::Closed);
        assert_eq!(engine.live_connection_count(), 0);
    }

    #[test]
    fn rst_on_unknown_flow_is_ignored() {
        let mut engine = FlowEngine::new();
        let now = Instant::now();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp_rst = tcp_segment(1234, 80, 1000, false, false, true, &[]);
        assert!(engine.on_packet_internal(&packet(ip, tcp_rst), now).is_none());
        assert_eq!(engine.live_connection_count(), 0);
    }

    #[test]
    fn rst_on_unknown_flow_is_still_ignored_not_unknown_data() {
        // Deliberate, documented narrowing from the old C++ (see plan's Global
        // Constraints) -- RST on an unknown flow stays a no-op, not UnknownData.
        let mut engine = FlowEngine::new();
        let now = Instant::now();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp_rst = tcp_segment(1234, 80, 1000, false, false, true, &[]);
        assert!(engine.on_packet_internal(&packet(ip, tcp_rst), now).is_none());
    }

    #[test]
    fn ack_on_unknown_flow_is_unknown_data() {
        // Behavior change from this task: a bare ACK (non-SYN, non-RST) on a
        // flow this engine never saw a SYN for used to be a silent None; it's
        // now an explicit UnknownData decision (see PacketKind::UnknownData
        // doc comment) so microseg's late-binding recovery can use it. WAF's
        // behavior is unchanged -- it still treats this as a no-op.
        let mut engine = FlowEngine::new();
        let now = Instant::now();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp_ack = tcp_segment(1234, 80, 1000, false, false, false, &[]);
        let decision =
            engine.on_packet_internal(&packet(ip, tcp_ack), now).expect("should decide");
        assert_eq!(decision.kind, PacketKind::UnknownData);
        assert_eq!(engine.live_connection_count(), 0);
    }

    #[test]
    fn duplicate_segment_is_recognized_and_does_not_regress_tracked_seq() {
        let mut engine = FlowEngine::new();
        let now = Instant::now();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);

        let tcp_syn = tcp_segment(1234, 80, 1000, true, false, false, &[]);
        let d1 = engine.on_packet_internal(&packet(ip.clone(), tcp_syn), now).expect("syn decision");
        assert_eq!(d1.kind, PacketKind::NewConnection);

        // First data segment: seq 1001, 10 bytes of payload.
        let tcp_data1 = tcp_segment(1234, 80, 1001, false, false, false, b"0123456789");
        let d2 = engine
            .on_packet_internal(&packet(ip.clone(), tcp_data1.clone()), now)
            .expect("data decision");
        assert_eq!(d2.kind, PacketKind::Data);

        // Replay the SAME segment (retransmission) -- must be recognized as
        // Duplicate, and must NOT advance the tracked seq past what data1
        // already advanced it to.
        let d3 = engine
            .on_packet_internal(&packet(ip.clone(), tcp_data1), now)
            .expect("duplicate decision");
        assert_eq!(d3.kind, PacketKind::Duplicate);

        // A genuinely new segment continuing from where data1 left off must
        // still be accepted as Data (proves the duplicate check didn't
        // corrupt tracked state).
        let tcp_data2 = tcp_segment(1234, 80, 1011, false, false, false, b"abcde");
        let d4 = engine
            .on_packet_internal(&packet(ip, tcp_data2), now)
            .expect("second data decision");
        assert_eq!(d4.kind, PacketKind::Data);
    }

    #[test]
    fn non_syn_non_rst_on_unknown_flow_returns_unknown_data() {
        let mut engine = FlowEngine::new();
        let now = Instant::now();

        // A bare data/ACK packet with no prior SYN ever seen for this flow.
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp = tcp_segment(1234, 80, 5000, false, false, false, b"GET / HTTP/1.1\r\n");
        let decision = engine
            .on_packet_internal(&packet(ip, tcp), now)
            .expect("unknown-data decision");
        assert_eq!(decision.kind, PacketKind::UnknownData);
        // payload_offset/ip_header_len must still be populated -- microseg's
        // late-binding path needs them to extract the payload.
        assert!(decision.payload_offset > 0);
    }

    #[test]
    fn non_tcp_protocol_is_ignored() {
        let mut engine = FlowEngine::new();
        let now = Instant::now();
        let ip = ipv4_header(1 /* ICMP */, [10, 0, 0, 1], [10, 0, 0, 2]);
        assert!(engine.on_packet_internal(&ip, now).is_none());
    }

    #[test]
    fn connection_strings_reports_both_directions() {
        let mut engine = FlowEngine::new();
        let now = Instant::now();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp = tcp_segment(1234, 80, 1000, true, false, false, &[]);
        engine.on_packet_internal(&packet(ip, tcp), now).unwrap();
        let mut conns = engine.connection_strings();
        conns.sort();
        assert_eq!(conns, vec!["10.0.0.1:1234,10.0.0.2:80", "10.0.0.2:80,10.0.0.1:1234"]);
    }

    #[test]
    fn evict_stale_removes_only_entries_past_the_timeout() {
        let mut engine = FlowEngine::new();
        let t0 = Instant::now();

        // Flow A: will go stale.
        let ip_a = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp_a = tcp_segment(1234, 80, 1000, true, false, false, &[]);
        engine.on_packet_internal(&packet(ip_a, tcp_a), t0).unwrap();

        // Flow B: a different five-tuple (different src IP/port), created
        // 400s after flow A. Stays fresh relative to t2 below.
        let t1 = t0 + Duration::from_secs(400);
        let ip_b = ipv4_header(6, [10, 0, 0, 3], [10, 0, 0, 4]);
        let tcp_b = tcp_segment(5555, 80, 2000, true, false, false, &[]);
        engine.on_packet_internal(&packet(ip_b, tcp_b), t1).unwrap();

        assert_eq!(engine.live_connection_count(), 4); // both directions of A and B

        // t2 is 600s after t0 (flow A stale under a 300s timeout: 600s >=
        // 300s) but only 200s after t1 (flow B fresh: 200s < 300s).
        let t2 = t0 + Duration::from_secs(600);
        let evicted = engine.evict_stale(t2, Duration::from_secs(300));

        assert_eq!(evicted.len(), 2); // both directions of flow A only
        assert_eq!(engine.live_connection_count(), 2); // only flow B (both directions) survives

        let mut conns = engine.connection_strings();
        conns.sort();
        assert_eq!(conns, vec!["10.0.0.3:5555,10.0.0.4:80", "10.0.0.4:80,10.0.0.3:5555"]);
    }

    // The C++ side's own sweep of late-bound microsegmentation entries (flows
    // that were never in `tcbs`, so `evict_stale_connections` can never report
    // them) reads its timeout from this getter rather than hardcoding a second
    // copy of the number. Assert it reports the SAME timeout
    // `evict_stale_connections` actually applies, in the unit the FFI name
    // promises -- an `as_millis`/`as_secs` slip here would silently make the
    // C++ sweep 1000x too eager or too lazy.
    #[test]
    fn stale_connection_timeout_secs_matches_the_applied_timeout() {
        assert_eq!(stale_connection_timeout_secs(), STALE_CONNECTION_TIMEOUT.as_secs());
        assert_eq!(stale_connection_timeout_secs(), 300);
    }

    #[test]
    fn evict_stale_returns_both_sides_of_an_evicted_flow() {
        let mut engine = FlowEngine::new();
        let t0 = Instant::now();
        let ip = ipv4_header(6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp = tcp_segment(1234, 80, 1000, true, false, false, &[]);
        let decision = engine.on_packet_internal(&packet(ip, tcp), t0).unwrap();

        let evicted = engine.evict_stale(t0 + Duration::from_secs(9999), Duration::from_secs(300));
        // Both conn_id and peer_conn_id should be gone.
        assert!(evicted.contains(&decision.conn_id));
        assert!(evicted.contains(&decision.peer_conn_id));
        assert_eq!(engine.live_connection_count(), 0);
    }
}

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
