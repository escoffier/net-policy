#[cxx::bridge(namespace = "net_flow")]
mod ffi {
    extern "Rust" {
        fn net_flow_engine_ffi_smoke() -> i32;
    }
}

fn net_flow_engine_ffi_smoke() -> i32 {
    42
}

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
            if tcp.syn {
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
