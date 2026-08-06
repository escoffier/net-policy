#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>

#include "http/http_filter_factory.h"
#include "net-policy.h"
#include "net/connection_manager.h"
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

namespace {

// 20-byte IPv4 header (saddr=10.0.0.1, daddr=10.0.0.2, protocol=TCP) followed
// by a 20-byte TCP header (source=1234, dest=80, doff=5, no flags -- an
// established-flow data segment, not the SYN) followed by `payload`.
std::vector<uint8_t> DataPacket(bool syn, const std::string& payload) {
  std::vector<uint8_t> p(40, 0);
  p[0] = (4 << 4) | 5;  // version=4, ihl=5
  p[9] = 6;             // protocol=TCP
  p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 1;   // saddr
  p[16] = 10; p[17] = 0; p[18] = 0; p[19] = 2;   // daddr
  p[20] = 0x04; p[21] = 0xD2;  // source port 1234 (matches SynPacket())
  p[22] = 0x00; p[23] = 0x50;  // dest port 80
  p[32] = 5 << 4;              // doff=5
  p[33] = syn ? 0x02 : 0x00;   // SYN flag iff requested
  p.insert(p.end(), payload.begin(), payload.end());
  return p;
}

// Same 4-tuple as SynPacket()/DataPacket(), FIN flag set instead of SYN --
// closes an already-established flow.
std::vector<uint8_t> FinPacket() {
  std::vector<uint8_t> p(40, 0);
  p[0] = (4 << 4) | 5;  // version=4, ihl=5
  p[9] = 6;             // protocol=TCP
  p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 1;   // saddr
  p[16] = 10; p[17] = 0; p[18] = 0; p[19] = 2;   // daddr
  p[20] = 0x04; p[21] = 0xD2;  // source port 1234
  p[22] = 0x00; p[23] = 0x50;  // dest port 80
  p[32] = 5 << 4;              // doff=5
  p[33] = 0x01;                // FIN
  return p;
}

}  // namespace

// End-to-end coverage for the full input_nfq_cb-shaped call sequence against
// the real ConnectionManager: a non-TCP (UDP) packet must still come back
// with a recognized five-tuple (L3-L4 policy matching needs this for every
// packet, not just TCP), while `decision` stays untouched -- on_packet is
// only ever invoked for TCP packets (see ReceiveResult::receive's doc
// comment), so a UDP packet must never reach it, tracking or not.
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

  auto result = manager.receive(udp_pkt.data(), udp_pkt.size(), /*track_tcp=*/false);
  EXPECT_TRUE(result.tuple.recognized);
  EXPECT_EQ(result.tuple.proto, 17);
  EXPECT_FALSE(result.is_tcp);
  // decision.kind should be left default (0/Ignore) -- on_packet was never
  // called for a non-TCP packet.
  EXPECT_EQ(result.decision.kind, 0);
}

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
TEST(ConnectionManagerCutoverTest, TcpPacketWithTrackingOffDoesNotEnterTcbTable) {
  http::HttpFilterFactory filter_factory;
  net::ConnectionManager manager(filter_factory);

  auto syn = SynPacket();
  auto result = manager.receive(syn.data(), syn.size(), /*track_tcp=*/false);

  // The five-tuple parse and the is_tcp classification are deliberately NOT
  // gated on track_tcp -- L3-L4 policy matching and net-policy.cpp's downstream
  // microsegmentation TCP-tracking block need both on every packet, whatever
  // the WAF's state.
  EXPECT_TRUE(result.tuple.recognized);
  EXPECT_TRUE(result.is_tcp);
  EXPECT_EQ(result.tuple.proto, 6);
  // on_packet was never called, so decision stays default-constructed.
  EXPECT_EQ(result.decision.kind, 0);
  // ...and, the point of the gate: no TCB entry was created.
  EXPECT_EQ(manager.stat().tcp_conn_, 0u);

  // Positive control on the same manager and the same packet: with tracking on,
  // this SYN does create TCB state (the flow plus its peer -- see
  // NetFlowEngineFfiTest.SynPacketCreatesNewConnection). Without this, the
  // assertions above would also pass for a SYN that simply could not be
  // tracked at all.
  auto tracked = manager.receive(syn.data(), syn.size(), /*track_tcp=*/true);
  EXPECT_TRUE(tracked.is_tcp);
  EXPECT_EQ(tracked.decision.kind, 1);  // NewConnection
  EXPECT_EQ(manager.stat().tcp_conn_, 2u);
}

TEST(NetFlowEngineFfiTest, DuplicateSegmentReturnsKind4) {
  auto engine = net_flow::new_flow_engine();
  auto syn = SynPacket();
  engine->on_packet(syn.data(), syn.size());

  // DataPacket helper doesn't set sequence numbers (defaults to 0), so we
  // manually set it to 1 to follow the SYN (which has seq=0, leaving state.seq=1).
  auto data = DataPacket(/*syn=*/false, "hello");
  // TCP sequence number is at bytes 4-7 of the TCP header (20 bytes into the packet).
  uint32_t seq_be = htonl(1);  // seq=1 in network byte order
  std::memcpy(data.data() + 24, &seq_be, sizeof(seq_be));

  auto d1 = engine->on_packet(data.data(), data.size());
  ASSERT_EQ(d1.kind, 3);  // Data
  auto d2 = engine->on_packet(data.data(), data.size());  // replay with same seq
  EXPECT_EQ(d2.kind, 4);  // Duplicate
}

TEST(NetFlowEngineFfiTest, NonSynNonRstOnUnknownFlowReturnsKind5) {
  auto engine = net_flow::new_flow_engine();
  auto data = DataPacket(/*syn=*/false, "GET / HTTP/1.1\r\n");  // no prior SYN
  auto decision = engine->on_packet(data.data(), data.size());
  EXPECT_EQ(decision.kind, 5);  // UnknownData
  EXPECT_GT(decision.payload_offset, 0u);
}

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
  // DataPacket() defaults its TCP sequence number to 0, same as SynPacket()'s
  // SYN -- which would make the engine treat this as a retransmission of the
  // SYN (Duplicate, kind 4) rather than the next segment (Data, kind 3). The
  // SYN consumes sequence number 0, so the next real segment must carry
  // seq=1. TCP sequence number is at byte offset 24 (20-byte IP header + 4
  // bytes into the TCP header).
  uint32_t seq_be = htonl(1);
  std::memcpy(data.data() + 24, &seq_be, sizeof(seq_be));
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

// Direct coverage for DispatchMicroseg's case 5 (UnknownData) -- the
// late-binding path this plan's own drafting history flagged as previously
// bug-prone (a double-dispatch-call risk caught and fixed before Task 4 was
// even written; see the case 1 vs case 5 split's comments in
// net/connection_manager.h). Unlike NewConnectionThenDataProducesHeaderWhenTracked
// above (which reaches case 1 then case 3 via a SYN followed by a Data
// packet), this test sends a data packet with NO prior SYN, so
// net_flow_engine's on_packet_internal has never seen this flow and returns
// kind 5 (UnknownData) -- and DispatchMicroseg's case 5 must do BOTH the
// first-sight insert AND the HTTP header extraction in that single call.
TEST(ConnectionManagerMicrosegTest, UnknownDataLateBindsAndExtractsHeaderInOneCall) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  auto data = DataPacket(/*syn=*/false, "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n");
  auto result = mgr.receive(data.data(), data.size(), /*track_tcp=*/true);
  ASSERT_EQ(result.decision.kind, 5);  // UnknownData
  EXPECT_FALSE(mgr.MicrosegTracked(result.decision));  // not tracked yet

  auto header = mgr.DispatchMicroseg(result.decision, data.data(), data.size(), "some-rule-key");
  ASSERT_TRUE(header.has_value());
  EXPECT_EQ(header->host_, "example.com");

  // The single DispatchMicroseg call above must have both inserted the
  // entry AND extracted the header -- no second call was made.
  EXPECT_TRUE(mgr.MicrosegTracked(result.decision));
}

namespace {

// Same connection as SynPacket(), but in the REVERSE direction with SYN+ACK
// set -- i.e. the server's handshake reply. Deliberately a distinct helper
// from SynPacket(): the whole point of the tests below is that this packet's
// ConnectionID is the peer of SynPacket()'s.
std::vector<uint8_t> SynAckPacket() {
  std::vector<uint8_t> p(40, 0);
  p[0] = (4 << 4) | 5;
  p[9] = 6;
  p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 2;   // saddr = 10.0.0.2 (reversed)
  p[16] = 10; p[17] = 0; p[18] = 0; p[19] = 1;   // daddr = 10.0.0.1
  p[20] = 0x00; p[21] = 0x50;  // source port 80  (reversed)
  p[22] = 0x04; p[23] = 0xD2;  // dest port 1234
  uint32_t seq_be = htonl(9000);               // server ISN, unrelated to the client's
  std::memcpy(p.data() + 24, &seq_be, sizeof(seq_be));
  p[32] = 5 << 4;              // doff=5
  p[33] = 0x12;                // SYN|ACK
  return p;
}

// Same connection as SynPacket()/FinPacket(), but the FIN travels in the
// REVERSE direction -- the server closing the connection rather than the
// client. Its ConnectionID is the peer of SynPacket()'s, which is the whole
// point of ClosedOnTheUntrackedPeerDirectionStillErasesTheTrackedDirection.
std::vector<uint8_t> ReverseFinPacket() {
  std::vector<uint8_t> p(40, 0);
  p[0] = (4 << 4) | 5;
  p[9] = 6;
  p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 2;   // saddr = 10.0.0.2 (reversed)
  p[16] = 10; p[17] = 0; p[18] = 0; p[19] = 1;   // daddr = 10.0.0.1
  p[20] = 0x00; p[21] = 0x50;  // source port 80  (reversed)
  p[22] = 0x04; p[23] = 0xD2;  // dest port 1234
  p[32] = 5 << 4;              // doff=5
  p[33] = 0x01;                // FIN
  return p;
}

}  // namespace

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

// Regression test for Critical #1 of Task 5's review: a SYN-ACK is SYN-flagged
// but is NOT kind 1 (NewConnection), because the initiating SYN already seeded
// its direction's TCB entry. The callbacks' microseg path reconstructs the old
// C++'s `tcphdr.syn != 0` test, which was blind to TCB state; an earlier
// revision tested `decision.kind != 1` instead, which made every SYN-ACK take
// the payload-less early return and escape MatchMicroPolicyRule entirely --
// an ingress DENY rule would no longer have blocked connection establishment.
TEST(NetFlowEngineFfiTest, SynAckIsSynFlaggedButNotNewConnection) {
  auto engine = net_flow::new_flow_engine();
  auto syn = SynPacket();
  auto d1 = engine->on_packet(syn.data(), syn.size());
  ASSERT_EQ(d1.kind, 1);
  EXPECT_TRUE(d1.syn);

  auto syn_ack = SynAckPacket();
  auto d2 = engine->on_packet(syn_ack.data(), syn_ack.size());
  EXPECT_EQ(d2.kind, 3);      // Data -- NOT NewConnection
  EXPECT_TRUE(d2.syn);        // ...but still SYN-flagged, which is what counts
}

// Same class of bug, second packet type: a retransmitted SYN carries the same
// seq as the original, so it is classified Duplicate, not NewConnection. Under
// a DENY rule the original SYN is dropped and the retransmit arrives ~1s
// later; if it escapes policy matching the handshake completes anyway.
TEST(NetFlowEngineFfiTest, SynRetransmissionIsDuplicateButStillSynFlagged) {
  auto engine = net_flow::new_flow_engine();
  auto syn = SynPacket();
  ASSERT_EQ(engine->on_packet(syn.data(), syn.size()).kind, 1);

  auto again = engine->on_packet(syn.data(), syn.size());
  EXPECT_EQ(again.kind, 4);  // Duplicate
  EXPECT_TRUE(again.syn);
}

// Regression test for Critical #2 of Task 5's review: a kind 3 (Data) packet
// on a flow with no microseg entry does NOT late-bind inside DispatchMicroseg
// (only kind 5 does). The caller must call MicrosegTrack first, mirroring the
// old C++'s explicit `if (tcp_it == end()) insert(...)` immediately before its
// onData() call. Without that, L7 policy was silently never enforced on such
// flows -- reachable for the response direction of any peer-initiated
// connection, and for any flow an AddPolicyRule started applying to
// mid-connection.
TEST(ConnectionManagerMicrosegTest, DataOnUntrackedFlowNeedsMicrosegTrackToExtract) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  // Establish the flow in the TCB tracker only -- no microseg dispatch for the
  // SYN, i.e. no HTTP policy applied at handshake time.
  auto syn = SynPacket();
  mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);

  auto data = DataPacket(/*syn=*/false, "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n");
  uint32_t seq_be = htonl(1);
  std::memcpy(data.data() + 24, &seq_be, sizeof(seq_be));
  auto result = mgr.receive(data.data(), data.size(), /*track_tcp=*/true);
  ASSERT_EQ(result.decision.kind, 3);  // Data, because the SYN was seen
  ASSERT_FALSE(mgr.MicrosegTracked(result.decision));

  // Dispatching without tracking first extracts nothing -- this is the exact
  // silent-no-enforcement behavior the review caught.
  {
    net::ConnectionManager untracked_mgr(factory);
    untracked_mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);
    auto r = untracked_mgr.receive(data.data(), data.size(), /*track_tcp=*/true);
    EXPECT_FALSE(untracked_mgr.DispatchMicroseg(r.decision, data.data(), data.size(), "k")
                     .has_value());
  }

  // With the caller's MicrosegTrack first -- what the callbacks now do once
  // MatchMicroPolicyRule yields an applicable HTTP policy -- the same single
  // dispatch extracts the header.
  mgr.MicrosegTrack(result.decision, "some-rule-key");
  ASSERT_TRUE(mgr.MicrosegTracked(result.decision));
  auto header = mgr.DispatchMicroseg(result.decision, data.data(), data.size(), "some-rule-key");
  ASSERT_TRUE(header.has_value());
  EXPECT_EQ(header->host_, "example.com");
}

// Regression test for Important #1 of Task 5's review: microseg rule keys are
// direction-specific (InputHttpPolicy vs OutputHttpPolicy), so tracking one
// direction must NOT seed the peer direction with this direction's key. The
// old C++ kept two separate direction-keyed maps for exactly this reason.
TEST(ConnectionManagerMicrosegTest, TrackingOneDirectionDoesNotSeedThePeer) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  auto syn = SynPacket();
  auto syn_result = mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);
  mgr.MicrosegTrack(syn_result.decision, "ingress-key");
  ASSERT_TRUE(mgr.MicrosegTracked(syn_result.decision));
  ASSERT_EQ(mgr.MicrosegRuleKey(syn_result.decision).value_or(""), "ingress-key");

  // The reverse direction (the SYN-ACK the pod sends back) must still be
  // untracked, so output_nfq_cb runs its own MatchMicroPolicyRule against
  // OutputHttpPolicy rather than inheriting the ingress key.
  auto syn_ack = SynAckPacket();
  auto rev = mgr.receive(syn_ack.data(), syn_ack.size(), /*track_tcp=*/true);
  EXPECT_FALSE(mgr.MicrosegTracked(rev.decision));

  mgr.MicrosegTrack(rev.decision, "egress-key");
  EXPECT_EQ(mgr.MicrosegRuleKey(rev.decision).value_or(""), "egress-key");
  // ...and the ingress side kept its own key.
  EXPECT_EQ(mgr.MicrosegRuleKey(syn_result.decision).value_or(""), "ingress-key");
}

// MicrosegTrack mirrors std::map::insert's insert-if-absent semantics: a
// repeat SYN must not reset a live entry's parser state (the old C++'s
// `TcpCtInput().insert(...)` was a no-op on an existing key).
TEST(ConnectionManagerMicrosegTest, MicrosegTrackDoesNotOverwriteAnExistingEntry) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  auto syn = SynPacket();
  auto r = mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);
  mgr.MicrosegTrack(r.decision, "first-key");
  mgr.MicrosegTrack(r.decision, "second-key");
  EXPECT_EQ(mgr.MicrosegRuleKey(r.decision).value_or(""), "first-key");
}

// Regression test for the final whole-branch review's Fix 1: a microseg entry
// must be torn down as soon as the connection closes, even when the closing
// FIN/RST is captured on the direction that has NO microseg entry of its own.
//
// The setup here is the common one, not an exotic corner: an L7 microseg
// policy is typically written for ONE direction, so only that direction gets a
// microseg_conns_ entry (MicrosegTrack deliberately never seeds the peer --
// see TrackingOneDirectionDoesNotSeedThePeer). But net_flow_engine removes
// BOTH directions' TCB entries on the FIRST FIN/RST it sees, whichever
// direction that is, so the Closed decision very often surfaces on the
// direction with no entry -- where the callback takes its !tracked branch.
// Before this fix, the callbacks only dispatched Closed from inside their
// `tracked` branch, so that entry survived until the reaper swept it up to
// ~5 minutes later. If the client reused the same 4-tuple in the meantime
// (ephemeral port reuse), MicrosegTrack's insert-if-absent semantics handed
// the NEW connection the OLD one's rule_key and mid-message llhttp parser
// state -- silently failing open on L7 enforcement, since the new
// connection's bytes could never reach ParseState::Done against that state.
//
// ConnectionManager::MicrosegClose is where the "not gated on
// MicrosegTracked" invariant now lives, precisely so it is testable here
// rather than only inside the two nfq callbacks (which take libnetfilter_queue
// handles and cannot be driven from a unit test).
TEST(ConnectionManagerMicrosegTest, ClosedOnTheUntrackedPeerDirectionStillErasesTheTrackedDirection) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  // Direction A (10.0.0.1:1234 -> 10.0.0.2:80) is the ONLY microseg-tracked
  // direction, as if an ingress-only HTTP policy applied at handshake time.
  auto syn = SynPacket();
  auto syn_result = mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);
  ASSERT_EQ(syn_result.decision.kind, 1);  // NewConnection
  mgr.MicrosegTrack(syn_result.decision, "ingress-key");
  ASSERT_TRUE(mgr.MicrosegTracked(syn_result.decision));
  ASSERT_EQ(mgr.microsegConnectionCount(), 1u);

  // The server closes first, so the FIN is captured on direction B.
  auto fin = ReverseFinPacket();
  auto fin_result = mgr.receive(fin.data(), fin.size(), /*track_tcp=*/true);
  ASSERT_EQ(fin_result.decision.kind, 2);  // Closed
  // The premise of the bug: direction B is the untracked one, so the
  // callback's `tracked` branch -- where the Closed dispatch used to live --
  // is not taken for this packet.
  ASSERT_FALSE(mgr.MicrosegTracked(fin_result.decision));

  EXPECT_TRUE(mgr.MicrosegClose(fin_result.decision, fin.data(), fin.size()));

  // Direction A's entry must be gone IMMEDIATELY -- not left for the reaper.
  EXPECT_FALSE(mgr.MicrosegTracked(syn_result.decision));
  EXPECT_EQ(mgr.microsegConnectionCount(), 0u);
}

// MicrosegClose is called unconditionally for every TCP packet by both
// callbacks, so it must be an exact no-op for every non-Closed kind -- in
// particular it must never erase a live flow's entry, and must report false so
// the caller knows this packet still needs the normal dispatch path.
TEST(ConnectionManagerMicrosegTest, MicrosegCloseIsANoOpForNonClosedDecisions) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  auto syn = SynPacket();
  auto syn_result = mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);
  mgr.MicrosegTrack(syn_result.decision, "ingress-key");
  ASSERT_EQ(mgr.microsegConnectionCount(), 1u);

  EXPECT_FALSE(mgr.MicrosegClose(syn_result.decision, syn.data(), syn.size()));  // kind 1
  EXPECT_EQ(mgr.microsegConnectionCount(), 1u);

  auto data = DataPacket(/*syn=*/false, "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n");
  uint32_t seq_be = htonl(1);
  std::memcpy(data.data() + 24, &seq_be, sizeof(seq_be));
  auto data_result = mgr.receive(data.data(), data.size(), /*track_tcp=*/true);
  ASSERT_EQ(data_result.decision.kind, 3);  // Data
  EXPECT_FALSE(mgr.MicrosegClose(data_result.decision, data.data(), data.size()));
  EXPECT_EQ(mgr.microsegConnectionCount(), 1u);
  // ...and the entry it left alone is still the same one, parser state and
  // rule_key intact.
  EXPECT_EQ(mgr.MicrosegRuleKey(data_result.decision).value_or(""), "ingress-key");
}

TEST(NetFlowEngineFfiTest, EvictStaleConnectionsIsCallableAndReturnsEmptyForFreshFlows) {
  auto engine = net_flow::new_flow_engine();
  auto syn = SynPacket();
  engine->on_packet(syn.data(), syn.size());
  // Freshly created -- nothing should be evicted yet (the FFI entry point
  // uses a fixed multi-minute production timeout; this test only confirms
  // the call is wired correctly end-to-end, not the timeout value itself,
  // which is exercised by Task 2's Rust unit tests with an injected clock).
  auto evicted = engine->evict_stale_connections();
  EXPECT_TRUE(evicted.empty());
}

// --- Reaper (Task 6) -------------------------------------------------------
//
// The gap these cover: a LATE-BOUND flow -- one the daemon never saw a SYN for,
// because it attached to a pod mid-connection or was restarted while
// connections were live. on_packet_internal only ever inserts into the Rust
// engine's `tcbs` on a SYN, so such a flow has NO TCB entry, every packet on it
// arrives as kind 5 (UnknownData) forever, and its ID can therefore NEVER be
// returned by evict_stale_connections(). Yet DispatchMicroseg's case 5
// late-binds a microseg_conns_ entry for it. An engine-driven-only reaper
// (erase whatever evict_stale_connections() reports) can never reach that
// entry: it leaks for the lifetime of the daemon, unboundedly, in exactly the
// deployments where late-binding is normal. Hence EvictStale's second,
// timestamp-driven sweep, which these tests pin down.

TEST(ConnectionManagerReaperTest, LateBoundFlowIsEvictedAfterTheTimeout) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  // No SYN -- straight to data, so this arrives as UnknownData and late-binds.
  auto data = DataPacket(/*syn=*/false, "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n");
  auto result = mgr.receive(data.data(), data.size(), /*track_tcp=*/true);
  ASSERT_EQ(result.decision.kind, 5);  // UnknownData
  ASSERT_TRUE(mgr.DispatchMicroseg(result.decision, data.data(), data.size(), "k").has_value());
  ASSERT_TRUE(mgr.MicrosegTracked(result.decision));
  ASSERT_EQ(mgr.microsegConnectionCount(), 1u);

  // The premise: this flow is invisible to the engine's own reaper. Not an
  // incidental assertion -- if a future change made UnknownData insert into
  // `tcbs`, this test would no longer be testing the late-bound case at all.
  ASSERT_EQ(mgr.stat().tcp_conn_, 0u);

  // A sweep now must NOT evict it -- the entry was just touched.
  auto t0 = std::chrono::steady_clock::now();
  mgr.EvictStale(t0, std::chrono::seconds(300));
  EXPECT_TRUE(mgr.MicrosegTracked(result.decision));

  // ...and a sweep past the timeout must, even though the engine reported
  // nothing. This is the leak the engine-driven sweep alone cannot close.
  mgr.EvictStale(t0 + std::chrono::seconds(301), std::chrono::seconds(300));
  EXPECT_FALSE(mgr.MicrosegTracked(result.decision));
  EXPECT_EQ(mgr.microsegConnectionCount(), 0u);
}

TEST(ConnectionManagerReaperTest, MicrosegTouchKeepsALiveLateBoundFlowFromBeingEvicted) {
  // Without a per-packet touch, "still alive" would be decided by the last
  // payload-bearing packet only -- and the callbacks return early on
  // payload-less ACKs, so a keepalive-heavy connection would have its rule_key
  // and half-parsed request reaped out from under it.
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  auto data = DataPacket(/*syn=*/false, "GET /x HTTP/1.1\r\n");  // header not finished
  auto result = mgr.receive(data.data(), data.size(), /*track_tcp=*/true);
  ASSERT_EQ(result.decision.kind, 5);
  mgr.DispatchMicroseg(result.decision, data.data(), data.size(), "k");
  ASSERT_TRUE(mgr.MicrosegTracked(result.decision));

  auto t0 = std::chrono::steady_clock::now();
  // A bare ACK 200s in: the callbacks touch on every packet, before their
  // payload-presence early return.
  mgr.MicrosegTouch(result.decision, t0 + std::chrono::seconds(200));

  // 400s after t0 is well past the timeout measured from the DATA packet, but
  // only 200s past the touch -- the entry must survive.
  mgr.EvictStale(t0 + std::chrono::seconds(400), std::chrono::seconds(300));
  EXPECT_TRUE(mgr.MicrosegTracked(result.decision));
  EXPECT_EQ(mgr.MicrosegRuleKey(result.decision).value_or(""), "k");

  // 501s after t0 is 301s after the touch -- now it goes.
  mgr.EvictStale(t0 + std::chrono::seconds(501), std::chrono::seconds(300));
  EXPECT_FALSE(mgr.MicrosegTracked(result.decision));
}

TEST(ConnectionManagerReaperTest, MicrosegTouchDoesNotInsertOrRefreshOnDuplicates) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  // Touching a flow with no entry must not create one (it is a pure refresh --
  // the callbacks call it on every TCP packet, including flows no policy
  // applies to).
  auto data = DataPacket(/*syn=*/false, "GET / HTTP/1.1\r\n\r\n");
  auto result = mgr.receive(data.data(), data.size(), /*track_tcp=*/true);
  mgr.MicrosegTouch(result.decision);
  EXPECT_EQ(mgr.microsegConnectionCount(), 0u);
  EXPECT_FALSE(mgr.MicrosegTracked(result.decision));

  // A kind-4 (Duplicate) touch must not refresh either, mirroring
  // on_packet_internal, which leaves a TCB's last_seen alone on a
  // retransmission. Forge the kind rather than replaying a real duplicate:
  // what is under test is MicrosegTouch's own kind filter.
  mgr.MicrosegTrack(result.decision, "k");
  auto t0 = std::chrono::steady_clock::now();
  auto dup = result.decision;
  dup.kind = 4;
  mgr.MicrosegTouch(dup, t0 + std::chrono::seconds(1000));
  mgr.EvictStale(t0 + std::chrono::seconds(301), std::chrono::seconds(300));
  EXPECT_FALSE(mgr.MicrosegTracked(result.decision));
}

// A flow the engine DOES track still ages out of microseg_conns_ on its own
// timestamp -- the two sweeps are independent, and neither depends on the
// other having run.
TEST(ConnectionManagerReaperTest, TrackedFlowsMicrosegEntryAlsoAgesOut) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  auto syn = SynPacket();
  auto syn_result = mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);
  ASSERT_EQ(syn_result.decision.kind, 1);
  mgr.MicrosegTrack(syn_result.decision, "k");
  ASSERT_EQ(mgr.microsegConnectionCount(), 1u);

  auto t0 = std::chrono::steady_clock::now();
  mgr.EvictStale(t0 + std::chrono::seconds(301), std::chrono::seconds(300));
  EXPECT_EQ(mgr.microsegConnectionCount(), 0u);
  // The engine's own table is untouched by the C++ sweep -- it evicts on its
  // own real-time clock and its own compiled-in timeout, which this fresh flow
  // is nowhere near.
  EXPECT_EQ(mgr.stat().tcp_conn_, 2u);
}

// The C++ sweep must apply the SAME timeout the Rust engine does, not a second
// hand-maintained copy of the number.
TEST(NetFlowEngineFfiTest, StaleConnectionTimeoutIsExposedOverFfi) {
  EXPECT_EQ(net_flow::stale_connection_timeout_secs(), 300u);
}

// --- End-to-end: SYN -> HTTP request -> policy verdict (Task 7) -----------
//
// Everything above exercises net_flow_engine and ConnectionManager in
// isolation. These tests trace the SAME call sequence input_nfq_cb/
// output_nfq_cb drive in net-policy.cpp (SYN tracked with a rule_key already
// resolved by MatchMicroPolicyRule -> HTTP data dispatched through
// DispatchMicroseg -> the resulting http::Header matched against the flow's
// HTTP_RULE_INFO list), to confirm the new Rust-backed path produces the same
// verdict shape (NetPolicyRule::kAllow / kDeny / kDefault) the old
// TcpCtInput()-based code did.
//
// MatchHttpPolicyRule itself has internal linkage (`static` in net-policy.cpp)
// and is not reachable from a test binary, so MatchHttpPolicyRuleLike below is
// a deliberate structural mirror of its body (net-policy.cpp:387-396) --
// first host/method/path match wins, empty fields wildcard, kDefault if none
// match -- NOT a literal reuse. What's under test is that DispatchMicroseg's
// real, Rust-decision-driven Header is what feeds this matching logic, not
// the matching logic itself (which Phase 4/5's own tests already cover).
namespace {

NetPolicyRule MatchHttpPolicyRuleLike(const std::vector<HTTP_RULE_INFO>& rules,
                                       const http::Header& header) {
  for (const auto& rule : rules) {
    if (!rule.host_.empty() && (rule.host_ != header.host_)) continue;
    if (!rule.method_.empty() && (rule.method_ != header.method_)) continue;
    if (!rule.path_.empty() && (rule.path_ != header.path_)) continue;
    return rule.action_;
  }
  return NetPolicyRule::kDefault;
}

}  // namespace

TEST(ConnectionManagerEndToEndTest, SynThenHttpRequestProducesAllowVerdictForMatchingRule) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  // SYN: mirrors input_nfq_cb's untracked-branch SYN handling once
  // MatchMicroPolicyRule has already resolved a rule_key for this flow's net
  // policy and an HTTP policy applies to that key (net-policy.cpp:776-784) --
  // MicrosegTrack, then return without extracting.
  auto syn = SynPacket();
  auto syn_result = mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);
  ASSERT_EQ(syn_result.decision.kind, 1);  // NewConnection
  const std::string rule_key = "allow-store-front";
  mgr.MicrosegTrack(syn_result.decision, rule_key);

  // Next packet on this flow: now tracked, so the real callback's tracked
  // branch (net-policy.cpp:711-742) would skip MatchMicroPolicyRule entirely
  // and pull the key back off the tracked entry -- reproduced directly here.
  ASSERT_TRUE(mgr.MicrosegTracked(syn_result.decision));
  ASSERT_EQ(mgr.MicrosegRuleKey(syn_result.decision).value_or(""), rule_key);

  auto data = DataPacket(/*syn=*/false, "GET /store HTTP/1.1\r\nHost: shop.example.com\r\n\r\n");
  uint32_t seq_be = htonl(1);  // SYN consumed seq 0; the next real segment must carry seq=1.
  std::memcpy(data.data() + 24, &seq_be, sizeof(seq_be));
  auto data_result = mgr.receive(data.data(), data.size(), /*track_tcp=*/true);
  ASSERT_EQ(data_result.decision.kind, 3);  // Data

  auto header = mgr.DispatchMicroseg(data_result.decision, data.data(), data.size(), rule_key);
  ASSERT_TRUE(header.has_value());
  EXPECT_EQ(header->host_, "shop.example.com");
  EXPECT_EQ(header->method_, "GET");
  EXPECT_EQ(header->path_, "/store");

  std::vector<HTTP_RULE_INFO> rules(1);
  rules[0].direction_ = static_cast<uint8_t>(FlowDir::kIngress);
  rules[0].action_    = NetPolicyRule::kAllow;
  rules[0].host_      = "shop.example.com";

  EXPECT_EQ(MatchHttpPolicyRuleLike(rules, *header), NetPolicyRule::kAllow);
}

TEST(ConnectionManagerEndToEndTest, SynThenHttpRequestProducesDenyVerdictForMatchingRule) {
  http::HttpFilterFactory factory;
  net::ConnectionManager mgr(factory);

  auto syn = SynPacket();
  auto syn_result = mgr.receive(syn.data(), syn.size(), /*track_tcp=*/true);
  ASSERT_EQ(syn_result.decision.kind, 1);  // NewConnection
  const std::string rule_key = "deny-admin-path";
  mgr.MicrosegTrack(syn_result.decision, rule_key);
  ASSERT_TRUE(mgr.MicrosegTracked(syn_result.decision));

  auto data = DataPacket(/*syn=*/false, "GET /admin HTTP/1.1\r\nHost: shop.example.com\r\n\r\n");
  uint32_t seq_be = htonl(1);
  std::memcpy(data.data() + 24, &seq_be, sizeof(seq_be));
  auto data_result = mgr.receive(data.data(), data.size(), /*track_tcp=*/true);
  ASSERT_EQ(data_result.decision.kind, 3);  // Data

  auto header = mgr.DispatchMicroseg(data_result.decision, data.data(), data.size(), rule_key);
  ASSERT_TRUE(header.has_value());
  EXPECT_EQ(header->path_, "/admin");

  std::vector<HTTP_RULE_INFO> rules(2);
  // A more specific rule ahead of a catch-all -- first match wins, exactly
  // like MatchHttpPolicyRule's linear scan, so this also proves ordering
  // matters and the catch-all does not shadow it.
  rules[0].direction_ = static_cast<uint8_t>(FlowDir::kIngress);
  rules[0].action_    = NetPolicyRule::kDeny;
  rules[0].path_      = "/admin";
  rules[1].direction_ = static_cast<uint8_t>(FlowDir::kIngress);
  rules[1].action_    = NetPolicyRule::kAllow;  // catch-all: empty host/method/path

  EXPECT_EQ(MatchHttpPolicyRuleLike(rules, *header), NetPolicyRule::kDeny);

  // Negative control on the SAME extracted header: a rule set with only a
  // non-matching host must fall through to kDefault, not accidentally match --
  // this is what would catch a MatchHttpPolicyRuleLike (or, if ever exposed,
  // MatchHttpPolicyRule) bug that ignores empty-field wildcarding incorrectly
  // in the other direction.
  std::vector<HTTP_RULE_INFO> non_matching(1);
  non_matching[0].host_   = "other.example.com";
  non_matching[0].action_ = NetPolicyRule::kDeny;
  EXPECT_EQ(MatchHttpPolicyRuleLike(non_matching, *header), NetPolicyRule::kDefault);
}
