#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <cstring>
#include <memory>
#include <string>

#include "http/http_filter_factory.h"
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
// The gate exists because net_flow_engine's FlowEngine has no timeout/reaper:
// entries leave the TCB table only on a FIN/RST for an already-tracked flow.
// net-policy.cpp passes daemon->WafEnabled() here, and waf_enable_ defaults to
// false, so tracking TCP unconditionally would grow that table without bound in
// the default deployment. Asserting on stat().tcp_conn_ (the Rust engine's live
// TCB count) is what makes this test observe that actual resource-leak
// scenario, rather than just restating the flag it was passed.
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

}  // namespace

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
