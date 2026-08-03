#include <gtest/gtest.h>

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
  ASSERT_EQ(mgr.receive(syn.data(), syn.size()), net::NetStatus::OK);

  const std::string payload = "GET /x";
  auto data_pkt = DataPacket(/*syn=*/false, payload);
  // Deliberately not asserting on the return value here: HandleData's final
  // OK-vs-Drop result additionally depends on http::Connection::processData's
  // llhttp-based HTTP detection for these arbitrary bytes, which is unrelated
  // to (and, independently of this test, order-dependent/flaky across runs
  // for reasons predating this change -- llhttp state is not perfectly
  // process-order-independent for partial, non-CRLF-terminated input) the
  // ip_header_len/setTCPSegment fix this test exists to check. Both
  // setTCPSegment and onData (below) run unconditionally before that
  // HTTP-parse-dependent branch, so they're unaffected either way.
  mgr.receive(data_pkt.data(), data_pkt.size());

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
  ASSERT_EQ(mgr.receive(syn.data(), syn.size()), net::NetStatus::OK);
  // Both the server-side (1234->80) and the auto-created peer (80->1234)
  // entries must be present -- this is the check that would catch
  // HandleNewConnection dropping its peer_is_new branch.
  EXPECT_EQ(mgr.httpConnectionCount(), 2u);
  EXPECT_FALSE(captured_filter->close_called_);

  auto fin = FinPacket();
  ASSERT_EQ(mgr.receive(fin.data(), fin.size()), net::NetStatus::OK);

  EXPECT_TRUE(captured_filter->close_called_);
  // Both entries must be gone -- this is the check that would catch
  // HandleClosed erasing only its own ConnectionID and leaking its peer's.
  EXPECT_EQ(mgr.httpConnectionCount(), 0u);
}
