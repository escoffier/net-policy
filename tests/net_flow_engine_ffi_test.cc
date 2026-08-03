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
