#include <gtest/gtest.h>

#include <algorithm>
#include <arpa/inet.h>
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

namespace {

std::vector<std::string> SortedConnections(net::ConnectionManager& mgr) {
  auto conns = mgr.connections();
  std::sort(conns.begin(), conns.end());
  return conns;
}

std::vector<std::string> SortedConnections(net_flow::FlowEngine& engine) {
  auto rust_conns = engine.connection_strings();
  std::vector<std::string> conns;
  conns.reserve(rust_conns.size());
  for (const auto& s : rust_conns) {
    conns.emplace_back(std::string(s));
  }
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
