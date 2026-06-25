#include <cstddef>
#include <cstdint>
#include <glog/logging.h>
#include <linux/ip.h>
#include <memory>
#include <netinet/in.h>
#include <utility>

#include "ip.h"
#include "net/tcp.h"
#include "net/utility.h"

namespace net {

ipv4::ipv4()
    : tcp_(), l4_{{uint8_t(l4_protocol::ICMP), nullptr},
                  {uint8_t(l4_protocol::TCP), &tcp_},
                  {uint8_t(l4_protocol::UDP), nullptr}} {}

NetStatus ipv4::receive(seastar::net::packet packet) {
  auto p = packet.get_header(0, packet.len());
  VLOG(4) << "receive ipv4 " << uint64_t(p);
  if (packet.len() < sizeof(iphdr)) {
    return NetStatus::OK;
  }
  auto iph = packet.get_header<iphdr>(0);

  auto ipHeaderLen = iph->ihl * 4;
  packet.trim_front(ipHeaderLen);
  auto l4 = l4_[iph->protocol];
  if (l4) {
    if (iph->protocol == uint8_t(l4_protocol::TCP)) {
      return l4->receive(std::move(packet), iph->saddr, iph->daddr);
    }
  }
  return NetStatus::OK;
}

NetworkStat ipv4::tcpStat() { return l4_[uint8_t(l4_protocol::TCP)]->stat(); }

std::vector<std::string> ipv4::connections() {
  return l4_[uint8_t(l4_protocol::TCP)]->connections();
}

} // namespace net