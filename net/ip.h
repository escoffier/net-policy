#pragma once

#include <array>
#include <memory>
#include <unordered_map>

#include "common/array_map.h"
#include "common/pure.h"
#include "http/packet.hh"
#include "net/utility.h"
#include "tcp.h"

namespace net {
enum class l4_protocol : uint8_t { ICMP = 1, TCP = 6, UDP = 17, UNUSED = 255 };

class ipv4 {
public:
  ipv4();
  
  NetStatus receive(seastar::net::packet p);

  NetworkStat tcpStat();

  std::vector<std::string> connections() ;

private:
  Tcp tcp_;
  common::array_map<IPProtocol*, 256> l4_;
  //  std::array<std::unique_ptr<IPProtocol>, 16> l4_;
};

} // namespace net