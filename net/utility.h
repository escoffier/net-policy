#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace net {
std::string ipv4ToString(uint32_t ip);

struct NetworkStat {
    uint64_t tcp_conn_;
};

struct ConnectionID {
  uint32_t local_ip_;
  uint32_t foreign_ip_;
  uint16_t local_port_;
  uint16_t foreign_port_;

  bool operator==(const ConnectionID& x) const {
    return local_ip_ == x.local_ip_ && foreign_ip_ == x.foreign_ip_ && local_port_ == x.local_port_ &&
           foreign_port_ == x.foreign_port_;
  }
};

struct ConnectionIDHash : private std::hash<uint32_t>, private std::hash<uint16_t> {
  size_t operator()(const ConnectionID& id) const noexcept {
    using h1 = std::hash<uint32_t>;
    using h2 = std::hash<uint16_t>;
    return h1::operator()(id.local_ip_) ^ h1::operator()(id.foreign_ip_) ^
           h2::operator()(id.local_port_) ^ h2::operator()(id.foreign_port_);
  }
};

}