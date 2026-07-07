#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <unordered_map>

#include "http/connection.h"
#include "http/packet.hh"
#include "ip_protocol.h"
#include "net/stream.h"
#include "net/utility.h"

namespace net {

const int TCP_HDR_LEN = 20;

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

class Tcp : public IPProtocol {
public:
  struct Tcb {
    Tcb(std::shared_ptr<http::Connection> http) : seq_(0), server_side_(false), http_(http) {}
    NetStatus handlePayload(seastar::net::packet p);

    uint32_t seq_;
    bool server_side_;
    std::shared_ptr<http::Connection> http_;
  };

  // void receive(seastar::net::packet packet) override;
  NetStatus receive(seastar::net::packet p, uint32_t from, uint32_t to) override;

  NetworkStat stat() override;

  std::vector<std::string> connections() override;

private:
  std::unordered_map<ConnectionID, std::shared_ptr<Tcb>, ConnectionIDHash> tcbs_;
};
} // namespace net
