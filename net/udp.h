#pragma once

#include "net/ip_protocol.h"
#include "net/utility.h"

namespace net {

class Udp : public IPProtocol {
public:
  NetStatus receive(seastar::net::packet packet, uint32_t from, uint32_t to);
};

} // namespace net