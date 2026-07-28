#pragma once

#include <glog/logging.h>
#include <memory>
#include <utility>

#include "http/http_filter_factory.h"
#include "http/packet.hh"
#include "ip.h"
#include "net/utility.h"

namespace net {
class ConnectionManager {
public:
  explicit ConnectionManager(http::HttpFilterFactory& filter_factory)
      : ipv4_(std::make_unique<ipv4>(filter_factory)) {}

  NetStatus receive(seastar::net::packet p) { return ipv4_->receive(std::move(p)); };

  NetworkStat stat() { return ipv4_->tcpStat(); }

  std::vector<std::string> connections() { return ipv4_->connections(); }

private:
  std::unique_ptr<ipv4> ipv4_;
};
} // namespace net