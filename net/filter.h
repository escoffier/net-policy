#pragma once

#include "http/packet.hh"
#include "net/stream.h"

#include <list>
#include <memory>

#include "common/pure.h"

namespace net {

enum class NetworkStatus {
  Continue,
};

class NetworkFilterBase {
public:
  virtual NetworkStatus onNewConnection(const net::ConnectionInfo& streamInfo) PURE;

  virtual NetworkStatus onData(seastar::net::packet packet) PURE;

  virtual NetworkStatus onClose() PURE;
};

using NetworkFilterPtr = std::shared_ptr<NetworkFilterBase>;

class NetworkFilterManager {
public:
  NetworkStatus onNewConnection(const net::ConnectionInfo& streamInfo);

  NetworkStatus onData(seastar::net::packet data);

  NetworkStatus onClose();

  void addFilter(NetworkFilterPtr filter);

private:
  std::list<NetworkFilterPtr> filters_;
};

} // namespace net