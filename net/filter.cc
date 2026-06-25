#include "filter.h"
#include <utility>

namespace net {

NetworkStatus NetworkFilterManager::onNewConnection(const net::ConnectionInfo& streamInfo) {
  for (auto it = filters_.begin(); it != filters_.end(); it++) {
    (*it)->onNewConnection(streamInfo);
  }
  return NetworkStatus::Continue;
}

NetworkStatus NetworkFilterManager::onData(seastar::net::packet data) {
  for (auto it = filters_.begin(); it != filters_.end(); it++) {
    (*it)->onData(std::move(data));
  }

  return NetworkStatus::Continue;
}
NetworkStatus NetworkFilterManager::onClose() {
  for (auto it = filters_.begin(); it != filters_.end(); it++) {
    (*it)->onClose();
  }
  return NetworkStatus::Continue;
}

void NetworkFilterManager::addFilter(NetworkFilterPtr filter) { filters_.emplace_back(filter); }
} // namespace net