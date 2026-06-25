#include <cstdint>
#include <glog/logging.h>

#include "http/filter.h"
#include "log.h"

namespace http {
namespace extension {
FilterStatus LogFilter::onRequestHeaders(RequestHeaderMap& headers, bool end_of_stream) {
  VLOG(4) << getConnectionID() << " on request header: " << headers
          << " tcp segment: " << getTcpSegment();
  return FilterStatus::Continue;
}

FilterStatus LogFilter::onRequestBody(seastar::net::packet& p, bool end_of_stream) {
  VLOG(4) << getConnectionID() << " on request body"
          << " tcp segment: " << getTcpSegment();
  return FilterStatus::Continue;
}

FilterStatus LogFilter::onResponseBody(seastar::net::packet& p, bool end_of_stream) {
  VLOG(4) << getConnectionID() << " on response body"
          << " tcp segment: " << getTcpSegment();
  return FilterStatus::Continue;
}

FilterStatus LogFilter::onResponseHeaders(RequestHeaderMap& headers, bool end_of_stream) {
  VLOG(4) << getConnectionID() << " on response header: " << headers
          << " tcp segment: " << getTcpSegment();
  return FilterStatus::Continue;
}

FilterStatus LogFilter::onNewConnection(const net::ConnectionInfo& streamInfo) {
  VLOG(4) << getConnectionID() << " on connection";

  return FilterStatus::Continue;
}

FilterStatus LogFilter::onData(seastar::net::packet& data) {
  auto p = data.get_header(0, data.len());
  VLOG(4) << getConnectionID() << " on data: " << uint64_t(p);

  return FilterStatus::Continue;
}

FilterStatus LogFilter::onClose() {
  VLOG(4) << getConnectionID() << " on close";
  return FilterStatus::Continue;
}
} // namespace extension
} // namespace http