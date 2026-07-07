#pragma once

#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <string_view>

#include "common/pure.h"
#include "http/header.h"
#include "http/packet.hh"
#include "net/stream.h"
// #include "net/tcp.h"
// #include "net/tcp.h"

namespace http {

enum class FilterStatus {
  Continue,
  StopIteration,
  DropPkt,
};

struct TCPSegment {
  // ip address using network order
  uint32_t from_;
  uint32_t to_;

  // tcp segment including tcp header
  char* base_;
  size_t size_;

  friend std::ostream& operator<<(std::ostream& os, TCPSegment& tcp);
};

class HttpFilterBase {
public:
  virtual FilterStatus onRequestHeaders(RequestHeaderMap& headers, bool end_of_stream) PURE;

  virtual FilterStatus onRequestBody(seastar::net::packet& p, bool end_of_stream) PURE;

  virtual FilterStatus onResponseBody(seastar::net::packet& p, bool end_of_stream) PURE;

  virtual FilterStatus onResponseHeaders(RequestHeaderMap& headers, bool end_of_stream) PURE;

  virtual FilterStatus onNewConnection(const net::ConnectionInfo& streamInfo) PURE;

  virtual FilterStatus onData(seastar::net::packet& data) PURE;

  virtual FilterStatus onClose() PURE;

  virtual size_t getConnectionID() const PURE;

  virtual void setTCPSegment(char* p, size_t size) PURE;

  virtual TCPSegment& getTcpSegment() PURE;

  virtual ~HttpFilterBase() = default;
};

using HttpFilterPtr = std::shared_ptr<HttpFilterBase>;

class HttpFilter : public HttpFilterBase {
public:
  HttpFilter(size_t connectionID, uint32_t from, uint32_t to);

  size_t getConnectionID() const override { return connectionID_; }

  void setTCPSegment(char* p, size_t size) override;

  TCPSegment& getTcpSegment() override;

private:
  size_t connectionID_;
  TCPSegment tcpSegment_;
};

class HttpFilterManager {
public:
  HttpFilterManager() = default;

  HttpFilterManager(size_t key);

  HttpFilterManager(size_t key, uint32_t from, uint32_t to);

  FilterStatus decodeHeaders(RequestHeaderMap& headers, bool serverSide);

  FilterStatus decodeBody(seastar::net::packet body, bool serverSide);

  FilterStatus onNewConnection(const net::ConnectionInfo& streamInfo);

  FilterStatus onData(seastar::net::packet& data);

  FilterStatus onClose();

  void addFilter(HttpFilterPtr filter);

  void setTCPSegment(seastar::net::packet& p);

private:
  std::list<HttpFilterPtr> filters_;
  TCPSegment tcp_segment_;
  net::ConnectionInfo connection_;
};

using HttpFilterManagerPtr = std::shared_ptr<HttpFilterManager>;

} // namespace http
