#pragma once
#include "http/filter.h"
#include <cstddef>
namespace http {
namespace extension {
class LogFilter : public http::HttpFilter {
public:
  LogFilter(size_t id, uint32_t from, uint32_t to) : http::HttpFilter(id, from, to) {}

  FilterStatus onRequestHeaders(RequestHeaderMap& headers, bool end_of_stream) override;

  FilterStatus onRequestBody(seastar::net::packet& p, bool end_of_stream) override;

  FilterStatus onResponseBody(seastar::net::packet& p, bool end_of_stream) override;

  FilterStatus onResponseHeaders(RequestHeaderMap& headers, bool end_of_stream) override;

  FilterStatus onNewConnection(const net::ConnectionInfo& streamInfo) override;

  FilterStatus onData(seastar::net::packet& data) override;

  FilterStatus onClose() override;
};
} // namespace extension
} // namespace http
