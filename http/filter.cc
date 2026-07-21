#include "filter.h"
#include "http/http_filter_factory.h"
#include "http/packet.hh"
#include "net/stream.h"
#include "net/tcp.h"
#include "net/utility.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <glog/logging.h>
#include <string_view>
#include <utility>

namespace http {

HttpFilterManager::HttpFilterManager(size_t key) {
  http::HttpFilterFactory::getInstance().traverse([this, key](http::FilterCB cb) {
    auto filter = cb(key, 0, 0);
    this->addFilter(filter);
    // filterManager->addFilter(
    //     std::make_shared<http::extension::LogFilter>(hashFunc(id)));
  });
}

HttpFilterManager::HttpFilterManager(size_t key, uint32_t from, uint32_t to) {
  http::HttpFilterFactory::getInstance().traverse([this, key, from, to](http::FilterCB cb) {
    auto filter = cb(key, from, to);
    this->addFilter(filter);
  });
  tcp_segment_.from_ = from;
  tcp_segment_.to_ = to;
}

FilterStatus HttpFilterManager::decodeHeaders(RequestHeaderMap& headers, bool serverSide) {
  VLOG(4) << "decodeHeaders" << tcp_segment_;
  auto filter = filters_.begin();
  if (serverSide) {
    while (filter != filters_.end()) {
      auto status = (*filter)->onRequestHeaders(headers, false);
      if (status == FilterStatus::StopIteration) {
        return FilterStatus::StopIteration;
      }
      filter++;
    }
  } else {
    while (filter != filters_.end()) {
      auto status = (*filter)->onResponseHeaders(headers, false);
      if (status == FilterStatus::StopIteration) {
        return FilterStatus::StopIteration;
      }
      filter++;
    }
  }

  return FilterStatus::Continue;
}

FilterStatus HttpFilterManager::decodeBody(seastar::net::packet body, bool serverSide) {
  VLOG(4) << "decodeBody: " << std::string_view(body.get_header(0, body.len()), body.len());
  auto filter = filters_.begin();
  if (serverSide) {
    while (filter != filters_.end()) {
      auto status = (*filter)->onRequestBody(body, false);
      if (status == FilterStatus::StopIteration) {
        return FilterStatus::StopIteration;
      }
      filter++;
    }
  } else {
    while (filter != filters_.end()) {
      auto status = (*filter)->onResponseBody(body, false);
      if (status == FilterStatus::StopIteration) {
        return FilterStatus::StopIteration;
      }
      filter++;
    }
  }
  return FilterStatus::Continue;
}

void HttpFilterManager::addFilter(HttpFilterPtr filter) { filters_.push_back(std::move(filter)); }

FilterStatus HttpFilterManager::onNewConnection(const net::ConnectionInfo& conn) {
  connection_ = conn;
  for (auto filter = filters_.begin(); filter != filters_.end(); filter++) {
    auto status = (*filter)->onNewConnection(conn);
    if (status == FilterStatus::StopIteration) {
      return FilterStatus::StopIteration;
    }
  }
  // std::for_each(filters_.begin(), filters_.end(),
  //               [&streamInfo](HttpFilterPtr filter) {
  //                 filter->onConnection(streamInfo);
  //               });
  // auto filter = filters_.begin();
  // while (filter != filters_.end()) {
  //   (*filter)->onConnection();
  //   filter++;
  // }
  return FilterStatus::Continue;
}

FilterStatus HttpFilterManager::onData(seastar::net::packet& data) {
  for (auto filter = filters_.begin(); filter != filters_.end(); filter++) {
    auto status = (*filter)->onData(data);
    if (status == FilterStatus::StopIteration) {
      return FilterStatus::StopIteration;
    }
  }
  return FilterStatus::Continue;
}

FilterStatus HttpFilterManager::onClose() {
  std::for_each(filters_.begin(), filters_.end(), [](HttpFilterPtr filter) { filter->onClose(); });
  return FilterStatus::Continue;
}

void HttpFilterManager::setTCPSegment(seastar::net::packet& p) {
  auto data = p.get_header(0, p.len());
  tcp_segment_.base_ = data;
  tcp_segment_.size_ = p.len();
  std::for_each(filters_.begin(), filters_.end(),
                [data, &p](HttpFilterPtr filter) { filter->setTCPSegment(data, p.len()); });
}

HttpFilter::HttpFilter(size_t connectionID, uint32_t from, uint32_t to)
    : connectionID_(connectionID) {
  tcpSegment_.from_ = from;
  tcpSegment_.to_ = to;
}

TCPSegment& HttpFilter::getTcpSegment() { return tcpSegment_; }

void HttpFilter::setTCPSegment(char* p, size_t size) {
  tcpSegment_.base_ = p;
  tcpSegment_.size_ = size;
}

std::ostream& operator<<(std::ostream& os, TCPSegment& tcp) {
  os << "TCPSegment{"
     << "from:" << net::ipv4ToString(tcp.from_) << ", to:" << net::ipv4ToString(tcp.to_)
     << ", base:" << uint64_t(tcp.base_) << ", size: " << tcp.size_;

  os << "}";
  return os;
}

// void HttpFilter::setConnection(net::ConnectionInfo& conn) { tcpSegment_.from_ = conn.from_; }

// net::ConnectionInfo& HttpFilter::getConnection() { return connection_; }

} // namespace http