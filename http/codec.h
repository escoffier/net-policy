#pragma once

#include <memory>
#include <string>

#include "common/pure.h"
#include "http/filter.h"
#include "http/packet.hh"
#include "http/utility.h"

namespace http {
struct Header {
  std::string method_;
  std::string path_;
  std::string host_;
  ParseState parseState_;
  FilterStatus status_;
};

std::ostream &operator<<(std::ostream &os, const Header &p);

class Codec {
public:
  virtual const Header &dispatch(std::string_view data) PURE;

  virtual const FilterStatus dispatch(seastar::net::packet data) PURE;

  virtual void addFilter(HttpFilterPtr filter) PURE;

  virtual void setFilterManager(HttpFilterManagerPtr filterManager) PURE;

  virtual ~Codec() = default;
};
} // namespace http