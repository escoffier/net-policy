#include "codec.h"

#include <iostream>

namespace http {
std::ostream &operator<<(std::ostream &os, const Header &p) {
  os << "method: " << p.method_ << ", path: " << p.path_ << ", host: " << p.host_
     << ", parse state: " << static_cast<int>(p.parseState_);
  return os;
}
} // namespace http
