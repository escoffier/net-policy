#include "header.h"
#include <ostream>

namespace http {

std::ostream& operator<<(std::ostream& os,  RequestHeaderMap& headers) {
  os << "headers{";
  auto hs = headers.getHttpHeaderPairs();
  for(auto it = hs.begin(); it !=  hs.end(); it++) {
    os << it->first << ":" <<it->second<<", ";
  }
  os << "}";
  return os;
}
}