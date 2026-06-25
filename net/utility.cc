
#include <arpa/inet.h>

#include "utility.h"

namespace net {
std::string ipv4ToString(uint32_t ip) {
  in_addr addr;
  addr.s_addr = ip;
  return inet_ntoa(addr);
}
} // namespace net