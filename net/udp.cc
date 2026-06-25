#include <netinet/in.h>
#include <netinet/udp.h>

#include "net/stream.h"
#include "net/utility.h"
#include "udp.h"

namespace net {
NetStatus Udp::receive(seastar::net::packet packet, uint32_t from, uint32_t to) {
  auto udpHdr = packet.get_header<udphdr>();
  net::ConnectionInfo connInfo{net::ipv4ToString(from), net::ipv4ToString(to),
                               ntohs(udpHdr->source), ntohs(udpHdr->dest)};

  //   if (http::FilterStatus::StopIteration ==
  //       filterManager->onConnection(connInfo)) {
  //     LOG(INFO) << "terminate connection processing";
  //     // return;
  //   }
  return NetStatus::OK;
}
} // namespace net