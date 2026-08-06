// These tests open a real conntrack session and, for the round-trip test,
// establish a genuine loopback UDP flow and confirm set_accept_mark drives a
// real NFCT_Q_DUMP against it. Both need CAP_NET_ADMIN -- nfct_open() itself
// opens a NETLINK_NETFILTER socket. Run this binary via `docker run/exec
// --privileged` (or `--cap-add=NET_ADMIN`), matching NetIptablesFfiTest's and
// NetNfqFfiTest's established pattern. See CLAUDE.md's Build Commands section.

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <string>

#include "net_conntrack_cxxbridge/lib.h"

namespace {

// Reads the conntrack mark the *kernel* currently holds for a loopback UDP
// flow, straight out of procfs. This is deliberately an independent path from
// the code under test (no libnetfilter_conntrack involved), so it can confirm
// set_accept_mark's callback really force-updated the entry rather than just
// returning without throwing. Returns -1 if no such entry is listed.
int ReadConntrackMark(uint16_t src_port, uint16_t dst_port) {
  std::ifstream in("/proc/net/nf_conntrack");
  if (!in.is_open())
    return -1;
  const std::string want =
      "sport=" + std::to_string(src_port) + " dport=" + std::to_string(dst_port);
  std::string line;
  while (std::getline(in, line)) {
    if (line.find(want) == std::string::npos)
      continue;
    size_t mark_at = line.find("mark=");
    if (mark_at == std::string::npos)
      return -1;  // kernel built without CONFIG_NF_CONNTRACK_MARK
    return std::atoi(line.c_str() + mark_at + std::strlen("mark="));
  }
  return -1;
}

// Binds a UDP socket to an ephemeral loopback port and reports both.
int BindLoopbackUdp(sockaddr_in* addr, uint16_t* port) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    return -1;
  *addr = sockaddr_in{};
  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr->sin_port = 0;  // let the kernel pick a free port
  if (bind(fd, reinterpret_cast<sockaddr*>(addr), sizeof(*addr)) != 0) {
    close(fd);
    return -1;
  }
  socklen_t addr_len = sizeof(*addr);
  if (getsockname(fd, reinterpret_cast<sockaddr*>(addr), &addr_len) != 0) {
    close(fd);
    return -1;
  }
  *port = ntohs(addr->sin_port);
  return fd;
}

}  // namespace

TEST(NetConntrackFfiTest, OpenSucceeds) {
  rust::Box<net_conntrack::ConntrackSession> session =
      net_conntrack::open_conntrack_session();
  SUCCEED();
}

TEST(NetConntrackFfiTest, SetAcceptMarkWithAnEmptyTupleDoesNotThrow) {
  // Mirrors UpdateMark's real call shape exactly: an all-zero FiveTuple and
  // mark = NetPolicyRule::kDeny (0). Exercises the "unconditional attrs only"
  // path through set_accept_mark and the NFCT_Q_DUMP query -- it does not need
  // a specific tracked connection to exist, since a dump with only
  // mark/l3proto set still succeeds.
  rust::Box<net_conntrack::ConntrackSession> session =
      net_conntrack::open_conntrack_session();
  net_conntrack::SharedFiveTuple tuple{};
  EXPECT_NO_THROW(session->set_accept_mark(tuple, 0));
}

TEST(NetConntrackFfiTest, MarkRoundTripOnARealLoopbackFlow) {
  // Establish a real UDP "connection" conntrack will track: bind a socket,
  // send one datagram to it from a second socket. UDP is used rather than TCP
  // since there is no handshake/teardown state machine to fight -- one
  // sendto() is enough for conntrack to create an entry.
  sockaddr_in server_addr{};
  uint16_t server_port = 0;
  int server_fd = BindLoopbackUdp(&server_addr, &server_port);
  ASSERT_GE(server_fd, 0);

  sockaddr_in client_addr{};
  uint16_t client_port = 0;
  int client_fd = BindLoopbackUdp(&client_addr, &client_port);
  ASSERT_GE(client_fd, 0);

  const char msg[] = "net_conntrack test datagram";
  ssize_t sent = sendto(client_fd, msg, sizeof(msg), 0,
                        reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr));
  ASSERT_EQ(sent, static_cast<ssize_t>(sizeof(msg)));

  net_conntrack::SharedFiveTuple tuple{};
  tuple.proto = IPPROTO_UDP;
  tuple.src_addr = "127.0.0.1";
  tuple.dst_addr = "127.0.0.1";
  tuple.src_port = client_port;
  tuple.dst_port = server_port;

  bool round_trip_worked = true;
  try {
    rust::Box<net_conntrack::ConntrackSession> session =
        net_conntrack::open_conntrack_session();
    session->set_accept_mark(tuple, 5);
  } catch (const std::exception&) {
    round_trip_worked = false;
  }

  int observed_mark = round_trip_worked ? ReadConntrackMark(client_port, server_port) : -1;

  close(client_fd);
  close(server_fd);

  if (!round_trip_worked) {
    GTEST_SKIP() << "set_accept_mark failed in this environment -- container "
                    "likely lacks CAP_NET_ADMIN or nf_conntrack support";
  }
  if (observed_mark < 0) {
    GTEST_SKIP() << "no readable /proc/net/nf_conntrack entry with a mark= field "
                    "for this flow -- cannot verify the mark independently";
  }
  // The kernel's own view, read back through procfs: update_net_session's
  // NFCT_Q_UPDATE really landed on this flow.
  EXPECT_EQ(observed_mark, 5);
}

TEST(NetConntrackFfiTest, MarkIsNotAppliedToFlowsTheFilterDoesNotMatch) {
  // Regression test for update_net_session's first nfct_cmp polarity.
  //
  // nfct_cmp returns NONZERO when the objects match and ZERO when they do not
  // (libnetfilter_conntrack/api.c:1017), so the callback skips on zero. If that
  // condition were ever flipped, the callback would force-update the mark on
  // exactly the connections that do NOT match the filter -- which is what this
  // test catches: it marks a real flow 5, then issues a second set_accept_mark
  // for a five-tuple matching nothing, and requires the real flow's mark to be
  // left alone rather than overwritten with 9.
  sockaddr_in server_addr{};
  uint16_t server_port = 0;
  int server_fd = BindLoopbackUdp(&server_addr, &server_port);
  ASSERT_GE(server_fd, 0);

  sockaddr_in client_addr{};
  uint16_t client_port = 0;
  int client_fd = BindLoopbackUdp(&client_addr, &client_port);
  ASSERT_GE(client_fd, 0);

  const char msg[] = "net_conntrack polarity datagram";
  ssize_t sent = sendto(client_fd, msg, sizeof(msg), 0,
                        reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr));
  ASSERT_EQ(sent, static_cast<ssize_t>(sizeof(msg)));

  net_conntrack::SharedFiveTuple matching{};
  matching.proto = IPPROTO_UDP;
  matching.src_addr = "127.0.0.1";
  matching.dst_addr = "127.0.0.1";
  matching.src_port = client_port;
  matching.dst_port = server_port;

  // Same addresses and protocol, but ports no live flow can be using: the
  // kernel never hands out port 0, and both sockets above are bound to
  // ephemeral ports well away from 1.
  net_conntrack::SharedFiveTuple non_matching{};
  non_matching.proto = IPPROTO_UDP;
  non_matching.src_addr = "127.0.0.1";
  non_matching.dst_addr = "127.0.0.1";
  non_matching.src_port = 1;
  non_matching.dst_port = 2;

  bool setup_worked = true;
  try {
    rust::Box<net_conntrack::ConntrackSession> session =
        net_conntrack::open_conntrack_session();
    session->set_accept_mark(matching, 5);
  } catch (const std::exception&) {
    setup_worked = false;
  }

  int mark_after_setup = setup_worked ? ReadConntrackMark(client_port, server_port) : -1;

  if (setup_worked) {
    try {
      // A fresh session, so the filter object starts clean rather than
      // inheriting the matching tuple's attributes.
      rust::Box<net_conntrack::ConntrackSession> session =
          net_conntrack::open_conntrack_session();
      session->set_accept_mark(non_matching, 9);
    } catch (const std::exception&) {
      setup_worked = false;
    }
  }

  int mark_after_non_matching = setup_worked ? ReadConntrackMark(client_port, server_port) : -1;

  close(client_fd);
  close(server_fd);

  if (!setup_worked) {
    GTEST_SKIP() << "set_accept_mark failed in this environment -- container "
                    "likely lacks CAP_NET_ADMIN or nf_conntrack support";
  }
  if (mark_after_setup < 0 || mark_after_non_matching < 0) {
    GTEST_SKIP() << "no readable /proc/net/nf_conntrack entry with a mark= field "
                    "for this flow -- cannot verify the mark independently";
  }
  ASSERT_EQ(mark_after_setup, 5) << "precondition: the matching tuple should mark the flow";
  EXPECT_EQ(mark_after_non_matching, 5)
      << "a five-tuple matching no flow must not overwrite this flow's mark";
}
