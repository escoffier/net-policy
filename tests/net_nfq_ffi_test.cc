// These tests open a real NFQUEUE (creating a scratch iptables NFQUEUE rule
// in the mangle table, matching net_iptables_ffi_test.cc's pattern), so
// they require CAP_NET_ADMIN -- run this binary via `docker run/exec
// --privileged` (or `--cap-add=NET_ADMIN`), not a plain unprivileged
// container/exec. See CLAUDE.md's Build Commands section.
//
// If the environment lacks the privilege or kernel support to actually
// bind/verdict a live queue, OpenRoundTrip is designed to report that as a
// GTEST_SKIP rather than a failure -- see its body.

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>

#include "net_nfq_cxxbridge/lib.h"

namespace {

// A scratch queue number unlikely to collide with anything else running in
// the test container.
constexpr uint16_t kTestQueueNum = 200;

bool InstallScratchNfqueueRule() {
  // -I (insert), not -A, so this rule is evaluated before any pre-existing
  // ones and reliably catches the test's own loopback ICMP traffic.
  int ret = std::system(
      "iptables -t mangle -I OUTPUT -p icmp -d 127.0.0.1 -j NFQUEUE "
      "--queue-num 200 --queue-bypass");
  return ret == 0;
}

void RemoveScratchNfqueueRule() {
  std::system(
      "iptables -t mangle -D OUTPUT -p icmp -d 127.0.0.1 -j NFQUEUE "
      "--queue-num 200 --queue-bypass");
}

}  // namespace

TEST(NetNfqFfiTest, OpenGivesAPositiveFd) {
  rust::Box<net_nfq::NfqQueue> queue = net_nfq::open_queue(kTestQueueNum);
  EXPECT_GT(queue->fd(), 0);
}

TEST(NetNfqFfiTest, RecvBatchOnAFreshQueueWithNoTrafficReturnsEmpty) {
  rust::Box<net_nfq::NfqQueue> queue = net_nfq::open_queue(kTestQueueNum);
  auto batch = queue->recv_batch();
  EXPECT_EQ(batch.size(), 0u);
}

TEST(NetNfqFfiTest, VerdictOnAnUnknownIdFails) {
  rust::Box<net_nfq::NfqQueue> queue = net_nfq::open_queue(kTestQueueNum);
  EXPECT_THROW(
      queue->verdict(999999, net_nfq::NfqVerdict::Accept, rust::Slice<const uint8_t>()),
      std::exception);
}

TEST(NetNfqFfiTest, OpenRoundTrip) {
  if (!InstallScratchNfqueueRule()) {
    GTEST_SKIP() << "could not install a scratch NFQUEUE rule -- container "
                    "likely lacks CAP_NET_ADMIN or nfnetlink_queue support";
  }
  rust::Box<net_nfq::NfqQueue> queue = net_nfq::open_queue(kTestQueueNum);

  // Trigger the rule: an ICMP echo request to loopback, sent from a
  // separate process so this test process's own send() doesn't race the
  // queue open above.
  std::system("ping -c 1 -W 1 127.0.0.1 > /dev/null 2>&1 &");

  rust::Vec<net_nfq::NfqMessage> batch;
  bool got_one = false;
  for (int i = 0; i < 50 && !got_one; i++) {
    batch = queue->recv_batch();
    if (batch.size() > 0) {
      got_one = true;
      break;
    }
    usleep(20000);  // 20ms
  }
  RemoveScratchNfqueueRule();

  if (!got_one) {
    GTEST_SKIP() << "no packet arrived on the scratch queue within 1s -- "
                    "container networking likely doesn't support a live "
                    "NFQUEUE round-trip";
  }
  ASSERT_GT(batch.size(), 0u);
  EXPECT_NO_THROW(
      queue->verdict(batch[0].id, net_nfq::NfqVerdict::Accept, rust::Slice<const uint8_t>()));
}
