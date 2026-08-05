// Placeholder suite for this plan's NFQ netlink port. Real (CAP_NET_ADMIN-
// gated) queue open/recv/verdict tests are added in Task 3.
#include <gtest/gtest.h>

#include "net_nfq_cxxbridge/lib.h"

TEST(NetNfqFfiTest, CrateLinksAndRuns) {
  EXPECT_EQ(net_nfq::ping(), 42);
}
