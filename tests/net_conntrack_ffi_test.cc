// Placeholder suite for this plan's conntrack port. Real (CAP_NET_ADMIN-
// gated) session/mark tests are added in Task 3.
#include <gtest/gtest.h>

#include "net_conntrack_cxxbridge/lib.h"

TEST(NetConntrackFfiTest, CrateLinksAndRuns) {
  EXPECT_EQ(net_conntrack::ping(), 42);
}
