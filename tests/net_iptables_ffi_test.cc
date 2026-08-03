#include <gtest/gtest.h>

#include "net_iptables_cxxbridge/lib.h"

TEST(NetIptablesFfiTest, GetIptablesVersionReturnsZeroOrOne) {
  int v = net_iptables::get_iptables_version();
  EXPECT_TRUE(v == 0 || v == 1);
}

TEST(NetIptablesFfiTest, CheckWriteClearRoundTrip) {
  net_iptables::clear_iptables_rule(0);  // best-effort pre-cleanup
  EXPECT_FALSE(net_iptables::check_iptables_rule(0));
  net_iptables::write_iptable_rule(100, 101, 0, /*waf_enable=*/true);
  EXPECT_TRUE(net_iptables::check_iptables_rule(0));
  net_iptables::clear_iptables_rule(0);
  EXPECT_FALSE(net_iptables::check_iptables_rule(0));
}
