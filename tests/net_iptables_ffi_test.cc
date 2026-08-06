// These tests shell out to real `iptables` commands against the mangle
// table (creating/deleting the TS_ZERO_PREROUTING/TS_ZERO_OUTPUT chains and
// their jump rules), so they require CAP_NET_ADMIN -- run this binary via
// `docker run/exec --privileged` (or `--cap-add=NET_ADMIN`), not a plain
// unprivileged container/exec. See CLAUDE.md's Build Commands section.
//
// Cross-process isolation hazard: these tests and the `net_iptables` Rust
// crate's own `cargo test` suite both mutate the same global iptables state
// (fixed chain names TS_ZERO_PREROUTING/TS_ZERO_OUTPUT, plus rules appended
// directly to the builtin INPUT/OUTPUT/PREROUTING/POSTROUTING chains) with no
// cross-process lock -- only a same-process Mutex on the Rust side. Nothing
// in this repo currently runs this binary and `cargo test` concurrently in
// the same container/network namespace, so this isn't a live bug today, but
// if a future CI change ever parallelizes them, the same
// create/flush/delete-chain flakiness an earlier task diagnosed and fixed
// *within* one process (see the IPTABLES_TEST_LOCK comment in
// crates/net_iptables/src/lib.rs) could reappear *across* processes. Do not
// run this binary concurrently with `cargo test` in `crates/net_iptables`
// (or any other process touching the same chains) in the same
// container/namespace.

#include <gtest/gtest.h>

#include "net_iptables_cxxbridge/lib.h"

TEST(NetIptablesFfiTest, GetIptablesVersionReturnsZeroOrOne) {
  int v = net_iptables::get_iptables_version();
  EXPECT_TRUE(v == 0 || v == 1);
}

TEST(NetIptablesFfiTest, CheckWriteClearRoundTrip) {
  net_iptables::clear_iptables_rule(0);  // best-effort pre-cleanup
  EXPECT_FALSE(net_iptables::check_iptables_rule(0));
  net_iptables::write_iptable_rule(100, 101, 0);
  EXPECT_TRUE(net_iptables::check_iptables_rule(0));
  net_iptables::clear_iptables_rule(0);
  EXPECT_FALSE(net_iptables::check_iptables_rule(0));
}
