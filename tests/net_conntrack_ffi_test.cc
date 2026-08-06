// Placeholder suite for this plan's conntrack port. Task 2 only adds raw
// extern "C" FFI declarations (crates/net_conntrack/src/ffi_raw.rs) with no
// safe wrapper exposed over the cxx bridge yet, so there is nothing to call
// through net_conntrack_cxxbridge/lib.h from C++ at this point. Real
// (CAP_NET_ADMIN-gated) session/mark tests are added in Task 3 once the safe
// ConntrackSession wrapper exists.
#include <gtest/gtest.h>

#include "net_conntrack_cxxbridge/lib.h"

TEST(NetConntrackFfiTest, Placeholder) { SUCCEED(); }
