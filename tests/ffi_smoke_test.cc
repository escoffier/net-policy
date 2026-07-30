#include <gtest/gtest.h>
#include "ffi_smoke_cxxbridge/lib.h"

TEST(FfiSmokeTest, RustPingReturns42) {
  EXPECT_EQ(ffi_smoke::rust_ping(), 42);
}
