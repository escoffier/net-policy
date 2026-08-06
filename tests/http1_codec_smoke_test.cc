#include <gtest/gtest.h>
#include "http1_codec_cxxbridge/lib.h"

TEST(Http1CodecSmokeTest, RustPingReturns42) {
  EXPECT_EQ(http1_codec::rust_ping(), 42);
}
