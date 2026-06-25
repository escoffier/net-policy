
#include "http/filter.h"
#include "http/http2/codec.hh"
#include "http/utility.h"
#include <gtest/gtest.h>
#include <memory>
#include <nghttp2/nghttp2.h>

namespace http {
namespace http2 {
#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)(NAME), (uint8_t *)(VALUE), sizeof((NAME)) - 1,                 \
        sizeof((VALUE)) - 1, NGHTTP2_NV_FLAG_NONE                              \
  }

class Http2CodecTest : public ::testing::Test {
protected:
  void SetUp() override {}
  ConnectionImpl codec_{true, std::make_shared<HttpFilterManager>()};
};

TEST_F(Http2CodecTest, dispatch1) {
  // const nghttp2_nv reqnv[] = {
  //     MAKE_NV(":method", "GET"),
  //     MAKE_NV(":path", "/"),
  //     MAKE_NV(":scheme", "https"),
  //     MAKE_NV(":authority", "localhost"),
  // };

  auto header = codec_.dispatch("dddd");
  EXPECT_EQ(header.parseState_, ParseState::Error);
}
} // namespace http2
} // namespace http