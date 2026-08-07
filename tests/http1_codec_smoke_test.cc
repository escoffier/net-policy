#include <cstring>
#include <gtest/gtest.h>
#include "http1_codec_cxxbridge/lib.h"

TEST(Http1CodecSmokeTest, ParserConstructsAndDispatchesOneRequest) {
  auto parser = http1_codec::new_http1_parser();
  const char* req = "GET /foo HTTP/1.1\r\n\r\n";
  auto result = parser->dispatch(
      rust::Slice<const uint8_t>(reinterpret_cast<const uint8_t*>(req), strlen(req)));
  EXPECT_EQ(result.parse_state, 1);
  EXPECT_EQ(std::string(result.method), "GET");
  EXPECT_EQ(std::string(result.path), "/foo");
}
