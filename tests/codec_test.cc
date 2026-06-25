#include "http/codec.h"

#include "glog/logging.h"
#include "gtest/gtest.h"
#include <cstring>
#include <memory>
#include <string_view>
#include <type_traits>

#include "http/filter.h"
#include "http/http1/codec.h"
#include "http/utility.h"

namespace http {
class Http1CodecTest : public ::testing::Test {
protected:
  void SetUp() override {}

  http1::ConnectionImpl codec_{true, std::make_shared<HttpFilterManager>(1)};
};

TEST_F(Http1CodecTest, Dispatch) {
  std::string data{"POST https://1.2.3.4:8888/internal/platform/waf/"};
  std::string data1(
      "service?cluster=123 HTTP/1.1\r\ncontent-length: 3\r\n\r\n123");
  auto header = codec_.dispatch(data);
  // EXPECT_EQ(header.method_, "POST");
  // EXPECT_EQ(header.path_, "/internal/platform/waf/");
  // EXPECT_EQ(header.host_, "1.2.3.4");

  EXPECT_EQ(header.method_, "");
  EXPECT_EQ(header.path_, "");
  EXPECT_EQ(header.host_, "");

  header = codec_.dispatch(data1);
  EXPECT_EQ(header.method_, "POST");
  EXPECT_EQ(header.path_, "/internal/platform/waf/service");
  EXPECT_EQ(header.host_, "1.2.3.4");
}

TEST_F(Http1CodecTest, Dispatch1) {

  const char *put = "PUT /internal/platform/waf/service?cluster=123 "
                    "HTTP/1.1\r\nHost: abc.com:9090\r\nContent-Type: "
                    "application/json\r\nContent-Length: 39\r\n\r\n{\n  \"id\": "
      "94,\n\"name\": "
      "\"测试应用5\"\n}";
  auto header = codec_.dispatch(std::string_view{put, strlen(put)});
  std::cout << header << std::endl;
  EXPECT_EQ(header.parseState_, ParseState::Done);
  EXPECT_EQ(codec_.getHost(), "abc.com:9090");
  EXPECT_EQ(header.host_, "abc.com");
  EXPECT_EQ(header.path_, "/internal/platform/waf/service");
}

} // namespace http

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  fLB::FLAGS_alsologtostderr = true;
  return RUN_ALL_TESTS();
}