#include "http/codec.h"

#include "glog/logging.h"
#include "gtest/gtest.h"
#include <cstring>
#include <memory>
#include <string_view>
#include <type_traits>

#include "http/filter.h"
#include "http/http1/codec.h"
#include "http/http_filter_factory.h"
#include "http/utility.h"

namespace http {
class Http1CodecTest : public ::testing::Test {
protected:
  void SetUp() override {}

  // empty factory -- no filters registered, matching this test's previous
  // behavior (it never registered any either)
  HttpFilterFactory factory_;
  http1::ConnectionImpl codec_{true, std::make_shared<HttpFilterManager>(factory_, 1, 0, 0)};
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

TEST_F(Http1CodecTest, ChunkedRequestBodyDoesNotBlockHeaderParsing) {
  const char* req = "POST /upload HTTP/1.1\r\nHost: example.com\r\n"
                     "Transfer-Encoding: chunked\r\n\r\n"
                     "3\r\nfoo\r\n0\r\n\r\n";
  auto header = codec_.dispatch(std::string_view{req, strlen(req)});
  EXPECT_EQ(header.parseState_, ParseState::Done);
  EXPECT_EQ(header.method_, "POST");
  EXPECT_EQ(header.path_, "/upload");
  EXPECT_EQ(header.host_, "example.com");
}

TEST_F(Http1CodecTest, PipelinedRequestsInOneCallReturnOnlyTheLastOne) {
  const char* req = "GET /first HTTP/1.1\r\n\r\nGET /second HTTP/1.1\r\n\r\n";
  auto header = codec_.dispatch(std::string_view{req, strlen(req)});
  EXPECT_EQ(header.parseState_, ParseState::Done);
  EXPECT_EQ(header.path_, "/second");
}

TEST_F(Http1CodecTest, ChunkedBodyDoesNotCorruptFollowingPipelinedRequest) {
  const char* req = "POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
                     "3\r\nfoo\r\n0\r\n\r\n"
                     "GET /next HTTP/1.1\r\n\r\n";
  auto header = codec_.dispatch(std::string_view{req, strlen(req)});
  EXPECT_EQ(header.parseState_, ParseState::Done);
  EXPECT_EQ(header.path_, "/next");
}

TEST_F(Http1CodecTest, OriginFormHostFallsBackToHostHeaderWithPortStripped) {
  const char* req = "GET /foo HTTP/1.1\r\nHost: example.com:9090\r\n\r\n";
  auto header = codec_.dispatch(std::string_view{req, strlen(req)});
  EXPECT_EQ(header.parseState_, ParseState::Done);
  EXPECT_EQ(header.host_, "example.com");
  EXPECT_EQ(codec_.getHost(), "example.com:9090");
}

TEST_F(Http1CodecTest, HostHeaderWithoutPortIsNotTruncated) {
  const char* req = "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n";
  auto header = codec_.dispatch(std::string_view{req, strlen(req)});
  EXPECT_EQ(header.host_, "example.com");
}

TEST_F(Http1CodecTest, AbsoluteFormHostWinsOverHostHeader) {
  const char* req = "GET https://1.2.3.4:8888/foo HTTP/1.1\r\nHost: other.example.com\r\n\r\n";
  auto header = codec_.dispatch(std::string_view{req, strlen(req)});
  EXPECT_EQ(header.host_, "1.2.3.4");
  EXPECT_EQ(header.path_, "/foo");
}

TEST_F(Http1CodecTest, MalformedRequestLineReportsError) {
  const char* req = "NOT A REQUEST\r\n\r\n";
  auto header = codec_.dispatch(std::string_view{req, strlen(req)});
  EXPECT_EQ(header.parseState_, ParseState::Error);
}

TEST_F(Http1CodecTest, TrailingGarbageAfterCompletedRequestDoesNotDiscardResult) {
  // A body-less request completes successfully, but the same dispatch()
  // call's buffer has one stray trailing byte left over (not a valid, even
  // partial, next request-line). This must not discard the already-Done
  // result -- the exact bug Task 5's own fix round found and fixed in
  // dispatch()'s loop (crates/http1_codec/src/lib.rs), reproduced here at
  // the C++ adapter layer where it had no coverage until now. Built via
  // std::string + push_back rather than a C-string literal, since a NUL
  // byte can't survive strlen()-based length inference -- exactly the
  // class of bug that originally surfaced this issue via a smoke test.
  std::string req = "GET /foo HTTP/1.1\r\n\r\n";
  req.push_back('\0');
  auto header = codec_.dispatch(std::string_view{req});
  EXPECT_EQ(header.parseState_, ParseState::Done);
  EXPECT_EQ(header.path_, "/foo");
}

} // namespace http

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  fLB::FLAGS_alsologtostderr = true;
  return RUN_ALL_TESTS();
}