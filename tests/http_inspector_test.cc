#include "http/http_inspector.h"

#include <iostream>
#include <memory>

#include <gtest/gtest.h>

#include "http/connection.h"

namespace http {
class HttpInspectorTest : public ::testing::Test {
protected:
  void SetUp() override {}

  HttpInspectorPtr inspector_;
};

TEST_F(HttpInspectorTest, parseHttpHeader) {
  inspector_ = std::make_unique<HttpInspector>();
  std::string data{"POST https://1.2.3.4:8888/internal/platform/waf/"};
  std::string data1(
      "service?cluster=123 HTTP/1.1\r\ncontent-length: 3\r\n\r\n123");
  auto st = inspector_->parseHttpHeader(data);
  if (st == ParseState::Continue) {
    st = inspector_->parseHttpHeader(data1);
  }
  EXPECT_EQ(st, ParseState::Done);
  EXPECT_EQ(inspector_->getProtocol(), Protocol::Http11);
}
} // namespace http
