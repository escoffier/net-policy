#include <map>
#include <memory>

#include <gtest/gtest.h>

#include "http/filter.h"
#include "http/utility.h"
#include "http/connection.h"

namespace http {
class ConnectionManagerTest : public ::testing::Test {
protected:
  void SetUp() override {}

  ConnectionPtr connPtr_;
};

TEST_F(ConnectionManagerTest, onData) {
  std::map<std::string, ConnectionPtr> connMaps;
  auto filterManager = std::make_shared<HttpFilterManager>();
  connMaps["test1"] = std::make_unique<Connection>(true, filterManager);

  std::string data{"POST https://1.2.3.4:8888/internal/platform/waf/"};
  std::string data1(
      "service?cluster=123 HTTP/1.1\r\ncontent-length: 3\r\n\r\n123");

  auto header = connMaps["test1"]->onData(data);
  EXPECT_EQ(header.parseState_, ParseState::Continue);

  header = connMaps["test1"]->onData(data1);
  EXPECT_EQ(header.method_, "POST");
  EXPECT_EQ(header.path_, "/internal/platform/waf/service");
  EXPECT_EQ(header.host_, "1.2.3.4");
  EXPECT_EQ(header.parseState_, ParseState::Done);
}

} // namespace http