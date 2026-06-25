#include "http_inspector.h"

#include <algorithm>
#include <string_view>

#include "llhttp.h"
namespace http {
const std::string_view HttpInspector::HTTP2_CONNECTION_PREFACE =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

HttpInspector::HttpInspector() {
  llhttp_settings_init(&settings_);
  llhttp_init(&parser_, HTTP_BOTH, &settings_);
}

HttpInspector::~HttpInspector() {
  // llhttp_free(&parser_);
}

ParseState HttpInspector::parseHttpHeader(std::string_view data) {
  size_t len =
      std::min(data.length(), HttpInspector::HTTP2_CONNECTION_PREFACE.length());
  if (HttpInspector::HTTP2_CONNECTION_PREFACE.compare(0, len, data, 0, len) ==
      0) {
    if (data.length() < HttpInspector::HTTP2_CONNECTION_PREFACE.length()) {
      return ParseState::Continue;
    }
    protocol_ = Protocol::Http2;
    return ParseState::Done;
  } else {
    if (data[0] == '\r' || data[0] == '\n') {
      return ParseState::Error;
    }

    // std::string_view new_data = data.substr(parser_.data);
    const size_t pos = data.find_first_of("\r\n");
    if (pos != std::string_view::npos) {
      std::string_view new_data = data.substr(0, pos + 1);
      auto ret = llhttp_execute(&parser_, new_data.data(), new_data.length());
      if (ret != HPE_OK && ret != HPE_PAUSED) {
        return ParseState::Error;
      }
      protocol_ = Protocol::Http11;
      return ParseState::Done;
    } else {
      auto ret = llhttp_execute(&parser_, data.data(), data.length());
      if (ret != HPE_OK && ret != HPE_PAUSED) {
        return ParseState::Error;
      } else {
        return ParseState::Continue;
      }
    }
  }
}
} // namespace http