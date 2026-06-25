#pragma once

#include "http/utility.h"
#include <llhttp.h>
#include <string_view>
namespace http {
enum class Protocol : uint8_t { Http10, Http11, Http2, Http3 };

class HttpInspector {
public:
  HttpInspector();
  ~HttpInspector();
  ParseState parseHttpHeader(std::string_view data);
  Protocol getProtocol() const { return protocol_; };

private:
  static const std::string_view HTTP2_CONNECTION_PREFACE;
  llhttp_t parser_;
  llhttp_settings_t settings_;
  Protocol protocol_;
};
} // namespace http