#pragma once

#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
namespace http {

/**
 * Default O(1) request and response headers.
 */
#define INLINE_REQ_RESP_STRING_HEADERS(HEADER_FUNC)                                                \
  HEADER_FUNC(Connection)                                                                          \
  HEADER_FUNC(ContentType)                                                                         \
  HEADER_FUNC(EnvoyDecoratorOperation)                                                             \
  HEADER_FUNC(KeepAlive)                                                                           \
  HEADER_FUNC(ProxyConnection)                                                                     \
  HEADER_FUNC(ProxyStatus)                                                                         \
  HEADER_FUNC(RequestId)                                                                           \
  HEADER_FUNC(TransferEncoding)                                                                    \
  HEADER_FUNC(Upgrade)                                                                             \
  HEADER_FUNC(Via)

// // Base class for both request and response headers.
// class RequestOrResponseHeaderMap : public HeaderMap {
// public:
//   INLINE_REQ_RESP_STRING_HEADERS(DEFINE_INLINE_STRING_HEADER)
//   INLINE_REQ_RESP_NUMERIC_HEADERS(DEFINE_INLINE_NUMERIC_HEADER)
// };

// // Request headers.
// class RequestHeaderMap
//     : public RequestOrResponseHeaderMap,
// public:
//   INLINE_REQ_STRING_HEADERS(DEFINE_INLINE_STRING_HEADER)
//   INLINE_REQ_NUMERIC_HEADERS(DEFINE_INLINE_NUMERIC_HEADER)
// };

class RequestHeaderMap {
public:
  std::string_view getHost() const;

  std::string getHttpHeader(std::string key) {
    std::string value;
    auto it = kv_.find(key);
    if (it != kv_.end()) {
      return value.assign(it->second.data(), it->second.length());
    } else {
      return "";
    }
  }

  std::unordered_map<std::string, std::string>& getHttpHeaderPairs() { return kv_; }

  void add(std::string key, std::string value) { kv_.insert({key, value}); };

  void clear() { kv_.clear(); }

  friend std::ostream& operator<<(std::ostream& os, RequestHeaderMap& headers);

private:
  std::unordered_map<std::string, std::string> kv_;
};
} // namespace http