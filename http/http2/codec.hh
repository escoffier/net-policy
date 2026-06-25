#pragma once

#include "http/codec.h"
#include "http/connection.h"
#include "http/filter.h"
#include "http/packet.hh"

#include <cstddef>
#include <iostream>
#include <memory>
#include <nghttp2/nghttp2.h>
#include <string_view>

namespace http {
namespace http2 {

using SessionDeletor = void (*)(nghttp2_session*);
using CallbackDeletor = void (*)(nghttp2_session_callbacks*);
using session_unque_ptr = std::unique_ptr<nghttp2_session, SessionDeletor>;

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))
// class Connection {
// public:
//   Connection();
//   ~Connection(){};
//   int64_t processData(std::string_view data);

//   int sendServerConnHeaer() {
//     std::cout << "submits SETTINGS frame." << std::endl;
//     nghttp2_settings_entry iv[1] = {
//         {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
//     auto rv = nghttp2_submit_settings(session_.get(), NGHTTP2_FLAG_NONE, iv,
//                                       ARRLEN(iv));
//     if (rv != 0) {
//       std::cout << "Fatal error: " << nghttp2_strerror(rv) << std::endl;
//       return -1;
//     }
//     return 0;
//   }

// private:
//   session_unque_ptr session_;

// public:
//   static nghttp2_session_callbacks *callbacks_;
// };

class codec {};

class ConnectionImpl : public Codec {
public:
  ConnectionImpl(bool serverSide, HttpFilterManagerPtr filterManager);

  const Header& dispatch(std::string_view data) override;

  const FilterStatus dispatch(seastar::net::packet data) override;

  inline void setPath(std::string_view path) { header_.path_ = path; }

  inline void setHost(std::string_view host) { header_.host_ = host; }

  inline void setMethod(std::string_view method) { header_.method_ = method; }

  void onUrl(std::string_view url);

  void onUrlComplete();

  bool isHeaderComplete();

  void onHeadersComplete() { header_.parseState_ = ParseState::Done; };

  void addFilter(HttpFilterPtr filter) override;

  void setFilterManager(HttpFilterManagerPtr filterManager) override;

  HttpFilterManagerPtr getFilterManager() { return filters_manager_; };

  std::string_view getBufferData(size_t len);

  void trimBufFront(size_t length);

  static nghttp2_session_callbacks* callbacks_;

private:
  session_unque_ptr session_;
  Header header_;
  std::string url_;
  seastar::net::packet packet_;
  HttpFilterManagerPtr filters_manager_;
  FilterStatus status_;
};

} // namespace http2
} // namespace http