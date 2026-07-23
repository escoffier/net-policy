#include "codec.h"

#include <cctype>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <memory>
#include <ostream>
#include <string_view>
#include <utility>

// #include "http/http1/http_parser.h"
#include "common/utility.h"
#include "glog/logging.h"
// #include "http/connection_manager.h"
#include "http/filter.h"
#include "llhttp.h"

#include "http/codec.h"
#include "http/url.hh"
#include "http/utility.h"

namespace http {
namespace http1 {
const Header& ConnectionImpl::dispatch(std::string_view data) {
  // auto ret =
  //     http_parser_execute(&parser_, &settings_, data.data(), data.length());
  // if (HTTP_PARSER_ERRNO(&parser_) != HPE_OK &&
  //     HTTP_PARSER_ERRNO(&parser_) != HPE_PAUSED) {
  //   std::cout << "parse err: " << HTTP_PARSER_ERRNO(&parser_) << std::endl;
  //   return Header{};
  // }
  auto ret = llhttp_execute(&parser_, data.data(), data.length());
  if (ret != HPE_OK && ret != HPE_PAUSED) {
    LOG(ERROR) << "parse err: " << llhttp_errno_name(ret);
    // std::cout << "parse err: " << llhttp_errno_name(ret) << std::endl;
    header_.parseState_ = ParseState::Error;
    return header_;
  }
  std::cout << "parsed bytes: " << ret << std::endl;
  return header_;
}

const FilterStatus ConnectionImpl::dispatch(seastar::net::packet pkt) {
  auto data = pkt.get_header(0, pkt.len());
  VLOG(8) << "dispatching " << pkt.len() << " bytes data";

  auto ret = llhttp_execute(&parser_, data, pkt.len());
  if (ret != HPE_OK && ret != HPE_PAUSED) {
    LOG(ERROR) << "parse err: " << llhttp_errno_name(ret);
    // std::cout << "parse err: " << llhttp_errno_name(ret) << std::endl;
    header_.parseState_ = ParseState::Error;
    return status_;
  }
  VLOG(4) << "parsed bytes: " << ret << " status: " << int(status_);
  return status_;
}

void ConnectionImpl::addFilter(HttpFilterPtr filter) { filters_manager_->addFilter(filter); }

void ConnectionImpl::setFilterManager(HttpFilterManagerPtr filterManager) {
  filters_manager_ = filterManager;
}

void ConnectionImpl::onUrl(std::string_view url) {
  url_.append(url);
  VLOG(6) << "url : " << url_ << std::endl;
}

void ConnectionImpl::onUrlComplete() {
  Url u;
  u.initialize(url_, false);
  setHost(u.host());
  setPath(u.path());
  VLOG(4) << "url complete: " << header_;
  // header_.completed = true;
}

void ConnectionImpl::onHeadersComplete() {
  if (header_fields_.size() != header_values_.size()) {
    return;
  }
  for (size_t i = 0; i < header_fields_.size(); i++) {
    if (header_fields_[i] == "Host" || header_fields_[i] == "host") {
      host_ = header_values_[i];
      if (header_.host_ == "") {
        auto n = host_.find_last_of(":");
        header_.host_ = host_.substr(0, n);
      }
    }

    headerMap_.add(utility::toLow(header_fields_[i]), utility::toLow(header_values_[i]));
  }

  headerMap_.add({":host"}, header_.host_);
  headerMap_.add({":method"}, header_.method_);
  headerMap_.add({":path"}, header_.path_);

  header_.parseState_ = ParseState::Done;
  status_ = filters_manager_->decodeHeaders(headerMap_, serverSide_);
}

int ConnectionImpl::onBodyComplete(std::string_view body) {
  auto p = seastar::net::packet::from_static_data(body.data(), body.length());
  status_ = filters_manager_->decodeBody(std::move(p), serverSide_);
  return 0;
}

ConnectionImpl::ConnectionImpl(bool serverSide, HttpFilterManagerPtr filterManager)
    : parser_(), settings_(), header_{"", "", "", ParseState::Continue}, url_(),
      filters_manager_(filterManager), serverSide_(serverSide) {

  // filters_manager_ = std::make_unique<HttpFilterManager>(serverSide);
  // http_parser_settings_init(&settings_);
  // settings_.on_url = [](http_parser *parser, const char *at,
  //                       size_t length) -> int {
  //   auto codec = reinterpret_cast<ConnectionImpl *>(parser->data);

  //   std::string_view url_str(at, length);
  //   codec->onUrl(url_str);
  //   auto method = http_method(parser->method);
  //   codec->setMethod(http_method_str(method));
  //   return 0;
  // };
  // http_parser_init(&parser_, HTTP_REQUEST);

  llhttp_settings_init(&settings_);
  settings_.on_message_begin = [](llhttp_t* parser) -> int {
    reinterpret_cast<ConnectionImpl*>(parser->data)->resetState();
    return 0;
  };
  settings_.on_method = [](llhttp_t* parser, const char* at, size_t length) -> int { return 0; };
  settings_.on_method_complete = [](llhttp_t* parser) -> int {
    VLOG(6) << "method: " << llhttp_method_name((llhttp_method_t)parser->method) << std::endl;
    return 0;
  };

  settings_.on_url = [](llhttp_t* parser, const char* at, size_t length) -> int {
    auto codec = reinterpret_cast<ConnectionImpl*>(parser->data);
    codec->onUrl(std::string_view{at, length});
    return 0;
  };

  settings_.on_url_complete = [](llhttp_t* parser) -> int {
    auto method = llhttp_method_name((llhttp_method_t)parser->method);
    auto codec = reinterpret_cast<ConnectionImpl*>(parser->data);
    codec->setMethod(std::string_view{method, strlen(method)});
    codec->onUrlComplete();
    return 0;
  };

  settings_.on_header_field = [](llhttp_t* parser, const char* at, size_t length) -> int {
    auto codec = reinterpret_cast<ConnectionImpl*>(parser->data);
    std::string field{at, length};
    VLOG(6) << "header field: " << field;
    codec->onHeaderField(field);
    return 0;
  };

  settings_.on_header_value = [](llhttp_t* parser, const char* at, size_t length) -> int {
    auto codec = reinterpret_cast<ConnectionImpl*>(parser->data);
    std::string value{at, length};
    VLOG(6) << "header value: " << value;
    codec->onHeaderValue(value);
    return 0;
  };

  settings_.on_headers_complete = [](llhttp_t* parser) -> int {
    auto codec = reinterpret_cast<ConnectionImpl*>(parser->data);
    codec->onHeadersComplete();
    return 0;
  };

  settings_.on_body = [](llhttp_t* parser, const char* at, size_t length) -> int {
    auto codec = reinterpret_cast<ConnectionImpl*>(parser->data);
    VLOG(4) << "body length: " << length;
    std::string_view body{at, length};
    codec->onBodyComplete(body);
    return 0;
  };

  llhttp_init(&parser_, HTTP_BOTH, &settings_);
  parser_.data = this;
}

ConnectionImpl::~ConnectionImpl() {
  // llhttp_free(&parser_);
}
} // namespace http1
} // namespace http
