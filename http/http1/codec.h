#pragma once

#include "http/codec.h"
#include "http/connection.h"
#include "http/filter.h"
#include "http/header.h"
#include "llhttp.h"

// #include "http/http1/http_parser.h"
#include <string>
#include <string_view>
#include <vector>

namespace http {
namespace http1 {
class ConnectionImpl : public Codec {
public:
  ConnectionImpl(bool serverSide, HttpFilterManagerPtr filterManager);

  ~ConnectionImpl();

  const Header &dispatch(std::string_view data) override;

  const FilterStatus dispatch(seastar::net::packet data) override;

  void addFilter(HttpFilterPtr filter) override;

  void setFilterManager(HttpFilterManagerPtr filterManager) override;

  inline void setPath(std::string_view path) { header_.path_ = path; }

  inline void setHost(std::string_view host) { header_.host_ = host; }

  inline void setMethod(std::string_view method) { header_.method_ = method; }

  inline std::string_view getHost() const { return host_; }

  void onUrl(std::string_view url);

  void onUrlComplete();

  void onHeadersComplete();

  int onBodyComplete(std::string_view body);

  void onHeaderField(std::string field) {
    header_fields_.push_back(field);
  };

  void onHeaderValue(std::string value) {
    header_values_.push_back(value);
  };

private:
  // http_parser parser_;
  // http_parser_settings settings_;
  llhttp_t parser_;
  llhttp_settings_t settings_;
  // http_parser_settings settings_;
  Header header_;
  std::string url_;
  std::string_view host_;
  std::vector<std::string> header_fields_;
  std::vector<std::string> header_values_;
  HttpFilterManagerPtr filters_manager_;
  RequestHeaderMap headerMap_;
  bool serverSide_;
  FilterStatus status_;
};
} // namespace http1
} // namespace http