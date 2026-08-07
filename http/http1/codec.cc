#include "codec.h"

#include <cstdint>
#include <utility>

#include "common/utility.h"
#include "glog/logging.h"
#include "http/filter.h"

namespace http {
namespace http1 {

ConnectionImpl::ConnectionImpl(bool serverSide, HttpFilterManagerPtr filterManager)
    : parser_(http1_codec::new_http1_parser()), header_{"", "", "", ParseState::Continue},
      filters_manager_(filterManager), serverSide_(serverSide) {}

ConnectionImpl::~ConnectionImpl() = default;

// Mirrors the old onHeadersComplete()'s headerMap_ construction and
// filters_manager_->decodeHeaders call exactly -- see the design spec's
// Non-Goal "any change to what the filter chain does with parsed headers."
// Only invoked when parsed.parse_state == Done.
const Header& ConnectionImpl::applyParsedHeader(const http1_codec::ParsedHeader& parsed) {
  header_.method_ = std::string(parsed.method);
  header_.path_ = std::string(parsed.path);
  header_.host_ = std::string(parsed.host);
  header_.parseState_ = ParseState::Done;

  headerMap_.clear();
  raw_host_header_.clear();
  for (const auto& f : parsed.fields) {
    std::string name(f.name);
    std::string value(f.value);
    if (name == "Host" || name == "host") {
      raw_host_header_ = value;
    }
    headerMap_.add(utility::toLow(name), utility::toLow(value));
  }
  headerMap_.add({":host"}, header_.host_);
  headerMap_.add({":method"}, header_.method_);
  headerMap_.add({":path"}, header_.path_);

  status_ = filters_manager_->decodeHeaders(headerMap_, serverSide_);
  return header_;
}

const Header& ConnectionImpl::dispatch(std::string_view data) {
  auto parsed = parser_->dispatch(
      rust::Slice<const uint8_t>(reinterpret_cast<const uint8_t*>(data.data()), data.length()));
  if (parsed.parse_state == /*Error*/ 2) {
    LOG(ERROR) << "http1_codec parse error";
    header_.parseState_ = ParseState::Error;
    return header_;
  }
  if (parsed.parse_state == /*Continue*/ 0) {
    header_.parseState_ = ParseState::Continue;
    return header_;
  }
  return applyParsedHeader(parsed);
}

const FilterStatus ConnectionImpl::dispatch(seastar::net::packet pkt) {
  auto data = pkt.get_header(0, pkt.len());
  VLOG(8) << "dispatching " << pkt.len() << " bytes data";

  auto parsed = parser_->dispatch(
      rust::Slice<const uint8_t>(reinterpret_cast<const uint8_t*>(data), pkt.len()));
  if (parsed.parse_state == /*Error*/ 2) {
    LOG(ERROR) << "http1_codec parse error";
    header_.parseState_ = ParseState::Error;
    return status_;
  }
  if (parsed.parse_state == /*Continue*/ 0) {
    header_.parseState_ = ParseState::Continue;
    return status_;
  }
  applyParsedHeader(parsed);
  return status_;
}

void ConnectionImpl::addFilter(HttpFilterPtr filter) { filters_manager_->addFilter(filter); }

void ConnectionImpl::setFilterManager(HttpFilterManagerPtr filterManager) {
  filters_manager_ = filterManager;
}

} // namespace http1
} // namespace http
