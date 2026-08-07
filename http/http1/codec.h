#pragma once

#include "http/codec.h"
#include "http/connection.h"
#include "http/filter.h"
#include "http/header.h"
#include "http1_codec_cxxbridge/lib.h"
#include "rust/cxx.h"

#include <memory>
#include <string>
#include <string_view>

namespace http {
namespace http1 {

// Thin C++ adapter over crates/http1_codec's Rust parser. Keeps the exact
// class name, namespace, constructor signature, and public interface the
// old llhttp-based implementation had, so http/connection.cc's createCodec
// call site and tests/codec_test.cc's existing tests need no changes --
// see docs/superpowers/plans/2026-08-06-phase3a-http1-codec.md Task 6.
class ConnectionImpl : public Codec {
public:
  ConnectionImpl(bool serverSide, HttpFilterManagerPtr filterManager);

  ~ConnectionImpl();

  const Header &dispatch(std::string_view data) override;

  const FilterStatus dispatch(seastar::net::packet data) override;

  void addFilter(HttpFilterPtr filter) override;

  void setFilterManager(HttpFilterManagerPtr filterManager) override;

  // Returns the raw (port-included) value of the most recently seen Host
  // header, or empty if none was seen -- mirrors the old private host_
  // member exactly, including that it's distinct from header_.host_'s
  // resolved-and-possibly-port-stripped value. Has no production caller
  // (see the design spec); kept only so tests/codec_test.cc's existing
  // Dispatch1 test needs no changes.
  std::string getHost() const { return raw_host_header_; }

private:
  const Header &applyParsedHeader(const http1_codec::ParsedHeader &parsed);

  rust::Box<http1_codec::Http1Parser> parser_;
  Header header_;
  std::string raw_host_header_;
  HttpFilterManagerPtr filters_manager_;
  RequestHeaderMap headerMap_;
  bool serverSide_;
  FilterStatus status_;
};
} // namespace http1
} // namespace http
