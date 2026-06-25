#pragma once

#include <string>
#include <memory>
#include <string_view>
#include <list>

#include "codec.h"
#include "http/http_inspector.h"
#include "http/packet.hh"
#include "http/filter.h"

namespace http {

using HttpCodecPtr = std::unique_ptr<Codec>;

class Connection;

using ConnectionPtr = std::unique_ptr<Connection>;

using HttpInspectorPtr = std::unique_ptr<HttpInspector>;

class Connection {
public:
  Connection(bool server, HttpFilterManagerPtr filterManager);
  Connection(std::string key);
  void createCodec(Protocol protocol);
  void setTcpSeq(int64_t seq) { tcp_seq_ = seq; }
  int64_t getTcpSeq() { return tcp_seq_; }
  const std::string& getRuleKey() const { return rule_key_; }
  const Header& onData(std::string_view data);

  FilterStatus processData(seastar::net::packet p);

  void registerFilter(HttpFilterPtr filter);

  HttpFilterManagerPtr httpFilterManager() { return filters_manager_; }

private:
  int64_t tcp_seq_;
  std::string rule_key_;
  HttpCodecPtr codec_;
  HttpInspectorPtr inspector_;
  Header header_;
  seastar::net::packet packet_;
  HttpFilterManagerPtr filters_manager_{};
  bool server_side_;
};
} // namespace http