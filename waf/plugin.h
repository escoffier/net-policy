#pragma once

#include <cstddef>

#include "http/filter.h"
#include "rule.h"

namespace grpc_bridge { class EventBridge; }

// Dual-publishes a WAF attack event to the new Rust EventService (Phase 3
// migration) -- extracted as a free function (rather than inlined in
// PluginContext::onClose) so it's testable directly with a constructed
// Rules/AttackedLog, without needing to drive PluginContext's private
// ruleArr_/atlog_ state through a full HTTP request/response cycle.
void PublishWafAttackToRustEventService(Rules& rule_ctx, AttackedLog& log);

namespace http {
namespace extension {

class PluginRootContext;

class PluginContext : public HttpFilter {
public:
  PluginContext(size_t id, uint32_t from, uint32_t to, PluginRootContext* root_ctx)
      : HttpFilter(id, from, to), root_ctx_(root_ctx) {}

  FilterStatus onRequestHeaders(RequestHeaderMap &headers, bool end_of_stream) override;

  FilterStatus onRequestBody(seastar::net::packet &p, bool end_of_stream) override;

  FilterStatus onResponseBody(seastar::net::packet &p, bool end_of_stream) override;

  FilterStatus onResponseHeaders(RequestHeaderMap &headers, bool end_of_stream) override;

  FilterStatus onNewConnection(const net::ConnectionInfo &streamInfo) override;

  FilterStatus onData(seastar::net::packet &data) override;

  FilterStatus onClose() override;

  FilterStatus ModifyNetPackets();

  std::string GetRequestHeaderInfo(RequestHeaderMap &headers,
                                   std::vector<std::string> &matchFunc,
                                   std::string key);

private:
  PluginRootContext* root_ctx_;
  Rules ruleArr;
  std::string forwardIp_;
  AttackedLog atlog = {};
};

class PluginRootContext {
private:
  int *post_fd_;
  grpc_bridge::EventBridge* event_bridge_ = nullptr;
  std::unordered_map<std::string, Rules> waf_rules_;

public:
  PluginRootContext();
  ~PluginRootContext();

  void SetPostFd(int *fd) { post_fd_ = fd; }

  /*non-owning; wired once at startup after the gRPC server exists*/
  void SetEventBridge(grpc_bridge::EventBridge* eb) { event_bridge_ = eb; }
  grpc_bridge::EventBridge* GetEventBridge() const { return event_bridge_; }

  int HttpPost(std::string value);

  bool ParseConfiguration(char *config);

  /*find waf rule*/
  bool GetWafRule(std::string ip, Rules &rule) {
    auto it = waf_rules_.find(ip);
    if (it == waf_rules_.end())
      return false;
    /*rule*/
    rule = it->second;
    return true;
  }

  /*waf rule size*/
  size_t GetWafRuleSize() { return waf_rules_.size(); }

  /*remove waf rule*/
  bool RemoveWafRule(char *config);

  /*insert waf rule*/
  bool InsertWafRule(std::string ip, Rules &rule);
};

} // namespace extension
} // namespace http
