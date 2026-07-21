#pragma once

#include <cstddef>

#include "http/filter.h"
#include "net-policy.h"
#include "rule.h"


namespace http {
namespace extension {
class PluginContext : public HttpFilter {
public:
  // PluginContext() {}

  PluginContext(size_t id, uint32_t from, uint32_t to) : HttpFilter(id, from, to) {}

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
  Rules ruleArr;
  std::string forwardIp_;
  AttackedLog atlog = {};
};

class PluginRootContext {
private:
  int *post_fd_;
  std::unordered_map<std::string, Rules> waf_rules_;

public:
  PluginRootContext();
  ~PluginRootContext();

  void SetPostFd(int *fd) { post_fd_ = fd; }

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

extern PluginRootContext RootContext;

} // namespace extension
} // namespace http
