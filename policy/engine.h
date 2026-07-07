#pragma once

#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "http/codec.h"

namespace policy {

enum class FlowDir { kIngress = 0, kEgress = 1, kMax };

enum class NetPolicyRule {
  kDeny = 0,
  kAllow = 1,
  kAllowRsp = 2,
  kAllowReq = 3,
  kDefault = 4,
  kMax
};

struct RulePort {
  uint16_t end_port_; //端口段上限
  uint16_t port_;     //端口段下限
  uint8_t proto_;     //协议
};

struct RuleDetail {
  char proto_;                    //协议
  int priority_;                  //权重
  int addr_type_;                 // ipv4 OR ipv6
  FlowDir direction_;             //流量策略方向
  NetPolicyRule action_;          //策略
  std::vector<RulePort> ports_;   //
  std::string policy_key_;        //策略主键
  std::string src_ip_;            //源地址
  std::string dst_ip_;            //目的地址
};

struct HttpRuleInfo {
  uint8_t direction_;
  NetPolicyRule action_;
  std::string host_;
  std::string method_;
  std::string path_;
};

struct FiveTuple {
  char proto_;
  uint16_t tot_len_;
  uint16_t src_port_;
  uint16_t dst_port_;
  uint32_t src_addr_u32_;
  uint32_t dst_addr_u32_;
  std::string src_addr_;
  std::string dst_addr_;
};

class PolicyEngine {
public:
  int AddNewPolicy(RuleDetail& policy, RulePort& stPort);

  int AddNewHttpPolicy(FlowDir dir, std::string& key, HttpRuleInfo& http_rule);

  std::string CreatePolicyRuleKey(RuleDetail& info);

  int CreatePolicyRuleKey(FiveTuple& tuple, FlowDir dir, std::vector<std::string>& value);

  NetPolicyRule MatchNetPolicyRule(FiveTuple& tuple, FlowDir dir, std::string& rule_key);

  NetPolicyRule MatchHttpPolicyRule(const std::vector<HttpRuleInfo>& http_rules,
                                    http::Header state);

  bool handle();

private:
  std::unordered_map<std::string, RuleDetail> net_input_policy_rule_;
  std::unordered_map<std::string, RuleDetail> net_output_policy_rule_;
  std::unordered_map<std::string, std::vector<HttpRuleInfo>> net_input_http_policy_;
  std::unordered_map<std::string, std::vector<HttpRuleInfo>> net_output_http_policy_;
  std::unordered_map<std::string, std::unordered_map<std::string, FlowDir>*> net_policy_key_;
  std::set<int> mask_cidr_;
  std::set<int> priority_;
};

} // namespace policy
