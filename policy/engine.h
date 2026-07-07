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
  uint16_t end_port; //端口段上限
  uint16_t port;     //端口段下限
  uint8_t proto;     //协议
};

struct RuleDetail {
  char proto;                    //协议
  int priority;                  //权重
  int addrType;                  // ipv4 OR ipv6
  FlowDir direction;             //流量策略方向
  NetPolicyRule action;          //策略
  std::vector<RulePort> vPorts;  //
  std::string policyKey;         //策略主键
  std::string srcIp;             //源地址
  std::string dstIp;             //目的地址
};

struct HttpRuleInfo {
  uint8_t direction;
  NetPolicyRule action;
  std::string host;
  std::string method;
  std::string path;
};

struct FiveTuple {
  char proto;
  uint16_t totLen;
  uint16_t srcPort;
  uint16_t dstPort;
  uint32_t uzSrcAddr;
  uint32_t uzDstAddr;
  std::string srcAddr;
  std::string dstAddr;
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
  std::unordered_map<std::string, RuleDetail> NetInputPolicyRule;
  std::unordered_map<std::string, RuleDetail> NetOutputPolicyRule;
  std::unordered_map<std::string, std::vector<HttpRuleInfo>> NetInputHttpPolicy;
  std::unordered_map<std::string, std::vector<HttpRuleInfo>> NetOutputHttpPolicy;
  std::unordered_map<std::string, std::unordered_map<std::string, FlowDir>*> NetPolicyKey;
  std::set<int> MaskCidr;
  std::set<int> Priority;
};

} // namespace policy
