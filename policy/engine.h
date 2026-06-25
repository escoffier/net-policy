#pragma once

#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "http/codec.h"

namespace policy {

enum class FLOW_DIR { DIR_INGRESS = 0, DIR_EGRESS = 1, FLOW_DIR_MAX };

enum class NET_POLICY_RULE {
  NET_DENY = 0,
  NET_ALLOW = 1,
  NET_ALLOW_RSP = 2,
  NET_ALLOW_REQ = 3,
  NET_DEFAULT = 4,
  NET_POLICY_MAX
};

struct RulePort {
  uint16_t endPort; //端口段上限
  uint16_t port;    //端口段下限
  uint8_t proto;    //协议
};

struct RuleDetail {
  char proto;                   //协议
  int priority;                 //权重
  int addrType;                 // ipv4 OR ipv6
  FLOW_DIR direction;           //流量策略方向
  NET_POLICY_RULE action;       //策略
  std::vector<RulePort> vPorts; //
  std::string policyKey;        //策略主键
  std::string srcIp;            //源地址
  std::string dstIp;            //目的地址
};

struct HttpRuleInfo {
  uint8_t direction;
  NET_POLICY_RULE action;
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
  int addNewPolicy(RuleDetail& policy, RulePort& stPort);

  int addNewHttpPolicy(FLOW_DIR dir, std::string& key, HttpRuleInfo& httpRule);

  std::string createPolicyRuleKey(RuleDetail& info);

  int createPolicyRuleKey(FiveTuple& tuple, FLOW_DIR dir, std::vector<std::string>& value);

  NET_POLICY_RULE matchNetPolicyRule(FiveTuple& tuple, FLOW_DIR dir, std::string& sRuleKey);

  NET_POLICY_RULE matchHttpPolicyRule(const std::vector<HttpRuleInfo>& httpRules,
                                      http::Header state);

  bool handle();

private:
  std::unordered_map<std::string, RuleDetail> NetInputPolicyRule;
  std::unordered_map<std::string, RuleDetail> NetOutputPolicyRule;
  std::unordered_map<std::string, std::vector<HttpRuleInfo>> NetInputHttpPolicy;
  std::unordered_map<std::string, std::vector<HttpRuleInfo>> NetOutputHttpPolicy;
  std::unordered_map<std::string, std::unordered_map<std::string, FLOW_DIR>*> NetPolicyKey;
  std::set<int> MaskCidr;
  std::set<int> Priority;
};

} // namespace policy