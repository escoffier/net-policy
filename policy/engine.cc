#include <arpa/inet.h>

#include <cstring>
#include <string>

#include "engine.h"
#include "log.h"

namespace policy {

static void Ipv4CidrToIp(std::string cidr, std::string &ip, int &mask) {
  struct in_addr addr;
  uint32_t uzIpaddr, uzMask;
  size_t index;
  std::string sip, smask;
  smask = "32";
  sip = cidr;
  index = cidr.find("/");
  if (index != std::string::npos) {
    sip = cidr.substr(0, index);
    smask = cidr.substr(index + 1);
  }
  uzIpaddr = ntohl(inet_addr(sip.c_str()));
  uzMask = atoi(smask.c_str());
  mask = uzMask;
  uzMask = ~0 << (32 - uzMask);
  /*count network address*/
  uzIpaddr &= uzMask;
  addr.s_addr = htonl(uzIpaddr);
  ip = inet_ntoa(addr);
}

static std::string Ipv4CidrToIp(std::string ip, int mask) {
  struct in_addr addr;
  uint32_t uzIpaddr, uzMask;
  uzIpaddr = ntohl(inet_addr(ip.c_str()));
  uzMask = ~0 << (32 - mask);
  /*count network address*/
  uzIpaddr &= uzMask;
  addr.s_addr = htonl(uzIpaddr);
  return inet_ntoa(addr);
}

static void PrintPolicyData(RuleDetail &r, RulePort &stPort) {
  if (g_log_level > 0) {
    fprintf(stderr,
            "[policy] name : %s, dir : %d, action : %d, priority : %d, proto : "
            "%d, ip : %s <--> %s port : %d ~ %d\n",
            r.policy_key_.c_str(), r.direction_, r.action_, r.priority_, r.proto_,
            r.src_ip_.c_str(), r.dst_ip_.c_str(), stPort.port_, stPort.end_port_);
  }
}

static ::std::string PrintPortsData(std::vector<RulePort> &ports) {
  std::string value = "";
  if (g_log_level > 0) {
    for (int p = 0; p < (int)ports.size(); p++) {
      value += std::to_string(ports.at(p).port_);
      value += " ~ ";
      value += std::to_string(ports.at(p).end_port_);
      if (p != ((int)ports.size() - 1))
        value += ", ";
    }
  }
  return value;
}

std::string PolicyEngine::CreatePolicyRuleKey(RuleDetail &info) {
  int mask;
  std::string key, ip;
  char buff[128] = {0};
  switch (info.direction_) {
  case FlowDir::kIngress:
    Ipv4CidrToIp(info.src_ip_, ip, mask);
    /*create key*/
    sprintf(buff, "%d-%d-%s-%s", info.priority_, info.proto_, ip.c_str(),
            info.dst_ip_.c_str());
    break;
  case FlowDir::kEgress:
    Ipv4CidrToIp(info.dst_ip_, ip, mask);
    /*create key*/
    sprintf(buff, "%d-%d-%s-%s", info.priority_, info.proto_, info.src_ip_.c_str(),
            ip.c_str());
    break;
  default:
    return key;
  }
  /*save cidr*/
  if ((mask > 0) && (mask <= 32))
    mask_cidr_.insert(mask);
  /*save priority*/
  priority_.insert(info.priority_);
  /*print debug log*/
  LOG_D("create policy rule key : [%s], priority : %d, priority size : %d",
        buff, info.priority_, (int)priority_.size());
  key = buff;
  return key;
}

int PolicyEngine::AddNewPolicy(RuleDetail &policy, RulePort &stPort) {
  std::string key;
  std::unordered_map<std::string, FlowDir> *subPolicy;
  std::unordered_map<std::string, FlowDir>::iterator it;
  std::unordered_map<std::string, RuleDetail> *ruleQue;
  std::unordered_map<std::string, RuleDetail>::iterator ruleIt;
  std::unordered_map<
      std::string, std::unordered_map<std::string, FlowDir> *>::iterator keyIt;
  // check
  if ((policy.priority_ <= 0) || (policy.priority_ >= 129))
    RETURN_ERROR(-1,
                 "priority is error, need 0 < priority < 129, priority : %d",
                 policy.priority_);
  // print debug log
  PrintPolicyData(policy, stPort);
  // find
  keyIt = net_policy_key_.find(policy.policy_key_);
  if (keyIt == net_policy_key_.end()) {
    subPolicy = new std::unordered_map<std::string, FlowDir>;
    net_policy_key_.insert(make_pair(policy.policy_key_, subPolicy));
    // print debug log
    LOG_D("create new policy : %s", policy.policy_key_.c_str());
  } else {
    subPolicy = keyIt->second;
  }
  /*clear ports*/
  policy.ports_.clear();
  // create policy rule key
  key = CreatePolicyRuleKey(policy);
  ruleQue = (policy.direction_ == FlowDir::kIngress) ? &net_input_policy_rule_
                                                      : &net_output_policy_rule_;
  /*check key*/
  ruleIt = ruleQue->find(key);
  if (ruleIt == ruleQue->end()) {
    policy.ports_.push_back(stPort);
    ruleQue->insert(make_pair(key, policy));
  } else {
    auto value = ruleIt->second;
    value.ports_.push_back(stPort);
    /*delete source key*/
    ruleQue->erase(ruleIt);
    /*insert key*/
    ruleQue->insert(make_pair(key, value));
    /*print debug log*/
    LOG_D("key : %s, mutil port : %d ~ %d, num : %d", key.c_str(), stPort.port_,
          stPort.end_port_, (int)value.ports_.size());
  }
  /*insert key*/
  subPolicy->insert(make_pair(key, policy.direction_));
  // return
  return 0;
}

int PolicyEngine::AddNewHttpPolicy(FlowDir dir, std::string &key,
                                   HttpRuleInfo &http_rule) {
  auto http = (dir == FlowDir::kIngress) ? &net_input_http_policy_
                                          : &net_output_http_policy_;
  auto it = http->find(key);
  if (it == http->end()) {
    auto [it1, success] =
        http->insert(std::make_pair(key, std::vector<HttpRuleInfo>{}));
    if (success) {
      it = it1;
    }
    /*print debug log*/
    LOG_D("create new http policy : %s.", key.c_str());
  }
  it->second.emplace_back(http_rule);
  /*return*/
  return 0;
}

int PolicyEngine::CreatePolicyRuleKey(FiveTuple &tuple, FlowDir dir,
                                      std::vector<std::string> &value) {
  char buff[128] = {0};
  std::vector<std::string> srcaddr, dstaddr;
  /*init*/
  value.clear();
  /*create key*/
  for (auto it = priority_.begin(); it != priority_.end(); ++it) {
    for (auto iter = mask_cidr_.begin(); iter != mask_cidr_.end(); ++iter) {
      switch (dir) {
      case FlowDir::kIngress:
        srcaddr.push_back("0.0.0.0");
        srcaddr.push_back(Ipv4CidrToIp(tuple.src_addr_, *iter));
        dstaddr.push_back(tuple.dst_addr_);
        break;
      case FlowDir::kEgress:
        srcaddr.push_back(tuple.src_addr_);
        dstaddr.push_back("0.0.0.0");
        dstaddr.push_back(Ipv4CidrToIp(tuple.dst_addr_, *iter));
        break;
      default:
        return -1;
      }
      // list priority
      for (size_t i = 0; i < srcaddr.size(); i++) {
        for (size_t j = 0; j < dstaddr.size(); j++) {
          memset(buff, 0, sizeof(buff));
          sprintf(buff, "%d-%d-%s-%s", *it, tuple.proto_, srcaddr.at(i).c_str(),
                  dstaddr.at(j).c_str());
          /*print debug log*/
          // if(tuple.dstPort == 80) LOG_D("rule key : [%s]", buff);
          /*save key*/
          value.push_back(buff);
          // all protocol
          memset(buff, 0, sizeof(buff));
          sprintf(buff, "%d-0-%s-%s", *it, srcaddr.at(i).c_str(),
                  dstaddr.at(j).c_str());
          /*save key*/
          value.push_back(buff);
          /*print debug log*/
          // if(tuple.dstPort == 80) LOG_D("rule key : [%s]", buff);
        }
      }
      /*clear data*/
      dstaddr.clear();
      srcaddr.clear();
    }
  }
  return 0;
}

NetPolicyRule PolicyEngine::MatchNetPolicyRule(FiveTuple &tuple, FlowDir dir,
                                               std::string &rule_key) {
  int p;
  bool bIsMatch;
  std::string key;
  std::vector<std::string> ruleKeys;
  std::unordered_map<std::string, RuleDetail> *ruleQue;
  std::unordered_map<std::string, RuleDetail>::iterator it;
  /*match*/
  ruleQue = (dir == FlowDir::kIngress) ? &net_input_policy_rule_
                                        : &net_output_policy_rule_;
  if (ruleQue->size() == 0)
    return NetPolicyRule::kDefault;
  /*get rule key*/
  CreatePolicyRuleKey(tuple, dir, ruleKeys);
  // print debug log
  // LOG_D("create rule key num : %lu.", ruleKeys.size());
  for (int i = 0; i < (int)ruleKeys.size(); i++) {
    // print debug log
    LOG_T("%s, find rule, key : %s, dst port : %d.",
          (dir == FlowDir::kIngress) ? "ingress" : "egress",
          ruleKeys[i].c_str(), tuple.dst_port_);
    // find rule
    it = ruleQue->find(ruleKeys.at(i).c_str());
    if (it == ruleQue->end())
      continue;
    // print debug log
    LOG_D("i : %d, match %s rule key, key : %s, tuple proto : %d, dst port : "
          "%d, ports size : %d, %s.",
          i, (dir == FlowDir::kIngress) ? "ingress" : "egress",
          ruleKeys.at(i).c_str(), tuple.proto_, tuple.dst_port_,
          (int)it->second.ports_.size(),
          PrintPortsData(it->second.ports_).c_str());
    /*match protocol*/
    if (!((it->second.proto_ == 0) || (tuple.proto_ == it->second.proto_)))
      break;
    /*port*/
    auto rulePorts = it->second.ports_;
    bIsMatch = (rulePorts.size() == 0) ? true : false;
    /*match port*/
    for (p = 0; p < (int)rulePorts.size(); p++) {
      if (rulePorts.at(p).end_port_ == 0) {
        bIsMatch = true;
        break;
      }
      /*check port rang*/
      if (tuple.dst_port_ > rulePorts.at(p).end_port_)
        continue;
      /*check min port*/
      if (tuple.dst_port_ < rulePorts.at(p).port_)
        continue;
      /*set match true*/
      bIsMatch = true;
      /*break*/
      break;
    }
    /*break*/
    if (!bIsMatch)
      continue;
    // print debug log
    LOG_D("[policy] match %s name : %s, dir : %d, action : %d, priority : %d, "
          "proto : %d, ip : %s <--> %s port : %d ~ %d\n",
          (dir == FlowDir::kIngress) ? "ingress" : "egress",
          it->second.policy_key_.c_str(), it->second.direction_, it->second.action_,
          it->second.priority_, it->second.proto_, it->second.src_ip_.c_str(),
          it->second.dst_ip_.c_str(), rulePorts.at(p).port_,
          rulePorts.at(p).end_port_);
    // rule policy key
    rule_key = it->second.policy_key_;
    // reverse selection
    return it->second.action_;
  }

  return NetPolicyRule::kDefault;
}

NetPolicyRule
PolicyEngine::MatchHttpPolicyRule(const std::vector<HttpRuleInfo> &http_rules,
                                   http::Header state) {
  std::string host, method, path;
//   if (http_rules == NULL)
//     return NetPolicyRule::kDefault;
  /*check http state*/
  for (auto it = http_rules.begin(); it != http_rules.end(); it++) {
    host = (*it).host_;
    method = it->method_;
    path = it->path_;
    if (!host.empty() && (host != state.host_))
      continue;
    if (!method.empty() && (method != state.method_))
      continue;
    if (!path.empty() && (path != state.path_))
      continue;
    /*return*/
    return (*it).action_;
  }
  /*return*/
  return NetPolicyRule::kDefault;
}

} // namespace policy
