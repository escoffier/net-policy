#include <arpa/inet.h>

#include <cstring>
#include <string>

#include "engine.h"
#include "log.h"

namespace policy {

static void ipv4CidrToIp(std::string cidr, std::string &ip, int &mask) {
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

static std::string ipv4CidrToIp(std::string ip, int mask) {
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
  if (gzLogLevel > 0) {
    fprintf(stderr,
            "[policy] name : %s, dir : %d, action : %d, priority : %d, proto : "
            "%d, ip : %s <--> %s port : %d ~ %d\n",
            r.policyKey.c_str(), r.direction, r.action, r.priority, r.proto,
            r.srcIp.c_str(), r.dstIp.c_str(), stPort.port, stPort.endPort);
  }
}

static ::std::string PrintPortsData(std::vector<RulePort> &ports) {
  std::string value = "";
  if (gzLogLevel > 0) {
    for (int p = 0; p < (int)ports.size(); p++) {
      value += std::to_string(ports.at(p).port);
      value += " ~ ";
      value += std::to_string(ports.at(p).endPort);
      if (p != ((int)ports.size() - 1))
        value += ", ";
    }
  }
  return value;
}

std::string PolicyEngine::createPolicyRuleKey(RuleDetail &info) {
  int mask;
  std::string key, ip;
  char buff[128] = {0};
  switch (info.direction) {
  case FLOW_DIR::DIR_INGRESS:
    ipv4CidrToIp(info.srcIp, ip, mask);
    /*create key*/
    sprintf(buff, "%d-%d-%s-%s", info.priority, info.proto, ip.c_str(),
            info.dstIp.c_str());
    break;
  case FLOW_DIR::DIR_EGRESS:
    ipv4CidrToIp(info.dstIp, ip, mask);
    /*create key*/
    sprintf(buff, "%d-%d-%s-%s", info.priority, info.proto, info.srcIp.c_str(),
            ip.c_str());
    break;
  default:
    return key;
  }
  /*save cidr*/
  if ((mask > 0) && (mask <= 32))
    MaskCidr.insert(mask);
  /*save priority*/
  Priority.insert(info.priority);
  /*print debug log*/
  LOG_D("create policy rule key : [%s], priority : %d, priority size : %d",
        buff, info.priority, (int)Priority.size());
  key = buff;
  return key;
}

int PolicyEngine::addNewPolicy(RuleDetail &policy, RulePort &stPort) {
  std::string key;
  std::unordered_map<std::string, FLOW_DIR> *subPolicy;
  std::unordered_map<std::string, FLOW_DIR>::iterator it;
  std::unordered_map<std::string, RuleDetail> *ruleQue;
  std::unordered_map<std::string, RuleDetail>::iterator ruleIt;
  std::unordered_map<
      std::string, std::unordered_map<std::string, FLOW_DIR> *>::iterator keyIt;
  // check
  if ((policy.priority <= 0) || (policy.priority >= 129))
    RETURN_ERROR(-1,
                 "priority is error, need 0 < priority < 129, priority : %d",
                 policy.priority);
  // print debug log
  PrintPolicyData(policy, stPort);
  // find
  keyIt = NetPolicyKey.find(policy.policyKey);
  if (keyIt == NetPolicyKey.end()) {
    subPolicy = new std::unordered_map<std::string, FLOW_DIR>;
    NetPolicyKey.insert(make_pair(policy.policyKey, subPolicy));
    // print debug log
    LOG_D("create new policy : %s", policy.policyKey.c_str());
  } else {
    subPolicy = keyIt->second;
  }
  /*clear ports*/
  policy.vPorts.clear();
  // create policy rule key
  key = createPolicyRuleKey(policy);
  ruleQue = (policy.direction == FLOW_DIR::DIR_INGRESS) ? &NetInputPolicyRule
                                                        : &NetOutputPolicyRule;
  /*check key*/
  ruleIt = ruleQue->find(key);
  if (ruleIt == ruleQue->end()) {
    policy.vPorts.push_back(stPort);
    ruleQue->insert(make_pair(key, policy));
  } else {
    auto value = ruleIt->second;
    value.vPorts.push_back(stPort);
    /*delete source key*/
    ruleQue->erase(ruleIt);
    /*insert key*/
    ruleQue->insert(make_pair(key, value));
    /*print debug log*/
    LOG_D("key : %s, mutil port : %d ~ %d, num : %d", key.c_str(), stPort.port,
          stPort.endPort, (int)value.vPorts.size());
  }
  /*insert key*/
  subPolicy->insert(make_pair(key, policy.direction));
  // return
  return 0;
}

int PolicyEngine::addNewHttpPolicy(FLOW_DIR dir, std::string &key,
                                   HttpRuleInfo &httpRule) {
  //   std::vector<HttpRuleInfo> httpRuleArr;
  auto http = (dir == FLOW_DIR::DIR_INGRESS) ? &NetInputHttpPolicy
                                             : &NetOutputHttpPolicy;
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
  it->second.emplace_back(httpRule);
  /*return*/
  return 0;
}

int PolicyEngine::createPolicyRuleKey(FiveTuple &tuple, FLOW_DIR dir,
                                      std::vector<std::string> &value) {
  char buff[128] = {0};
  std::vector<std::string> srcaddr, dstaddr;
  /*init*/
  value.clear();
  /*create key*/
  for (auto it = Priority.begin(); it != Priority.end(); ++it) {
    for (auto iter = MaskCidr.begin(); iter != MaskCidr.end(); ++iter) {
      switch (dir) {
      case FLOW_DIR::DIR_INGRESS:
        srcaddr.push_back("0.0.0.0");
        srcaddr.push_back(ipv4CidrToIp(tuple.srcAddr, *iter));
        dstaddr.push_back(tuple.dstAddr);
        break;
      case FLOW_DIR::DIR_EGRESS:
        srcaddr.push_back(tuple.srcAddr);
        dstaddr.push_back("0.0.0.0");
        dstaddr.push_back(ipv4CidrToIp(tuple.dstAddr, *iter));
        break;
      default:
        return -1;
      }
      // list priority
      for (size_t i = 0; i < srcaddr.size(); i++) {
        for (size_t j = 0; j < dstaddr.size(); j++) {
          memset(buff, 0, sizeof(buff));
          sprintf(buff, "%d-%d-%s-%s", *it, tuple.proto, srcaddr.at(i).c_str(),
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

NET_POLICY_RULE PolicyEngine::matchNetPolicyRule(FiveTuple &tuple, FLOW_DIR dir,
                                                 std::string &sRuleKey) {
  int p;
  bool bIsMatch;
  std::string key;
  std::vector<std::string> ruleKeys;
  std::unordered_map<std::string, RuleDetail> *ruleQue;
  std::unordered_map<std::string, RuleDetail>::iterator it;
  /*match*/
  ruleQue = (dir == FLOW_DIR::DIR_INGRESS) ? &NetInputPolicyRule
                                           : &NetOutputPolicyRule;
  if (ruleQue->size() == 0)
    return NET_POLICY_RULE::NET_DEFAULT;
  /*get rule key*/
  createPolicyRuleKey(tuple, dir, ruleKeys);
  // print debug log
  // LOG_D("create rule key num : %lu.", ruleKeys.size());
  for (int i = 0; i < (int)ruleKeys.size(); i++) {
    // print debug log
    LOG_T("%s, find rule, key : %s, dst port : %d.",
          (dir == FLOW_DIR::DIR_INGRESS) ? "ingress" : "egress",
          ruleKeys[i].c_str(), tuple.dstPort);
    // find rule
    it = ruleQue->find(ruleKeys.at(i).c_str());
    if (it == ruleQue->end())
      continue;
    // print debug log
    LOG_D("i : %d, match %s rule key, key : %s, tuple proto : %d, dst port : "
          "%d, vPorts size : %d, %s.",
          i, (dir == FLOW_DIR::DIR_INGRESS) ? "ingress" : "egress",
          ruleKeys.at(i).c_str(), tuple.proto, tuple.dstPort,
          (int)it->second.vPorts.size(),
          PrintPortsData(it->second.vPorts).c_str());
    /*match protocol*/
    if (!((it->second.proto == 0) || (tuple.proto == it->second.proto)))
      break;
    /*port*/
    auto rulePorts = it->second.vPorts;
    bIsMatch = (rulePorts.size() == 0) ? true : false;
    /*match port*/
    for (p = 0; p < (int)rulePorts.size(); p++) {
      if (rulePorts.at(p).endPort == 0) {
        bIsMatch = true;
        break;
      }
      /*check port rang*/
      if (tuple.dstPort > rulePorts.at(p).endPort)
        continue;
      /*check min port*/
      if (tuple.dstPort < rulePorts.at(p).port)
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
          (dir == FLOW_DIR::DIR_INGRESS) ? "ingress" : "egress",
          it->second.policyKey.c_str(), it->second.direction, it->second.action,
          it->second.priority, it->second.proto, it->second.srcIp.c_str(),
          it->second.dstIp.c_str(), rulePorts.at(p).port,
          rulePorts.at(p).endPort);
    // rule policy key
    sRuleKey = it->second.policyKey;
    // reverse selection
    return it->second.action;
  }

  return NET_POLICY_RULE::NET_DEFAULT;
}

NET_POLICY_RULE
PolicyEngine::matchHttpPolicyRule(const std::vector<HttpRuleInfo> &httpRules,
                                  http::Header state) {
  std::string host, method, path;
//   if (httpRules == NULL)
//     return NET_POLICY_RULE::NET_DEFAULT;
  /*check http state*/
  for (auto it = httpRules.begin(); it != httpRules.end(); it++) {
    host = (*it).host;
    method = it->method;
    path = it->path;
    if (!host.empty() && (host != state.host_))
      continue;
    if (!method.empty() && (method != state.method_))
      continue;
    if (!path.empty() && (path != state.path_))
      continue;
    /*return*/
    return (*it).action;
  }
  /*return*/
  return NET_POLICY_RULE::NET_DEFAULT;
}

} // namespace policy