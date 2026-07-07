#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <linux/ip.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <gflags/gflags.h>
#include "net-policy.h"

using std::string;
using std::vector;
using std::make_pair;

int g_log_level = 0;
bool g_waf_enable = false;
const char* PREFIX = "#%% pre";

struct u32_mask {
  uint32_t value;
  uint32_t mask;
};

/*static value*/
static int g_local_net_ns_fd = 0;
static int g_post_link_fd = 0;
static int g_client_fd = 0;
static PolicyRule g_micro_rule;

static std::unordered_map<uint32_t, uint8_t> g_nodes_ip;
static std::map<TCP_FOUR_TUPLE_V4, http::ConnectionPtr> g_tcp_ct_input;
static std::map<TCP_FOUR_TUPLE_V4, http::ConnectionPtr> g_tcp_ct_output;
static std::unordered_map<std::string, std::vector<HTTP_RULE_INFO>> g_net_input_http_policy;
static std::unordered_map<std::string, std::vector<HTTP_RULE_INFO>> g_net_output_http_policy;
net::ConnectionManager g_connection_manager;
static int g_ipt_ver = 0;

int NetProtoConvert(std::string proto) {
  if (proto.length() == 0)
    return 0;
  if (proto.compare("TCP") == 0)
    return IPPROTO_TCP;
  if (proto.compare("UDP") == 0)
    return IPPROTO_UDP;
  if (proto.compare("ICMP") == 0)
    return IPPROTO_ICMP;
  /*return*/
  return 0;
}

const char* GetProtoString(int proto) {
  switch (proto) {
  case IPPROTO_TCP:
    return "TCP";
  case IPPROTO_UDP:
    return "UDP";
  case IPPROTO_ICMP:
    return "ICMP";
  default:
    break;
  }
  return "UNKNOWN";
}

int ParseIpString(std::string input, std::vector<std::string>& ret) {
  // struct in_addr addr;
  // uint32_t uzIpaddr, uzMask, uzBroadcast;
  std::stringstream ss(input);
  std::string segment, value;
  /*parse string*/
  while (std::getline(ss, segment, ',')) {
    size_t pos = segment.find('-');
    if (pos != std::string::npos) {
      std::string startIP = segment.substr(0, pos);
      std::string endIP = segment.substr(pos + 1);

      size_t dotCount = std::count(startIP.begin(), startIP.end(), '.');
      if (dotCount == 3) {
        // Assuming it's an IPv4 range
        size_t lastDot = startIP.rfind('.');
        std::string baseIP = startIP.substr(0, lastDot + 1);
        int startRange = std::stoi(startIP.substr(lastDot + 1));
        int endRange = std::stoi(endIP);

        for (int i = startRange; i <= endRange; ++i) {
          ret.push_back(baseIP + std::to_string(i));
        }
      }
      continue;
    }
    /*
    pos = segment.find('/');
            if (pos != std::string::npos) {

                    // Handling CIDR notation
                    std::string baseIP = segment.substr(0, pos);
                    int subnetMask = std::stoi(segment.substr(pos + 1));
                    uzIpaddr = ntohl(inet_addr(baseIP.c_str()));
                    uzMask   = ~0 << (32 - subnetMask);
                    //count network address
                    uzIpaddr &= uzMask;
                    //count network broadcast
                    uzBroadcast = uzIpaddr | (~uzMask);
                    // Generate all IP addresses in the subnet
                    for (uint32_t i = uzIpaddr; i <= uzBroadcast; ++i)
        {
                            addr.s_addr = htonl(i);
                            value = inet_ntoa(addr);
                            ret.push_back(value);
                    }
                    continue;
            }*/
    // If not a range or CIDR, directly push the single IP address
    ret.push_back(segment);
  }
  /*return*/
  return 0;
}

/*now system second to string*/
std::string TimeToString() {
  std::string data;
  char value[64], buffer[128];
  struct tm* info = NULL;
  struct timeval tv;
  /*buffer info*/
  memset(value, 0, sizeof(value));
  memset(buffer, 0, sizeof(buffer));
  /*time format*/
  gettimeofday(&tv, NULL);
  // 将时间转换为本地时间
  info = localtime(&tv.tv_sec);
  if (!info)
    return data;
  // 格式化时间为字符串
  strftime(value, sizeof(value), "%Y-%m-%d %H:%M:%S", info);
  /*milliseconds*/
  snprintf(buffer, sizeof(buffer), "%s.%03ld", value, tv.tv_usec / 1000);
  /*to string*/
  data = buffer;
  /*return*/
  return data;
}

/* Checksum a block of data */
uint16_t csum(uint16_t* packet, int packlen) {
  unsigned long sum = 0;
  while (packlen > 1) {
    sum += *packet++;
    packlen -= 2;
  }
  /*sum*/
  if (packlen > 0)
    sum += *(uint8_t*)packet;
  /* TODO: this depends on byte order */
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  /*return*/
  return (uint16_t)~sum;
}

/*tcp checksum*/
uint16_t TcpCsum(char* packet) {
  struct iphdr* iphdr;
  struct tcphdr *tcpphdr, *ttcphdr;
  PSEUDO_HEADER* pseudo;
  uint16_t datalen;
  char buffer[2048];
  /*ip protocol header*/
  iphdr = reinterpret_cast<struct iphdr*>(packet);
  /*check protocol*/
  if (iphdr->protocol != IPPROTO_TCP)
    return 0;
  /*udp protocol header*/
  tcpphdr = reinterpret_cast<struct tcphdr*>(packet + iphdr->ihl * 4);
  /*buffer length*/
  datalen = ntohs(iphdr->tot_len);
  if (datalen >= sizeof(buffer))
    RETURN_ERROR(0, "create tcp checksum failed, data is too long than buffer, data len : %d",
                 datalen);
  /*init memory*/
  memset(buffer, 0, sizeof(buffer));
  /*pesudo header*/
  pseudo = (PSEUDO_HEADER*)buffer;
  pseudo->daddr_ = iphdr->daddr;
  pseudo->saddr_ = iphdr->saddr;
  pseudo->placeholder_ = 0;
  pseudo->protocol_ = iphdr->protocol;
  pseudo->length_ = htons(ntohs(iphdr->tot_len) - (iphdr->ihl << 2));
  /*tcp header*/
  ttcphdr = (struct tcphdr*)(buffer + sizeof(PSEUDO_HEADER));
  memcpy(ttcphdr, tcpphdr, ntohs(pseudo->length_));
  ttcphdr->check = 0;
  /*checksum*/
  return csum((uint16_t*)buffer,
              ntohs(pseudo->length_) +
                  sizeof(PSEUDO_HEADER)); // sizeof(PSEUDO_HEADER) + sizeof(UDP_HEADER));
}

void PrintPolicyData(RuleDetail& r, RULE_PORT& stPort) {
  if (g_log_level > 0) {
    fprintf(stderr,
            "[policy] name : %s, dir : %d, action : %d, priority : %d, proto : %d, ip : %s <--> %s "
            "port : %d ~ %d\n",
            r.policy_key_.c_str(), r.direction_, r.action_, r.priority_, r.proto_, r.src_ip_.c_str(),
            r.dst_ip_.c_str(), stPort.port_, stPort.end_port_);
  }
}

std::string PrintPortsData(std::vector<RULE_PORT>& ports) {
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

int OpenLocalNetNs() {
  const char* path = "/proc/self/ns/net";
  // open net namespaces
  g_local_net_ns_fd = open(path, O_RDONLY);
  if (g_local_net_ns_fd <= 0)
    RETURN_ERROR(-1, "open %s net namespaces failed! err : %s.", path, strerror(errno));
  return 0;
}

int SetLocalNetNs(int fd) {
  int ret;
  if (fd <= 0)
    RETURN_ERROR(-1, "local net ns fd is error!!");
  // unshare net
  ret = unshare(CLONE_NEWNET);
  if (ret != 0)
    RETURN_ERROR(-1, "unshare net failed! err : %s.", strerror(errno));
  // set local net ns
  ret = setns(fd, CLONE_NEWNET);
  if (ret != 0)
    RETURN_ERROR(-1, "set local net ns failed! err : %s.", strerror(errno));

  return 0;
}

std::string ipv6Convert(char* ipv6) {
  int ret;
  string sRet = "";
  unsigned char addr[INET6_ADDRSTRLEN];
  ret = inet_pton(AF_INET6, ipv6, &(addr));
  if (ret <= 0)
    RETURN_ERROR(sRet, "format ipv6 address failed, ipv6 : %s.", ipv6);
  sRet = (char*)addr;
  return sRet;
}

uint32_t ipv4StringToInt(std::string ip) {
  struct in_addr addr;
  if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
    return addr.s_addr;
  }
  return 0;
}

int SetNs(int pid, char* basePath) {
  int fd = 0, ret;
  char path[128];
  if (pid <= 0)
    RETURN_ERROR(-1, "pid is error!");
  // path
  memset(path, 0, sizeof(path));
  sprintf(path, "%s/proc/%d/ns/net", basePath, pid);
  // open path
  fd = open(path, O_RDONLY);
  if (fd <= 0)
    RETURN_ERROR(-1, "open %s failed, err : %s.", path, strerror(errno));
  // unshare net
  ret = unshare(CLONE_NEWNET);
  if (ret != 0)
    GOTO_ERROR(err, "unshare net failed! err : %s.", strerror(errno));
  // set net ns
  ret = setns(fd, CLONE_NEWNET);
  if (ret != 0)
    GOTO_ERROR(err, "set net ns failed, path : %s, err : %s.", path, strerror(errno));
  // close fd
  close(fd);
  // return
  return 0;
err:
  if (fd > 0)
    close(fd);
  /*return*/
  return -1;
}

/*post match message*/
static int PostMatchMsg(FiveTuple& tuple, NET_POLICY_RULE action, FLOW_DIR dir, string& rule_key) {
  int ret, len;
  char buf[11] = {"#%% pre"};
  char data[1024];
  /*post socket fd*/
  if (g_post_link_fd <= 0)
    return 0;
  /*init memory*/
  memset(data, 0, sizeof(data));
  /*json data*/
  sprintf(data,
          "{\"type\":\"microseg\",\"proto\":%d,\"action\":%d,\"direction\":%d,\"src_port\":%d,"
          "\"dst_port\":%d,\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"policy_name\":\"%s\"}",
          tuple.proto_, static_cast<int>(action), static_cast<int>(dir), tuple.src_port_, tuple.dst_port_, tuple.src_addr_.c_str(),
          tuple.dst_addr_.c_str(), rule_key.c_str());
  /*print debug log*/
  if (!((tuple.proto_ == IPPROTO_UDP) && (tuple.dst_port_ == 53)))
    LOG_D("[post] post micro seg data : %s", data);
  /*data len*/
  len = (int)strlen(data);
  /*send data*/
  buf[7] = len & 0xff;
  buf[8] = (len >> 8) & 0xff;
  buf[9] = (len >> 16) & 0xff;
  buf[10] = (len >> 24) & 0xff;
  ret = write(g_post_link_fd, buf, 11);
  if (ret <= 0)
    GOTO_ERROR(err, "post match msg to server failed, %s.", strerror(errno));
  /*post data*/
  ret = write(g_post_link_fd, data, len);
  if (ret <= 0)
    GOTO_ERROR(err, "post match msg to server failed, %s.", strerror(errno));
  /*return*/
  return 0;
err:
  return -1;
}

/*match http policy rule*/
static NET_POLICY_RULE MatchHttpPolicyRule(const std::vector<HTTP_RULE_INFO>& http_rules,
                                           http::Header state) {
  for (const auto& rule : http_rules) {
    if (!rule.host_.empty()   && (rule.host_   != state.host_))   continue;
    if (!rule.method_.empty() && (rule.method_ != state.method_)) continue;
    if (!rule.path_.empty()   && (rule.path_   != state.path_))   continue;
    return rule.action_;
  }
  return NetPolicyRule::kDefault;
}

/*math net policy rule*/
static NET_POLICY_RULE MatchNetPolicyRule(FiveTuple& tuple, FLOW_DIR dir, RuleDetail& detail) {
  std::vector<std::string> rule_keys;
  /*is node ip*/
  auto nodeIt = g_nodes_ip.find(tuple.src_addr_u32_);
  if (nodeIt != g_nodes_ip.end())
    return NetPolicyRule::kDefault;
  /*get rule map*/
  auto rules = g_micro_rule.GetPolicyTree(dir);
  if (rules->RuleSize() == 0)
    return NetPolicyRule::kDefault;
  /*get rule key*/
  g_micro_rule.CreateRuleKeyByTuple(tuple, dir, rule_keys);
  /*遍历规则进行匹配*/
  for (int i = 0; i < (int)rule_keys.size(); i++) {
    /*匹配规则*/
    auto found = rules->MatchRuleGroup(rule_keys.at(i), tuple, detail);
    if (!found)
      continue;
    /*reverse selection*/
    return detail.action_;
  }

  return NetPolicyRule::kDefault;
}

/*match micro policy rule*/
static NET_POLICY_RULE MatchMicroPolicyRule(FiveTuple& tuple, FLOW_DIR& dir,
                                            std::string& rule_key) {
  FiveTuple data;
  FLOW_DIR fdir;
  RuleDetail detail, revDetail;
  /*策略匹配*/
  auto ret = MatchNetPolicyRule(tuple, dir, detail);
  if (ret == NetPolicyRule::kDefault)
    return ret;
  /*判断匹配上的策略*/
  rule_key = detail.policy_key_;
  if (ret == NetPolicyRule::kAllow)
    return ret;
  /*交换地址信息*/
  tuple.ReverseTuple(data);
  fdir = (dir == FlowDir::kIngress) ? FlowDir::kEgress : FlowDir::kIngress;
  /*反向匹配策略*/
  auto result = MatchNetPolicyRule(data, fdir, revDetail);
  if (result == NetPolicyRule::kDefault)
    return ret;
  /*根据权重进行匹配*/
  if (detail.priority_ <= revDetail.priority_)
    return ret;
  /*处理策略匹配结果*/
  tuple = data;
  dir = fdir;
  rule_key = revDetail.policy_key_;
  return result;
}

/*update session callback*/
static int UpdateNetSession(NFC_MSG_TYPE type, NF_CONNTRACK* ct, void* data) {
  int ret;
  uint32_t mark;
  struct nfct_handle* ith = NULL;
  NFQ_RES_INFO* nfq_res = (NFQ_RES_INFO*)data;
  NF_CONNTRACK *obj, *tmp = NULL;
  /*check argument*/
  if (!ct || !data)
    return NFCT_CB_CONTINUE;
  //
  obj = nfq_res->nfct_;
  /*compare nfct*/
  if (!nfct_cmp(obj, ct, NFCT_CMP_ORIG))
    return NFCT_CB_CONTINUE;
  /*get mark*/
  mark = nfct_get_attr_u32(obj, ATTR_MARK);
  if (mark > 100)
    return NFCT_CB_CONTINUE;
  /*new nfct*/
  tmp = nfq_res->nfct_cb_;
  if (!tmp)
    RETURN_ERROR(NFCT_CB_CONTINUE, "new nfct failed.");
  /*open nfct*/
  ith = nfq_res->nfct_cb_hd_;
  if (!ith)
    RETURN_ERROR(NFCT_CB_CONTINUE, "open nfct failed.");
  /*copy info*/
  nfct_copy(tmp, ct, NFCT_CP_ORIG);
  // nfct_copy(tmp, obj, NFCT_CP_META);
  /*set mark*/
  nfct_set_attr_u32(tmp, ATTR_MARK, mark);
  /* do not send NFCT_Q_UPDATE if ct appears unchanged */
  if (nfct_cmp(tmp, ct, NFCT_CMP_ALL | NFCT_CMP_MASK))
    return NFCT_CB_CONTINUE;
  /*query*/
  ret = nfct_query(ith, NFCT_Q_UPDATE, tmp);
  if (ret < 0)
    LOG_E("Operation failed: update mark failed.")
  /*return*/
  return NFCT_CB_CONTINUE;
}

/*set mark to accept*/
static int SetAcceptMark(NFQ_RES_INFO* nfq_res, FiveTuple& tuple, NFC_MSG_TYPE msgtype,
                         int markValue) {
  int ret, family = AF_INET;
  NF_CONNTRACK* ct = NULL;
  struct nfct_handle* cth = NULL;
  if (!nfq_res)
    RETURN_ERROR(-1, "nfct resource is nil.");
  /*new nfct*/
  ct = nfq_res->nfct_;
  if (!ct)
    RETURN_ERROR(-1, "nfct is null.");
  /*open nfct*/
  cth = nfq_res->nfct_hd_;
  if (!cth)
    RETURN_ERROR(-1, "nfct handle is nil.");
  /*set mark*/
  nfct_set_attr_u32(ct, ATTR_MARK, markValue);
  /*L3 proto*/
  nfct_set_attr_u8(ct, ATTR_ORIG_L3PROTO, family);
  /*set protocol*/
  if (tuple.proto_ > 0)
    nfct_set_attr_u8(ct, ATTR_L4PROTO, tuple.proto_);
  // ip
  if (tuple.src_addr_.length() > 0)
    nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, inet_addr(tuple.src_addr_.c_str()));
  if (tuple.dst_addr_.length() > 0)
    nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, inet_addr(tuple.dst_addr_.c_str()));
  // port
  if (tuple.src_port_ > 0)
    nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, htons(tuple.src_port_));
  if (tuple.dst_port_ > 0)
    nfct_set_attr_u16(ct, ATTR_ORIG_PORT_DST, htons(tuple.dst_port_));
  // register
  // nfct_callback_register(cth, msgtype, UpdateNetSession, nfq_res);
  /*query*/
  ret = nfct_query(cth, NFCT_Q_DUMP, &family);
  if (ret != 0)
    RETURN_ERROR(ret, "nfct query failed.");
  /*return*/
  return 0;
}

/*parse package*/
static int parse_package(unsigned char* pkg, FiveTuple& tuple, struct tcphdr* tcphdr, int& offset) {
  uint16_t src_port, dst_port;
  struct iphdr* iph;
  struct udphdr* udph;
  struct tcphdr* tcph;
  struct in_addr addr;
  /*init buffer*/
  char ntopBuf[INET_ADDRSTRLEN];
  iph = (struct iphdr*)pkg;
  addr.s_addr = iph->saddr;
  tuple.src_addr_u32_ = iph->saddr;
  tuple.src_addr_ = inet_ntop(AF_INET, &addr, ntopBuf, sizeof(ntopBuf));
  addr.s_addr = iph->daddr;
  tuple.dst_addr_u32_ = iph->daddr;
  tuple.dst_addr_ = inet_ntop(AF_INET, &addr, ntopBuf, sizeof(ntopBuf));
  if (iph->version != 4)
    return NF_ACCEPT;
  /*ip header length*/
  offset = iph->ihl << 2;
  /*procotol*/
  switch (iph->protocol) {
  case IPPROTO_UDP:
    udph = (struct udphdr*)(pkg + iph->ihl * 4);
    src_port = udph->source;
    dst_port = udph->dest;
    offset += sizeof(struct udphdr);
    break;

  case IPPROTO_TCP:
    tcph = (struct tcphdr*)(pkg + iph->ihl * 4);
    src_port = tcph->source;
    dst_port = tcph->dest;
    offset += tcph->doff << 2;
    memcpy(tcphdr, tcph, sizeof(struct tcphdr));
    break;

  case IPPROTO_ICMP:
    src_port = 0;
    dst_port = 0;
    break;

  default:
    return NF_ACCEPT;
  }
  /*five tuple*/
  tuple.proto_    = iph->protocol;
  tuple.src_port_ = ntohs(src_port);
  tuple.dst_port_ = ntohs(dst_port);
  tuple.tot_len_  = ntohs(iph->tot_len);
  /*return*/
  return kNfMatchRule;
}

/*reset tcp link*/
static int rst_tcp_link(unsigned char* pkg) {
  int offset, datalen;
  // uint16_t check;
  struct iphdr* iph;
  struct tcphdr* tcph;
  /*init buffer*/
  iph = (struct iphdr*)pkg;
  if (iph->version != 4)
    return NF_ACCEPT;
  /*procotol*/
  if (iph->protocol != IPPROTO_TCP)
    return NF_ACCEPT;
  /*tcp protocol*/
  tcph = (struct tcphdr*)(pkg + iph->ihl * 4);
  // check = tcph->check;
  /*modify method*/
  offset = (iph->ihl * 4) + (tcph->doff << 2);
  datalen = ntohs(iph->tot_len) - offset;
  for (auto i = offset; i < (offset + datalen); i++) {
    pkg[i] = 0;
    if ((i - offset) > 6)
      break;
  }
  /*checksum*/
  tcph->check = TcpCsum((char*)pkg);
  /*print debug log*/
  // LOG_D("src check : 0x%04x, now check : 0x%04x", check & 0xffff, tcph->check & 0xffff);
  /*return*/
  return NF_ACCEPT;
}

static int input_nfq_cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa,
                        void* argv) {
  bool found = false;
  int id = 0, ret, offset;
  uint32_t mark;
  FLOW_DIR dir = FlowDir::kIngress;
  std::string rule_key;
  FiveTuple tuple;
  struct tcphdr tcphdr;
  TCP_FOUR_TUPLE_V4 ct_key;
  NET_POLICY_RULE rule_ret;
  struct nfqnl_msg_packet_hdr* ph;
  unsigned char *pkg, *value = nullptr;
  std::map<TCP_FOUR_TUPLE_V4, http::ConnectionPtr>::iterator tcp_it;
  NFQ_RES_INFO* nfq_res = (NFQ_RES_INFO*)argv;
  (void)nfq_res;

  ph = nfq_get_msg_packet_hdr(nfa);
  if (!ph)
    return 0;

  id = ntohl(ph->packet_id);
  // printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);

  mark = nfq_get_nfmark(nfa);
  if ((mark == static_cast<uint32_t>(NetPolicyRule::kAllow)) ||
      (mark == static_cast<uint32_t>(NetPolicyRule::kAllowRsp)))
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

  auto data_len = nfq_get_payload(nfa, &pkg);
  if (data_len < 0)
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

  // printf("payload_len=%d ", ret);
  if (data_len < (int)sizeof(struct iphdr))
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

  ret = parse_package(pkg, tuple, &tcphdr, offset);
  if (ret != kNfMatchRule)
    nfq_set_verdict(qh, id, ret, 0, NULL);
  /*print debug log*/
  // LOG_V("input receive %s, mark : %d, seq: %u, tot len : %d, %s:%u -> %s:%u, memory : %p ",
  // GetProtoString(tuple.proto_), mark, ntohl(tcphdr.seq), tuple.tot_len_, tuple.src_addr_.c_str(),
  // tuple.src_port_, tuple.dst_addr_.c_str(), tuple.dst_port_, argv); LOG_D("input receive data: %p",
  // pkg);
  if (g_waf_enable && (tuple.proto_ == IPPROTO_TCP)) {
    auto status =
        g_connection_manager.receive(seastar::net::packet::from_static_data((char*)pkg, data_len));
    if (status == net::NetStatus::Drop) {
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), data_len, pkg);
    }
  }
  /*tcp four tuple*/
  ct_key.dst_port_ = tuple.dst_port_;
  ct_key.src_port_ = tuple.src_port_;
  ct_key.dst_addr_ = tuple.dst_addr_u32_;
  ct_key.src_addr_ = tuple.src_addr_u32_;
  /*tcp protocol*/
  switch (tuple.proto_) {
  case IPPROTO_TCP:
    /*query conntrack info*/
    tcp_it = g_tcp_ct_input.find(ct_key);
    if (tcp_it == g_tcp_ct_input.end()) {
      /*tcp syn*/
      if (tcphdr.syn != 0)
        break;
      /*tcp ack*/
      if (data_len <= offset)
        return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), 0, NULL);
      /*break*/
      break;
    }
    /*tcp tuple exist*/
    found = true;
    /*tcp fin*/
    if ((tcphdr.fin == 1) || (tcphdr.rst == 1)) {
      g_tcp_ct_input.erase(ct_key);
      /*print debug log*/
      LOG_D("microseg-dp input data, delete conntrack info, src: %s:%d, dest : %s:%d",
            tuple.src_addr_.c_str(), tuple.src_port_, tuple.dst_addr_.c_str(), tuple.dst_port_);
      /*return*/
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllow), 0, NULL);
    }
    /*tcp ack*/
    if (data_len <= offset)
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), 0, NULL);
    /*break*/
    break;
  case IPPROTO_UDP:
  case IPPROTO_ICMP:
    break;
  default:
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
  }
  /*query tcp conntrack result*/
  if (!found) {
    /*match rule*/
    rule_ret = MatchMicroPolicyRule(tuple, dir, rule_key);
    if (rule_ret == NetPolicyRule::kDefault)
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllow), 0, NULL);
    /*query http rule*/
    auto http_rule = g_net_input_http_policy.find(rule_key);
    /*check http rule*/
    if ((http_rule == g_net_input_http_policy.end()) || (tuple.proto_ == IPPROTO_UDP) ||
        (tuple.proto_ == IPPROTO_ICMP) || (http_rule->second.empty())) {
      /*post match message*/
      PostMatchMsg(tuple, rule_ret, dir, rule_key);
      // deny
      if (rule_ret == NetPolicyRule::kDeny) {
        LOG_D("input drop %s %s:%u -> %s:%u ", GetProtoString(tuple.proto_), tuple.src_addr_.c_str(),
              tuple.src_port_, tuple.dst_addr_.c_str(), tuple.dst_port_);
        /*drop data*/
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
      }
      /*return*/
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllow), 0, NULL);
    }
  }

  auto tcp_seq = ntohl(tcphdr.seq);
  /*tcp syn packet*/
  if (tcphdr.syn == 1) {
    LOG_D("microseg-dp  input sync, src: %s, dest : %s, offset : %d, data len : %d",
          tuple.src_addr_.c_str(), tuple.dst_addr_.c_str(), offset, data_len);
    auto conn = std::make_unique<http::Connection>(rule_key);
    conn->setTcpSeq(tcp_seq + 1);
    g_tcp_ct_input.insert({ct_key, std::move(conn)});
    /*return*/
    return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), 0, NULL);
  }
  /*print debug log*/
  LOG_D("microseg-dp  input data, src: %s, dest : %s, offset : %d, data len : %d",
        tuple.src_addr_.c_str(), tuple.dst_addr_.c_str(), offset, data_len);
  /*can not find tcp conntrack*/
  if (tcp_it == g_tcp_ct_input.end()) {
    LOG_D(
        "microseg-dp input not sync, new conntrack, src: %s, dest : %s, offset : %d, data len : %d",
        tuple.src_addr_.c_str(), tuple.dst_addr_.c_str(), offset, data_len);
    auto [it, success] = g_tcp_ct_input.insert({ct_key, std::make_unique<http::Connection>(rule_key)});
    if (success) {
      tcp_it = it;
    }
  }
  /*get tcp data*/
  value = pkg + offset;
  /*get rule key*/
  rule_key = tcp_it->second->getRuleKey();
  /*get tcp seq*/
  if (tcp_seq < tcp_it->second->getTcpSeq()) {
    LOG_D("input - duplicated tcp segment");
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
  }
  auto payload_len = data_len - offset;
  /*save tcp seq*/
  tcp_it->second->setTcpSeq(tcp_seq + payload_len);
  /*string convert*/
  auto data = std::string_view(reinterpret_cast<const char*>(value), payload_len);
  auto header = tcp_it->second->onData(data);
  LOG_D("input method : %s, path : %s, host : %s, state : %d", header.method_.c_str(),
        header.path_.c_str(), header.host_.c_str(), static_cast<int>(header.parseState_));
  /*parse http state*/
  if (header.parseState_ != ParseState::Done)
    return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), 0, NULL);
  /*get rule key*/
  rule_key = tcp_it->second->getRuleKey();
  /*query http rule*/
  auto http_rule = g_net_input_http_policy.find(rule_key);
  if (http_rule == g_net_input_http_policy.end())
    return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kDefault), 0, NULL);
  // process header
  rule_ret = MatchHttpPolicyRule(http_rule->second, header);
  /*print debug log*/
  LOG_D("match input http rule : %d, key : %s", static_cast<int>(rule_ret), rule_key.c_str());
  /*net rule continue*/
  if (rule_ret == NetPolicyRule::kDefault)
    return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), 0, NULL);
  /*post match message*/
  PostMatchMsg(tuple, rule_ret, FlowDir::kIngress, rule_key);
  /*rst tcp link*/
  if (rule_ret == NetPolicyRule::kDeny)
    rst_tcp_link(pkg);
  /*send rst http*/
  return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowReq), data_len, pkg);
}

static int output_nfq_cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa,
                         void* argv) {
  bool found = false;
  int id = 0, ret, offset;
  uint32_t mark;
  FLOW_DIR dir = FlowDir::kEgress;
  std::string rule_key;
  FiveTuple tuple;
  struct tcphdr tcphdr;
  TCP_FOUR_TUPLE_V4 ct_key;
  struct nfqnl_msg_packet_hdr* ph;
  unsigned char *pkg, *value;
  NET_POLICY_RULE rule_ret;
  std::map<TCP_FOUR_TUPLE_V4, http::ConnectionPtr>::iterator tcp_it;
  // NFQ_RES_INFO *nfq_res = (NFQ_RES_INFO *)argv;
  // nfq_res = nfq_res;

  ph = nfq_get_msg_packet_hdr(nfa);
  if (!ph)
    return 0;

  id = ntohl(ph->packet_id);
  // printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);

  mark = nfq_get_nfmark(nfa);
  if ((mark == static_cast<uint32_t>(NetPolicyRule::kAllow)) ||
      (mark == static_cast<uint32_t>(NetPolicyRule::kAllowReq)))
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

  auto data_len = nfq_get_payload(nfa, &pkg);
  if (data_len < 0)
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

  // printf("payload_len=%d ", ret);
  if (data_len < (int)sizeof(struct iphdr))
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

  ret = parse_package(pkg, tuple, &tcphdr, offset);
  if (ret != kNfMatchRule)
    nfq_set_verdict(qh, id, ret, 0, NULL);
  /*print debug log*/
  // LOG_V("output receive %s, mark : %d, seq: %u, tot len : %d, %s:%u -> %s:%u, memory : %p ",
  // GetProtoString(tuple.proto_), mark, ntohl(tcphdr.seq), tuple.tot_len_, tuple.src_addr_.c_str(),
  // tuple.src_port_, tuple.dst_addr_.c_str(), tuple.dst_port_, argv); LOG_D("input receive data: %p",
  // pkg);
  if (g_waf_enable && (tuple.proto_ == IPPROTO_TCP)) {
    auto status =
        g_connection_manager.receive(seastar::net::packet::from_static_data((char*)pkg, data_len));
    if (status == net::NetStatus::Drop) {
      // LOG_D("drop pkt: %p", pkg);
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowRsp), data_len, pkg);
    }
  }
  /*tcp four tuple*/
  ct_key.dst_port_ = tuple.dst_port_;
  ct_key.src_port_ = tuple.src_port_;
  ct_key.dst_addr_ = tuple.dst_addr_u32_;
  ct_key.src_addr_ = tuple.src_addr_u32_;
  /*tcp protocol*/
  switch (tuple.proto_) {
  case IPPROTO_TCP:
    /*query conntrack info*/
    tcp_it = g_tcp_ct_output.find(ct_key);
    if (tcp_it == g_tcp_ct_output.end()) {
      /*tcp syn*/
      if (tcphdr.syn != 0)
        break;
      /*tcp ack*/
      if (data_len <= offset)
        return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowRsp), 0, NULL);
      /*break*/
      break;
    }
    /*tcp tuple exist*/
    found = true;
    /*tcp fin*/
    if ((tcphdr.fin == 1) || (tcphdr.rst == 1)) {
      g_tcp_ct_output.erase(ct_key);
      /*print debug log*/
      LOG_D("microseg-dp out data, delete conntrack info, src: %s:%d, dest : %s:%d",
            tuple.src_addr_.c_str(), tuple.src_port_, tuple.dst_addr_.c_str(), tuple.dst_port_);
      /*return*/
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllow), 0, NULL);
    }
    /*tcp ack*/
    if (data_len <= offset)
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowRsp), 0, NULL);
    /*break*/
    break;
  case IPPROTO_UDP:
  case IPPROTO_ICMP:
    break;
  default:
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
  }
  /*query tcp conntrack result*/
  if (!found) {
    /*match rule*/
    rule_ret = MatchMicroPolicyRule(tuple, dir, rule_key);
    if (rule_ret == NetPolicyRule::kDefault)
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllow), 0, NULL);
    /*query http rule*/
    auto http_rule = g_net_output_http_policy.find(rule_key);
    /*check http rule*/
    if ((http_rule == g_net_output_http_policy.end()) || (tuple.proto_ == IPPROTO_UDP) ||
        (tuple.proto_ == IPPROTO_ICMP) || (http_rule->second.empty())) {
      /*post match message*/
      PostMatchMsg(tuple, rule_ret, dir, rule_key);
      // deny
      if (rule_ret == NetPolicyRule::kDeny) {
        LOG_D("output drop %s %s:%u -> %s:%u ", GetProtoString(tuple.proto_), tuple.src_addr_.c_str(),
              tuple.src_port_, tuple.dst_addr_.c_str(), tuple.dst_port_);
        /*drop data*/
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
      }
      /*return*/
      return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllow), 0, NULL);
    }
  }
  auto tcp_seq = ntohl(tcphdr.seq);
  /*tcp syn packet*/
  if (tcphdr.syn == 1) {
    LOG_D("microseg-dp output sync, rule key : %s, src: %s, dest : %s, offset : %d, data len : %d",
          rule_key.c_str(), tuple.src_addr_.c_str(), tuple.dst_addr_.c_str(), offset, data_len);
    auto conn = std::make_unique<http::Connection>(rule_key);
    conn->setTcpSeq(tcp_seq + 1);
    g_tcp_ct_output.insert({ct_key, std::move(conn)});
    /*return*/
    return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowRsp), 0, NULL);
  }
  /*print debug log*/
  LOG_D("microseg-dp output data, src: %s, dest : %s, offset : %d, data len : %d",
        tuple.src_addr_.c_str(), tuple.dst_addr_.c_str(), offset, data_len);
  /*can not find tcp conntrack*/
  if (tcp_it == g_tcp_ct_output.end()) {
    LOG_D("microseg-dp output not sync, new conntrack, src: %s, dest : %s, offset : %d, data len : "
          "%d",
          tuple.src_addr_.c_str(), tuple.dst_addr_.c_str(), offset, data_len);
    auto [it, success] = g_tcp_ct_output.insert({ct_key, std::make_unique<http::Connection>(rule_key)});
    if (success) {
      tcp_it = it;
    }
  }
  /*get tcp data*/
  value = pkg + offset;
  /*get rule key*/
  rule_key = tcp_it->second->getRuleKey();
  /*get tcp seq*/
  if (tcp_seq < tcp_it->second->getTcpSeq()) {
    LOG_D("output - duplicated tcp segment");
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
  }

  auto payload_len = data_len - offset;
  /*save tcp seq*/
  tcp_it->second->setTcpSeq(tcp_seq + payload_len);
  /*string convert*/
  auto data = std::string_view(reinterpret_cast<const char*>(value), payload_len);
  auto header = tcp_it->second->onData(data);
  LOG_D("output method : %s, path : %s, host : %s, state : %d, rule key : %s",
        header.method_.c_str(), header.path_.c_str(), header.host_.c_str(),
        static_cast<int>(header.parseState_), rule_key.c_str());
  /*parse http state*/
  if (header.parseState_ != ParseState::Done)
    return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowRsp), 0, NULL);
  /*query http rule*/
  auto http_rule = g_net_output_http_policy.find(rule_key);
  if (http_rule == g_net_output_http_policy.end())
    return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kDefault), 0, NULL);
  // process header
  rule_ret = MatchHttpPolicyRule(http_rule->second, header);
  /*print debug log*/
  LOG_D("match output http rule : %d, key : %s", static_cast<int>(rule_ret), rule_key.c_str());
  /*net rule continue*/
  if (rule_ret == NetPolicyRule::kDefault)
    return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowRsp), 0, NULL);
  /*post match message*/
  PostMatchMsg(tuple, rule_ret, FlowDir::kEgress, rule_key);
  /*rst tcp link*/
  if (rule_ret == NetPolicyRule::kDeny)
    rst_tcp_link(pkg);
  /*send rst http*/
  return nfq_set_verdict2(qh, id, NF_ACCEPT, static_cast<uint32_t>(NetPolicyRule::kAllowRsp), data_len, pkg);
}

int OpenConntrack(NFQ_RES_INFO* nfq_res) {
  FiveTuple tuple = {};
  // nf conntrack
  nfq_res->nfct_ = nfct_new();
  if (!nfq_res->nfct_)
    GOTO_ERROR(err, "new nf conntrack failed");
  nfq_res->nfct_hd_ = nfct_open();
  if (!nfq_res->nfct_hd_)
    GOTO_ERROR(err, "open nf conntrack failed");
  // nf conntrack callback
  nfq_res->nfct_cb_ = nfct_new();
  if (!nfq_res->nfct_cb_)
    GOTO_ERROR(err, "new nf conntrack cb failed");
  nfq_res->nfct_cb_hd_ = nfct_open();
  if (!nfq_res->nfct_cb_hd_)
    GOTO_ERROR(err, "open nf conntrack cb failed");
  // register
  nfct_callback_register(nfq_res->nfct_hd_, NFCT_T_ALL, UpdateNetSession, nfq_res);
  /*return*/
  return 0;
err:
  if (nfq_res->nfct_)      nfct_destroy(nfq_res->nfct_);
  if (nfq_res->nfct_cb_)   nfct_destroy(nfq_res->nfct_cb_);
  if (nfq_res->nfct_hd_)   nfct_close(nfq_res->nfct_hd_);
  if (nfq_res->nfct_cb_hd_) nfct_close(nfq_res->nfct_cb_hd_);
  return -1;
}

int OpenNfque(FLOW_DIR quenum, NFQ_RES_INFO* nfq_res) {
  int ret;
  struct nfq_handle* h = NULL;
  struct nfq_q_handle* qh = NULL;
  /*nfq open*/
  h = nfq_open();
  if (!h)
    RETURN_ERROR(-1, "nfq_open failed.");

  ret = nfq_unbind_pf(h, AF_INET);
  if (ret < 0)
    GOTO_ERROR(err, "nfq unbind pf failed.");

  ret = nfq_bind_pf(h, AF_INET);
  if (ret < 0)
    GOTO_ERROR(err, "fq bind pf failed.");

  if (quenum == FlowDir::kIngress) {
    qh = nfq_create_queue(h, static_cast<uint16_t>(quenum), &input_nfq_cb, (void*)nfq_res);
  } else {
    qh = nfq_create_queue(h, static_cast<uint16_t>(quenum), &output_nfq_cb, (void*)nfq_res);
  }
  if (!qh)
    GOTO_ERROR(err, "nfq create queue failed");

  ret = nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
  if (ret < 0)
    GOTO_ERROR(err, "nfq set mode failed.");

  /*save nfqueue handle*/
  if (quenum == FlowDir::kIngress) {
    nfq_res->input_fd_  = nfq_fd(h);
    nfq_res->input_que_ = qh;
  } else {
    nfq_res->output_fd_  = nfq_fd(h);
    nfq_res->output_que_ = qh;
  }
  /*return*/
  return 0;

err:
  if (h)
    nfq_close(h);
  if (qh)
    nfq_destroy_queue(qh);
  /*return*/
  return -1;
}

int NfqueueRcvData(int32_t epoll_fd, int32_t fd, void* ptr) {
  int ret;
  char buf[65536];
  NFQ_RES_INFO* nfq_res = NULL;
  struct nfq_q_handle* qh;
  RCV_EPOLL_CB* nfqEvent = (RCV_EPOLL_CB*)ptr;
  if (!ptr)
    RETURN_ERROR(0, "the argument pointer is nil.");
  nfq_res = nfqEvent->nfq_res_;
  /*read data*/
  ret = read(fd, buf, sizeof(buf));
  if (ret <= 0) {
    if ((errno == 0) || (errno == EAGAIN) || (errno == EINTR))
      RETURN_WARN(0, "read data failed, fd : %d, %s.", fd, strerror(errno));
    close(fd);
    RETURN_ERROR(0, "read nfqueue data failed, ret : %d, fd : %d, pid : %d, %s.", ret, fd,
                 nfq_res->pid_, strerror(errno));
  }
  /*check buffer*/
  // if(ret == (int)sizeof(buf)) RETURN_ERROR(0, "read nfqueue data is overflow.");
  /*get nfq handle*/
  qh = nfq_res->input_que_;
  if (fd != nfq_res->input_fd_)
    qh = nfq_res->output_que_;
  /*parse nfqueue data*/
  nfq_handle_packet(qh->h, buf, ret);
  /*return*/
  return 0;
}

int AddEpollEvent(int zEvfd, NFQ_RES_INFO* nfq_res) {
  int ret;
  struct epoll_event ev;
  RCV_EPOLL_CB *nfqInput = nullptr, *nfqOutput = nullptr;

  nfqInput = new RCV_EPOLL_CB;
  nfqOutput = new RCV_EPOLL_CB;
  if (!nfqInput || !nfqOutput)
    GOTO_ERROR(err, "new nfqueue resource info memory failed, %s.", strerror(errno));
  /*copy data*/
  nfqInput->nfq_res_ = nfq_res;
  nfqOutput->nfq_res_ = nfq_res;
  /*set nonblock*/
  fcntl(nfq_res->input_fd_, F_SETFL, fcntl(nfq_res->input_fd_, F_GETFL) | O_NONBLOCK);
  fcntl(nfq_res->output_fd_, F_SETFL, fcntl(nfq_res->output_fd_, F_GETFL) | O_NONBLOCK);
  /*input queue event*/
  nfqInput->fd_ = nfq_res->input_fd_;
  nfqInput->epoll_in_func_ = NfqueueRcvData;
  // register epoll event
  ev.data.ptr = nfqInput;
  ev.events = EPOLLIN;
  ret = epoll_ctl(zEvfd, EPOLL_CTL_ADD, nfq_res->input_fd_, &ev);
  if (ret < 0)
    GOTO_ERROR(err, "add nfqueue handle to epoll failed, pid : %d, %s.", nfq_res->input_fd_,
               strerror(errno));
  /*output queue event*/
  nfqOutput->fd_ = nfq_res->output_fd_;
  nfqOutput->epoll_in_func_ = NfqueueRcvData;
  // register epoll event
  ev.data.ptr = nfqOutput;
  ev.events = EPOLLIN;
  ret = epoll_ctl(zEvfd, EPOLL_CTL_ADD, nfq_res->output_fd_, &ev);
  if (ret < 0)
    GOTO_ERROR(err, "add nfqueue handle to epoll failed, pid : %d, %s.", nfq_res->output_fd_,
               strerror(errno));
  /*print debug log*/
  LOG_I("pid : %d, inputfd : %d, outputfd : %d.", nfq_res->pid_, nfq_res->input_fd_, nfq_res->output_fd_);
  nfq_res->input_cb_  = nfqInput;
  nfq_res->output_cb_ = nfqOutput;
  /*return*/
  return 0;

err:
  if (nfqInput)
    delete nfqInput;
  if (nfqOutput)
    delete nfqOutput;
  return 9;
}

int InitNfqueue(int epoll_fd, NET_CTRL_INFO& ctrl) {
  int ret;
  // check resource — duplicated resource is not an error
  if (g_micro_rule.GetNfqRes(ctrl.pod_id_) != nullptr)
    RETURN_WARN(0, "duplicated pod resource, pid : %d.", ctrl.pid_);
  // new memory
  auto nfq_res = std::make_unique<NFQ_RES_INFO>();
  /*memory init*/
  nfq_res->Init();
  /*save pid*/
  nfq_res->pid_     = ctrl.pid_;
  nfq_res->pod_id_  = ctrl.pod_id_;
  nfq_res->poll_fd_ = epoll_fd;
  /*init input queue*/
  ret = OpenNfque(FlowDir::kIngress, nfq_res.get());
  if (ret != 0)
    GOTO_ERROR(err, "init input queue resource failed, pid : %d.", ctrl.pid_);
  /*init output queue*/
  ret = OpenNfque(FlowDir::kEgress, nfq_res.get());
  if (ret != 0)
    GOTO_ERROR(err, "init output queue resource failed, pid : %d.", ctrl.pid_);
  /*init conntrack*/
  ret = OpenConntrack(nfq_res.get());
  if (ret != 0)
    GOTO_ERROR(err, "init conntrack resource failed, pid : %d.", ctrl.pid_);
  /*add epoll event*/
  ret = AddEpollEvent(epoll_fd, nfq_res.get());
  if (ret != 0)
    GOTO_ERROR(err, "add %d epoll event failed.", ctrl.pid_);
  /*insert nfqueue — transfer ownership*/
  ret = g_micro_rule.NewNfQueRes(ctrl.pod_id_, std::move(nfq_res));
  if (ret != 0)
    GOTO_ERROR(err, "insert nfqueue resource failed, pid : %d.", ctrl.pid_);
  /*return*/
  return 0;

err:
  if (nfq_res) nfq_res->FreeResource(epoll_fd);
  /*unique_ptr destructor handles delete*/
  return -6;
}

/*delete policy*/
int DeletePolicy(std::string& name) {
  if (name.empty())
    RETURN_ERROR(0, "the policy name is empty.");

  /*clear input http policy*/
  g_net_input_http_policy.erase(name);
  /*clear output http policy*/
  g_net_output_http_policy.erase(name);
  /*clear*/
  g_micro_rule.DeletePolicy(FlowDir::kIngress, name);
  /*clear*/
  g_micro_rule.DeletePolicy(FlowDir::kEgress, name);
  /*return*/
  return 0;
}

int AddNewHttpPolicy(FLOW_DIR dir, std::string& key, HTTP_RULE_INFO& http_rule) {
  auto& http = (dir == FlowDir::kIngress) ? g_net_input_http_policy : g_net_output_http_policy;
  auto& rules = http[key]; // default-constructs vector if key absent
  LOG_D("add http policy : %s, rules so far : %zu.", key.c_str(), rules.size());
  rules.push_back(http_rule);
  return 0;
}

/*add policy*/
int AddNewPolicy(RuleDetail& policy, RULE_PORT& stPort) {
  // check
  if ((policy.priority_ <= 0) || (policy.priority_ >= 129))
    RETURN_ERROR(-1, "priority is error, need 0 < priority < 129, priority : %d", policy.priority_);
  /*print debug log*/
  // PrintPolicyData(policy, stPort);
  /*处理下发的规则*/
  return g_micro_rule.AddPolicyToTree(policy, stPort);
}

/*update iptable rule*/
void UpdateMark(std::unordered_map<uint64_t, string>& cgRes) {
  int mark = static_cast<int>(NetPolicyRule::kDeny);
  FiveTuple tuple = {};

  for (auto it = cgRes.begin(); it != cgRes.end(); it++) {
    auto res = g_micro_rule.GetNfqRes(it->first);
    if (res == nullptr)
      CONTINUE_ERROR("can not find pod resource, pod id : %lu.", it->first);
    // set mark
    SetAcceptMark(res, tuple, NFCT_T_ALL, mark);
    //
    LOG_D("update mark, mark : %d, address : %s.", mark, it->second.c_str());
  }
}

/*check iptables rule*/
bool CheckIptablesRule() {
  int length;
  FILE* fp = NULL;
  char buf[1024];
  const char* icheck = (g_ipt_ver == 0) ? "iptables -t mangle -S | grep TS_ZERO_PREROUTING"
                                      : "iptables-legacy -t mangle -S | grep TS_ZERO_PREROUTING";
  //
  fp = popen(icheck, "r");
  if (!fp)
    RETURN_ERROR(false, "popen iptables input command failed, %s.", strerror(errno));

  length = fread(buf, 1, sizeof(buf), fp);
  pclose(fp);

  if (length < 0)
    RETURN_ERROR(false, "fread iptables input command ret failed, %s.", strerror(errno));
  if ((length == 0) || (strlen(buf) == 0))
    return false;

  return true;
}

void ClearIptabelsRule() {
  const char* clear = (g_ipt_ver == 0) ? "iptables -t mangle -F" : "iptables-legacy -t mangle -F";
  const char* dichan = (g_ipt_ver == 0) ? "iptables -t mangle -X TS_ZERO_PREROUTING"
                                      : "iptables-legacy -t mangle -X TS_ZERO_PREROUTING";
  const char* dochan = (g_ipt_ver == 0) ? "iptables -t mangle -X TS_ZERO_OUTPUT"
                                      : "iptables-legacy -t mangle -X TS_ZERO_OUTPUT";
  system(clear);
  system(dichan);
  system(dochan);
}

/*exec iptables*/
void WriteIptableRule(int iMarkNum, int oMarkNum) {
  int ret;
  FILE* fp = NULL;
  char buf[1024];
  char cmd[1024];
  const char* simark = nullptr;
  const char* somark = nullptr;

  const char* pcheck = (g_ipt_ver == 0) ? "iptables -t mangle -S | grep TS_ZERO_PREROUTING"
                                      : "iptables-legacy -t mangle -S | grep TS_ZERO_PREROUTING";
  const char* ocheck = (g_ipt_ver == 0) ? "iptables -t mangle -S | grep TS_ZERO_OUTPUT"
                                      : "iptables-legacy -t mangle -S | grep TS_ZERO_OUTPUT";

  const char* icreate = (g_ipt_ver == 0)
                            ? "iptables -t mangle -N TS_ZERO_PREROUTING 2>/dev/null && iptables -t "
                              "mangle -I PREROUTING -j TS_ZERO_PREROUTING"
                            : "iptables-legacy -t mangle -N TS_ZERO_PREROUTING 2>/dev/null && "
                              "iptables-legacy -t mangle -I PREROUTING -j TS_ZERO_PREROUTING";
  const char* ocreate = (g_ipt_ver == 0) ? "iptables -t mangle -N TS_ZERO_OUTPUT 2>/dev/null && "
                                         "iptables -t mangle -I OUTPUT -j TS_ZERO_OUTPUT"
                                       : "iptables-legacy -t mangle -N TS_ZERO_OUTPUT 2>/dev/null "
                                         "&& iptables-legacy -t mangle -I OUTPUT -j TS_ZERO_OUTPUT";

  const char* imark = (g_ipt_ver == 0)
                          ? "iptables -t mangle -I PREROUTING -j CONNMARK --restore-mark"
                          : "iptables-legacy -t mangle -I PREROUTING -j CONNMARK --restore-mark";
  const char* omark = (g_ipt_ver == 0)
                          ? "iptables -t mangle -I OUTPUT -j CONNMARK --restore-mark"
                          : "iptables-legacy -t mangle -I OUTPUT -j CONNMARK --restore-mark";

  if (!g_waf_enable) {
    simark = (g_ipt_ver == 0) ? "iptables -t mangle -A INPUT -j CONNMARK --save-mark"
                            : "iptables-legacy -t mangle -A INPUT -j CONNMARK --save-mark";
    somark = (g_ipt_ver == 0) ? "iptables -t mangle -A POSTROUTING -j CONNMARK --save-mark"
                            : "iptables-legacy -t mangle -A POSTROUTING -j CONNMARK --save-mark";
  }

  const char* ipass =
      (g_ipt_ver == 0)
          ? "iptables -t mangle -A TS_ZERO_PREROUTING -m mark --mark %d -j ACCEPT"
          : "iptables-legacy -t mangle -A TS_ZERO_PREROUTING -m mark --mark %d -j ACCEPT";
  const char* infque =
      (g_ipt_ver == 0)
          ? "iptables -t mangle -A TS_ZERO_PREROUTING -j NFQUEUE --queue-num 0 --queue-bypass"
          : "iptables-legacy -t mangle -A TS_ZERO_PREROUTING -j NFQUEUE --queue-num 0 "
            "--queue-bypass";

  const char* opass =
      (g_ipt_ver == 0) ? "iptables -t mangle -A TS_ZERO_OUTPUT -m mark --mark %d -j ACCEPT"
                     : "iptables-legacy -t mangle -A TS_ZERO_OUTPUT -m mark --mark %d -j ACCEPT";
  const char* onfque =
      (g_ipt_ver == 0)
          ? "iptables -t mangle -A TS_ZERO_OUTPUT -j NFQUEUE --queue-num 1 --queue-bypass"
          : "iptables-legacy -t mangle -A TS_ZERO_OUTPUT -j NFQUEUE --queue-num 1 --queue-bypass";

  // check iptables rule
  // if(CheckIptablesRule()) return;
  if (CheckIptablesRule()) {
    ClearIptabelsRule();
  }
  //
  fp = popen(pcheck, "r");
  if (!fp)
    GOTO_ERROR(err, "popen iptables input command failed, %s.", strerror(errno));
  ret = fread(buf, 1, sizeof(buf), fp);
  if (ret < 0)
    GOTO_ERROR(err, "fread iptables input command ret failed, %s.", strerror(errno));
  if ((ret == 0) || (strlen(buf) == 0)) {
    system(icreate);
    system(imark);
    bzero(cmd, sizeof(cmd));
    sprintf(cmd, ipass, iMarkNum);
    system(cmd);
    system(infque);
    if (simark)
      system(simark);
  }
  pclose(fp);
  //
  fp = popen(ocheck, "r");
  if (!fp)
    GOTO_ERROR(err, "popen iptables output command failed, %s.", strerror(errno));
  ret = fread(buf, 1, sizeof(buf), fp);
  if (ret < 0)
    GOTO_ERROR(err, "fread iptables output command ret failed, %s.", strerror(errno));
  if ((ret == 0) || (strlen(buf) == 0)) {
    system(ocreate);
    system(omark);
    bzero(cmd, sizeof(cmd));
    sprintf(cmd, opass, oMarkNum);
    system(cmd);
    system(onfque);
    if (somark)
      system(somark);
  }
  pclose(fp);
  return;
err:
  if (fp)
    pclose(fp);
  return;
}

NET_POLICY_RULE ConvertRuleAction(std::string& str) {
  if ((str.compare("Allow") == 0) || (str.compare("Log") == 0))
    return NetPolicyRule::kAllow;
  if (str.compare("Alert") == 0)
    return NetPolicyRule::kMark;
  /*default*/
  return NetPolicyRule::kDeny;
}

int ParseNodeCfg(char* buf) {
  uint32_t uzIp;
  int i, size, action;
  std::string value, ip;
  cJSON *root = NULL, *item, *param;
  /*check argument*/
  if (!buf)
    return -1;
  // ctrl json
  root = cJSON_Parse(buf);
  if (!root)
    GOTO_ERROR(err, "parse net policy json failed! original data : %s.", buf);
  // get action
  item = cJSON_GetObjectItem(root, "action");
  if (!item)
    GOTO_ERROR(err, "get node action failed.");
  value = item->valuestring;
  action = (value.compare("delete") == 0) ? 0 : 1;

  // get node ips
  item = cJSON_GetObjectItem(root, "node_ips");
  if (!item)
    GOTO_ERROR(err, "get node ip address failed.");

  size = cJSON_GetArraySize(item);
  for (i = 0; i < size; i++) {
    param = cJSON_GetArrayItem(item, i);
    if (!param)
      break;
    // node ip
    ip = param->valuestring;
    uzIp = ipv4StringToInt(ip);
    // add or delete node ip
    if (action == 0) {
      g_nodes_ip.erase(uzIp);
    } else {
      g_nodes_ip[uzIp] = 1;
    }
  }
  // free resource
  cJSON_Delete(root);
  // return
  return 0;

err:
  if (root)
    cJSON_Delete(root);
  return -1;
}

int ParseNetPolicy(char* buf) {
  uint64_t podId;
  int i, size, num, ret;
  cJSON *root = NULL, *item, *array, *ipaddr, *ports, *rules, *param, *httparr;
  std::string key, action, dir, value;
  std::vector<RULE_PORT> rulePorts = {};
  std::vector<std::string> srcip = {}, dstip = {};
  RULE_PORT rulePort = {};
  RuleDetail rule = {};
  NET_CTRL_INFO ctrl = {};
  HTTP_RULE_INFO http;
  std::unordered_map<uint64_t, string> cgRes = {};
  /*check argument*/
  if (!buf)
    return -1;
  // ctrl json
  root = cJSON_Parse(buf);
  if (!root)
    GOTO_ERROR(err, "parse net policy json failed! original data : %s.", buf);
  // get resource key
  item = cJSON_GetObjectItem(root, "policy_name");
  if (!item)
    GOTO_ERROR(err, "get net policy name failed.");
  /*clear vector ports*/
  rule.ports_.clear();
  rule.policy_key_ = item->valuestring;
  ctrl.policy_key_ = rule.policy_key_;
  // clear old policy
  DeletePolicy(rule.policy_key_);
  // create new policy
  rules = cJSON_GetObjectItem(root, "rules");
  if (!rules)
    GOTO_ERROR(err, "get rules information failed.");

  size = cJSON_GetArraySize(rules);
  for (i = 0; i < size; i++) {
    array = cJSON_GetArrayItem(rules, i);
    if (!array)
      break;
    // action
    item = cJSON_GetObjectItem(array, "action");
    if (!item)
      BREAK_ERROR("get rule's action failed");
    action = item->valuestring;
    rule.action_dsc_ = action;
    rule.action_ = ConvertRuleAction(rule.action_dsc_);
    // direction
    item = cJSON_GetObjectItem(array, "direction");
    if (!item)
      BREAK_ERROR("get rule's direction failed");
    dir = item->valuestring;
    rule.direction_ = (dir.compare("ingress") == 0) ? FlowDir::kIngress : FlowDir::kEgress;

    // default protocol
    rule.proto_ = 0;
    // get protocol
    item = cJSON_GetObjectItem(array, "protocol");
    if (item) {
      value = item->valuestring;
      rule.proto_ = NetProtoConvert(value);
    }
    // list http rule
    httparr = cJSON_GetObjectItem(array, "http");
    if (httparr) {
      http.action_ = rule.action_;
      http.direction_ = static_cast<uint8_t>(rule.direction_);
      for (int k = 0; k < cJSON_GetArraySize(httparr); k++) {
        item = cJSON_GetArrayItem(httparr, k);
        if (!item)
          BREAK_ERROR("get http config info failed.");
        param = cJSON_GetObjectItem(item, "host");
        if (!param)
          BREAK_ERROR("get http host failed.");
        http.host_ = cJSON_GetStringValue(param);
        param = cJSON_GetObjectItem(item, "method");
        if (!param)
          BREAK_ERROR("get http method failed.");
        http.method_ = cJSON_GetStringValue(param);
        param = cJSON_GetObjectItem(item, "path");
        if (!param)
          BREAK_ERROR("get http path failed.");
        http.path_ = cJSON_GetStringValue(param);
        /*save http rule*/
        AddNewHttpPolicy(rule.direction_, rule.policy_key_, http);
      }
    }
    // source address
    ipaddr = cJSON_GetObjectItem(array, "from_addresses");
    if (!ipaddr)
      BREAK_ERROR("get rule's from_addresses failed");
    num = cJSON_GetArraySize(ipaddr);
    for (int j = 0; j < num; j++) {
      // get ip address
      item = cJSON_GetArrayItem(ipaddr, j);
      if (!item)
        BREAK_ERROR("get source address info failed.");
      /*get ip string*/
      param = cJSON_GetObjectItem(item, "ip");
      if (!param)
        BREAK_ERROR("get source ip address failed.");
      value = cJSON_GetStringValue(param);
      // save source ip address
      ParseIpString(value, srcip);
      // direction
      if (rule.direction_ != FlowDir::kEgress)
        continue;
      //
      param = cJSON_GetObjectItem(item, "pod_id");
      if (!param)
        CONTINUE_ERROR("get pod id failed.");
      podId = (uint64_t)param->valuedouble;
      cgRes.insert(make_pair(podId, value));
    }
    //
    ports = cJSON_GetObjectItem(array, "ports");
    if (ports) {
      num = cJSON_GetArraySize(ports);
      for (int j = 0; j < num; j++) {
        value = "";
        rulePort = {};
        //
        param = cJSON_GetArrayItem(ports, j);
        if (!param)
          BREAK_ERROR("get port information failed.");
        //
        item = cJSON_GetObjectItem(param, "endPort");
        if (item)
          rulePort.end_port_ = item->valueint;
        //
        item = cJSON_GetObjectItem(param, "port");
        if (item)
          rulePort.port_ = item->valueint;
        //
        rulePort.proto_ = rule.proto_;
        //
        rulePort.end_port_ = (rulePort.end_port_ == 0) ? rulePort.port_ : rulePort.end_port_;
        // push
        rulePorts.push_back(rulePort);
      }
    }
    //
    item = cJSON_GetObjectItem(array, "priority");
    if (!item)
      BREAK_ERROR("get rule's priority failed");
    rule.priority_ = item->valueint;
    // destination address
    ipaddr = cJSON_GetObjectItem(array, "to_addresses");
    if (!ipaddr)
      BREAK_ERROR("get rule's to_addresses failed");
    num = cJSON_GetArraySize(ipaddr);
    for (int j = 0; j < num; j++) {
      item = cJSON_GetArrayItem(ipaddr, j);
      if (!item)
        BREAK_ERROR("get destination ip address failed.");
      //
      param = cJSON_GetObjectItem(item, "ip");
      if (!param)
        BREAK_ERROR("get source ip address failed.");
      value = cJSON_GetStringValue(param);
      // save source ip address
      ParseIpString(value, dstip);
      // direction
      if (rule.direction_ != FlowDir::kIngress)
        continue;
      //
      param = cJSON_GetObjectItem(item, "pod_id");
      if (!param)
        CONTINUE_ERROR("get pod id failed.");
      podId = (uint64_t)param->valuedouble;
      cgRes.insert(make_pair(podId, value));
    }
    // create network policy rule
    for (int j = 0; j < (int)srcip.size(); j++) {
      rule.src_ip_ = srcip.at(j);
      for (int n = 0; n < (int)dstip.size(); n++) {
        rule.dst_ip_ = dstip.at(n);
        if (rulePorts.size() == 0) {
          RULE_PORT rPort = {};
          // add new policy
          ret = AddNewPolicy(rule, rPort);
          if (ret != 0)
            LOG_E("create new policy failed.");
        } else {
          for (int p = 0; p < (int)rulePorts.size(); p++) {
            // add new policy
            ret = AddNewPolicy(rule, rulePorts.at(p));
            if (ret != 0)
              LOG_E("create new policy failed.");
          }
        }
      }
    }
    // clear data
    rulePorts.clear();
    srcip.clear();
    dstip.clear();
  }
  // free resource
  cJSON_Delete(root);
  // update iptables rule
  UpdateMark(cgRes);
  // return
  return 0;

err:
  if (root)
    cJSON_Delete(root);
  return -1;
}

int ParseRcvJson(char* buf, NET_CTRL_INFO* ctrl) {
  cJSON *root = NULL, *item;
  if (!ctrl || !buf)
    return -1;
  // ctrl json
  root = cJSON_Parse(buf);
  if (!root)
    RETURN_ERROR(-2, "parse json failed! original data : %s.", buf);
  // get data type
  item = cJSON_GetObjectItem(root, "msg_type");
  if (!item)
    GOTO_ERROR(err, "get message type item failed!");
  ctrl->msg_type_ = static_cast<NET_DATA_TYPE>(item->valueint);
  // get pid
  item = cJSON_GetObjectItem(root, "pid");
  if (item)
    ctrl->pid_ = item->valueint;
  // get pod id
  item = cJSON_GetObjectItem(root, "pod_id");
  if (item)
    ctrl->pod_id_ = (uint64_t)item->valuedouble;
  // get resource key
  item = cJSON_GetObjectItem(root, "policy_name");
  if (item)
    ctrl->policy_key_ = item->valuestring;
  // get uuid
  item = cJSON_GetObjectItem(root, "uuid");
  if (item)
    ctrl->uuid_ = item->valuestring;
  // get log level
  item = cJSON_GetObjectItem(root, "level");
  if (item)
    ctrl->level_ = item->valueint;
  // free resource
  cJSON_Delete(root);
  // check data
  switch (ctrl->msg_type_) {
  case NetDataType::kPodPid:
  case NetDataType::kPodDie:
    if (ctrl->pid_ == 0 || ctrl->pod_id_ == 0)
      RETURN_ERROR(-1, "need pod pid, message type : %d.", static_cast<int>(ctrl->msg_type_));
    break;
  case NetDataType::kAddRule:
  case NetDataType::kDelRule:
    if (ctrl->policy_key_.length() == 0)
      RETURN_ERROR(-1, "need policy name, message type : %d.", static_cast<int>(ctrl->msg_type_));
    break;
  default:
    break;
  }

  return 0;

err:
  if (root)
    cJSON_Delete(root);
  return -1;
}

cJSON* dumpConnectons(std::string_view req) {
  cJSON* root = cJSON_Parse(req.data());
  auto limitItem = cJSON_GetObjectItem(root, "limit");
  int limit = (int)limitItem->valuedouble;

  cJSON* connections = cJSON_CreateObject();
  cJSON_AddNumberToObject(connections, "total", g_connection_manager.stat().tcp_conn_);

  auto items = cJSON_CreateArray();
  auto conns = g_connection_manager.connections();
  for (int i = 0; i < limit; i++) {
    auto item = cJSON_CreateString(conns[i].c_str());
    cJSON_AddItemToArray(items, item);
  }

  cJSON_AddItemToObject(connections, "items", items);
  return connections;
}

char* ReadData(int epoll_fd, int fd) {
  int zDataLen = 0, offset = 0;
  char* pos = nullptr;
  char* pcBuffer = nullptr;
  char cDataBuf[1024] = {0};
  int totalRead, remainingBytes, initialDataLen;
  /*read data*/
  int ret = read(fd, cDataBuf, sizeof(cDataBuf));
  if (ret <= 0) {
    if ((errno == EAGAIN) || (errno == EINTR))
      RETURN_WARN(nullptr, "read data failed, fd : %d, %s.", fd, strerror(errno));
    GOTO_ERROR(err, "read net policy data failed, fd : %d, %s.", fd, strerror(errno));
  }
  totalRead = ret;
  if (ret <= ((int)strlen(PREFIX) + (int)sizeof(int)))
    RETURN_ERROR(nullptr, "data length error, data len : %d.", ret);

  pos = strstr(cDataBuf, PREFIX);
  if (pos == nullptr)
    RETURN_ERROR(nullptr, "can find message header.");

  pos += strlen(PREFIX);
  zDataLen = *(int*)pos;
  if (zDataLen <= 0)
    RETURN_ERROR(nullptr, "message length error, message len : %d.", zDataLen);
  /*print debug log*/
  LOG_D("message data length : %d", zDataLen);

  zDataLen += 1;
  pcBuffer = (char*)malloc(zDataLen);
  if (pcBuffer == nullptr)
    RETURN_WARN(nullptr, "malloc memory failed, fd : %d, %s.", fd, strerror(errno));
  memset(pcBuffer, 0, zDataLen);
  pos += sizeof(int);

  offset = pos - cDataBuf;
  // Copy initial data
  initialDataLen = totalRead - offset;
  if (initialDataLen > 0)
    memcpy(pcBuffer, pos, initialDataLen);

  // Read remaining data if necessary
  remainingBytes = zDataLen - 1 - initialDataLen; // -1 to exclude null terminator
  while (remainingBytes > 0) {
    ret = read(fd, pcBuffer + totalRead - offset, remainingBytes);
    if (ret <= 0) {
      if ((errno == EAGAIN) || (errno == EINTR))
        continue;
      GOTO_ERROR(err, "read remaining data failed, fd : %d, %s.", fd, strerror(errno));
    }
    remainingBytes -= ret;
    totalRead += ret;
  }

  return pcBuffer;

err:
  if (pcBuffer)
    free(pcBuffer);
  epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
  close(fd);
  return nullptr;
}

int ParseRcvData(int32_t epoll_fd, int32_t fd, void* ptr) {
  bool found;
  int ret = 400, length, offset = 0;
  char* result = nullptr;
  admin::Status status;
  char* data_buf = nullptr;
  cJSON* respBody = nullptr;
  char buf[11] = {"#%% pre"};
  NET_CTRL_INFO ctrl = {};
  if ((fd <= 0) || (!ptr))
    RETURN_ERROR(-2, "[net] parse failed by argumnet is error!");
  /*read data*/
  data_buf = ReadData(epoll_fd, fd);
  if (data_buf == nullptr)
    RETURN_ERROR(0, "read data faile.");
  /*print debug log*/
  LOG_V("receive msg, time : %s, data : %s", TimeToString().c_str(), data_buf);
  /*parse json*/
  ret = ParseRcvJson(data_buf, &ctrl);
  if (ret < 0)
    GOTO_ERROR(rsp, "[net] parse receive json failed!");
  /*condition*/
  switch (ctrl.msg_type_) {
  case NetDataType::kPodPid:
    // set ns
    ret = SetNs(ctrl.pid_, const_cast<char*>(kBasePath.data()));
    if (ret < 0)
      GOTO_ERROR(rsp, "setns to %d failed.", ctrl.pid_);
    // init nfqueue
    ret = InitNfqueue(epoll_fd, ctrl);
    /*print error info*/
    if (ret != 0)
      GOTO_ERROR(rsp, "init %d nfqueue failed, ret : %d.", ctrl.pid_, ret);
    // write iptables rule
    WriteIptableRule(1, 1);
    /*goto*/
    goto rsp;

  case NetDataType::kPodDie:
    ret = g_micro_rule.DeleteNfQueRes(epoll_fd, ctrl.pod_id_);
    goto rsp;

  case NetDataType::kAddRule:
    ret = ParseNetPolicy(data_buf);
    /*print rule size*/
    g_micro_rule.PrintPolicyLog();
    goto rsp;

  case NetDataType::kDelRule:
    ret = DeletePolicy(ctrl.policy_key_);
    goto rsp;

  case NetDataType::kAddWafRule:
    found = http::extension::RootContext.ParseConfiguration(data_buf);
    ret = (found == true) ? 0 : 1;
    goto rsp;

  case NetDataType::kDelWafRule:
    // delete waf config
    found = http::extension::RootContext.RemoveWafRule(data_buf);
    ret = (found == true) ? 0 : 1;
    goto rsp;

  case NetDataType::kHeapDump:
    status = admin::Heap::handleHeapProfile(std::string_view{data_buf, strlen(data_buf)});
    ret = (status == admin::Status::OK) ? 0 : 1;
    goto rsp;

  case NetDataType::kConfDump:
    respBody = g_micro_rule.GetAllConfig(ctrl.policy_key_);
    goto rsp;

  case NetDataType::kConnDump:
    respBody = dumpConnectons(std::string_view{data_buf, strlen(data_buf)});
    goto rsp;

  case NetDataType::kReset:
    ret = g_micro_rule.ClearCfg();
    ;
    goto rsp;

  case NetDataType::kNodeCfg:
    ret = ParseNodeCfg(data_buf);
    goto rsp;

  case NetDataType::kLogLevel:
    g_log_level = ctrl.level_;
    LOG_I("set log level : %d", g_log_level);
    goto rsp;

  default:
    LOG_E("data type is error, datatype : %d.", static_cast<int>(ctrl.msg_type_));
    break;
  }

rsp:
  /*释放内存*/
  if (data_buf != nullptr)
    free(data_buf);
  /*切换network namespace*/
  SetLocalNetNs(g_local_net_ns_fd);
  /*response data*/
  cJSON* response = cJSON_CreateObject();
  if (response == nullptr) {
    if (respBody)
      cJSON_Delete(respBody);
    RETURN_ERROR(0, "Create json object failed, error msg : %s", strerror(errno));
  }

  cJSON_AddNumberToObject(response, "status", ret);
  cJSON_AddNumberToObject(response, "msg_type", static_cast<int>(NetDataType::kRspAck));
  cJSON_AddStringToObject(response, "uuid", ctrl.uuid_.c_str());
  if (respBody != nullptr)
    cJSON_AddItemToObject(response, "body", respBody);
  /*format reponse data*/
  if (ctrl.msg_type_ == NetDataType::kConfDump) {
    result = cJSON_Print(response);
    /*data len*/
    length = (int)strlen(result);
    /*print response data*/
    LOG_V("rsp dump msg, time : %s, all data length : %d.", TimeToString().c_str(), length);
    /*send data*/
    buf[7] = length & 0xff;
    buf[8] = (length >> 8) & 0xff;
    buf[9] = (length >> 16) & 0xff;
    buf[10] = (length >> 24) & 0xff;
    /*send message header*/
    auto n = write(fd, buf, 11);
    LOG_V("write message header %ld bytes", n);
  } else {
    result = cJSON_PrintUnformatted(response);
    /*print response data*/
    LOG_V("rsp msg, time : %s, data : %s.", TimeToString().c_str(), result);
  }
  // send response data
  length = strlen(result);
  do {
    ret = write(fd, result + offset, length);
    /*print debug log*/
    if (ctrl.msg_type_ == NetDataType::kConfDump)
      LOG_D("send rsp msg, time : %s, ret: %d, data len %d, offset : %d.", TimeToString().c_str(),
            ret, length, offset);
    if (ret < 0)
      LOG_E("write data err : %s", strerror(errno));
    if ((ret <= 0) || (ret == length))
      break;
    /*repeat write data*/
    length -= ret;
    offset += ret;
  } while (1);

  /*free json memory*/
  cJSON_Delete(response);
  /*free memory*/
  if (result != nullptr)
    free(result);
  /*return*/
  return 0;
}

int ProcAcceptEvent(int32_t epoll_fd, int32_t fd, void* ptr) {
  int ret, zClientFd;
  socklen_t cliAddrLen;
  struct epoll_event ev;
  struct sockaddr_in address;
  static RCV_EPOLL_CB DaeEvent;
  // client address length
  cliAddrLen = sizeof(struct sockaddr_in);
  zClientFd = accept(fd, (struct sockaddr*)&address, &cliAddrLen);
  if (zClientFd <= 0)
    RETURN_ERROR(0, "accept a new client failed, %s.", strerror(errno));
  /*close old fd*/
  if (g_client_fd > 0) {
    if (zClientFd != g_client_fd)
      close(g_client_fd);
    LOG_W("close old globe fd, old fd : %d, new fd : %d.", g_client_fd, zClientFd);
  }
  /*print debug log*/
  LOG_I("accept new unix socket link, fd : %d, log level : %d", zClientFd, g_log_level);
  /*save fd*/
  g_client_fd = zClientFd;
  // noblock
  fcntl(zClientFd, F_SETFL, fcntl(zClientFd, F_GETFL) | O_NONBLOCK);
  /*callback*/
  DaeEvent.fd_ = g_client_fd;
  DaeEvent.epoll_in_func_ = ParseRcvData;
  // epoll event
  ev.data.ptr = &DaeEvent;
  ev.events = EPOLLIN;
  ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, zClientFd, &ev);
  if (ret < 0) {
    close(zClientFd);
    LOG_E("add new client to epoll failed, %s.", strerror(errno));
  }
  return 0;
}

int ProcAcceptPostLinkEvent(int32_t epoll_fd, int32_t fd, void* ptr) {
  int zClientFd;
  socklen_t cliAddrLen;
  struct sockaddr_in address;
  // client address length
  cliAddrLen = sizeof(struct sockaddr_in);
  zClientFd = accept(fd, (struct sockaddr*)&address, &cliAddrLen);
  if (zClientFd <= 0)
    RETURN_ERROR(0, "accept a new client failed, %s.", strerror(errno));
  /*close old fd*/
  if (g_post_link_fd > 0) {
    if (zClientFd != g_post_link_fd)
      close(g_post_link_fd);
    LOG_W("close old globe post fd, old fd : %d, new fd : %d.", g_post_link_fd, zClientFd);
  }
  /*save fd*/
  g_post_link_fd = zClientFd;
  http::extension::RootContext.SetPostFd(&g_post_link_fd);

  // noblock
  fcntl(zClientFd, F_SETFL, fcntl(zClientFd, F_GETFL) | O_NONBLOCK);
  // return
  return 0;
}

int CreatePostServer(int efd, RCV_EPOLL_CB* pstPostEv) {
  int fd = 0, ret, opt = 1;
  struct epoll_event ev;
  struct sockaddr_in address;
  // check argument
  if ((efd <= 0) || !pstPostEv)
    RETURN_ERROR(-5, "the argument pointer is nil");
  // create socket
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd <= 0)
    RETURN_ERROR(-2, "create unix socket failed! %s.", strerror(errno));
  // noblock
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  // socket address
  ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
  if (ret != 0)
    GOTO_ERROR(err, "set socket opt failed, %s", strerror(errno));
  // 设置服务器地址和端口
  address.sin_family = AF_INET;
  address.sin_port = htons(kPostNetPort);
  address.sin_addr.s_addr = inet_addr(kNetPolicyAddr.data());
  // bind socket address
  ret = bind(fd, (struct sockaddr*)&address, sizeof(address));
  if (ret != 0)
    GOTO_ERROR(err, "bind server tcp server socket failed, err : %s", strerror(errno));
  // listen sockfd
  ret = listen(fd, 1);
  if (ret != 0)
    GOTO_ERROR(err, "listen the client connect request! err : %s", strerror(errno));
  //
  pstPostEv->fd_ = fd;
  pstPostEv->epoll_in_func_ = ProcAcceptPostLinkEvent;
  // register epoll event
  ev.data.ptr = pstPostEv;
  ev.events = EPOLLIN;
  ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
  if (ret < 0)
    GOTO_ERROR(err, "epoll ctl failed, %s.", strerror(errno));
  // return
  return 0;
err:
  if (fd > 0)
    close(fd);
  return -2;
}

void CustomPrefix(std::ostream& s, const google::LogMessageInfo& l, void*) {
  s << std::setw(4) << 1900 + l.time.year() << '-' << std::setw(2) << 1 + l.time.month() << '-'
    << std::setw(2) << l.time.day() << 'T' << std::setw(2) << l.time.hour() << ':' << std::setw(2) << l.time.min()
    << ':' << std::setw(2) << l.time.sec() << "." << std::setw(6) << l.time.usec()
    << ' '
    //    << std::setfill(' ') << std::setw(5)
    << l.thread_id << std::setfill('0') << " {" << l.severity << "} " << l.filename << ':'
    << l.line_number;
}

int GetIptablesVersion() {
  int ret;
  FILE* fp = NULL;
  std::string value;
  char buf[1024];
  /*exec command*/
  fp = popen("iptables -t nat -S PREROUTING", "r");
  if (!fp)
    RETURN_ERROR(-1, "popen iptables command failed, %s.", strerror(errno));
  /*init memory*/
  memset(buf, 0, sizeof(buf));
  /*read data*/
  ret = fread(buf, 1, sizeof(buf), fp);
  /*close*/
  pclose(fp);
  /*check result*/
  if (ret < 0)
    RETURN_ERROR(-1, "fread iptables command's ret failed, %s.", strerror(errno));
  /*to string*/
  value = buf;
  auto pos = value.find("-A PREROUTING");
  if (pos != std::string::npos)
    return 0;
  /*use new iptables*/
  g_ipt_ver = 1;
  /*return*/
  return 0;
}

int main(int argc, char* argv[]) {
  google::InitGoogleLogging(argv[0], &CustomPrefix);
  google::ParseCommandLineFlags(&argc, &argv, true);
  FLAGS_logtostderr = true;

  http::HttpFilterFactory::getInstance().registerFilter(
      [](size_t id, uint32_t from, uint32_t to) -> std::shared_ptr<http::HttpFilterBase> {
        return std::make_shared<http::extension::LogFilter>(id, from, to);
      });

  http::HttpFilterFactory::getInstance().registerFilter(
      [](size_t id, uint32_t from, uint32_t to) -> std::shared_ptr<http::HttpFilterBase> {
        return std::make_shared<http::extension::PluginContext>(id, from, to);
      });

  char* log_level_env = NULL;
  struct epoll_event ev, events[20];
  int zListenFd = 0, epfd = 0, zLinkFd;
  int ret, nfds, i, opt = 1;
  struct sockaddr_in address;
  RCV_EPOLL_CB unixEvent, postEvent, *pstCbEv;
  // print start log
  LOG_I("policy process start......");
  /*get log level env*/
  log_level_env = getenv(POLICY_LOG_LEVEL);
  if (log_level_env)
    g_log_level = std::stoi(log_level_env);
  /*get waf env*/
  log_level_env = getenv(POLICY_WAF_ENABLE);
  if (log_level_env)
    g_waf_enable = (strcmp(log_level_env, "true") == 0) ? true : false;
  // open local net ns
  OpenLocalNetNs();
  /*get iptables version*/
  GetIptablesVersion();
  /*print debug log*/
  LOG_I("choose iptables version : %d", g_ipt_ver);
  // epoll fd
  epfd = epoll_create(32000);
  if (epfd <= 0)
    GOTO_ERROR(err, "create epoll fd failed, %s.", strerror(errno));
  // create post socket server
  ret = CreatePostServer(epfd, &postEvent);
  if (ret != 0)
    GOTO_ERROR(err, "create post server failed.");
  // create socket
  zListenFd = socket(AF_INET, SOCK_STREAM, 0);
  if (zListenFd <= 0)
    GOTO_ERROR(err, "create unix socket failed! %s.", strerror(errno));
  // noblock
  fcntl(zListenFd, F_SETFL, fcntl(zListenFd, F_GETFL) | O_NONBLOCK);
  // socket address
  ret = setsockopt(zListenFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
  if (ret != 0)
    GOTO_ERROR(err, "set socket opt failed, %s", strerror(errno));
  // 设置服务器地址和端口
  address.sin_family = AF_INET;
  address.sin_port = htons(kNetPolicyPort);
  address.sin_addr.s_addr = inet_addr(kNetPolicyAddr.data());
  // bind socket address
  ret = bind(zListenFd, (struct sockaddr*)&address, sizeof(address));
  if (ret < 0)
    GOTO_ERROR(err, "bind server unix socket failed, %s!", strerror(errno));
  // listen sockfd
  ret = listen(zListenFd, 10);
  if (ret < 0)
    GOTO_ERROR(err, "listen the client connect request! err : %s.", strerror(errno));
  //
  g_micro_rule.efd_ = epfd;
  //
  unixEvent.fd_ = zListenFd;
  unixEvent.epoll_in_func_ = ProcAcceptEvent;
  // register epoll event
  ev.data.ptr = &unixEvent;
  ev.events = EPOLLIN;
  ret = epoll_ctl(epfd, EPOLL_CTL_ADD, zListenFd, &ev);
  if (ret < 0)
    GOTO_ERROR(err, "epoll ctl failed, %s.", strerror(errno));
  // accept client request
  while (1) {
    nfds = epoll_wait(epfd, events, 20, -1);
    for (i = 0; i < nfds; i++) {
      pstCbEv = (RCV_EPOLL_CB*)events[i].data.ptr;
      /*check pointer*/
      if (!pstCbEv)
        continue;
      /*link fd*/
      zLinkFd = pstCbEv->fd_;
      if (events[i].events & EPOLLIN) {
        if (!pstCbEv->epoll_in_func_)
          continue;
        /*epll in callback*/
        pstCbEv->epoll_in_func_(epfd, zLinkFd, (void*)pstCbEv);
      }
    }
  }

err:
  if (zListenFd > 0)
    close(zListenFd);
  if (epfd > 0)
    close(epfd);
  return -1;
}
