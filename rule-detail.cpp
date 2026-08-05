#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
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
#include "common/utf8_check.h"
#include "net-policy.h"

using std::make_pair;
using std::string;

FiveTuple::FiveTuple() { this->InitTuple(); }
FiveTuple::~FiveTuple() {}

void FiveTuple::InitTuple() {
  this->proto_ = 0;
  this->tot_len_ = 0;
  this->src_port_ = 0;
  this->dst_port_ = 0;
  this->src_addr_u32_ = 0;
  this->dst_addr_u32_ = 0;
  this->src_addr_ = "";
  this->dst_addr_ = "";
}

void FiveTuple::PrintData(std::string key, int level) {
  if (level < g_log_level)
    return;
  if (this->src_port_ == 53 || this->dst_port_ == 53)
    return;
  if (this->src_addr_ == "127.0.0.1" || this->dst_addr_ == "127.0.0.1")
    return;
  LOG_D("key : %s, five tuple -> proto : %d, %s:%d --> %s:%d", key.c_str(), this->proto_,
        this->src_addr_.c_str(), this->src_port_, this->dst_addr_.c_str(), this->dst_port_);
}

void FiveTuple::ReverseTuple(FiveTuple& tuple) {
  // 备份当前对象的成员变量
  auto temp_proto = this->proto_;
  auto temp_tot_len = this->tot_len_;
  auto temp_src_port = this->src_port_;
  auto temp_dst_port = this->dst_port_;
  auto temp_src_u32 = this->src_addr_u32_;
  auto temp_dst_u32 = this->dst_addr_u32_;
  auto temp_src_addr = this->src_addr_;
  auto temp_dst_addr = this->dst_addr_;

  // 将当前对象的值赋给传入的 tuple
  tuple.proto_ = temp_proto;
  tuple.tot_len_ = temp_tot_len;
  tuple.src_port_ = temp_dst_port; // 交换 src_port_ 和 dst_port_
  tuple.dst_port_ = temp_src_port;
  tuple.src_addr_u32_ = temp_dst_u32; // 交换地址
  tuple.dst_addr_u32_ = temp_src_u32;
  tuple.src_addr_ = temp_dst_addr;
  tuple.dst_addr_ = temp_src_addr;
}

NFQ_RES_INFO::NFQ_RES_INFO() {}
NFQ_RES_INFO::~NFQ_RES_INFO() {}

void NFQ_RES_INFO::Init() {
  this->pid_ = 0;
  this->pod_id_ = 0;
  this->poll_fd_ = 0;
  // input_queue_/output_queue_ default-construct as disengaged
  // std::optionals; no explicit reset needed here.
  this->input_cb_ = nullptr;
  this->output_cb_ = nullptr;
  // nf conntrack
  this->nfct_ = nullptr;
  this->nfct_cb_ = nullptr;
  this->nfct_hd_ = nullptr;
  this->nfct_cb_hd_ = nullptr;
}

/*释放资源*/
void NFQ_RES_INFO::FreeResource(int efd) {
  struct epoll_event ev;

  /*unregister + close input queue*/
  if (this->input_queue_) {
    int fd = (*this->input_queue_)->fd();
    ev.data.fd = fd;
    epoll_ctl(efd, EPOLL_CTL_DEL, fd, &ev);
    this->input_queue_.reset();  // drops the Rust NfqQueue, closing its socket
  }
  /*unregister + close output queue*/
  if (this->output_queue_) {
    int fd = (*this->output_queue_)->fd();
    ev.data.fd = fd;
    epoll_ctl(efd, EPOLL_CTL_DEL, fd, &ev);
    this->output_queue_.reset();
  }
  if (this->input_cb_)
    delete this->input_cb_;
  if (this->output_cb_)
    delete this->output_cb_;
  if (this->nfct_)
    nfct_destroy(this->nfct_);
  if (this->nfct_cb_)
    nfct_destroy(this->nfct_cb_);
  if (this->nfct_hd_)
    nfct_close(this->nfct_hd_);
  if (this->nfct_cb_hd_)
    nfct_close(this->nfct_cb_hd_);
  /*print debug log*/
  LOG_I("free nfqueue resource, pid : %d", this->pid_);
}

PolicyRule::PolicyRule() : engine_(policy_engine::new_policy_engine()) {}
PolicyRule::~PolicyRule() {}

int PolicyRule::ClearCfg() {
  engine_->clear_cfg();
  return 0;
}

std::optional<RuleDetail> PolicyRule::MatchFiveTuple(FiveTuple& tuple, FlowDir dir) {
  if (!IsValidUtf8(tuple.src_addr_) || !IsValidUtf8(tuple.dst_addr_)) {
    LOG_W("skipped policy match: invalid UTF-8 in five-tuple address");
    return std::nullopt;
  }
  int32_t dir_int = (dir == FlowDir::kIngress) ? 0 : 1;
  auto result = engine_->match_five_tuple(tuple.proto_, tuple.dst_port_, tuple.src_port_,
                                            tuple.src_addr_, tuple.dst_addr_, dir_int);
  if (!result.matched)
    return std::nullopt;

  RuleDetail rd;
  rd.proto_ = result.detail.proto;
  rd.priority_ = result.detail.priority;
  rd.addr_type_ = result.detail.addr_type;
  rd.direction_ = (result.detail.direction == 0) ? FlowDir::kIngress : FlowDir::kEgress;
  rd.action_ = static_cast<NetPolicyRule>(result.detail.action);
  rd.action_dsc_ = std::string(result.detail.action_dsc);
  rd.policy_key_ = std::string(result.detail.policy_key);
  rd.src_ip_ = std::string(result.detail.src_ip);
  rd.dst_ip_ = std::string(result.detail.dst_ip);
  for (const auto& p : result.detail.ports) {
    RULE_PORT port{};
    port.end_port_ = p.end_port;
    port.port_ = p.port;
    port.proto_ = p.proto;
    rd.ports_.push_back(port);
  }
  return rd;
}

int PolicyRule::AddPolicyToTree(RuleDetail& policy, RULE_PORT& stPort) {
  if (!IsValidUtf8(policy.policy_key_) || !IsValidUtf8(policy.src_ip_) ||
      !IsValidUtf8(policy.dst_ip_) || !IsValidUtf8(policy.action_dsc_)) {
    RETURN_ERROR(-1, "invalid UTF-8 in policy fields, refusing to add.");
  }
  policy_engine::SharedRuleDetail rd{};
  rd.proto = policy.proto_;
  rd.priority = policy.priority_;
  rd.addr_type = policy.addr_type_;
  rd.direction = (policy.direction_ == FlowDir::kIngress) ? 0 : 1;
  rd.action = static_cast<uint32_t>(policy.action_);
  rd.action_dsc = policy.action_dsc_;
  rd.policy_key = policy.policy_key_;
  rd.src_ip = policy.src_ip_;
  rd.dst_ip = policy.dst_ip_;

  policy_engine::SharedRulePort rp{};
  rp.end_port = stPort.end_port_;
  rp.port = stPort.port_;
  rp.proto = stPort.proto_;

  engine_->add_policy(rd, rp);
  return 0;
}

int PolicyRule::DeletePolicy(FlowDir dir, std::string name) {
  if (!IsValidUtf8(name)) {
    RETURN_ERROR(-1, "invalid UTF-8 in policy name, refusing to delete.");
  }
  int32_t dir_int = (dir == FlowDir::kIngress) ? 0 : 1;
  engine_->delete_policy(dir_int, name);
  return 0;
}

void PolicyRule::PrintPolicyLog() {
  auto in_rules = engine_->all_rules(0);
  auto out_rules = engine_->all_rules(1);
  LOG_D("NetInput : %lu, NetOutput : %lu", in_rules.size(), out_rules.size());
}

/*获取所有规则配置 -- linear scan over all_rules() rather than the old O(1)
 *unordered_map::find per group; deliberate, acceptable simplification for
 *this admin/debug config-dump path (not the packet-matching hot path).*/
cJSON* PolicyRule::GetAllConfig(std::string name, net::ConnectionManager& conn_mgr) {
  NFQ_RES_INFO* res;
  cJSON *containers = nullptr, *tcp = nullptr, *r = nullptr, *item;
  cJSON *config = nullptr, *inrule = nullptr, *outrule = nullptr;

  tcp = cJSON_CreateObject();
  config = cJSON_CreateObject();
  inrule = cJSON_CreateArray();
  outrule = cJSON_CreateArray();
  containers = cJSON_CreateArray();
  auto stat = conn_mgr.stat();
  if (!config || !outrule || !inrule || !tcp || !containers)
    GOTO_ERROR(err, "create json object failed.");

  for (int dir_idx = 0; dir_idx < 2; dir_idx++) {
    auto rules = engine_->all_rules(dir_idx);
    cJSON* arr = (dir_idx == 0) ? inrule : outrule;
    const char* label = (dir_idx == 0) ? "inbound_rules" : "outbound_rules";

    for (const auto& rd : rules) {
      if (!name.empty() && std::string(rd.policy_key) != name)
        continue;
      r = cJSON_CreateObject();
      if (!r) GOTO_ERROR(err, "create json object failed.");
      cJSON_AddStringToObject(r, "policy_name", std::string(rd.policy_key).c_str());
      cJSON_AddNumberToObject(r, "priority", rd.priority);
      cJSON_AddStringToObject(r, "direction",
          utility::directionString(rd.direction == 0 ? FlowDir::kIngress : FlowDir::kEgress).data());
      cJSON_AddStringToObject(r, "action",
          utility::actionString(static_cast<NetPolicyRule>(rd.action)).data());
      cJSON_AddStringToObject(r, "protocol", utility::protocolString(rd.proto).data());
      cJSON_AddNumberToObject(r, "protocol_int", rd.proto);
      cJSON_AddStringToObject(r, "from_address", std::string(rd.src_ip).c_str());
      cJSON_AddStringToObject(r, "to_address", std::string(rd.dst_ip).c_str());
      cJSON_AddItemToArray(arr, r);
    }
    cJSON_AddItemToObject(config, label, arr);
  }

  if (!name.empty())
    return config;

  for (auto it = this->res_data_.begin(); it != this->res_data_.end(); it++) {
    res = it->second.get();
    if (res == nullptr)
      continue;
    item = cJSON_CreateObject();
    if (!item)
      GOTO_ERROR(err, "create json object failed.");
    cJSON_AddNumberToObject(item, "pid", res->pid_);
    cJSON_AddNumberToObject(item, "pod_id", res->pod_id_);
    cJSON_AddItemToArray(containers, item);
  }
  cJSON_AddItemToObject(config, "containers", containers);

  cJSON_AddNumberToObject(tcp, "tcp_connection", stat.tcp_conn_);
  cJSON_AddItemToObject(config, "tcp", tcp);

  return config;

err:
  if (tcp) cJSON_Delete(tcp);
  if (config) cJSON_Delete(config);
  if (inrule) cJSON_Delete(inrule);
  if (outrule) cJSON_Delete(outrule);
  if (containers) cJSON_Delete(containers);
  return nullptr;
}

NfQueData::NfQueData() { this->res_data_.clear(); }
NfQueData::~NfQueData() {}

/*create nfqueue resource*/
int NfQueData::NewNfQueRes(uint64_t pid, std::unique_ptr<NFQ_RES_INFO> res) {
  auto ret = this->res_data_.insert(make_pair(pid, std::move(res)));
  if (!ret.second)
    RETURN_ERROR(-2, "save nfq resource data failed.");
  /*return*/
  return 0;
}

/*delete nfqueue resource*/
int NfQueData::DeleteNfQueRes(int efd, uint64_t pid) {
  auto it = this->res_data_.find(pid);
  if (it == this->res_data_.end())
    return 0;
  /*free resource before erasing*/
  if (it->second != nullptr)
    it->second->FreeResource(efd);
  /*erase key — unique_ptr destructor handles delete*/
  this->res_data_.erase(it);
  /*return*/
  return 0;
}

/*get nfqueue resource*/
NFQ_RES_INFO* NfQueData::GetNfqRes(uint64_t pid) {
  auto it = this->res_data_.find(pid);
  if (it == this->res_data_.end())
    return nullptr;
  /*return*/
  return it->second.get();
}
