#pragma once

#include <map>
#include <memory>
#include <optional>
#include <unordered_map>
#include <string>
#include <tuple>
#include <vector>
#include <set>
#include <netinet/in.h>
#include <unistd.h>
#include "vector"
#include "cjson.h"
#include "libmnl/libmnl.h"
#include "libnetfilter_conntrack/libnetfilter_conntrack.h"
#include "libnetfilter_queue/libnetfilter_queue.h"
#include "glog/logging.h"
#include "http/packet.hh"
#include "log.h"
#include "http/codec.h"
#include "http/connection.h"
#include "http/extension/log.h"
#include "http/filter.h"
#include "http/http_filter_factory.h"
#include "net/connection_manager.h"
#include "net/ip.h"
#include "net/utility.h"
#include "waf/plugin.h"
#include "net_policy_engine_cxxbridge/lib.h"
#include "admin/profile.h"
#include "utils.h"

inline constexpr std::string_view kBasePath      = "/host";
inline constexpr std::string_view kNetPolicyAddr = "127.0.0.1";
inline constexpr uint16_t         kNetPolicyPort  = 9999;
inline constexpr uint16_t         kPostNetPort    = 8888;
inline constexpr int              kNfMatchRule    = 6;

/* Responses from hook functions.
#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define NF_QUEUE 3
#define NF_REPEAT 4
#define NF_STOP 5
#define NF_MAX_VERDICT NF_STOP
*/

typedef struct nf_conntrack NF_CONNTRACK;
/*epoll call function*/
using RcvCbFunc = int32_t(*)(int32_t epoll_fd, int32_t fd, void* ptr);
/*清除iptables配置*/
extern void ClearIptabelsRule(int ipt_ver);
extern int SetNs(int pid, char *basePath);
/*daemon entrypoint; defined in net-policy.cpp, called from main.cpp*/
extern int RunNetPolicyDaemon(int argc, char* argv[]);

enum class NetDataType : int
{
    kPodPid      = 1,  // pod up
    kPodDie      = 2,  // delete pod
    kAddRule     = 3,  // add rule
    kDelRule     = 4,  // delete rule
    kRspAck      = 5,  // response
    kPostNet     = 6,  // deny post
    kAddWafRule  = 7,  // add waf rule
    kDelWafRule  = 8,  // delete waf rule
    kHeapDump    = 9,
    kConfDump    = 10,
    kConnDump    = 11,
    kReset       = 12,
    kNodeCfg     = 13,
    kLogLevel    = 14,
    kMax
};
// legacy alias
using NET_DATA_TYPE = NetDataType;

enum class NetPolicyRule : uint32_t
{
    kDeny      = 0,
    kAllow     = 1,
    kMark      = 2,
    kAllowRsp  = 3,
    kAllowReq  = 4,
    kDefault   = 5,
    kMax
};
// legacy alias
using NET_POLICY_RULE = NetPolicyRule;

enum class FlowDir : int
{
    kIngress = 0,
    kEgress  = 1,
    kMax
};
// legacy alias
using FLOW_DIR = FlowDir;

/*TCP/UDP伪首部*/
struct PseudoHeader
{
    uint32_t  saddr_;
    uint32_t  daddr_;
    uint8_t   placeholder_;
    uint8_t   protocol_;
    uint16_t  length_;
};
using PSEUDO_HEADER = PseudoHeader; // legacy alias

struct TcpFourTupleV4
{
    uint32_t src_addr_;
    uint32_t dst_addr_;
    uint16_t src_port_;
    uint16_t dst_port_;

    bool operator<(const TcpFourTupleV4& other) const noexcept {
        return std::tie(src_addr_, dst_addr_, src_port_, dst_port_) <
               std::tie(other.src_addr_, other.dst_addr_, other.src_port_, other.dst_port_);
    }
};
using TCP_FOUR_TUPLE_V4 = TcpFourTupleV4; // legacy alias

class FiveTuple
{
public:
    uint8_t  proto_;
    uint16_t tot_len_;
    uint16_t src_port_;
    uint16_t dst_port_;
    uint32_t src_addr_u32_;
    uint32_t dst_addr_u32_;
    std::string src_addr_;
    std::string dst_addr_;
public:
    FiveTuple();
    ~FiveTuple();
    void InitTuple();
    void ReverseTuple(FiveTuple &tuple);
    void PrintData(std::string, int level = 0);
};

struct RcvEpollCb; // forward declaration — full definition follows NFQ_RES_INFO
class DaemonContext; // forward declaration — full definition follows PostServer
namespace grpc_bridge { class GrpcDispatchQueue; }

class NFQ_RES_INFO
{
public:
    int pid_;
    int input_fd_;
    int output_fd_;
    int poll_fd_;
    struct nfq_q_handle* input_que_  = nullptr;
    struct nfq_q_handle* output_que_ = nullptr;
    RcvEpollCb*          input_cb_   = nullptr;
    RcvEpollCb*          output_cb_  = nullptr;
    // nf conntrack
    NF_CONNTRACK*        nfct_       = nullptr;
    NF_CONNTRACK*        nfct_cb_    = nullptr;
    struct nfct_handle*  nfct_hd_    = nullptr;
    struct nfct_handle*  nfct_cb_hd_ = nullptr;
    uint64_t pod_id_;
    DaemonContext*       daemon_     = nullptr; // non-owning; set once in InitNfqueue

public:
    NFQ_RES_INFO();
    ~NFQ_RES_INFO();
    /*初始化*/
    void Init();
    /*释放资源*/
    void FreeResource(int efd);
} ;

struct RcvEpollCb
{
    int32_t fd_;
    RcvCbFunc epoll_in_func_; // epoll EPOLLIN
    NFQ_RES_INFO *nfq_res_;
    DaemonContext* daemon_ = nullptr; // non-owning; set wherever this cb is wired up
};
using RCV_EPOLL_CB = RcvEpollCb; // legacy alias

struct NetCtrlInfo
{
    int  pid_;           // 进程PID
    int  level_;         // 日志级别
    uint64_t pod_id_;
    std::string policy_key_;
    std::string uuid_;
    NetDataType msg_type_; // 数据类型
};
using NET_CTRL_INFO = NetCtrlInfo; // legacy alias

struct RulePort
{
    uint16_t end_port_; // 端口段上限
    uint16_t port_;    // 端口段下限
    uint8_t  proto_;   // 协议
};
using RULE_PORT = RulePort; // legacy alias

struct HTTP_RULE_INFO
{
    uint8_t direction_;
    NetPolicyRule action_;
    std::string host_;
    std::string method_;
    std::string path_;
};

/*NFQUE*/
class NfQueData
{
public:
    std::unordered_map<uint64_t, std::unique_ptr<NFQ_RES_INFO>> res_data_;

public:
    NfQueData();
    ~NfQueData();
    /**/
    int NewNfQueRes(uint64_t pid, std::unique_ptr<NFQ_RES_INFO>);
    /**/
    int DeleteNfQueRes(int efd, uint64_t pid);
    /**/
    NFQ_RES_INFO *GetNfqRes(uint64_t pid);
    /**/
    void ClearNfQueResource(int efd, int ipt_ver);
};

/*策略详情 -- plain data holder; matching/key-generation logic now lives in
 *the Rust policy_engine crate (see PolicyRule below)*/
class RuleDetail
{
public:
    uint8_t proto_;//协议
    int  priority_;//权重
    int  addr_type_;//ipv4 OR ipv6
    FlowDir direction_; //流量策略方向
    NetPolicyRule action_;//策略
    std::string action_dsc_;//策略描述
    std::string policy_key_;//策略主键
    std::string src_ip_;//源地址
    std::string dst_ip_;//目的地址
    std::vector<RULE_PORT> ports_;//端口信息
};

/*网络策略详情 -- delegates all matching/mutation to the Rust policy engine*/
class PolicyRule : public NfQueData
{
public:
    int efd_;

public:
    PolicyRule();
    ~PolicyRule();
    /*清除优先级和子网掩码*/
    int ClearCfg();
    /*删除指定策略*/
    int DeletePolicy(FlowDir dir, std::string name);
    /*将规则添加到链上*/
    int AddPolicyToTree(RuleDetail &policy, RULE_PORT &stPort);
    /*single-call match, replacing the old GetPolicyTree/CreateRuleKeyByTuple/
     *MatchRuleGroup three-call sequence -- see
     *docs/superpowers/specs/2026-08-02-cpp-to-rust-phase4-policy-engine-design.md*/
    std::optional<RuleDetail> MatchFiveTuple(FiveTuple &tuple, FlowDir dir);
    /*获取所有规则配置*/
    cJSON *GetAllConfig(std::string name, net::ConnectionManager& conn_mgr);
    /*打印日志*/
    void PrintPolicyLog();

private:
    rust::Box<policy_engine::RustPolicyEngine> engine_;
};

/*micro-segmentation engine — owns the policy rule set and all companion state*/
class MicroSegEngine
{
public:
    /*set the epoll fd used by the underlying NFQ resources*/
    void SetEfd(int efd) { policy_rule_.efd_ = efd; }

    /*---- NFQ resource lifecycle (delegated to PolicyRule/NfQueData) ----*/
    NFQ_RES_INFO* GetNfqRes(uint64_t pod_id)      { return policy_rule_.GetNfqRes(pod_id); }
    int  NewNfQueRes(uint64_t pod_id, std::unique_ptr<NFQ_RES_INFO> res)
                                                   { return policy_rule_.NewNfQueRes(pod_id, std::move(res)); }
    int  DeleteNfQueRes(int efd, uint64_t pod_id)  { return policy_rule_.DeleteNfQueRes(efd, pod_id); }

    /*---- network policy (delegated to PolicyRule) ----*/
    std::optional<RuleDetail> MatchFiveTuple(FiveTuple& t, FlowDir d) { return policy_rule_.MatchFiveTuple(t, d); }
    int  AddPolicy(RuleDetail& policy, RulePort& port) { return policy_rule_.AddPolicyToTree(policy, port); }
    void DeletePolicy(const std::string& name);    /*erases HTTP rules AND net policy for both directions*/
    int  ClearCfg()                                { return policy_rule_.ClearCfg(); }
    void PrintPolicyLog()                          { policy_rule_.PrintPolicyLog(); }
    cJSON* GetAllConfig(const std::string& name, net::ConnectionManager& conn_mgr)
                                                    { return policy_rule_.GetAllConfig(name, conn_mgr); }

    /*---- HTTP L7 policy ----*/
    int  AddHttpPolicy(FlowDir dir, const std::string& key, HTTP_RULE_INFO& rule);
    std::unordered_map<std::string, std::vector<HTTP_RULE_INFO>>& InputHttpPolicy()  { return input_http_policy_; }
    std::unordered_map<std::string, std::vector<HTTP_RULE_INFO>>& OutputHttpPolicy() { return output_http_policy_; }

    /*---- node IP registry ----*/
    bool IsNodeIp(uint32_t ip) const               { return nodes_ip_.count(ip) > 0; }
    void AddNodeIp(uint32_t ip)                    { nodes_ip_[ip] = 1; }
    void RemoveNodeIp(uint32_t ip)                 { nodes_ip_.erase(ip); }

    /*---- TCP connection tracking ----*/
    std::map<TcpFourTupleV4, http::ConnectionPtr>& TcpCtInput()  { return tcp_ct_input_; }
    std::map<TcpFourTupleV4, http::ConnectionPtr>& TcpCtOutput() { return tcp_ct_output_; }

private:
    PolicyRule                                                         policy_rule_;
    std::unordered_map<uint32_t, uint8_t>                             nodes_ip_;
    std::map<TcpFourTupleV4, http::ConnectionPtr>                     tcp_ct_input_;
    std::map<TcpFourTupleV4, http::ConnectionPtr>                     tcp_ct_output_;
    std::unordered_map<std::string, std::vector<HTTP_RULE_INFO>>      input_http_policy_;
    std::unordered_map<std::string, std::vector<HTTP_RULE_INFO>>      output_http_policy_;
};

/*control-channel server — owns the connected client fd and registers it with epoll*/
class CtrlServer
{
public:
    ~CtrlServer() { if (client_fd_ > 0) close(client_fd_); }
    /*accept a new client; closes any previously connected fd, registers new fd with epoll*/
    int Accept(int epoll_fd, int client_fd, DaemonContext* daemon);

private:
    int client_fd_ = 0;
    RcvEpollCb epoll_cb_;
};

/*post-notification server — owns the client fd and sends match/WAF events*/
class PostServer
{
public:
    ~PostServer() { if (post_link_fd_ > 0) close(post_link_fd_); }
    /*accept a new client; closes any previously connected fd*/
    void Accept(int client_fd);
    /*send a policy-match notification; returns 0 on success, -1 on error*/
    int  SendMatchMsg(FiveTuple& tuple, NetPolicyRule action, FlowDir dir,
                      const std::string& rule_key);
    /*return pointer to the fd so the WAF plugin can write directly*/
    int* FdPtr() { return &post_link_fd_; }

private:
    int post_link_fd_ = 0;
};

/*single aggregate owner of everything that used to be a free-standing global
 *in net-policy.cpp/waf/plugin.cc. One instance is constructed on the stack of
 *RunNetPolicyDaemon and threaded through every epoll callback via
 *RcvEpollCb::daemon_ / NFQ_RES_INFO::daemon_. Not copyable — there is
 *exactly one instance for the life of the process (or of a test).*/
class DaemonContext
{
public:
    DaemonContext() : connection_manager_(http_filter_factory_) {
        waf_root_.SetPostFd(post_server_.FdPtr());
    }
    DaemonContext(const DaemonContext&) = delete;
    DaemonContext& operator=(const DaemonContext&) = delete;

    /*---- already-encapsulated instances ----*/
    MicroSegEngine&                     Microseg()   { return microseg_; }
    net::ConnectionManager&             ConnMgr()    { return connection_manager_; }
    PostServer&                         PostSrv()    { return post_server_; }
    CtrlServer&                         CtrlSrv()    { return ctrl_server_; }
    http::extension::PluginRootContext& WafRoot()    { return waf_root_; }
    http::HttpFilterFactory&            HttpFilters(){ return http_filter_factory_; }

    /*---- former raw-scalar globals (g_log_level stays a separate atomic global) ----*/
    bool WafEnabled() const           { return waf_enable_; }
    void SetWafEnabled(bool v)        { waf_enable_ = v; }
    int  LocalNetNsFd() const         { return local_net_ns_fd_; }
    void SetLocalNetNsFd(int fd)      { local_net_ns_fd_ = fd; }
    int  IptablesVersion() const      { return ipt_ver_; }
    void SetIptablesVersion(int v)    { ipt_ver_ = v; }

    /*non-owning; wired once at startup -- see grpc/control_dispatch.h for
     *GrpcDispatchQueue.*/
    void WireRustControlDispatch(grpc_bridge::GrpcDispatchQueue* q) { rust_dispatch_queue_ = q; }
    grpc_bridge::GrpcDispatchQueue* RustControlDispatchQueue() { return rust_dispatch_queue_; }

private:
    bool waf_enable_      = false;
    int  local_net_ns_fd_ = 0;
    int  ipt_ver_         = 0;

    http::HttpFilterFactory              http_filter_factory_;      // must precede connection_manager_
    net::ConnectionManager               connection_manager_;
    MicroSegEngine                       microseg_;
    CtrlServer                           ctrl_server_;
    PostServer                           post_server_;
    http::extension::PluginRootContext   waf_root_;

    grpc_bridge::GrpcDispatchQueue* rust_dispatch_queue_ = nullptr; // non-owning
};
