#pragma once

#include <memory>
#include <unordered_map>
#include <string>
#include <tuple>
#include <vector>
#include <set>
#include <netinet/in.h>
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
#include "policy/engine.h"
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
extern void ClearIptabelsRule();
extern int SetNs(int pid, char *basePath);
/*connection manager*/
extern net::ConnectionManager g_connection_manager;

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
    uint32_t  saddr;
    uint32_t  daddr;
    uint8_t   placeholder;
    uint8_t   protocol;
    uint16_t  length;
};
using PSEUDO_HEADER = PseudoHeader; // legacy alias

struct TcpFourTupleV4
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator<(const TcpFourTupleV4& other) const noexcept {
        return std::tie(src_addr, dst_addr, src_port, dst_port) <
               std::tie(other.src_addr, other.dst_addr, other.src_port, other.dst_port);
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
    int32_t fd;
    RcvCbFunc epoll_in_func; // epoll EPOLLIN
    NFQ_RES_INFO *nfq_res;
};
using RCV_EPOLL_CB = RcvEpollCb; // legacy alias

struct NetCtrlInfo
{
    int  pid;           // 进程PID
    int  level;         // 日志级别
    uint64_t pod_id;
    std::string policy_key;
    std::string uuid;
    NetDataType msg_type; // 数据类型
};
using NET_CTRL_INFO = NetCtrlInfo; // legacy alias

struct RulePort
{
    uint16_t end_port; // 端口段上限
    uint16_t port;    // 端口段下限
    uint8_t  proto;   // 协议
};
using RULE_PORT = RulePort; // legacy alias

struct HTTP_RULE_INFO
{
    uint8_t direction;
    NetPolicyRule action;
    std::string host;
    std::string method;
    std::string path;
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
    void ClearNfQueResource(int efd);
};

/*策略详情*/
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

public:
    RuleDetail();
    ~RuleDetail();
    RuleDetail(const RuleDetail&) = default;
    RuleDetail& operator=(const RuleDetail&) = default;
    /*assign from shared_ptr — named method avoids non-standard operator= signature*/
    void AssignFrom(const std::shared_ptr<RuleDetail>& other) { *this = *other; }
    /*添加端口*/
    void AddPortsCfg(RULE_PORT &);
    /*清除端口配置*/
    void ClearPortsCfg();
    /*生成用于匹配的策略*/
    std::string CreateRuleKey(int &mask);
    /*匹配策略详情*/
    bool MatchRuleDetail(FiveTuple &tuple, FlowDir dir);
    /*打印策略详情*/
    void PrintRuleDetail(std::string desc);
};

/*策略组*/
class RuleGroup
{
public:
    std::unordered_map<std::string, std::shared_ptr<RuleDetail>> rules_;//key-策略名称

public:
    RuleGroup();
    ~RuleGroup();
    /*增加策略详情信息*/
    bool AddRuleDetail(RuleDetail, RULE_PORT &);
    /*删除匹配策略*/
    void DeleteRule(std::string policyName);
    /*匹配策略*/
    bool MatchRule(FiveTuple &tuple, RuleDetail &detail, FlowDir dir);
    /*获取规则数*/
    size_t GetRulesSize();
};

/*链上规则表*/
class RuleChain
{
public:
    FlowDir dir_;
    std::unordered_map<std::string, std::shared_ptr<RuleGroup>> chain_;//key-匹配规则

public:
    RuleChain();
    ~RuleChain();
    /*获取规则表数据量*/
    size_t RuleSize();
    /*清空规则*/
    void RuleChainClear();
    /*set dir*/
    void SetRuleDir(FlowDir);
    /*匹配规则*/
    bool MatchRuleGroup(std::string &key, FiveTuple &tuple, RuleDetail &detail);
    /*生成匹配规则,并保持到链上*/
    int AddRuleToChain(std::string key, RuleDetail &policy, RULE_PORT &stPort);
    /*从链上删除规则*/
    void DeleteRuleFromChain(std::string pname, std::string ruleKey);
};

/**/
class PolicyTree : public RuleChain
{
public:
    /*policy tree*/
    std::unordered_map<std::string, std::unordered_map<std::string, FlowDir>*> tree_;

public:
    PolicyTree();
    ~PolicyTree();
    /*clear*/
    int Clear();
    /*get size*/
    int GetTreeSize();
    /*delete policy*/
    int DeletePolicyFromTree(std::string &name);
    /*将规则添加到链上*/
    int AddPolicyToChain(RuleDetail &policy, RULE_PORT &stPort, int &zMask);
};

/*网络策略详情*/
class PolicyRule : public NfQueData
{
public:
    int efd_;
    /*Input上的策略规则*/
    /*Output上的策略规则*/
    PolicyTree input_tree_;
    PolicyTree output_tree_;
    /*子网掩码*/
    std::set<int> mask_cidr_;
    /*优先级*/
    std::set<int> priority_;

public:
    PolicyRule();
    ~PolicyRule();
    /*清除优先级和子网掩码*/
    int ClearCfg();
    /*删除指定策略*/
    int DeletePolicy(FlowDir dir, std::string name);
    /*添加优先级和子网掩码*/
    void AddMaskAndPriority(int priority, int mask);
    /*将规则添加到链上*/
    int AddPolicyToTree(RuleDetail &policy, RULE_PORT &stPort);
    /*通过五元组生成规则*/
    void CreateRuleKeyByTuple(FiveTuple &tuple, FlowDir dir, std::vector<std::string> &value);
    /*获取策略map*/
    PolicyTree *GetPolicyTree(FlowDir dir);
    /*获取所有规则配置*/
    cJSON *GetAllConfig(std::string name);
    /*打印日志*/
    void PrintPolicyLog();
};
