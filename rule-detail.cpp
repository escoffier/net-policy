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
#include "net-policy.h"

using std::string;
using std::make_pair;

void Ipv4CidrToIp(std::string cidr, std::string &ip, int &mask)
{
    struct in_addr addr;
    uint32_t uzIpaddr, uzMask;
    size_t index;
    string sip, smask;
    smask = "32";
    sip = cidr;
    index = cidr.find("/");
    if(index != string::npos)
    {
        sip = cidr.substr(0, index);
        smask = cidr.substr(index + 1);
    }
    uzIpaddr = ntohl(inet_addr(sip.c_str()));
    uzMask   = std::stoi(smask);
    mask     = static_cast<int>(uzMask);
    uzMask   = ~0u << (32 - uzMask);
    /*count network address*/
    uzIpaddr &= uzMask;
    addr.s_addr = htonl(uzIpaddr);
    char buf[INET_ADDRSTRLEN];
    ip = inet_ntop(AF_INET, &addr, buf, sizeof(buf));
}

std::string Ipv4CidrToIp(std::string ip, int mask)
{
    struct in_addr addr;
    uint32_t uzIpaddr, uzMask;
    uzIpaddr = ntohl(inet_addr(ip.c_str()));
    uzMask   = ~0u << (32 - mask);
    /*count network address*/
    uzIpaddr &= uzMask;
    addr.s_addr = htonl(uzIpaddr);
    char buf[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET, &addr, buf, sizeof(buf));
}


FiveTuple::FiveTuple() { this->InitTuple(); }
FiveTuple::~FiveTuple() {}

void FiveTuple::InitTuple()
{
    this->proto_        = 0;
    this->tot_len_      = 0;
    this->src_port_     = 0;
    this->dst_port_     = 0;
    this->src_addr_u32_ = 0;
    this->dst_addr_u32_ = 0;
    this->src_addr_     = "";
    this->dst_addr_     = "";
}

void FiveTuple::PrintData(std::string key, int level)
{
    if(level < g_log_level) return;
    if(this->src_port_ == 53 || this->dst_port_ == 53) return;
    if(this->src_addr_ == "127.0.0.1" || this->dst_addr_ == "127.0.0.1") return;
    LOG_D("key : %s, five tuple -> proto : %d, %s:%d --> %s:%d", key.c_str(), this->proto_, this->src_addr_.c_str(), this->src_port_, this->dst_addr_.c_str(), this->dst_port_);
}

void FiveTuple::ReverseTuple(FiveTuple &tuple)
{
    // 备份当前对象的成员变量
    auto temp_proto      = this->proto_;
    auto temp_tot_len    = this->tot_len_;
    auto temp_src_port   = this->src_port_;
    auto temp_dst_port   = this->dst_port_;
    auto temp_src_u32    = this->src_addr_u32_;
    auto temp_dst_u32    = this->dst_addr_u32_;
    auto temp_src_addr   = this->src_addr_;
    auto temp_dst_addr   = this->dst_addr_;

    // 将当前对象的值赋给传入的 tuple
    tuple.proto_        = temp_proto;
    tuple.tot_len_      = temp_tot_len;
    tuple.src_port_     = temp_dst_port;    // 交换 src_port_ 和 dst_port_
    tuple.dst_port_     = temp_src_port;
    tuple.src_addr_u32_ = temp_dst_u32;     // 交换地址
    tuple.dst_addr_u32_ = temp_src_u32;
    tuple.src_addr_     = temp_dst_addr;
    tuple.dst_addr_     = temp_src_addr;
}

NFQ_RES_INFO::NFQ_RES_INFO() {}
NFQ_RES_INFO::~NFQ_RES_INFO() {}

void NFQ_RES_INFO::Init()
{
    this->pid_       = 0;
    this->input_fd_  = 0;
    this->output_fd_ = 0;
    this->pod_id_    = 0;
    this->poll_fd_   = 0;
    this->input_que_ = nullptr;
    this->output_que_= nullptr;
    this->input_cb_  = nullptr;
    this->output_cb_ = nullptr;
    //nf conntrack
    this->nfct_      = nullptr;
    this->nfct_cb_   = nullptr;
    this->nfct_hd_   = nullptr;
    this->nfct_cb_hd_= nullptr;
}

/*释放资源*/
void NFQ_RES_INFO::FreeResource(int efd)
{
    struct epoll_event ev;
    struct nfq_q_handle *qh = NULL;

    /*close input fd*/
    if(this->input_fd_ > 0)
    {
        ev.data.fd = this->input_fd_;
        epoll_ctl(efd, EPOLL_CTL_DEL, this->input_fd_, &ev);
        close(this->input_fd_);
    }
    /*close output fd*/
    if(this->output_fd_ > 0)
    {
        ev.data.fd = this->output_fd_;
        epoll_ctl(efd, EPOLL_CTL_DEL, this->output_fd_, &ev);
        close(this->output_fd_);
    }
    /*destroy input queue*/
    if(this->input_que_)
    {
        qh = this->input_que_;
        nfq_close(qh->h);
        nfq_destroy_queue(qh);
    }
    /*destroy output queue*/
    if(this->output_que_)
    {
        qh = this->output_que_;
        nfq_close(qh->h);
        nfq_destroy_queue(qh);
    }
    if(this->input_cb_)  delete this->input_cb_;
    if(this->output_cb_) delete this->output_cb_;
    if(this->nfct_)      nfct_destroy(this->nfct_);
    if(this->nfct_cb_)   nfct_destroy(this->nfct_cb_);
    if(this->nfct_hd_)   nfct_close(this->nfct_hd_);
    if(this->nfct_cb_hd_) nfct_close(this->nfct_cb_hd_);
    /*print debug log*/
    LOG_I("free nfqueue resource, pid : %d", this->pid_);
}

RuleDetail::RuleDetail() {}
RuleDetail::~RuleDetail() {}

/*添加端口*/
void RuleDetail::AddPortsCfg(RULE_PORT &port) { this->ports_.push_back(port); }
/*清除端口配置*/
void RuleDetail::ClearPortsCfg() { this->ports_.clear(); }
/*生成用于匹配的策略*/
std::string RuleDetail::CreateRuleKey(int &mask)
{
    string key, ip;
    char buff[128] = {0};
    switch (this->direction_)
    {
        case FlowDir::kIngress:
            Ipv4CidrToIp(this->src_ip_, ip, mask);
            /*create key*/
            sprintf(buff, "%d-%d-%s-%s", this->priority_, this->proto_, ip.c_str(), this->dst_ip_.c_str());
            break;
        default:
            Ipv4CidrToIp(this->dst_ip_, ip, mask);
            /*create key*/
            sprintf(buff, "%d-%d-%s-%s", this->priority_, this->proto_, this->src_ip_.c_str(), ip.c_str());
            break;
    }
    key = buff;
    /*return*/
    return key;
}

/*匹配策略详情*/
bool RuleDetail::MatchRuleDetail(FiveTuple &tuple, FlowDir dir)
{
    int p = 0;
    bool bIsMatch = false;
    uint8_t protocol = tuple.proto_;
    /*处理ICMP协议*/
    if(protocol == IPPROTO_ICMP) protocol = this->proto_;
    /*匹配协议*/
    if(!((this->proto_ == 0) || (protocol == this->proto_))) return false;
    /*匹配ICMP协议*/
    if((this->ports_.size() == 0) || (tuple.proto_ == IPPROTO_ICMP)) bIsMatch = true;
    /*匹配端口*/
    for(p = 0; p < (int)this->ports_.size(); p++)
    {
        if(this->ports_.at(p).end_port_ == 0)
        {
            bIsMatch = true;
            break;
        }
        /*check port rang*/
        if(tuple.dst_port_ > this->ports_.at(p).end_port_) continue;
        /*check min port*/
        if(tuple.dst_port_ < this->ports_.at(p).port_) continue;
        /*set match true*/
        bIsMatch = true;
        break;
    }
    /*判断是否匹配成功*/
    if(!bIsMatch) return false;
    /*过滤DNS*/
    if((tuple.src_port_ == 53) || (tuple.dst_port_ == 53)) return true;
    /*print debug log*/
    LOG_D("flow dir %s, match name : %s, dir : %d, action : %d, priority : %d, proto : %d, ip : %s <--> %s port : %d ~ %d",
        (dir == FlowDir::kIngress) ? "ingress" : "egress", this->policy_key_.c_str(), static_cast<int>(this->direction_), static_cast<int>(this->action_), this->priority_,
        this->proto_, this->src_ip_.c_str(), this->dst_ip_.c_str(), this->ports_.at(p).port_, this->ports_.at(p).end_port_);
    /*return*/
    return true;
}

/*打印策略详情*/
void RuleDetail::PrintRuleDetail(std::string desc)
{
    char buf[128];
    std::string ports = "";
    /*log level*/
    if(g_log_level < 2) return;
    /*format port*/
    for(int i = 0; i < (int)this->ports_.size(); i++)
    {
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "%d ~ %d", this->ports_.at(i).port_, this->ports_.at(i).end_port_);
        ports += buf;
        if((i + 1) < (int)this->ports_.size()) ports += ",";
    }
    LOG_V("%s detail -> proto : %d, priority : %d, dir : %d, action : %d, name : %s, addr : %s -> %s, ports : %s",
        desc.c_str(), this->proto_, this->priority_, static_cast<int>(this->direction_), static_cast<int>(this->action_), this->policy_key_.c_str(), this->src_ip_.c_str(), this->dst_ip_.c_str(), ports.c_str());
}

RuleGroup::RuleGroup() { this->rules_.clear(); }
RuleGroup::~RuleGroup() {}

/*增加策略详情信息*/
bool RuleGroup::AddRuleDetail(RuleDetail rule, RULE_PORT &stPort)
{
    /*clear ports*/
    rule.ClearPortsCfg();
    /*查询策略是否已经存在*/
    auto it = this->rules_.find(rule.policy_key_);
    if(it == this->rules_.end())
    {
        /*print debug log*/
        LOG_D("create policy name : %s, action : %d, mutil port : %d ~ %d.", rule.policy_key_.c_str(), rule.action_, stPort.port_, stPort.end_port_);
        /*save policy port*/
        rule.AddPortsCfg(stPort);
        /*make shared*/
        auto detail = std::make_shared<RuleDetail>(rule);
        /*新增数据*/
        this->rules_[rule.policy_key_] = detail;
        /*return*/
        return true;
    }
    /*value*/
    auto detail = it->second;
    /*add port config*/
    detail->AddPortsCfg(stPort);
    /*print debug log*/
    LOG_D("add policy name : %s, dir : %d, action : %d, mutil port : %d ~ %d, port num : %d", rule.policy_key_.c_str(), rule.direction_, rule.action_, stPort.port_, stPort.end_port_, (int)detail->ports_.size());
    /*print debug log*/
    detail->PrintRuleDetail("add");
    /*return*/
    return true;
}

/*删除匹配策略*/
void RuleGroup::DeleteRule(std::string policyName)
{
    auto it = this->rules_.find(policyName);
    if(it == this->rules_.end()) return;
    /*删除策略*/
    auto detail = it->second;
    /*打印需要删除的策略详情*/
    detail->PrintRuleDetail("delete");
    /*删除该策略*/
    this->rules_.erase(it);
}

/*匹配策略*/
bool RuleGroup::MatchRule(FiveTuple &tuple, RuleDetail &detail, FlowDir dir)
{
    if(this->rules_.size() == 0) return false;
    /*遍历规则列表*/
    for(auto it = this->rules_.begin(); it != this->rules_.end(); it++)
    {
        detail.AssignFrom(it->second);
        auto ret = detail.MatchRuleDetail(tuple, dir);
        if(ret) return true;
    }

    /*return*/
    return false;
}

/*获取规则数*/
size_t RuleGroup::GetRulesSize() { return this->rules_.size(); }


RuleChain::RuleChain() { this->chain_.clear(); }
RuleChain::~RuleChain() {}

/*获取规则表数据量*/
size_t RuleChain::RuleSize() { return this->chain_.size(); }

/*set dir*/
void RuleChain::SetRuleDir(FlowDir direction) { this->dir_ = direction;}

/*清空规则*/
void RuleChain::RuleChainClear() { this->chain_.clear(); }

/*匹配规则*/
bool RuleChain::MatchRuleGroup(std::string &key, FiveTuple &tuple, RuleDetail &detail)
{
    /*match rule*/
    auto it = this->chain_.find(key);
    if(it == this->chain_.end()) return false;
    /*print debug log*/
    tuple.PrintData(key);
    /*match rule*/
    return it->second->MatchRule(tuple, detail, this->dir_);
}

/*生成匹配规则,并保持到链上*/
int RuleChain::AddRuleToChain(std::string key, RuleDetail &policy, RULE_PORT &stPort)
{
    /*check key*/
    auto it = this->chain_.find(key);
    if(it == this->chain_.end())
    {
        auto rg = std::make_shared<RuleGroup>();
        if(rg == nullptr) RETURN_ERROR(2, "new memory failed by rule group.");
        /*print debug log*/
        LOG_D("create group to chain, policy name : %s, rule key : %s", policy.policy_key_.c_str(), key.c_str());
        /*add rule*/
        auto ok = rg->AddRuleDetail(policy, stPort);
        if(!ok) RETURN_ERROR(5, "add policy detail failed.");
        /*add rule group*/
        this->chain_[key] = rg;
    }
    else
    {
        auto rg = it->second;
        if(rg == nullptr) RETURN_ERROR(8, "rule group is null, key : %s", key.c_str());
        /*add rule*/
        auto ok = rg->AddRuleDetail(policy, stPort);
        if(!ok) RETURN_ERROR(5, "update policy detail failed.");
        /*print debug log*/
        LOG_D("add group to chain, policy name : %s, rule key : %s, group size : %d", policy.policy_key_.c_str(), key.c_str(), (int)rg->GetRulesSize());
    }
    /*return*/
    return 0;
}

/*从链上删除规则*/
void RuleChain::DeleteRuleFromChain(std::string pname, std::string ruleKey)
{
    auto it = this->chain_.find(ruleKey);
    if(it == this->chain_.end()) return;
    /*获取规则组*/
    auto group = it->second;
    if (group == nullptr) return;
    /*删除规则*/
    group->DeleteRule(pname);
    /*重新将规则添加到链上*/
    if(group->GetRulesSize() == 0)
    {
        /*打印调试日志*/
        LOG_D("delete group, policy name : %s, rule key : %s, dir : %d", pname.c_str(), ruleKey.c_str(), static_cast<int>(this->dir_));
        /*从新将规则添加到链上*/
        this->chain_.erase(it);
    }
}


PolicyTree::PolicyTree() { this->Clear(); }
PolicyTree::~PolicyTree() {}


/*get size*/
int PolicyTree::GetTreeSize() { return (int)this->tree_.size(); }

/*clear*/
int PolicyTree::Clear()
{
    for(auto it = this->tree_.begin(); it != this->tree_.end(); it++)
    {
        auto value = it->second;
        if(value == nullptr) continue;
        delete value;
    }

    this->tree_.clear();
    this->RuleChainClear();
    return 0;
}

/*delete policy*/
int PolicyTree::DeletePolicyFromTree(std::string &name)
{
    /*find*/
    auto pit = this->tree_.find(name);
    if(pit == this->tree_.end()) RETURN_INFO(0, "can not find this key : [%s], dir : %d", name.c_str(), static_cast<int>(this->dir_));
    /*remove policy*/
    this->tree_.erase(pit);
    /*get value*/
    auto rules = pit->second;
    if(rules == nullptr) RETURN_WARN(0, "policy information is null, name : %s, dir : %d", name.c_str(), static_cast<int>(this->dir_));
    /*print debug log*/
    LOG_D("policy name : %s, rule numbers : %lu, dir : %d.", name.c_str(), rules->size(), static_cast<int>(this->dir_));
    /*delete rule*/
    for(auto it = rules->begin(); it != rules->end(); it++)
    {
        auto key = it->first;
        auto value = it->second;
        /*print debug log*/
        LOG_D("delete policy, flow dir : %s, key : %s.", (value == FlowDir::kIngress) ? "ingress" : "egress", key.c_str());
        /*删除策略下的规则*/
        this->DeleteRuleFromChain(name, key);
    }
    /*clear net policy*/
    rules->clear();
    delete rules;
    /*clear all*/
    if(this->tree_.size() == 0) return this->Clear();
    /*print debug log*/
    LOG_D("delete net policy name : %s, dir : %d", name.c_str(), static_cast<int>(this->dir_));
    /*return*/
    return 0;
}

/*将规则添加到链上*/
int PolicyTree::AddPolicyToChain(RuleDetail &policy, RULE_PORT &stPort, int &zMask)
{
    std::unordered_map<std::string, FlowDir>* ruleMap;
    /*query policy*/
    auto it = this->tree_.find(policy.policy_key_);
    if(it == this->tree_.end())
    {
        ruleMap = new std::unordered_map<std::string, FlowDir>;
        if(ruleMap == nullptr) RETURN_ERROR(2, "new memory failed when add policy.");
        /*insert data*/
        auto ret = this->tree_.insert(std::make_pair(policy.policy_key_, ruleMap));
        if(!ret.second) RETURN_ERROR(3, "insert policy name to map failed when add policy.");
        /*print debug log*/
        LOG_D("create new policy : [%s]", policy.policy_key_.c_str());
    }
    else
    {
        ruleMap = it->second;
    }
    /*check rule map*/
    if(ruleMap == nullptr) RETURN_ERROR(12, "rule map is nil.");
    /*create policy rule key*/
    auto key = policy.CreateRuleKey(zMask);
    /*写入匹配规则*/
    auto ret = this->AddRuleToChain(key, policy, stPort);
    if(ret != 0) return ret;
    /*insert key*/
    ruleMap->insert(std::make_pair(key, policy.direction_));
    /*return*/
    return 0;
}

PolicyRule::PolicyRule() { this->ClearCfg(); }
PolicyRule::~PolicyRule() {}

/*清除优先级和子网掩码*/
int PolicyRule::ClearCfg()
{
    this->mask_cidr_.clear();
    this->priority_.clear();
    this->mask_cidr_.insert(32);
    /*init map*/
    this->input_tree_.Clear();
    this->output_tree_.Clear();
    /*set rule direction*/
    this->input_tree_.SetRuleDir(FlowDir::kIngress);
    this->output_tree_.SetRuleDir(FlowDir::kEgress);
    return 0;
}

/*通过五元组生成规则*/
void PolicyRule::CreateRuleKeyByTuple(FiveTuple &tuple, FlowDir dir, std::vector<std::string> &value)
{
    char buff[128] = {0};
    char data[128] = {0};
    std::vector<std::string> srcaddr, dstaddr;
    /*init*/
    value.clear();
    /*create key*/
    for(auto it = this->priority_.begin(); it != this->priority_.end(); ++it)
    {
        for(auto iter = this->mask_cidr_.begin(); iter != this->mask_cidr_.end(); ++iter)
        {
            /*clear data*/
            dstaddr.clear();
            srcaddr.clear();
            switch (dir)
            {
                case FlowDir::kIngress:
                    srcaddr.push_back("0.0.0.0");
                    srcaddr.push_back(Ipv4CidrToIp(tuple.src_addr_, *iter));
                    dstaddr.push_back(tuple.dst_addr_);
                    break;
                default:
                    srcaddr.push_back(tuple.src_addr_);
                    dstaddr.push_back("0.0.0.0");
                    dstaddr.push_back(Ipv4CidrToIp(tuple.dst_addr_, *iter));
                    break;
            }
            //list priority
            for(size_t i = 0; i < srcaddr.size(); i++)
            {
                for(size_t j = 0; j < dstaddr.size(); j++)
                {
                    memset(buff, 0, sizeof(buff));
                    sprintf(buff, "%d-%d-%s-%s", *it, tuple.proto_, srcaddr.at(i).c_str(), dstaddr.at(j).c_str());
                    /*save key*/
                    value.push_back(buff);
                    /*print debug log*/
                    //tuple.PrintData(buff, 2);
                    /*all protocol*/
                    memset(data, 0, sizeof(data));
                    sprintf(data, "%d-0-%s-%s", *it, srcaddr.at(i).c_str(), dstaddr.at(j).c_str());
                    /*save key*/
                    value.push_back(data);
                    /*print debug log*/
                    //tuple.PrintData(data, 2);
                }
            }
        }
    }
    /*print debug log*/
    LOG_T("create rule key num : %lu, priority size : %lu, mark size : %lu.", value.size(), this->priority_.size(), this->mask_cidr_.size());
}

/*获取策略map*/
PolicyTree *PolicyRule::GetPolicyTree(FlowDir dir)
{
    return (dir == FlowDir::kIngress) ? &this->input_tree_ : &this->output_tree_;
}

/*打印日志*/
void PolicyRule::PrintPolicyLog()
{
    LOG_D("NetInput : %d, NetOutput : %d, input tree : %d, output tree : %d", (int)this->input_tree_.RuleSize(), (int)this->output_tree_.RuleSize(), this->input_tree_.GetTreeSize(), this->output_tree_.GetTreeSize());
}

/*添加优先级和子网掩码*/
void PolicyRule::AddMaskAndPriority(int priority, int mask)
{
    /*save priority*/
    this->priority_.insert(priority);
    /*save cidr*/
    if((mask > 0) && (mask <= 32)) this->mask_cidr_.insert(mask);
}

/*将规则添加到链上*/
int PolicyRule::AddPolicyToTree(RuleDetail &policy, RULE_PORT &stPort)
{
    int zMask = 0;
    /*get policy tree*/
    auto tree = this->GetPolicyTree(policy.direction_);
    /*return*/
    auto ret = tree->AddPolicyToChain(policy, stPort, zMask);
    if(ret != 0) RETURN_ERROR(ret, "add policy to chain failed.");
    /*save priority*/
    this->AddMaskAndPriority(policy.priority_, zMask);
    /*return*/
    return 0;
}

/*删除指定策略*/
int PolicyRule::DeletePolicy(FlowDir dir, std::string name)
{
   auto tree = this->GetPolicyTree(dir);
    /*return*/
    return tree->DeletePolicyFromTree(name);
}

/*获取所有规则配置*/
cJSON *PolicyRule::GetAllConfig(std::string name)
{
    NFQ_RES_INFO *res;
    cJSON *containers = nullptr, *tcp = nullptr, *r, *item;
    cJSON *config = nullptr, *inrule = nullptr, *outrule = nullptr;

    tcp = cJSON_CreateObject();
    config = cJSON_CreateObject();
    inrule = cJSON_CreateArray();
    outrule = cJSON_CreateArray();
    containers = cJSON_CreateArray();
    auto stat = g_connection_manager.stat();
    if(!config || !outrule || !inrule || !tcp || !containers) GOTO_ERROR(err, "create json object failed.");

    for(auto it = this->input_tree_.chain_.begin(); it != this->input_tree_.chain_.end(); it++)
    {
        auto rule = it->second;
        if(rule == nullptr) continue;

        for(auto rd = rule->rules_.begin(); rd != rule->rules_.end(); rd++)
        {
            if(!name.empty() && name != rd->second->policy_key_) continue;

            r = cJSON_CreateObject();
            if(!r) GOTO_ERROR(err, "create json object failed.");

            cJSON_AddStringToObject(r, "policy_name", rd->second->policy_key_.c_str());
            cJSON_AddNumberToObject(r, "priority", rd->second->priority_);
            cJSON_AddStringToObject(r, "direction", utility::directionString(rd->second->direction_).data());
            cJSON_AddStringToObject(r, "action", utility::actionString(rd->second->action_).data());
            cJSON_AddStringToObject(r, "protocol", utility::protocolString(rd->second->proto_).data());
            cJSON_AddNumberToObject(r, "protocol_int", rd->second->proto_);
            cJSON_AddStringToObject(r, "from_address", rd->second->src_ip_.c_str());
            cJSON_AddStringToObject(r, "to_address", rd->second->dst_ip_.c_str());
            cJSON_AddItemToArray(inrule, r);
        }
    }
    cJSON_AddItemToObject(config, "inbound_rules", inrule);

    for (auto it = this->output_tree_.chain_.begin(); it != this->output_tree_.chain_.end(); it++)
    {
        auto rule = it->second;
        if(rule == nullptr) continue;

        for(auto rd = rule->rules_.begin(); rd != rule->rules_.end(); rd++)
        {
            if(!name.empty() && name != rd->second->policy_key_) continue;

            r = cJSON_CreateObject();
            if(!r) GOTO_ERROR(err, "create json object failed.");

            cJSON_AddStringToObject(r, "policy_name", rd->second->policy_key_.c_str());
            cJSON_AddNumberToObject(r, "priority", rd->second->priority_);
            cJSON_AddStringToObject(r, "direction", utility::directionString(rd->second->direction_).data());
            cJSON_AddStringToObject(r, "action", utility::actionString(rd->second->action_).data());
            cJSON_AddStringToObject(r, "protocol", utility::protocolString(rd->second->proto_).data());
            cJSON_AddNumberToObject(r, "protocol_int", rd->second->proto_);
            cJSON_AddStringToObject(r, "from_address", rd->second->src_ip_.c_str());
            cJSON_AddStringToObject(r, "to_address", rd->second->dst_ip_.c_str());
            cJSON_AddItemToArray(outrule, r);
        }
    }
    cJSON_AddItemToObject(config, "outbound_rules", outrule);

    if(!name.empty()) return config;

    for (auto it = this->res_data_.begin(); it != this->res_data_.end(); it++)
    {
        res = it->second.get();
        if(res == nullptr) continue;

        item = cJSON_CreateObject();
        if(!item) GOTO_ERROR(err, "create json object failed.");
        cJSON_AddNumberToObject(item, "pid", res->pid_);
        cJSON_AddNumberToObject(item, "pod_id", res->pod_id_);
        cJSON_AddItemToArray(containers,  item);
    }
    cJSON_AddItemToObject(config, "containers",containers);

    cJSON_AddNumberToObject(tcp, "tcp_connection", stat.tcp_conn_);
    cJSON_AddItemToObject(config, "tcp",tcp);

    return config;

err:
    if(tcp) cJSON_Delete(tcp);
    if(config) cJSON_Delete(config);
    if(inrule) cJSON_Delete(inrule);
    if(outrule) cJSON_Delete(outrule);
    if(containers) cJSON_Delete(containers);
    return nullptr;
}


NfQueData::NfQueData() { this->res_data_.clear(); }
NfQueData::~NfQueData() {}

/*create nfqueue resource*/
int NfQueData::NewNfQueRes(uint64_t pid, std::unique_ptr<NFQ_RES_INFO> res)
{
    auto ret = this->res_data_.insert(make_pair(pid, std::move(res)));
    if(!ret.second) RETURN_ERROR(-2, "save nfq resource data failed.");
    /*return*/
    return 0;
}

/*delete nfqueue resource*/
int NfQueData::DeleteNfQueRes(int efd, uint64_t pid)
{
    auto it = this->res_data_.find(pid);
    if(it == this->res_data_.end()) return 0;
    /*free resource before erasing*/
    if(it->second != nullptr)
        it->second->FreeResource(efd);
    /*erase key — unique_ptr destructor handles delete*/
    this->res_data_.erase(it);
    /*return*/
    return 0;
}

/*get nfqueue resource*/
NFQ_RES_INFO *NfQueData::GetNfqRes(uint64_t pid)
{
    auto it = this->res_data_.find(pid);
    if(it == this->res_data_.end()) return nullptr;
    /*return*/
    return it->second.get();
}

/*clear nfqueue resource*/
void NfQueData::ClearNfQueResource(int efd)
{
    int ret;
    for (auto& [pid, res] : this->res_data_)
    {
        if(res == nullptr) continue;
        /*set network namespace*/
        ret = SetNs(res->pid_, const_cast<char*>(kBasePath.data()));
        if (ret != 0) continue;
        /*print debug log*/
        LOG_D("destroy nfqueue, pid : %d.", res->pid_);
        /*clear iptables rule*/
        ClearIptabelsRule();
        /*free nfque resource — unique_ptr handles delete*/
        res->FreeResource(efd);
    }
    /*clear map*/
    this->res_data_.clear();
}
