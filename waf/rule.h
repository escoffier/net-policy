#pragma once

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <condition_variable>


extern std::vector<std::string> MatchFunc;

typedef enum {
    ACTION_BYPASS  = 0,
    ATCION_ALERT   = 1,
    ATCTION_DROP   = 2,
    ATCION_MAX
} RULE_ATCION;

typedef enum {
    AUTO_RULE_IP_EQUAL    = 0,
    AUTO_RULE_IP_CIDR     = 1,
    AUTO_RULE_PATH_EQUAL  = 2,
    AUTO_RULE_PATH_REG    = 3,
    AUTO_RULE_MAX
} AUTO_RULE_DSC;

typedef enum {
    MATCH_REQ_HEADER = 0,
    MATCH_REQ_BODY   = 1,
    MATCH_REQ_MAX
} MATCH_REQ_POS;

struct AttackedLog {
    std::string attack_ip_;//攻击IP
    std::string attacked_app_;//受攻击应用
    std::string attack_load_;//攻击载荷
    std::string attacked_url_;//受攻击地址
    std::string req_pkg_;//请求报文
    std::string rsp_pkg_;//响应报文
    std::string type_;
    std::string action_;//判决
    std::string rule_name_;
    std::string req_method_;
    std::string rsp_content_type_;
    std::int64_t attack_time_;//攻击时间
    std::int64_t rule_id_;//匹配到的规则ID
};

struct Rule {
    std::int64_t id_;
    std::int64_t level_;
    std::string type_;
    std::string name_;
    std::string description_;
    std::string expr_;
    std::string mode_;
    std::vector<std::string> keys_;
    std::vector<std::string> match_func_;
};

struct BWList {
    uint64_t id_;
    uint8_t action_;
    std::string name_;
    std::string expr_;
    std::string mode_;
    std::string desc_;
    std::string oprexpr_;/*运算表达式*/
    std::vector<uint8_t> rtype_;
    std::vector<std::string> rdata_;
};

class Rules{

private:
    uint8_t def_action_;
    // app id
    std::string app_name_;
    std::string app_uri_;
    std::vector<Rule> header_rules_; // rules数组
    std::vector<Rule> body_rules_; // rules数组
    std::unordered_map<std::string, uint8_t> ignore_;//需要排除的类型
    std::vector<std::string> detect_header_;//检测包头配置
    std::vector<std::string> domain_;//检测包头配置
    std::vector<BWList> white_list_;//白名单
    std::vector<BWList> black_list_;//黑名单
    std::vector<BWList> force_white_list_;//强白名单

public:
    uint64_t app_id_;
    std::string cluster_key_;// cluster key
    std::string pod_namespace_;// namespace
    std::string res_kind_;// kind
    std::string res_name_;// resource name
    std::string app_mode_;// app mode

public:
    // 构造函数
    Rules();
    ~Rules();

    //init
    void InitRule();
    // 添加规则到rules数组
    void AddRule(Rule rule);
    /*add ignore type*/
    void AddIgnoreType(std::string &);
    /*add detect header*/
    void AddDetectHeader(std::string &);
    /*add force white list*/
    void AddForceWhiteList(BWList &bw);
    /*add black list and white list*/
    void AddBlackWhiteList(BWList &);
    /*add domain*/
    void AddDomain(std::string &);
    /*add default action*/
    void AddDefAction(std::string);
    /*add app name*/
    void AddAppName(std::string name) { app_name_ = name; }
    /*add app name*/
    void AddAppUri(std::string uri) { app_uri_ = uri; }
    /*get app name*/
    std::string GetAppName() { return app_name_; }
    /*match mode function*/
    int MatchModeFunc(std::string str);
    /*get header rule*/
    std::vector<Rule> GetHeaderRule() { return header_rules_; }
    /*get body rule*/
    std::vector<Rule> GetBodyRule() { return body_rules_; }
    /*get detect headers*/
    std::vector<std::string> GetDetectHeaders() { return detect_header_; }
    /*get default action*/
    uint8_t GetDefAction() { return def_action_; }
    /*pcre2 match*/
    bool Pcre2Regex(std::uint64_t id, std::string &expr, std::string &src, std::string &dst);
    /*match ignore type*/
    bool MatchIgnoreType(std::string &src);
    /*match ignore type*/
    bool MatchDomain(std::string &src);
    /*match force white list*/
    bool MatchForceWhiteList(std::vector<std::string> &ips, std::string &path, BWList &policy);
    /*match ip address*/
    bool MatchBlackWhiteList(std::vector<std::string> &ips, std::string &path, BWList &policy);
};

template <typename T>
class CacheQueue {
public:
    CacheQueue() : max_size_(200) {}

    int push(const T& item) {
        std::unique_lock<std::mutex> lock(mutex_);

        if((int)queue_.size() >= max_size_) return 1;
        /*push back*/
        queue_.push_back(item);
        /*return*/
        return 0;
    }

    T pop() {
        std::unique_lock<std::mutex> lock(mutex_);

        if(queue_.empty()) return T();
        /*get front data*/
        T item = queue_.front();
        /*pop data*/
        queue_.pop_front();
        /*return*/
        return item;
    }

    bool isEmpty() const {
        return queue_.empty();
    }

    size_t Size() const {
        return queue_.size();
    }

private:
    std::deque<T> queue_;
    std::mutex mutex_;
    int max_size_;
};

extern std::string urlDecode(const std::string& url);
extern std::string substr(std::string fs, std::string &str);
extern std::string iterator(std::string);
extern std::string SaveHeadersInfo(AttackedLog &r, std::unordered_map<std::string, std::string> &pairs);
extern std::string FormartRspHeaders(std::unordered_map<std::string, std::string> &pairs);
extern int64_t GetNowTime();
extern bool isIPAddress(const std::string& str);
extern std::vector<std::string> split(std::string str, std::string pattern);