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
    std::string AttackIp;//攻击IP
    std::string AttackedApp;//受攻击应用
    std::string AttackLoad;//攻击载荷
    std::string AttackedUrl;//受攻击地址
    std::string ReqPkg;//请求报文
    std::string RspPkg;//响应报文
    std::string type;
    std::string action;//判决
    std::string RuleName;
    std::string ReqMethod;
    std::string RspContentType;
    std::int64_t AttackTime;//攻击时间
    std::int64_t RuleId;//匹配到的规则ID
};

struct Rule {
    std::int64_t id;
    std::int64_t level;
    std::string type;
    std::string name;
    std::string description;
    std::string expr;
    std::string mode;
    std::vector<std::string> keys;
    std::vector<std::string> matchFunc;
};

struct BWList {
    uint64_t id;
    uint8_t action;
    std::string name;
    std::string expr;
    std::string mode;
    std::string desc;
    std::string oprexpr;/*运算表达式*/
    std::vector<uint8_t> rtype;
    std::vector<std::string> rdata;
};

class Rules{

private:
    uint8_t defAction;
    // app id
    std::string app_name;
    std::string app_uri;
    std::vector<Rule> HeaderRules; // rules数组
    std::vector<Rule> BodyRules; // rules数组
    std::unordered_map<std::string, uint8_t> ignore;//需要排除的类型
    std::vector<std::string> detectHeader;//检测包头配置
    std::vector<std::string> domain;//检测包头配置
    std::vector<BWList> WhiteList;//白名单
    std::vector<BWList> BlackList;//黑名单
    std::vector<BWList> ForceWhiteList;//强白名单

public:
    uint64_t app_id;
    std::string cluster_key;// cluster key
    std::string pod_namespace;// namespace
    std::string res_kind;// kind
    std::string res_name;// resource name
    std::string app_mode;// app mode

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
    void AddAppName(std::string name) { app_name = name; }
    /*add app name*/
    void AddAppUri(std::string uri) { app_uri = uri; }
    /*get app name*/
    std::string GetAppName() { return app_name; }
    /*match mode function*/
    int MatchModeFunc(std::string str);
    /*get header rule*/
    std::vector<Rule> GetHeaderRule() { return HeaderRules; }
    /*get body rule*/
    std::vector<Rule> GetBodyRule() { return BodyRules; }
    /*get detect headers*/
    std::vector<std::string> GetDetectHeaders() { return detectHeader; }
    /*get default action*/
    uint8_t GetDefAction() { return defAction; }
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
    CacheQueue() : maxSize(200) {}

    int push(const T& item) {
        std::unique_lock<std::mutex> lock(mutex);

        if((int)queue.size() >= maxSize) return 1;
        /*push back*/
        queue.push_back(item);
        /*return*/
        return 0;
    }

    T pop() {
        std::unique_lock<std::mutex> lock(mutex);
        
        if(queue.empty()) return T();
        /*get front data*/
        T item = queue.front();
        /*pop data*/
        queue.pop_front();
        /*return*/
        return item;
    }

    bool isEmpty() const {
        return queue.empty();
    }

    size_t Size() const {
        return queue.size();
    }

private:
    std::deque<T> queue;
    std::mutex mutex;
    int maxSize;
};

extern std::string urlDecode(const std::string& url);
extern std::string substr(std::string fs, std::string &str);
extern std::string iterator(std::string);
extern std::string SaveHeadersInfo(AttackedLog &r, std::unordered_map<std::string, std::string> &pairs);
extern std::string FormartRspHeaders(std::unordered_map<std::string, std::string> &pairs);
extern int64_t GetNowTime();
extern bool isIPAddress(const std::string& str);
extern std::vector<std::string> split(std::string str, std::string pattern);