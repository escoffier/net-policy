#define PCRE2_CODE_UNIT_WIDTH 8
#include <regex>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <iostream>
#include <chrono>
#include <stack>
#include <pcre2.h>
#include "rule.h"
#include "net-policy.h"
#include "log.h"

std::vector<std::string> MatchFunc = {"urlDecode", "substr", "iterator"};

/*
std::string GetNowTime()
{
    std::ostringstream oss;
    // 获取当前时间
    std::time_t currentTime = std::time(nullptr);
    std::tm* localTime = std::localtime(&currentTime);
    // 格式化时间
    oss << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
    //return
    return oss.str();
}
*/

std::string removeSpeStr(std::string src, std::string sub) {
	if(src.empty()) return src;
    size_t start = src.find_first_not_of(sub);
    size_t end = src.find_last_not_of(sub);
    return src.substr(start, end - start + 1);
}

std::string replaceString(std::string src, std::string target, std::string dst)
{
    size_t pos = src.find(target);
    // 如果找到目标子串，则进行替换
    if (pos != std::string::npos) {
        src.replace(pos, target.length(), dst);
    }
    return src;
}

std::string delSpace(std::string str)
{
    str.erase(std::remove(str.begin(), str.end(), ' '), str.end());
    return str;
}

std::string getRuleVaule(std::string str)
{
	std::string value = str;
	// 查找第一个引号的位置
    size_t firstQuotePos = str.find('\"');
    if (firstQuotePos == std::string::npos) return value;
	// 查找最后一个引号的位置
	size_t lastQuotePos = str.rfind('\"');
	if (lastQuotePos != std::string::npos && lastQuotePos > firstQuotePos)
	{
		// 提取引号之间的内容
		value = str.substr(firstQuotePos + 1, lastQuotePos - firstQuotePos - 1);
	}
	return value;
}

/*eval*/
bool eval(const std::string& expression) {
    char op;
    std::stack<char> operators;
    std::stack<bool> operands;

    for (size_t i = 0; i < expression.length(); i++)
    {
        char c = expression[i];

        if (c == ' ') continue;

        if (c == '(')
        {
            operators.push(c);
        }
        else if (c == ')')
        {
            while (!operators.empty() && operators.top() != '(')
            {
                op = operators.top();
                operators.pop();

                bool op2 = operands.top();
                operands.pop();

                bool op1 = operands.top();
                operands.pop();

                bool result;
                if (op == '&')
                    result = op1 && op2;
                else if (op == '|')
                    result = op1 || op2;

                operands.push(result);
            }

            if (!operators.empty()) operators.pop();
        }
        else if (c == '&' && i + 1 < expression.length() && expression[i + 1] == '&')
        {
            i++;
            while (!operators.empty() && operators.top() != '(' && operators.top() != '|')
            {
                operators.pop();

                bool op2 = operands.top();
                operands.pop();

                bool op1 = operands.top();
                operands.pop();

                bool result = op1 && op2;

                operands.push(result);
            }

            operators.push('&');
        }
        else if (c == '|' && i + 1 < expression.length() && expression[i + 1] == '|')
        {
            i++;
            while (!operators.empty() && operators.top() != '(')
            {
                operators.pop();

                bool op2 = operands.top();
                operands.pop();

                bool op1 = operands.top();
                operands.pop();

                bool result = op1 || op2;

                operands.push(result);
            }

            operators.push('|');
        }
        else if (c == 't' && i + 3 < expression.length() && expression.substr(i, 4) == "true")
        {
            operands.push(true);
            i += 3;
        }
        else if (c == 'f' && i + 4 < expression.length() && expression.substr(i, 5) == "false")
        {
            operands.push(false);
            i += 4;
        }
    }

    while (!operators.empty())
    {
        op = operators.top();
        operators.pop();

        bool op2 = operands.top();
        operands.pop();

        bool op1 = operands.top();
        operands.pop();

        bool result;
        if (op == '&')
            result = op1 && op2;
        else if (op == '|')
            result = op1 || op2;

        operands.push(result);
    }

    return operands.top();
}

int CountSubstr(const std::string& str, const std::string subStr)
{
    int count = 0;
    size_t pos = 0;
    while ((pos = str.find(subStr, pos)) != std::string::npos)
    {
        count++;
        pos += subStr.length();
    }
    /*return*/
    return count;
}

int CountRuleTagNum(std::string str)
{
    int count = 0;
    std::regex ip("\\(\\s*ip\\s*==");
    std::regex path("\\(\\s*path\\s*==");
    std::sregex_iterator it(str.begin(), str.end(), ip);
    std::sregex_iterator itp(str.begin(), str.end(), path);
    std::sregex_iterator end;
    /*count (ip*/
    for (; it != end; ++it) {
        count++;
    }
    /*count (path*/
    for (; itp != end; ++itp) {
        count++;
    }
    /*return*/
    return count;
}

std::string CountRuleTagNumWithDelSpace(std::string str)
{
    std::string result = str;
    std::regex ebip("\\s*\\(\\s*ip\\s*==");
    std::regex ebpath("\\s*\\(\\s*path\\s*==");
    std::regex eip("\\s*ip\\s*==");
    std::regex epath("\\s*path\\s*==");
    std::regex bip("\\s*\\(\\s*ip\\s*CIDR");
    std::regex bpath("\\s*\\(\\s*path\\s*matches");
    std::regex ip("\\s*ip\\s*CIDR");
    std::regex path("\\s*path\\s*matches");
    /*replace string*/
    result = std::regex_replace(result, ebip, "(ip ==");
    result = std::regex_replace(result, eip, "ip ==");
    result = std::regex_replace(result, ebpath, "(path ==");
    result = std::regex_replace(result, epath, "path ==");
    result = std::regex_replace(result, bip, "(ip CIDR");
    result = std::regex_replace(result, ip, "ip CIDR");
    result = std::regex_replace(result, bpath, "(path matches");
    result = std::regex_replace(result, path, "path matches");
    /*return*/
    return result;
}

int64_t GetNowTime()
{
    // 获取当前时间的时间点
    auto now = std::chrono::system_clock::now();
    // 将时间点转换为毫秒级时间戳
    return std::chrono::time_point_cast<std::chrono::milliseconds>(now).time_since_epoch().count();
}

bool isIPAddress(const std::string& str)
{
    std::regex pattern("^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
                      "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
                      "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
                      "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
    return std::regex_match(str, pattern);
}

std::string calculateNetworkAddress(std::string ipAddress, int subnetMask) {
    // 将IP地址字符串拆分为四个部分
    std::stringstream ss(ipAddress);
    std::string segment;
    int octets[4] = {0};
    int i = 0;
    while (std::getline(ss, segment, '.')) {
        octets[i++] = std::stoi(segment);
    }
    
    // 计算网络地址
    uint32_t ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    uint32_t subnetMaskBits = (0xFFFFFFFFU << (32 - subnetMask));
    uint32_t networkAddress = ip & subnetMaskBits;
    
    // 将网络地址转换回字符串形式
    std::stringstream networkAddressSS;
    networkAddressSS << ((networkAddress >> 24) & 0xFF) << "." 
                     << ((networkAddress >> 16) & 0xFF) << "." 
                     << ((networkAddress >> 8) & 0xFF) << "." 
                     << (networkAddress & 0xFF);
    
    return networkAddressSS.str();
}

std::string ipv4CidrToIp(std::string cidr, int &mask)
{
    size_t index;
    std::string sip, smask;
    smask = "32";
    sip = cidr;
    index = cidr.find("/");
    if(index != std::string::npos)
    {
        sip = cidr.substr(0, index);
        smask = cidr.substr(index + 1);
    }
    mask = atoi(smask.c_str());
    return calculateNetworkAddress(sip, mask);   
}

std::string SaveHeadersInfo(AttackedLog &r, std::unordered_map<std::string, std::string> &pairs)
{
    std::string uri, method, scheme, authority, path, other, url;
    //print debug log
    LOG_D("headers : %d", (int)pairs.size());
    /*list request header info*/
    for (auto &p : pairs)
    {
        //print debug log
        LOG_D("%s -> %s", std::string(p.first).c_str(), std::string(p.second).c_str());
        if(p.first == ":method") {
            method = p.second;
        } else if(p.first == ":scheme") {
            scheme = p.second;
        } else if(p.first == ":authority") {
            authority = p.second;
        } else if(p.first == ":host") {
            authority = p.second;
        } else if(p.first == ":path") {
            path = p.second;
        } else {
            other = other + "\r\n" + std::string(p.first) + ": " + std::string(p.second);
        }
    }
    if(scheme.empty()) scheme = "http";
    /*uri*/
    uri = method + " " + path + " " + scheme + "/1.1";
    r.req_pkg_ = uri + other + "\r\n";
    /*url*/
    auto pos = path.find("?");
    if(pos != std::string::npos) {
        path = path.substr(0, pos);
    }
    url = scheme + "://" + authority;// + path;
    /*return*/
    return url;
}

std::string FormartRspHeaders(std::unordered_map<std::string, std::string> &pairs)
{
    std::string uri, method, status, scheme, authority, path, other, url;
    //print debug log
    LOG_D("response headers: %d", (int)pairs.size());
    /*list request header info*/
    for (auto &p : pairs)
    {
        //print debug log
        //LOG_D("%s -> %s", std::string(p.first).c_str(), std::string(p.second).c_str());
        if(p.first == ":method") {
            method = p.second;
        } else if(p.first == ":scheme") {
            scheme = p.second;
        } else if(p.first == ":authority") {
            authority = p.second;
        } else if(p.first == ":host") {
            authority = p.second;
        } else if(p.first == ":path") {
            path = p.second;
        } else if(p.first == ":status") {
            status = p.second;
        } else {
            other = other + "\r\n" + std::string(p.first) + ": " + std::string(p.second);
        }
    }
    /*uri*/
    uri = "HTTP " + status;
    url = uri + other + "\r\n\r\n";
    /*return*/
    return url;
}

std::vector<size_t> GetInt(std::string str)
{
    std::vector<size_t> value;
    // 正则表达式模式
    std::regex pattern("\\d+");

    // 使用迭代器进行匹配
    std::smatch match;
    std::string::const_iterator searchStart(str.cbegin());

    while (std::regex_search(searchStart, str.cend(), match, pattern))
    {
        // 提取匹配到的数字
        value.push_back(std::stoull(match.str()));
        // 更新搜索的起始位置
        searchStart = match.suffix().first;
    }
    /*return*/
    return value;
}

std::string urlDecode(const std::string& url)
{
    std::ostringstream decoded;
    for (size_t i = 0; i < url.length(); ++i)
    {
        if (url[i] == '%')
        {
            if (i + 2 < url.length())
            {
                int hexValue = 0;
                std::istringstream hexStream(url.substr(i + 1, 2));
                if (hexStream >> std::hex >> hexValue)
                {
                    decoded << static_cast<char>(hexValue);
                    i += 2;
                }
                else
                {
                    decoded << url[i];
                }
            }
            else
            {
                decoded << url[i];
            }
        }
        else if (url[i] == '+')
        {
            decoded << ' ';
        }
        else
        {
            decoded << url[i];
        }
    }
    /*return*/
    return decoded.str();
}

std::string substr(std::string fs, std::string &str)
{
    size_t pos, len;
    auto num = GetInt(fs);

    if(num.size() == 1) {
        return str.substr(num.at(0));
    }

    if(num.size() == 2) {
        pos = num.at(0);
        len = num.at(1);
        return str.substr(pos, len);
    }
    
    return str.substr();
}

std::string iterator(std::string str)
{
    std::string value, data;

    // 正则表达式模式，匹配=后面的值
    std::regex pattern("=([^&]+)");

    std::sregex_iterator iter(str.begin(), str.end(), pattern);
    std::sregex_iterator end;

    while (iter != end)
    {
        std::smatch match = *iter;
        data = match.str().substr(1); // 去除等号前面的字符
        value += data + "|";
        ++iter;
    }
    /*return*/
    return value;
}

std::vector<std::string> split(std::string str, std::string pattern)
{
    std::string::size_type pos;
    std::vector<std::string> result;
    str += pattern;
    int size = (int)str.size();
    for (int i = 0; i < size; i++)
    {
        pos = str.find(pattern, i);
        if ((int)pos < size)
        {
            std::string s = str.substr(i, pos - i);
            //if(s.length() != 0) result.push_back(s);
            i = pos + pattern.size() - 1;
            /*save data*/
            result.push_back(s);
        }
    }
	
    return result;
}

std::vector<std::string> ParseModeInfo(std::string &mode)
{
    std::string value;
    std::vector<std::string> vMode;
    /*split (*/
	auto left = split(mode, "(");
    if(left.size() == 0) return vMode;
    /*get left back data*/
    auto tmp = left.back();
    /*split )*/
    auto right = split(tmp, ")");
	/*check ()*/
	if(left.size() != right.size()) return vMode;
	/*get function*/
	for(int i = 0; i < (int)left.size() - 1; i++)
	{
        //auto pos = left.at(i).find("match");
        //if(pos != std::string::npos) continue;
        /*value*/
		value = left.at(i) + "(" + right.at(right.size() - i - 2) + ")";
		vMode.push_back(value);
	}
	/*return*/
	return vMode;
}

void ParseDecodeType(std::string src, std::vector<std::string> &headers, std::vector<std::string> &bodys)
{
    MATCH_REQ_POS mt = MATCH_REQ_MAX;
    std::string basic = "header_";
    std::vector<std::string> data = {"path", "method", "authority", "scheme"};
    /*check value*/
    if(src.length() == 0) return;
    /*parse rule*/
    auto datas = split(src, "|");
    for(auto &value : datas)
    {
        mt  = MATCH_REQ_HEADER;
        auto pos = value.find("header_");
        if(pos == std::string::npos)
        {
            basic = "body_";
            pos = value.find(basic);
            if(pos == std::string::npos) continue;
            mt = MATCH_REQ_BODY;
        }
        //offset
        auto offset = pos + basic.length();
        auto last = value.find(",", pos);
        if(last != std::string::npos)
        {
            value = value.substr(pos + basic.length(), last - offset);
        }
        else
        {
            last = value.find(")", pos);
            if(last == std::string::npos) {
                value = value.substr(pos + basic.length());
            } else {
                value = value.substr(pos + basic.length(), last - offset);
            }
        }

        for(int i = 0; i < (int)data.size(); i++)
        {
            if(data[i] != value) continue;
            value = ":" + value;
            break;
        }
        //type
        if(mt == MATCH_REQ_HEADER) {
            headers.push_back(value);
        } else {
            bodys.push_back(value);
        }
    }
}

Rules::Rules() {}

Rules::~Rules() {}

//init
void Rules::InitRule()
{
    this->white_list_.clear();
    this->black_list_.clear();
    this->header_rules_.clear();
    this->body_rules_.clear();
    this->domain_.clear();
    this->detect_header_.clear();
    this->ignore_.clear();
    this->force_white_list_.clear();
}

void Rules::AddRule(Rule rule)
{
    std::vector<std::string> headers, bodys;
    /*format mode*/
    rule.match_func_ = ParseModeInfo(rule.mode_);
    if(rule.match_func_.size() == 0) RETURN_ERROR(, "parse rule mode failed, mode : %s", rule.mode_.c_str());

    /*print debug log*/
    LOG_D("func back : %s", rule.match_func_.back().c_str());
    /*request type*/
    ParseDecodeType(rule.match_func_.back(), headers, bodys);
    /*push header rule*/
    if(headers.size() > 0)
    {
        rule.keys_.assign(headers.begin(), headers.end());
        header_rules_.push_back(rule);
        LOG_D("add header rule id : %ld, mode : %s, keys size : %d", rule.id_, rule.mode_.c_str(), (int)rule.keys_.size());
    }
    /*push body rule*/
    if(bodys.size() > 0)
    {
        rule.keys_.clear();
        rule.keys_.assign(bodys.begin(), bodys.end());
        body_rules_.push_back(rule);
        LOG_D("add body rule id : %ld, mode : %s, keys size : %d", rule.id_, rule.mode_.c_str(), (int)rule.keys_.size());
    }
}

/*match mode function*/
int Rules::MatchModeFunc(std::string str)
{
    int i = 0;
    for(i = 0; i < (int)MatchFunc.size(); i++)
    {
        auto flag = str.find(MatchFunc.at(i));
        if(flag != std::string::npos) break;
    }
    return i;
}

/*add ignore type*/
void Rules::AddIgnoreType(std::string &value)
{
    if(value.length() == 0) return;
    //insert
    this->ignore_.insert(std::make_pair(value, 0));
    //print debug log
    LOG_D("ignore type : %s", value.c_str());
}

/*add detect header*/
void Rules::AddDetectHeader(std::string &value)
{
    if(value.length() == 0) return;
    //push back
    this->detect_header_.push_back(value);
    //print debug log
    LOG_D("detect header : %s", value.c_str());
}

/*add domain*/
void Rules::AddDomain(std::string &value)
{ 
    if(value.length() == 0) return;
    //push back
    this->domain_.push_back(value);
    //print debug log
    LOG_D("domain : %s", value.c_str());
}

/*add default action*/
void Rules::AddDefAction(std::string value)
{
    if(value == "passthrough") {
        this->def_action_ = ACTION_BYPASS;
    } else if(value == "alert") {
        this->def_action_ = ATCION_ALERT;
    } else if(value == "protect") {
        this->def_action_ = ATCTION_DROP;
    }
}

/*add force white list*/
void Rules::AddForceWhiteList(BWList &bw)
{
    int i;
    if(bw.mode_ != "strong-white") return;

    auto para = split(bw.expr_, ",");
    for(i = 0; i < (int)para.size(); i++)
    {
        auto argv = para.at(i);
        //print debug log
        LOG_D("force white list, src : %s", argv.c_str());
        //check cidr
        auto pos = argv.find("/");
        if(pos == std::string::npos) {
            bw.rtype_.push_back(AUTO_RULE_IP_EQUAL);
        } else {
            bw.rtype_.push_back(AUTO_RULE_IP_CIDR);
        }
        bw.rdata_.push_back(argv);
    }
    //mode
    bw.action_ = ACTION_BYPASS;
    bw.desc_   =  "IP强白名单";
    this->force_white_list_.push_back(bw);
}

/*add black list and white list*/
void Rules::AddBlackWhiteList(BWList &bw)
{
    int i, j;
    std::string rinfo, argv;
    bw.rtype_.clear();
    bw.rdata_.clear();
    /*check force white*/
    if(bw.mode_ == "strong-white") return AddForceWhiteList(bw);
    /*count || && number*/
    auto input = CountRuleTagNumWithDelSpace(bw.expr_);
    auto data = split(input, "||");
    for(i = 0; i < (int)data.size(); i++)
    {
        auto value = split(data.at(i), "&&");
        for(j = 0; j < (int)value.size(); j++)
        {
            argv = removeSpeStr(value.at(j), " ");
            argv = removeSpeStr(argv, "(");
            argv = removeSpeStr(argv, ")");
            input = replaceString(input, argv, std::to_string(bw.rtype_.size()));
            /*get rule info*/
            rinfo = getRuleVaule(argv);
            /*find string*/
            auto pos = argv.find("path ==");
            if(pos != std::string::npos) {
                bw.rdata_.push_back(rinfo);
                bw.rtype_.push_back(AUTO_RULE_PATH_EQUAL);
                continue;
            }
            //path match
            pos = argv.find("path matches");
            if(pos != std::string::npos) {
                bw.rdata_.push_back(rinfo);
                bw.rtype_.push_back(AUTO_RULE_PATH_REG);
                continue;
            }
            //ip
            pos = argv.find("ip ==");
            if(pos != std::string::npos) {
                bw.rdata_.push_back(rinfo);
                bw.rtype_.push_back(AUTO_RULE_IP_EQUAL);
                continue;
            }
            //ip cidr
            pos = argv.find("ip CIDR");
            if(pos != std::string::npos) {
                bw.rdata_.push_back(rinfo);
                bw.rtype_.push_back(AUTO_RULE_IP_CIDR);
                continue;
            }
        }
    }
    /*save operation expression*/
    bw.oprexpr_ = delSpace(input);
    /*print debug  log*/
    LOG_D("[bwlist] opr expr : [%s], src : [%s], mode : %s", input.c_str(), bw.expr_.c_str(), bw.mode_.c_str());
    //mode
    if(bw.mode_ == "black")
    {
        bw.action_ = ATCTION_DROP;
        //push back
        this->black_list_.push_back(bw);
    }
    else
    {
        bw.action_ = ACTION_BYPASS;
        this->white_list_.push_back(bw);
    }
}

/*pcre2 match*/
bool Rules::Pcre2Regex(std::uint64_t id, std::string &expr, std::string &src, std::string &dst)
{
    bool ret = false;
    pcre2_code *re = nullptr;
    std::string buf;
    PCRE2_UCHAR buffer[256];
    int errorcode, rc;
    PCRE2_SIZE erroroffset;
    PCRE2_SPTR substring_start = nullptr;
    PCRE2_SIZE substring_length = 0, *ovector;
    PCRE2_SPTR pattern = (PCRE2_SPTR)expr.c_str();
    PCRE2_SPTR input   = (PCRE2_SPTR)src.c_str();
    // 编译正则表达式
    re = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED, 0, &errorcode, &erroroffset, NULL);
    if(!re)
    {
        pcre2_get_error_message(errorcode, buffer, sizeof(buffer));
        buf = (char *)buffer;
        LOG_E("PCRE2 compilation failed, id : %lu, erroroffset : %d, error : %s, number : %d", id, (int)erroroffset, buf.c_str(), errorcode);
        return false;
    }
    // 匹配正则表达式
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(re, NULL);
    if(!match_data)
    {
        LOG_E("PCRE2 match data create from pattern failed, id : %lu", id);
        goto end;
    }
    /*ovector pointer*/
    ovector = pcre2_get_ovector_pointer(match_data);
    /*pcre2 match*/
    rc = pcre2_match(re, input, PCRE2_ZERO_TERMINATED, 0, 0, match_data, NULL);
    while (rc > 0)
    {
        for (int i = 0; i < rc; i++)
        {
            substring_start  = input + ovector[2 * i];
            substring_length = ovector[2 * i + 1] - ovector[2 * i];
            dst = (char *)substring_start;
            /*set result state*/
            ret = true;
            /*goto end*/
            goto end;
        }

        input = substring_start + substring_length;
        rc = pcre2_match(re, input, PCRE2_ZERO_TERMINATED, 0, 0, match_data, NULL);
        /*ovector pointer*/
        ovector = pcre2_get_ovector_pointer(match_data);
    }
end:
    /*free*/
    if(match_data) pcre2_match_data_free(match_data);
    if(re) pcre2_code_free(re);
    /*return*/
    return ret;
}

bool Rules::MatchIgnoreType(std::string &src)
{
    auto value = split(src, "?");
    auto pos = value.at(0).rfind(".");
    if(pos == std::string::npos) return false;
    auto data = value.at(0).substr(pos);
    auto it = this->ignore_.find(data);
    return (it == this->ignore_.end()) ? false : true;
}

/*match ignore type*/
bool Rules::MatchDomain(std::string &src)
{
    for(int i = 0; i < (int)this->domain_.size(); i++)
    {
        if(src == this->domain_.at(i)) return true;
    }
    return false;
}

/*match force white list*/
bool Rules::MatchForceWhiteList(std::vector<std::string> &ips, std::string &path, BWList &policy)
{
    int mask, j, n, i;
    std::string sip, rip, ip;
    std::vector<std::string> data;
    if((this->force_white_list_.size() == 0) || (ips.size() == 0)) return false;
    /*set action*/
    policy.action_ = ACTION_BYPASS;
    policy.desc_   = "IP强白名单";
    policy.mode_   = ips.at(0);
    /*list black and white list*/
    for(i = 0; i < (int)this->force_white_list_.size(); i++)
    {
        auto wType = this->force_white_list_.at(i).rtype_;
        auto wRule = this->force_white_list_.at(i).rdata_;
        for(j = 0; j < (int)wRule.size(); j++)
        {
            switch (wType.at(j))
            {
            case AUTO_RULE_IP_EQUAL:
                for(n = 0; n < (int)ips.size(); n++)
                {
                    ip = ips.at(n);
                    if(ip != wRule.at(j)) continue;
                    policy = this->force_white_list_.at(i);
                    policy.mode_ = ip;
                    return true;
                }
                break;

            case AUTO_RULE_IP_CIDR:
                sip = ipv4CidrToIp(wRule.at(j), mask);
                for(n = 0; n < (int)ips.size(); n++)
                {
                    ip = ips.at(n);
                    rip = calculateNetworkAddress(ip, mask);
                    if(rip != sip) continue;
                    policy = this->force_white_list_.at(i);
                    policy.mode_ = ip;
                    return true;
                }
                break;

            default:
                break;
            }
        }
    }
    /*set reverse action*/
    policy.action_ = ATCTION_DROP;
    /*return*/
    return true;
}

/*match white and black list*/
bool Rules::MatchBlackWhiteList(std::vector<std::string> &ips, std::string &path, BWList &policy)
{
    int mask, n, j, i;
    std::string sMathRet = "false";
    std::string sip, rip, ip, sMode, sDesc;
    std::vector<BWList> bwList;
    std::vector<std::string> data, bRet, mode, desc;
    /*white and black list*/
    bwList.clear();
    bwList.assign(this->white_list_.begin(), this->white_list_.end());
    bwList.insert(bwList.end(), this->black_list_.begin(), this->black_list_.end());
    /*list black and white list*/
    for(i = 0; i < (int)bwList.size(); i++)
    {
        auto bwType = bwList.at(i).rtype_;
        auto bwRule = bwList.at(i).rdata_;
        /*init vector*/
        bRet.clear();
        mode.clear();
        desc.clear();
        data.clear();
        /*init policy*/
        policy = bwList.at(i);
        /*check number*/
        if(bwType.size() != bwRule.size())
        {
            LOG_E("[bwlist] rule data size : %d, rule type size : %d, them is not equal!", (int)bwRule.size(), (int)bwType.size());
            return false;
        }
        /*list rule data*/
        for(j = 0; j < (int)bwRule.size(); j++)
        {
            sMathRet = "false";
            sMode = "default";
            sDesc = "default";
            switch (bwType.at(j))
            {
            case AUTO_RULE_IP_EQUAL:
                for(n = 0; n < (int)ips.size(); n++)
                {
                    ip = ips.at(n);
                    if(ip != bwRule.at(j)) continue;
                    sMathRet = "true";
                    sMode = ip;
                    sDesc = (policy.action_ == ATCTION_DROP) ? "IP黑名单" : "IP白名单";
                    break;
                }
                mode.push_back(ip);
                desc.push_back(sDesc);
                bRet.push_back(sMathRet);
                break;

            case AUTO_RULE_IP_CIDR:
                sip = ipv4CidrToIp(bwRule.at(j), mask);
                for(n = 0; n < (int)ips.size(); n++)
                {
                    ip = ips.at(n);
                    rip = calculateNetworkAddress(ip, mask);
                    if(rip != sip) continue;
                    sMathRet = "true";
                    sMode = ip;
                    sDesc = (policy.action_ == ATCTION_DROP) ? "IP黑名单" : "IP白名单";
                    break;
                }
                mode.push_back(ip);
                desc.push_back(sDesc);
                bRet.push_back(sMathRet);
                break;

            case AUTO_RULE_PATH_EQUAL:
                for(n = 0; n < 1; n++)
                {
                    if(path.length() == 0) break;
                    data = split(path, "?");
                    if(data.at(0) != bwRule.at(j)) break;
                    sMathRet = "true";
                    sMode = path;
                    sDesc = (policy.action_ == ATCTION_DROP) ? "路径黑名单" : "路径白名单";
                    break;
                }
                mode.push_back(ip);
                desc.push_back(sDesc);
                bRet.push_back(sMathRet);
                break;

            case AUTO_RULE_PATH_REG:
                for(n = 0; n < 1; n++)
                {
                    if(path.length() == 0) break;
                    data = split(path, "?");
                    if (!std::regex_search(data.at(0), std::regex(bwRule.at(j)))) break;
                    sMathRet = "true";
                    sMode = path;
                    sDesc = (policy.action_ == ATCTION_DROP) ? "路径黑名单" : "路径白名单";
                    break;
                }
                mode.push_back(ip);
                desc.push_back(sDesc);
                bRet.push_back(sMathRet);
                break;

            default:
                break;
            }
        }
        /*operation expression*/
        auto orNum = CountSubstr(policy.oprexpr_, "||");
        auto andNum = CountSubstr(policy.oprexpr_, "&&");
        auto aCount = orNum + andNum;
        /*one*/
        if(aCount == 0)
        {
            /*not match*/
            if(bRet.at(0).compare("false") == 0) continue;
            policy.mode_ = mode.at(0);
            policy.desc_ = desc.at(0);
            /*match success*/
            return true;
        }
        /*all && operation expression*/
        if(orNum == 0)
        {
            n = 0;
            bool mret = true;
            for(n = 0; n < (int)bRet.size(); n++)
            {
                if(bRet.at(n).compare("true") == 0) continue;
                mret = false;
                break;
            }
            /*match failed*/
            if(!mret) continue;
            policy.mode_ = mode.at(n);
            policy.desc_ = desc.at(n);
            /*match success*/
            return true;
        }
        /*all || operation expression*/
        if(andNum == 0)
        {
            n = 0;
            bool mret = false;
            for(n = 0; n < (int)bRet.size(); n++)
            {
                if(bRet.at(n).compare("false") == 0) continue;
                mret = true;
                break;
            }
            /*match failed*/
            if(!mret) continue;
            /*get match information*/
            policy.mode_ = mode.at(n);
            policy.desc_ = desc.at(n);
            /*match success*/
            return true;
        }
        /*replace*/
        policy.mode_ = "";
        std::string expr = policy.oprexpr_;
        for(n = 0; n < (int)bRet.size(); n++)
        {
            expr = replaceString(expr, std::to_string(n), bRet.at(n));
            if((bRet.at(n).compare("true") == 0) && (policy.mode_.empty()))
            {
                /*get mode and desc*/
                policy.mode_ = mode.at(n);
                policy.desc_ = desc.at(n);
            }
        }
        /*eval*/
        if(eval(expr)) return true;
    }
    /*return*/
    return false;
}
