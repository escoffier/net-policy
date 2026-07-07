#include <cstddef>
#include <cstdint>
#include <fstream>
#include <cstdlib>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <linux/tcp.h>
#include <string.h>
#include "http/filter.h"
#include "net/stream.h"
#include "plugin.h"
#include "log.h"


namespace http {
namespace extension {

const char *PREFIX = "#%% pre";
const size_t HEADER_LEN = 11;

PluginRootContext RootContext;

/* Checksum a block of data */
static uint16_t csum(uint16_t *packet, int packlen)
{
  unsigned long sum = 0;
  while (packlen > 1)
  {
    sum += *packet++;
    packlen -= 2;
  }
  /*sum*/
  if (packlen > 0) sum += *(uint8_t *)packet;
  /* TODO: this depends on byte order */
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  /*return*/
  return (uint16_t)~sum;
}

/*tcp checksum*/
static uint16_t TcpCsum(char *packet, size_t length, uint32_t from, uint32_t to)
{
  struct tcphdr *tcpphdr, *ttcphdr;
  PSEUDO_HEADER *pseudo;
  char buffer[2048];
  /*udp protocol header*/
  tcpphdr = reinterpret_cast<struct tcphdr *>(packet);
  if (length >= sizeof(buffer)) RETURN_ERROR(0, "create tcp checksum failed, data is too long than buffer, data len : %d", (int)length);
  /*init memory*/
  memset(buffer, 0, sizeof(buffer));
  /*pesudo header*/
  pseudo = (PSEUDO_HEADER *)buffer;
  pseudo->daddr_ = to;
  pseudo->saddr_ = from;
  pseudo->placeholder_ = 0;
  pseudo->protocol_ = IPPROTO_TCP;
  pseudo->length_ = htons(length);
  /*tcp header*/
  ttcphdr = (struct tcphdr *)(buffer + sizeof(PSEUDO_HEADER));
  memcpy(ttcphdr, tcpphdr, ntohs(pseudo->length_));
  ttcphdr->check = 0;
  /*checksum*/
  return csum((uint16_t *)buffer, ntohs(pseudo->length_) + sizeof(PSEUDO_HEADER)); // sizeof(PSEUDO_HEADER) + sizeof(UDP_HEADER));
}

FilterStatus PluginContext::ModifyNetPackets()
{
  auto data = getTcpSegment();
  struct tcphdr *tcphdr = (struct tcphdr *)data.base_;
  int offset = tcphdr->doff << 2;
  int dataLen = data.size_ - offset;
  dataLen = (dataLen > 30) ? 30 : dataLen;
  for(int i = offset; i < (dataLen + offset); i++)
  {
    data.base_[i] = 0;
  }
  //tcp checksum
  tcphdr->check = TcpCsum((char *)data.base_, data.size_, data.from_, data.to_);
  //return
  return FilterStatus::StopIteration;
}

FilterStatus PluginContext::onNewConnection(const net::ConnectionInfo &streamInfo)
{
  //print debug log
  LOG_T("new connection, dst ip : %s, waf rule size : %ld", streamInfo.to_.c_str(), RootContext.GetWafRuleSize());
  //get waf rule
  auto ret = RootContext.GetWafRule(streamInfo.to_, ruleArr);
  if(!ret) return FilterStatus::StopIteration;
  /*source address*/
  forwardIp_ = streamInfo.from_;
  //print debug log
  LOG_T("new connection, get waf rule success, id : %lu, default action : %d", getConnectionID(), ruleArr.GetDefAction());
  //return
  return FilterStatus::Continue;
}

FilterStatus PluginContext::onClose()
{
  char *str = NULL;
  cJSON *root = NULL, *array = nullptr, *obj = nullptr;
  /*link close*/
  LOG_T("http connection close, app length : %d, id : %lu", (int)atlog.attacked_app_.length(), getConnectionID());
  /*check attack app length*/
  if(atlog.attacked_app_.length() == 0) return FilterStatus::Continue;
  /*create json object*/
  root = cJSON_CreateObject();
  if(!root) RETURN_ERROR(FilterStatus::Continue, "create json object failed.");
  /*pod info*/
  cJSON_AddStringToObject(root, "type", "waf");
  cJSON_AddNumberToObject(root, "service_id", ruleArr.app_id_);
  cJSON_AddStringToObject(root, "res_name", ruleArr.res_name_.c_str());
  cJSON_AddStringToObject(root, "app_name", ruleArr.GetAppName().c_str());
  cJSON_AddStringToObject(root, "res_kind", ruleArr.res_kind_.c_str());
  cJSON_AddStringToObject(root, "namespace", ruleArr.pod_namespace_.c_str());
  cJSON_AddStringToObject(root, "cluster_key", ruleArr.cluster_key_.c_str());
  //json array
  array = cJSON_CreateArray();
  obj   = cJSON_CreateObject();
  if(!array || !obj) RETURN_ERROR(FilterStatus::Continue, "create json array object failed.");
  cJSON_AddStringToObject(obj, "action",      atlog.action_.c_str());
  cJSON_AddStringToObject(obj, "attack_ip", atlog.attack_ip_.c_str());
  cJSON_AddStringToObject(obj, "attacked_app", atlog.attacked_app_.c_str());
  cJSON_AddStringToObject(obj, "attack_load", atlog.attack_load_.c_str());
  cJSON_AddNumberToObject(obj, "attack_time", atlog.attack_time_);
  cJSON_AddNumberToObject(obj, "rule_id",     atlog.rule_id_);
  cJSON_AddStringToObject(obj, "rule_name",   atlog.rule_name_.c_str());
  cJSON_AddStringToObject(obj, "req_pkg",     atlog.req_pkg_.c_str());
  cJSON_AddStringToObject(obj, "rsp_pkg",     atlog.rsp_pkg_.c_str());
  cJSON_AddStringToObject(obj, "attack_type", atlog.type_.c_str());
  cJSON_AddStringToObject(obj, "attacked_url", atlog.attacked_url_.c_str());
  cJSON_AddStringToObject(obj, "rsp_content_type", atlog.rsp_content_type_.c_str());
  //add json array
  cJSON_AddItemToArray(array, obj);
  cJSON_AddItemToObject(root, "attacked_log", array);
  /*add to object*/
  str = cJSON_PrintUnformatted(root);
  if(!str) GOTO_ERROR(err, "json format failed.");
  /*http post*/
  RootContext.HttpPost(str);
  
err:
  if(root) cJSON_Delete(root);
  if(str) cJSON_free(str);
  return FilterStatus::Continue;
}

std::string PluginContext::GetRequestHeaderInfo(RequestHeaderMap &headers, std::vector<std::string> &matchFunc, std::string key)
{
  std::smatch smRet;
  std::string value;
  std::string basic;
  std::regex reg("\\['(.*)'\\]");
  /*find header*/
  basic = "para";
  auto pos = key.find(basic);
  if(pos == std::string::npos)
  {
    pos = key.find("uri");
    if(pos != std::string::npos) return headers.getHttpHeader(":path");
    /*return*/
    return headers.getHttpHeader(key);
  }
  
  value = headers.getHttpHeader(":path");
  if(value.length() == 0) return value;
  
  pos = value.find("?");
  if(pos == std::string::npos) return "";

  /*get para*/
  value = value.substr(pos + 1);

  LOG_D("func size: %d", (int)matchFunc.size());
  for(auto i = matchFunc.size(); i > 0; i--)
  {
      auto func = matchFunc.at(i - 1);
      LOG_D("headers: %s", func.c_str());
      /*urlDecode*/
      pos = func.find("urlDecode");
      if(pos != std::string::npos) {
        value = urlDecode(value);
        LOG_D("urlDecode: %s", value.c_str());
        continue;
      }
      /*substr*/
      pos = func.find("substr");
      if(pos != std::string::npos) {
        value = substr(func, value);
        continue;
      }
      /*iterator*/
      pos = func.find("iterator");
      if(pos != std::string::npos) {
        value = iterator(value);
        continue;
      }
  }
  
  LOG_D("value : %s, key : %s", value.c_str(), key.c_str());
  /*match para*/
  if(basic == key) return value;
  /*match para['*']*/
  auto ret = std::regex_search(key, smRet, reg);
  if(!ret || (smRet.size() < 2)) return "";
  /*regex*/
  basic = "\\b" + smRet[1].str() + "=.*?(?=&|$)";
  reg = std::regex(basic);
  ret = std::regex_search(value, smRet, reg);
  if(!ret|| (smRet.size() == 0)) return "";
  /*return*/
  return smRet[0].str();
}

FilterStatus PluginContext::onRequestHeaders(RequestHeaderMap &headers, bool end_of_stream)
{
  bool ret;
  BWList param = {};
  std::string smret;
  std::string value, path;
  std::int64_t nowtime = GetNowTime();
  /*get request header pairs*/
  auto headerPairs = headers.getHttpHeaderPairs();
  /*save requst header infor*/
  atlog.attacked_url_ = SaveHeadersInfo(atlog, headerPairs);
  /*match domain*/
  auto domain = headers.getHttpHeader(":authority");
  if(domain.empty()) domain = headers.getHttpHeader(":host");
  if(!isIPAddress(domain))
  {
    ret = ruleArr.MatchDomain(domain);
    if(!ret) return FilterStatus::Continue;
  }
  /*get content-length*/
  auto clen = headers.getHttpHeader("content-length");
  /*print debug log*/
  LOG_D("match domain success, content-length : [%s]", clen.c_str());
  /*match black and white list*/
  auto xff = headers.getHttpHeader("x-forwarded-for");
  /*check x-forwared-for key*/
  if(xff.empty()) xff = forwardIp_;
  /*get first x-forwarded-for ip*/
  auto xffip = split(xff, ",");
  /*forward ip*/
  forwardIp_ = xffip.at(0);
  path = headers.getHttpHeader(":path");
  /*match force white list*/
  ret  = ruleArr.MatchForceWhiteList(xffip, path, param);
  if(ret)
  {
    //print debug log
    LOG_D("[success] match force white list, action : %d", param.action_);
    /*save attack info*/
    atlog.attack_ip_   = forwardIp_;
    atlog.attack_time_ = nowtime;
    atlog.rule_id_     = param.id_;
    atlog.attack_load_ = param.mode_;
    atlog.rule_name_   = param.desc_;
    atlog.type_ = "force-white";
    atlog.attacked_app_ = ruleArr.GetAppName();
    atlog.action_ = (param.action_ == ATCTION_DROP) ? "drop" : "pass";
    /*check action and content-length*/
    if((param.action_ == ATCTION_DROP) && (clen.length() == 0)) return ModifyNetPackets();
    /*return*/
    return FilterStatus::Continue;
  }
  /*print debug log*/
  LOG_D("%lu no match force white list", getConnectionID());
  /*match black and white list*/
  ret  = ruleArr.MatchBlackWhiteList(xffip, path, param);
  if(ret)
  {
    //print debug log
    LOG_D("[success] match black and white list, action : %d", param.action_);
    /*save attack info*/
    atlog.attack_ip_   = forwardIp_;
    atlog.attack_time_ = nowtime;
    atlog.rule_id_     = param.id_;
    atlog.attack_load_ = param.mode_;
    atlog.rule_name_   = param.desc_;
    atlog.type_ = (param.action_ == ATCTION_DROP) ? "black" : "white";
    atlog.attacked_app_ = ruleArr.GetAppName();
    atlog.action_ = (param.action_ == ATCTION_DROP) ? "drop" : "pass";
    /*check action and content-length*/
    if((param.action_ == ATCTION_DROP) && (clen.length() == 0)) return ModifyNetPackets();
    /*return*/
    return FilterStatus::Continue;
  }
  //print debug log
  LOG_D("no match black and white list");
  /*ignore config*/
  auto src = headers.getHttpHeader(":path");
  ret = ruleArr.MatchIgnoreType(src);
  if(ret) return FilterStatus::Continue;
  //print debug log
  LOG_D("no ignore suffix");
  /*check bypass*/
  if(ruleArr.GetDefAction() == ACTION_BYPASS) return FilterStatus::Continue;
  /*list header rule*/
  for (auto &r : ruleArr.GetHeaderRule())
  {
    auto cfg = r.keys_;
    auto deh = ruleArr.GetDetectHeaders();
    deh.insert(deh.end(), cfg.begin(), cfg.end());
    /*list configs*/
    for(auto &key : deh)
    {
      if(key == "body") continue;
      /*get request header*/
      auto value = GetRequestHeaderInfo(headers, r.match_func_, key);
      //print debug log
      LOG_D("id : %ld, rule, key : %s, value : %s", r.id_, key.c_str(), value.c_str());
      //check value
      if(value.empty()) continue;
      //regex
      if (ruleArr.Pcre2Regex(r.id_, r.expr_, value, smret))
      {
        /*save attack info*/
        LOG_D("[success] matched header rule success, id : %ld", r.id_);
        atlog.attack_ip_ = forwardIp_;
        atlog.attack_time_ = nowtime;
        atlog.rule_id_   = r.id_;
        atlog.rule_name_ = r.name_;
        atlog.attack_load_ = smret.c_str();
        atlog.attacked_app_ = ruleArr.GetAppName();
        atlog.type_ = r.type_;
        atlog.action_ = (ruleArr.GetDefAction() == ATCTION_DROP) ? "drop" : "warn";
        /*check action and content-length*/
        if((ruleArr.GetDefAction() == ATCTION_DROP) && (clen.length() == 0)) return ModifyNetPackets();
        /*return*/
        return FilterStatus::Continue;
      }
    }
  }
  
  return FilterStatus::Continue;
}

FilterStatus PluginContext::onRequestBody(seastar::net::packet &p, bool end_of_stream) 
{
  std::string ret, body;
  /*check body length*/
  if(p.len() == 0) return FilterStatus::Continue;
  /*body*/
  body = p.get_header(0, p.len());
  /*print debug log*/
  LOG_D("onRequestBody %s", body.c_str());
  /*save request body*/
  if(atlog.attacked_app_.length() != 0)
  {
    atlog.req_pkg_ = body;
    /*check action*/
    if(atlog.action_ == "drop") return ModifyNetPackets();
  }
  /*print debug log*/
  LOG_D("onRequestBody, continue match request body rule.");
  /*match body rule*/
  for (auto &r : ruleArr.GetBodyRule())
  {
    for(auto &key : r.keys_)
    {
      if (ruleArr.Pcre2Regex(r.id_, r.expr_, body, ret))
      {
        /*save attack info*/
        LOG_D("[success] matched body rule, id : %ld, action : %d, expr : %s, key : %s", r.id_, ruleArr.GetDefAction(), r.expr_.c_str(), key.c_str());
        atlog.attack_ip_ = forwardIp_;
        atlog.attack_time_ = GetNowTime();
        atlog.rule_id_   = r.id_;
        atlog.rule_name_ = r.name_;
        atlog.attack_load_ = ret.c_str();
        atlog.attacked_app_ = ruleArr.GetAppName();
        atlog.type_ = r.type_;
        atlog.rsp_pkg_ = body;
        atlog.action_ = (ruleArr.GetDefAction() == ATCTION_DROP) ? "drop" : "warn";
        /*check action*/
        if(ruleArr.GetDefAction() == ATCTION_DROP) return ModifyNetPackets();
        /*return*/
        return FilterStatus::Continue;
      }
    }
  }

  return FilterStatus::Continue;
}

/*response headers*/
FilterStatus PluginContext::onResponseHeaders(RequestHeaderMap &headers, bool end_of_stream)
{
  /*get content-type*/
  atlog.rsp_content_type_ = headers.getHttpHeader("content-type");
  /*print debug log*/
  LOG_D("onResponseHeaders, content-type : %s", atlog.rsp_content_type_.c_str());
  /*get response header*/
  auto rspHdr = headers.getHttpHeaderPairs();
  atlog.rsp_pkg_ = FormartRspHeaders(rspHdr);
  /*return*/
  return FilterStatus::Continue;
}

/*reponse body*/
FilterStatus PluginContext::onResponseBody(seastar::net::packet &p, bool end_of_stream)
{
  if(atlog.action_ == "drop") return FilterStatus::Continue;
  /*save response body*/
  if(atlog.attacked_app_.length() != 0)
  {
    if(p.len() == 0) return FilterStatus::Continue;
    /*save response data*/
    atlog.rsp_pkg_ += p.get_header(0, p.len());
    /*print debug log*/
    LOG_D("save onResponseBody, id : %ld", atlog.rule_id_);
  }
  /*return*/
  return FilterStatus::Continue;
}

FilterStatus PluginContext::onData(seastar::net::packet &data) {
  return FilterStatus::Continue;
}


PluginRootContext::PluginRootContext() { post_fd_ = nullptr; }
PluginRootContext::~PluginRootContext() {}


bool PluginRootContext::ParseConfiguration(char *config) {
  Rules ruleData;
  int size, i;
  std::vector<std::string> sPodIps;
  std::string data, port, podIp;
  cJSON *root = NULL, *item, *array, *rules;
  //init rule
  ruleData.InitRule();
  //parse json
  root = cJSON_Parse(config);
  if(!root) RETURN_ERROR(false, "parse json failed! original data : %s.", config);
  //get pod ip
  item = cJSON_GetObjectItem(root, "pod_ips");
  if(!item)
  {
    cJSON_Delete(root);
    RETURN_ERROR(false, "[waf] need pod ips");
  }
  //pod ips
  size = cJSON_GetArraySize(item);
  for(i = 0; i < size; i++)
  {
    array = cJSON_GetArrayItem(item, i);
    if(!array) continue;
    podIp = array->valuestring;
    sPodIps.push_back(podIp);
  }
  
  //get rule
  rules = cJSON_GetObjectItem(root, "rules");
  if(rules)
  {
    size = cJSON_GetArraySize(rules);
    for(i = 0; i < size; i++)
    {
      Rule tmp = {};
      array = cJSON_GetArrayItem(rules, i);
      if(!array) continue;
      item = cJSON_GetObjectItem(array, "id");
      if(item) tmp.id_ = item->valueint;
      item = cJSON_GetObjectItem(array, "level");
      if(item) tmp.level_ = item->valueint;
      item = cJSON_GetObjectItem(array, "type");
      if(item) tmp.type_ = item->valuestring;
      item = cJSON_GetObjectItem(array, "name");
      if(item) tmp.name_ = item->valuestring;
      item = cJSON_GetObjectItem(array, "expr");
      if(item) tmp.expr_ = item->valuestring;
      item = cJSON_GetObjectItem(array, "mode");
      if(item) tmp.mode_ = item->valuestring;
      item = cJSON_GetObjectItem(array, "Description");
      if(item) tmp.description_ = item->valuestring;
      //save data
      ruleData.AddRule(tmp);
    }
  }
  //get domain
  rules = cJSON_GetObjectItem(root, "domain");
  if(rules)
  {
    size = cJSON_GetArraySize(rules);
    for(i = 0; i < size; i++)
    {
      array = cJSON_GetArrayItem(rules, i);
      if(!array) continue;
      data = cJSON_GetStringValue(array);
      //save data
      ruleData.AddDomain(data);
    }
  }
  //get exclude
  rules = cJSON_GetObjectItem(root, "excluded_file_types");
  if(rules)
  {
    size = cJSON_GetArraySize(rules);
    for(i = 0; i < size; i++)
    {
      array = cJSON_GetArrayItem(rules, i);
      if(!array) continue;
      data = cJSON_GetStringValue(array);
      //save data
      ruleData.AddIgnoreType(data);
    }
  }
  //get detect headers
  rules = cJSON_GetObjectItem(root, "detect_headers");
  if(rules)
  {
    size = cJSON_GetArraySize(rules);
    for(i = 0; i < size; i++)
    {
      array = cJSON_GetArrayItem(rules, i);
      if(!array) continue;
      data = cJSON_GetStringValue(array);
      //save data
      ruleData.AddDetectHeader(data);
    }
  }
  //get black white list
  rules = cJSON_GetObjectItem(root, "black_white_lists");
  if(rules)
  {
    size = cJSON_GetArraySize(rules);
    for(i = 0; i < size; i++)
    {
      BWList bw = {};
      array = cJSON_GetArrayItem(rules, i);
      if(!array) continue;
      item = cJSON_GetObjectItem(array, "id");
      if(item) bw.id_ = item->valueint;
      item = cJSON_GetObjectItem(array, "name");
      if(item) bw.name_ = item->valuestring;
      item = cJSON_GetObjectItem(array, "expr");
      if(item) bw.expr_ = item->valuestring;
      item = cJSON_GetObjectItem(array, "mode");
      if(item) bw.mode_ = item->valuestring;
      //save data
      ruleData.AddBlackWhiteList(bw);
    }
  }
  //get app uri
  item = cJSON_GetObjectItem(root, "uri");
  if(item) ruleData.AddAppUri(item->valuestring);
  //get app mode
  item = cJSON_GetObjectItem(root, "mode");
  if(item) ruleData.AddDefAction(item->valuestring);
  //get app name
  item = cJSON_GetObjectItem(root, "name");
  if(item) ruleData.AddAppName(item->valuestring);
  //get cluster key
  item = cJSON_GetObjectItem(root, "cluster_key");
  if(item) ruleData.cluster_key_ = item->valuestring;
  //get post host
  item = cJSON_GetObjectItem(root, "namespace");
  if(item) ruleData.pod_namespace_ = item->valuestring;
  //get post host
  item = cJSON_GetObjectItem(root, "kind");
  if(item) ruleData.res_kind_ = item->valuestring;
  //get post host
  item = cJSON_GetObjectItem(root, "workload_name");
  if(item) ruleData.res_name_ = item->valuestring;
  //get app id
  item = cJSON_GetObjectItem(root, "service_id");
  if(item) ruleData.app_id_ = item->valuedouble;
  //free json object
  cJSON_Delete(root);
  //print debug log
  LOG_D("cluster_key : %s, namespace : %s, kind : %s, resource_name : %s", ruleData.cluster_key_.c_str(), ruleData.pod_namespace_.c_str(), ruleData.res_kind_.c_str(), ruleData.res_name_.c_str());
  //return
  for (const auto& str : sPodIps)
  {
    this->InsertWafRule(str, ruleData);
  }
  //return
  return true;
}

/*insert waf rule*/
bool PluginRootContext::InsertWafRule(std::string ip, Rules &rule) {
    /*remove key*/
    waf_rules_.erase(ip);
    /*insert data*/
    auto it = waf_rules_.insert({ip, rule});
    //print debug log
    LOG_D("save waf rule, pod ip : %s", ip.c_str());
    //return
    return it.second;
}

int PluginRootContext::HttpPost(std::string value) {
  int zRet;
  std::string data;
  //
  if(!post_fd_) RETURN_ERROR(1, "[waf] the post fd is nil");
  //post data
  char buf[11] = {"#%% pre"};
  auto len = value.length();
  buf[7] = len & 0xff;
  buf[8] = (len >> 8) & 0xff;
  buf[9] = (len >> 16) & 0xff;
  buf[10] = (len >> 24) & 0xff;
  zRet = write(*post_fd_, buf, HEADER_LEN);
  if(zRet <= 0) RETURN_ERROR(1, "[waf] post waf data");

  zRet = write(*post_fd_, value.c_str(), value.length());
  if(zRet <= 0) RETURN_ERROR(1, "[waf] post waf data");
  //print debug log
  data = (value.length() > 1024) ? value.substr(0, 1024) : value;
  LOG_D("data length : %d, post data length : %d, value : %s", (int)value.length(), zRet, data.c_str());
  //return
  return 0;
}

/*remove waf rule*/
bool PluginRootContext::RemoveWafRule(char *config)
{
  int size, i;
  cJSON *root = NULL, *item, *array;
  //parse json
  root = cJSON_Parse(config);
  if(!root) RETURN_ERROR(false, "parse json failed! original data : %s.", config);
  //get pod ip
  item = cJSON_GetObjectItem(root, "pod_ips");
  if(!item)
  {
    cJSON_Delete(root);
    RETURN_ERROR(false, "[waf] need pod ips");
  }
  //pod ips
  size = cJSON_GetArraySize(item);
  for(i = 0; i < size; i++)
  {
    array = cJSON_GetArrayItem(item, i);
    if(!array) continue;
    waf_rules_.erase(array->valuestring);
  }
  //free json object
  cJSON_Delete(root);
  //return
  return true;
}

} // namespace extension
} // namespace http
