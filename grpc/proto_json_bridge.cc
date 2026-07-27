#include "grpc/proto_json_bridge.h"

namespace grpc_bridge {

namespace {

/*mirrors ConvertRuleAction, net-policy.cpp:1373-1379*/
const char* PolicyActionToString(netpolicy::v1::PolicyAction action) {
  switch (action) {
  case netpolicy::v1::POLICY_ACTION_ALLOW: return "Allow";
  case netpolicy::v1::POLICY_ACTION_ALERT: return "Alert";
  default:                                 return "Deny";
  }
}

/*mirrors the "ingress"/other-defaults-to-egress check, net-policy.cpp:1483*/
const char* FlowDirectionToString(netpolicy::v1::FlowDirection dir) {
  return (dir == netpolicy::v1::FLOW_DIRECTION_INGRESS) ? "ingress" : "egress";
}

/*mirrors NetProtoConvert, net-policy.cpp:56-66 (empty string == "any")*/
const char* L4ProtocolToString(netpolicy::v1::L4Protocol proto) {
  switch (proto) {
  case netpolicy::v1::L4_PROTOCOL_TCP:  return "TCP";
  case netpolicy::v1::L4_PROTOCOL_UDP:  return "UDP";
  case netpolicy::v1::L4_PROTOCOL_ICMP: return "ICMP";
  default:                              return "";
  }
}

cJSON* AddressEndpointToJson(const netpolicy::v1::AddressEndpoint& ep) {
  cJSON* obj = cJSON_CreateObject();
  cJSON_AddStringToObject(obj, "ip", ep.ip().c_str());
  cJSON_AddNumberToObject(obj, "pod_id", static_cast<double>(ep.pod_id()));
  return obj;
}

} // namespace

std::string BuildAddPolicyRuleJson(const netpolicy::v1::AddPolicyRuleRequest& req) {
  cJSON* root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "policy_name", req.policy_name().c_str());

  cJSON* rules = cJSON_CreateArray();
  for (const auto& spec : req.rules()) {
    cJSON* rule = cJSON_CreateObject();
    cJSON_AddStringToObject(rule, "action", PolicyActionToString(spec.action()));
    cJSON_AddStringToObject(rule, "direction", FlowDirectionToString(spec.direction()));
    if (spec.protocol() != netpolicy::v1::L4_PROTOCOL_UNSPECIFIED)
      cJSON_AddStringToObject(rule, "protocol", L4ProtocolToString(spec.protocol()));

    if (spec.http_rules_size() > 0) {
      cJSON* http = cJSON_CreateArray();
      for (const auto& h : spec.http_rules()) {
        cJSON* item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "host", h.host().c_str());
        cJSON_AddStringToObject(item, "method", h.method().c_str());
        cJSON_AddStringToObject(item, "path", h.path().c_str());
        cJSON_AddItemToArray(http, item);
      }
      cJSON_AddItemToObject(rule, "http", http);
    }

    cJSON* from_addrs = cJSON_CreateArray();
    for (const auto& ep : spec.from_addresses())
      cJSON_AddItemToArray(from_addrs, AddressEndpointToJson(ep));
    cJSON_AddItemToObject(rule, "from_addresses", from_addrs);

    cJSON* to_addrs = cJSON_CreateArray();
    for (const auto& ep : spec.to_addresses())
      cJSON_AddItemToArray(to_addrs, AddressEndpointToJson(ep));
    cJSON_AddItemToObject(rule, "to_addresses", to_addrs);

    if (spec.ports_size() > 0) {
      cJSON* ports = cJSON_CreateArray();
      for (const auto& p : spec.ports()) {
        cJSON* item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "port", p.port());
        // legacy wire key is "endPort" (camelCase), net-policy.cpp:1557
        cJSON_AddNumberToObject(item, "endPort", p.end_port());
        cJSON_AddItemToArray(ports, item);
      }
      cJSON_AddItemToObject(rule, "ports", ports);
    }

    cJSON_AddNumberToObject(rule, "priority", spec.priority());
    cJSON_AddItemToArray(rules, rule);
  }
  cJSON_AddItemToObject(root, "rules", rules);

  char* text = cJSON_PrintUnformatted(root);
  std::string result = text ? text : "";
  if (text) free(text);
  cJSON_Delete(root);
  return result;
}

std::string BuildUpdateNodeConfigJson(const netpolicy::v1::UpdateNodeConfigRequest& req) {
  cJSON* root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "action",
      (req.action() == netpolicy::v1::UpdateNodeConfigRequest::ACTION_DELETE) ? "delete" : "add");
  cJSON* ips = cJSON_CreateArray();
  for (const auto& ip : req.node_ips())
    cJSON_AddItemToArray(ips, cJSON_CreateString(ip.c_str()));
  cJSON_AddItemToObject(root, "node_ips", ips);

  char* text = cJSON_PrintUnformatted(root);
  std::string result = text ? text : "";
  if (text) free(text);
  cJSON_Delete(root);
  return result;
}

std::string BuildAddWafRuleJson(const netpolicy::v1::AddWafRuleRequest& req) {
  cJSON* root = cJSON_CreateObject();

  cJSON* pod_ips = cJSON_CreateArray();
  for (const auto& ip : req.pod_ips())
    cJSON_AddItemToArray(pod_ips, cJSON_CreateString(ip.c_str()));
  cJSON_AddItemToObject(root, "pod_ips", pod_ips);

  cJSON* rules = cJSON_CreateArray();
  for (const auto& r : req.rules()) {
    cJSON* item = cJSON_CreateObject();
    cJSON_AddNumberToObject(item, "id", static_cast<double>(r.id()));
    cJSON_AddNumberToObject(item, "level", static_cast<double>(r.level()));
    cJSON_AddStringToObject(item, "type", r.type().c_str());
    cJSON_AddStringToObject(item, "name", r.name().c_str());
    cJSON_AddStringToObject(item, "expr", r.expr().c_str());
    cJSON_AddStringToObject(item, "mode", r.mode().c_str());
    // legacy wire key is "Description" (capital D), waf/plugin.cc:477
    cJSON_AddStringToObject(item, "Description", r.description().c_str());
    cJSON_AddItemToArray(rules, item);
  }
  cJSON_AddItemToObject(root, "rules", rules);

  cJSON* domains = cJSON_CreateArray();
  for (const auto& d : req.domains())
    cJSON_AddItemToArray(domains, cJSON_CreateString(d.c_str()));
  // legacy wire key is "domain" (singular), waf/plugin.cc:479
  cJSON_AddItemToObject(root, "domain", domains);

  cJSON* excluded = cJSON_CreateArray();
  for (const auto& e : req.excluded_file_types())
    cJSON_AddItemToArray(excluded, cJSON_CreateString(e.c_str()));
  cJSON_AddItemToObject(root, "excluded_file_types", excluded);

  cJSON* headers = cJSON_CreateArray();
  for (const auto& h : req.detect_headers())
    cJSON_AddItemToArray(headers, cJSON_CreateString(h.c_str()));
  cJSON_AddItemToObject(root, "detect_headers", headers);

  cJSON* bw_lists = cJSON_CreateArray();
  for (const auto& bw : req.black_white_lists()) {
    cJSON* item = cJSON_CreateObject();
    cJSON_AddNumberToObject(item, "id", static_cast<double>(bw.id()));
    cJSON_AddStringToObject(item, "name", bw.name().c_str());
    cJSON_AddStringToObject(item, "expr", bw.expr().c_str());
    cJSON_AddStringToObject(item, "mode", bw.mode().c_str());
    cJSON_AddItemToArray(bw_lists, item);
  }
  cJSON_AddItemToObject(root, "black_white_lists", bw_lists);

  cJSON_AddStringToObject(root, "uri", req.uri().c_str());
  cJSON_AddStringToObject(root, "mode", req.mode().c_str());
  cJSON_AddStringToObject(root, "name", req.name().c_str());
  cJSON_AddStringToObject(root, "cluster_key", req.cluster_key().c_str());
  // legacy wire key is "namespace", waf/plugin.cc:558
  cJSON_AddStringToObject(root, "namespace", req.k8s_namespace().c_str());
  cJSON_AddStringToObject(root, "kind", req.kind().c_str());
  cJSON_AddStringToObject(root, "workload_name", req.workload_name().c_str());
  cJSON_AddNumberToObject(root, "service_id", static_cast<double>(req.service_id()));

  char* text = cJSON_PrintUnformatted(root);
  std::string result = text ? text : "";
  if (text) free(text);
  cJSON_Delete(root);
  return result;
}

std::string BuildDeleteWafRuleJson(const netpolicy::v1::DeleteWafRuleRequest& req) {
  cJSON* root = cJSON_CreateObject();
  cJSON* pod_ips = cJSON_CreateArray();
  for (const auto& ip : req.pod_ips())
    cJSON_AddItemToArray(pod_ips, cJSON_CreateString(ip.c_str()));
  cJSON_AddItemToObject(root, "pod_ips", pod_ips);

  char* text = cJSON_PrintUnformatted(root);
  std::string result = text ? text : "";
  if (text) free(text);
  cJSON_Delete(root);
  return result;
}

std::string BuildDumpConnectionsJson(const netpolicy::v1::DumpConnectionsRequest& req) {
  cJSON* root = cJSON_CreateObject();
  cJSON_AddNumberToObject(root, "limit", req.limit());
  char* text = cJSON_PrintUnformatted(root);
  std::string result = text ? text : "";
  if (text) free(text);
  cJSON_Delete(root);
  return result;
}

std::string BuildDumpHeapProfileJson(const netpolicy::v1::DumpHeapProfileRequest& req) {
  cJSON* root = cJSON_CreateObject();
  // admin::Heap::handleHeapProfile expects a JSON string "y"/"n", admin/profile.cc:30-37
  cJSON_AddStringToObject(root, "enable", req.enable() ? "y" : "n");
  char* text = cJSON_PrintUnformatted(root);
  std::string result = text ? text : "";
  if (text) free(text);
  cJSON_Delete(root);
  return result;
}

void ConvertConfigCJsonToProto(cJSON* config, netpolicy::v1::DumpConfigResponse* out) {
  if (!config || !out) return;

  auto convert_rule_array = [](cJSON* arr,
      google::protobuf::RepeatedPtrField<netpolicy::v1::PolicyRuleConfigEntry>* dst) {
    if (!arr) return;
    int size = cJSON_GetArraySize(arr);
    for (int i = 0; i < size; i++) {
      cJSON* item = cJSON_GetArrayItem(arr, i);
      if (!item) continue;
      auto* entry = dst->Add();
      cJSON* f;
      if ((f = cJSON_GetObjectItem(item, "policy_name"))) entry->set_policy_name(f->valuestring);
      if ((f = cJSON_GetObjectItem(item, "priority"))) entry->set_priority(f->valueint);
      if ((f = cJSON_GetObjectItem(item, "direction"))) entry->set_direction(f->valuestring);
      if ((f = cJSON_GetObjectItem(item, "action"))) entry->set_action(f->valuestring);
      if ((f = cJSON_GetObjectItem(item, "protocol"))) entry->set_protocol(f->valuestring);
      if ((f = cJSON_GetObjectItem(item, "protocol_int"))) entry->set_protocol_int(f->valueint);
      if ((f = cJSON_GetObjectItem(item, "from_address"))) entry->set_from_address(f->valuestring);
      if ((f = cJSON_GetObjectItem(item, "to_address"))) entry->set_to_address(f->valuestring);
    }
  };

  convert_rule_array(cJSON_GetObjectItem(config, "inbound_rules"), out->mutable_inbound_rules());
  convert_rule_array(cJSON_GetObjectItem(config, "outbound_rules"), out->mutable_outbound_rules());

  cJSON* containers = cJSON_GetObjectItem(config, "containers");
  if (containers) {
    int size = cJSON_GetArraySize(containers);
    for (int i = 0; i < size; i++) {
      cJSON* item = cJSON_GetArrayItem(containers, i);
      if (!item) continue;
      auto* c = out->add_containers();
      cJSON* f;
      if ((f = cJSON_GetObjectItem(item, "pid"))) c->set_pid(f->valueint);
      if ((f = cJSON_GetObjectItem(item, "pod_id"))) c->set_pod_id(static_cast<uint64_t>(f->valuedouble));
    }
  }

  cJSON* tcp = cJSON_GetObjectItem(config, "tcp");
  if (tcp) {
    cJSON* conn = cJSON_GetObjectItem(tcp, "tcp_connection");
    if (conn) out->set_tcp_connections(static_cast<int64_t>(conn->valuedouble));
  }
}

void ConvertConnectionsCJsonToProto(cJSON* conns, netpolicy::v1::DumpConnectionsResponse* out) {
  if (!conns || !out) return;
  cJSON* total = cJSON_GetObjectItem(conns, "total");
  if (total) out->set_total(static_cast<int64_t>(total->valuedouble));
  cJSON* items = cJSON_GetObjectItem(conns, "items");
  if (items) {
    int size = cJSON_GetArraySize(items);
    for (int i = 0; i < size; i++) {
      cJSON* item = cJSON_GetArrayItem(items, i);
      if (item && item->valuestring) out->add_items(item->valuestring);
    }
  }
}

} // namespace grpc_bridge
