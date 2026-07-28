#include <gtest/gtest.h>

#include "grpc/proto_json_bridge.h"
#include "grpc/work_queue.h"
#include "net-policy.h"
#include "waf/plugin.h"

namespace {

using grpc_bridge::ControlOp;
using grpc_bridge::ControlWorkItem;

/*Shared across every TEST() in this file, mirroring how the removed globals
 *(g_microseg, RootContext, etc.) used to be implicitly shared -- see
 *net-policy.h's DaemonContext.*/
DaemonContext daemon;

/*Drives DispatchGrpcControlOp directly, bypassing gRPC transport entirely --
 *this exercises exactly the same code path a real RPC would reach after
 *EnqueueAndWait/the work queue, minus the thread hop. epoll_fd is unused by
 *every op exercised here (policy/WAF CRUD, config dump, log level), so a
 *dummy value is fine; pod-lifecycle ops (PodUp/PodDown) need a real NFQUEUE-
 *capable epoll fd and are intentionally not covered here.*/
grpc::Status Dispatch(ControlOp op, const google::protobuf::Message& request,
                       google::protobuf::Message* response) {
  ControlWorkItem item;
  item.op = op;
  item.request = &request;
  item.response = response;
  DispatchGrpcControlOp(/*epoll_fd=*/-1, item, daemon);
  return item.status;
}

TEST(ControlDispatch, AddThenDeletePolicyRuleUpdatesPolicyTree) {
  netpolicy::v1::AddPolicyRuleRequest add_req;
  add_req.set_policy_name("grpc-test-policy-1");
  auto* rule = add_req.add_rules();
  rule->set_action(netpolicy::v1::POLICY_ACTION_ALLOW);
  rule->set_direction(netpolicy::v1::FLOW_DIRECTION_INGRESS);
  rule->set_priority(10);
  auto* from = rule->add_from_addresses();
  from->set_ip("10.0.0.1");
  auto* to = rule->add_to_addresses();
  to->set_ip("10.0.0.2");
  to->set_pod_id(42);

  netpolicy::v1::StatusResponse add_resp;
  Dispatch(ControlOp::kAddPolicyRule, add_req, &add_resp);
  EXPECT_EQ(add_resp.status(), 0);

  netpolicy::v1::DumpConfigRequest dump_req;
  dump_req.set_policy_name("grpc-test-policy-1");
  netpolicy::v1::DumpConfigResponse dump_resp;
  Dispatch(ControlOp::kDumpConfig, dump_req, &dump_resp);
  ASSERT_EQ(dump_resp.inbound_rules_size(), 1);
  EXPECT_EQ(dump_resp.inbound_rules(0).policy_name(), "grpc-test-policy-1");
  EXPECT_EQ(dump_resp.inbound_rules(0).action(), "Allow");

  netpolicy::v1::DeletePolicyRuleRequest del_req;
  del_req.set_policy_name("grpc-test-policy-1");
  netpolicy::v1::StatusResponse del_resp;
  Dispatch(ControlOp::kDeletePolicyRule, del_req, &del_resp);
  EXPECT_EQ(del_resp.status(), 0);

  netpolicy::v1::DumpConfigResponse dump_after;
  Dispatch(ControlOp::kDumpConfig, dump_req, &dump_after);
  EXPECT_EQ(dump_after.inbound_rules_size(), 0);
  EXPECT_EQ(dump_after.outbound_rules_size(), 0);
}

TEST(ControlDispatch, AddWafRuleThenReadBackViaGetWafRule) {
  netpolicy::v1::AddWafRuleRequest req;
  req.add_pod_ips("10.1.1.1");
  req.set_name("grpc-test-app");
  auto* rule = req.add_rules();
  rule->set_id(1);
  rule->set_level(1);
  rule->set_type("sqli");
  rule->set_name("test-rule");
  rule->set_expr(".*");
  // "mode" is a match-location DSL (header_xxx(...)/body_xxx(...)), not an
  // action string -- ParseModeInfo (waf/rule.cc) expects this shape.
  rule->set_mode("header_path(match)");

  netpolicy::v1::StatusResponse resp;
  Dispatch(ControlOp::kAddWafRule, req, &resp);
  EXPECT_EQ(resp.status(), 0);

  Rules waf_rule;
  ASSERT_TRUE(daemon.WafRoot().GetWafRule("10.1.1.1", waf_rule));
  EXPECT_EQ(waf_rule.GetAppName(), "grpc-test-app");

  netpolicy::v1::DeleteWafRuleRequest del_req;
  del_req.add_pod_ips("10.1.1.1");
  netpolicy::v1::StatusResponse del_resp;
  Dispatch(ControlOp::kDeleteWafRule, del_req, &del_resp);
  EXPECT_EQ(del_resp.status(), 0);
  EXPECT_FALSE(daemon.WafRoot().GetWafRule("10.1.1.1", waf_rule));
}

TEST(ControlDispatch, SetLogLevelUpdatesGlobal) {
  netpolicy::v1::SetLogLevelRequest req;
  req.set_level(2);
  netpolicy::v1::StatusResponse resp;
  Dispatch(ControlOp::kSetLogLevel, req, &resp);
  EXPECT_EQ(resp.status(), 0);
  EXPECT_EQ(g_log_level, 2);
  g_log_level = 0; // restore default so later tests aren't affected
}

TEST(ProtoJsonBridge, AddPolicyRuleRequestProducesExpectedJsonShape) {
  netpolicy::v1::AddPolicyRuleRequest req;
  req.set_policy_name("json-shape-test");
  auto* rule = req.add_rules();
  rule->set_action(netpolicy::v1::POLICY_ACTION_ALERT);
  rule->set_direction(netpolicy::v1::FLOW_DIRECTION_EGRESS);
  rule->set_protocol(netpolicy::v1::L4_PROTOCOL_TCP);
  rule->set_priority(5);
  auto* port = rule->add_ports();
  port->set_port(80);
  port->set_end_port(90);
  auto* from = rule->add_from_addresses();
  from->set_ip("1.2.3.4");
  from->set_pod_id(7);
  auto* to = rule->add_to_addresses();
  to->set_ip("5.6.7.8");

  std::string json_text = grpc_bridge::BuildAddPolicyRuleJson(req);
  cJSON* root = cJSON_Parse(json_text.c_str());
  ASSERT_NE(root, nullptr);
  EXPECT_STREQ(cJSON_GetObjectItem(root, "policy_name")->valuestring, "json-shape-test");
  cJSON* rules = cJSON_GetObjectItem(root, "rules");
  ASSERT_EQ(cJSON_GetArraySize(rules), 1);
  cJSON* r = cJSON_GetArrayItem(rules, 0);
  EXPECT_STREQ(cJSON_GetObjectItem(r, "action")->valuestring, "Alert");
  EXPECT_STREQ(cJSON_GetObjectItem(r, "direction")->valuestring, "egress");
  EXPECT_STREQ(cJSON_GetObjectItem(r, "protocol")->valuestring, "TCP");
  EXPECT_EQ(cJSON_GetObjectItem(r, "priority")->valueint, 5);
  cJSON* ports = cJSON_GetObjectItem(r, "ports");
  ASSERT_EQ(cJSON_GetArraySize(ports), 1);
  // legacy wire key is "endPort" (camelCase), net-policy.cpp
  EXPECT_EQ(cJSON_GetObjectItem(cJSON_GetArrayItem(ports, 0), "endPort")->valueint, 90);
  cJSON_Delete(root);
}

TEST(ProtoJsonBridge, GetAllConfigCJsonConvertsToTypedProto) {
  cJSON* config = cJSON_CreateObject();
  cJSON* inbound = cJSON_CreateArray();
  cJSON* entry = cJSON_CreateObject();
  cJSON_AddStringToObject(entry, "policy_name", "p1");
  cJSON_AddNumberToObject(entry, "priority", 3);
  cJSON_AddStringToObject(entry, "direction", "ingress");
  cJSON_AddStringToObject(entry, "action", "Allow");
  cJSON_AddStringToObject(entry, "protocol", "TCP");
  cJSON_AddNumberToObject(entry, "protocol_int", 6);
  cJSON_AddStringToObject(entry, "from_address", "1.1.1.1");
  cJSON_AddStringToObject(entry, "to_address", "2.2.2.2");
  cJSON_AddItemToArray(inbound, entry);
  cJSON_AddItemToObject(config, "inbound_rules", inbound);
  cJSON_AddItemToObject(config, "outbound_rules", cJSON_CreateArray());

  netpolicy::v1::DumpConfigResponse out;
  grpc_bridge::ConvertConfigCJsonToProto(config, &out);
  ASSERT_EQ(out.inbound_rules_size(), 1);
  EXPECT_EQ(out.inbound_rules(0).policy_name(), "p1");
  EXPECT_EQ(out.inbound_rules(0).priority(), 3);
  EXPECT_EQ(out.inbound_rules(0).protocol_int(), 6);
  cJSON_Delete(config);
}

} // namespace
