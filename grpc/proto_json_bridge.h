#pragma once

#include <string>

#include "cjson.h"
#include "proto/net_policy_control.pb.h"

/*Translates between the new typed gRPC control-service messages and the JSON
 *shapes the existing (unchanged) legacy handlers expect -- ParseNetPolicy,
 *ParseNodeCfg, PluginRootContext::ParseConfiguration/RemoveWafRule, and
 *dumpConnectons all take a raw JSON blob today. Rather than reimplementing
 *their field-mapping logic a second time against protobuf types directly,
 *these builders reproduce the identical JSON so the unchanged functions can
 *be called as-is. This is a low-QPS administrative path (pod lifecycle,
 *policy/WAF CRUD, admin dumps), not the NFQUEUE packet hot path, so the extra
 *cJSON round-trip is immaterial -- and it keeps exactly one implementation of
 *each piece of business logic.*/
namespace grpc_bridge {

std::string BuildAddPolicyRuleJson(const netpolicy::v1::AddPolicyRuleRequest& req);
std::string BuildUpdateNodeConfigJson(const netpolicy::v1::UpdateNodeConfigRequest& req);
std::string BuildAddWafRuleJson(const netpolicy::v1::AddWafRuleRequest& req);
std::string BuildDeleteWafRuleJson(const netpolicy::v1::DeleteWafRuleRequest& req);
std::string BuildDumpConnectionsJson(const netpolicy::v1::DumpConnectionsRequest& req);
std::string BuildDumpHeapProfileJson(const netpolicy::v1::DumpHeapProfileRequest& req);

/*reverse direction: legacy cJSON* output -> typed proto response*/
void ConvertConfigCJsonToProto(cJSON* config, netpolicy::v1::DumpConfigResponse* out);
void ConvertConnectionsCJsonToProto(cJSON* conns, netpolicy::v1::DumpConnectionsResponse* out);

} // namespace grpc_bridge
