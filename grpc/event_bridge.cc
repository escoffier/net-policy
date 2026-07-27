#include "grpc/event_bridge.h"

#include <memory>

namespace grpc_bridge {

namespace {

std::unique_ptr<EventBridge> g_event_bridge = std::make_unique<EventBridge>();

/*mirrors GetProtoString's IPPROTO_* mapping, net-policy.cpp:68-79*/
netpolicy::v1::L4Protocol ProtoToL4Protocol(uint8_t proto) {
  switch (proto) {
  case IPPROTO_TCP:  return netpolicy::v1::L4_PROTOCOL_TCP;
  case IPPROTO_UDP:  return netpolicy::v1::L4_PROTOCOL_UDP;
  case IPPROTO_ICMP: return netpolicy::v1::L4_PROTOCOL_ICMP;
  default:           return netpolicy::v1::L4_PROTOCOL_UNSPECIFIED;
  }
}

netpolicy::v1::PolicyAction NetPolicyRuleToProto(NetPolicyRule action) {
  switch (action) {
  case NetPolicyRule::kAllow: return netpolicy::v1::POLICY_ACTION_ALLOW;
  case NetPolicyRule::kMark:  return netpolicy::v1::POLICY_ACTION_ALERT;
  case NetPolicyRule::kDeny:  return netpolicy::v1::POLICY_ACTION_DENY;
  default:                    return netpolicy::v1::POLICY_ACTION_UNSPECIFIED;
  }
}

netpolicy::v1::FlowDirection FlowDirToProto(FlowDir dir) {
  return (dir == FlowDir::kIngress) ? netpolicy::v1::FLOW_DIRECTION_INGRESS
                                    : netpolicy::v1::FLOW_DIRECTION_EGRESS;
}

} // namespace

void EventBridge::PublishPolicyMatch(FiveTuple& tuple, NetPolicyRule action, FlowDir dir,
                                      const std::string& rule_key) {
  netpolicy::v1::PolicyEvent event;
  auto* match = event.mutable_policy_match();
  match->set_protocol(ProtoToL4Protocol(tuple.proto_));
  match->set_action(NetPolicyRuleToProto(action));
  match->set_direction(FlowDirToProto(dir));
  match->set_src_port(tuple.src_port_);
  match->set_dst_port(tuple.dst_port_);
  match->set_src_ip(tuple.src_addr_);
  match->set_dst_ip(tuple.dst_addr_);
  match->set_policy_name(rule_key);
  Push(std::move(event));
}

void EventBridge::PublishWafAttack(Rules& rule_ctx, AttackedLog& log) {
  netpolicy::v1::PolicyEvent event;
  auto* attack = event.mutable_waf_attack();
  attack->set_service_id(rule_ctx.app_id_);
  attack->set_res_name(rule_ctx.res_name_);
  attack->set_app_name(rule_ctx.GetAppName());
  attack->set_res_kind(rule_ctx.res_kind_);
  attack->set_k8s_namespace(rule_ctx.pod_namespace_);
  attack->set_cluster_key(rule_ctx.cluster_key_);
  attack->set_action(log.action_);
  attack->set_attack_ip(log.attack_ip_);
  attack->set_attacked_app(log.attacked_app_);
  attack->set_attack_load(log.attack_load_);
  attack->set_attack_time(log.attack_time_);
  attack->set_rule_id(log.rule_id_);
  attack->set_rule_name(log.rule_name_);
  attack->set_req_pkg(log.req_pkg_);
  attack->set_rsp_pkg(log.rsp_pkg_);
  attack->set_attack_type(log.type_);
  attack->set_attacked_url(log.attacked_url_);
  attack->set_rsp_content_type(log.rsp_content_type_);
  Push(std::move(event));
}

void EventBridge::Push(netpolicy::v1::PolicyEvent event) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (queue_.size() >= kEventQueueCapacity) {
    LOG_W("gRPC event queue full (capacity %zu), dropping oldest event", kEventQueueCapacity);
    queue_.pop_front();
  }
  queue_.push_back(std::move(event));
  cv_.notify_one();
}

bool EventBridge::WaitAndPop(netpolicy::v1::PolicyEvent* out, std::chrono::milliseconds timeout) {
  std::unique_lock<std::mutex> lock(mutex_);
  if (!cv_.wait_for(lock, timeout, [this] { return !queue_.empty(); }))
    return false;
  *out = std::move(queue_.front());
  queue_.pop_front();
  return true;
}

EventBridge& GetEventBridge() { return *g_event_bridge; }

} // namespace grpc_bridge
