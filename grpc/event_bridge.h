#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <string>

#include "net-policy.h" // FiveTuple, NetPolicyRule, FlowDir -- value types only, no globals used
#include "waf/rule.h"   // Rules, AttackedLog -- value types only
#include "proto/net_policy_events.pb.h"

namespace grpc_bridge {

constexpr size_t kEventQueueCapacity = 256;

/*Bounded, thread-safe, drop-oldest-on-overflow queue bridging epoll-thread
 *event producers (PostServer::SendMatchMsg, PluginContext::onClose) to the
 *dedicated per-stream gRPC thread serving SubscribeEvents (see
 *event_service.h). Publish* methods are O(1) and never block -- dropping
 *under backpressure matches the existing "best-effort, no ack, no listener
 *means no-op" semantics of the legacy push channel (PostServer::SendMatchMsg,
 *net-policy.cpp:375-376) -- this is not a new guarantee gap, just the same
 *one carried over.*/
class EventBridge {
public:
  // Called from the epoll thread only (PostServer::SendMatchMsg / PluginContext::onClose).
  void PublishPolicyMatch(FiveTuple& tuple, NetPolicyRule action, FlowDir dir,
                           const std::string& rule_key);
  void PublishWafAttack(Rules& rule_ctx, AttackedLog& log);

  // Called from the streaming RPC's dedicated per-call thread only.
  bool WaitAndPop(netpolicy::v1::PolicyEvent* out, std::chrono::milliseconds timeout);

private:
  void Push(netpolicy::v1::PolicyEvent event);

  std::mutex mutex_;
  std::condition_variable cv_;
  std::deque<netpolicy::v1::PolicyEvent> queue_;
};

EventBridge& GetEventBridge();

} // namespace grpc_bridge
