#pragma once

#include "grpc/event_bridge.h"
#include "proto/net_policy_events.grpc.pb.h"

namespace grpc_bridge {

/*Streaming replacement for PostServer (port 8888). One active SubscribeEvents
 *call runs on its own dedicated gRPC thread and may block that thread on a
 *slow client -- never the epoll thread, and never shared with another RPC.
 *See event_bridge.h for how events get here from the epoll thread.*/
class EventServiceImpl final : public netpolicy::v1::NetPolicyEvents::Service {
public:
  explicit EventServiceImpl(EventBridge& bridge) : bridge_(bridge) {}

  grpc::Status SubscribeEvents(grpc::ServerContext* context,
                                const netpolicy::v1::SubscribeEventsRequest* request,
                                grpc::ServerWriter<netpolicy::v1::PolicyEvent>* writer) override;

private:
  EventBridge& bridge_;
};

} // namespace grpc_bridge
