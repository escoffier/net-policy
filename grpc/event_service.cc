#include "grpc/event_service.h"

#include <chrono>

#include "grpc/event_bridge.h"

namespace grpc_bridge {

grpc::Status EventServiceImpl::SubscribeEvents(grpc::ServerContext* context,
                                                const netpolicy::v1::SubscribeEventsRequest* /*request*/,
                                                grpc::ServerWriter<netpolicy::v1::PolicyEvent>* writer) {
  while (!context->IsCancelled()) {
    netpolicy::v1::PolicyEvent event;
    if (GetEventBridge().WaitAndPop(&event, std::chrono::milliseconds(500))) {
      if (!writer->Write(event))
        break; // client gone; this dedicated thread exits, epoll thread is unaffected
    }
  }
  return grpc::Status::OK;
}

} // namespace grpc_bridge
