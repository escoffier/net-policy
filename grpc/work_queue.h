#pragma once

#include <deque>
#include <future>
#include <mutex>
#include <vector>

#include <google/protobuf/message.h>
#include <grpcpp/grpcpp.h>

namespace grpc_bridge {

enum class ControlOp {
  kPodUp,
  kPodDown,
  kAddPolicyRule,
  kDeletePolicyRule,
  kAddWafRule,
  kDeleteWafRule,
  kDumpHeapProfile,
  kDumpConfig,
  kDumpConnections,
  kResetConfig,
  kUpdateNodeConfig,
  kSetLogLevel,
};

/*One item per inbound control RPC. Allocated on the gRPC handler thread's stack
 *(see EnqueueAndWait, grpc/control_service.cc), pushed onto the queue by pointer,
 *and mutated only by the epoll thread (via DispatchGrpcControlOp in net-policy.cpp)
 *until `done` is fulfilled -- after which the gRPC handler thread resumes and the
 *item goes out of scope. There is never more than one writer to a given item's
 *`response`/`status` fields at a time, which is what lets this cross a thread
 *boundary with no lock of its own.*/
struct ControlWorkItem {
  ControlOp op;
  const google::protobuf::Message* request;
  google::protobuf::Message* response;
  grpc::Status status;
  std::promise<void> done;
};

/*Thread-safe multi-producer/single-consumer queue: any number of gRPC handler
 *threads call Push(); exactly one consumer (the epoll loop, woken via the eventfd
 *passed at construction) calls DrainAll(). This is the only synchronization this
 *migration adds -- g_microseg/RootContext/the policy trees remain single-writer,
 *touched only from inside DispatchGrpcControlOp on the epoll thread.*/
class ControlWorkQueue {
public:
  explicit ControlWorkQueue(int wake_fd);

  void Push(ControlWorkItem* item);              // gRPC handler thread
  std::vector<ControlWorkItem*> DrainAll();       // epoll thread only

private:
  int wake_fd_;
  std::mutex mutex_;
  std::deque<ControlWorkItem*> queue_;
};

/*Process-wide singleton, constructed by GrpcServer::Start before the server
 *starts accepting RPCs.*/
void InitControlWorkQueue(int wake_fd);
ControlWorkQueue& GetControlWorkQueue();

} // namespace grpc_bridge

/*Implemented in net-policy.cpp, where it has direct access to g_microseg,
 *RootContext, and the legacy parsing/policy functions -- see the migration
 *plan for why this lives there instead of grpc/. Declared here (rather than
 *kept file-static) so tests can drive it directly without going through a
 *real gRPC transport.*/
void DispatchGrpcControlOp(int32_t epoll_fd, grpc_bridge::ControlWorkItem& item);

/*Epoll callback (RcvCbFunc-shaped) for the gRPC work-queue wake eventfd;
 *drains ControlWorkQueue and runs each item through DispatchGrpcControlOp.
 *Implemented in net-policy.cpp; declared here so an end-to-end test can
 *register it on its own test-driven epoll loop, mirroring exactly how
 *RunNetPolicyDaemon registers it in production.*/
int32_t DispatchGrpcWorkQueueEvent(int32_t epoll_fd, int32_t fd, void* ptr);

