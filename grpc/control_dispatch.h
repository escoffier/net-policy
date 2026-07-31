#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <vector>
#include "rust/cxx.h"

class DaemonContext; // forward declaration; full type in net-policy.h

namespace grpc_bridge {

/*One item per inbound Rust-originated control RPC. Allocated on the calling
 *(Rust/tokio blocking) thread's stack, pushed onto the queue by pointer, and
 *run only by the epoll thread (via DispatchGrpcRustQueueEvent in
 *net-policy.cpp) until `done` is fulfilled -- mirrors ControlWorkItem's
 *existing single-writer contract in grpc/work_queue.h, just with a closure
 *instead of a protobuf Message* (which can't cross the cxx boundary).*/
struct GrpcDispatchItem {
  std::function<void()> work;
  std::promise<void> done;
};

/*Thread-safe multi-producer/single-consumer queue: any number of tokio
 *blocking threads call Push(); exactly one consumer (the epoll loop, woken
 *via the eventfd passed at construction) calls DrainAll(). Mirrors
 *ControlWorkQueue's existing shape in grpc/work_queue.h exactly.*/
class GrpcDispatchQueue {
public:
  explicit GrpcDispatchQueue(int wake_fd);

  void Push(GrpcDispatchItem* item);        // calling (tokio blocking) thread
  std::vector<GrpcDispatchItem*> DrainAll(); // epoll thread only

private:
  int wake_fd_;
  std::mutex mutex_;
  std::deque<GrpcDispatchItem*> queue_;
};

// Rust-callable dispatch functions. Each builds a closure capturing `daemon`
// by pointer, pushes it onto `queue`, blocks until the epoll thread
// (DispatchGrpcRustQueueEvent, net-policy.cpp) has run it, and returns the
// typed result. Implemented in net-policy.cpp, where DaemonContext's full
// definition and the legacy policy/WAF functions are already visible --
// mirrors where DispatchGrpcControlOp lives today.
int32_t GrpcDispatchResetConfig(DaemonContext* daemon, GrpcDispatchQueue* queue);

int32_t GrpcDispatchPodUp(DaemonContext* daemon, GrpcDispatchQueue* queue, int32_t epoll_fd,
                           int32_t pid, uint64_t pod_id);

int32_t GrpcDispatchPodDown(DaemonContext* daemon, GrpcDispatchQueue* queue, int32_t epoll_fd,
                             uint64_t pod_id);

int32_t GrpcDispatchDeletePolicyRule(DaemonContext* daemon, GrpcDispatchQueue* queue,
                                      rust::Str policy_name);

// Epoll callback (RcvCbFunc-shaped: int32_t(int32_t epoll_fd, int32_t fd,
// void* ptr)) for the Rust dispatch queue's wake eventfd. Drains `queue`
// (read from the registering RcvEpollCb, threaded through via `ptr`) and
// runs each item's closure on this (the epoll) thread. Implemented in
// net-policy.cpp since it needs RcvEpollCb's shape from net-policy.h.
int32_t DispatchGrpcRustQueueEvent(int32_t epoll_fd, int32_t fd, void* ptr);

} // namespace grpc_bridge
