#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <vector>

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

} // namespace grpc_bridge
