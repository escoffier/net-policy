#include "grpc/control_dispatch.h"

#include <sys/eventfd.h>
#include <unistd.h>

namespace grpc_bridge {

GrpcDispatchQueue::GrpcDispatchQueue(int wake_fd) : wake_fd_(wake_fd) {}

void GrpcDispatchQueue::Push(GrpcDispatchItem* item) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push_back(item);
  }
  uint64_t one = 1;
  ssize_t written = write(wake_fd_, &one, sizeof(one));
  (void)written; // best-effort wake; DrainAll's caller polls on a timeout regardless
}

std::vector<GrpcDispatchItem*> GrpcDispatchQueue::DrainAll() {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<GrpcDispatchItem*> drained(queue_.begin(), queue_.end());
  queue_.clear();
  return drained;
}

} // namespace grpc_bridge
