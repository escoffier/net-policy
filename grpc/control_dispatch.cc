#include "grpc/control_dispatch.h"

#include <cerrno>
#include <cstring>
#include <sys/eventfd.h>
#include <unistd.h>

#include "log.h"

namespace grpc_bridge {

GrpcDispatchQueue::GrpcDispatchQueue(int wake_fd) : wake_fd_(wake_fd) {}

void GrpcDispatchQueue::Push(GrpcDispatchItem* item) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push_back(item);
  }
  uint64_t one = 1;
  ssize_t written = write(wake_fd_, &one, sizeof(one));
  if (written < 0) {
    LOG_E("grpc dispatch queue wake write failed, %s; item may not be processed until the next unrelated wake", strerror(errno));
  }
}

std::vector<GrpcDispatchItem*> GrpcDispatchQueue::DrainAll() {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<GrpcDispatchItem*> drained(queue_.begin(), queue_.end());
  queue_.clear();
  return drained;
}

} // namespace grpc_bridge
