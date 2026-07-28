#include "grpc/work_queue.h"

#include <unistd.h>

namespace grpc_bridge {

ControlWorkQueue::ControlWorkQueue(int wake_fd) : wake_fd_(wake_fd) {}

void ControlWorkQueue::Push(ControlWorkItem* item) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push_back(item);
  }
  /*wake the epoll loop; best-effort -- if this write is ever lost, the epoll
   *thread still drains everything queued on its next unrelated wakeup*/
  uint64_t one = 1;
  (void)write(wake_fd_, &one, sizeof(one));
}

std::vector<ControlWorkItem*> ControlWorkQueue::DrainAll() {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<ControlWorkItem*> items(queue_.begin(), queue_.end());
  queue_.clear();
  return items;
}

} // namespace grpc_bridge
