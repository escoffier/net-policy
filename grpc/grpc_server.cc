#include "grpc/grpc_server.h"

#include <sys/eventfd.h>

namespace grpc_bridge {

GrpcServer::GrpcServer()
    : wake_fd_(eventfd(0, EFD_NONBLOCK)),
      control_work_queue_(wake_fd_),
      control_service_(control_work_queue_),
      event_service_(event_bridge_) {}

int GrpcServer::Start(int port) {
  if (wake_fd_ < 0)
    return -1;

  std::string address = "0.0.0.0:" + std::to_string(port);
  grpc::ServerBuilder builder;
  builder.AddListeningPort(address, grpc::InsecureServerCredentials(), &bound_port_);
  builder.RegisterService(&control_service_);
  builder.RegisterService(&event_service_);
  server_ = builder.BuildAndStart();
  if (!server_)
    return -2;

  /*server_->Wait() blocks until Shutdown() -- must not run on the epoll
   *thread, which is itself permanently inside its own epoll_wait loop*/
  wait_thread_ = std::thread([this] { server_->Wait(); });
  return 0;
}

void GrpcServer::Shutdown() {
  if (server_)
    server_->Shutdown();
  if (wait_thread_.joinable())
    wait_thread_.join();
}

} // namespace grpc_bridge
