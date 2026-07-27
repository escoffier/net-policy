#pragma once

#include <memory>
#include <thread>

#include <grpcpp/grpcpp.h>

#include "grpc/control_service.h"
#include "grpc/event_service.h"

namespace grpc_bridge {

/*port for the new gRPC control/event server; distinct from the existing
 *raw-socket ports (9999 control, 8888 push) -- both keep running untouched*/
inline constexpr int kGrpcPort = 50051;

/*Owns the gRPC server and the eventfd that wakes the epoll loop when a
 *control RPC is queued. RunNetPolicyDaemon (net-policy.cpp) calls Start()
 *once at startup, alongside the existing raw-socket server setup, then
 *registers WakeFd() with the same epoll instance itself -- DispatchGrpcControlOp
 *and the RcvEpollCb it's wired through stay local to net-policy.cpp, exactly
 *like the rest of that file's TU-local handlers, so this class has no
 *dependency on net-policy.h.*/
class GrpcServer {
public:
  /*binds to 0.0.0.0:<port> (port 0 lets the OS pick an ephemeral port, used
   *by tests); returns 0 on success. Non-blocking -- BuildAndStart() returns
   *immediately and RPCs run on gRPC's own thread pool.*/
  int Start(int port = kGrpcPort);
  void Shutdown();

  int WakeFd() const { return wake_fd_; }
  int Port() const { return bound_port_; }

private:
  int wake_fd_ = -1;
  int bound_port_ = 0;
  ControlServiceImpl control_service_;
  EventServiceImpl event_service_;
  std::unique_ptr<grpc::Server> server_;
  std::thread wait_thread_;
};

} // namespace grpc_bridge
