#pragma once

#include <memory>
#include <thread>

#include <grpcpp/grpcpp.h>

#include "grpc/event_service.h"

namespace grpc_bridge {

/*port for the gRPC event server; distinct from the existing raw-socket ports
 *(9999 control, 8888 push) and from the Rust ControlService's production
 *port (50051, grpc/control_dispatch.h) -- all keep running untouched*/
inline constexpr int kGrpcPort = 50052;

/*Owns the gRPC event server. RunNetPolicyDaemon (net-policy.cpp) calls
 *Start() once at startup, alongside the existing raw-socket server setup
 *and the separate Rust ControlService. This class has no dependency on
 *net-policy.h.*/
class GrpcServer {
public:
  /*event_bridge_ is constructed eagerly here (not lazily in Start()) so
   *event_service_ can take a reference to it at construction time -- no
   *singletons anywhere in this class.*/
  GrpcServer();

  /*binds to 0.0.0.0:<port> (port 0 lets the OS pick an ephemeral port, used
   *by tests); returns 0 on success. Non-blocking -- BuildAndStart() returns
   *immediately and RPCs run on gRPC's own thread pool.*/
  int Start(int port = kGrpcPort);
  void Shutdown();

  int Port() const { return bound_port_; }
  EventBridge& GetEventBridge() { return event_bridge_; }

private:
  int bound_port_ = 0;
  EventBridge event_bridge_;              // must precede event_service_
  EventServiceImpl event_service_;
  std::unique_ptr<grpc::Server> server_;
  std::thread wait_thread_;
};

} // namespace grpc_bridge
