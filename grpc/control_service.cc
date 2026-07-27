#include "grpc/control_service.h"

#include "grpc/work_queue.h"

namespace grpc_bridge {

namespace {

/*Builds a ControlWorkItem on this (gRPC handler) thread's stack, pushes it to
 *the epoll thread via ControlWorkQueue, and blocks until DispatchGrpcControlOp
 *(net-policy.cpp) has run it and fulfilled `done`. This is the only place
 *a control RPC crosses from the gRPC thread pool onto the epoll thread.*/
grpc::Status EnqueueAndWait(ControlOp op, const google::protobuf::Message* request,
                             google::protobuf::Message* response) {
  ControlWorkItem item;
  item.op = op;
  item.request = request;
  item.response = response;
  std::future<void> future = item.done.get_future();
  GetControlWorkQueue().Push(&item);
  future.wait();
  return item.status;
}

} // namespace

grpc::Status ControlServiceImpl::PodUp(grpc::ServerContext*, const netpolicy::v1::PodUpRequest* request,
                                        netpolicy::v1::StatusResponse* response) {
  return EnqueueAndWait(ControlOp::kPodUp, request, response);
}

grpc::Status ControlServiceImpl::PodDown(grpc::ServerContext*, const netpolicy::v1::PodDownRequest* request,
                                          netpolicy::v1::StatusResponse* response) {
  return EnqueueAndWait(ControlOp::kPodDown, request, response);
}

grpc::Status ControlServiceImpl::AddPolicyRule(grpc::ServerContext*, const netpolicy::v1::AddPolicyRuleRequest* request,
                                                netpolicy::v1::StatusResponse* response) {
  return EnqueueAndWait(ControlOp::kAddPolicyRule, request, response);
}

grpc::Status ControlServiceImpl::DeletePolicyRule(grpc::ServerContext*,
                                                   const netpolicy::v1::DeletePolicyRuleRequest* request,
                                                   netpolicy::v1::StatusResponse* response) {
  return EnqueueAndWait(ControlOp::kDeletePolicyRule, request, response);
}

grpc::Status ControlServiceImpl::AddWafRule(grpc::ServerContext*, const netpolicy::v1::AddWafRuleRequest* request,
                                             netpolicy::v1::StatusResponse* response) {
  return EnqueueAndWait(ControlOp::kAddWafRule, request, response);
}

grpc::Status ControlServiceImpl::DeleteWafRule(grpc::ServerContext*, const netpolicy::v1::DeleteWafRuleRequest* request,
                                                netpolicy::v1::StatusResponse* response) {
  return EnqueueAndWait(ControlOp::kDeleteWafRule, request, response);
}

grpc::Status ControlServiceImpl::DumpHeapProfile(grpc::ServerContext*,
                                                  const netpolicy::v1::DumpHeapProfileRequest* request,
                                                  netpolicy::v1::StatusResponse* response) {
  return EnqueueAndWait(ControlOp::kDumpHeapProfile, request, response);
}

grpc::Status ControlServiceImpl::DumpConfig(grpc::ServerContext*, const netpolicy::v1::DumpConfigRequest* request,
                                             netpolicy::v1::DumpConfigResponse* response) {
  return EnqueueAndWait(ControlOp::kDumpConfig, request, response);
}

grpc::Status ControlServiceImpl::DumpConnections(grpc::ServerContext*,
                                                  const netpolicy::v1::DumpConnectionsRequest* request,
                                                  netpolicy::v1::DumpConnectionsResponse* response) {
  return EnqueueAndWait(ControlOp::kDumpConnections, request, response);
}

grpc::Status ControlServiceImpl::ResetConfig(grpc::ServerContext*, const netpolicy::v1::ResetConfigRequest* request,
                                              netpolicy::v1::StatusResponse* response) {
  return EnqueueAndWait(ControlOp::kResetConfig, request, response);
}

grpc::Status ControlServiceImpl::UpdateNodeConfig(grpc::ServerContext*,
                                                   const netpolicy::v1::UpdateNodeConfigRequest* request,
                                                   netpolicy::v1::StatusResponse* response) {
  return EnqueueAndWait(ControlOp::kUpdateNodeConfig, request, response);
}

grpc::Status ControlServiceImpl::SetLogLevel(grpc::ServerContext*, const netpolicy::v1::SetLogLevelRequest* request,
                                              netpolicy::v1::StatusResponse* response) {
  return EnqueueAndWait(ControlOp::kSetLogLevel, request, response);
}

} // namespace grpc_bridge
