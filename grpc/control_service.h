#pragma once

#include "grpc/work_queue.h"
#include "proto/net_policy_control.grpc.pb.h"

namespace grpc_bridge {

/*Implements the NetPolicyControl RPCs by handing each request to the epoll
 *thread (via the ControlWorkQueue reference passed in at construction, owned
 *by GrpcServer -- see grpc_server.h) and blocking this gRPC handler thread
 *until DispatchGrpcControlOp (net-policy.cpp) has run it through the same
 *legacy functions the raw-socket control channel calls today. No policy/WAF
 *state is touched from this class directly.*/
class ControlServiceImpl final : public netpolicy::v1::NetPolicyControl::Service {
public:
  explicit ControlServiceImpl(ControlWorkQueue& queue) : queue_(queue) {}

  grpc::Status PodUp(grpc::ServerContext* context, const netpolicy::v1::PodUpRequest* request,
                      netpolicy::v1::StatusResponse* response) override;
  grpc::Status PodDown(grpc::ServerContext* context, const netpolicy::v1::PodDownRequest* request,
                        netpolicy::v1::StatusResponse* response) override;
  grpc::Status AddPolicyRule(grpc::ServerContext* context, const netpolicy::v1::AddPolicyRuleRequest* request,
                              netpolicy::v1::StatusResponse* response) override;
  grpc::Status DeletePolicyRule(grpc::ServerContext* context, const netpolicy::v1::DeletePolicyRuleRequest* request,
                                 netpolicy::v1::StatusResponse* response) override;
  grpc::Status AddWafRule(grpc::ServerContext* context, const netpolicy::v1::AddWafRuleRequest* request,
                           netpolicy::v1::StatusResponse* response) override;
  grpc::Status DeleteWafRule(grpc::ServerContext* context, const netpolicy::v1::DeleteWafRuleRequest* request,
                              netpolicy::v1::StatusResponse* response) override;
  grpc::Status DumpHeapProfile(grpc::ServerContext* context, const netpolicy::v1::DumpHeapProfileRequest* request,
                                netpolicy::v1::StatusResponse* response) override;
  grpc::Status DumpConfig(grpc::ServerContext* context, const netpolicy::v1::DumpConfigRequest* request,
                           netpolicy::v1::DumpConfigResponse* response) override;
  grpc::Status DumpConnections(grpc::ServerContext* context, const netpolicy::v1::DumpConnectionsRequest* request,
                                netpolicy::v1::DumpConnectionsResponse* response) override;
  grpc::Status ResetConfig(grpc::ServerContext* context, const netpolicy::v1::ResetConfigRequest* request,
                            netpolicy::v1::StatusResponse* response) override;
  grpc::Status UpdateNodeConfig(grpc::ServerContext* context, const netpolicy::v1::UpdateNodeConfigRequest* request,
                                 netpolicy::v1::StatusResponse* response) override;
  grpc::Status SetLogLevel(grpc::ServerContext* context, const netpolicy::v1::SetLogLevelRequest* request,
                            netpolicy::v1::StatusResponse* response) override;

private:
  grpc::Status EnqueueAndWait(ControlOp op, const google::protobuf::Message& request,
                               google::protobuf::Message* response);

  ControlWorkQueue& queue_;
};

} // namespace grpc_bridge
