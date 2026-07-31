#include <chrono>
#include <thread>

#include <gtest/gtest.h>
#include <grpcpp/grpcpp.h>

#include "grpc/event_bridge.h"
#include "grpc/grpc_server.h"
#include "net-policy.h"
#include "proto/net_policy_events.grpc.pb.h"

namespace {

/*Drives the gRPC event server for real over a real channel/stub -- the
 *ControlService equivalent of this now lives in
 *tests/grpc_rust_control_e2e_test.cc, since ControlService itself moved to
 *the Rust server (grpc/control_dispatch.h). EventService has no
 *epoll/work-queue dependency (see grpc/event_bridge.h), so no epoll loop is
 *needed here: PublishPolicyMatch is called directly from this test's thread
 *and SubscribeEvents runs on its own dedicated gRPC thread.*/
class GrpcEndToEndTest : public ::testing::Test {
protected:
  void SetUp() override {
    ASSERT_EQ(server_.Start(/*port=*/0), 0);
    daemon_.WireEventBridge(&server_.GetEventBridge());

    auto channel = grpc::CreateChannel("localhost:" + std::to_string(server_.Port()),
                                        grpc::InsecureChannelCredentials());
    events_stub_ = netpolicy::v1::NetPolicyEvents::NewStub(channel);
  }

  void TearDown() override { server_.Shutdown(); }

  DaemonContext daemon_;
  grpc_bridge::GrpcServer server_;
  std::unique_ptr<netpolicy::v1::NetPolicyEvents::Stub> events_stub_;
};

TEST_F(GrpcEndToEndTest, SubscribeEventsStreamReceivesPublishedPolicyMatch) {
  grpc::ClientContext ctx;
  netpolicy::v1::SubscribeEventsRequest req;
  req.set_client_id("e2e-test-subscriber");
  std::unique_ptr<grpc::ClientReader<netpolicy::v1::PolicyEvent>> reader =
      events_stub_->SubscribeEvents(&ctx, req);

  // give the server-side stream a moment to actually start before publishing
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  FiveTuple tuple;
  tuple.proto_ = IPPROTO_TCP;
  tuple.src_port_ = 55555;
  tuple.dst_port_ = 443;
  tuple.src_addr_ = "172.16.0.1";
  tuple.dst_addr_ = "172.16.0.2";
  server_.GetEventBridge().PublishPolicyMatch(tuple, NetPolicyRule::kDeny, FlowDir::kEgress,
                                               "e2e-event-policy");

  netpolicy::v1::PolicyEvent event;
  ASSERT_TRUE(reader->Read(&event));
  ASSERT_TRUE(event.has_policy_match());
  EXPECT_EQ(event.policy_match().src_port(), 55555u);
  EXPECT_EQ(event.policy_match().policy_name(), "e2e-event-policy");

  ctx.TryCancel();
}

} // namespace
