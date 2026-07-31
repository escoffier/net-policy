#include <chrono>
#include <thread>

#include <gtest/gtest.h>
#include <grpcpp/grpcpp.h>

#include "net_policy_events_cxxbridge/lib.h"
#include "proto/net_policy_events.grpc.pb.h"

namespace {

// Mirrors GrpcRustControlEndToEndTest's SetUpTestSuite/TearDownTestSuite
// pattern (tests/grpc_rust_control_e2e_test.cc) -- the Rust event server
// binds once per process (no OnceLock re-entry guard needed here since
// start_event_server has no shared DaemonContext-style singleton state to
// protect, but starting two servers in the same process would still double-
// bind, so share one across the whole suite regardless).
class GrpcRustEventsEndToEndTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() {
    port_ = grpc_bridge::start_event_server(/*port=*/0);
    ASSERT_NE(port_, 0) << "rust event server failed to bind";
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  void SetUp() override {
    auto channel = grpc::CreateChannel("localhost:" + std::to_string(port_),
                                        grpc::InsecureChannelCredentials());
    stub_ = netpolicy::v1::NetPolicyEvents::NewStub(channel);
  }

  static uint16_t port_;
  std::unique_ptr<netpolicy::v1::NetPolicyEvents::Stub> stub_;
};

uint16_t GrpcRustEventsEndToEndTest::port_ = 0;

TEST_F(GrpcRustEventsEndToEndTest, SubscribeEventsReceivesPublishedPolicyMatch) {
  grpc::ClientContext ctx;
  netpolicy::v1::SubscribeEventsRequest req;
  req.set_client_id("test-client");
  auto reader = stub_->SubscribeEvents(&ctx, req);

  // give the server-side loop a moment to start polling before publishing
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  grpc_bridge::publish_policy_match(
      /*protocol=*/6, /*action=*/1, /*direction=*/0,
      /*src_port=*/1234, /*dst_port=*/80,
      "10.0.0.1", "10.0.0.2", "test-policy");

  netpolicy::v1::PolicyEvent event;
  ASSERT_TRUE(reader->Read(&event));
  ASSERT_TRUE(event.has_policy_match());
  const auto& match = event.policy_match();
  EXPECT_EQ(match.protocol(), netpolicy::v1::L4_PROTOCOL_TCP);
  EXPECT_EQ(match.action(), netpolicy::v1::POLICY_ACTION_ALLOW);
  EXPECT_EQ(match.direction(), netpolicy::v1::FLOW_DIRECTION_INGRESS);
  EXPECT_EQ(match.src_port(), 1234u);
  EXPECT_EQ(match.dst_port(), 80u);
  EXPECT_EQ(match.src_ip(), "10.0.0.1");
  EXPECT_EQ(match.dst_ip(), "10.0.0.2");
  EXPECT_EQ(match.policy_name(), "test-policy");

  ctx.TryCancel();
}

TEST_F(GrpcRustEventsEndToEndTest, SubscribeEventsReceivesPublishedWafAttack) {
  grpc::ClientContext ctx;
  netpolicy::v1::SubscribeEventsRequest req;
  req.set_client_id("test-client");
  auto reader = stub_->SubscribeEvents(&ctx, req);

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  grpc_bridge::publish_waf_attack(
      /*service_id=*/42, "res", "app", "kind", "ns", "cluster",
      "block", "1.2.3.4", "attacked-app", "load", /*attack_time=*/100,
      /*rule_id=*/7, "rule-name", "req", "rsp", "sqli", "url", "text/html");

  netpolicy::v1::PolicyEvent event;
  ASSERT_TRUE(reader->Read(&event));
  ASSERT_TRUE(event.has_waf_attack());
  const auto& attack = event.waf_attack();
  EXPECT_EQ(attack.service_id(), 42u);
  EXPECT_EQ(attack.res_name(), "res");
  EXPECT_EQ(attack.rule_id(), 7);
  EXPECT_EQ(attack.attacked_url(), "url");

  ctx.TryCancel();
}

// The server-side spawn_blocking loop has no direct C++-observable handle
// (unlike the old C++ EventServiceImpl, which ran on grpc++'s own thread
// pool where cancellation is entirely internal to that library too) -- the
// practical, externally-observable proxy for "the loop notices
// cancellation and exits promptly" is that the RPC itself actually
// terminates (grpc++ surfaces CANCELLED) rather than hanging forever.
TEST_F(GrpcRustEventsEndToEndTest, SubscribeEventsStopsAfterClientCancellation) {
  grpc::ClientContext ctx;
  netpolicy::v1::SubscribeEventsRequest req;
  req.set_client_id("cancel-test-client");
  auto reader = stub_->SubscribeEvents(&ctx, req);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  ctx.TryCancel();
  grpc::Status status = reader->Finish();
  // Finish() must return promptly (this test's own timeout, GTest's
  // default per-test deadline, is the backstop if it doesn't) with a
  // cancellation-shaped status rather than hang or report OK.
  EXPECT_EQ(status.error_code(), grpc::StatusCode::CANCELLED);
}

} // namespace
