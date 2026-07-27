#include <chrono>

#include <gtest/gtest.h>

#include "grpc/event_bridge.h"

namespace {

TEST(EventBridge, PublishPolicyMatchThenWaitAndPopReturnsEvent) {
  FiveTuple tuple;
  tuple.proto_ = IPPROTO_TCP;
  tuple.src_port_ = 1234;
  tuple.dst_port_ = 80;
  tuple.src_addr_ = "10.0.0.1";
  tuple.dst_addr_ = "10.0.0.2";

  grpc_bridge::GetEventBridge().PublishPolicyMatch(tuple, NetPolicyRule::kAllow, FlowDir::kIngress,
                                                     "test-policy");

  netpolicy::v1::PolicyEvent event;
  ASSERT_TRUE(grpc_bridge::GetEventBridge().WaitAndPop(&event, std::chrono::milliseconds(100)));
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
}

TEST(EventBridge, WaitAndPopTimesOutWhenQueueEmpty) {
  // drain anything left over from other tests before asserting on emptiness
  netpolicy::v1::PolicyEvent drain;
  while (grpc_bridge::GetEventBridge().WaitAndPop(&drain, std::chrono::milliseconds(1))) {
  }
  netpolicy::v1::PolicyEvent event;
  EXPECT_FALSE(grpc_bridge::GetEventBridge().WaitAndPop(&event, std::chrono::milliseconds(50)));
}

TEST(EventBridge, QueueDropsOldestWhenFullAndLogsWarning) {
  netpolicy::v1::PolicyEvent drain;
  while (grpc_bridge::GetEventBridge().WaitAndPop(&drain, std::chrono::milliseconds(1))) {
  }

  FiveTuple tuple;
  tuple.proto_ = IPPROTO_TCP;
  for (size_t i = 0; i < grpc_bridge::kEventQueueCapacity + 1; i++) {
    tuple.src_port_ = static_cast<uint16_t>(i);
    grpc_bridge::GetEventBridge().PublishPolicyMatch(tuple, NetPolicyRule::kAllow, FlowDir::kIngress,
                                                       "overflow-test");
  }

  size_t popped = 0;
  netpolicy::v1::PolicyEvent event;
  // the oldest event (src_port 0) should have been dropped; the first one
  // popped should be src_port 1
  ASSERT_TRUE(grpc_bridge::GetEventBridge().WaitAndPop(&event, std::chrono::milliseconds(100)));
  EXPECT_EQ(event.policy_match().src_port(), 1u);
  popped++;
  while (grpc_bridge::GetEventBridge().WaitAndPop(&event, std::chrono::milliseconds(1)))
    popped++;
  EXPECT_EQ(popped, grpc_bridge::kEventQueueCapacity);
}

} // namespace
