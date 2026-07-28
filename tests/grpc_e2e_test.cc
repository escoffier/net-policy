#include <atomic>
#include <chrono>
#include <thread>

#include <gtest/gtest.h>
#include <grpcpp/grpcpp.h>
#include <sys/epoll.h>

#include "grpc/event_bridge.h"
#include "grpc/grpc_server.h"
#include "grpc/work_queue.h"
#include "net-policy.h"
#include "proto/net_policy_control.grpc.pb.h"
#include "proto/net_policy_events.grpc.pb.h"

namespace {

/*Drives a real epoll loop on a test thread, exactly like RunNetPolicyDaemon's
 *production loop (net-policy.cpp), so the queue/eventfd bridge between gRPC
 *handler threads and DispatchGrpcControlOp is exercised for real -- not just
 *called directly as in grpc_control_service_test.cc.*/
class GrpcEndToEndTest : public ::testing::Test {
protected:
  void SetUp() override {
    epfd_ = epoll_create(32);
    ASSERT_GT(epfd_, 0);

    ASSERT_EQ(server_.Start(/*port=*/0), 0);
    daemon_.WireGrpc(&server_.GetControlWorkQueue(), &server_.GetEventBridge());
    wake_cb_.fd_ = server_.WakeFd();
    wake_cb_.epoll_in_func_ = DispatchGrpcWorkQueueEvent;
    wake_cb_.daemon_ = &daemon_;
    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.ptr = &wake_cb_;
    ASSERT_EQ(epoll_ctl(epfd_, EPOLL_CTL_ADD, wake_cb_.fd_, &ev), 0);

    stop_ = false;
    loop_thread_ = std::thread([this] { RunEpollLoop(); });

    auto channel = grpc::CreateChannel("localhost:" + std::to_string(server_.Port()),
                                        grpc::InsecureChannelCredentials());
    control_stub_ = netpolicy::v1::NetPolicyControl::NewStub(channel);
    events_stub_ = netpolicy::v1::NetPolicyEvents::NewStub(channel);
  }

  void TearDown() override {
    stop_ = true;
    if (loop_thread_.joinable())
      loop_thread_.join();
    server_.Shutdown();
    if (epfd_ > 0)
      close(epfd_);
  }

  void RunEpollLoop() {
    struct epoll_event events[8];
    while (!stop_) {
      int nfds = epoll_wait(epfd_, events, 8, /*timeout_ms=*/50);
      for (int i = 0; i < nfds; i++) {
        auto* cb = static_cast<RCV_EPOLL_CB*>(events[i].data.ptr);
        if (cb && cb->epoll_in_func_)
          cb->epoll_in_func_(epfd_, cb->fd_, cb);
      }
    }
  }

  int epfd_ = -1;
  RCV_EPOLL_CB wake_cb_ = {};
  DaemonContext daemon_;
  grpc_bridge::GrpcServer server_;
  std::atomic<bool> stop_{false};
  std::thread loop_thread_;
  std::unique_ptr<netpolicy::v1::NetPolicyControl::Stub> control_stub_;
  std::unique_ptr<netpolicy::v1::NetPolicyEvents::Stub> events_stub_;
};

TEST_F(GrpcEndToEndTest, AddPolicyRuleOverRealChannelThenReadBackViaDumpConfig) {
  netpolicy::v1::AddPolicyRuleRequest add_req;
  add_req.set_policy_name("e2e-test-policy");
  auto* rule = add_req.add_rules();
  rule->set_action(netpolicy::v1::POLICY_ACTION_ALLOW);
  rule->set_direction(netpolicy::v1::FLOW_DIRECTION_INGRESS);
  rule->set_priority(1);
  rule->add_from_addresses()->set_ip("192.168.0.1");
  rule->add_to_addresses()->set_ip("192.168.0.2");

  grpc::ClientContext add_ctx;
  netpolicy::v1::StatusResponse add_resp;
  grpc::Status status = control_stub_->AddPolicyRule(&add_ctx, add_req, &add_resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_EQ(add_resp.status(), 0);

  grpc::ClientContext dump_ctx;
  netpolicy::v1::DumpConfigRequest dump_req;
  dump_req.set_policy_name("e2e-test-policy");
  netpolicy::v1::DumpConfigResponse dump_resp;
  status = control_stub_->DumpConfig(&dump_ctx, dump_req, &dump_resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  ASSERT_EQ(dump_resp.inbound_rules_size(), 1);
  EXPECT_EQ(dump_resp.inbound_rules(0).policy_name(), "e2e-test-policy");

  grpc::ClientContext del_ctx;
  netpolicy::v1::DeletePolicyRuleRequest del_req;
  del_req.set_policy_name("e2e-test-policy");
  netpolicy::v1::StatusResponse del_resp;
  status = control_stub_->DeletePolicyRule(&del_ctx, del_req, &del_resp);
  ASSERT_TRUE(status.ok());
  EXPECT_EQ(del_resp.status(), 0);
}

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
