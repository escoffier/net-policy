#include <chrono>
#include <thread>

#include <gtest/gtest.h>
#include <grpcpp/grpcpp.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "grpc/control_dispatch.h"
#include "net-policy.h"
#include "net_policy_control_cxxbridge/lib.h"
#include "proto/net_policy_control.grpc.pb.h"

namespace {

// The Rust control server (crates/net_policy_control) keeps its DaemonContext
// / GrpcDispatchQueue / epoll_fd pointers in a process-wide OnceLock and
// panics if start_control_server is called a second time in the same
// process. GTest constructs a fresh fixture instance (and, historically, ran
// SetUp/TearDown) per TEST_F, so starting the server per-test would abort
// this whole binary the moment a second TEST_F exists. Instead, the server
// (and the epoll loop thread that drives it) is started ONCE for the entire
// suite via SetUpTestSuite/TearDownTestSuite; each individual test only
// creates its own gRPC channel/stub against the already-known port.
class GrpcRustControlEndToEndTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() {
    epfd_ = epoll_create(32);
    ASSERT_GT(epfd_, 0);

    wake_fd_ = eventfd(0, EFD_NONBLOCK);
    ASSERT_GT(wake_fd_, 0);
    queue_ = new grpc_bridge::GrpcDispatchQueue(wake_fd_);
    daemon_ = new DaemonContext();
    daemon_->WireRustControlDispatch(queue_);

    wake_cb_.fd_ = wake_fd_;
    wake_cb_.epoll_in_func_ = grpc_bridge::DispatchGrpcRustQueueEvent;
    wake_cb_.daemon_ = daemon_;
    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.ptr = &wake_cb_;
    ASSERT_EQ(epoll_ctl(epfd_, EPOLL_CTL_ADD, wake_fd_, &ev), 0);

    stop_ = false;
    loop_thread_ = new std::thread([] { RunEpollLoop(); });

    port_ = grpc_bridge::start_control_server(daemon_, queue_, epfd_, /*dev_port=*/0);
    ASSERT_NE(port_, 0) << "rust control server failed to bind";

    // Give the C++ epoll loop, the Rust tokio runtime, and the gRPC
    // transport a moment to actually be ready before the first RPC --
    // matches grpc_e2e_test.cc's precedent of a brief sleep after starting a
    // background operation.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  static void TearDownTestSuite() {
    stop_ = true;
    if (loop_thread_ && loop_thread_->joinable())
      loop_thread_->join();
    delete loop_thread_;
    loop_thread_ = nullptr;
    if (epfd_ > 0)
      close(epfd_);
    epfd_ = -1;
    delete daemon_;
    daemon_ = nullptr;
    delete queue_;
    queue_ = nullptr;
  }

  void SetUp() override {
    auto channel = grpc::CreateChannel("localhost:" + std::to_string(port_),
                                        grpc::InsecureChannelCredentials());
    stub_ = netpolicy::v1::NetPolicyControl::NewStub(channel);
  }

  static void RunEpollLoop() {
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

  static int epfd_;
  static int wake_fd_;
  static RCV_EPOLL_CB wake_cb_;
  static DaemonContext* daemon_;
  static grpc_bridge::GrpcDispatchQueue* queue_;
  static std::atomic<bool> stop_;
  static std::thread* loop_thread_;
  static uint16_t port_;

  std::unique_ptr<netpolicy::v1::NetPolicyControl::Stub> stub_;
};

int GrpcRustControlEndToEndTest::epfd_ = -1;
int GrpcRustControlEndToEndTest::wake_fd_ = -1;
RCV_EPOLL_CB GrpcRustControlEndToEndTest::wake_cb_ = {};
DaemonContext* GrpcRustControlEndToEndTest::daemon_ = nullptr;
grpc_bridge::GrpcDispatchQueue* GrpcRustControlEndToEndTest::queue_ = nullptr;
std::atomic<bool> GrpcRustControlEndToEndTest::stop_{false};
std::thread* GrpcRustControlEndToEndTest::loop_thread_ = nullptr;
uint16_t GrpcRustControlEndToEndTest::port_ = 0;

TEST_F(GrpcRustControlEndToEndTest, ResetConfigReturnsOkStatus) {
  grpc::ClientContext ctx;
  netpolicy::v1::ResetConfigRequest req;
  netpolicy::v1::StatusResponse resp;
  grpc::Status status = stub_->ResetConfig(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_EQ(resp.status(), 0);
}

TEST_F(GrpcRustControlEndToEndTest, PodUpWithInvalidPidReturnsNonZeroStatus) {
  // A pid that doesn't exist makes SetNs fail deterministically without
  // requiring real container/netns setup in a test environment.
  grpc::ClientContext ctx;
  netpolicy::v1::PodUpRequest req;
  req.set_pid(999999);
  req.set_pod_id(1);
  netpolicy::v1::StatusResponse resp;
  grpc::Status status = stub_->PodUp(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_NE(resp.status(), 0);
}

} // namespace
