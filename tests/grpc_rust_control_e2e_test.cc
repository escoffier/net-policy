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

class GrpcRustControlEndToEndTest : public ::testing::Test {
protected:
  void SetUp() override {
    epfd_ = epoll_create(32);
    ASSERT_GT(epfd_, 0);

    wake_fd_ = eventfd(0, EFD_NONBLOCK);
    ASSERT_GT(wake_fd_, 0);
    queue_ = std::make_unique<grpc_bridge::GrpcDispatchQueue>(wake_fd_);
    daemon_.WireRustControlDispatch(queue_.get());

    wake_cb_.fd_ = wake_fd_;
    wake_cb_.epoll_in_func_ = grpc_bridge::DispatchGrpcRustQueueEvent;
    wake_cb_.daemon_ = &daemon_;
    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.ptr = &wake_cb_;
    ASSERT_EQ(epoll_ctl(epfd_, EPOLL_CTL_ADD, wake_fd_, &ev), 0);

    stop_ = false;
    loop_thread_ = std::thread([this] { RunEpollLoop(); });

    uint16_t port = grpc_bridge::start_control_server(&daemon_, queue_.get(), epfd_, /*dev_port=*/0);
    ASSERT_NE(port, 0) << "rust control server failed to bind";

    auto channel = grpc::CreateChannel("localhost:" + std::to_string(port),
                                        grpc::InsecureChannelCredentials());
    stub_ = netpolicy::v1::NetPolicyControl::NewStub(channel);

    // Give the C++ epoll loop, the Rust tokio runtime, and the gRPC
    // transport a moment to actually be ready before the first RPC --
    // matches grpc_e2e_test.cc's precedent of a brief sleep after starting a
    // background operation.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  void TearDown() override {
    stop_ = true;
    if (loop_thread_.joinable())
      loop_thread_.join();
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
  int wake_fd_ = -1;
  RCV_EPOLL_CB wake_cb_ = {};
  DaemonContext daemon_;
  std::unique_ptr<grpc_bridge::GrpcDispatchQueue> queue_;
  std::atomic<bool> stop_{false};
  std::thread loop_thread_;
  std::unique_ptr<netpolicy::v1::NetPolicyControl::Stub> stub_;
};

TEST_F(GrpcRustControlEndToEndTest, ResetConfigReturnsOkStatus) {
  grpc::ClientContext ctx;
  netpolicy::v1::ResetConfigRequest req;
  netpolicy::v1::StatusResponse resp;
  grpc::Status status = stub_->ResetConfig(&ctx, req, &resp);
  ASSERT_TRUE(status.ok()) << status.error_message();
  EXPECT_EQ(resp.status(), 0);
}

} // namespace
