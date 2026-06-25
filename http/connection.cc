#include <cstddef>
#include <iostream>
#include <memory>
#include <string_view>

#include <glog/logging.h>
#include <utility>

#include "http/codec.h"
#include "http/filter.h"
#include "http/http1/codec.h"
#include "http/http2/codec.hh"
#include "http/http_inspector.h"
#include "http/packet.hh"
#include "http/utility.h"

#include "connection.h"

namespace http {

// Connection::Connection(std::string key)
//     : ruleKey_(key), header_(), packet_(),
//       filters_manager_(std::make_unique<HttpFilterManager>()) {
//   inspector_ = std::make_unique<HttpInspector>();
//   tcpSeq_ = 0;
//   LOG(INFO) << "new connection : " << key;
// }

Connection::Connection(bool serverSide, HttpFilterManagerPtr filterManager)
    : header_(), packet_(), filters_manager_(filterManager), server_side_(serverSide) {
  inspector_ = std::make_unique<HttpInspector>();
}

Connection::Connection(std::string key) : header_(), packet_(), server_side_(false) {
  inspector_ = std::make_unique<HttpInspector>();
}

void Connection::createCodec(Protocol protocol) {
  switch (protocol) {
  case Protocol::Http2:
    LOG(INFO) << "protocol: http2";
    codec_ = std::make_unique<http2::ConnectionImpl>(server_side_, filters_manager_);
    break;
  case Protocol::Http10:
  case Protocol::Http11:
    LOG(INFO) << "protocol: http";
    codec_ = std::make_unique<http1::ConnectionImpl>(server_side_, filters_manager_);
    break;
  case Protocol::Http3:
    LOG(INFO) << "protocol: http3";
    codec_ = nullptr;
    break;
  }
}

const Header& Connection::onData(std::string_view data) {
  VLOG(8) << "data: " << data;
  if (!codec_) {
    auto st = inspector_->parseHttpHeader(data);
    header_.parseState_ = st;
    if (st == ParseState::Done) {
      auto protocol = inspector_->getProtocol();
      createCodec(protocol);
    } else if (st == ParseState::Continue) {
      packet_.append(seastar::net::packet::from_static_data(data.data(), data.length()));
      VLOG(8) << "parse continue" << std::endl;
      return header_;
    } else {
      return header_;
    }
  }

  if (packet_.len() > 0) {
    auto buf = packet_.get_header(0, packet_.len());
    std::string_view data1(buf, packet_.len());
    codec_->dispatch(data1);
    packet_.trim_front(packet_.len());
    VLOG(8) << "parse buffed data" << std::endl;
  }
  return codec_->dispatch(data);
}

FilterStatus Connection::processData(seastar::net::packet p) {
  if (p.len() == 0) {
    return FilterStatus::Continue;
  }
  auto data = p.get_header(0, p.len());
  VLOG(4) << "data len: " << p.len() << " data: " << std::string_view(data, p.len());
  if (!codec_) {
    auto st = inspector_->parseHttpHeader(data);
    header_.parseState_ = st;
    if (st == ParseState::Done) {
      auto protocol = inspector_->getProtocol();
      createCodec(protocol);
    } else if (st == ParseState::Continue) {
      packet_.append(std::move(p));
      LOG(INFO) << "parse continue: " << packet_.len() << std::endl;
      return FilterStatus::Continue;
    } else {
      return FilterStatus::StopIteration;
    }
  }

  VLOG(8) << "begin processing cached pkt";
  if (packet_.len() > 0) {
    auto buf = packet_.get_header(0, packet_.len());
    std::string_view data1(buf, packet_.len());
    codec_->dispatch(data1);
    packet_.trim_front(packet_.len());
    LOG(INFO) << "parse buffed data" << std::endl;
  }

  VLOG(8) << "begin processing pkt";
  return codec_->dispatch(std::move(p));
}

void Connection::registerFilter(HttpFilterPtr filter) {
  filters_manager_->addFilter(filter);
  if (codec_) {
    codec_->addFilter(std::move(filter));
    return;
  }
}
} // namespace http
