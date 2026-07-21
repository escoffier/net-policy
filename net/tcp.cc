
#include <cstdint>
#include <glog/logging.h>
#include <memory>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <boost/endian/conversion.hpp>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "http/connection.h"
#include "http/extension/log.h"
#include "http/filter.h"
#include "http/http_filter_factory.h"
#include "http/packet.hh"
#include "net/filter.h"
#include "net/utility.h"
#include "tcp.h"

namespace net {

std::ostream& operator<<(std::ostream& os, const ConnectionID& conn) {
  os << "connection{ " << ipv4ToString(conn.local_ip_) << ":" << conn.local_port_ << ", "
     << ipv4ToString(conn.foreign_ip_) << ":" << conn.foreign_port_ << " }";
  return os;
}

NetStatus Tcp::Tcb::handlePayload(seastar::net::packet p) {
  auto filsterStatus = http_->processData(std::move(p));
  if (filsterStatus == http::FilterStatus::DropPkt ||
      filsterStatus == http::FilterStatus::StopIteration) {
    VLOG(4) << "drop tcp segment";
    return NetStatus::Drop;
  }
  return NetStatus::OK;
}

NetStatus Tcp::receive(seastar::net::packet p, uint32_t from, uint32_t to) {
  auto th = p.get_header(0, TCP_HDR_LEN);
  VLOG(4) << "receive tcp " << uint64_t(th);

  if (!th) {
    return NetStatus::OK;
  }
  tcphdr* tcp_hdr = reinterpret_cast<tcphdr*>(th);
  auto hdrLen = tcp_hdr->doff * 4;
  if (hdrLen < TCP_HDR_LEN) {
    return NetStatus::OK;
  }
  VLOG(4) << "tcp payload length: " << (p.len() - hdrLen);

  ConnectionID id{from, to, ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest)};
  ConnectionID peer_id{to, from, ntohs(tcp_hdr->dest), ntohs(tcp_hdr->source)};

  auto tcb_iter = tcbs_.find(id);
  if (tcb_iter == tcbs_.end()) {
    if (tcp_hdr->rst == 1) {
      VLOG(2) << "reset tcp " << id;
      return NetStatus::OK;
    }

    if (tcp_hdr->syn == 1) {
      auto hashFunc = ConnectionIDHash();
      auto hash_key = hashFunc(id);
      auto filter_manager = std::make_shared<http::HttpFilterManager>(hash_key, from, to);

      net::ConnectionInfo connInfo{net::ipv4ToString(from), net::ipv4ToString(to),
                                   ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest)};
      if (http::FilterStatus::StopIteration == filter_manager->onNewConnection(connInfo)) {
        LOG(INFO) << "terminate connection processing (" << id << ")";
      }
      auto httpServerConn = std::make_shared<http::Connection>(true, filter_manager);
      auto t = std::make_shared<Tcb>(httpServerConn);
      // t->seq_ = ntohl(tcpHdr->seq) + 1;
      t->seq_ = boost::endian::big_to_native(tcp_hdr->seq) + 1;
      t->server_side_ = true;
      tcbs_.insert({id, t});
      VLOG(2) << hash_key << " new tcp connection: " << id;

      auto peer_it = tcbs_.find(peer_id);
      if (peer_it == tcbs_.end()) {
        auto http_client = std::make_shared<http::Connection>(false, filter_manager);
        VLOG(2) << hash_key << " new tcp connection peer: " << peer_id;
        auto t1 = std::make_shared<Tcb>(http_client);
        t1->server_side_ = false;
        tcbs_.insert({peer_id, t1});
      }

      return NetStatus::OK;
    }
    // if (tcpHdr->ack == 1) {
    //   auto t = std::make_shared<Tcb>();
    //   t->seq_ = ntohl(tcpHdr->seq);
    //   t->seq_ = boost::endian::big_to_native(tcpHdr->seq);
    //   t->serverSide_ = false;
    //   tcbs.insert({id, t});
    //   VLOG(4) << "new tcp connection";
    //   return;
    // }

  } else {
    if (tcp_hdr->fin == 1 || tcp_hdr->rst == 1) {
      VLOG(2) << "close tcp connection: " << tcb_iter->first;
      tcb_iter->second->http_->httpFilterManager()->onClose();
      tcbs_.erase(tcb_iter);

      // ConnectionID peerID{to, from, ntohs(tcpHdr->dest), ntohs(tcpHdr->source)};
      VLOG(2) << "close tcp connection peer: " << peer_id;
      tcbs_.erase(peer_id);
      return NetStatus::OK;
    }
    // if ((tcpHdr->ack == 1) && tcpHdr->syn == 1) {
    //   tcbIter->second->seq_ = boost::endian::big_to_native(tcpHdr->seq);
    //   tcbIter->second->serverSide_ = false;
    // }

    tcb_iter->second->http_->httpFilterManager()->setTCPSegment(p);

    p.trim_front(hdrLen);

    if (http::FilterStatus::StopIteration ==
        tcb_iter->second->http_->httpFilterManager()->onData(p)) {
      return NetStatus::OK;
    }
    return tcb_iter->second->handlePayload(std::move(p));
    // return NetStatus::OK;
  }
  return NetStatus::OK;
}

NetworkStat Tcp::stat() {
  NetworkStat st{};
  st.tcp_conn_ = tcbs_.size();
  return st;
}

std::vector<std::string> Tcp::connections() {
  std::vector<std::string> conns{};
  for (auto& [key, value] : tcbs_) {
    std::ostringstream conn;
    conn << ipv4ToString(key.local_ip_) << ":" << key.local_port_ << ","
         << ipv4ToString(key.foreign_ip_) << ":" << key.foreign_port_;
    conns.push_back(conn.str());
  }
  return conns;
}

std::ostream& operator<<(std::ostream& os, const Tcp::Tcb& tcb) {
  os << "tcp{" << tcb.seq_ << ", ";
  os << "}";
  return os;
}

} // namespace net