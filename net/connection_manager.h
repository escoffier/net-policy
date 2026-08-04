#pragma once

#include <glog/logging.h>
#include <netinet/in.h>  // IPPROTO_TCP, for receive()'s is_tcp classification
#include <memory>
#include <unordered_map>
#include <utility>

#include "http/connection.h"
#include "http/http_filter_factory.h"
#include "http/packet.hh"
#include "net/stream.h"   // ConnectionInfo -- direct include; after this task
                           // deletes net/tcp.h (which used to provide it
                           // transitively) and Task 1 removed net/utility.h's
                           // now-dangling include of the deleted net/filter.h
                           // (which also used to chain to it), nothing else
                           // in net/ pulls this in anymore
#include "net/utility.h"  // now also declares ConnectionID / ConnectionIDHash
#include "net_flow_engine_cxxbridge/lib.h"

namespace net {

class ConnectionManager {
public:
  // `tuple` is populated for every recognized protocol (TCP/UDP/ICMP), and
  // `is_tcp` is always accurate for a recognized packet -- the downstream
  // microsegmentation TCP-tracking block in net-policy.cpp needs both
  // regardless of WAF state. `decision` is only meaningful when `is_tcp` is
  // true AND the caller asked for TCB tracking (receive's `track_tcp`);
  // otherwise it stays default-constructed, i.e. kind 0 (Ignore).
  struct ReceiveResult {
    // Deliberately the raw FFI struct, NOT net-policy.h's FiveTuple:
    // net-policy.h already includes this header, so including it back here
    // for FiveTuple would be circular. ConnectionManager only hands back the
    // raw parsed fields; net-policy.cpp (which includes both headers safely)
    // constructs the policy-matching FiveTuple from them.
    net_flow::SharedFiveTuple tuple;
    net_flow::PacketDecision decision;
    bool is_tcp;
  };

  explicit ConnectionManager(http::HttpFilterFactory& filter_factory)
      : filter_factory_(filter_factory), engine_(net_flow::new_flow_engine()) {}

  // Parses the packet's five-tuple (all of TCP/UDP/ICMP) -- always, since L3-L4
  // policy matching needs it on every packet -- and, when `track_tcp` is set
  // and the packet is TCP, additionally advances the Rust engine's TCB state
  // machine. Deliberately does NOT dispatch to the WAF; the caller decides
  // whether to, via DispatchWaf below.
  //
  // `track_tcp` exists to preserve a resource-lifetime property that predates
  // this phase: net_flow_engine's FlowEngine has no timeout/reaper, so entries
  // are only removed when a FIN/RST is seen for an already-tracked flow.
  // Before the receive/DispatchWaf split, on_packet was only ever reached
  // behind net-policy.cpp's `daemon->WafEnabled()` guard, and waf_enable_
  // defaults to false. Calling on_packet unconditionally would make the TCB
  // table grow without bound (half-open connections, drops, timeouts) in the
  // default WAF-off deployment. Callers pass WafEnabled() here; do NOT gate
  // the five-tuple parse or `is_tcp` on it.
  ReceiveResult receive(const uint8_t* pkg, size_t len, bool track_tcp) {
    ReceiveResult result{};
    result.tuple = net_flow::parse_five_tuple(pkg, len);
    result.is_tcp = result.tuple.recognized && (result.tuple.proto == IPPROTO_TCP);
    if (result.is_tcp && track_tcp) {
      result.decision = engine_->on_packet(pkg, len);
    }
    return result;
  }

  // Unchanged logic from the old internal Handle{NewConnection,Data,Closed}
  // dispatch -- only the call site moved, from inside receive() to here, an
  // explicitly-invoked public method. Callers should only call this for TCP
  // (ReceiveResult::is_tcp); a default-constructed decision (kind 0, Ignore)
  // is handled as a no-op regardless.
  NetStatus DispatchWaf(const net_flow::PacketDecision& decision, const uint8_t* pkg, size_t len) {
    switch (decision.kind) {
      case 0:  // Ignore
        return NetStatus::OK;
      case 1:  // NewConnection
        return HandleNewConnection(decision);
      case 2:  // Closed
        return HandleClosed(decision);
      case 3:  // Data
        return HandleData(decision, pkg, len);
      default:
        return NetStatus::OK;
    }
  }

  NetworkStat stat() { NetworkStat st{}; st.tcp_conn_ = engine_->live_connection_count(); return st; }

  std::vector<std::string> connections() {
    auto rust_conns = engine_->connection_strings();
    std::vector<std::string> conns;
    conns.reserve(rust_conns.size());
    for (const auto& s : rust_conns) {
      conns.emplace_back(std::string(s));
    }
    return conns;
  }

  // Exposes the size of the C++-side connection table (distinct from the Rust
  // engine's own flow table reported by connections()/stat() above). Used by
  // tests to verify HandleClosed/HandleNewConnection keep both the flow's own
  // entry and its peer's entry in sync with the Rust engine's lifecycle
  // decisions.
  size_t httpConnectionCount() const { return http_conns_.size(); }

private:
  static ConnectionID ToConnectionID(const net_flow::SharedConnectionId& id) {
    return ConnectionID{id.local_ip, id.foreign_ip, id.local_port, id.foreign_port};
  }

  NetStatus HandleNewConnection(const net_flow::PacketDecision& decision) {
    auto id = ToConnectionID(decision.conn_id);
    auto peer_id = ToConnectionID(decision.peer_conn_id);
    auto hashFunc = ConnectionIDHash();
    auto hash_key = hashFunc(id);
    auto filter_manager = std::make_shared<http::HttpFilterManager>(
        filter_factory_, hash_key, decision.conn_id.local_ip, decision.conn_id.foreign_ip);

    net::ConnectionInfo connInfo{
        net::ipv4ToString(decision.conn_id.local_ip), net::ipv4ToString(decision.conn_id.foreign_ip),
        decision.conn_id.local_port, decision.conn_id.foreign_port};
    if (http::FilterStatus::StopIteration == filter_manager->onNewConnection(connInfo)) {
      LOG(INFO) << "terminate connection processing";
    }
    auto http_server_conn = std::make_shared<http::Connection>(true, filter_manager);
    http_conns_[id] = http_server_conn;

    if (decision.peer_is_new) {
      auto http_client_conn = std::make_shared<http::Connection>(false, filter_manager);
      http_conns_[peer_id] = http_client_conn;
    }
    return NetStatus::OK;
  }

  NetStatus HandleClosed(const net_flow::PacketDecision& decision) {
    auto id = ToConnectionID(decision.conn_id);
    auto peer_id = ToConnectionID(decision.peer_conn_id);
    auto it = http_conns_.find(id);
    if (it != http_conns_.end()) {
      it->second->httpFilterManager()->onClose();
      http_conns_.erase(it);
    }
    http_conns_.erase(peer_id);
    return NetStatus::OK;
  }

  NetStatus HandleData(const net_flow::PacketDecision& decision, const uint8_t* pkg, size_t len) {
    auto id = ToConnectionID(decision.conn_id);
    auto it = http_conns_.find(id);
    if (it == http_conns_.end()) {
      return NetStatus::OK;
    }
    auto p = seastar::net::packet::from_static_data(reinterpret_cast<const char*>(pkg), len);
    // setTCPSegment's contract requires the packet to already start at the TCP
    // header (see waf/plugin.cc's ModifyNetPackets, which casts the stored
    // pointer directly to `struct tcphdr*`). This mirrors the old (deleted)
    // ipv4::receive, which always stripped the IP header before Tcp::receive
    // (and thus setTCPSegment) ever saw the packet. Trimming by the combined
    // payload_offset before setTCPSegment -- or not trimming at all before it
    // -- would feed it IP-header bytes and corrupt a live packet on the
    // waf/plugin.cc ModifyNetPackets code path. Do NOT collapse this into a
    // single trim_front(payload_offset) call.
    p.trim_front(decision.ip_header_len);
    it->second->httpFilterManager()->setTCPSegment(p);
    p.trim_front(decision.payload_offset - decision.ip_header_len);
    if (http::FilterStatus::StopIteration == it->second->httpFilterManager()->onData(p)) {
      return NetStatus::OK;
    }
    auto filterStatus = it->second->processData(std::move(p));
    if (filterStatus == http::FilterStatus::DropPkt || filterStatus == http::FilterStatus::StopIteration) {
      return NetStatus::Drop;
    }
    return NetStatus::OK;
  }

  http::HttpFilterFactory& filter_factory_;
  rust::Box<net_flow::FlowEngine> engine_;
  std::unordered_map<ConnectionID, std::shared_ptr<http::Connection>, ConnectionIDHash> http_conns_;
};

}  // namespace net
