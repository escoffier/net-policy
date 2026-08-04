#pragma once

#include <glog/logging.h>
#include <netinet/in.h>  // IPPROTO_TCP, for receive()'s is_tcp classification
#include <memory>
#include <optional>
#include <string_view>
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
  // `track_tcp` originally existed to preserve a resource-lifetime property:
  // FlowEngine had no timeout/reaper, entries left the TCB table only on a
  // FIN/RST for an already-tracked flow, and on_packet was only ever reached
  // behind net-policy.cpp's `daemon->WafEnabled()` guard (waf_enable_ defaults
  // to false), so tracking unconditionally would have grown that table without
  // bound in the default deployment.
  //
  // Both halves of that rationale are now gone: FlowEngine has a timeout
  // reaper, and microsegmentation's per-connection HTTP tracking is driven by
  // the same PacketDecision the WAF is, so gating it on the WAF would silently
  // disable L7 microsegmentation policy whenever the WAF is off. Production
  // callers (input_nfq_cb/output_nfq_cb) therefore pass `true`; the flag stays
  // on the signature because tests still use it to assert the untracked
  // behavior. Do NOT gate the five-tuple parse or `is_tcp` on it either way.
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
      case 4:  // Duplicate -- new for WAF: a retransmission guard it didn't
               // have before this phase (see plan Task 1's commit message).
        return NetStatus::OK;
      case 5:  // UnknownData -- matches WAF's pre-existing implicit behavior
               // for this case exactly (previously fell into `default:` via
               // kind 0/Ignore; now explicit).
        return NetStatus::OK;
      default:
        return NetStatus::OK;
    }
  }

  // Pure lookup: does a tracked microseg Connection already exist for this
  // decision's conn_id? Mirrors the old C++'s `tcp_it != TcpCtInput().end()`
  // check (renamed `found`). Callers use this BEFORE deciding whether to
  // re-run policy matching (see net-policy.cpp's input_nfq_cb/output_nfq_cb,
  // Task 5) -- a flow can be fully tracked by the TCB state machine while
  // having no tracked microseg Connection, if no HTTP policy applied to it
  // at NewConnection/UnknownData time. Never mutates state.
  bool MicrosegTracked(const net_flow::PacketDecision& decision) const {
    return microseg_conns_.find(ToConnectionID(decision.conn_id)) != microseg_conns_.end();
  }

  // The rule_key stored on the tracked microseg Connection for this decision,
  // or std::nullopt when no entry exists. Mirrors the old C++'s
  // `rule_key = tcp_it->second->getRuleKey();` overwrite, which is what made
  // the *tracked* path's `InputHttpPolicy().find(rule_key)` lookup work at
  // all: on a tracked flow the caller skips MatchMicroPolicyRule entirely
  // (see MicrosegTracked above), so its local rule_key is still empty and the
  // entry's own stored key -- captured when the flow was first tracked -- is
  // the only authoritative source. DispatchMicroseg deliberately returns only
  // a Header, so callers that need the key must ask for it here (Task 5).
  std::optional<std::string> MicrosegRuleKey(const net_flow::PacketDecision& decision) const {
    auto it = microseg_conns_.find(ToConnectionID(decision.conn_id));
    if (it == microseg_conns_.end()) {
      return std::nullopt;
    }
    return it->second->getRuleKey();
  }

  // Starts tracking this decision's flow for microsegmentation, if it is not
  // already tracked. Mirrors the old C++'s two explicit inserts --
  // `TcpCt{Input,Output}().insert({ct_key, Connection(rule_key)})` on a SYN,
  // and the same insert on the first data packet of a flow with an applicable
  // HTTP policy -- including their insert-if-absent semantics (`std::map::
  // insert` does nothing when the key exists, so a repeat SYN never reset a
  // live entry's parser state).
  //
  // Deliberately inserts ONLY `conn_id`, never `peer_conn_id`, unlike
  // http_conns_ (WAF), where both directions legitimately share one
  // HttpFilterManager. Microsegmentation's rule keys are direction-specific:
  // the ingress direction's key is looked up in InputHttpPolicy() and the
  // egress direction's in OutputHttpPolicy(), and the old code kept two
  // separate direction-keyed maps for exactly that reason. Seeding the peer
  // here with this direction's key would hand output_nfq_cb an ingress key to
  // look up in OutputHttpPolicy() -- a near-certain miss, silently disabling
  // egress L7 policy. Each direction binds its own entry, with its own
  // MatchMicroPolicyRule result, when its own callback first sees a packet for
  // it; the merged ConnectionID-keyed map stays equivalent to the old two maps
  // because the two directions have distinct ConnectionIDs.
  void MicrosegTrack(const net_flow::PacketDecision& decision, const std::string& rule_key) {
    auto id = ToConnectionID(decision.conn_id);
    if (microseg_conns_.find(id) == microseg_conns_.end()) {
      microseg_conns_[id] = std::make_unique<http::Connection>(rule_key);
    }
  }

  // Mirrors the old C++ microseg block's per-kind handling, keyed by
  // ConnectionID instead of a queue-direction-specific TcpFourTupleV4 map.
  // `rule_key` is only consulted for NewConnection/UnknownData (the caller
  // must have already run MatchMicroPolicyRule for those -- see Task 5);
  // for Data/Duplicate/Closed on an already-tracked entry, the entry's own
  // stored rule_key (via Connection::getRuleKey()) is authoritative and the
  // passed-in rule_key is ignored, mirroring the old
  // `rule_key = tcp_it->second->getRuleKey();` overwrite.
  //
  // Returns the reconstructed HTTP header once a Data- or UnknownData-kind
  // packet completes an HTTP parse (ParseState::Done), for the caller to run
  // MatchHttpPolicyRule against -- std::nullopt for every other case
  // (NewConnection, Closed, Duplicate, an incomplete parse, or a Data-kind
  // packet with no matching entry -- Data never inserts on a miss, only
  // UnknownData does; see case 3 vs case 5 below).
  std::optional<http::Header> DispatchMicroseg(const net_flow::PacketDecision& decision,
                                                const uint8_t* pkg, size_t len,
                                                const std::string& rule_key) {
    auto id = ToConnectionID(decision.conn_id);
    switch (decision.kind) {
      case 0:  // Ignore -- should not be reached for TCP; defensive no-op.
        return std::nullopt;
      case 1: {  // NewConnection (SYN): insert only. A SYN never carries
                 // payload worth extracting, so this case -- unlike case 5
                 // below -- never attempts onData().
                 //
                 // Note the callbacks do NOT reach this case for their SYN
                 // handling: they test the decision's `syn` flag and call
                 // MicrosegTrack directly, because SYN-ACKs and SYN
                 // retransmissions are SYN-flagged but arrive as kind 3/4,
                 // not kind 1 (see PacketDecision::syn's doc comment). This
                 // case exists so that kind-1 dispatch is complete and
                 // equivalent to that path.
        MicrosegTrack(decision, rule_key);
        return std::nullopt;  // SYN itself never produces a Header.
      }
      case 5: {  // UnknownData: late-binding. UNLIKE case 1, this packet DOES
                 // carry real payload (there was no separate SYN packet to
                 // "use up" first), so this case inserts on first sight AND
                 // always attempts extraction in the same call -- including
                 // on every SUBSEQUENT packet of this same flow, since
                 // on_packet_internal has no way to ever promote an
                 // untracked-by-Rust flow to a "known" state (only a SYN
                 // creates a tcbs entry -- Task 1) -- every later packet on
                 // a flow that started this way keeps arriving as
                 // UnknownData too, forever, not Data. This single case must
                 // therefore handle both "first sight" and "already
                 // late-bound, here's more data" without the caller needing
                 // to distinguish them (see Task 5's dispatch, which for
                 // this exact reason calls DispatchMicroseg for kind 5
                 // EXACTLY ONCE, the same as every other kind -- never
                 // paired with a separate insert-only pre-call the way
                 // kind 1 sometimes is).
        auto it = microseg_conns_.find(id);
        if (it == microseg_conns_.end()) {
          // Own direction only -- see MicrosegTrack for why the peer is not
          // seeded with this direction's rule_key.
          MicrosegTrack(decision, rule_key);
          it = microseg_conns_.find(id);
        }
        auto data = std::string_view(reinterpret_cast<const char*>(pkg) + decision.payload_offset,
                                      len - decision.payload_offset);
        const auto& header = it->second->onData(data);
        if (header.parseState_ != ParseState::Done) {
          return std::nullopt;
        }
        return header;
      }
      case 2: {  // Closed
        microseg_conns_.erase(id);
        microseg_conns_.erase(ToConnectionID(decision.peer_conn_id));
        return std::nullopt;
      }
      case 3: {  // Data
        auto it = microseg_conns_.find(id);
        if (it == microseg_conns_.end()) {
          return std::nullopt;  // Untracked. Unlike case 5, this case never
                                 // late-binds: the caller is responsible for
                                 // calling MicrosegTrack first once it has a
                                 // policy-matched rule_key (mirroring the old
                                 // C++'s explicit `if (tcp_it == end())
                                 // insert(...)` immediately before its
                                 // onData() call). A miss here therefore means
                                 // no HTTP policy applied to this flow, and
                                 // extracting would be pointless -- not that
                                 // the caller "routed around" this call, which
                                 // it does not: !MicrosegTracked + Data + an
                                 // applicable policy reaches this case
                                 // routinely, having just tracked the flow.
        }
        auto data = std::string_view(reinterpret_cast<const char*>(pkg) + decision.payload_offset,
                                      len - decision.payload_offset);
        const auto& header = it->second->onData(data);
        if (header.parseState_ != ParseState::Done) {
          return std::nullopt;
        }
        return header;  // copies out of the Connection-owned reference -- safe
                         // past this call regardless of the Connection's lifetime.
      }
      case 4:  // Duplicate -- retransmitted segment, skip (mirrors the old
               // `tcp_seq < getTcpSeq()` early return).
        return std::nullopt;
      default:
        return std::nullopt;
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
  std::unordered_map<ConnectionID, http::ConnectionPtr, ConnectionIDHash> microseg_conns_;
};

}  // namespace net
