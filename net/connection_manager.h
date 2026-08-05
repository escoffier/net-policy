#pragma once

#include <glog/logging.h>
#include <netinet/in.h>  // IPPROTO_TCP, for receive()'s is_tcp classification
#include <chrono>
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
    return it->second.conn->getRuleKey();
  }

  // Refreshes the reaper clock on this decision's microsegmentation entry, if
  // one exists (a no-op otherwise -- this NEVER inserts). The callbacks call it
  // once per TCP packet, before any of their early returns, so that "this flow
  // is still alive" is decided by packet arrival and NOT by whether the packet
  // happened to reach DispatchMicroseg: a keepalive-heavy or long-idle-between-
  // requests connection sends plenty of payload-less ACKs that the callbacks
  // return on early (`!has_payload`), and without this its entry would age out
  // from under a live flow, losing its rule_key and any half-parsed request.
  //
  // Kinds 0 (Ignore) and 4 (Duplicate) deliberately do NOT refresh, mirroring
  // net_flow_engine's on_packet_internal, which likewise leaves `last_seen`
  // untouched on a duplicate ("an entry that only ever receives retransmits of
  // old data is not active for reaper purposes") and never reaches a flow's
  // state at all for kind 0.
  void MicrosegTouch(const net_flow::PacketDecision& decision) {
    MicrosegTouch(decision, std::chrono::steady_clock::now());
  }

  // Test seam: same, with the clock injected. Mirrors the split net_flow_engine
  // already uses between evict_stale(now, timeout) and evict_stale_connections().
  void MicrosegTouch(const net_flow::PacketDecision& decision,
                     std::chrono::steady_clock::time_point now) {
    if ((decision.kind == 0) || (decision.kind == 4)) {
      return;
    }
    TouchMicroseg(ToConnectionID(decision.conn_id), now);
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
      microseg_conns_[id] =
          MicrosegEntry{std::make_unique<http::Connection>(rule_key), std::chrono::steady_clock::now()};
    }
  }

  // Microsegmentation teardown for a Closed (FIN/RST) decision: a no-op for
  // every other kind, so the callbacks can -- and must -- call it once for
  // every TCP packet, unconditionally. Returns true iff the decision was a
  // Closed one, i.e. iff teardown actually ran.
  //
  // Deliberately NOT gated on MicrosegTracked(decision), and that is the whole
  // reason this method exists rather than the callbacks calling
  // DispatchMicroseg for kind 2 from inside their `tracked` branch (which is
  // what they did until the final whole-branch review of Phase 6b-2 caught it):
  //
  //   MicrosegTrack seeds ONLY the packet's own direction, never the peer (see
  //   its comment -- microseg rule keys are direction-specific), so a
  //   connection covered by an L7 policy on one direction only -- the usual
  //   case -- has exactly one microseg_conns_ entry. But net_flow_engine
  //   removes BOTH directions' TCB entries on the FIRST FIN/RST it sees,
  //   whichever direction carried it, so the resulting Closed decision very
  //   often surfaces on the direction that has no entry, where the callback
  //   takes its !tracked branch and returns early at `!syn && !has_payload`.
  //   Gating teardown on `tracked` therefore left the OTHER direction's now
  //   permanently-stale entry in place until the reaper swept it up to five
  //   minutes later. In that window, a client reusing the same 4-tuple
  //   (ephemeral port reuse) inherited the dead connection's rule_key and
  //   mid-message llhttp parser state via MicrosegTrack's insert-if-absent
  //   semantics -- the new connection's bytes could then never reach
  //   ParseState::Done, silently failing open on L7 policy enforcement.
  //
  // DispatchMicroseg's case 2 erases both `conn_id` and `peer_conn_id`, so one
  // call from EITHER direction's callback cleans up both directions' entries.
  // The callbacks keep their existing per-direction verdicts for the closing
  // packet (kAllow when tracked, kAllowReq/kAllowRsp when not) -- this method
  // changes only WHEN the erase happens, never what the packet's verdict is.
  bool MicrosegClose(const net_flow::PacketDecision& decision, const uint8_t* pkg, size_t len) {
    if (decision.kind != 2) {
      return false;
    }
    // Routed through DispatchMicroseg rather than erasing here, so case 2 stays
    // the single owner of what "closed" means for microseg_conns_. `rule_key`
    // is unused by that case, as are pkg/len.
    DispatchMicroseg(decision, pkg, len, std::string());
    return true;
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
        it->second.last_seen = std::chrono::steady_clock::now();
        auto data = std::string_view(reinterpret_cast<const char*>(pkg) + decision.payload_offset,
                                      len - decision.payload_offset);
        const auto& header = it->second.conn->onData(data);
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
        it->second.last_seen = std::chrono::steady_clock::now();
        auto data = std::string_view(reinterpret_cast<const char*>(pkg) + decision.payload_offset,
                                      len - decision.payload_offset);
        const auto& header = it->second.conn->onData(data);
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

  // Called periodically (net-policy.cpp's RunNetPolicyDaemon arms a timerfd on
  // the epoll loop for it) to sweep stale per-flow state. Runs on the epoll
  // thread, like every other callback -- no threads, no locking.
  //
  // There are TWO independent sources of staleness, and both are needed:
  //
  //  1. The Rust engine's own TCB table. `evict_stale_connections()` drops
  //     entries whose last packet is older than the timeout and hands back
  //     their IDs; whatever this class holds for those IDs goes with them, so
  //     neither map keeps a Connection referencing a flow the engine no longer
  //     tracks.
  //
  //  2. `microseg_conns_` entries the engine can never report. A flow the
  //     daemon never saw a SYN for (it attached to a pod mid-connection, or was
  //     restarted while connections were live) is NEVER inserted into the
  //     engine's `tcbs` -- only the SYN branch of on_packet_internal inserts --
  //     so every packet on it arrives as UnknownData forever and its ID can
  //     never appear in evict_stale_connections()' output. But DispatchMicroseg
  //     case 5 late-binds a microseg_conns_ entry for exactly that flow. Source
  //     1 alone therefore leaks every late-bound flow permanently, for the
  //     lifetime of the daemon. Hence the second loop: microseg entries carry
  //     their own last_seen (refreshed by MicrosegTouch on every packet) and
  //     age out on it, whether or not the engine ever knew about them.
  //
  // `http_conns_` (WAF) deliberately gets no equivalent age sweep, because it
  // has no late-bound entries to leak: it is only ever inserted into by
  // HandleNewConnection, i.e. kind 1, whose conn_id and peer_conn_id are BOTH
  // in `tcbs` by construction (the SYN branch inserts both -- peer_is_new is
  // false precisely when the peer was already there). Source 1 covers all of
  // them. DispatchWaf's case 5 is a no-op and never inserts.
  void EvictStale() {
    EvictStale(std::chrono::steady_clock::now(),
               std::chrono::seconds(net_flow::stale_connection_timeout_secs()));
  }

  // Test seam: same, with the clock and timeout injected -- the timeout the
  // no-arg overload uses is 5 minutes, which no test can wait out. Mirrors the
  // split net_flow_engine already uses between evict_stale(now, timeout) and
  // evict_stale_connections(). Note `now`/`timeout` govern the C++-side sweep
  // only; the engine's own eviction (below) always runs against the real clock
  // and its own compiled-in timeout, since its Instants are not reachable from
  // here.
  void EvictStale(std::chrono::steady_clock::time_point now,
                  std::chrono::steady_clock::duration timeout) {
    for (const auto& shared_id : engine_->evict_stale_connections()) {
      ConnectionID id{shared_id.local_ip, shared_id.foreign_ip, shared_id.local_port,
                      shared_id.foreign_port};
      // Same teardown a FIN/RST gets (HandleClosed): the WAF's onClose is what
      // emits a connection's accumulated attack report, so erasing the entry
      // without it would silently drop that report for any connection that
      // timed out instead of closing cleanly. Erasing the peer alongside it --
      // also HandleClosed's behavior -- is additionally what keeps onClose to
      // exactly ONE call per connection when both directions go stale in the
      // same sweep, since the two directions share one HttpFilterManager.
      //
      // KNOWN, ACCEPTED ASYMMETRY -- WAF INSPECTION IS NOT RECOVERABLE AFTER A
      // REAP, MICROSEGMENTATION'S IS. Flagged explicitly here rather than
      // silently absorbed, matching how this phase documented its other
      // deliberate behavior changes (the RST-on-unknown-flow narrowing, the new
      // duplicate-segment guard WAF gained for free).
      //
      // http_conns_ is (re-)inserted ONLY by HandleNewConnection, reachable
      // only from DispatchWaf case 1 (NewConnection), which requires a SYN on a
      // flow not already in the engine's `tcbs`. Once this sweep evicts a
      // connection, the engine has dropped its TCB too, so every later packet
      // on that still-live socket arrives as kind 5 (UnknownData) -- and
      // DispatchWaf's case 5 is deliberately a no-op per this phase's plan
      // (Global Constraints), never late-binding the way DispatchMicroseg's
      // case 5 does. So a connection that goes idle past the timeout (a
      // keep-alive HTTP connection-pool socket is the realistic case) loses WAF
      // inspection permanently, for the whole remainder of its life; only
      // microsegmentation re-binds, via its own case 5.
      //
      // This is NEW with this phase -- there was no reaper before it, so no
      // connection was ever evicted while live. It is accepted rather than
      // fixed because a late-binding WAF path is a genuine design change (WAF
      // state is a whole HttpFilterManager with connection-scoped context, not
      // microseg's single re-derivable rule_key), out of scope for the fix wave
      // that documented it. If it needs fixing later, the shape is a DispatchWaf
      // case 5 that reconstructs a filter manager mid-stream -- with its own
      // decision about what onNewConnection means for a connection whose start
      // was never observed.
      CloseHttpConn(id, PeerOf(id));
      microseg_conns_.erase(id);
    }
    for (auto it = microseg_conns_.begin(); it != microseg_conns_.end();) {
      if ((now - it->second.last_seen) >= timeout) {
        it = microseg_conns_.erase(it);
      } else {
        ++it;
      }
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

  // Same, for the microsegmentation map. Used by the reaper tests to observe
  // that an evicted entry is really gone rather than merely unreachable.
  size_t microsegConnectionCount() const { return microseg_conns_.size(); }

private:
  // A tracked microsegmentation flow: its HTTP parse/rule-key state, plus when
  // a packet for it was last seen. The timestamp is NOT redundant with the Rust
  // engine's per-TCB last_seen: a late-bound flow (no SYN ever seen, so no
  // `tcbs` entry -- see EvictStale) has an entry here and none there, and this
  // is the only thing that can ever age it out.
  struct MicrosegEntry {
    http::ConnectionPtr conn;
    std::chrono::steady_clock::time_point last_seen;
  };

  static ConnectionID ToConnectionID(const net_flow::SharedConnectionId& id) {
    return ConnectionID{id.local_ip, id.foreign_ip, id.local_port, id.foreign_port};
  }

  // The reverse-direction ID: local and foreign swapped, exactly how
  // on_packet_internal derives peer_conn_id from conn_id.
  static ConnectionID PeerOf(const ConnectionID& id) {
    return ConnectionID{id.foreign_ip_, id.local_ip_, id.foreign_port_, id.local_port_};
  }

  void TouchMicroseg(const ConnectionID& id, std::chrono::steady_clock::time_point now) {
    auto it = microseg_conns_.find(id);
    if (it != microseg_conns_.end()) {
      it->second.last_seen = now;
    }
  }

  // Shared by HandleClosed (FIN/RST) and EvictStale (idle timeout): run the
  // WAF's connection-close hook once, then drop both directions' entries.
  void CloseHttpConn(const ConnectionID& id, const ConnectionID& peer_id) {
    auto it = http_conns_.find(id);
    if (it != http_conns_.end()) {
      it->second->httpFilterManager()->onClose();
      http_conns_.erase(it);
    }
    http_conns_.erase(peer_id);
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
    CloseHttpConn(ToConnectionID(decision.conn_id), ToConnectionID(decision.peer_conn_id));
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

  // KNOWN LIMITATION -- LOOPBACK TRAFFIC COLLIDES IN BOTH MAPS BELOW.
  //
  // Both maps are keyed by ConnectionID alone, which is derived purely from the
  // packet's (saddr, daddr, sport, dport) -- it carries no notion of which NFQ
  // queue, and therefore which direction, the packet was captured on.
  // crates/net_iptables installs its NFQUEUE jumps on mangle PREROUTING and
  // mangle OUTPUT with no `lo`/loopback exclusion, so a 127.0.0.1 -> 127.0.0.1
  // packet is delivered to BOTH input_nfq_cb and output_nfq_cb with identical
  // bytes, yielding the SAME ConnectionID in both callbacks. For localhost or
  // sidecar traffic under an L7 microseg or WAF policy, the two directions then
  // share one entry: one direction's rule_key (looked up in InputHttpPolicy)
  // and half-parsed llhttp state can be handed to the other (which would look
  // its key up in OutputHttpPolicy), i.e. cross-direction contamination.
  //
  // This is a real regression from the pre-Phase-6b-2 design, which kept two
  // separate direction-keyed maps (MicroSegEngine::TcpCtInput()/TcpCtOutput())
  // that could not collide. It predates the callback cutover -- it arrived with
  // the single ConnectionID-keyed microseg_conns_ -- and is recorded here, in
  // the code, deliberately: the SDD ledger that first flagged it is deleted
  // when this branch merges. Non-loopback traffic is unaffected, since the two
  // directions of such a flow have genuinely distinct ConnectionIDs.
  //
  // The fix, when it is done, is to key both maps by (ConnectionID, direction)
  // -- roughly 40 lines, touching every call site in net-policy.cpp -- or to
  // exclude `lo` at the iptables layer. Do not paper over it by mutating shared
  // entries defensively at the use sites.
  std::unordered_map<ConnectionID, std::shared_ptr<http::Connection>, ConnectionIDHash> http_conns_;
  std::unordered_map<ConnectionID, MicrosegEntry, ConnectionIDHash> microseg_conns_;
};

}  // namespace net
