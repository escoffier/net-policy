# Phase 6b-3: NFQ Netlink Mechanics Design

## Overview

Phase 6a's design spec split the original Phase 6 ("NFQ/netlink core") into three
independently-planned sub-phases, on the grounds that its pieces have wildly
different risk profiles: iptables rule management and legacy-protocol retirement
(6a, shipped), the NFQ packet-queue/epoll/netns layer (6b, itself split into 6b-1
unified packet decision and 6b-2 microsegmentation TCP-tracking consolidation,
both shipped), and conntrack (6c, not yet started, scoped for an FFI-wrap approach
given the immaturity of the Rust conntrack-event-subscription ecosystem).

This spec covers what's left of Phase 6b after 6b-1 and 6b-2 carved out the
packet-decision logic and TCP-tracking state: the NFQ netlink mechanics
themselves (`nfq_open`/`bind`/`create_queue`/`set_mode`/`handle_packet`/
`set_verdict(2)`), `NFQ_RES_INFO`'s queue-handle lifecycle, and netns switching
(`OpenLocalNetNs`/`SetLocalNetNs`/`SetNs`). Unlike conntrack, the pure-Rust `nfq`
crate (`nbdd0121/nfq-rs`) was already assessed in Phase 6a's spec as "reasonably
capable" for this piece — this phase pursues a real replacement of
`libnetfilter_queue`'s C API, not an FFI wrap, following the same "Rust owns
protocol mechanics, C++ orchestrates" shape Phase 5 established for TCP/IP header
parsing.

The practical challenge this spec resolves: `nfq_set_verdict`/`nfq_set_verdict2`
calls are spread across roughly 44 return points inside `input_nfq_cb`/
`output_nfq_cb` — the same two callbacks 6b-1 and 6b-2 already restructured
twice for unrelated reasons. This phase treats that restructuring as settled and
untouchable: the decision logic between verdict calls does not change, only the
mechanism each call site uses to issue its verdict.

## Goals

- Replace `libnetfilter_queue`'s C API surface with a new Rust crate, `net_nfq`
  (`crates/net_nfq/`), wrapping the `nfq` crate for queue open/bind/create/mode,
  message receive, and verdict issuance, plus `nix` for the netns syscalls this
  phase also owns.
- Port `NFQ_RES_INFO`'s NFQ-specific fields (`input_fd_`/`output_fd_`/
  `input_que_`/`output_que_`) to two opaque `net_nfq::NfqQueue` handles (one per
  direction), and the functions that manage them (`OpenNfque`, `AddEpollEvent`,
  `NfqueueRcvData`) onto the new crate's API.
- Port netns switching (`open()`/`unshare(CLONE_NEWNET)`/`setns()`, i.e. `SetNs`)
  to Rust.
- `input_nfq_cb`/`output_nfq_cb` keep their existing decision logic verbatim;
  every one of the ~44 `nfq_set_verdict`/`nfq_set_verdict2` call sites becomes a
  `cxx` call into the corresponding direction's `NfqQueue::verdict(...)` — a
  mechanical swap, not a restructuring.
- Preserve in-place payload rewriting: `rst_tcp_link`-style code that zeroes TCP
  payload bytes and recomputes the checksum before issuing a verdict must keep
  working — the new verdict API accepts a (possibly modified) payload buffer,
  not just a re-injection of the original bytes.
- Delete two dead-code items Phase 6b-1's review flagged and scoped to whichever
  phase owns netns/`NFQ_RES_INFO` lifecycle (this one), after a fresh grep
  confirms no new callers appeared since: `SetLocalNetNs`/`OpenLocalNetNs`/
  `DaemonContext::LocalNetNsFd()`/`SetLocalNetNsFd()`/`local_net_ns_fd_`, and
  `NfQueData::ClearNfQueResource`.

## Non-Goals

- **Conntrack** (`OpenConntrack`, `UpdateNetSession`, `SetAcceptMark`,
  `NFQ_RES_INFO`'s `nfct_*` fields) — untouched, stays exactly as-is, Phase 6c's
  territory. `InitNfqueue` keeps calling `OpenConntrack` inline, unmodified;
  `NFQ_RES_INFO` keeps holding raw `nfct_`/`nfct_cb_`/`nfct_hd_`/`nfct_cb_hd_`
  pointers alongside its new Rust-backed NFQ fields until 6c ports its half of
  the same struct.
- **`SetNs`'s call sites** (pod-up/pod-down orchestration in
  `GrpcDispatchPodUp`, `NfQueData::ClearNfQueResource`'s replacement path) are
  not restructured — only `SetNs` itself moves to Rust; who calls it, and when,
  is unchanged.
- **The packet-decision logic** inside `input_nfq_cb`/`output_nfq_cb` (WAF/
  microseg/policy dispatch on `decision.kind`, `DispatchWaf`, `DispatchMicroseg`,
  `MatchMicroPolicyRule`/`MatchHttpPolicyRule`) — unchanged. This phase only
  changes how a packet's id/payload arrive and how a verdict leaves.
- **Heap profiling** (`admin/profile.{h,cc}`) — stays deferred to the
  Decommission phase, per Phase 6a's spec.
- **The epoll main loop's overall shape** (`RunNetPolicyDaemon`'s `while(1)`/
  `epoll_wait` dispatch, the `RcvEpollCb{fd_, epoll_in_func_, ...}` pattern) is
  unchanged — NFQ fds keep being registered into the same epoll set alongside
  the timerfd reaper (6b-2), the gRPC dispatch eventfd, and the post-notification
  socket, via the same `epoll_ctl(EPOLL_CTL_ADD, ...)` calls, just now getting
  their fd from `NfqQueue::fd()` instead of a stored raw field.

## Architecture

### 1. `net_nfq` crate (`crates/net_nfq/`)

New Cargo workspace member (`staticlib`, `cxx` + `nfq` + `nix` dependencies),
following the existing per-phase-crate convention (`net_iptables`,
`net_flow_engine`, etc. — one crate per phase's cohesive scope). Two modules:
`queue.rs` (NFQ mechanics) and `netns.rs` (netns switching) — kept in one crate
rather than split, since both fire inside the same per-pod setup/teardown
sequence and neither is large enough alone to justify its own crate.

`cxx` bridge shape:

```rust
pub struct NfqMessage { id: u32, payload: Vec<u8>, nfmark: u32 }
pub enum NfqVerdict { Accept, Drop }

// opaque Rust type, one instance per direction (input/output) — matching
// today's already-independent input_que_/output_que_ handles exactly; no
// pairing abstraction is introduced, since every other piece of the existing
// code (OpenNfque, AddEpollEvent, epoll registration) already treats the two
// directions as independent.
fn open_queue(queue_num: u16) -> Result<Box<NfqQueue>>; // nfq_open+bind_pf+create_queue+set_mode
impl NfqQueue {
    fn fd(&self) -> i32;                                  // for epoll_ctl registration
    fn recv_batch(&mut self) -> Result<Vec<NfqMessage>>;   // drains until WouldBlock
    // `mark` is Option, not a bare u32: nfq_set_verdict (no mark argument at
    // all) and nfq_set_verdict2 (explicit mark) are NOT the same operation --
    // the 3-arg form leaves the packet's existing nfmark untouched, while the
    // 2-arg-plus-mark form overwrites it. Collapsing both into "always set an
    // explicit mark, using 0 for the old no-mark call sites" would forcibly
    // zero marks that used to survive ACCEPT verdicts untouched (see
    // input_nfq_cb's own nfq_get_nfmark(nfa) fast-path, which depends on a
    // mark set by an EARLIER verdict surviving to be read on a LATER packet).
    // None => nfq_set_verdict (mark untouched); Some(m) => nfq_set_verdict2
    // with that mark. `payload`: an empty slice means "no NFQA_PAYLOAD
    // attribute at all" (kernel keeps the original, unmodified payload,
    // matching today's `data_len=0, pkg=NULL` calls) -- NOT a zero-length
    // payload override. A non-empty slice is sent as the replacement payload,
    // covering both "re-inject the unmodified bytes" and "re-inject after an
    // in-place rewrite" call sites identically, since both already hand back
    // the full buffer today.
    fn verdict(&mut self, id: u32, v: NfqVerdict, mark: Option<u32>, payload: &[u8]) -> Result<()>;
    // Drop closes the queue -- replaces nfq_close/nfq_destroy_queue
}

fn set_ns(pid: i32, base_path: &str) -> Result<()>; // unshare(CLONE_NEWNET)+setns()
```

`recv_batch` mirrors `nfq_handle_packet`'s current batch-drain-per-epoll-wakeup
behavior: internally loops calling the underlying `nfq` crate's per-message recv
until it hits `WouldBlock`, collecting everything available into one `Vec` — a
single `read()` on the netlink socket can carry multiple queued messages today,
and this preserves that. Each `NfqMessage` carries `nfmark` (from
`nfq_get_nfmark`) alongside `id`/`payload`, since `input_nfq_cb` reads the
incoming mark itself (its fast-path early-accept when the mark already says
`kAllow`/`kAllowRsp`) — today via `nfq_get_nfmark(nfa)`, going forward via this
field instead of a separate call.

### 2. Error handling — a new pattern for this codebase, narrowly scoped

Every crate ported so far returns plain sentinels and swallows Rust-side errors
internally (`net_iptables` fire-and-forgets its `Command`s; no crate has yet
needed to signal fallibility across the `cxx` boundary). NFQ open genuinely can
fail — queue-number conflicts, permission errors, socket creation failure — and
`OpenNfque`/`InitNfqueue` already has real `GOTO_ERROR` handling for exactly this
today. `open_queue`/`recv_batch`/`verdict` therefore return `Result<T>`, which
`cxx` translates into a throwing `rust::Error` (a `std::exception` subclass) on
the C++ side; call sites wrap them in `try { ... } catch (const std::exception&
e) { GOTO_ERROR(...) }`. This is `cxx`'s own documented mechanism for fallible
FFI, and it isn't inventing exception handling from nothing in this codebase —
`net-policy.cpp:2015` already uses the identical try/catch shape today (for a
C++-native throw from a dispatched closure, not yet a `cxx` one). The pattern is
confined to the new NFQ call sites; nothing about how every other crate signals
failure changes.

### 3. `NFQ_RES_INFO` and mechanical fallout (`net-policy.h`/`.cpp`)

- `NFQ_RES_INFO` drops `input_fd_`/`output_fd_`/`input_que_`/`output_que_` in
  favor of `rust::Box<net_nfq::NfqQueue> input_queue_`/`output_queue_`. Its
  `nfct_*` fields, `pid_`, `pod_id_`, `poll_fd_`, `daemon_`, `input_cb_`/
  `output_cb_` (`RcvEpollCb*`) are all unchanged.
- `OpenNfque` becomes a thin wrapper around `net_nfq::open_queue()`.
  `AddEpollEvent` reads the fd via `.fd()` instead of a stored field; its
  `epoll_ctl(EPOLL_CTL_ADD, ...)` registration is otherwise unchanged.
- `NfqueueRcvData` replaces `read()` + `nfq_handle_packet()` with
  `queue->recv_batch()`, then loops over the returned messages, calling
  `input_nfq_cb`/`output_nfq_cb` once per message (mirroring how
  `nfq_handle_packet` today invokes the registered C callback once per message
  in the buffer).
- `input_nfq_cb`/`output_nfq_cb` drop their C-library callback signature
  (`struct nfq_q_handle*`, `struct nfgenmsg*`, `struct nfq_data*`, `void*`) for
  `(net_nfq::NfqQueue& queue, uint32_t id, unsigned char* pkg, int data_len)` —
  `NfqueueRcvData` extracts `id`/`pkg`/`data_len` directly from each
  `net_nfq::NfqMessage` before calling in, replacing the current
  `nfq_get_msg_packet_hdr`/`nfq_get_payload` calls at the top of each callback,
  and `nfq_get_nfmark(nfa)`'s one read site (`input_nfq_cb`'s fast-path
  early-accept) reads the message's `nfmark` field instead.
  Every `nfq_set_verdict(qh, id, V, 0, NULL)` becomes
  `queue.verdict(id, V, std::nullopt, {})` (mark left untouched, no payload
  override); every `nfq_set_verdict2(qh, id, V, mark, data_len, pkg)` becomes
  `queue.verdict(id, V, mark, {pkg, (size_t)data_len})`. The decision logic
  surrounding these calls is untouched.
- The `rst_tcp_link`-style in-place payload rewrite (zeroing TCP payload bytes,
  recomputing the checksum) keeps mutating `pkg` directly before the verdict
  call — `pkg` is still a plain mutable buffer, just sourced from
  `recv_batch()`'s `Vec<u8>` instead of a `libnetfilter_queue`-owned pointer.
- `FreeResource`'s current fd-cleanup order — `epoll_ctl(EPOLL_CTL_DEL, ...)`
  then `close(fd)` for each direction, done explicitly *before* the queue
  object itself is destroyed — is preserved: it calls `.fd()` on each
  `NfqQueue` to do the `epoll_ctl` removal, then drops the `Box`, rather than
  relying on `Drop` alone to implicitly unregister-and-close in an
  unspecified order relative to the epoll set.

### 4. Netns switching (`net_nfq::netns` + `net-policy.cpp`)

`SetNs(pid, basePath)` — `open()` the target's `/proc/<pid>/ns/net`,
`unshare(CLONE_NEWNET)`, `setns(fd, CLONE_NEWNET)` — ports 1:1 to
`net_nfq::set_ns(pid, base_path)` using the `nix` crate's `sched::unshare`/
`sched::setns`. Its call sites (inside `GrpcDispatchPodUp`'s closure, and
wherever `NfQueData::ClearNfQueResource`'s equivalent per-pod-teardown work
lives) become one-line calls into the new function; nothing about *when* or
*why* `SetNs` is called changes.

`OpenLocalNetNs`/`SetLocalNetNs`/`DaemonContext::LocalNetNsFd()`/
`SetLocalNetNsFd()`/`local_net_ns_fd_` are deleted outright — confirmed zero
callers by Phase 6b-1's review (the daemon apparently never returns to its own
host namespace once it first enters a pod's, by design: every socket needing
the host namespace, the gRPC servers and `PostServer`, is created before the
first `SetNs()` call at pod-lifecycle time). This phase re-confirms via a fresh
grep before deleting, in case anything changed since 6b-1.

`NfQueData::ClearNfQueResource` is deleted outright for the same reason —
confirmed zero callers (its only real behavior, `SetNs` → `clear_iptables_rule`
→ `FreeResource` per pod, has no surviving caller; `PolicyRule::ClearCfg` only
calls `engine_->clear_cfg()`).

## Testing & Rollout

- **Real integration test** (`tests/net_nfq_ffi_test.cc`, `NetNfqFfiTest` suite,
  `CAP_NET_ADMIN`-gated, mirroring `NetIptablesFfiTest`'s established pattern):
  open a real queue via `net_nfq::open_queue`, install a scratch `NFQUEUE` rule
  in a throwaway chain, send a loopback packet, `recv_batch()` it, issue a
  verdict, confirm the packet round-trips as verdicted. If the build container
  can't actually exercise `nfnetlink_queue` end-to-end under the privilege it
  runs with (the kernel module itself is present per `/proc/net/netfilter`, but
  a full open/bind/verdict round-trip needs elevated capability the default
  build container doesn't run with), this test degrades to skip-if-unsupported
  — the same posture the existing iptables tests already take.
- **Rust unit tests** in `net_nfq` for logic not requiring a live kernel queue:
  message/verdict struct construction, `set_ns`'s error paths on obviously
  invalid input (`pid <= 0`).
- **No new differential harness.** Unlike Phase 6a's iptables port (no
  interesting semantic risk to lose in translation) or Phase 6b-2's tracker
  consolidation (real state-machine logic moving), this phase's risk is
  concentrated entirely in the new `net_nfq` crate's correctness — the
  packet-*decision* logic isn't changing at all, and was already extensively
  covered by 6b-1/6b-2's test suite. That suite staying green unmodified is
  itself part of this phase's regression check; the real integration test above
  is where the new risk surface actually lives.
- **Manual sanity check**, following Phase 6b-2's Task 6 precedent (the reaper's
  manual timerfd verification): run the real `net-rule` binary under elevated
  privilege with real traffic if the automated privileged test can't fully
  exercise the kernel round-trip in CI, confirming packets actually flow
  end-to-end before calling the phase done.
- **Rollout**: same strangler-fig pattern as every prior phase — one binary, no
  runtime toggle for this piece (matching 6a/6b-1/6b-2, none of which added a
  canary flag either), verified via the full test suite plus the manual check
  above before merge.

## Final State

- `libnetfilter_queue`'s C API is no longer called directly from
  `net-policy.cpp`/`.h` — all NFQ mechanics (open/bind/create/mode/receive/
  verdict) go through the new `net_nfq` Rust crate.
- `NFQ_RES_INFO` holds Rust-backed queue handles for its NFQ half and unchanged
  raw C pointers for its conntrack half, cleanly split along the 6b-3/6c
  boundary until 6c ports the latter.
- Netns switching is Rust-backed; the confirmed-dead "return to host namespace"
  machinery and `NfQueData::ClearNfQueResource` are deleted.
- `input_nfq_cb`/`output_nfq_cb`'s decision logic is byte-for-byte the same as
  before this phase — only the packet-id/payload extraction at the top and the
  verdict mechanism at every return point changed.
- Remaining before Phase 6 is fully done: Phase 6c (conntrack, FFI-wrap
  approach) — untouched by this phase, planned separately when its turn comes.
