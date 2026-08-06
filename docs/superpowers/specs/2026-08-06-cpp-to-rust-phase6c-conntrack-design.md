# Phase 6c: Conntrack Design

## Overview

Phase 6a's design spec split the original Phase 6 ("NFQ/netlink core") into
three independently-planned sub-phases: iptables + legacy-protocol retirement
(6a, shipped), the NFQ packet-queue/epoll/netns layer (6b, itself split into
6b-1 unified packet decision, 6b-2 microsegmentation TCP-tracking
consolidation, and 6b-3 NFQ netlink mechanics, all shipped), and conntrack
(6c, this spec) — scoped from the start for an FFI-wrap approach (Rust owns
the lifecycle/state-machine and call sequencing; `cxx` FFI calls into the
still-vendored `libnetfilter_conntrack` for the actual netlink protocol work)
rather than a full pure-Rust netlink reimplementation, given the immaturity of
the Rust conntrack-event-subscription ecosystem.

That immaturity was re-verified, not assumed, while writing this spec: the
`conntrack` crate on crates.io still only implements `dump()` as of today — no
mark mutation, no event-subscription callback — so the FFI-wrap decision
stands. Unlike Phase 6b-3's `nfq` crate situation (a pure-Rust crate existed
and just needed a small patch), there is no existing Rust wrapper for
`libnetfilter_conntrack` at any maturity level — not even a raw bindgen-style
FFI crate. This phase's new crate therefore declares its own `extern "C"`
bindings for the small, fixed set of C functions this codebase actually calls,
hand-written rather than `bindgen`-generated, matching this codebase's
established preference (visible throughout `net_nfq`) for small,
exactly-scoped, human-auditable FFI surfaces over pulling in more machinery
than a narrow need requires.

The exact C API surface this phase binds is verified against this repo's own
vendored header (`libnetfilter_conntrack/libnetfilter_conntrack.h`), not
assumed from upstream documentation — this vendored copy's `nfct_open()`
takes zero arguments, for example, differing from the signature shown in some
upstream libnetfilter_conntrack references. Every function signature this
plan's implementation ports must be re-verified against that same header
before being written into task-level code, the same discipline that caught a
real API-mismatch mistake during Phase 6b-3's planning.

## Goals

- New Rust crate, `net_conntrack` (`crates/net_conntrack/`), providing
  hand-written `extern "C"` declarations for exactly the C functions this
  codebase calls today: `nfct_new`, `nfct_open`, `nfct_close`, `nfct_destroy`,
  `nfct_query`, `nfct_callback_register`, `nfct_cmp`, `nfct_copy`,
  `nfct_get_attr_u32`, `nfct_set_attr_u32`, `nfct_set_attr_u8`,
  `nfct_set_attr_u16`, plus the `NFCT_T_*`/`NFCT_CMP_*`/`NFCT_CP_*`/`NFCT_Q_*`
  constants and `ATTR_MARK`/`ATTR_ORIG_*` attribute IDs those calls use.
  Linked against the already-vendored `libnetfilter_conntrack` C library — no
  new vendoring; only who calls it moves.
- Rust owns the **whole** per-pod conntrack lifecycle and call-sequencing —
  matching `net_nfq`'s shape from 6b-3 (C++ never called `nfq_open`/
  `nfq_bind_pf` individually; it called `open_queue()` once and Rust
  sequenced everything internally). A new opaque type,
  `net_conntrack::ConntrackSession`, bundles what `NFQ_RES_INFO` currently
  holds as four raw pointers (`nfct_`, `nfct_cb_`, `nfct_hd_`, `nfct_cb_hd_`)
  and exposes exactly two high-level operations to C++:
  - session open (replacing `OpenConntrack`), and
  - `set_accept_mark(tuple, mark)` (replacing `SetAcceptMark`, with
    `UpdateNetSession`'s comparison/mark-update logic moving entirely into
    Rust as the registered callback — not something C++ orchestrates
    step by step).
- `NFQ_RES_INFO`'s four `nfct_*` raw pointer fields become one
  `std::optional<rust::Box<net_conntrack::ConntrackSession>> conntrack_;` —
  the same `std::optional<rust::Box<T>>` pattern `input_queue_`/
  `output_queue_` already use, for the same reason (fallible construction;
  `rust::Box<T>` has no default constructor).
- Preserve `UpdateMark`'s exact current behavior, deliberately not
  redesigned: it is called once per pod, every time the `AddPolicyRule` gRPC
  RPC runs (via `ParseNetPolicy`, its real production handler — this is live
  traffic-affecting code, not dead), with today's always-empty `FiveTuple`
  and `mark = kDeny (0)`. Combined with `UpdateNetSession`'s logic (dump the
  conntrack table via that filter, and for any entry whose mark is ≤ 100,
  force-update it to match), the net effect is: **whenever any policy rule is
  added, every currently-tracked connection's conntrack mark is forced back
  toward deny** — presumably so already-established connections get
  re-evaluated against the new rule set rather than continuing to sail
  through on a stale accept mark. This is subtle and easy to "fix" by
  accident during a mechanical port; it must be preserved exactly and flagged
  explicitly as deliberate in the implementation's commit message, following
  this migration's established practice for every other preserved-but-
  surprising behavior (e.g. Phase 6b-2's RST-on-unknown-flow narrowing).

## Non-Goals

- **No pure-Rust netlink reimplementation of conntrack.** Re-confirmed against
  crates.io/docs.rs while writing this spec, not assumed from Phase 6a's
  original (now ~2-week-old) assessment: the `conntrack` crate still only
  supports `dump()`. This phase FFI-wraps the existing C library.
- **`bindgen`-generated bindings** — considered and rejected in favor of hand-
  written declarations. The C API surface actually used is small (~12
  functions) and fixed; hand-written declarations need no build-time
  `libclang` dependency and generate exactly what's used, not the full header
  tree's worth of unrelated declarations.
- **NFQ netlink mechanics, `NFQ_RES_INFO`'s NFQ fields, netns switching** —
  already `net_nfq`-backed since Phase 6b-3, untouched here.
- **No behavior change to `UpdateMark`'s call site, frequency, or its
  always-empty-tuple argument.** Whether that design is optimal is out of
  scope for this phase — it is ported, not redesigned.
- **Full deletion of the vendored `libnetfilter_conntrack` C library** —
  explicitly deferred by Phase 6a's original spec to a later follow-up,
  contingent on the Rust ecosystem maturing. This phase does not touch
  `CMakeLists.txt`'s `add_subdirectory(libnetfilter_conntrack)`/
  `target_link_libraries` wiring.
- **Heap profiling** (`admin/profile.{h,cc}`) — stays deferred to the
  Decommission phase, per Phase 6a's spec; the daemon remains substantially
  C++ after this phase (HTTP codecs, WAF plugin orchestration, `main.cpp`).

## Architecture

### 1. `net_conntrack` crate (`crates/net_conntrack/`)

New Cargo workspace member (`staticlib`, `cxx` dependency, no other crate
dependencies needed — this crate talks to the kernel exclusively through the
vendored C library's FFI, not through any Rust netlink stack), following the
per-phase-crate convention every prior phase used.

`extern "C"` block, declared against this repo's own vendored header
(`libnetfilter_conntrack/libnetfilter_conntrack.h`) — exact signatures
confirmed at spec-writing time, to be re-confirmed again at implementation
time:

```rust
#[repr(C)]
pub struct nf_conntrack { _private: [u8; 0] }   // opaque
#[repr(C)]
pub struct nfct_handle { _private: [u8; 0] }    // opaque

pub type NfcMsgType = c_int;   // NFC_MSG_TYPE is a plain C enum in this header

extern "C" {
    fn nfct_new() -> *mut nf_conntrack;
    fn nfct_destroy(ct: *mut nf_conntrack);
    fn nfct_open() -> *mut nfct_handle;             // zero args in THIS vendored header
    fn nfct_close(cth: *mut nfct_handle) -> c_int;
    fn nfct_callback_register(
        h: *mut nfct_handle,
        type_: NfcMsgType,
        cb: extern "C" fn(NfcMsgType, *mut nf_conntrack, *mut c_void) -> c_int,
        data: *mut c_void,
    ) -> c_int;
    fn nfct_cmp(ct1: *const nf_conntrack, ct2: *const nf_conntrack, flags: c_uint) -> c_int;
    fn nfct_copy(dest: *mut nf_conntrack, src: *const nf_conntrack, flags: c_uint);
    fn nfct_get_attr_u32(ct: *const nf_conntrack, type_: c_int) -> u32;
    fn nfct_set_attr_u8(ct: *mut nf_conntrack, type_: c_int, value: u8);
    fn nfct_set_attr_u16(ct: *mut nf_conntrack, type_: c_int, value: u16);
    fn nfct_set_attr_u32(ct: *mut nf_conntrack, type_: c_int, value: u32);
    fn nfct_query(h: *mut nfct_handle, query: c_uint, data: *const c_void) -> c_int;
}
```

(Exact constant values for `NFCT_T_ALL`, `NFCT_CMP_ORIG`, `NFCT_CMP_ALL`,
`NFCT_CMP_MASK`, `NFCT_CP_ORIG`, `NFCT_Q_DUMP`, `NFCT_Q_UPDATE`, `ATTR_MARK`,
`ATTR_ORIG_L3PROTO`, `ATTR_L4PROTO`, `ATTR_ORIG_IPV4_SRC`,
`ATTR_ORIG_IPV4_DST`, `ATTR_ORIG_PORT_SRC`, `ATTR_ORIG_PORT_DST` — copied
verbatim from the vendored header's enum definitions at implementation time,
not re-derived from memory.)

`cxx` bridge shape, mirroring `net_nfq`'s `open_queue`/`NfqQueue` pattern:

```rust
#[cxx::bridge(namespace = "net_conntrack")]
mod ffi {
    struct SharedFiveTuple {
        proto: u8,
        src_addr: String,   // dotted-decimal, matching FiveTuple::src_addr_'s
        dst_addr: String,   // current std::string representation
        src_port: u16,
        dst_port: u16,
    }

    extern "Rust" {
        type ConntrackSession;

        fn open_conntrack_session() -> Result<Box<ConntrackSession>>;
        fn set_accept_mark(
            self: &mut ConntrackSession, tuple: &SharedFiveTuple, mark: u32,
        ) -> Result<()>;
    }
}
```

### 2. `ConntrackSession`'s internals (`crates/net_conntrack/src/lib.rs` or a
   `session.rs` module, TBD at implementation time based on final file size)

```rust
pub struct ConntrackSession {
    filter: *mut nf_conntrack,       // was NFQ_RES_INFO::nfct_
    update: *mut nf_conntrack,       // was ::nfct_cb_
    query_handle: *mut nfct_handle,  // was ::nfct_hd_
    update_handle: *mut nfct_handle, // was ::nfct_cb_hd_
}
```

`open_conntrack_session()` ports `OpenConntrack` 1:1: allocates both
`nf_conntrack` objects and opens both handles, registers
`update_net_session` (below) on `query_handle` for `NFCT_T_ALL`, and returns
`Err` on any allocation/open failure — mirroring `OpenConntrack`'s existing
`GOTO_ERROR` cleanup-then-fail behavior, translated to `Drop` plus an early
`Err` return.

`set_accept_mark(tuple, mark)` ports `SetAcceptMark` 1:1: sets `ATTR_MARK` and
`ATTR_ORIG_L3PROTO` (`AF_INET`) unconditionally on `self.filter`, then sets
`ATTR_L4PROTO`/`ATTR_ORIG_IPV4_SRC`/`ATTR_ORIG_IPV4_DST`/
`ATTR_ORIG_PORT_SRC`/`ATTR_ORIG_PORT_DST` **only when the corresponding
tuple field is present** — `proto > 0`, `!src_addr.is_empty()`, `dst_port >
0`, etc., field-for-field matching the current C++ conditionals, not
simplified to "always set everything." Then issues
`nfct_query(query_handle, NFCT_Q_DUMP, &family)`, returning `Err` on a
non-zero result.

`extern "C" fn update_net_session(msg_type, ct, data) -> c_int` ports
`UpdateNetSession` 1:1: recovers `&mut ConntrackSession` from `data` via an
`unsafe` pointer cast (the one place in this crate's design that needs care —
narrowly scoped to this single function, matching the class of unsafe work
`net_nfq`'s vendored crate already does internally for its own callback/
buffer plumbing), compares `self.filter` against `ct` via `nfct_cmp(...,
NFCT_CMP_ORIG)`, reads the mark off `self.filter`, skips if `> 100`, copies
`ct`'s original-direction attributes into `self.update` via `nfct_copy(...,
NFCT_CP_ORIG)`, sets the same mark on `self.update`, skips the query if
`nfct_cmp(self.update, ct, NFCT_CMP_ALL | NFCT_CMP_MASK)` shows no change,
and otherwise issues `nfct_query(update_handle, NFCT_Q_UPDATE, self.update)`,
logging (not failing the whole batch) on a per-entry query failure — matching
`UpdateNetSession`'s existing `LOG_E`-and-continue behavior, since this
callback fires once per dumped conntrack entry and one entry's update
failure must not abort the rest of the dump.

`Drop for ConntrackSession` calls `nfct_destroy` on both `nf_conntrack`
objects and `nfct_close` on both handles — replacing `FreeResource`'s
existing conntrack teardown block.

### 3. C++ call-site changes (`net-policy.h`, `net-policy.cpp`, `rule-detail.cpp`)

- `NFQ_RES_INFO` drops its four `nfct_*` raw pointer fields in favor of
  `std::optional<rust::Box<net_conntrack::ConntrackSession>> conntrack_;`.
  `Init()` needs no explicit reset (a disengaged `std::optional` is the
  correct default state); `FreeResource`'s conntrack teardown block becomes
  `this->conntrack_.reset();` (Rust's `Drop` does the rest).
- `OpenConntrack(NFQ_RES_INFO*)` becomes a thin wrapper: `try { nfq_res->
  conntrack_.emplace(net_conntrack::open_conntrack_session()); } catch (...)
  { GOTO_ERROR/RETURN_ERROR(...); }`, called from `InitNfqueue` exactly where
  it is today, in the same position relative to `OpenNfque`/`AddEpollEvent`.
- `SetAcceptMark`'s one real call site, `UpdateMark` (`net-policy.cpp:1281-
  1294`), converts the C++ `FiveTuple` into the bridge's `SharedFiveTuple` (a
  handful of field copies, mirroring every prior phase's five-tuple bridging
  pattern) and calls `(*res->conntrack_)->set_accept_mark(tuple_bridge,
  mark)`. `SetAcceptMark`'s own current defensive checks (`!nfq_res`, `!ct`,
  `!cth` — each an explicit `RETURN_ERROR(-1, "...")` with a log message, not
  a silent no-op) are preserved by checking `res->conntrack_.has_value()`
  before the call and logging+skipping exactly like `RETURN_ERROR` does if
  it's empty — matching the old behavior rather than assuming this path is
  unreachable. It is expected to always be engaged in practice (`NewNfQueRes`
  only inserts a pod into the resource map after `InitNfqueue`'s full
  success, `OpenConntrack` included), the same way the old `nfct_`/`nfct_hd_`
  null checks were defensive-but-practically-always-true — this phase keeps
  the defensive check rather than removing it, since nothing about this port
  changes that invariant's provability.
- `UpdateNetSession` and `SetAcceptMark`'s standalone C++ function
  definitions are deleted outright, along with their forward declarations if
  any exist separately.

## Testing & Rollout

- **Real integration test** (`tests/net_conntrack_ffi_test.cc`,
  `NetConntrackFfiTest` suite, `CAP_NET_ADMIN`-gated, joining
  `NetIptablesFfiTest`/`NetNfqFfiTest` in the routine test filter's exclusion
  list — i.e. the filter becomes `-NetIptablesFfiTest.*:NetNfqFfiTest.*:
  NetConntrackFfiTest.*`, verified with the same single-leading-dash gtest
  syntax Phase 6b-3 established): open a real `ConntrackSession`, establish a
  genuine tracked connection via a real loopback UDP socket pair (simpler
  than TCP here — no handshake/teardown state machine to fight, and conntrack
  tracks UDP flows too), call `set_accept_mark` with a tuple matching that
  real flow and a test mark value, then verify the mark actually changed by
  querying that specific entry back (`nfct_query(..., NFCT_Q_GET, ...)` with
  a filter matching the tuple — more direct than re-dumping the whole table).
  Degrades to `GTEST_SKIP` if the environment can't complete a full check,
  matching `NetNfqFfiTest.OpenRoundTrip`'s established precedent from 6b-3.
- **Rust unit tests** for `set_accept_mark`'s conditional-attribute-setting
  logic specifically — factored so the "which tuple fields are present →
  which `nfct_set_attr_*` calls fire" mapping is testable in isolation from
  the actual `nfct_query` dispatch, the same "prove the mapping logic, not
  just that it compiles" bar Phase 6b-3's `verdict`/`verdict_with_mark` split
  was held to.
- **No differential harness.** This phase is a lifecycle/mechanics port, not
  new decision logic — `UpdateNetSession`'s comparison/mark-update logic is
  the one piece of real logic here, and its correctness is best proven by the
  integration test's direct assertion (did the live entry's mark actually
  change) rather than a differential comparison against a parallel old path,
  since there is no parallel old-Rust path to differentiate against.
- **Manual sanity check**, following every prior phase's final-task
  precedent: drive a real `AddPolicyRule` RPC through the production
  `net-rule` binary with a genuinely-tracked live connection present,
  confirm (via temporary, reverted debug output) that `set_accept_mark` runs
  without error and the live connection's conntrack mark actually flips.
- **Rollout**: direct cutover, no shadow-run, no runtime toggle — matching
  every prior phase on this codebase.

## Final State

- `libnetfilter_conntrack`'s C API is no longer called directly from
  `net-policy.cpp`/`.h`/`rule-detail.cpp` — all conntrack mechanics (session
  lifecycle, mark comparison/update) go through the new `net_conntrack` Rust
  crate. The vendored C library itself remains linked (full removal is a
  later follow-up, contingent on the Rust ecosystem maturing, per Phase 6a's
  original scoping).
- `NFQ_RES_INFO` holds Rust-backed handles for both its NFQ half (since
  6b-3) and its conntrack half (this phase) — no raw C netlink pointers of
  any kind remain in the struct.
- `UpdateMark`'s subtle "force every tracked connection's mark toward deny
  whenever a policy is added" behavior is preserved exactly, and explicitly
  documented as deliberate (not silently reproduced, not silently "fixed")
  in the implementation's commit message.
- **Phase 6 (NFQ/netlink core) is fully done.** Every piece of the original
  roadmap's Phase 6 scope — iptables, the legacy control protocol, NFQ
  packet-queue mechanics, netns switching, and conntrack — is now Rust-backed
  or FFI-wrapped. Remaining on the original roadmap: Phase 7 (Decommission —
  remove the C++ build target, the `cxx` bridge, the legacy Makefile, and all
  remaining C/C++ dependencies including the now-fully-unused-by-daemon-logic
  vendored netlink libraries, heap profiling, `cjson`, llhttp, nghttp2,
  pcre2, gflags, `fmt`, gperftools/`libunwind`, `glog`) — not yet planned,
  and gated on HTTP codecs/WAF plugin orchestration/`main.cpp` also moving to
  Rust first, none of which this phase or any of 6a/6b touched.
