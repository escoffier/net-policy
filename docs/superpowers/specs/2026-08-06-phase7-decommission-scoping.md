# Phase 7 Decommission Scoping

## Overview

This spec re-scopes the remainder of `docs/superpowers/specs/2026-07-29-cpp-to-rust-migration-design.md` (the master roadmap) now that WAF removal has landed. It does not design any single phase in detail — each phase still gets its own low-level design spec, written just before that phase starts, per the roadmap's own stated practice. This document exists because the roadmap's remaining phase count and numbering no longer matched reality, and that needed to be corrected before any of the remaining phases could be planned individually.

Two things changed the picture since the roadmap was written:

1. **WAF** (originally "Phase 1: WAF rule/regex engine") was deleted outright rather than migrated — already resolved, see `docs/superpowers/specs/2026-08-06-waf-removal-design.md`.
2. **Phase 6 ("NFQ/netlink core") turned out to be incomplete relative to its own stated scope.** Its row in the roadmap describes "`net-policy.cpp`/`.h` main loop, `NFQ_RES_INFO`, epoll wiring, `admin/profile.cc`" — but the actual completed sub-phases (6a, 6b-1, 6b-2, 6b-3, 6c) only migrated the low-level netlink *mechanics* (NFQUEUE operations, conntrack sessions, iptables rule writing) into Rust crates (`net_nfq`, `net_conntrack`, `net_iptables`). The daemon *orchestration* sitting on top of those mechanics — the epoll event loop itself, NFQ callback dispatch (SYN/FIN/dup/tracked/untracked branching), pod lifecycle management, and gRPC-dispatch JSON marshalling — is still real, substantial C++ logic. This was verified directly against the current codebase (see Inventory below), not assumed from the roadmap's row description.

The roadmap's "Phase 7 (Decommission)" was written assuming everything else would already be Rust by the time it started. That assumption no longer holds, so this document inserts the missing work as new phases and pushes the true decommission step to genuinely be last.

## Inventory (verified 2026-08-06, against the current `main` branch)

This is the factual basis for the scoping decisions below — sourced from a direct codebase read, not from the roadmap's descriptions.

- **`http/` (3,262 lines total)** — pure C++, untouched by any Rust migration. Uses `llhttp` directly (`http_inspector.{cc,h}`, `http1/codec.{cc,h}`) and `nghttp2` directly (`http2/codec.{cc,hh}`). `net/connection_manager.h`'s `DispatchMicroseg` is the actual call site that constructs and drives `http::Connection` — HTTP-codec migration is coupled to that file, not just to `http/` itself.
- **`net-policy.cpp` (2,044 lines) / `net-policy.h` (327 lines)** — **not thin wiring**. Real C++ logic: the epoll `while(1)` loop itself (`RunNetPolicyDaemon`, lines 1893-2044), the full NFQ callback state machines (`input_nfq_cb` ~318 lines, `output_nfq_cb` ~244 lines), pod lifecycle (`InitNfqueue`, `AddEpollEvent`, `OpenNfque`), and ~300 lines of cJSON-based JSON marshalling across the ten `GrpcDispatch*` handlers plus `ParseNetPolicy`/`ParseNodeCfg`/`dumpConnectons`. What *is* thin is only the leaf calls into already-Rust crates (`net_flow_engine`, `net_policy_engine`, `net_nfq`, `net_conntrack`, `net_iptables`) — the branching, sequencing, and (de)serialization around those calls is hand-written C++.
- **`rule-detail.cpp` (311 lines)** — mixed. `PolicyRule`'s matching/storage methods are thin wrappers over `policy_engine::RustPolicyEngine` (confirms the roadmap's Phase 4 claim), but `GetAllConfig` (cJSON tree-building), `FiveTuple`'s methods, and `NFQ_RES_INFO`/`NfQueData` (resource lifecycle, `std::optional<rust::Box<T>>` teardown) are real C++ tightly coupled to `net-policy.cpp`'s pod lifecycle.
- **`admin/profile.cc` (58 lines)** — thin `gperftools` (`HeapProfilerStart/Stop/Dump`) wrapper; sole first-party consumer of `gperftools`/`libunwind`.
- **`grpc/control_dispatch.cc` (33 lines)** — small but real: the mutex-guarded queue + eventfd mechanism that lets Rust's `net_policy_control` tokio threads hop work onto the C++ epoll thread. Not deletable in isolation — needs rethinking once the epoll loop itself is Rust.
- **`cjson.c`/`.h` (vendored, 3,210 lines)** — used pervasively: 120 call sites in `net-policy.cpp`, 28 in `rule-detail.cpp`, 2 in `admin/profile.cc`.
- **Vendored deps whose *sole* first-party consumer is `http/`:** `nghttp2`, `llhttp`, `fmt` (the latter only via `http/packet.cc`). Everything else linked into `net-rule` — `glog`, `gflags`, `gperftools`/`libunwind`, `cjson`, the `libmnl`/`libnetfilter_*` family — either has consumers outside `http/` or (for the netfilter family) is now consumed by Rust crates directly, not remaining C++.

## Goals

- Correct the roadmap's phase numbering and scope to match the verified inventory above, inserting the previously-invisible daemon-orchestration work as its own phase rather than silently folding it into "Decommission."
- Preserve the roadmap's original Phase 3a/3b/3c numbering and scope for the HTTP codec/inspection layer — confirmed still wanted, not up for the same reconsideration WAF got.
- Name the new phase for the daemon-orchestration gap **"6d"** rather than a new top-level number, to signal explicitly that it completes Phase 6's own originally-stated scope rather than being unrelated new work.
- Restore "Phase 7 (Decommission)" to genuinely being the last phase, with its original scope and intent unchanged — it just now follows 6d instead of directly following 6c.
- Leave every phase's low-level design (module layout, exact crate APIs, the epoll-loop redesign question, the `control_dispatch.cc` replacement question) to that phase's own future spec, written just before it starts — this document only sequences and scopes, per the roadmap's own established practice.

## Non-Goals

- No low-level design for 3a/3b/3c or 6d — those come later, each as its own `brainstorming` → `writing-plans` cycle.
- No reconsideration of whether to migrate HTTP codecs at all — explicitly confirmed still wanted, unlike WAF.
- No decision here on 6d's hardest open question (how the epoll loop and `control_dispatch.cc`'s cross-thread queue get redesigned once the loop itself is Rust) — flagged for 6d's own spec, not resolved now.

## Architecture

Revised phase sequence, in execution order, replacing the roadmap's remaining rows:

| Phase | Scope | Rust target | Status |
|---|---|---|---|
| **3a. HTTP/1.1 codec** | `http/http1/*` (llhttp-based) | `httparse` + hand-rolled incremental/streaming state, matching llhttp's chunked-body/pipelining/request-smuggling-defense behavior | Not started |
| **3b. HTTP/2 codec** | `http/http2/*` (nghttp2-based) | `h2` crate + an adapter, since `h2` is client/server-shaped but the inspector passively observes traffic between two other parties | Not started |
| **3c. HTTP inspection orchestration** | Everything else under `http/` (`http_inspector`, `filter`, `http_filter_factory`, `connection`, `header`, `url`, `packet`, `temporary_buffer`) | Rust, built on 3a/3b. Rewires `net/connection_manager.h`'s `DispatchMicroseg` — today's actual `http::Connection` call site — to call the new Rust HTTP stack instead. `llhttp`/`nghttp2`/`fmt` drop from the C++ link line once this lands. | Not started |
| **6d. Daemon orchestration** *(new — completes Phase 6's original scope)* | `net-policy.cpp`/`.h`'s epoll loop, NFQ callback dispatch, pod lifecycle, gRPC JSON marshalling; folds in `rule-detail.cpp`'s remaining real logic (`GetAllConfig`, `NFQ_RES_INFO`, `NfQueData`), `grpc/control_dispatch.cc`'s work queue, `admin/profile.cc` | Rust — becomes the driver calling the already-Rust crates directly (no more `cxx` roundtrip) and into Phase 3's Rust HTTP stack. Open design questions (epoll-loop redesign around tokio's reactor; what replaces `control_dispatch.cc`'s cross-thread queue) deferred to this phase's own spec. | Not started |
| **7. Decommission** | Delete the C++ build target, `cxx` bridge, legacy Makefile, `cjson`, and any vendored dep not already gone (`glog`, `gflags`, `gperftools`/`libunwind`, `libmnl` family if unused by then) | — Rust-only build going forward | Unchanged from original roadmap; now genuinely last |

## Testing & Rollout

Each new phase (3a, 3b, 3c, 6d) follows the roadmap's existing "Validation Strategy (per phase)" section unchanged: port the relevant GTest suite to Rust, run a differential harness feeding identical inputs through both the C++ and Rust paths, and gate the cutover behind a runtime toggle canaried per-pod before the C++ path is deleted.

**6d's runtime toggle is a materially harder case than earlier phases'.** Phases 0–6c and 3a–3c each toggle a single component (e.g. "does this five-tuple match go to C++ or Rust?") with both implementations coexisting cheaply in the same process. 6d replaces the entire epoll event loop — there is no equivalently cheap way to run two loops side-by-side per-pod. Whether 6d's own design resolves this via a process-level toggle (canary by pod-scheduling between two whole-daemon binaries, rather than an in-process flag) or some other mechanism is explicitly left open for that phase's spec.

This scoping document does not write per-phase test plans or low-level designs. Each phase gets its own spec via the same `brainstorming` → `writing-plans` → `subagent-driven-development` flow already used for every completed phase, written just before that phase starts.

## Final State (of this scoping pass, not of the migration)

- The master roadmap's remaining rows are understood to be: 3a, 3b, 3c, 6d, 7 — in that order.
- 3a is next up for its own design spec.
- No code changes result from this document — it is a sequencing/scoping correction only.
