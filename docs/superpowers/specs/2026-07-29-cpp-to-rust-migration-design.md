# net-policy: C++ → Rust Migration Design

## Overview

`net-policy` is a kernel-integrated network policy enforcement daemon: it
intercepts packets via Linux Netfilter (NFQ), applies Layer 3-4 policy rules,
and performs Layer 7 HTTP inspection and WAF filtering for containerized
workloads. The current implementation (~14k lines of first-party C++,
excluding vendored `cjson`, llhttp, nghttp2, and the libmnl/libnetfilter_queue
family) is to be migrated to Rust.

This document is a **phased migration roadmap**. Each phase is scoped enough
to plan sequencing and ownership; the detailed low-level design for a given
phase (module layout, exact crate APIs) is written just before that phase
starts, as its own spec.

## Goals

- Migrate the daemon to Rust without a production outage or a big-bang
  cutover.
- Preserve external behavior (policy semantics, WAF rule semantics, gRPC
  control-plane contract) unless a deliberate, called-out change is made.
- Reach a fully-Rust codebase with no C/C++ dependencies by the final phase.

## Strategy

**Strangler fig.** The C++ daemon keeps running in production throughout the
migration. Each phase converts one subsystem to Rust and wires it back into
the same process via a `cxx`-generated bridge — one binary, no IPC hop in the
packet-processing hot path. This was chosen over a parallel shadow deployment
or a big-bang rewrite because it lets every phase ship independently and keeps
the blast radius of any regression scoped to the subsystem just converted.

Conversion order is **outside-in**: self-contained, non-kernel-facing modules
first (WAF, control plane), core logic next (HTTP codecs, policy engine), and
the netlink/NFQ kernel interface last, since it is the highest-risk, most
kernel-coupled piece. The C++ build shrinks module-by-module; only once
nothing is left does the C++ toolchain, the `cxx` bridge, and the legacy
Makefile get deleted (Phase 7).

### Build integration

The repo becomes a mixed workspace during the migration: a `Cargo.toml`
workspace alongside the existing `CMakeLists.txt`, with `cxx-build` invoked
from CMake (via `corrosion` or a custom `add_custom_command`) so that
`cmake && make` keeps producing one `net-rule` binary at every phase. This is
established in Phase 0 before any behavior moves.

## Phase Breakdown

| Phase | Subsystem (current files) | Rust target | Notes |
|---|---|---|---|
| **0. Foundations** | — | Cargo workspace scaffold, `cxx` bridge skeleton, CMake↔Cargo build integration, CI updated to build both | No behavior change; proves the toolchain before any logic moves. |
| **1. WAF rule/regex engine** | `waf/rule.{h,cc}` (`Rules`, `Pcre2Regex`, `MatchIgnoreType`, `MatchDomain`, `MatchForceWhiteList`, `MatchBlackWhiteList`) | Rust crate using the `regex` crate | Requires a PCRE-feature audit of existing rules (backreferences, lookaround, possessive quantifiers are not supported by `regex`); any incompatible rules are rewritten as part of this phase. `waf/plugin.{h,cc}` (`PluginRootContext`/`PluginContext`) stays C++ for now and calls into the Rust rule engine via `cxx`. |
| **2. gRPC control plane** | `grpc/*` (`control_service`, `event_service`, `event_bridge`, `grpc_server`, `proto_json_bridge`, `work_queue`) | Rust crate using `tonic` + `prost` | The legacy raw-socket protocol (port 9999, `NetDataType` enum: `POD_PID`/`ADD_RULE`/`ADD_WAF_RULE`/etc.) is retired in this phase — gRPC becomes the only control plane. Talks to the still-C++ core (`MicroSegEngine`, `PolicyRule`) via `cxx` to apply rule/WAF-rule mutations. |
| **3a. HTTP/1.1 codec** | `http/http1/*` (llhttp-based) | `httparse` + hand-rolled incremental/streaming state | Must replicate llhttp's edge-case handling (chunked bodies, pipelining, request-smuggling defenses). Highest behavioral-parity risk in the migration. |
| **3b. HTTP/2 codec** | `http/http2/*` (nghttp2-based) | `h2` crate | `h2` is client/server-shaped; needs an adapter since the inspector observes traffic between two other parties rather than terminating a connection itself. |
| **3c. HTTP inspection orchestration** | `http/http_inspector.*`, `http/filter.*`, `http/http_filter_factory.*`, `http/connection.*`, `http/header.*`, `http/url.*` | Rust, built on 3a/3b | Wires codecs into the per-connection filter chain; depends on both codecs being done. |
| **4. Policy engine** | `rule-detail.cpp` + the `RuleDetail`/`RuleGroup`/`RuleChain`/`PolicyTree`/`PolicyRule`/`MicroSegEngine` classes declared in `net-policy.h` | Rust crate, pure logic | CIDR-aware five-tuple matching, no kernel interaction — well-isolated port. `MicroSegEngine` becomes the seam other phases call through via `cxx`. Note: `policy/engine.{h,cc}` (a separate `PolicyEngine` class) is **dead code** — it is not in `CMakeLists.txt`'s `SOURCES` and nothing else references it — so it is deleted rather than migrated; it is not the live policy engine. |
| **5. Network filters** | `net/filter.*`, `net/ip.*`, `net/tcp.*`, `net/udp.*`, `net/utility.*`, `net/connection_manager.h` | Rust crate | Operates on packet buffers already handed up from NFQ; no direct netlink dependency, so it can move before Phase 6. |
| **6. NFQ/netlink core** | `net-policy.cpp`/`.h` main loop, `NFQ_RES_INFO`, epoll wiring, `admin/profile.cc` (netns), vendored `libmnl`/`libnetfilter_queue`/`libnetfilter_conntrack`/`libnfnetlink` | Rust using pure-Rust netlink crates (e.g. `neli`, `nfq`) | Replaces the vendored C netlink libs entirely. Highest risk and effort; done last, after everything that calls into it already speaks Rust. |
| **7. Decommission** | — | — | Remove the C++ build target, `cxx` bridge, legacy Makefile, and all remaining C/C++ dependencies (`cjson`, llhttp, nghttp2, pcre2, libmnl family, `gflags`, `fmt`, gperftools/`libunwind`, `glog`). Rust-only build going forward. |

## Validation Strategy (per phase)

Each phase follows the same gate before its Rust component takes over from
the C++ one in production:

1. **Port existing tests** — the relevant GTest suite (`http_inspector_test.cc`,
   `codec_test.cc`, `connection_manager_test.cc`, `grpc_control_service_test.cc`,
   `grpc_e2e_test.cc`, `grpc_event_bridge_test.cc`, `http2/`) gets an
   equivalent Rust test suite.
2. **Differential harness** — a test tool feeds identical inputs (raw
   packets, HTTP messages, WAF payloads, control-plane RPCs) to both the old
   C++ path and the new Rust path through the `cxx` bridge, asserting
   identical verdicts/output.
3. **Runtime toggle** — each converted module is switchable at runtime (config
   flag) between the C++ implementation and the Rust implementation, so a
   phase can be canaried on a subset of pods before its C++ path is deleted.
4. Only after a phase passes both test tiers and a canary period does its C++
   source get deleted.

## Cross-Cutting Concerns

- **Logging**: `glog`/`LOG_E/W/I/D/V/T` macros → `tracing` crate; log level
  stays controllable at runtime via the (now gRPC-only) `LOG_LEVEL` message,
  bridged into `tracing`'s level filter.
- **JSON**: `cjson` usage in newly-converted modules → `serde_json`; `cjson`
  itself is deleted in Phase 7 once nothing references it.
- **Error handling**: internal Rust modules use `Result`/`thiserror`; the
  `cxx` boundary translates errors to the sentinel/status codes the
  still-C++ side expects, since `cxx` cannot propagate Rust panics as C++
  exceptions.
- **Build**: CMake stays the top-level driver throughout (per Phase 0) so
  `./build/net-rule` keeps working the same way at every phase; only in
  Phase 7 does the build become pure Cargo.
- **CLI/config**: `gflags`-based argument parsing → `clap`, converted in
  whichever phase first needs to add or change a flag (no dedicated phase,
  since it's a small surface).
- **Profiling/backtraces**: `gperftools`/`libunwind` → standard Rust panic
  backtraces (`RUST_BACKTRACE`) and, if heap profiling is still needed,
  `dhat` or an equivalent Rust profiler; addressed in Phase 6 since that's
  when the last C++ binary using them goes away.

## Key Risks

- **Phase 3a (HTTP/1.1)** carries the most behavioral-parity risk — llhttp's
  lenient/security-hardened parsing has to be matched exactly, or the
  differential harness will catch a divergence that an attacker could
  otherwise exploit.
- **Phase 6 (netlink)** is the largest engineering effort and sits directly in
  the kernel packet path — a regression here can drop or misroute live
  traffic, hence it is last and gated hardest.
- **WAF rule audit (Phase 1)** could surface rules that genuinely need
  PCRE-only features (backreferences, lookaround, possessive quantifiers); if
  so, those specific rules need a documented rewrite or an explicit exception
  before the `regex`-crate cutover for that rule.

## Decisions Made (for reference)

- Spec scope: phased roadmap, not a single comprehensive design.
- Rollout: strangler fig / incremental, not shadow deployment or big-bang.
- Netlink/NFQ layer: pure-Rust netlink crates, not FFI to the vendored C libs.
- WAF regex: audit existing rules and migrate to Rust's `regex` crate, not a
  PCRE2 FFI binding.
- HTTP/2: pure-Rust `h2` crate, not FFI to nghttp2.
- HTTP/1.1: pure-Rust `httparse` + hand-rolled incremental state, not FFI to
  llhttp.
- Control plane: gRPC only; the legacy raw-socket protocol (port 9999) is
  retired as part of this migration.
- C++/Rust interop during the migration: `cxx` crate bridge in a single
  process, not a separate process with IPC.
- Validation: golden/differential tests comparing Rust output against the
  existing C++ implementation, not Rust-only unit tests.
