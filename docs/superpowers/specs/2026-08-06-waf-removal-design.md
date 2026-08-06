# WAF Feature Removal Design

## Overview

This spec covers the complete removal of the WAF (Web Application Firewall)
feature from the daemon: `waf/plugin.{h,cc}`, `waf/rule.{h,cc}`, the
`waf_rules_core` Rust crate, the `AddWafRule`/`DeleteWafRule` gRPC RPCs, the
`WafAttackEvent` event stream message, and every call site that wires WAF into
the packet-processing path, the control plane, and the build.

**This is a deliberate deviation from this repo's own documented migration
roadmap**, not a continuation of it. `docs/superpowers/specs/2026-07-29-cpp-to-rust-migration-design.md`
(the master roadmap) treats WAF as a permanent feature being incrementally
ported to Rust — Phase 1 already moved WAF's regex/rule-matching engine to
Rust (`waf_rules_core`), with `waf/plugin.{h,cc}`'s filter-chain orchestration
explicitly slated to migrate to Rust in a later, not-yet-scheduled HTTP-codec
phase (Phase 3a/3b/3c in the original numbering). That phase never ran; this
spec replaces "eventually migrate WAF orchestration to Rust" with "delete WAF
entirely." The roadmap's stated end-state — "reach a fully-Rust codebase" —
implied a fully-Rust *WAF*; after this work, there is no WAF at all. Flagging
this explicitly, per this project's practice of never silently absorbing a
scope or direction change.

Full removal is being done now, ahead of Phase 7 (Decommission), because it
directly reduces Phase 7's blocking scope: Phase 7 was gated on three
untouched C++ subsystems (HTTP codecs, WAF plugin orchestration, `main.cpp`).
Removing WAF eliminates one of those three outright, rather than requiring it
to be migrated first.

## Goals

- Delete `waf/plugin.{h,cc}`, `waf/rule.{h,cc}`, and the `crates/waf_rules_core/`
  Rust crate in full.
- Remove WAF-only machinery from `net::ConnectionManager`
  (`net/connection_manager.h`): `DispatchWaf`, `HandleNewConnection`,
  `HandleClosed`, `HandleData`, `CloseHttpConn`, and the `http_conns_` map,
  plus the WAF-eviction half of `EvictStale()`'s engine-driven sweep loop
  (the `CloseHttpConn(id, PeerOf(id))` call and its explanatory comment) —
  while leaving `receive()`, `ReceiveResult`, `DispatchMicroseg`, every
  `Microseg*` helper, and `microseg_conns_`'s own age-sweep completely
  untouched. These are independent sibling dispatch paths inside the same
  class, not a shared mechanism WAF happens to also use — confirmed by
  reading both paths in full: `DispatchMicroseg`/`microseg_conns_` were
  built as deliberately separate from `http_conns_` specifically because
  their key semantics differ (documented in `MicrosegTrack`'s own comment
  and in `docs/superpowers/specs/2026-08-04-cpp-to-rust-phase6b2-microseg-consolidation-design.md`).
- Remove `DaemonContext`'s WAF wiring (`net-policy.h`): the `waf_root_`
  member, `WafRoot()` accessor, `WafEnabled()`/`SetWafEnabled()`/
  `waf_enable_`, and the constructor's `waf_root_.SetPostFd(post_server_.FdPtr())`
  line. `PostServer`/`CreatePostServer`/the port-8888 socket stay — 6 of its
  7 real uses (`PostServer::SendMatchMsg`) are policy-match notifications
  with no WAF involvement at all; only the WAF-to-`PostServer` fd wiring is
  WAF-specific.
- Remove the `PluginContext` filter registration from `RunNetPolicyDaemon`
  (`net-policy.cpp`) and the `WafEnabled()`-gated `DispatchWaf` calls from
  `input_nfq_cb`/`output_nfq_cb`. `LogFilter`'s registration and the generic
  `HttpFilterBase`/`HttpFilter`/`HttpFilterManager`/`HttpFilterFactory`
  infrastructure (`http/filter.h`) are untouched — WAF and `LogFilter` are
  independent siblings of the same generic interface; nothing about
  removing one affects the other's correctness or the interface itself.
- Remove the `POLICY_WAF_ENABLE` env var read and its `#define` (`log.h`).
- Drop `write_iptable_rule`'s `waf_enable: bool` parameter
  (`crates/net_iptables/src/lib.rs`) — its two `if !waf_enable { ... }`
  blocks (installing `CONNMARK --save-mark` on `INPUT`/`POSTROUTING`) become
  unconditional, exactly matching today's default behavior (`WafEnabled()`
  defaults to `false`), a deliberate no-op for the common case. The
  alternative reading (never install these rules, matching the WAF-on
  behavior) was considered and rejected — it would be an observable
  iptables-rule change for every default deployment, and nothing in the
  code indicates these rules are actively harmful when WAF-equivalent state
  doesn't exist.
- Delete `AddWafRule`/`DeleteWafRule` (RPCs, and the `WafRule`/
  `BlackWhiteListEntry`/`AddWafRuleRequest`/`DeleteWafRuleRequest` messages)
  from `net_policy_control.proto`, and `WafAttackEvent` (message + its
  `oneof event` arm) from `net_policy_events.proto` — entirely, not stubbed.
  A client calling either RPC afterward gets a real gRPC "method not found,"
  consistent with how every other phase of this migration has done direct
  cutovers with no compatibility shim. Delete the corresponding Rust
  handlers (`net_policy_control`'s `add_waf_rule`/`delete_waf_rule`,
  `net_policy_events`'s `publish_waf_attack`) and C++ dispatch functions
  (`GrpcDispatchAddWafRule`/`GrpcDispatchDeleteWafRule` in `net-policy.cpp`,
  their declarations in `grpc/control_dispatch.h`). `PolicyMatchEvent`/
  `publish_policy_match` and the shared `EventQueue`/`SubscribeEvents`
  streaming machinery are untouched — WAF's event was one `oneof` arm on
  shared infrastructure, not owned infrastructure.
- Remove the now-fully-vestigial `pcre2` link lines (`libpcre2-8.a`,
  `libpcre2-posix.a`) from `CMakeLists.txt`'s `net-rule`, `net_rule_test`,
  and `net_rule_grpc_test` targets. Confirmed via repo-wide grep that no
  first-party code calls any PCRE2 symbol — `waf/rule.cc`'s `Pcre2Regex`
  method is already fully Rust-backed via `waf_rules_core`'s
  `regex_first_match` (the name was kept only for API stability during an
  earlier phase, per that phase's own comment). Bundled into this work
  rather than filed separately, since WAF is the only reason these link
  lines existed and the context is freshest now.
- Delete `tests/waf_rules_test.cc` wholesale. Remove the WAF-specific test
  cases from `tests/grpc_rust_control_e2e_test.cc` (`DeleteWafRuleForUnknownPodReturnsZeroStatus`,
  `AddWafRuleWithMinimalFieldsReturnsOkStatus`) and
  `tests/grpc_rust_events_e2e_test.cc` (`SubscribeEventsReceivesPublishedWafAttack`,
  `PublishWafAttackToRustEventServiceSendsEvent`,
  `PublishWafAttackToRustEventServiceSkipsInvalidUtf8`, plus the now-unused
  `#include "waf/plugin.h"`) — both files have other, non-WAF tests that
  must stay.
- **Rewrite, not delete**, `tests/net_flow_engine_ffi_test.cc`'s two tests
  that currently use `DispatchWaf`/`http_conns_` as their mechanism for
  proving unrelated `ConnectionManager` behaviors:
  `HandleDataPassesTcpHeaderStartNotIpHeaderStartToFilters` (proves the
  filter chain receives a pointer starting at the TCP header, not the IP
  header) and `HandleClosedInvokesOnCloseAndRemovesBothConnections` (proves
  closing a connection tears down both directions' state exactly once).
  Both properties have a direct `DispatchMicroseg`/`microseg_conns_`
  analog (`MicrosegTracked`/`DispatchMicroseg` share the same
  `payload_offset` semantics; `MicrosegClose` has the same
  both-directions-erased invariant `HandleClosed` had) — retarget both
  tests at the microseg path so this regression coverage doesn't silently
  disappear along with WAF.
- Update `CLAUDE.md`: remove the architecture overview's WAF sentence, the
  data-flow diagram's "WAF rule evaluation" step, the component table's WAF
  row entirely (it currently says "PCRE2 regex pattern matching," already
  stale since `waf_rules_core` took over — moot once the row is deleted
  rather than corrected), the gRPC RPC surface list's `AddWafRule`/
  `DeleteWafRule` entries, and `pcre2` from the build-deps line.
- Add an explicit note to the master roadmap doc
  (`docs/superpowers/specs/2026-07-29-cpp-to-rust-migration-design.md`)
  recording that WAF was removed rather than migrated, and why, so the
  document's stated end-state stays accurate for future readers.

## Non-Goals

- HTTP codecs (`http/http1/`, `http/http2/`), `http/http_inspector.*`,
  `http/connection.*`, `http/url.*`, `http/header.*` — untouched. WAF was
  one consumer of the HTTP filter chain; the codecs and connection/filter
  infrastructure exist independently of WAF and remain fully C++ for now
  (Phase 7's other remaining blocker).
- `main.cpp` and the daemon's general startup/shutdown scaffolding —
  untouched beyond the specific WAF-wiring lines named above.
- Any change to microsegmentation's behavior, API, or test coverage beyond
  the two rewritten tests explicitly gaining microseg-based coverage.
- No compatibility shim, no deprecation window, no stubbed RPCs returning
  success — this is a direct, hard cutover matching every prior phase's
  style. A control-plane client still calling `AddWafRule`/`DeleteWafRule`
  after this change gets a real RPC error, not silent success.
- Full removal of the now-orphaned `libnetfilter_conntrack`-adjacent or any
  other vendored C dependency — out of scope; this spec's dependency
  cleanup is limited to `pcre2`, which is uniquely tied to WAF's history and
  already fully vestigial.

## Architecture

### 1. `net::ConnectionManager` (`net/connection_manager.h`)

Delete in full: `DispatchWaf`, `HandleNewConnection`, `HandleClosed`,
`HandleData`, `CloseHttpConn`, `http_conns_`.

In `EvictStale(now, timeout)`'s engine-driven sweep (the loop iterating
`engine_->evict_stale_connections()`), remove the `CloseHttpConn(id,
PeerOf(id))` call and its ~30-line comment block (entirely about WAF-onClose
semantics and the WAF-reap-is-unrecoverable asymmetry — none of it applies
once `CloseHttpConn` is gone). Keep `microseg_conns_.erase(id)` in the same
loop, and keep the second loop (the pure `microseg_conns_` age-sweep)
untouched.

`receive()`, `ReceiveResult`, `DispatchMicroseg`, `MicrosegTracked`,
`MicrosegRuleKey`, `MicrosegTouch`, `MicrosegTrack`, `MicrosegClose`, and
`microseg_conns_` are untouched — confirmed independent of WAF's machinery by
direct code reading (they maintain their own map, their own tracking
helpers, and were deliberately NOT unified with `http_conns_`'s design during
an earlier phase specifically because their key semantics differ).

### 2. `DaemonContext` and filter registration (`net-policy.h`, `net-policy.cpp`)

Remove `waf_root_` (the `http::extension::PluginRootContext` member),
`WafRoot()`, `WafEnabled()`/`SetWafEnabled()`/`waf_enable_`, and the
constructor's `waf_root_.SetPostFd(post_server_.FdPtr())` line. Remove the
`#include "waf/plugin.h"`.

Remove `RunNetPolicyDaemon`'s `PluginContext` `registerFilter(...)` block.
`LogFilter`'s registration stays exactly as-is — the two were independent
siblings of `HttpFilterBase`, registered through the same generic
`HttpFilterFactory::registerFilter` mechanism; nothing about that mechanism,
`HttpFilterManager`, or `LogFilter` itself needs to change.

Remove the `if (daemon->WafEnabled() && result.is_tcp) { DispatchWaf(...) }`
block from both `input_nfq_cb` and `output_nfq_cb`. Every surrounding
microsegmentation dispatch statement (`MicrosegTracked`/`MicrosegTouch`/
`DispatchMicroseg`/etc.) is untouched.

Remove the `POLICY_WAF_ENABLE` env var read in `RunNetPolicyDaemon` and its
`#define` in `log.h`.

### 3. `net_iptables` crate (`crates/net_iptables/src/lib.rs`)

`write_iptable_rule`'s signature drops `waf_enable: bool`. Its body's two
`if !waf_enable { run(bin, [... "CONNMARK", "--save-mark"]) }` blocks become
unconditional `run(...)` calls — always installing the `CONNMARK
--save-mark` rules on `INPUT` and `POSTROUTING`. This exactly reproduces
today's default behavior (`WafEnabled()` defaults to `false`, so these rules
already install in every deployment that doesn't explicitly set
`POLICY_WAF_ENABLE=true`); the one call site in `net-policy.cpp` drops the
trailing `daemon->WafEnabled()` argument to match.

### 4. Control-plane surface (`proto/`, `crates/net_policy_control/`, `crates/net_policy_events/`, `grpc/control_dispatch.h`, `net-policy.cpp`)

Delete from `proto/net_policy_control.proto`: the `AddWafRule`/`DeleteWafRule`
RPC declarations and the `WafRule`/`BlackWhiteListEntry`/`AddWafRuleRequest`/
`DeleteWafRuleRequest` messages.

Delete from `proto/net_policy_events.proto`: the `WafAttackEvent` message
and its arm in `PolicyEvent`'s `oneof event`. `PolicyMatchEvent` and the
`oneof`'s other arm are untouched.

Delete the Rust handlers `net_policy_control::add_waf_rule`/`delete_waf_rule`
(including their `cxx` bridge struct/function declarations for `WafRule`/
`BlackWhiteListEntry`/`GrpcDispatchAddWafRule`/`GrpcDispatchDeleteWafRule`)
and `net_policy_events::publish_waf_attack` (including its bridge
declaration). Delete the C++ dispatch functions `GrpcDispatchAddWafRule`/
`GrpcDispatchDeleteWafRule` (`net-policy.cpp`) and their forward declarations
(`grpc/control_dispatch.h`). `PublishWafAttackToRustEventService` (in
`waf/plugin.cc`, already being deleted with the rest of that file) has no
separate removal step of its own.

### 5. Build (`CMakeLists.txt`, `Cargo.toml`)

Delete `crates/waf_rules_core/` and its `Cargo.toml` workspace-member entry.
Remove `waf_rules_core_cxxbridge`'s `corrosion_add_cxxbridge` block and every
`target_link_libraries` reference to it (`net-rule`, `net_rule_grpc_test` —
`net_rule_test` never linked it).

Remove `waf/plugin.cc`/`waf/rule.cc` from `net-rule`'s and
`net_rule_grpc_test`'s `SOURCES` lists; delete `waf/` in full.

Remove `libpcre2-8.a`/`libpcre2-posix.a` from all three targets'
`target_link_libraries` (`net-rule`, `net_rule_test`, `net_rule_grpc_test`).

## Testing & Rollout

- Delete `tests/waf_rules_test.cc` in full, remove it from
  `net_rule_grpc_test`'s `SOURCES`.
- Remove the WAF-specific test cases (named above) from
  `tests/grpc_rust_control_e2e_test.cc` and `tests/grpc_rust_events_e2e_test.cc`,
  leaving both files' non-WAF tests (PodUp, PolicyRule CRUD,
  `PolicyMatchEvent` streaming, etc.) untouched.
- Rewrite `tests/net_flow_engine_ffi_test.cc`'s two `DispatchWaf`-based
  tests against `DispatchMicroseg`, preserving the exact properties they
  proved (TCP-header-offset-not-IP-header-offset handed to the filter
  chain; both-directions-torn-down-exactly-once on close) rather than
  simply deleting them and losing that regression coverage.
- `tests/connection_manager_test.cc`, `tests/codec_test.cc`,
  `tests/http_inspector_test.cc` — confirmed no real WAF coupling
  (the latter two only have coincidental `/waf/`-shaped URL strings in test
  fixtures); untouched.
- **No differential harness.** This is deletion of an already-well-isolated
  feature (once the `ConnectionManager` surgical edit separates WAF's
  machinery from microsegmentation's, confirmed independent by direct code
  reading), not new decision logic needing a parallel-path comparison. The
  real risk — did removing WAF's side effects break something that
  depended on them — is exactly what the rewritten tests plus a full clean
  build/test run catch.
- **Verification**: full build, then `net_rule_test` + `net_rule_grpc_test`,
  run 3× (matching this migration's established practice for changes
  touching the NFQ callback hot path), confirming the pass count drops by
  exactly the deleted WAF tests' count and every remaining test — including
  the two rewritten ones — passes.
- **Rollout**: direct cutover, no shadow-run, no runtime toggle, no
  deprecation window for the removed RPCs — matching every prior phase.

## Final State

- No WAF feature exists anywhere in the codebase: no `waf/` directory, no
  `waf_rules_core` crate, no `AddWafRule`/`DeleteWafRule`/`WafAttackEvent`
  on the control plane, no `WafEnabled()`/`POLICY_WAF_ENABLE` runtime
  toggle.
- `net::ConnectionManager` has exactly one HTTP-inspection-shaped dispatch
  path left (`DispatchMicroseg`), not two independent siblings — the
  `receive()`/five-tuple-parsing/TCB-tracking machinery it's built on is
  unchanged, since that was always shared infrastructure, never WAF-owned.
- `net-rule`'s iptables rule installation behavior is unconditionally what
  today's WAF-off default already produces — no observable change for any
  deployment that wasn't explicitly setting `POLICY_WAF_ENABLE=true`.
- `pcre2` is no longer linked into any target — a small, independent
  cleanup bundled in because WAF was its only historical justification.
- The master roadmap doc's stated end-state is corrected to reflect that
  WAF was removed, not migrated — this project's documentation stays
  accurate rather than silently drifting from what actually happened.
- **Phase 7 (Decommission)'s remaining blockers narrow from three
  subsystems to two: HTTP codecs and `main.cpp`.** WAF plugin orchestration
  is no longer one of them, since there's nothing left to migrate.
