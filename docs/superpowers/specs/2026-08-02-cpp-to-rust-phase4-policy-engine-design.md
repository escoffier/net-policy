# net-policy: Phase 4 — Policy Engine Migration Design

## Overview

Phase 4 of the C++→Rust migration (see the [overall roadmap](2026-07-29-cpp-to-rust-migration-design.md)) migrates the network policy matching engine — the CIDR-aware five-tuple rule storage and matching logic — to a new Rust crate, `net_policy_engine`. This is the logic that decides, for every packet on the enforcement hot path, which policy rule (if any) applies and what action it prescribes.

The original roadmap described this phase's scope as "`rule-detail.cpp` + the `RuleDetail`/`RuleGroup`/`RuleChain`/`PolicyTree`/`PolicyRule`/`MicroSegEngine` classes... pure logic, no kernel interaction... `MicroSegEngine` becomes the seam." A closer read of the actual code shows `MicroSegEngine` is a larger aggregate than that description suggests — it also owns NFQ resource lifecycle (via `PolicyRule : public NfQueData`, genuinely kernel/netlink code), HTTP L7 policy storage, a node-IP registry, and TCP connection tracking keyed on an HTTP-layer type. This spec narrows the scope accordingly: only the genuinely pure five-tuple/CIDR matching subset moves in this phase; everything else `MicroSegEngine` currently owns stays in C++ untouched.

This spec also confirms and acts on the roadmap's other Phase 4 note: `policy/engine.{h,cc}` (a separate `PolicyEngine` class in the `policy` namespace, with its own parallel, never-instantiated type system) is dead code — referenced nowhere outside its own two files, not in `CMakeLists.txt`'s `SOURCES` — and is deleted rather than migrated.

## Goals

- Move `RuleDetail`, `RuleGroup`, `RuleChain`, `PolicyTree`, and `PolicyRule`'s tree-management logic (`AddPolicyToTree`, `DeletePolicy`, `CreateRuleKeyByTuple`, `ClearCfg`, `AddMaskAndPriority`, `GetPolicyTree`) to Rust, along with the `ParseCidr`/`Ipv4CidrToIp` CIDR helpers.
- Preserve exact matching semantics, including undocumented quirks (e.g. the `end_port_ == 0` "any port" sentinel, ICMP's protocol-comparison special-case) — verified via differential testing against the real C++ implementation, not by manual re-derivation of the rules.
- Keep every existing call site (`net-policy.cpp`'s `MatchNetPolicyRule`, `grpc/control_dispatch.cc`'s `AddPolicyRule`/`DeletePolicyRule` dispatch functions from Phase 2) unchanged — only what's behind `PolicyRule`'s existing public methods changes.
- Delete the confirmed-dead `policy/engine.{h,cc}`.

## Non-Goals (deferred to later phases)

- **NFQ/netlink resource lifecycle** (`NfQueData`, `NFQ_RES_INFO`) — stays in C++; belongs to the later NFQ/netlink phase (Phase 6 in the original roadmap). `PolicyRule` keeps its `: public NfQueData` inheritance unchanged.
- **HTTP L7 policy matching** (`MicroSegEngine::AddHttpPolicy`/`InputHttpPolicy`/`OutputHttpPolicy`, `MatchHttpPolicyRule`) — stays in C++; not part of the five-tuple/CIDR matching engine, and touches HTTP-layer types not yet migrated.
- **Node-IP registry** (`MicroSegEngine::IsNodeIp`/`AddNodeIp`/`RemoveNodeIp`) — stays in C++; simple state unrelated to rule matching.
- **TCP connection tracking** (`MicroSegEngine::TcpCtInput`/`TcpCtOutput`) — stays in C++; keyed on `http::ConnectionPtr`, an HTTP-layer type out of scope here.
- **`PolicyRule::GetAllConfig`** (cJSON building + `net::ConnectionManager::stat()`) — stays a C++ function; it calls into Rust getters for rule data and builds JSON in C++, following the `proto_json_bridge` precedent from Phase 2 rather than moving JSON serialization into Rust.
- **`FiveTuple` itself** — stays a C++ struct. It's used pervasively outside policy matching (raw packet parsing, HTTP inspection), so it isn't moved to Rust ownership; its fields cross the FFI boundary by value, the same pattern Phase 3 used for `publish_policy_match`.

## Architecture

`PolicyRule` keeps its current public shape and its `NfQueData` inheritance. Its tree-related members (`input_tree_`, `output_tree_`, `mask_cidr_`, `priority_`) are replaced by a single opaque Rust engine handle, owned via `cxx::UniquePtr<RustPolicyEngine>` — constructed in `PolicyRule`'s constructor, destroyed automatically with it. (Named `RustPolicyEngine`, deliberately distinct from the dead `policy::PolicyEngine` class this same phase deletes, to avoid confusion during implementation.) `PolicyRule`'s tree-management methods become thin delegating wrappers around calls into that handle. This mirrors the pattern Phase 1 used for `waf/plugin.{h,cc}`: keep the C++ class's public interface stable, swap what's behind it. `MicroSegEngine` and the mutation call path need zero code changes — the `AddPolicyRule`/`DeletePolicyRule` dispatch functions (declared in `grpc/control_dispatch.h`, implemented in `net-policy.cpp`, from Phase 2) already call `PolicyRule::AddPolicyToTree`/`DeletePolicy` at single-call granularity and are unaffected by what's behind those methods.

`MatchNetPolicyRule` (`net-policy.cpp`) is the one exception, and does need a small edit — consistent with, not contradicting, the FFI-granularity decision below. Today it calls three separate `PolicyTree`-family methods in sequence: `GetPolicyTree(dir)` → `CreateRuleKeyByTuple(tuple, dir)` → a loop calling `MatchRuleGroup(key, tuple)` once per generated key. Once `PolicyTree`/`RuleChain`/`RuleGroup` no longer exist as C++ types to call methods on, this collapses into one call to the single-call match function described below (`PolicyRule` gains a new `MatchFiveTuple(FiveTuple&, FlowDir)` method that wraps it) — which is a strict simplification of `MatchNetPolicyRule`'s body, not a change to its signature, its caller, or its `IsNodeIp` early-return.

**Ownership model — a deliberate departure from Phase 2/3's precedent.** Phase 2 and 3 used process-wide `OnceLock` singletons for their Rust-side state, because that state genuinely was a single process-wide service (one gRPC server). The policy engine is different: it's data belonging to a specific `PolicyRule`/`DaemonContext` instance, and test binaries construct multiple such instances (sequentially, and potentially in parallel test runs) — a global singleton would mean cross-test contamination. `cxx::UniquePtr<RustPolicyEngine>` gives clean, ordinary per-instance ownership instead.

**FFI granularity — one call per logical operation, not one call per current C++ method.** Translating `GetPolicyTree` → `CreateRuleKeyByTuple` → a loop calling `MatchRuleGroup` method-for-method would cost 1+N FFI crossings per packet on the hot path. Instead:
- `rust_match_five_tuple(engine, tuple_fields.., dir) -> Option<matched rule fields>` does key generation, chain lookup, and rule matching internally in Rust in a single call.
- `rust_add_policy(engine, rule_fields.., port_fields..) -> i32` and `rust_delete_policy(engine, dir, name) -> i32` do the equivalent for mutation, at the same granularity Phase 2 used for its dispatch functions.

`RuleDetail`/`RulePort` cross the boundary as `cxx` shared structs (string fields as `rust::String`/`rust::Str`, `ports_` as `rust::Vec<SharedRulePort>`) rather than as long individual-scalar argument lists.

**UTF-8 guard requirement (carried forward from every prior phase).** Every string field crossing into Rust as `rust::Str`/`rust::String` — most relevantly `policy_key_`/`src_ip_`/`dst_ip_`/`action_dsc_` on the `AddPolicyRule` mutation path, sourced from gRPC requests — must be `IsValidUtf8`-guarded before the call, regardless of presumed trust level, matching this codebase's established discipline. The hot-path match call's fields (sourced from `inet_ntop`) are lower-risk but get the same treatment for consistency and defense-in-depth.

## Testing & Rollout

Before any cutover, a differential-test harness (`tests/policy_engine_differential_test.cc`) is built that:
- Generates many synthetic `(policy set, five-tuple)` combinations — varying protocol, CIDR-masked and exact addresses, port ranges (including the `end_port_ == 0` sentinel), priorities, directions.
- Constructs the real, unmodified old C++ `PolicyTree`/`RuleChain`/`RuleGroup` from each generated policy set, and separately the new Rust engine from the same set.
- Runs both against the same five-tuple and asserts identical verdicts (match/no-match, and if matched, the same `action_`).

This requires keeping the current C++ tree-matching code compiled and available for comparison throughout development — production still calls the old path until cutover — deleted only in the final cutover step. The harness is the mechanism that verifies every matching quirk is replicated exactly, without needing to manually enumerate them here; any divergence it finds that looks like a genuine C++ bug (not just an idiom difference) gets decided on its own merits at that point — replicate bug-for-bug with a tracked follow-up, or fix now — the same choice this project made for the `eval()` precedence bug in Phase 0/1.

**Overlapping-rule ambiguity.** `RuleGroup::MatchRule` iterates a `std::unordered_map` and returns the first rule whose `MatchRuleDetail` succeeds. If a generated policy set has multiple genuinely overlapping rules in the same chain-key group, "which one wins" depends on hash-iteration order — which is not guaranteed to agree between C++'s `std::unordered_map` and Rust's `HashMap` (different hashers), and isn't a real behavioral bug in either implementation (production configs shouldn't have ambiguous overlapping rules). The generator produces mostly non-overlapping policy sets (unambiguous winner) for the bulk of coverage, plus a smaller deliberately-overlapping subset where the assertion is relaxed to "some rule with the correct action matched" rather than requiring an identical `policy_key_` — so a real bug isn't lost in iteration-order noise, and iteration-order noise isn't mistaken for a bug.

**Cutover.** Once the differential suite passes fully:
1. Cut `PolicyRule`'s methods over to delegate to the Rust engine, in one commit.
2. Delete the old C++ `RuleDetail`/`RuleGroup`/`RuleChain`/`PolicyTree` class bodies from `net-policy.h`/`rule-detail.cpp`, and the `ParseCidr`/`Ipv4CidrToIp` helpers.
3. Delete the differential test file itself — once there's only one implementation, a test comparing two of them no longer makes sense. Ongoing matching correctness continues to be covered by Rust unit tests (mirroring `waf_rules_core`'s style) plus the existing `net_rule_test`/`net_rule_grpc_test` C++ integration tests that already exercise policy matching end-to-end (from Phase 2's work).
4. Delete `policy/engine.{h,cc}` and the stray `#include "policy/engine.h"` in `net-policy.h`.

This is a **direct cutover**, not a production shadow-run period (contrast with Phase 3's dual-publish approach for the event service). Rationale: unlike event publishing, which is a side effect safe to duplicate with no correctness risk, this is the actual allow/deny decision on the enforcement hot path — shadow-running it in production would mean either still enforcing via the old path during the shadow period (buying detection but not faster confidence than just closing the differential suite's gaps would) or enforcing via the new path (which is cutover with extra steps). The differential suite is the right tool for this class of bug: a pure function with no I/O, trivially fuzzable — the same reasoning that led Phase 0/1 to use differential/golden tests for the WAF regex engine rather than shadow-running that in production either.

## Final State

`net_policy_engine` is a new Rust crate, instance-owned (not a singleton) via `cxx::UniquePtr` inside `PolicyRule`, performing all CIDR/five-tuple/priority matching and rule-tree mutation. NFQ resource lifecycle, HTTP L7 policy, node-IP registry, and TCP connection tracking remain exactly as they are in C++ today. `policy/engine.{h,cc}` is deleted as confirmed dead code.
