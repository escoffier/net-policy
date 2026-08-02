# Phase 4: Policy Engine Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the CIDR-aware five-tuple policy matching engine (`RuleDetail`/`RuleGroup`/`RuleChain`/`PolicyTree`/`PolicyRule`'s tree logic) from C++ to a new Rust crate, `net_policy_engine`, verified via differential testing against the real C++ implementation before cutover.

**Architecture:** `PolicyRule` (net-policy.h/rule-detail.cpp) keeps its public shape and its `NfQueData` inheritance, but its tree-related members are replaced by an opaque `cxx::UniquePtr<RustPolicyEngine>` handle, owned per-instance (not a singleton, unlike Phase 2/3). A differential test harness compares the real C++ matcher against the new Rust engine across many generated cases before the final cutover deletes the old C++ classes.

**Tech Stack:** Rust (`cxx` crate for FFI, `staticlib` crate type, Corrosion for CMake integration — same toolchain as `waf_rules_core`/`net_policy_control`/`net_policy_events`), C++17, Google Test.

**Reference spec:** `docs/superpowers/specs/2026-08-02-cpp-to-rust-phase4-policy-engine-design.md`

## Global Constraints

- Every string field crossing into Rust as `rust::Str`/`rust::String` must be `IsValidUtf8`-guarded (via `common/utf8_check.h`, already promoted to shared use in Phase 3) before the call — `rust::Str`'s constructor throws `std::invalid_argument` on invalid UTF-8, and none of this phase's call sites have an enclosing try/catch.
- `NfQueData`/`NFQ_RES_INFO`, `MicroSegEngine`'s HTTP L7 policy/node-IP registry/TCP connection tracking, and `FiveTuple` itself are OUT OF SCOPE — do not modify them beyond what's explicitly listed in a task's Files section.
- `mask_cidr_`/`priority_` are `std::set<int>` in C++ (sorted ascending iteration) — their Rust equivalents MUST be `BTreeSet<i32>`, not `HashSet<i32>`. `CreateRuleKeyByTuple` generates candidate match keys in priority-then-mask order, and the caller returns on the first key that finds a match — a `HashSet`'s unspecified iteration order would make matching nondeterministic across otherwise-identical runs.
- Never `git worktree` inside the `net-policy-build-test` Docker container (it bind-mounts the same host repo, and has wiped the host's worktree registry twice in this project's history) — use `git archive <commit> | tar -x -C /tmp/<unique-dir>` instead.
- Verify every code snippet and line number in this plan against the actual current source before editing — line numbers may have drifted from when this plan was written.

---

### Task 1: Scaffold the `net_policy_engine` Rust crate and wire it into CMake

**Files:**
- Create: `crates/net_policy_engine/Cargo.toml`
- Create: `crates/net_policy_engine/src/lib.rs`
- Modify: `Cargo.toml` (repo root — add to workspace `members`)
- Modify: `CMakeLists.txt` (add `corrosion_add_cxxbridge` block, link into `net-rule` and `net_rule_grpc_test` — NOT `net_rule_test`, which deliberately excludes `rule-detail.cpp`/policy-engine code per the comment at its `add_executable` block)

**Interfaces:**
- Produces: an empty-but-real `#[cxx::bridge]` module (cxxbridge hard-errors on a module with zero bridge items — Phase 2's Task 3 hit this; a minimal stub avoids it) that later tasks extend.

- [ ] **Step 1: Create the crate**

`crates/net_policy_engine/Cargo.toml`:
```toml
[package]
name = "net_policy_engine"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
cxx = "1"
```

`crates/net_policy_engine/src/lib.rs`:
```rust
#[cxx::bridge(namespace = "policy_engine")]
mod ffi {
    extern "Rust" {
        fn policy_engine_ffi_smoke() -> i32;
    }
}

fn policy_engine_ffi_smoke() -> i32 {
    42
}
```

- [ ] **Step 2: Add to the Cargo workspace**

Read the current root `Cargo.toml` first (`cat /Users/robbieqiu/workspace/net-policy/Cargo.toml` or equivalent in your worktree) to get its exact current `members` list, then add `"crates/net_policy_engine"` to it. As of this writing it reads:
```toml
[workspace]
resolver = "2"
members = ["crates/ffi_smoke", "crates/waf_rules_core", "crates/net_policy_control"]
```
(If a `net_policy_events` entry is present — from Phase 3, once merged — keep it; just add `net_policy_engine` alongside whatever is already there.)

- [ ] **Step 3: Wire into CMake**

Read the current `CMakeLists.txt`'s existing `corrosion_add_cxxbridge` blocks (search for `corrosion_add_cxxbridge` — there are blocks for `ffi_smoke_cxxbridge`, `waf_rules_core_cxxbridge`, `net_policy_control_cxxbridge`, matching the pattern below) and add a new block immediately after the last one, following the exact same style:
```cmake
corrosion_add_cxxbridge(net_policy_engine_cxxbridge
  CRATE net_policy_engine
  FILES lib.rs
)
```
Then find `target_link_libraries(net-rule ...)` and `target_link_libraries(net_rule_grpc_test ...)` and add `net_policy_engine_cxxbridge` to both lists, alongside the existing `waf_rules_core_cxxbridge`/`net_policy_control_cxxbridge` entries. Do NOT add it to `net_rule_test`'s link list — that target doesn't compile `rule-detail.cpp` and won't need this crate until (never, in this phase) it does.

Update the comment above `set_target_properties(net-rule PROPERTIES LINK_FLAGS "-Wl,--allow-multiple-definition")` that explains why the flag is needed (it currently names 2 or 3 cxxbridge crates depending on whether Phase 3 has merged) to include `net_policy_engine_cxxbridge` in its list.

- [ ] **Step 4: Build and verify**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -80"
```
Expected: clean build, zero new warnings under `-Wall -Werror` (the only expected warnings are the known-harmless Cargo jobserver messages — grep the log for `warning|error`, excluding lines containing `jobserver`).

- [ ] **Step 5: Commit**

```bash
git add crates/net_policy_engine Cargo.toml CMakeLists.txt
git commit -m "Scaffold net_policy_engine Rust crate and wire into CMake"
```

---

### Task 2: Port the CIDR helper functions to Rust

**Files:**
- Modify: `crates/net_policy_engine/src/lib.rs` (add `parse_cidr`/`ipv4_cidr_to_ip`, private to the crate — not exposed over FFI yet)

**Interfaces:**
- Produces: `fn parse_cidr(cidr: &str) -> (String, i32)`, `fn ipv4_cidr_to_ip(ip: &str, mask: i32) -> String` — pure functions, consumed by Task 3/4.

The C++ originals (`rule-detail.cpp`, read them yourself to confirm current line numbers and exact text before porting):
```cpp
static std::pair<std::string, int> ParseCidr(const std::string& cidr) {
  struct in_addr addr;
  uint32_t uzIpaddr, uzMask;
  std::string sip = cidr;
  int mask = 32;
  auto index = cidr.find('/');
  if (index != std::string::npos) {
    sip  = cidr.substr(0, index);
    mask = std::stoi(cidr.substr(index + 1));
  }
  uzIpaddr = ntohl(inet_addr(sip.c_str()));
  uzMask   = ~0u << (32 - mask);
  uzIpaddr &= uzMask;
  addr.s_addr = htonl(uzIpaddr);
  char buf[INET_ADDRSTRLEN];
  return { inet_ntop(AF_INET, &addr, buf, sizeof(buf)), mask };
}

std::string Ipv4CidrToIp(std::string ip, int mask) {
  struct in_addr addr;
  uint32_t uzIpaddr, uzMask;
  uzIpaddr = ntohl(inet_addr(ip.c_str()));
  uzMask = ~0u << (32 - mask);
  uzIpaddr &= uzMask;
  addr.s_addr = htonl(uzIpaddr);
  char buf[INET_ADDRSTRLEN];
  return inet_ntop(AF_INET, &addr, buf, sizeof(buf));
}
```

**Known edge case to flag, not silently resolve:** `~0u << (32 - mask)` is undefined behavior in C++ when `mask == 0` (shifting a 32-bit value left by 32). In practice this happens to behave as a no-op shift on the platforms this runs on (so `mask == 0` produces a full `0xFFFFFFFF` mask, not the mathematically-expected `0x00000000` for a `/0` CIDR) — but that's UB, not a portable guarantee, and `AddMaskAndPriority` normally filters `mask` to `(0, 32]` before it reaches storage, so this specific UB path may not be reachable from the real production call chain. `ParseCidr` itself has no such guard, though (it's called directly from `CreateRuleKey` on arbitrary `src_ip_`/`dst_ip_` strings, which could contain `/0`). Port `parse_cidr` to replicate the platform's actual (non-portable) behavior — `1u32.wrapping_shl(32 - mask as u32)` style, using Rust's well-defined wrapping-shift semantics tuned to match what the C++ actually does at runtime on this platform, NOT what standard CIDR math would say — and flag this explicitly for the differential test (Task 6) to exercise `mask == 0` as a generated case. If Task 6 finds a real discrepancy here, follow this project's established practice (see the design spec's Testing & Rollout section): decide replicate-bug-for-bug vs. fix-now on its own merits, don't silently pick one.

- [ ] **Step 1: Write the failing tests**

Add to `crates/net_policy_engine/src/lib.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_masks_to_network_address() {
        assert_eq!(parse_cidr("10.1.2.3/24"), ("10.1.2.0".to_string(), 24));
        assert_eq!(parse_cidr("192.168.5.9/16"), ("192.168.0.0".to_string(), 16));
    }

    #[test]
    fn parse_cidr_bare_ip_defaults_to_slash_32() {
        assert_eq!(parse_cidr("10.1.2.3"), ("10.1.2.3".to_string(), 32));
    }

    #[test]
    fn parse_cidr_slash_32_is_identity() {
        assert_eq!(parse_cidr("10.1.2.3/32"), ("10.1.2.3".to_string(), 32));
    }

    #[test]
    fn ipv4_cidr_to_ip_masks_to_network_address() {
        assert_eq!(ipv4_cidr_to_ip("10.1.2.3", 24), "10.1.2.0");
        assert_eq!(ipv4_cidr_to_ip("10.1.2.3", 32), "10.1.2.3");
    }
}
```

- [ ] **Step 2: Run to verify the tests fail** (function not yet defined)

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/crates/net_policy_engine && cargo test 2>&1 | tail -40"
```
Expected: compile error, `parse_cidr`/`ipv4_cidr_to_ip` not found.

- [ ] **Step 3: Implement**

```rust
fn parse_cidr(cidr: &str) -> (String, i32) {
    let (ip_str, mask): (&str, i32) = match cidr.find('/') {
        Some(idx) => (&cidr[..idx], cidr[idx + 1..].parse().unwrap_or(32)),
        None => (cidr, 32),
    };
    let ip_u32: u32 = ip_str.parse::<std::net::Ipv4Addr>().map(u32::from).unwrap_or(0);
    let net_mask: u32 = (!0u32).wrapping_shl((32 - mask) as u32);
    let masked = ip_u32 & net_mask;
    (std::net::Ipv4Addr::from(masked).to_string(), mask)
}

fn ipv4_cidr_to_ip(ip: &str, mask: i32) -> String {
    let ip_u32: u32 = ip.parse::<std::net::Ipv4Addr>().map(u32::from).unwrap_or(0);
    let net_mask: u32 = (!0u32).wrapping_shl((32 - mask) as u32);
    std::net::Ipv4Addr::from(ip_u32 & net_mask).to_string()
}
```
Note: Rust's `wrapping_shl` takes the shift amount modulo the type's bit width (32 for `u32`), which is exactly the "no-op on shift-by-32" platform behavior being replicated — confirm this matches what the differential test observes from the real C++ binary in Task 6 rather than assuming it; if the platform's actual C++ behavior differs, adjust here instead of carrying a silent mismatch forward.

- [ ] **Step 4: Run to verify the tests pass**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/crates/net_policy_engine && cargo test 2>&1 | tail -40"
```
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/net_policy_engine/src/lib.rs
git commit -m "Port CIDR helper functions to net_policy_engine"
```

---

### Task 3: Port `RuleDetail`/`RuleGroup`/`RuleChain`/`PolicyTree` matching logic to Rust

**Files:**
- Modify: `crates/net_policy_engine/src/lib.rs` (add the Rust data model and matching logic — pure Rust, no FFI wiring yet)

**Interfaces:**
- Consumes: `parse_cidr` (Task 2).
- Produces: `RuleDetail`, `RulePort`, `FlowDir`, `RuleGroup`, `RuleChain`, `PolicyTree` Rust types and their methods, consumed by Task 4's `RustPolicyEngine`.

Read `rule-detail.cpp` and `net-policy.h` (the `RuleDetail`/`RuleGroup`/`RuleChain`/`PolicyTree` class declarations, roughly lines 242-336 as of this writing, and `RuleDetail::MatchRuleDetail`/`RuleGroup::AddRuleDetail`/`RuleGroup::MatchRule`/`RuleChain::MatchRuleGroup`/`RuleChain::AddRuleToChain`/`RuleChain::DeleteRuleFromChain`/`PolicyTree::AddPolicyToChain`/`PolicyTree::DeletePolicyFromTree` in `rule-detail.cpp`) yourself before porting — line numbers may have drifted.

- [ ] **Step 1: Define the data model**

Add to `crates/net_policy_engine/src/lib.rs`:
```rust
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlowDir {
    Ingress,
    Egress,
}

#[derive(Clone, Debug)]
struct RulePort {
    end_port: u16,
    port: u16,
    proto: u8,
}

#[derive(Clone, Debug)]
struct RuleDetail {
    proto: u8,
    priority: i32,
    addr_type: i32,
    direction: FlowDir,
    action: u32,
    action_dsc: String,
    policy_key: String,
    src_ip: String,
    dst_ip: String,
    ports: Vec<RulePort>,
}

const IPPROTO_ICMP: u8 = 1;

impl RuleDetail {
    /// Mirrors RuleDetail::CreateRuleKey (rule-detail.cpp) exactly, including
    /// which address gets CIDR-masked per direction.
    fn create_rule_key(&self) -> (String, i32) {
        match self.direction {
            FlowDir::Ingress => {
                let (ip, mask) = parse_cidr(&self.src_ip);
                (format!("{}-{}-{}/{}-{}", self.priority, self.proto, ip, mask, self.dst_ip), mask)
            }
            FlowDir::Egress => {
                let (ip, mask) = parse_cidr(&self.dst_ip);
                (format!("{}-{}-{}-{}/{}", self.priority, self.proto, self.src_ip, ip, mask), mask)
            }
        }
    }

    /// Mirrors RuleDetail::MatchRuleDetail exactly, including the ICMP
    /// protocol special-case (packet protocol is overwritten with the rule's
    /// own proto before comparing, forcing the protocol check to pass for
    /// ICMP regardless of the rule's configured protocol), the
    /// end_port == 0 "any port" sentinel, and the DNS (port 53) short-circuit.
    fn matches(&self, proto: u8, dst_port: u16, src_port: u16) -> bool {
        let mut protocol = proto;
        if protocol == IPPROTO_ICMP {
            protocol = self.proto;
        }
        if !(self.proto == 0 || protocol == self.proto) {
            return false;
        }
        let mut is_match = self.ports.is_empty() || proto == IPPROTO_ICMP;
        for port in &self.ports {
            if port.end_port == 0 {
                is_match = true;
                break;
            }
            if dst_port > port.end_port {
                continue;
            }
            if dst_port < port.port {
                continue;
            }
            is_match = true;
            break;
        }
        if !is_match {
            return false;
        }
        if src_port == 53 || dst_port == 53 {
            return true;
        }
        true
    }
}

struct RuleGroup {
    /// keyed by policy_key, mirroring RuleGroup::rules_
    rules: HashMap<String, RuleDetail>,
}

impl RuleGroup {
    fn new() -> Self {
        RuleGroup { rules: HashMap::new() }
    }

    /// Mirrors RuleGroup::AddRuleDetail: clears the incoming rule's ports,
    /// then either inserts it fresh (with just the one port) or, if a rule
    /// with the same policy_key already exists in this group, appends the
    /// port to the existing entry's port list instead of overwriting it.
    fn add_rule_detail(&mut self, mut rule: RuleDetail, port: RulePort) {
        rule.ports.clear();
        match self.rules.get_mut(&rule.policy_key) {
            None => {
                rule.ports.push(port);
                self.rules.insert(rule.policy_key.clone(), rule);
            }
            Some(existing) => {
                existing.ports.push(port);
            }
        }
    }

    fn delete_rule(&mut self, policy_name: &str) {
        self.rules.remove(policy_name);
    }

    /// Mirrors RuleGroup::MatchRule. Iteration order over `rules` is a
    /// HashMap here (vs. C++'s std::unordered_map) -- if a generated test
    /// case has multiple genuinely overlapping rules in the same group, the
    /// two implementations may legitimately disagree on which one "wins",
    /// since neither language guarantees hash-iteration order. This is
    /// expected and handled by Task 6's differential-test design, not a bug
    /// to fix here.
    fn match_rule(&self, proto: u8, dst_port: u16, src_port: u16) -> Option<RuleDetail> {
        self.rules.values().find(|r| r.matches(proto, dst_port, src_port)).cloned()
    }

    fn size(&self) -> usize {
        self.rules.len()
    }
}

struct RuleChain {
    dir: FlowDir,
    /// keyed by rule key (RuleDetail::create_rule_key's output), mirroring
    /// RuleChain::chain_
    chain: HashMap<String, RuleGroup>,
}

impl RuleChain {
    fn new(dir: FlowDir) -> Self {
        RuleChain { dir, chain: HashMap::new() }
    }

    fn size(&self) -> usize {
        self.chain.len()
    }

    fn clear(&mut self) {
        self.chain.clear();
    }

    fn match_rule_group(&self, key: &str, proto: u8, dst_port: u16, src_port: u16) -> Option<RuleDetail> {
        self.chain.get(key)?.match_rule(proto, dst_port, src_port)
    }

    fn add_rule_to_chain(&mut self, key: String, policy: RuleDetail, port: RulePort) {
        self.chain.entry(key).or_insert_with(RuleGroup::new).add_rule_detail(policy, port);
    }

    /// Mirrors RuleChain::DeleteRuleFromChain: removes the named rule from
    /// the group at `rule_key`, then removes the whole group if it's now
    /// empty (mirroring the C++ behavior exactly -- an empty group is
    /// pruned, not left as a dangling empty entry).
    fn delete_rule_from_chain(&mut self, policy_name: &str, rule_key: &str) {
        if let Some(group) = self.chain.get_mut(rule_key) {
            group.delete_rule(policy_name);
            if group.size() == 0 {
                self.chain.remove(rule_key);
            }
        }
    }
}

struct PolicyTree {
    chain: RuleChain,
    /// policy_key -> {rule_key: dir}, mirroring PolicyTree::tree_
    tree: HashMap<String, HashMap<String, FlowDir>>,
}

impl PolicyTree {
    fn new(dir: FlowDir) -> Self {
        PolicyTree { chain: RuleChain::new(dir), tree: HashMap::new() }
    }

    fn size(&self) -> usize {
        self.chain.size()
    }

    fn tree_size(&self) -> usize {
        self.tree.len()
    }

    fn clear(&mut self) {
        self.tree.clear();
        self.chain.clear();
    }

    /// Mirrors PolicyTree::AddPolicyToChain: derives the rule key from the
    /// policy (mask is discarded here -- the caller, PolicyRule, extracts it
    /// separately for AddMaskAndPriority), adds to the chain, then records
    /// the {rule_key: direction} mapping under this policy_key for later
    /// deletion.
    fn add_policy_to_chain(&mut self, policy: RuleDetail, port: RulePort) {
        let (key, _mask) = policy.create_rule_key();
        let direction = policy.direction;
        let policy_key = policy.policy_key.clone();
        self.chain.add_rule_to_chain(key.clone(), policy, port);
        self.tree.entry(policy_key).or_default().insert(key, direction);
    }

    /// Mirrors PolicyTree::DeletePolicyFromTree: removes every chain entry
    /// this policy_key ever added, then clears the whole tree if nothing is
    /// left (mirroring the C++ behavior exactly).
    fn delete_policy_from_tree(&mut self, name: &str) {
        let Some(rules) = self.tree.remove(name) else {
            return;
        };
        for key in rules.keys() {
            self.chain.delete_rule_from_chain(name, key);
        }
        if self.tree.is_empty() {
            self.clear();
        }
    }
}

fn parse_cidr(cidr: &str) -> (String, i32) {
    // (from Task 2)
}
```
(The `parse_cidr`/`ipv4_cidr_to_ip` bodies from Task 2 stay as they were — this step only adds the new types above them in the file, it doesn't touch Task 2's functions except to note they're now consumed by `RuleDetail::create_rule_key`.)

- [ ] **Step 2: Write unit tests**

```rust
#[cfg(test)]
mod policy_tree_tests {
    use super::*;

    fn sample_rule(policy_key: &str, priority: i32, proto: u8, dir: FlowDir, src: &str, dst: &str) -> RuleDetail {
        RuleDetail {
            proto,
            priority,
            addr_type: 0,
            direction: dir,
            action: 1,
            action_dsc: String::new(),
            policy_key: policy_key.to_string(),
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            ports: Vec::new(),
        }
    }

    #[test]
    fn match_rule_detail_any_port_sentinel() {
        let mut rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        rule.ports.push(RulePort { end_port: 0, port: 0, proto: 6 });
        assert!(rule.matches(6, 9999, 12345));
    }

    #[test]
    fn match_rule_detail_port_range() {
        let mut rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        rule.ports.push(RulePort { end_port: 8080, port: 8000, proto: 6 });
        assert!(rule.matches(6, 8050, 12345));
        assert!(!rule.matches(6, 9000, 12345));
    }

    #[test]
    fn match_rule_detail_icmp_ignores_configured_protocol() {
        let rule = sample_rule("p1", 10, 6 /* TCP */, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        // packet protocol is ICMP (1); the ICMP special-case in matches()
        // overwrites it with the rule's own proto (6) before comparing, so
        // this must match despite the rule being configured for TCP.
        assert!(rule.matches(IPPROTO_ICMP, 0, 0));
    }

    #[test]
    fn match_rule_detail_dns_port_bypasses_port_list() {
        let mut rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        rule.ports.push(RulePort { end_port: 9999, port: 9000, proto: 6 });
        assert!(rule.matches(6, 53, 12345));
    }

    #[test]
    fn policy_tree_add_then_match_ingress() {
        let mut tree = PolicyTree::new(FlowDir::Ingress);
        let rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        let (key, _mask) = rule.create_rule_key();
        tree.add_policy_to_chain(rule, RulePort { end_port: 0, port: 0, proto: 6 });
        let matched = tree.chain.match_rule_group(&key, 6, 80, 12345);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().policy_key, "p1");
    }

    #[test]
    fn policy_tree_delete_removes_all_chain_entries_for_policy() {
        let mut tree = PolicyTree::new(FlowDir::Ingress);
        let rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        let (key, _mask) = rule.create_rule_key();
        tree.add_policy_to_chain(rule, RulePort { end_port: 0, port: 0, proto: 6 });
        assert_eq!(tree.size(), 1);
        tree.delete_policy_from_tree("p1");
        assert_eq!(tree.size(), 0);
        assert!(tree.chain.match_rule_group(&key, 6, 80, 12345).is_none());
    }

    #[test]
    fn rule_group_add_rule_detail_appends_port_for_existing_policy() {
        let mut group = RuleGroup::new();
        let rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        group.add_rule_detail(rule.clone(), RulePort { end_port: 100, port: 100, proto: 6 });
        group.add_rule_detail(rule, RulePort { end_port: 200, port: 200, proto: 6 });
        assert_eq!(group.rules.get("p1").unwrap().ports.len(), 2);
    }
}
```

- [ ] **Step 3: Run tests**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/crates/net_policy_engine && cargo test 2>&1 | tail -60"
```
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/net_policy_engine/src/lib.rs
git commit -m "Port RuleDetail/RuleGroup/RuleChain/PolicyTree matching logic to Rust"
```

---

### Task 4: Port `PolicyRule`'s tree-management logic as `RustPolicyEngine`

**Files:**
- Modify: `crates/net_policy_engine/src/lib.rs` (add `RustPolicyEngine`, the dual-tree wrapper with `CreateRuleKeyByTuple`'s key-generation logic)

**Interfaces:**
- Consumes: `PolicyTree`, `RuleDetail`, `RulePort`, `FlowDir` (Task 3).
- Produces: `RustPolicyEngine` and its methods (`add_policy`, `delete_policy`, `match_five_tuple`, `clear_cfg`, `all_rules`), consumed by Task 5's cxx bridge.

Read `PolicyRule`'s declaration in `net-policy.h` and its implementation in `rule-detail.cpp` (`CreateRuleKeyByTuple`, `GetPolicyTree`, `PrintPolicyLog`, `AddMaskAndPriority`, `AddPolicyToTree`, `DeletePolicy`, `ClearCfg`) yourself before porting.

- [ ] **Step 1: Define `RustPolicyEngine` and port `CreateRuleKeyByTuple`**

```rust
use std::collections::BTreeSet;

pub struct RustPolicyEngine {
    input_tree: PolicyTree,
    output_tree: PolicyTree,
    // std::set<int> in C++ -- BTreeSet (sorted iteration), NOT HashSet. See
    // Global Constraints: CreateRuleKeyByTuple's generated-key order depends
    // on this, and the caller returns on the first matching key.
    mask_cidr: BTreeSet<i32>,
    priority: BTreeSet<i32>,
}

impl RustPolicyEngine {
    fn new() -> Self {
        let mut mask_cidr = BTreeSet::new();
        mask_cidr.insert(32);
        RustPolicyEngine {
            input_tree: PolicyTree::new(FlowDir::Ingress),
            output_tree: PolicyTree::new(FlowDir::Egress),
            mask_cidr,
            priority: BTreeSet::new(),
        }
    }

    fn tree(&self, dir: FlowDir) -> &PolicyTree {
        match dir {
            FlowDir::Ingress => &self.input_tree,
            FlowDir::Egress => &self.output_tree,
        }
    }

    fn tree_mut(&mut self, dir: FlowDir) -> &mut PolicyTree {
        match dir {
            FlowDir::Ingress => &mut self.input_tree,
            FlowDir::Egress => &mut self.output_tree,
        }
    }

    fn add_mask_and_priority(&mut self, priority: i32, mask: i32) {
        self.priority.insert(priority);
        if mask > 0 && mask <= 32 {
            self.mask_cidr.insert(mask);
        }
    }

    /// Mirrors PolicyRule::CreateRuleKeyByTuple exactly: for each known
    /// priority, emits 2 wildcard keys (any-source for ingress / any-dest
    /// for egress) plus 2 CIDR-masked keys per known mask (proto-specific +
    /// proto-wildcard "0" variant). Order matters -- see Global Constraints.
    fn create_rule_key_by_tuple(&self, proto: u8, src_addr: &str, dst_addr: &str, dir: FlowDir) -> Vec<String> {
        let ingress = dir == FlowDir::Ingress;
        let cidr_addr = if ingress { src_addr } else { dst_addr };
        let exact_addr = if ingress { dst_addr } else { src_addr };
        let proto_str = proto.to_string();

        let mut keys = Vec::with_capacity(self.priority.len() * 2 * (1 + self.mask_cidr.len()));
        for &priority in &self.priority {
            let proto_pfx = format!("{}-{}-", priority, proto_str);
            let proto0_pfx = format!("{}-0-", priority);

            let wildcard_suffix = if ingress {
                format!("0.0.0.0/32-{}", exact_addr)
            } else {
                format!("{}-0.0.0.0/32", exact_addr)
            };
            keys.push(format!("{}{}", proto_pfx, wildcard_suffix));
            keys.push(format!("{}{}", proto0_pfx, wildcard_suffix));

            for &mask in &self.mask_cidr {
                let cidr = format!("{}/{}", ipv4_cidr_to_ip(cidr_addr, mask), mask);
                let cidr_suffix = if ingress {
                    format!("{}-{}", cidr, exact_addr)
                } else {
                    format!("{}-{}", exact_addr, cidr)
                };
                keys.push(format!("{}{}", proto_pfx, cidr_suffix));
                keys.push(format!("{}{}", proto0_pfx, cidr_suffix));
            }
        }
        keys
    }
}
```

- [ ] **Step 2: Port the mutation and match entry points**

```rust
impl RustPolicyEngine {
    /// Mirrors PolicyRule::AddPolicyToTree.
    fn add_policy_internal(&mut self, policy: RuleDetail, port: RulePort) {
        let (_key, mask) = policy.create_rule_key();
        let priority = policy.priority;
        let dir = policy.direction;
        self.tree_mut(dir).add_policy_to_chain(policy, port);
        self.add_mask_and_priority(priority, mask);
    }

    /// Mirrors PolicyRule::DeletePolicy.
    fn delete_policy_internal(&mut self, dir: FlowDir, name: &str) {
        self.tree_mut(dir).delete_policy_from_tree(name);
    }

    /// Mirrors PolicyRule::ClearCfg.
    fn clear_cfg_internal(&mut self) {
        self.mask_cidr.clear();
        self.priority.clear();
        self.mask_cidr.insert(32);
        self.input_tree.clear();
        self.output_tree.clear();
    }

    /// Single-call replacement for MatchNetPolicyRule's current three-call
    /// sequence (GetPolicyTree -> CreateRuleKeyByTuple -> loop over
    /// MatchRuleGroup) -- see the design spec's FFI-granularity rationale.
    /// Mirrors that function's node-IP-registry-agnostic core (the
    /// IsNodeIp check itself stays in C++, in MatchNetPolicyRule, since
    /// MicroSegEngine's node registry is out of scope for this crate).
    fn match_five_tuple_internal(&self, proto: u8, dst_port: u16, src_port: u16, src_addr: &str, dst_addr: &str, dir: FlowDir) -> Option<RuleDetail> {
        let tree = self.tree(dir);
        if tree.size() == 0 {
            return None;
        }
        for key in self.create_rule_key_by_tuple(proto, src_addr, dst_addr, dir) {
            if let Some(matched) = tree.chain.match_rule_group(&key, proto, dst_port, src_port) {
                return Some(matched);
            }
        }
        None
    }

    /// Supports the C++-side GetAllConfig, which currently walks
    /// PolicyTree::chain_/RuleGroup::rules_ directly (public members on
    /// types this phase deletes) -- this flat enumeration replaces that
    /// walk. Order is unspecified (HashMap iteration); GetAllConfig's JSON
    /// output ordering was never a documented contract, only an
    /// implementation artifact of unordered_map iteration, which was never
    /// stable across runs anyway.
    fn all_rules_internal(&self, dir: FlowDir) -> Vec<RuleDetail> {
        self.tree(dir).chain.chain.values().flat_map(|group| group.rules.values().cloned()).collect()
    }
}
```

- [ ] **Step 3: Write unit tests**

```rust
#[cfg(test)]
mod engine_tests {
    use super::*;

    fn sample_rule(policy_key: &str, priority: i32, proto: u8, dir: FlowDir, src: &str, dst: &str) -> RuleDetail {
        RuleDetail {
            proto, priority, addr_type: 0, direction: dir, action: 1,
            action_dsc: String::new(), policy_key: policy_key.to_string(),
            src_ip: src.to_string(), dst_ip: dst.to_string(), ports: Vec::new(),
        }
    }

    #[test]
    fn engine_add_and_match_cidr_rule() {
        let mut engine = RustPolicyEngine::new();
        let rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/24", "1.2.3.4");
        engine.add_policy_internal(rule, RulePort { end_port: 0, port: 0, proto: 6 });
        let matched = engine.match_five_tuple_internal(6, 80, 12345, "10.0.0.5", "1.2.3.4", FlowDir::Ingress);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().policy_key, "p1");
    }

    #[test]
    fn engine_no_match_when_tree_empty() {
        let engine = RustPolicyEngine::new();
        assert!(engine.match_five_tuple_internal(6, 80, 12345, "10.0.0.5", "1.2.3.4", FlowDir::Ingress).is_none());
    }

    #[test]
    fn engine_delete_then_no_match() {
        let mut engine = RustPolicyEngine::new();
        let rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/24", "1.2.3.4");
        engine.add_policy_internal(rule, RulePort { end_port: 0, port: 0, proto: 6 });
        engine.delete_policy_internal(FlowDir::Ingress, "p1");
        assert!(engine.match_five_tuple_internal(6, 80, 12345, "10.0.0.5", "1.2.3.4", FlowDir::Ingress).is_none());
    }

    #[test]
    fn engine_egress_matches_dst_cidr() {
        let mut engine = RustPolicyEngine::new();
        let rule = sample_rule("p1", 10, 6, FlowDir::Egress, "1.2.3.4", "10.0.0.0/24");
        engine.add_policy_internal(rule, RulePort { end_port: 0, port: 0, proto: 6 });
        let matched = engine.match_five_tuple_internal(6, 80, 12345, "1.2.3.4", "10.0.0.9", FlowDir::Egress);
        assert!(matched.is_some());
    }

    #[test]
    fn engine_all_rules_returns_added_rule() {
        let mut engine = RustPolicyEngine::new();
        let rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/24", "1.2.3.4");
        engine.add_policy_internal(rule, RulePort { end_port: 0, port: 0, proto: 6 });
        let rules = engine.all_rules_internal(FlowDir::Ingress);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].policy_key, "p1");
    }

    #[test]
    fn engine_clear_cfg_resets_everything() {
        let mut engine = RustPolicyEngine::new();
        let rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/24", "1.2.3.4");
        engine.add_policy_internal(rule, RulePort { end_port: 0, port: 0, proto: 6 });
        engine.clear_cfg_internal();
        assert_eq!(engine.all_rules_internal(FlowDir::Ingress).len(), 0);
        assert!(engine.match_five_tuple_internal(6, 80, 12345, "10.0.0.5", "1.2.3.4", FlowDir::Ingress).is_none());
    }
}
```

- [ ] **Step 4: Run tests**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/crates/net_policy_engine && cargo test 2>&1 | tail -60"
```
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/net_policy_engine/src/lib.rs
git commit -m "Port PolicyRule's tree-management logic as RustPolicyEngine"
```

---

### Task 5: Wire the `cxx` bridge and add a C++ smoke test

**Files:**
- Modify: `crates/net_policy_engine/src/lib.rs` (add the `#[cxx::bridge]` module with shared structs and the `RustPolicyEngine` opaque-type FFI surface, replacing Task 1's smoke stub)
- Create: `tests/net_policy_engine_ffi_test.cc` (standalone smoke test — proves the FFI surface works end-to-end, independent of `PolicyRule`, which isn't wired up until Task 7)
- Modify: `CMakeLists.txt` (add the new test file to `net_rule_grpc_test`'s `SOURCES`)

**Interfaces:**
- Consumes: `RustPolicyEngine`, `RuleDetail`, `RulePort`, `FlowDir` (Tasks 3-4).
- Produces: `policy_engine::SharedRuleDetail`, `policy_engine::SharedRulePort`, `policy_engine::MatchedRule` (C++-visible shared structs), `policy_engine::RustPolicyEngine` (opaque Rust type), `policy_engine::new_policy_engine() -> std::unique_ptr<RustPolicyEngine>`, and its methods — the actual seam Task 7 wires `PolicyRule` up to.

This is new territory for this codebase: every prior phase exposed *C++* types as opaque to Rust (`DaemonContext`, `GrpcDispatchQueue`). This is the first phase where an opaque *Rust* type (`RustPolicyEngine`) is owned by C++ via `cxx::UniquePtr`/`std::unique_ptr`. This is a standard, well-supported `cxx` pattern (`extern "Rust" { type Foo; fn method(self: &Foo) -> ...; }`), just a different corner of the crate's feature set than this codebase has exercised before — read `cxx`'s documentation on opaque Rust types if anything below doesn't compile as written; the exact bridge macro syntax may need adjustment (this project has hit this before, e.g. Phase 2's Task 3 cxxbridge-empty-file lesson).

- [ ] **Step 1: Replace the bridge module**

Replace `crates/net_policy_engine/src/lib.rs`'s `#[cxx::bridge]` module (from Task 1) with:
```rust
#[cxx::bridge(namespace = "policy_engine")]
mod ffi {
    struct SharedRulePort {
        end_port: u16,
        port: u16,
        proto: u8,
    }

    struct SharedRuleDetail {
        proto: u8,
        priority: i32,
        addr_type: i32,
        /// 0 = Ingress, 1 = Egress -- matches FlowDir's C++ underlying values
        direction: i32,
        /// matches NetPolicyRule's uint32_t values directly (kDeny=0,
        /// kAllow=1, kMark=2, kAllowRsp=3, kAllowReq=4, kDefault=5)
        action: u32,
        action_dsc: String,
        policy_key: String,
        src_ip: String,
        dst_ip: String,
        ports: Vec<SharedRulePort>,
    }

    struct MatchedRule {
        matched: bool,
        detail: SharedRuleDetail,
    }

    extern "Rust" {
        type RustPolicyEngine;

        fn new_policy_engine() -> Box<RustPolicyEngine>;
        fn add_policy(self: &mut RustPolicyEngine, rule: SharedRuleDetail, port: SharedRulePort);
        fn delete_policy(self: &mut RustPolicyEngine, dir: i32, name: &str);
        fn match_five_tuple(
            self: &RustPolicyEngine, proto: u8, dst_port: u16, src_port: u16,
            src_addr: &str, dst_addr: &str, dir: i32,
        ) -> MatchedRule;
        fn clear_cfg(self: &mut RustPolicyEngine);
        fn all_rules(self: &RustPolicyEngine, dir: i32) -> Vec<SharedRuleDetail>;
    }
}
```
Note `Box<RustPolicyEngine>` as the return type of `new_policy_engine` — `cxx` maps a returned `Box<T>` for an opaque Rust type to `std::unique_ptr<T>` on the C++ side, which is exactly the `cxx::UniquePtr<RustPolicyEngine>` ownership the design spec calls for.

- [ ] **Step 2: Add the FFI-facing conversions and entry points**

Add conversions between the internal `RuleDetail`/`RulePort`/`FlowDir` types (Tasks 3-4) and the FFI `SharedRuleDetail`/`SharedRulePort`/`i32` shapes, plus the free functions/methods the bridge declares:
```rust
impl From<ffi::SharedRulePort> for RulePort {
    fn from(p: ffi::SharedRulePort) -> Self {
        RulePort { end_port: p.end_port, port: p.port, proto: p.proto }
    }
}

impl From<ffi::SharedRuleDetail> for RuleDetail {
    fn from(d: ffi::SharedRuleDetail) -> Self {
        RuleDetail {
            proto: d.proto,
            priority: d.priority,
            addr_type: d.addr_type,
            direction: if d.direction == 0 { FlowDir::Ingress } else { FlowDir::Egress },
            action: d.action,
            action_dsc: d.action_dsc,
            policy_key: d.policy_key,
            src_ip: d.src_ip,
            dst_ip: d.dst_ip,
            ports: d.ports.into_iter().map(RulePort::from).collect(),
        }
    }
}

impl From<RuleDetail> for ffi::SharedRuleDetail {
    fn from(d: RuleDetail) -> Self {
        ffi::SharedRuleDetail {
            proto: d.proto,
            priority: d.priority,
            addr_type: d.addr_type,
            direction: if d.direction == FlowDir::Ingress { 0 } else { 1 },
            action: d.action,
            action_dsc: d.action_dsc,
            policy_key: d.policy_key,
            src_ip: d.src_ip,
            dst_ip: d.dst_ip,
            ports: d.ports.into_iter().map(|p| ffi::SharedRulePort { end_port: p.end_port, port: p.port, proto: p.proto }).collect(),
        }
    }
}

fn dir_from_i32(dir: i32) -> FlowDir {
    if dir == 0 { FlowDir::Ingress } else { FlowDir::Egress }
}

fn new_policy_engine() -> Box<RustPolicyEngine> {
    Box::new(RustPolicyEngine::new())
}
```
Then extend `impl RustPolicyEngine` (from Task 4) with the `cxx`-facing method wrappers. These MUST use exactly the names the bridge module declares (`add_policy`, `delete_policy`, `match_five_tuple`, `clear_cfg`, `all_rules`) — `cxx` generates a C++-side call to `RustPolicyEngine::<name>(...)` matching the bridge declaration verbatim, and Rust has no method overloading, so these names would collide with Task 4's internal methods if Task 4's methods had kept the same names. That collision is why Task 4's methods are named `add_policy_internal`/`delete_policy_internal`/`match_five_tuple_internal`/`clear_cfg_internal`/`all_rules_internal` — these wrappers are what's actually exposed to C++, and they delegate to Task 4's internal methods after converting between the FFI shared-struct types and the internal types:
```rust
impl RustPolicyEngine {
    fn add_policy(&mut self, rule: ffi::SharedRuleDetail, port: ffi::SharedRulePort) {
        self.add_policy_internal(RuleDetail::from(rule), RulePort::from(port));
    }

    fn delete_policy(&mut self, dir: i32, name: &str) {
        self.delete_policy_internal(dir_from_i32(dir), name);
    }

    fn match_five_tuple(&self, proto: u8, dst_port: u16, src_port: u16, src_addr: &str, dst_addr: &str, dir: i32) -> ffi::MatchedRule {
        match self.match_five_tuple_internal(proto, dst_port, src_port, src_addr, dst_addr, dir_from_i32(dir)) {
            Some(detail) => ffi::MatchedRule { matched: true, detail: detail.into() },
            None => ffi::MatchedRule { matched: false, detail: ffi::SharedRuleDetail::default() },
        }
    }

    fn clear_cfg(&mut self) {
        self.clear_cfg_internal();
    }

    fn all_rules(&self, dir: i32) -> Vec<ffi::SharedRuleDetail> {
        self.all_rules_internal(dir_from_i32(dir)).into_iter().map(ffi::SharedRuleDetail::from).collect()
    }
}
```
`ffi::SharedRuleDetail::default()` requires the shared struct to derive `Default` — add `#[derive(Default)]` to `SharedRuleDetail`'s and `SharedRulePort`'s declarations in the bridge module (both contain only `Default`-able field types: integers, `String`, `Vec`).

- [ ] **Step 3: Build and fix compile errors**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net_policy_engine_cxxbridge 2>&1 | tail -100"
```
Iterate here until it builds clean — this is exactly the kind of task where the plan's Rust snippets may need real adjustment against the actual `cxx` version pinned in this workspace's `Cargo.lock`. Verify `cxx`'s resolved version (`grep -A2 '^name = "cxx"' Cargo.lock` from the repo root) matches the `cxx = "1"` already used by `waf_rules_core`/`net_policy_control` (it should, since they share one workspace `Cargo.lock`).

- [ ] **Step 4: Write the smoke test**

`tests/net_policy_engine_ffi_test.cc`:
```cpp
#include <gtest/gtest.h>

#include "net_policy_engine_cxxbridge/lib.h"

TEST(PolicyEngineFfiTest, AddThenMatchSucceeds) {
  auto engine = policy_engine::new_policy_engine();

  policy_engine::SharedRuleDetail rule{};
  rule.proto = 6;
  rule.priority = 10;
  rule.addr_type = 0;
  rule.direction = 0;  // ingress
  rule.action = 1;     // kAllow
  rule.action_dsc = "test";
  rule.policy_key = "smoke-test-policy";
  rule.src_ip = "10.0.0.0/24";
  rule.dst_ip = "1.2.3.4";

  policy_engine::SharedRulePort port{};
  port.end_port = 0;
  port.port = 0;
  port.proto = 6;

  engine->add_policy(rule, port);

  auto result = engine->match_five_tuple(6, 80, 12345, "10.0.0.5", "1.2.3.4", 0);
  ASSERT_TRUE(result.matched);
  EXPECT_EQ(std::string(result.detail.policy_key), "smoke-test-policy");
}

TEST(PolicyEngineFfiTest, NoMatchWhenTreeEmpty) {
  auto engine = policy_engine::new_policy_engine();
  auto result = engine->match_five_tuple(6, 80, 12345, "10.0.0.5", "1.2.3.4", 0);
  EXPECT_FALSE(result.matched);
}

TEST(PolicyEngineFfiTest, DeletePolicyRemovesMatch) {
  auto engine = policy_engine::new_policy_engine();
  policy_engine::SharedRuleDetail rule{};
  rule.proto = 6;
  rule.priority = 10;
  rule.direction = 0;
  rule.action = 1;
  rule.policy_key = "smoke-test-policy-2";
  rule.src_ip = "10.0.0.0/24";
  rule.dst_ip = "1.2.3.4";
  policy_engine::SharedRulePort port{};
  port.proto = 6;
  engine->add_policy(rule, port);

  engine->delete_policy(0, "smoke-test-policy-2");

  auto result = engine->match_five_tuple(6, 80, 12345, "10.0.0.5", "1.2.3.4", 0);
  EXPECT_FALSE(result.matched);
}

TEST(PolicyEngineFfiTest, AllRulesReturnsAddedRule) {
  auto engine = policy_engine::new_policy_engine();
  policy_engine::SharedRuleDetail rule{};
  rule.proto = 6;
  rule.priority = 10;
  rule.direction = 0;
  rule.action = 1;
  rule.policy_key = "smoke-test-policy-3";
  rule.src_ip = "10.0.0.0/24";
  rule.dst_ip = "1.2.3.4";
  policy_engine::SharedRulePort port{};
  port.proto = 6;
  engine->add_policy(rule, port);

  auto rules = engine->all_rules(0);
  ASSERT_EQ(rules.size(), 1u);
  EXPECT_EQ(std::string(rules[0].policy_key), "smoke-test-policy-3");
}
```
Verify the generated header path (`net_policy_engine_cxxbridge/lib.h`) matches what Task 1's `corrosion_add_cxxbridge` block actually produces — check how `waf_rules_core_cxxbridge`'s or `net_policy_control_cxxbridge`'s generated header is included elsewhere in the codebase (e.g. `grep -rn 'net_policy_control_cxxbridge/lib.h'`) and match that convention exactly.

Add `tests/net_policy_engine_ffi_test.cc` to `net_rule_grpc_test`'s `SOURCES` list in `CMakeLists.txt` (it needs `net_policy_engine_cxxbridge` linked, which `net_rule_grpc_test` will have from Task 1; `common/utf8_check.h` needs no additional linking, it's header-only).

- [ ] **Step 5: Build and run**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net_rule_grpc_test 2>&1 | tail -100"
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && ./net_rule_grpc_test --gtest_filter='PolicyEngineFfiTest.*'"
```
Expected: clean build, all 4 smoke tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/net_policy_engine/src/lib.rs tests/net_policy_engine_ffi_test.cc CMakeLists.txt
git commit -m "Wire net_policy_engine cxx bridge; add FFI smoke test"
```

---

### Task 6: Build the differential test harness

**Files:**
- Create: `tests/policy_engine_differential_test.cc`
- Modify: `CMakeLists.txt` (add to `net_rule_grpc_test`'s `SOURCES`)

**Interfaces:**
- Consumes: the real, unmodified C++ `RuleDetail`/`RuleGroup`/`RuleChain`/`PolicyTree` (`net-policy.h`/`rule-detail.cpp` — still live at this point, not yet cut over), and `policy_engine::RustPolicyEngine` via `net_policy_engine_cxxbridge/lib.h` (Task 5).

Per the design spec's Testing & Rollout section: generate many `(policy set, five-tuple)` combinations, construct both the real C++ tree and the new Rust engine from the same policy set, and assert identical verdicts. Use a fixed-seed PRNG (not real randomness) so failures are reproducible.

- [ ] **Step 1: Write the generator**

```cpp
#include <gtest/gtest.h>

#include <algorithm>
#include <random>
#include <sstream>

#include "net-policy.h"
#include "net_policy_engine_cxxbridge/lib.h"

namespace {

struct GeneratedRule {
  RuleDetail cpp_rule;
  RULE_PORT cpp_port;
};

struct GeneratedPolicySet {
  std::vector<GeneratedRule> rules;
};

struct GeneratedTuple {
  uint8_t proto;
  uint16_t src_port;
  uint16_t dst_port;
  std::string src_addr;
  std::string dst_addr;
  FlowDir dir;
};

// Returns a 3-octet address prefix ENDING IN A DOT, e.g. "10.123.45." --
// every call site appends its own 4th octet after this, so the trailing dot
// is load-bearing: without it, `RandomIpPrefix(...) + "0/24"` would produce
// a malformed address like "10.123.450/24" (silently merging the 3rd octet
// with the appended one) instead of the intended "10.123.45.0/24". A
// malformed address would make C++'s inet_addr() (which returns
// INADDR_NONE, 0xFFFFFFFF, on unparseable input) and the Rust port's
// std::net::Ipv4Addr parsing (which this plan's Task 2 falls back to 0 on
// unparseable input) disagree on totally different grounds than the
// matching logic under test -- exactly the kind of self-inflicted false
// mismatch the differential suite must not produce.
std::string RandomIpPrefix(std::mt19937& rng, int subnet_choice) {
  // A small fixed pool of /8 subnets so generated CIDRs and exact addresses
  // have realistic odds of overlapping (all-random /32 addresses would
  // almost never fall inside a generated CIDR, defeating the point of the
  // generator).
  static const char* kSubnets[] = {"10.", "172.16.", "192.168.", "203.0.113."};
  std::uniform_int_distribution<int> octet(0, 255);
  std::ostringstream oss;
  oss << kSubnets[subnet_choice % 4] << octet(rng) << "." << octet(rng) << ".";
  return oss.str();
}

// non-overlapping: each generated rule gets its own priority, so within a
// single RuleGroup at most one rule can ever match a given tuple -- avoids
// the hash-iteration-order ambiguity described in the design spec.
GeneratedPolicySet GenerateNonOverlappingPolicySet(std::mt19937& rng, int num_rules) {
  static const uint8_t kProtos[] = {6, 17, 1, 0};  // TCP, UDP, ICMP, wildcard
  std::uniform_int_distribution<int> proto_idx(0, 3);
  std::uniform_int_distribution<int> mask_dist(8, 32);
  std::uniform_int_distribution<int> port_dist(1, 65000);
  std::uniform_int_distribution<int> dir_dist(0, 1);
  std::uniform_int_distribution<int> subnet_dist(0, 3);

  GeneratedPolicySet set;
  for (int i = 0; i < num_rules; i++) {
    RuleDetail rule;
    rule.proto_ = kProtos[proto_idx(rng)];
    rule.priority_ = i + 1;  // distinct priority per rule -- see above
    rule.addr_type_ = 0;
    rule.direction_ = (dir_dist(rng) == 0) ? FlowDir::kIngress : FlowDir::kEgress;
    rule.action_ = NetPolicyRule::kAllow;
    rule.policy_key_ = "policy-" + std::to_string(i);
    int mask = mask_dist(rng);
    rule.src_ip_ = RandomIpPrefix(rng, subnet_dist(rng)) + "0/" + std::to_string(mask);
    rule.dst_ip_ = RandomIpPrefix(rng, subnet_dist(rng)) + "0/" + std::to_string(mask_dist(rng));

    RULE_PORT port{};
    port.proto_ = rule.proto_;
    int p1 = port_dist(rng);
    int p2 = port_dist(rng);
    port.port_ = std::min(p1, p2);
    port.end_port_ = std::max(p1, p2);

    set.rules.push_back({rule, port});
  }
  return set;
}

GeneratedTuple GenerateTuple(std::mt19937& rng) {
  static const uint8_t kProtos[] = {6, 17, 1};
  std::uniform_int_distribution<int> proto_idx(0, 2);
  std::uniform_int_distribution<int> port_dist(1, 65000);
  std::uniform_int_distribution<int> dir_dist(0, 1);
  std::uniform_int_distribution<int> subnet_dist(0, 3);

  GeneratedTuple t;
  t.proto = kProtos[proto_idx(rng)];
  t.src_port = static_cast<uint16_t>(port_dist(rng));
  t.dst_port = static_cast<uint16_t>(port_dist(rng));
  t.src_addr = RandomIpPrefix(rng, subnet_dist(rng)) + "1";
  t.dst_addr = RandomIpPrefix(rng, subnet_dist(rng)) + "1";
  t.dir = (dir_dist(rng) == 0) ? FlowDir::kIngress : FlowDir::kEgress;
  return t;
}

}  // namespace
```

- [ ] **Step 2: Write the comparison harness**

```cpp
namespace {

struct OldMatchResult {
  bool matched;
  std::string policy_key;
  NetPolicyRule action;
};

OldMatchResult MatchWithCpp(const GeneratedPolicySet& set, const GeneratedTuple& tuple) {
  PolicyTree tree;
  tree.SetRuleDir(tuple.dir);
  for (const auto& r : set.rules) {
    if (r.cpp_rule.direction_ != tuple.dir) continue;
    RuleDetail copy = r.cpp_rule;
    RULE_PORT port_copy = r.cpp_port;
    tree.AddPolicyToChain(copy, port_copy);
  }

  PolicyRule policy_rule;  // only used for CreateRuleKeyByTuple's priority_/mask_cidr_ bookkeeping
  for (const auto& r : set.rules) {
    if (r.cpp_rule.direction_ != tuple.dir) continue;
    RuleDetail mutable_copy = r.cpp_rule;  // CreateRuleKey() is non-const; r.cpp_rule is const here
    auto [key, mask] = mutable_copy.CreateRuleKey();  // discard key, just want mask
    policy_rule.AddMaskAndPriority(r.cpp_rule.priority_, mask);
  }

  FiveTuple ft;
  ft.proto_ = tuple.proto;
  ft.src_port_ = tuple.src_port;
  ft.dst_port_ = tuple.dst_port;
  ft.src_addr_ = tuple.src_addr;
  ft.dst_addr_ = tuple.dst_addr;

  auto keys = policy_rule.CreateRuleKeyByTuple(ft, tuple.dir);
  for (auto& key : keys) {
    if (auto matched = tree.MatchRuleGroup(key, ft)) {
      return {true, matched->policy_key_, matched->action_};
    }
  }
  return {false, "", NetPolicyRule::kDefault};
}

policy_engine::MatchedRule MatchWithRust(const GeneratedPolicySet& set, const GeneratedTuple& tuple) {
  auto engine = policy_engine::new_policy_engine();
  for (const auto& r : set.rules) {
    if (r.cpp_rule.direction_ != tuple.dir) continue;
    policy_engine::SharedRuleDetail rd{};
    rd.proto = r.cpp_rule.proto_;
    rd.priority = r.cpp_rule.priority_;
    rd.addr_type = r.cpp_rule.addr_type_;
    rd.direction = (r.cpp_rule.direction_ == FlowDir::kIngress) ? 0 : 1;
    rd.action = static_cast<uint32_t>(r.cpp_rule.action_);
    rd.policy_key = r.cpp_rule.policy_key_;
    rd.src_ip = r.cpp_rule.src_ip_;
    rd.dst_ip = r.cpp_rule.dst_ip_;

    policy_engine::SharedRulePort rp{};
    rp.end_port = r.cpp_port.end_port_;
    rp.port = r.cpp_port.port_;
    rp.proto = r.cpp_port.proto_;

    engine->add_policy(rd, rp);
  }
  int32_t dir_int = (tuple.dir == FlowDir::kIngress) ? 0 : 1;
  return engine->match_five_tuple(tuple.proto, tuple.dst_port, tuple.src_port,
                                    tuple.src_addr, tuple.dst_addr, dir_int);
}

}  // namespace

TEST(PolicyEngineDifferentialTest, NonOverlappingPolicySetsMatchIdentically) {
  std::mt19937 rng(0xC0FFEE);  // fixed seed -- reproducible failures
  const int kIterations = 2000;
  int mismatches = 0;
  for (int i = 0; i < kIterations; i++) {
    auto set = GenerateNonOverlappingPolicySet(rng, /*num_rules=*/5);
    auto tuple = GenerateTuple(rng);

    auto cpp_result = MatchWithCpp(set, tuple);
    auto rust_result = MatchWithRust(set, tuple);

    if (cpp_result.matched != rust_result.matched) {
      mismatches++;
      ADD_FAILURE() << "iteration " << i << ": match/no-match disagreement -- cpp matched="
                    << cpp_result.matched << " rust matched=" << rust_result.matched;
      continue;
    }
    if (cpp_result.matched) {
      EXPECT_EQ(cpp_result.policy_key, std::string(rust_result.detail.policy_key))
          << "iteration " << i << ": different policy matched";
      EXPECT_EQ(static_cast<uint32_t>(cpp_result.action), rust_result.detail.action)
          << "iteration " << i << ": same policy, different action";
    }
  }
  EXPECT_EQ(mismatches, 0) << mismatches << "/" << kIterations << " iterations disagreed";
}

TEST(PolicyEngineDifferentialTest, OverlappingPolicySetsAgreeOnSomeValidMatch) {
  // Deliberately overlapping: every rule shares the SAME priority, so
  // multiple rules can legitimately match the same tuple within one
  // RuleGroup -- "which one wins" is hash-iteration-order-dependent and NOT
  // required to agree between the C++ std::unordered_map and Rust HashMap
  // implementations (see design spec). Assert only that if one
  // implementation finds a match, the other does too, with a valid action --
  // not that they pick the identical policy_key.
  std::mt19937 rng(0xDEADBEEF);
  const int kIterations = 500;
  for (int i = 0; i < kIterations; i++) {
    GeneratedPolicySet set;
    std::uniform_int_distribution<int> subnet_dist(0, 3);
    std::string shared_src = RandomIpPrefix(rng, subnet_dist(rng)) + "0/8";
    std::string shared_dst = RandomIpPrefix(rng, subnet_dist(rng)) + "0/8";
    for (int r = 0; r < 4; r++) {
      RuleDetail rule;
      rule.proto_ = 0;  // wildcard proto -- maximizes overlap odds
      rule.priority_ = 1;  // SAME priority for every rule -- the overlap
      rule.addr_type_ = 0;
      rule.direction_ = FlowDir::kIngress;
      rule.action_ = NetPolicyRule::kAllow;
      rule.policy_key_ = "overlap-policy-" + std::to_string(r);
      rule.src_ip_ = shared_src;
      rule.dst_ip_ = shared_dst;
      RULE_PORT port{};
      set.rules.push_back({rule, port});
    }
    GeneratedTuple tuple;
    tuple.proto = 6;
    tuple.src_port = 12345;
    tuple.dst_port = 80;
    // Append a clean single-digit last octet (no leading zero -- Rust's
    // Ipv4Addr parser rejects leading-zero octets, while C++'s inet_addr()
    // historically treats them as octal; avoid the whole ambiguity by
    // construction). The /8 mask makes the exact trailing octets
    // irrelevant to matching anyway -- both sides mask src/dst down to the
    // shared "10."-style first octet before comparing -- this just needs
    // to be a syntactically clean address sharing that prefix.
    tuple.src_addr = shared_src.substr(0, shared_src.rfind('.') + 1) + "5";
    tuple.dst_addr = shared_dst.substr(0, shared_dst.rfind('.') + 1) + "5";
    tuple.dir = FlowDir::kIngress;

    auto cpp_result = MatchWithCpp(set, tuple);
    auto rust_result = MatchWithRust(set, tuple);
    EXPECT_EQ(cpp_result.matched, rust_result.matched)
        << "iteration " << i << ": one implementation matched, the other didn't";
  }
}
```

- [ ] **Step 3: Wire into CMake and build**

Add `tests/policy_engine_differential_test.cc` to `net_rule_grpc_test`'s `SOURCES` list.
```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net_rule_grpc_test 2>&1 | tail -100"
```

- [ ] **Step 4: Run and fix any real discrepancies**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && ./net_rule_grpc_test --gtest_filter='PolicyEngineDifferentialTest.*'"
```
If this fails: read the failure output carefully (which iteration, what disagreed), reproduce it as a minimal Rust unit test in `crates/net_policy_engine/src/lib.rs`, and determine whether it's a real Rust-side bug (fix it, matching the C++ behavior) or a genuine C++ behavioral quirk worth a deliberate decision (per the design spec's Testing & Rollout section — replicate bug-for-bug with a tracked follow-up, or fix now; don't silently pick either without noting the decision in the commit message). Increase `kIterations` temporarily while debugging if a failure seems to need more reproductions to characterize. Re-run until both tests pass consistently — run at least 3 times in a row to build confidence before moving on, since this suite gates an irreversible cutover in Task 7.

- [ ] **Step 5: Commit**

```bash
git add tests/policy_engine_differential_test.cc CMakeLists.txt
git commit -m "Add differential test harness comparing C++ and Rust policy matchers"
```
(If Step 4 required fixes to `crates/net_policy_engine/src/lib.rs`, include those in this commit or a preceding one with a message explaining what was wrong and why the fix is correct — don't fold a real bug fix silently into "add tests".)

---

### Task 7: Cutover — wire `PolicyRule` to the Rust engine, delete old C++ matching code

**Files:**
- Modify: `net-policy.h` (`PolicyRule`'s member declarations; `MicroSegEngine`'s `GetPolicyTree`/`CreateRuleKeyByTuple` delegators replaced with a `MatchFiveTuple` delegator; remove the stray `#include "policy/engine.h"`)
- Modify: `rule-detail.cpp` (`PolicyRule`'s method implementations, including `GetAllConfig`; delete `RuleDetail`/`RuleGroup`/`RuleChain`/`PolicyTree` class bodies and `ParseCidr`/`Ipv4CidrToIp`)
- Modify: `net-policy.cpp` (`MatchNetPolicyRule`'s body only)
- Delete: `tests/policy_engine_differential_test.cc`
- Delete: `policy/engine.h`, `policy/engine.cc`
- Modify: `CMakeLists.txt` (remove `policy/engine.cc` and `tests/policy_engine_differential_test.cc` from source lists)

**Interfaces:**
- Consumes: `policy_engine::RustPolicyEngine`/`new_policy_engine`/`SharedRuleDetail`/`SharedRulePort`/`MatchedRule` (Task 5).

This is the highest-risk task in the plan — it's an irreversible-in-spirit cutover (recoverable via git, but production-facing). Read every file's actual current content before editing; do not trust this plan's line numbers.

- [ ] **Step 1: Confirm nothing else depends on the old classes**

```bash
grep -rn 'RuleDetail\|RuleGroup\|RuleChain\|PolicyTree' --include='*.h' --include='*.cc' --include='*.cpp' /Users/robbieqiu/workspace/net-policy | grep -v '/policy/engine\.' | grep -v 'net_policy_engine'
```
Every remaining hit must be inside a file this task explicitly modifies (`net-policy.h`, `rule-detail.cpp`, `net-policy.cpp`) or a genuinely unrelated identical-looking name (double check — `RuleDetail`/`RulePort`/`FlowDir` are also used as the *shared FFI struct* names in `net_policy_engine`'s bridge, which is expected and fine; the check here is for lingering references to the *C++ classes* being deleted, e.g. a `PolicyTree tree;` local variable declaration or `.MatchRuleGroup(...)` call outside the three files above). If something unexpected turns up, stop and re-scope rather than deleting it out from under a caller this plan didn't account for.

- [ ] **Step 2: Rewrite `PolicyRule` in `net-policy.h`**

Replace `PolicyRule`'s member declarations (read the current class body first — it should still match what's quoted in this plan's earlier sections, but confirm):
```cpp
class PolicyRule : public NfQueData
{
public:
    int efd_;
    PolicyTree input_tree_;
    PolicyTree output_tree_;
    std::set<int> mask_cidr_;
    std::set<int> priority_;

public:
    PolicyRule();
    ~PolicyRule();
    int ClearCfg();
    int DeletePolicy(FlowDir dir, std::string name);
    void AddMaskAndPriority(int priority, int mask);
    int AddPolicyToTree(RuleDetail &policy, RULE_PORT &stPort);
    std::vector<std::string> CreateRuleKeyByTuple(FiveTuple &tuple, FlowDir dir);
    PolicyTree *GetPolicyTree(FlowDir dir);
    cJSON *GetAllConfig(std::string name, net::ConnectionManager& conn_mgr);
    void PrintPolicyLog();
};
```
with:
```cpp
class PolicyRule : public NfQueData
{
public:
    int efd_;

public:
    PolicyRule();
    ~PolicyRule();
    int ClearCfg();
    int DeletePolicy(FlowDir dir, std::string name);
    int AddPolicyToTree(RuleDetail &policy, RULE_PORT &stPort);
    /*single-call match, replacing the old GetPolicyTree/CreateRuleKeyByTuple/
     *MatchRuleGroup three-call sequence -- see
     *docs/superpowers/specs/2026-08-02-cpp-to-rust-phase4-policy-engine-design.md*/
    std::optional<RuleDetail> MatchFiveTuple(FiveTuple &tuple, FlowDir dir);
    cJSON *GetAllConfig(std::string name, net::ConnectionManager& conn_mgr);
    void PrintPolicyLog();

private:
    std::unique_ptr<policy_engine::RustPolicyEngine> engine_;
};
```
Note: `GetPolicyTree`, `CreateRuleKeyByTuple`, and `AddMaskAndPriority` are removed from the public interface entirely — `PolicyTree` no longer exists as a type to return a pointer to, `CreateRuleKeyByTuple` is now internal to the Rust engine (only reachable via `MatchFiveTuple`), and `AddMaskAndPriority` is likewise now purely internal to `RustPolicyEngine::add_policy`. Grep for any caller of these three methods outside `PolicyRule` itself (there should be none beyond what Step 1 already found and what this task's own Step 4 fixes) before removing them.

Add `#include "net_policy_engine_cxxbridge/lib.h"` near `net-policy.h`'s existing `#include "net_policy_control_cxxbridge/lib.h"`.

Remove the stray `#include "policy/engine.h"` (confirmed dead in the design spec).

- [ ] **Step 3: Rewrite `PolicyRule`'s implementation in `rule-detail.cpp`**

Delete the `RuleDetail`, `RuleGroup`, `RuleChain`, `PolicyTree` class method implementations, and the `ParseCidr`/`Ipv4CidrToIp` free functions (everything from `RuleDetail::RuleDetail()` through `PolicyTree::AddPolicyToChain`, per this plan's earlier Task 2/3 sections which quote the originals in full — diff against the actual current file to confirm exact boundaries).

Replace `PolicyRule`'s implementations with:
```cpp
PolicyRule::PolicyRule() : engine_(policy_engine::new_policy_engine()) {}
PolicyRule::~PolicyRule() {}

int PolicyRule::ClearCfg() {
  engine_->clear_cfg();
  return 0;
}

std::vector<std::string> PolicyRule::CreateRuleKeyByTuple(FiveTuple& tuple, FlowDir dir) = delete;
// (deleted -- see net-policy.h; folded into MatchFiveTuple below)

std::optional<RuleDetail> PolicyRule::MatchFiveTuple(FiveTuple& tuple, FlowDir dir) {
  if (!IsValidUtf8(tuple.src_addr_) || !IsValidUtf8(tuple.dst_addr_)) {
    LOG_W("skipped policy match: invalid UTF-8 in five-tuple address");
    return std::nullopt;
  }
  int32_t dir_int = (dir == FlowDir::kIngress) ? 0 : 1;
  auto result = engine_->match_five_tuple(tuple.proto_, tuple.dst_port_, tuple.src_port_,
                                            tuple.src_addr_, tuple.dst_addr_, dir_int);
  if (!result.matched)
    return std::nullopt;

  RuleDetail rd;
  rd.proto_ = result.detail.proto;
  rd.priority_ = result.detail.priority;
  rd.addr_type_ = result.detail.addr_type;
  rd.direction_ = (result.detail.direction == 0) ? FlowDir::kIngress : FlowDir::kEgress;
  rd.action_ = static_cast<NetPolicyRule>(result.detail.action);
  rd.action_dsc_ = std::string(result.detail.action_dsc);
  rd.policy_key_ = std::string(result.detail.policy_key);
  rd.src_ip_ = std::string(result.detail.src_ip);
  rd.dst_ip_ = std::string(result.detail.dst_ip);
  for (const auto& p : result.detail.ports) {
    RULE_PORT port{};
    port.end_port_ = p.end_port;
    port.port_ = p.port;
    port.proto_ = p.proto;
    rd.ports_.push_back(port);
  }
  return rd;
}

int PolicyRule::AddPolicyToTree(RuleDetail& policy, RULE_PORT& stPort) {
  if (!IsValidUtf8(policy.policy_key_) || !IsValidUtf8(policy.src_ip_) ||
      !IsValidUtf8(policy.dst_ip_) || !IsValidUtf8(policy.action_dsc_)) {
    RETURN_ERROR(-1, "invalid UTF-8 in policy fields, refusing to add.");
  }
  policy_engine::SharedRuleDetail rd{};
  rd.proto = policy.proto_;
  rd.priority = policy.priority_;
  rd.addr_type = policy.addr_type_;
  rd.direction = (policy.direction_ == FlowDir::kIngress) ? 0 : 1;
  rd.action = static_cast<uint32_t>(policy.action_);
  rd.action_dsc = policy.action_dsc_;
  rd.policy_key = policy.policy_key_;
  rd.src_ip = policy.src_ip_;
  rd.dst_ip = policy.dst_ip_;

  policy_engine::SharedRulePort rp{};
  rp.end_port = stPort.end_port_;
  rp.port = stPort.port_;
  rp.proto = stPort.proto_;

  engine_->add_policy(rd, rp);
  return 0;
}

int PolicyRule::DeletePolicy(FlowDir dir, std::string name) {
  if (!IsValidUtf8(name)) {
    RETURN_ERROR(-1, "invalid UTF-8 in policy name, refusing to delete.");
  }
  int32_t dir_int = (dir == FlowDir::kIngress) ? 0 : 1;
  engine_->delete_policy(dir_int, name);
  return 0;
}

void PolicyRule::PrintPolicyLog() {
  auto in_rules = engine_->all_rules(0);
  auto out_rules = engine_->all_rules(1);
  LOG_D("NetInput : %lu, NetOutput : %lu", in_rules.size(), out_rules.size());
}

cJSON* PolicyRule::GetAllConfig(std::string name, net::ConnectionManager& conn_mgr) {
  NFQ_RES_INFO* res;
  cJSON *containers = nullptr, *tcp = nullptr, *r = nullptr, *item;
  cJSON *config = nullptr, *inrule = nullptr, *outrule = nullptr;

  tcp = cJSON_CreateObject();
  config = cJSON_CreateObject();
  inrule = cJSON_CreateArray();
  outrule = cJSON_CreateArray();
  containers = cJSON_CreateArray();
  auto stat = conn_mgr.stat();
  if (!config || !outrule || !inrule || !tcp || !containers)
    GOTO_ERROR(err, "create json object failed.");

  for (int dir_idx = 0; dir_idx < 2; dir_idx++) {
    auto rules = engine_->all_rules(dir_idx);
    cJSON* arr = (dir_idx == 0) ? inrule : outrule;
    const char* label = (dir_idx == 0) ? "inbound_rules" : "outbound_rules";

    for (const auto& rd : rules) {
      if (!name.empty() && std::string(rd.policy_key) != name)
        continue;
      r = cJSON_CreateObject();
      if (!r) GOTO_ERROR(err, "create json object failed.");
      cJSON_AddStringToObject(r, "policy_name", std::string(rd.policy_key).c_str());
      cJSON_AddNumberToObject(r, "priority", rd.priority);
      cJSON_AddStringToObject(r, "direction",
          utility::directionString(rd.direction == 0 ? FlowDir::kIngress : FlowDir::kEgress).data());
      cJSON_AddStringToObject(r, "action",
          utility::actionString(static_cast<NetPolicyRule>(rd.action)).data());
      cJSON_AddStringToObject(r, "protocol", utility::protocolString(rd.proto).data());
      cJSON_AddNumberToObject(r, "protocol_int", rd.proto);
      cJSON_AddStringToObject(r, "from_address", std::string(rd.src_ip).c_str());
      cJSON_AddStringToObject(r, "to_address", std::string(rd.dst_ip).c_str());
      cJSON_AddItemToArray(arr, r);
    }
    cJSON_AddItemToObject(config, label, arr);
  }

  if (!name.empty())
    return config;

  for (auto it = this->res_data_.begin(); it != this->res_data_.end(); it++) {
    res = it->second.get();
    if (res == nullptr)
      continue;
    item = cJSON_CreateObject();
    if (!item)
      GOTO_ERROR(err, "create json object failed.");
    cJSON_AddNumberToObject(item, "pid", res->pid_);
    cJSON_AddNumberToObject(item, "pod_id", res->pod_id_);
    cJSON_AddItemToArray(containers, item);
  }
  cJSON_AddItemToObject(config, "containers", containers);

  cJSON_AddNumberToObject(tcp, "tcp_connection", stat.tcp_conn_);
  cJSON_AddItemToObject(config, "tcp", tcp);

  return config;

err:
  if (tcp) cJSON_Delete(tcp);
  if (config) cJSON_Delete(config);
  if (inrule) cJSON_Delete(inrule);
  if (outrule) cJSON_Delete(outrule);
  if (containers) cJSON_Delete(containers);
  return nullptr;
}
```
(Remove the stray `std::vector<std::string> PolicyRule::CreateRuleKeyByTuple(...) = delete;` line above — it was included in this plan only to make the removal explicit in prose; it is not valid C++ for a non-virtual member function that's been removed from the class declaration entirely. Simply don't define it.)

Note the behavior change in `GetAllConfig`'s name-filtered path: it's now a linear scan over `all_rules()` instead of an O(1) `unordered_map::find` per group. This is a deliberate, acceptable simplification for this admin/debug config-dump path (not the packet-matching hot path) — call this out in the commit message, don't silently absorb it.

Add `#include "common/utf8_check.h"` to `rule-detail.cpp` if not already present.

- [ ] **Step 4: Update `MatchNetPolicyRule` in `net-policy.cpp`**

Read the current function (it should still resemble what's quoted in this plan's exploration notes, but confirm — `net-policy.cpp`, search for `MatchNetPolicyRule`):
```cpp
static std::optional<RuleDetail> MatchNetPolicyRule(FiveTuple& tuple, FLOW_DIR dir, DaemonContext& daemon) {
  if (daemon.Microseg().IsNodeIp(tuple.src_addr_u32_))
    return std::nullopt;
  auto rules = daemon.Microseg().GetPolicyTree(dir);
  if (rules->RuleSize() == 0)
    return std::nullopt;
  auto rule_keys = daemon.Microseg().CreateRuleKeyByTuple(tuple, dir);
  for (auto& key : rule_keys) {
    if (auto matched = rules->MatchRuleGroup(key, tuple))
      return matched;
  }
  return std::nullopt;
}
```
Replace with:
```cpp
static std::optional<RuleDetail> MatchNetPolicyRule(FiveTuple& tuple, FLOW_DIR dir, DaemonContext& daemon) {
  if (daemon.Microseg().IsNodeIp(tuple.src_addr_u32_))
    return std::nullopt;
  return daemon.Microseg().MatchFiveTuple(tuple, dir);
}
```
This requires `MicroSegEngine::MatchFiveTuple` (net-policy.h) to exist as a thin delegator to `PolicyRule::MatchFiveTuple`. Read `MicroSegEngine`'s current declaration in `net-policy.h` yourself to confirm the exact text (it should closely resemble the following, under the `/*---- network policy (delegated to PolicyRule) ----*/` comment block):
```cpp
    /*---- network policy (delegated to PolicyRule) ----*/
    PolicyTree* GetPolicyTree(FlowDir dir)         { return policy_rule_.GetPolicyTree(dir); }
    std::vector<std::string> CreateRuleKeyByTuple(FiveTuple& t, FlowDir d)
                                                   { return policy_rule_.CreateRuleKeyByTuple(t, d); }
    int  AddPolicy(RuleDetail& policy, RulePort& port) { return policy_rule_.AddPolicyToTree(policy, port); }
```
Replace the `GetPolicyTree`/`CreateRuleKeyByTuple` lines (keep `AddPolicy` unchanged — `PolicyRule::AddPolicyToTree`'s signature isn't changing) with:
```cpp
    /*---- network policy (delegated to PolicyRule) ----*/
    std::optional<RuleDetail> MatchFiveTuple(FiveTuple& t, FlowDir d) { return policy_rule_.MatchFiveTuple(t, d); }
    int  AddPolicy(RuleDetail& policy, RulePort& port) { return policy_rule_.AddPolicyToTree(policy, port); }
```

- [ ] **Step 5: Delete `policy/engine.{h,cc}` and update `CMakeLists.txt`**

```bash
git rm policy/engine.h policy/engine.cc
git rm tests/policy_engine_differential_test.cc
```
Remove `policy/engine.cc` from `CMakeLists.txt`'s `SOURCES` list (search for it — if it's genuinely not there, per the design spec's confirmation that it's dead code with zero build-system references, there's nothing to remove and this step is a no-op; verify rather than assume). Remove `tests/policy_engine_differential_test.cc` from `net_rule_grpc_test`'s `SOURCES`.

- [ ] **Step 6: Build and run everything**

```bash
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc) net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -c "cd /tmp/<scratch-dir>/build && ./net_rule_test && ./net_rule_grpc_test"
```
Expected: clean build under `-Wall -Werror` (zero new warnings — the differential test file and its dependency on the old classes are both gone, so this should compile without the old `RuleDetail`/`RuleGroup`/`RuleChain`/`PolicyTree` definitions existing anywhere anymore), every remaining test passes, including `PolicyEngineFfiTest.*` (Task 5, now exercising what's actually wired into production) and the existing `net_rule_grpc_test` suites that exercise `AddPolicyRule`/policy matching end-to-end through the real `GrpcDispatchAddPolicyRule`/`GrpcDispatchDeletePolicyRule` path (unaffected by this task's changes, but worth confirming explicitly still pass, since they're the closest thing to an integration-level regression check for this cutover). Run `net_rule_grpc_test` at least 3 times to check for flakiness.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "Cut over policy matching to the Rust engine; delete old C++ implementation"
```

---

## Definition of Done

- `docker exec net-policy-build-test bash -lc "cd /tmp/<scratch-dir>/build && cmake .. && make -j$(nproc)"` builds `net-rule`, `net_rule_test`, and `net_rule_grpc_test` with no new warnings under `-Wall -Werror`.
- `./net_rule_test` and `./net_rule_grpc_test` both pass in full.
- `RuleDetail`, `RuleGroup`, `RuleChain`, `PolicyTree` no longer exist as C++ classes; `PolicyRule` delegates all matching/mutation to `policy_engine::RustPolicyEngine` via an owned `std::unique_ptr`.
- `policy/engine.h`, `policy/engine.cc` no longer exist in the codebase.
- `NfQueData`/`NFQ_RES_INFO`, `MicroSegEngine`'s HTTP L7 policy/node-IP registry/TCP connection tracking, and `FiveTuple` are all unchanged from before this plan.
- `grpc/control_dispatch.h`-declared `AddPolicyRule`/`DeletePolicyRule` dispatch functions (implemented in `net-policy.cpp`, from Phase 2) required zero changes.
