# C++→Rust Migration: Phase 0 (Foundations) + Phase 1 (WAF Rule/Regex Engine) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a Rust workspace that builds as part of the existing CMake/`net-rule` binary via a `cxx` bridge (Phase 0), then move the WAF engine's core matching/regex computations (`Pcre2Regex`, `MatchDomain`, `MatchIgnoreType`, the CIDR/regex/boolean-expression leaves of `MatchForceWhiteList`/`MatchBlackWhiteList`) from C++/PCRE2/`std::regex` to Rust's `regex` crate, with the `Rules` class's public C++ API unchanged so no caller (`waf/plugin.cc`) needs to change.

**Architecture:** Strangler fig, single binary. A Cargo workspace lives at the repo root; each Rust crate is imported into the existing `CMakeLists.txt` via the `corrosion` CMake module, and `corrosion_add_cxxbridge` generates the C++-facing header/glue for each crate's `#[cxx::bridge]` module. Phase 1 keeps `Rules`'s control flow (looping over `BWList`/`Rule` vectors, mutating output `policy` structs) in C++, and replaces only the leaf computations — CIDR arithmetic, regex compilation/matching, boolean-expression evaluation, domain/suffix comparison — with calls into a new `waf_rules_core` Rust crate. This is a smaller, safer first cut than moving the whole `Rules` object into Rust; owning the full object is deferred to a later plan.

**Tech Stack:** Rust (stable channel, pinned via `rust-toolchain.toml`), `cxx` for C++ interop, `corrosion` for CMake↔Cargo build integration, the `regex` crate for WAF pattern matching.

## Global Constraints

- C++ build stays C++17, `-Wall -Werror` for the `net-rule`/`net_rule_grpc_test` targets (existing `CMakeLists.txt:139-147`) — do not weaken these flags to accommodate generated code; generated protobuf/cxx-bridge sources are already exempted the same way `NET_POLICY_PROTO_GENERATED_SRCS` is (`CMakeLists.txt:109-112`).
- No behavior change to `Rules`'s public C++ API (`waf/rule.h`) in this plan — every method keeps its existing name, parameter types, and return type, so `waf/plugin.cc` requires zero changes.
- Per the approved migration spec (`docs/superpowers/specs/2026-07-29-cpp-to-rust-migration-design.md`), interop uses the `cxx` crate bridge in a single process — no separate Rust process, no IPC.
- Build/test verification for every task in this plan runs inside the `net-policy-build-test` Docker container (Ubuntu 22.04, aarch64), which bind-mounts this repo at `/workspace/net-policy` — **not** `gracious_bardeen`, which mounts a different repo (`tensornavigator`) despite its `vsc-net-policy-*` image tag. Start it first if stopped: `docker start net-policy-build-test`.

---

## Phase 0: Foundations

**Note on CI:** the design spec calls for "CI updated to build both" as part of Phase 0. This repository has no CI configuration at all (no `.github/workflows` or equivalent) — there is nothing to update. If CI is added later, it should build the Rust workspace the same way Task 3 makes CMake build it.

### Task 1: Rust toolchain in the dev environment

**Files:**
- Modify: `.devcontainer/Dockerfile`
- Create: `rust-toolchain.toml`

**Interfaces:**
- Produces: a `rustc`/`cargo` on `PATH` inside the devcontainer image, and a pinned toolchain (`stable` channel) that every later Rust task in this plan builds against.

- [ ] **Step 1: Pin the toolchain**

Create `rust-toolchain.toml` at the repo root:

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

- [ ] **Step 2: Add Rust install to the devcontainer Dockerfile**

Append to `.devcontainer/Dockerfile` (after the existing `googletest` install block, before the gRPC toolchain block):

```dockerfile
RUN wget -qO- https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
  && echo 'export PATH="/root/.cargo/bin:$PATH"' >> /etc/bash.bashrc
ENV PATH="/root/.cargo/bin:${PATH}"
```

This is the durable fix for future container rebuilds. `wget` is already installed by the existing `apt-get install` line in this Dockerfile, so no new apt package is needed.

- [ ] **Step 3: Install Rust into the already-running container**

The `net-policy-build-test` container was built from an older image and won't pick up the Dockerfile edit until it's rebuilt. Install Rust into the running container directly so the rest of this plan is testable without a disruptive rebuild:

```bash
docker start net-policy-build-test
docker exec net-policy-build-test bash -lc "wget -qO- https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable"
```

- [ ] **Step 4: Verify**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && rustc --version && cargo --version"
```

Expected: both print version strings (no "command not found").

- [ ] **Step 5: Commit**

```bash
git add .devcontainer/Dockerfile rust-toolchain.toml
git commit -m "Add Rust toolchain to devcontainer for the C++->Rust migration"
```

---

### Task 2: Scaffold the Cargo workspace with a smoke-test cxx bridge

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `crates/ffi_smoke/Cargo.toml`
- Create: `crates/ffi_smoke/src/lib.rs`

**Interfaces:**
- Produces: `waf_rules::ffi_smoke::rust_ping() -> i32` (cxx-bridged, namespace `ffi_smoke`), used by Task 4 to prove the C++ build can call into Rust.

- [ ] **Step 1: Workspace manifest**

Create `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["crates/ffi_smoke"]
```

- [ ] **Step 2: Crate manifest**

Create `crates/ffi_smoke/Cargo.toml`:

```toml
[package]
name = "ffi_smoke"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
cxx = "1"
```

- [ ] **Step 3: Write the failing Rust test**

Create `crates/ffi_smoke/src/lib.rs`:

```rust
#[cxx::bridge(namespace = "ffi_smoke")]
mod ffi {
    extern "Rust" {
        fn rust_ping() -> i32;
    }
}

fn rust_ping() -> i32 {
    42
}

#[cfg(test)]
mod tests {
    use super::rust_ping;

    #[test]
    fn ping_returns_42() {
        assert_eq!(rust_ping(), 42);
    }
}
```

(Writing the implementation directly here is fine for a one-line smoke function; the test still runs and must pass before anything else depends on it.)

- [ ] **Step 4: Run the Rust test**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo test -p ffi_smoke"
```

Expected: `test tests::ping_returns_42 ... ok`.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/ffi_smoke
git commit -m "Scaffold Cargo workspace with a cxx-bridged smoke-test crate"
```

---

### Task 3: Wire Corrosion into CMake and import the workspace

**Files:**
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `crates/ffi_smoke` (Task 2) via the Cargo workspace manifest at repo root.
- Produces: a CMake target `ffi_smoke_cxxbridge` that Task 4 links into `net_rule_test`.

- [ ] **Step 1: Fetch Corrosion**

Add near the top of `CMakeLists.txt`, after `enable_testing()` / before the `SOURCES` list (around line 25):

```cmake
include(FetchContent)
FetchContent_Declare(
  Corrosion
  GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
  GIT_TAG v0.5
)
FetchContent_MakeAvailable(Corrosion)
```

- [ ] **Step 2: Import the Cargo workspace and generate the cxx bridge**

Add right after the Corrosion `FetchContent_MakeAvailable` call:

```cmake
corrosion_import_crate(MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml)

corrosion_add_cxxbridge(ffi_smoke_cxxbridge
  CRATE ffi_smoke
  FILES lib.rs
)
```

- [ ] **Step 3: Verify CMake configure succeeds**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy/build && cmake .. 2>&1 | tail -40"
```

Expected: configure completes without error and mentions Corrosion/the imported `ffi_smoke` crate. If `corrosion_add_cxxbridge` isn't recognized, check the Corrosion version fetched (`v0.5`) actually ships that macro — bump `GIT_TAG` to the latest release tag and re-run.

- [ ] **Step 4: Commit**

```bash
git add CMakeLists.txt
git commit -m "Wire Corrosion into CMake to build the Rust workspace"
```

---

### Task 4: Call the Rust smoke function from C++ and prove it end-to-end

**Files:**
- Create: `tests/ffi_smoke_test.cc`
- Modify: `CMakeLists.txt` (`net_rule_test` sources and link libraries, around lines 118-137 and 185-200)

**Interfaces:**
- Consumes: `ffi_smoke::rust_ping()` (declared in the cxx-generated header `ffi_smoke/src/lib.rs.h`, produced by Task 3's `ffi_smoke_cxxbridge` target).

- [ ] **Step 1: Write the failing GTest**

Create `tests/ffi_smoke_test.cc`:

```cpp
#include <gtest/gtest.h>
#include "ffi_smoke/src/lib.rs.h"

TEST(FfiSmokeTest, RustPingReturns42) {
  EXPECT_EQ(ffi_smoke::rust_ping(), 42);
}
```

- [ ] **Step 2: Wire it into the `net_rule_test` target**

In `CMakeLists.txt`, add `tests/ffi_smoke_test.cc` to the `net_rule_test` executable's source list (line 133, alongside the other `tests/*.cc` entries):

```cmake
add_executable(net_rule_test
    net/utility.cc
    net/filter.cc
    cjson.c
    http/header.cc
    http/codec.cc
    http/packet.cc
    http/http_filter_factory.cc
    http/filter.cc
    http/http1/http_parser.c
    http/http1/codec.cc
    http/http2/codec.cc
    http/url.cc
    http/http_inspector.cc
    http/connection.cc
    tests/http_inspector_test.cc
    tests/codec_test.cc
    tests/connection_manager_test.cc
    tests/http2/codec_tests.cc
    tests/ffi_smoke_test.cc
)
```

And add `ffi_smoke_cxxbridge` to `net_rule_test`'s `target_link_libraries` call (around line 185):

```cmake
target_link_libraries(net_rule_test
libnfnetlink
libnetfilter_queue
libnetfilter_conntrack
libnghttp2.a
libpcre2-8.a
libpcre2-posix.a
fmt::fmt-header-only
llhttp::llhttp_static
glog.a
gflags.a
${CMAKE_THREAD_LIBS_INIT}
libunwind.a
liblzma.a
libz.a
ffi_smoke_cxxbridge
GTest::gtest_main)
```

- [ ] **Step 3: Build and run**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy/build && cmake .. && make -j\$(nproc) net_rule_test 2>&1 | tail -60"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_test --gtest_filter=FfiSmokeTest.RustPingReturns42"
```

Expected: build succeeds, test passes — `[ PASSED ] 1 test.`

- [ ] **Step 4: Commit**

```bash
git add CMakeLists.txt tests/ffi_smoke_test.cc
git commit -m "Prove C++ can call into the Rust workspace end-to-end via cxx"
```

Phase 0 is now done: the build produces one binary, and C++ can call Rust. Everything below builds on this.

---

## Phase 1: WAF Rule/Regex Engine

Target: `waf/rule.h` / `waf/rule.cc`'s `Rules` class. The C++ class keeps its exact public API (used by `waf/plugin.cc`); each task below moves one leaf computation into the new `waf_rules_core` Rust crate and rewires the corresponding C++ method to call it.

**Why no PCRE-corpus audit task:** the design spec called for auditing existing WAF rules for PCRE-only syntax (backreferences, lookaround, possessive quantifiers) before switching to Rust's `regex` crate. There is no rule corpus checked into this repository — rules arrive at runtime via the control plane (`ParseConfiguration`, `waf/plugin.cc:428`) and aren't available to audit statically. Task 8 below implements the fallback behavior instead: if a pattern fails to compile under `regex`, log it and treat the rule as non-matching, mirroring today's behavior when `pcre2_compile` fails (`waf/rule.cc:765-772`). This keeps behavior identical for every pattern that already works, and fails safe (rather than crashing, which is what `MatchBlackWhiteList`'s current `std::regex(bwRule.at(j))` call would do today on a malformed pattern) for ones that don't.

### Task 5: Add the `waf_rules_core` crate

**Files:**
- Modify: `Cargo.toml` (workspace members)
- Create: `crates/waf_rules_core/Cargo.toml`
- Create: `crates/waf_rules_core/src/lib.rs`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces: the `waf_rules` cxx-bridge namespace and its shared struct types (`CidrNetwork`, `RegexMatch`), used by every task after this one.
- Produces: CMake target `waf_rules_core_cxxbridge`, to be linked into `net-rule` and `net_rule_grpc_test` (the two targets that compile `waf/rule.cc`; see `CMakeLists.txt:62-63` and `CMakeLists.txt:232-233`).

- [ ] **Step 1: Add the crate to the workspace**

Modify `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["crates/ffi_smoke", "crates/waf_rules_core"]
```

- [ ] **Step 2: Crate manifest**

Create `crates/waf_rules_core/Cargo.toml`:

```toml
[package]
name = "waf_rules_core"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
cxx = "1"
regex = "1"
```

- [ ] **Step 3: Bridge module skeleton**

Create `crates/waf_rules_core/src/lib.rs`:

```rust
#[cxx::bridge(namespace = "waf_rules")]
mod ffi {
    struct CidrNetwork {
        network_ip: String,
        mask: u8,
    }

    struct RegexMatch {
        matched: bool,
        value: String,
    }

    extern "Rust" {
        fn is_ip_address(s: &str) -> bool;
        fn ipv4_network_address(ip: &str, mask: u8) -> String;
        fn ipv4_cidr_to_network(cidr: &str) -> CidrNetwork;
        fn regex_first_match(pattern: &str, haystack: &str) -> RegexMatch;
        fn match_domain(host: &str, domains: Vec<String>) -> bool;
        fn match_ignore_type(path: &str, ignored_suffixes: Vec<String>) -> bool;
        fn eval_bool_expr(expr: &str) -> bool;
    }
}
```

(Function bodies are added task-by-task below; this step establishes the full signature set up front so every later task's `extern "Rust"` entry already has a home.)

- [ ] **Step 4: CMake wiring**

Add to `CMakeLists.txt` next to the `ffi_smoke_cxxbridge` block from Task 3:

```cmake
corrosion_add_cxxbridge(waf_rules_core_cxxbridge
  CRATE waf_rules_core
  FILES lib.rs
)
```

Add `waf_rules_core_cxxbridge` to the `target_link_libraries` calls for `net-rule` (`CMakeLists.txt:151-169`) and `net_rule_grpc_test` (`CMakeLists.txt:246-264`) — these are the two targets whose sources include `waf/rule.cc`.

- [ ] **Step 5: Verify it builds (even with stub-only bodies not yet added — Rust won't compile without them, so add minimal bodies now)**

Add temporary bodies to `crates/waf_rules_core/src/lib.rs` below the `mod ffi` block, one per declared function, each `unimplemented!()`:

```rust
fn is_ip_address(_s: &str) -> bool { unimplemented!() }
fn ipv4_network_address(_ip: &str, _mask: u8) -> String { unimplemented!() }
fn ipv4_cidr_to_network(_cidr: &str) -> ffi::CidrNetwork { unimplemented!() }
fn regex_first_match(_pattern: &str, _haystack: &str) -> ffi::RegexMatch { unimplemented!() }
fn match_domain(_host: &str, _domains: Vec<String>) -> bool { unimplemented!() }
fn match_ignore_type(_path: &str, _ignored_suffixes: Vec<String>) -> bool { unimplemented!() }
fn eval_bool_expr(_expr: &str) -> bool { unimplemented!() }
```

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo build -p waf_rules_core"
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy/build && cmake .. && make -j\$(nproc) net-rule 2>&1 | tail -60"
```

Expected: both succeed (the `unimplemented!()` bodies compile fine; they only panic if called, and nothing calls them yet).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml CMakeLists.txt crates/waf_rules_core
git commit -m "Scaffold waf_rules_core crate with the Phase 1 cxx bridge signatures"
```

---

### Task 6: Port `is_ip_address`

Replaces the free function `isIPAddress` (`waf/rule.h:194`, defined `waf/rule.cc:247-254`), which checks whether a string is a dotted-quad IPv4 literal.

**Files:**
- Modify: `crates/waf_rules_core/src/lib.rs`

**Interfaces:**
- Produces: `is_ip_address(s: &str) -> bool`, called by Task 13's C++ wrapper for the free function `isIPAddress`.

- [ ] **Step 1: Write the failing test**

Replace the `is_ip_address` stub body and add a test module (create the `#[cfg(test)] mod tests` block at the bottom of `lib.rs` if it doesn't exist yet):

```rust
#[cfg(test)]
mod tests {
    use super::is_ip_address;

    #[test]
    fn accepts_valid_dotted_quad() {
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("0.0.0.0"));
        assert!(is_ip_address("255.255.255.255"));
    }

    #[test]
    fn rejects_non_ip_strings() {
        assert!(!is_ip_address("example.com"));
        assert!(!is_ip_address("256.1.1.1"));
        assert!(!is_ip_address("1.2.3"));
        assert!(!is_ip_address("1.2.3.4.5"));
        assert!(!is_ip_address(""));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo test -p waf_rules_core is_ip_address"
```

Expected: FAIL (panics with "not implemented").

- [ ] **Step 3: Implement**

Replace the stub body:

```rust
fn is_ip_address(s: &str) -> bool {
    let re = regex::Regex::new(
        r"^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])$"
    )
    .expect("static IP regex is valid");
    re.is_match(s)
}
```

(Direct translation of the pattern in `waf/rule.cc:249-252` — one unbroken raw string, four dotted octet groups.)

- [ ] **Step 4: Run to verify it passes**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo test -p waf_rules_core is_ip_address"
```

Expected: PASS, both tests.

- [ ] **Step 5: Commit**

```bash
git add crates/waf_rules_core/src/lib.rs
git commit -m "Port is_ip_address to Rust"
```

---

### Task 7: Port `ipv4_network_address` and `ipv4_cidr_to_network`

Replaces `calculateNetworkAddress` and `ipv4CidrToIp` (`waf/rule.cc:256-295`), used by both `MatchForceWhiteList` and `MatchBlackWhiteList` to compare a client IP against a CIDR block.

**Files:**
- Modify: `crates/waf_rules_core/src/lib.rs`

**Interfaces:**
- Produces: `ipv4_network_address(ip: &str, mask: u8) -> String`, `ipv4_cidr_to_network(cidr: &str) -> CidrNetwork { network_ip, mask }` — both called from Task 13's rewired `MatchForceWhiteList`/`MatchBlackWhiteList`.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module:

```rust
#[cfg(test)]
mod tests {
    // ... existing tests from Task 6 stay above ...
    use super::{ipv4_cidr_to_network, ipv4_network_address};

    #[test]
    fn network_address_masks_correctly() {
        assert_eq!(ipv4_network_address("192.168.1.55", 24), "192.168.1.0");
        assert_eq!(ipv4_network_address("10.0.5.9", 8), "10.0.0.0");
        assert_eq!(ipv4_network_address("172.16.0.1", 32), "172.16.0.1");
    }

    #[test]
    fn cidr_to_network_splits_mask() {
        let result = ipv4_cidr_to_network("192.168.1.55/24");
        assert_eq!(result.network_ip, "192.168.1.0");
        assert_eq!(result.mask, 24);
    }

    #[test]
    fn cidr_to_network_defaults_to_slash_32() {
        let result = ipv4_cidr_to_network("10.1.2.3");
        assert_eq!(result.network_ip, "10.1.2.3");
        assert_eq!(result.mask, 32);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo test -p waf_rules_core cidr"
```

Expected: FAIL (`unimplemented!()`).

- [ ] **Step 3: Implement**

```rust
fn ipv4_network_address(ip: &str, mask: u8) -> String {
    let octets: Vec<u32> = ip.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    if octets.len() != 4 {
        return String::new();
    }
    let ip_bits = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    let mask_bits: u32 = if mask == 0 { 0 } else { 0xFFFF_FFFFu32 << (32 - mask as u32) };
    let network = ip_bits & mask_bits;
    format!(
        "{}.{}.{}.{}",
        (network >> 24) & 0xFF,
        (network >> 16) & 0xFF,
        (network >> 8) & 0xFF,
        network & 0xFF
    )
}

fn ipv4_cidr_to_network(cidr: &str) -> ffi::CidrNetwork {
    let (ip_part, mask) = match cidr.find('/') {
        Some(idx) => (&cidr[..idx], cidr[idx + 1..].parse().unwrap_or(32u8)),
        None => (cidr, 32u8),
    };
    ffi::CidrNetwork {
        network_ip: ipv4_network_address(ip_part, mask),
        mask,
    }
}
```

This mirrors `calculateNetworkAddress`/`ipv4CidrToIp` (`waf/rule.cc:256-295`), including the `/32` default when no mask is given.

- [ ] **Step 4: Run to verify it passes**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo test -p waf_rules_core cidr"
```

Expected: PASS, all three tests.

- [ ] **Step 5: Commit**

```bash
git add crates/waf_rules_core/src/lib.rs
git commit -m "Port CIDR network-address computation to Rust"
```

---

### Task 8: Port `regex_first_match` (replaces `Pcre2Regex`)

Replaces `Rules::Pcre2Regex` (`waf/rule.cc:753-799`) and the `std::regex` path-matching branch inside `MatchBlackWhiteList` (`waf/rule.cc:962-971`). This is the task that implements the PCRE-incompatibility fallback discussed in the Phase 1 preamble.

**Files:**
- Modify: `crates/waf_rules_core/src/lib.rs`

**Interfaces:**
- Produces: `regex_first_match(pattern: &str, haystack: &str) -> RegexMatch { matched, value }`, called from Task 12 (`Pcre2Regex` rewrite) and Task 13 (`MatchBlackWhiteList`'s path-regex case).

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    // ... existing tests stay above ...
    use super::regex_first_match;

    #[test]
    fn finds_first_match() {
        let result = regex_first_match(r"\d+", "abc123def456");
        assert!(result.matched);
        assert_eq!(result.value, "123");
    }

    #[test]
    fn reports_no_match() {
        let result = regex_first_match(r"\d+", "no digits here");
        assert!(!result.matched);
        assert_eq!(result.value, "");
    }

    #[test]
    fn invalid_pattern_fails_closed_instead_of_panicking() {
        // Backreferences aren't supported by the `regex` crate — this is
        // exactly the PCRE-incompatible case flagged in the Phase 1 preamble.
        let result = regex_first_match(r"(a)\1", "aa");
        assert!(!result.matched);
        assert_eq!(result.value, "");
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo test -p waf_rules_core regex_first_match"
```

Expected: FAIL (`unimplemented!()`).

- [ ] **Step 3: Implement**

```rust
fn regex_first_match(pattern: &str, haystack: &str) -> ffi::RegexMatch {
    let re = match regex::Regex::new(pattern) {
        Ok(re) => re,
        Err(e) => {
            eprintln!("waf_rules_core: pattern failed to compile, treating as no-match: {pattern:?}: {e}");
            return ffi::RegexMatch { matched: false, value: String::new() };
        }
    };
    match re.find(haystack) {
        Some(m) => ffi::RegexMatch { matched: true, value: m.as_str().to_string() },
        None => ffi::RegexMatch { matched: false, value: String::new() },
    }
}
```

This mirrors `Pcre2Regex`'s failure behavior — a pattern that won't compile is treated as "no match" (`waf/rule.cc:765-772` does the same on `pcre2_compile` failure) rather than propagating an error or crashing.

- [ ] **Step 4: Run to verify it passes**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo test -p waf_rules_core regex_first_match"
```

Expected: PASS, all three tests.

- [ ] **Step 5: Commit**

```bash
git add crates/waf_rules_core/src/lib.rs
git commit -m "Port regex matching to Rust, failing closed on PCRE-only patterns"
```

---

### Task 9: Port `match_domain`

Replaces `Rules::MatchDomain` (`waf/rule.cc:812-819`)'s comparison loop.

**Files:**
- Modify: `crates/waf_rules_core/src/lib.rs`

**Interfaces:**
- Produces: `match_domain(host: &str, domains: Vec<String>) -> bool`, called from Task 12's rewired `Rules::MatchDomain`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    // ... existing tests stay above ...
    use super::match_domain;

    #[test]
    fn matches_exact_domain_in_list() {
        let domains = vec!["example.com".to_string(), "example.org".to_string()];
        assert!(match_domain("example.org", domains));
    }

    #[test]
    fn does_not_match_absent_domain() {
        let domains = vec!["example.com".to_string()];
        assert!(!match_domain("evil.com", domains));
    }

    #[test]
    fn empty_domain_list_never_matches() {
        assert!(!match_domain("example.com", vec![]));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo test -p waf_rules_core match_domain"
```

Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
fn match_domain(host: &str, domains: Vec<String>) -> bool {
    domains.iter().any(|d| d == host)
}
```

Direct port of `MatchDomain`'s loop (`waf/rule.cc:812-819`).

- [ ] **Step 4: Run to verify it passes**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo test -p waf_rules_core match_domain"
```

Expected: PASS, all three tests.

- [ ] **Step 5: Commit**

```bash
git add crates/waf_rules_core/src/lib.rs
git commit -m "Port MatchDomain comparison to Rust"
```

---

### Task 10: Port `match_ignore_type`

Replaces `Rules::MatchIgnoreType` (`waf/rule.cc:801-809`).

**Files:**
- Modify: `crates/waf_rules_core/src/lib.rs`

**Interfaces:**
- Produces: `match_ignore_type(path: &str, ignored_suffixes: Vec<String>) -> bool`, called from Task 12's rewired `Rules::MatchIgnoreType`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    // ... existing tests stay above ...
    use super::match_ignore_type;

    #[test]
    fn matches_ignored_suffix_before_query_string() {
        let ignored = vec![".jpg".to_string(), ".png".to_string()];
        assert!(match_ignore_type("/static/logo.jpg?v=2", ignored));
    }

    #[test]
    fn no_match_when_suffix_not_ignored() {
        let ignored = vec![".jpg".to_string()];
        assert!(!match_ignore_type("/api/users.json", ignored));
    }

    #[test]
    fn no_match_when_path_has_no_dot() {
        let ignored = vec![".jpg".to_string()];
        assert!(!match_ignore_type("/api/users", ignored));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo test -p waf_rules_core match_ignore_type"
```

Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
fn match_ignore_type(path: &str, ignored_suffixes: Vec<String>) -> bool {
    let before_query = path.split('?').next().unwrap_or("");
    match before_query.rfind('.') {
        None => false,
        Some(pos) => {
            let suffix = &before_query[pos..];
            ignored_suffixes.iter().any(|s| s == suffix)
        }
    }
}
```

Direct port of `MatchIgnoreType` (`waf/rule.cc:801-809`): split on `?`, take the part before it, find the last `.`, compare the suffix (including the dot) against the ignore list.

- [ ] **Step 4: Run to verify it passes**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo test -p waf_rules_core match_ignore_type"
```

Expected: PASS, all three tests.

- [ ] **Step 5: Commit**

```bash
git add crates/waf_rules_core/src/lib.rs
git commit -m "Port MatchIgnoreType suffix check to Rust"
```

---

### Task 11: Port `eval_bool_expr`

Replaces the free function `eval` (`waf/rule.cc:68-180`), a shunting-yard-style evaluator for expressions built from `true`/`false`/`&&`/`||`/`(`/`)`, used at the end of `MatchBlackWhiteList` (`waf/rule.cc:1035-1047`) once each rule component has been reduced to a `true`/`false` token.

**Files:**
- Modify: `crates/waf_rules_core/src/lib.rs`

**Interfaces:**
- Produces: `eval_bool_expr(expr: &str) -> bool`, called from Task 13's rewired `MatchBlackWhiteList`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    // ... existing tests stay above ...
    use super::eval_bool_expr;

    #[test]
    fn evaluates_simple_and() {
        assert!(eval_bool_expr("true&&true"));
        assert!(!eval_bool_expr("true&&false"));
    }

    #[test]
    fn evaluates_simple_or() {
        assert!(eval_bool_expr("false||true"));
        assert!(!eval_bool_expr("false||false"));
    }

    #[test]
    fn and_binds_tighter_than_or() {
        // true || (false && false) -> true
        assert!(eval_bool_expr("true||false&&false"));
    }

    #[test]
    fn respects_parentheses() {
        // (true || false) && false -> false
        assert!(!eval_bool_expr("(true||false)&&false"));
    }

    #[test]
    fn tolerates_surrounding_spaces() {
        assert!(eval_bool_expr("true && true"));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo test -p waf_rules_core eval_bool_expr"
```

Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
fn eval_bool_expr(expr: &str) -> bool {
    let chars: Vec<char> = expr.chars().collect();
    let mut operators: Vec<char> = Vec::new();
    let mut operands: Vec<bool> = Vec::new();

    fn reduce_one(operators: &mut Vec<char>, operands: &mut Vec<bool>) {
        let op = operators.pop().expect("reduce_one called with empty operator stack");
        let rhs = operands.pop().expect("missing rhs operand");
        let lhs = operands.pop().expect("missing lhs operand");
        operands.push(if op == '&' { lhs && rhs } else { lhs || rhs });
    }

    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == ' ' {
            i += 1;
            continue;
        }
        if c == '(' {
            operators.push(c);
        } else if c == ')' {
            while !operators.is_empty() && *operators.last().unwrap() != '(' {
                reduce_one(&mut operators, &mut operands);
            }
            if !operators.is_empty() {
                operators.pop();
            }
        } else if c == '&' && chars.get(i + 1) == Some(&'&') {
            i += 1;
            while !operators.is_empty()
                && *operators.last().unwrap() != '('
                && *operators.last().unwrap() != '|'
            {
                reduce_one(&mut operators, &mut operands);
            }
            operators.push('&');
        } else if c == '|' && chars.get(i + 1) == Some(&'|') {
            i += 1;
            while !operators.is_empty() && *operators.last().unwrap() != '(' {
                reduce_one(&mut operators, &mut operands);
            }
            operators.push('|');
        } else if chars[i..].starts_with(&['t', 'r', 'u', 'e']) {
            operands.push(true);
            i += 3;
        } else if chars[i..].starts_with(&['f', 'a', 'l', 's', 'e']) {
            operands.push(false);
            i += 4;
        }
        i += 1;
    }

    while !operators.is_empty() {
        reduce_one(&mut operators, &mut operands);
    }

    operands.pop().unwrap_or(false)
}
```

This is a direct transliteration of `eval()` (`waf/rule.cc:68-180`): `&&` reduces any pending `&` operators but stops at `|` or `(` (same precedence, left-associative); `||` reduces everything down to the nearest `(` (lower precedence than `&&`); at the end, the whole stack drains. `reduce_one` factors out the repeated pop-pop-combine-push block that appears four times in the original.

- [ ] **Step 4: Run to verify it passes**

```bash
docker exec net-policy-build-test bash -lc "source \$HOME/.cargo/env && cd /workspace/net-policy && cargo test -p waf_rules_core eval_bool_expr"
```

Expected: PASS, all five tests.

- [ ] **Step 5: Commit**

```bash
git add crates/waf_rules_core/src/lib.rs
git commit -m "Port boolean-expression evaluator to Rust"
```

---

### Task 12: Rewire `Pcre2Regex`, `MatchDomain`, `MatchIgnoreType`, and `isIPAddress` to call Rust

**Files:**
- Modify: `waf/rule.cc:247-254` (`isIPAddress`)
- Modify: `waf/rule.cc:753-799` (`Rules::Pcre2Regex`)
- Modify: `waf/rule.cc:801-809` (`Rules::MatchIgnoreType`)
- Modify: `waf/rule.cc:812-819` (`Rules::MatchDomain`)
- Modify: `waf/rule.cc:1` (add `#include "waf_rules_core/src/lib.rs.h"`)

**Interfaces:**
- Consumes: `waf_rules::is_ip_address`, `waf_rules::regex_first_match`, `waf_rules::match_domain`, `waf_rules::match_ignore_type` (all from Task 5's bridge, implemented in Tasks 6, 8, 9, 10).
- Produces: no change to any signature in `waf/rule.h` — `waf/plugin.cc` is untouched by this task.

- [ ] **Step 1: Add the include**

At the top of `waf/rule.cc`, alongside the other includes (line 1-12):

```cpp
#include "waf_rules_core/src/lib.rs.h"
```

- [ ] **Step 2: Rewire `isIPAddress`**

Replace `waf/rule.cc:247-254`:

```cpp
bool isIPAddress(const std::string& str)
{
    return waf_rules::is_ip_address(str);
}
```

(Deletes the `std::regex pattern` local and its `std::regex_match` call; the `<regex>` include stays for now since other functions in this file still use `std::regex` until Task 13.)

- [ ] **Step 3: Rewire `Pcre2Regex`**

Replace `waf/rule.cc:753-799`:

```cpp
std::optional<std::string> Rules::Pcre2Regex(std::uint64_t id, std::string &expr, std::string &src)
{
    auto result = waf_rules::regex_first_match(expr, src);
    if (!result.matched) {
        return std::nullopt;
    }
    return std::string(result.value);
}
```

`id` is kept for API compatibility (`waf/rule.h:135` declares it) even though it's no longer used for error-message context — Rust's `regex_first_match` logs compile failures itself (Task 8). The `#define PCRE2_CODE_UNIT_WIDTH 8` / `#include <pcre2.h>` lines at the top of the file can now be deleted since nothing in `waf/rule.cc` calls PCRE2 directly anymore — leave the `CMakeLists.txt` `libpcre2-8.a`/`libpcre2-posix.a` link lines alone for now, since other translation units may still need them (verified in Task 14's build).

- [ ] **Step 4: Rewire `MatchIgnoreType` and `MatchDomain`**

Replace `waf/rule.cc:801-809`:

```cpp
bool Rules::MatchIgnoreType(std::string &src)
{
    std::vector<std::string> suffixes;
    for (auto &entry : this->ignore_) {
        suffixes.push_back(entry.first);
    }
    return waf_rules::match_ignore_type(src, suffixes);
}
```

Replace `waf/rule.cc:812-819`:

```cpp
bool Rules::MatchDomain(std::string &src)
{
    return waf_rules::match_domain(src, this->domain_);
}
```

`waf_rules::match_domain`/`match_ignore_type` take `Vec<String>` (an owned Rust vector, generated by cxx as `rust::Vec<rust::String>`) — passing `this->domain_` (a `std::vector<std::string>`) directly relies on cxx's implicit conversion for `Vec<String>` parameters; if the generated header doesn't accept a `std::vector<std::string>` directly, build the `rust::Vec<rust::String>` explicitly with a loop instead (this is exactly the kind of small API mismatch Step 5's build below will surface).

- [ ] **Step 5: Build and run the existing suites**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j\$(nproc) net-rule net_rule_grpc_test 2>&1 | tail -80"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test"
```

Expected: both targets build; `net_rule_grpc_test` passes (it doesn't yet directly test `Rules`' WAF matching — Task 14 adds that — but it exercises `waf/plugin.cc`/`waf/rule.cc` indirectly through the gRPC control-plane tests, so a regression here would show up as a build or link failure at minimum).

- [ ] **Step 6: Commit**

```bash
git add waf/rule.cc
git commit -m "Rewire isIPAddress, Pcre2Regex, MatchIgnoreType, MatchDomain to Rust"
```

---

### Task 13: Rewire `MatchForceWhiteList` and `MatchBlackWhiteList`'s leaf computations

**Files:**
- Modify: `waf/rule.cc:821-874` (`MatchForceWhiteList`)
- Modify: `waf/rule.cc:877-1051` (`MatchBlackWhiteList`)

**Interfaces:**
- Consumes: `waf_rules::ipv4_cidr_to_network`, `waf_rules::ipv4_network_address` (Task 7), `waf_rules::regex_first_match` (Task 8), `waf_rules::eval_bool_expr` (Task 11).

- [ ] **Step 1: Rewire the CIDR case in `MatchForceWhiteList`**

In `waf/rule.cc:852-863`, replace:

```cpp
            case AUTO_RULE_IP_CIDR:
                sip = ipv4CidrToIp(wRule.at(j), mask);
                for(n = 0; n < (int)ips.size(); n++)
                {
                    ip = ips.at(n);
                    rip = calculateNetworkAddress(ip, mask);
                    if(rip != sip) continue;
                    policy = this->force_white_list_.at(i);
                    policy.mode_ = ip;
                    return true;
                }
                break;
```

with:

```cpp
            case AUTO_RULE_IP_CIDR:
            {
                auto cidr = waf_rules::ipv4_cidr_to_network(wRule.at(j));
                sip = std::string(cidr.network_ip);
                mask = cidr.mask;
                for(n = 0; n < (int)ips.size(); n++)
                {
                    ip = ips.at(n);
                    rip = std::string(waf_rules::ipv4_network_address(ip, mask));
                    if(rip != sip) continue;
                    policy = this->force_white_list_.at(i);
                    policy.mode_ = ip;
                    return true;
                }
                break;
            }
```

- [ ] **Step 2: Rewire the CIDR case in `MatchBlackWhiteList`**

In `waf/rule.cc:929-944`, replace:

```cpp
            case AUTO_RULE_IP_CIDR:
                sip = ipv4CidrToIp(bwRule.at(j), mask);
                for(n = 0; n < (int)ips.size(); n++)
                {
                    ip = ips.at(n);
                    rip = calculateNetworkAddress(ip, mask);
                    if(rip != sip) continue;
                    sMathRet = "true";
                    sMode = ip;
                    sDesc = (policy.action_ == ATCTION_DROP) ? "IP黑名单" : "IP白名单";
                    break;
                }
                mode.push_back(ip);
                desc.push_back(sDesc);
                bRet.push_back(sMathRet);
                break;
```

with:

```cpp
            case AUTO_RULE_IP_CIDR:
            {
                auto cidr = waf_rules::ipv4_cidr_to_network(bwRule.at(j));
                sip = std::string(cidr.network_ip);
                mask = cidr.mask;
                for(n = 0; n < (int)ips.size(); n++)
                {
                    ip = ips.at(n);
                    rip = std::string(waf_rules::ipv4_network_address(ip, mask));
                    if(rip != sip) continue;
                    sMathRet = "true";
                    sMode = ip;
                    sDesc = (policy.action_ == ATCTION_DROP) ? "IP黑名单" : "IP白名单";
                    break;
                }
                mode.push_back(ip);
                desc.push_back(sDesc);
                bRet.push_back(sMathRet);
                break;
            }
```

- [ ] **Step 3: Rewire the path-regex case in `MatchBlackWhiteList`**

Replace `waf/rule.cc:962-971`:

```cpp
            case AUTO_RULE_PATH_REG:
                for(n = 0; n < 1; n++)
                {
                    if(path.length() == 0) break;
                    data = split(path, "?");
                    if (!std::regex_search(data.at(0), std::regex(bwRule.at(j)))) break;
                    sMathRet = "true";
                    sMode = path;
                    sDesc = (policy.action_ == ATCTION_DROP) ? "路径黑名单" : "路径白名单";
                    break;
                }
```

with:

```cpp
            case AUTO_RULE_PATH_REG:
                for(n = 0; n < 1; n++)
                {
                    if(path.length() == 0) break;
                    data = split(path, "?");
                    if (!waf_rules::regex_first_match(bwRule.at(j), data.at(0)).matched) break;
                    sMathRet = "true";
                    sMode = path;
                    sDesc = (policy.action_ == ATCTION_DROP) ? "路径黑名单" : "路径白名单";
                    break;
                }
```

This also fixes a latent crash: `std::regex(bwRule.at(j))` throws `std::regex_error` (uncaught) if `bwRule.at(j)` isn't a valid ECMAScript pattern, taking down the process; `regex_first_match` fails closed instead (Task 8).

- [ ] **Step 4: Rewire the final `eval()` call**

Replace `waf/rule.cc:1046-1047`:

```cpp
        /*eval*/
        if(eval(expr)) return true;
```

with:

```cpp
        /*eval*/
        if(waf_rules::eval_bool_expr(expr)) return true;
```

- [ ] **Step 5: Remove now-dead C++ helpers**

`calculateNetworkAddress`, `ipv4CidrToIp`, and `eval` (`waf/rule.cc:68-180`, `256-295`) have no remaining callers after Steps 1-4 — delete them. Leave `removeSpeStr`, `replaceString`, `delSpace`, `getRuleVaule`, `CountSubstr`, `CountRuleTagNumWithDelSpace`, `split`, and the rest of `AddBlackWhiteList`'s parsing logic alone; they're out of scope for this plan (Phase 1 targets matching, not rule-loading).

- [ ] **Step 6: Build and run**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j\$(nproc) net-rule net_rule_grpc_test 2>&1 | tail -80"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test"
```

Expected: both build; `net_rule_grpc_test` passes.

- [ ] **Step 7: Commit**

```bash
git add waf/rule.cc
git commit -m "Rewire MatchForceWhiteList/MatchBlackWhiteList leaf computations to Rust"
```

---

### Task 14: Golden-value GTest coverage for the now-Rust-backed `Rules` API

There is no pre-existing GTest suite for `waf/rule.cc` to port (confirmed: no `tests/*waf*` file exists, and `waf/rule.cc` isn't compiled into `net_rule_test`, only into `net-rule`/`net_rule_grpc_test`). This task adds one, with expected outputs derived directly from tracing the pre-Phase-1 C++ implementation, so this behavior has real regression coverage going forward.

**Files:**
- Create: `tests/waf_rules_test.cc`
- Modify: `CMakeLists.txt` (`net_rule_grpc_test` sources, around line 241)

**Interfaces:**
- Consumes: `Rules` (`waf/rule.h`) — the public C++ API, unchanged by this plan.

- [ ] **Step 1: Write the test file**

Create `tests/waf_rules_test.cc`:

```cpp
#include <gtest/gtest.h>
#include "rule.h"

TEST(WafRulesTest, MatchDomainFindsExactEntry) {
  Rules rules;
  rules.InitRule();
  std::string a = "example.com", b = "example.org";
  rules.AddDomain(a);
  rules.AddDomain(b);

  std::string target = "example.org";
  EXPECT_TRUE(rules.MatchDomain(target));

  std::string other = "evil.com";
  EXPECT_FALSE(rules.MatchDomain(other));
}

TEST(WafRulesTest, MatchIgnoreTypeChecksSuffixBeforeQueryString) {
  Rules rules;
  rules.InitRule();
  std::string jpg = ".jpg";
  rules.AddIgnoreType(jpg);

  std::string image = "/static/logo.jpg?v=2";
  EXPECT_TRUE(rules.MatchIgnoreType(image));

  std::string api = "/api/users.json";
  EXPECT_FALSE(rules.MatchIgnoreType(api));
}

TEST(WafRulesTest, Pcre2RegexFindsSubstring) {
  Rules rules;
  std::string expr = "\\d+";
  std::string src = "user id: 4821";
  auto result = rules.Pcre2Regex(1, expr, src);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(*result, "4821");
}

TEST(WafRulesTest, Pcre2RegexReturnsNulloptOnNoMatch) {
  Rules rules;
  std::string expr = "\\d+";
  std::string src = "no digits here";
  auto result = rules.Pcre2Regex(1, expr, src);
  EXPECT_FALSE(result.has_value());
}

TEST(WafRulesTest, MatchForceWhiteListMatchesCidrEntry) {
  Rules rules;
  rules.InitRule();
  BWList bw;
  bw.mode_ = "strong-white";
  bw.expr_ = "10.0.0.0/8";
  rules.AddForceWhiteList(bw);

  std::vector<std::string> ips = {"10.1.2.3"};
  std::string path = "/anything";
  BWList policy;
  EXPECT_TRUE(rules.MatchForceWhiteList(ips, path, policy));
  EXPECT_EQ(policy.action_, ACTION_BYPASS);
}

TEST(WafRulesTest, MatchBlackWhiteListMatchesPathRegex) {
  Rules rules;
  rules.InitRule();
  BWList bw;
  bw.mode_ = "black";
  bw.expr_ = "(path matches \"^/admin\")";
  rules.AddBlackWhiteList(bw);

  std::vector<std::string> ips = {"203.0.113.5"};
  std::string path = "/admin/delete-everything";
  BWList policy;
  EXPECT_TRUE(rules.MatchBlackWhiteList(ips, path, policy));
  EXPECT_EQ(policy.action_, ATCTION_DROP);
}
```

- [ ] **Step 2: Wire it into `net_rule_grpc_test`**

In `CMakeLists.txt`, add `tests/waf_rules_test.cc` to `net_rule_grpc_test`'s source list (line 241, alongside the other `tests/grpc_*.cc` entries):

```cmake
    tests/grpc_control_service_test.cc
    tests/grpc_event_bridge_test.cc
    tests/grpc_e2e_test.cc
    tests/waf_rules_test.cc
```

- [ ] **Step 3: Run to verify it fails first**

Before wiring, this step doesn't apply the usual way (the test targets already-implemented Rust-backed code from Tasks 6-13, not new code) — instead, run it once right after adding to confirm it actually exercises the Rust path and passes, which is the real regression-coverage goal here:

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j\$(nproc) net_rule_grpc_test 2>&1 | tail -80"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter=WafRulesTest.*"
```

Expected: all 6 `WafRulesTest.*` cases pass.

- [ ] **Step 4: Run the full existing suite to confirm no regression**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_test && ./net_rule_grpc_test"
```

Expected: all tests in both binaries pass (`ffi_smoke_test.cc` from Phase 0, plus every existing suite, plus the new `WafRulesTest.*` cases).

- [ ] **Step 5: Commit**

```bash
git add CMakeLists.txt tests/waf_rules_test.cc
git commit -m "Add golden-value GTest coverage for the Rust-backed WAF matching API"
```

---

## Definition of Done

- `docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j\$(nproc)"` builds `net-rule`, `net_rule_test`, and `net_rule_grpc_test` with no new warnings under `-Wall -Werror`.
- `./net_rule_test` and `./net_rule_grpc_test` both pass in full, including the new `FfiSmokeTest` and `WafRulesTest` cases.
- `waf/plugin.cc` and `waf/rule.h` are byte-for-byte unchanged from before this plan — only `waf/rule.cc`'s method bodies changed.
- `Pcre2Regex`, `MatchDomain`, `MatchIgnoreType`, and the CIDR/regex/boolean-expression leaves of `MatchForceWhiteList`/`MatchBlackWhiteList` all execute in Rust.
