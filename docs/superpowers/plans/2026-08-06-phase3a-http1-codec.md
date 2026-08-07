# Phase 3a: HTTP/1.1 Codec Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `http/http1/codec.{h,cc}`'s llhttp-based HTTP/1.1 request-line/header parser with a new Rust crate (`crates/http1_codec`), reached via `cxx`, that does header parsing plus body *framing* only (no body content exposed) — matching real current need rather than full llhttp parity.

**Architecture:** A new Rust crate does incremental, accumulate-and-reparse header parsing (via `httparse`) plus a hand-rolled body-framing state machine (Content-Length countdown / chunked-encoding skip), exposed through a `cxx` bridge as an opaque `Http1Parser` type with one `dispatch(&mut self, data: &[u8]) -> ParsedHeader` method. `http/http1/codec.h`/`codec.cc` are rewritten *in place* (same file paths, same `http::http1::ConnectionImpl` class name and public interface) to become a thin adapter over the new Rust type — this means `http/connection.cc`'s `createCodec` call site needs no changes at all, and the two existing tests in `tests/codec_test.cc` need no changes either, since the class name, constructor signature, and every public method's behavior are preserved exactly.

**Tech Stack:** Rust (`httparse` crate, `cxx` bridge, following the same opaque-struct pattern as `net_flow_engine`/`net_policy_engine`), C++17.

## Global Constraints

- C++17, `-Wall -Werror` — every task's edits must build clean.
- **Direct cutover, no runtime toggle, no differential harness, no canary.** Verified against actual practice across every completed phase (not the master roadmap's stale "Validation Strategy" section) — see `docs/superpowers/specs/2026-08-06-phase3a-http1-codec-design.md`'s Testing & Rollout section. Port/build out tests, get them green, cut over directly.
- **`http/http1/http_parser.{h,c}` (vendored joyent http-parser) is NOT touched by this plan.** It is not fully dead — `http/url.cc` (out of scope, stays C++ until Phase 3c) genuinely depends on it. Deletion is deferred to Phase 3c. Do not delete or edit it in any task below.
- **Framing only — no body content is exposed anywhere in this plan.** Content-Length and chunked `Transfer-Encoding` are tracked only to correctly locate the next pipelined request; body bytes are never stored or returned.
- **Absolute-form request-target parsing is reimplemented natively in Rust**, not by calling back into C++'s `Url`/`http/url.cc`.
- The exact current host-resolution algorithm (verified by reading `http/http1/codec.cc`/`codec.h` directly, and by running `Http1CodecTest.*` to confirm real behavior — see the design spec) must be preserved exactly:
  1. If the request-target is absolute-form (`scheme://host[:port]/path`), the header's host is set from that authority's host component (port excluded) — unconditionally, and this always wins over a `Host` header even if one is present later.
  2. If the request-target is origin-form (`/path`) and a `Host` header is present, the header's host is the `Host` header's value with a trailing `:port` suffix stripped (found via the *last* `:` in the value — this is not IPv6-literal-aware, matching the old code's `find_last_of(":")`, which was never IPv6-aware either; not being fixed here).
  3. If neither applies, the header's host is empty.
- Source of truth for scope: `docs/superpowers/specs/2026-08-06-phase3a-http1-codec-design.md` (committed, user-approved, including two corrections made while writing this plan). Any conflict between this plan and that spec's Goals/Non-Goals is the human partner's call, not the implementer's.

---

### Task 1: Scaffold the `http1_codec` Rust crate

**Files:**
- Create: `crates/http1_codec/Cargo.toml`
- Create: `crates/http1_codec/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)
- Modify: `CMakeLists.txt`
- Create: `tests/http1_codec_smoke_test.cc`

**Interfaces:**
- Produces: a linkable `http1_codec_cxxbridge` CMake target and a working (but not yet functional beyond a smoke test) `cxx` bridge, proving the plumbing before real parsing logic is written. Later tasks build directly on this crate's `lib.rs`.

- [ ] **Step 1: Create the crate's `Cargo.toml`**

```toml
[package]
name = "http1_codec"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
cxx = "1"
httparse = "1"
```

- [ ] **Step 2: Create a smoke-test-only `lib.rs`**

```rust
#[cxx::bridge(namespace = "http1_codec")]
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

This is deliberately a placeholder mirroring `crates/ffi_smoke`'s own smoke-test shape — later tasks replace it with the real bridge and delete `rust_ping`.

- [ ] **Step 3: Add the crate to the Cargo workspace**

In `Cargo.toml`, replace:

```toml
members = ["crates/ffi_smoke", "crates/net_policy_control", "crates/net_policy_events", "crates/net_flow_engine", "crates/net_policy_engine", "crates/net_iptables", "crates/net_nfq", "crates/net_conntrack"]
```

with:

```toml
members = ["crates/ffi_smoke", "crates/http1_codec", "crates/net_policy_control", "crates/net_policy_events", "crates/net_flow_engine", "crates/net_policy_engine", "crates/net_iptables", "crates/net_nfq", "crates/net_conntrack"]
```

- [ ] **Step 4: Add the `corrosion_add_cxxbridge` block to `CMakeLists.txt`**

Insert immediately after the `net_flow_engine_cxxbridge` block (i.e. between it and `net_policy_engine_cxxbridge`) — exact anchor text:

```cmake
corrosion_add_cxxbridge(net_flow_engine_cxxbridge
  CRATE net_flow_engine
  FILES lib.rs
)

corrosion_add_cxxbridge(net_policy_engine_cxxbridge
  CRATE net_policy_engine
  FILES lib.rs
)
```

becomes:

```cmake
corrosion_add_cxxbridge(net_flow_engine_cxxbridge
  CRATE net_flow_engine
  FILES lib.rs
)

corrosion_add_cxxbridge(http1_codec_cxxbridge
  CRATE http1_codec
  FILES lib.rs
)

corrosion_add_cxxbridge(net_policy_engine_cxxbridge
  CRATE net_policy_engine
  FILES lib.rs
)
```

- [ ] **Step 5: Link the new bridge into all three C++ targets**

In `CMakeLists.txt`, there are three `target_link_libraries` blocks (`net-rule`, `net_rule_test`, `net_rule_grpc_test`). Two of them (`net-rule`'s and `net_rule_grpc_test`'s) contain an *identical* two-line substring:

```cmake
  net_flow_engine_cxxbridge
  net_policy_engine_cxxbridge
```

Since this exact text occurs twice in the file, use a **replace-all** edit (not a single-match replace, which would fail or hit the wrong occurrence) to change both at once, from:

```cmake
  net_flow_engine_cxxbridge
  net_policy_engine_cxxbridge
```

to:

```cmake
  net_flow_engine_cxxbridge
  http1_codec_cxxbridge
  net_policy_engine_cxxbridge
```

This correctly updates both `net-rule`'s and `net_rule_grpc_test`'s blocks in one pass, since both need the identical change.

`net_rule_test`'s block is different — it currently only links `ffi_smoke_cxxbridge` (it doesn't link `net_flow_engine_cxxbridge` at all). This text is unique in the file; replace:

```cmake
ffi_smoke_cxxbridge
GTest::gtest_main)
```

with:

```cmake
ffi_smoke_cxxbridge
http1_codec_cxxbridge
GTest::gtest_main)
```

Also update the two `--allow-multiple-definition` explanatory comments (one after `net-rule`'s `LINK_FLAGS`, one after `net_rule_grpc_test`'s) to include `http1_codec_cxxbridge` in the list of staticlib crates named. For `net-rule`'s comment, replace:

```cmake
# net_policy_control_cxxbridge, net_policy_events_cxxbridge, net_flow_engine_cxxbridge,
# net_policy_engine_cxxbridge, net_iptables_cxxbridge, net_nfq_cxxbridge, and
# net_conntrack_cxxbridge are separate Rust staticlib crates that all depend on the `cxx` crate; since each
```

with:

```cmake
# net_policy_control_cxxbridge, net_policy_events_cxxbridge, net_flow_engine_cxxbridge,
# http1_codec_cxxbridge, net_policy_engine_cxxbridge, net_iptables_cxxbridge, net_nfq_cxxbridge, and
# net_conntrack_cxxbridge are separate Rust staticlib crates that all depend on the `cxx` crate; since each
```

For `net_rule_grpc_test`'s comment, replace:

```cmake
# See the matching comment on net-rule's LINK_FLAGS above (applies to
# net_policy_control_cxxbridge, net_policy_events_cxxbridge, net_flow_engine_cxxbridge,
# net_policy_engine_cxxbridge, net_iptables_cxxbridge, net_nfq_cxxbridge, and net_conntrack_cxxbridge).
```

with:

```cmake
# See the matching comment on net-rule's LINK_FLAGS above (applies to
# net_policy_control_cxxbridge, net_policy_events_cxxbridge, net_flow_engine_cxxbridge,
# http1_codec_cxxbridge, net_policy_engine_cxxbridge, net_iptables_cxxbridge, net_nfq_cxxbridge,
# and net_conntrack_cxxbridge).
```

- [ ] **Step 6: Add the smoke test to `net_rule_grpc_test`'s `SOURCES`**

In `CMakeLists.txt`, replace:

```cmake
    tests/net_flow_engine_ffi_test.cc
    tests/net_policy_engine_ffi_test.cc
```

with:

```cmake
    tests/net_flow_engine_ffi_test.cc
    tests/http1_codec_smoke_test.cc
    tests/net_policy_engine_ffi_test.cc
```

- [ ] **Step 7: Write the smoke test**

```cpp
#include <gtest/gtest.h>
#include "http1_codec_cxxbridge/lib.h"

TEST(Http1CodecSmokeTest, RustPingReturns42) {
  EXPECT_EQ(http1_codec::rust_ping(), 42);
}
```

- [ ] **Step 8: Build and run**

```bash
cargo check --workspace
cd build && cmake .. && make -j2 && cd ..
./build/net_rule_grpc_test --gtest_filter='Http1CodecSmokeTest.*'
```

Expected: build succeeds, `cargo check` succeeds, the smoke test passes.

- [ ] **Step 9: Commit**

```bash
git add crates/http1_codec Cargo.toml Cargo.lock CMakeLists.txt tests/http1_codec_smoke_test.cc
git commit -m "Scaffold the http1_codec Rust crate

Adds crates/http1_codec (empty except a rust_ping() smoke test, mirroring
ffi_smoke's shape), wires it into the Cargo workspace and CMakeLists.txt's
three C++ targets, and adds a trivial C++ FFI test proving the cxx bridge
plumbing works. No parsing logic yet -- later tasks build the real crate
on top of this scaffold."
```

---

### Task 2: Rust request-target parsing (`request_target` module)

**Files:**
- Create: `crates/http1_codec/src/request_target.rs`
- Modify: `crates/http1_codec/src/lib.rs`

**Interfaces:**
- Produces: `pub struct RequestTarget { pub host: String, pub path: String }` and `pub fn parse_request_target(target: &str) -> RequestTarget`, both `pub(crate)`-visible from `lib.rs` via `mod request_target;`. Task 3 calls `parse_request_target` directly.

This task is pure Rust logic with no `cxx` exposure — fully unit-testable in isolation.

- [ ] **Step 1: Write the failing tests**

Create `crates/http1_codec/src/request_target.rs` with just the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_form_extracts_host_and_strips_port_and_query() {
        let t = parse_request_target("https://1.2.3.4:8888/internal/platform/waf/service?cluster=123");
        assert_eq!(t.host, "1.2.3.4");
        assert_eq!(t.path, "/internal/platform/waf/service");
    }

    #[test]
    fn absolute_form_http_scheme_also_recognized() {
        let t = parse_request_target("http://example.com/foo");
        assert_eq!(t.host, "example.com");
        assert_eq!(t.path, "/foo");
    }

    #[test]
    fn absolute_form_without_port_extracts_host() {
        let t = parse_request_target("https://example.com/foo");
        assert_eq!(t.host, "example.com");
        assert_eq!(t.path, "/foo");
    }

    #[test]
    fn origin_form_has_empty_host_and_strips_query() {
        let t = parse_request_target("/internal/platform/waf/service?cluster=123");
        assert_eq!(t.host, "");
        assert_eq!(t.path, "/internal/platform/waf/service");
    }

    #[test]
    fn origin_form_no_query() {
        let t = parse_request_target("/foo/bar");
        assert_eq!(t.host, "");
        assert_eq!(t.path, "/foo/bar");
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd crates/http1_codec && cargo test request_target
```

Expected: FAIL — `parse_request_target` and `RequestTarget` are not defined yet.

- [ ] **Step 3: Implement `parse_request_target`**

Add above the test module in `crates/http1_codec/src/request_target.rs`:

```rust
/// A parsed HTTP/1.x request-target, per RFC 7230 §5.3. Only origin-form
/// (`/path`) and absolute-form (`scheme://host[:port]/path`) produce a
/// non-empty `host` -- the only two forms `http/url.cc`'s `Url::initialize`
/// (what this replaces) ever did. Authority-form (bare `host:port`, used
/// only by CONNECT) and asterisk-form (`*`, used only by OPTIONS) are not
/// exercised by any existing test or caller; they fall through to the
/// origin-form branch below (empty host), matching what an unrecognized
/// target produced in the old code path.
pub struct RequestTarget {
    pub host: String,
    pub path: String,
}

pub fn parse_request_target(target: &str) -> RequestTarget {
    if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let host = authority.split(':').next().unwrap_or("").to_string();
        let path_and_query = &rest[authority_end..];
        let path = path_and_query.split('?').next().unwrap_or("").to_string();
        RequestTarget { host, path }
    } else {
        let path = target.split('?').next().unwrap_or("").to_string();
        RequestTarget { host: String::new(), path }
    }
}
```

- [ ] **Step 4: Wire the module into `lib.rs`**

In `crates/http1_codec/src/lib.rs`, add near the top (before the `#[cxx::bridge...]` block):

```rust
mod request_target;
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd crates/http1_codec && cargo test request_target
```

Expected: all 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/http1_codec/src/request_target.rs crates/http1_codec/src/lib.rs
git commit -m "Add Rust request-target parsing for http1_codec

parse_request_target splits an HTTP/1.x request-target into host/path,
handling absolute-form (scheme://host:port/path) and origin-form (/path)
exactly as http/url.cc's Url::initialize did for the same two forms --
reimplemented natively rather than calling back into C++."
```

---

### Task 3: Rust header/request-line parsing (`header_parser` module)

**Files:**
- Create: `crates/http1_codec/src/header_parser.rs`
- Modify: `crates/http1_codec/src/lib.rs`

**Interfaces:**
- Consumes: `request_target::parse_request_target` (Task 2).
- Produces:
  ```rust
  pub struct HeaderParseResult {
      pub method: String,
      pub path: String,
      pub host: String,
      pub fields: Vec<(String, String)>,
      pub content_length: Option<usize>,
      pub chunked: bool,
      pub consumed: usize,
  }
  pub fn try_parse_headers(buf: &[u8]) -> Result<Option<HeaderParseResult>, ()>
  ```
  `Ok(None)` means "need more data" (httparse `Status::Partial`); `Err(())` means malformed input. Task 5 calls this directly.

- [ ] **Step 1: Write the failing tests**

Create `crates/http1_codec/src/header_parser.rs` with the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_input_returns_none() {
        let buf = b"GET / HTTP/1.1\r\nHost: example";
        assert!(try_parse_headers(buf).unwrap().is_none());
    }

    #[test]
    fn origin_form_with_host_header() {
        let buf = b"PUT /internal/platform/waf/service?cluster=123 HTTP/1.1\r\nHost: abc.com:9090\r\nContent-Type: application/json\r\nContent-Length: 39\r\n\r\n";
        let result = try_parse_headers(buf).unwrap().unwrap();
        assert_eq!(result.method, "PUT");
        assert_eq!(result.path, "/internal/platform/waf/service");
        assert_eq!(result.host, "abc.com");
        assert_eq!(result.content_length, Some(39));
        assert!(!result.chunked);
        assert_eq!(result.consumed, buf.len());
        let host_field = result.fields.iter().find(|(n, _)| n.eq_ignore_ascii_case("host"));
        assert_eq!(host_field.map(|(_, v)| v.as_str()), Some("abc.com:9090"));
    }

    #[test]
    fn absolute_form_host_wins_over_host_header() {
        let buf = b"GET https://1.2.3.4:8888/foo HTTP/1.1\r\nHost: other.example.com\r\n\r\n";
        let result = try_parse_headers(buf).unwrap().unwrap();
        assert_eq!(result.host, "1.2.3.4");
        assert_eq!(result.path, "/foo");
    }

    #[test]
    fn origin_form_no_host_header_yields_empty_host() {
        let buf = b"GET /foo HTTP/1.1\r\n\r\n";
        let result = try_parse_headers(buf).unwrap().unwrap();
        assert_eq!(result.host, "");
    }

    #[test]
    fn host_header_without_port_is_not_truncated() {
        let buf = b"GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = try_parse_headers(buf).unwrap().unwrap();
        assert_eq!(result.host, "example.com");
    }

    #[test]
    fn chunked_transfer_encoding_detected() {
        let buf = b"POST /foo HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        let result = try_parse_headers(buf).unwrap().unwrap();
        assert!(result.chunked);
        assert_eq!(result.content_length, None);
    }

    #[test]
    fn malformed_request_line_is_an_error() {
        let buf = b"NOT A REQUEST\r\n\r\n";
        assert!(try_parse_headers(buf).is_err());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd crates/http1_codec && cargo test header_parser
```

Expected: FAIL to compile — `try_parse_headers`/`HeaderParseResult` not defined.

- [ ] **Step 3: Implement `try_parse_headers`**

Add above the test module in `crates/http1_codec/src/header_parser.rs`:

```rust
use crate::request_target::parse_request_target;

const MAX_HEADERS: usize = 64;

pub struct HeaderParseResult {
    pub method: String,
    pub path: String,
    pub host: String,
    pub fields: Vec<(String, String)>,
    pub content_length: Option<usize>,
    pub chunked: bool,
    pub consumed: usize,
}

/// Attempts to parse one complete HTTP/1.x request-line + header block from
/// the start of `buf`. `Ok(None)` means the buffer holds a valid prefix of a
/// request but not yet a complete header block (caller should wait for more
/// data via a later call). `Err(())` means the input is malformed --
/// includes both genuinely invalid syntax and MAX_HEADERS being exceeded
/// (httparse's `TooManyHeaders`); the caller does not need to distinguish
/// these since neither is recoverable, mirroring llhttp's own behavior for
/// unrecoverable parse errors (no reset-and-retry exists in the old code
/// either).
pub fn try_parse_headers(buf: &[u8]) -> Result<Option<HeaderParseResult>, ()> {
    let mut raw_headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut raw_headers);
    let consumed = match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(_) => return Err(()),
    };

    let method = req.method.unwrap_or("").to_string();
    let raw_target = req.path.unwrap_or("");
    let target = parse_request_target(raw_target);

    let mut fields = Vec::with_capacity(req.headers.len());
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for h in req.headers.iter() {
        let name = h.name.to_string();
        let value = String::from_utf8_lossy(h.value).into_owned();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") && value.trim().eq_ignore_ascii_case("chunked") {
            chunked = true;
        }
        fields.push((name, value));
    }

    let host = resolve_host(&target.host, &fields);

    Ok(Some(HeaderParseResult {
        method,
        path: target.path,
        host,
        fields,
        content_length,
        chunked,
        consumed,
    }))
}

/// Mirrors http/http1/codec.cc's exact host-resolution priority: an
/// absolute-form request-target's host always wins (`target_host` is
/// already non-empty only in that case -- see request_target.rs); otherwise
/// fall back to the Host header with a trailing `:port` stripped by finding
/// the LAST `:` in the value, matching the old code's
/// `host_.find_last_of(":")` exactly, including its non-awareness of IPv6
/// literal hosts in brackets (not fixed here, same limitation as before).
fn resolve_host(target_host: &str, fields: &[(String, String)]) -> String {
    if !target_host.is_empty() {
        return target_host.to_string();
    }
    for (name, value) in fields {
        if name.eq_ignore_ascii_case("host") {
            return match value.rfind(':') {
                Some(idx) => value[..idx].to_string(),
                None => value.clone(),
            };
        }
    }
    String::new()
}
```

- [ ] **Step 4: Wire the module into `lib.rs`**

In `crates/http1_codec/src/lib.rs`, replace:

```rust
mod request_target;
```

with:

```rust
mod header_parser;
mod request_target;
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd crates/http1_codec && cargo test header_parser
```

Expected: all 7 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/http1_codec/src/header_parser.rs crates/http1_codec/src/lib.rs
git commit -m "Add Rust header/request-line parsing for http1_codec

try_parse_headers wraps httparse for incremental request-line + header
parsing, extracts Content-Length/chunked Transfer-Encoding for the next
task's body-framing state machine, and resolves the request's host with
the exact priority order verified against the current C++ behavior:
absolute-form request-target wins over the Host header; origin-form falls
back to a port-stripped Host header value."
```

---

### Task 4: Rust body-framing state machine (`body_framing` module)

> **Post-implementation correction (found by this task's own reviewer, before Task 5 was built on top of it):** the original version of this task's `advance()` had two real bugs, not just style nits — an unparseable chunk-size line silently defaulted to `0` (treated as the end-of-body terminator, silently truncating a body early instead of rejecting it), and chunk-data not immediately followed by `\r\n` caused `advance()` to return `(pos, false)` forever with no error signal and no further progress — since nothing ever drains past the stuck point, this is an unbounded buffer-growth / memory-exhaustion vector on a single malformed connection, not just a parsing nicety. `advance()`'s signature is corrected below to `Result<(usize, bool), ()>`, matching `header_parser::try_parse_headers`'s existing `Result<Option<_>, ()>` shape. If you are executing this task fresh (not fixing an already-landed Task 4), just follow the steps below as written — they already reflect the correction.

**Files:**
- Create: `crates/http1_codec/src/body_framing.rs`
- Modify: `crates/http1_codec/src/lib.rs`

**Interfaces:**
- Produces:
  ```rust
  pub enum BodyFraming { None, ContentLength(usize), ChunkedSize, ChunkedData(usize), ChunkedTrailer }
  impl BodyFraming {
      pub fn start(content_length: Option<usize>, chunked: bool) -> BodyFraming;
      pub fn advance(&mut self, buf: &[u8]) -> Result<(usize, bool), ()>; // Ok((bytes_consumed, framing_complete)); Err(()) on malformed chunked input
  }
  ```
  Task 5 constructs a `BodyFraming` via `start()` right after a header parse completes, then calls `advance()` repeatedly as more data arrives (or immediately, if the whole body is already in the buffer) until it returns `Ok((_, true))` for completion or `Err(())` for malformed input (mapped to `ParseState::Error`, the same way a header-parse error already is).

- [ ] **Step 1: Write the failing tests**

Create `crates/http1_codec/src/body_framing.rs` with the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_body_completes_immediately_consuming_nothing() {
        let mut f = BodyFraming::start(None, false);
        let (consumed, done) = f.advance(b"GET /next HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(consumed, 0);
        assert!(done);
    }

    #[test]
    fn zero_content_length_completes_immediately() {
        let mut f = BodyFraming::start(Some(0), false);
        let (consumed, done) = f.advance(b"").unwrap();
        assert_eq!(consumed, 0);
        assert!(done);
    }

    #[test]
    fn content_length_consumes_exactly_that_many_bytes() {
        let mut f = BodyFraming::start(Some(5), false);
        let (consumed, done) = f.advance(b"12345restofbuffer").unwrap();
        assert_eq!(consumed, 5);
        assert!(done);
    }

    #[test]
    fn content_length_needs_more_data_across_calls() {
        let mut f = BodyFraming::start(Some(10), false);
        let (consumed1, done1) = f.advance(b"12345").unwrap();
        assert_eq!(consumed1, 5);
        assert!(!done1);
        let (consumed2, done2) = f.advance(b"67890").unwrap();
        assert_eq!(consumed2, 5);
        assert!(done2);
    }

    #[test]
    fn chunked_single_chunk_then_terminator() {
        let mut f = BodyFraming::start(None, true);
        let buf = b"5\r\nhello\r\n0\r\n\r\n";
        let (consumed, done) = f.advance(buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert!(done);
    }

    #[test]
    fn chunked_multiple_chunks_with_different_sizes() {
        // Deliberately DIFFERENT chunk sizes (3, then 4) -- proves each
        // chunk's size is read from its own size line, not e.g. reused from
        // the first chunk (which a same-sized-chunks test couldn't catch).
        let mut f = BodyFraming::start(None, true);
        let buf = b"3\r\nfoo\r\n4\r\nbarz\r\n0\r\n\r\n";
        let (consumed, done) = f.advance(buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert!(done);
    }

    #[test]
    fn chunked_needs_more_data_mid_chunk() {
        let mut f = BodyFraming::start(None, true);
        let (consumed1, done1) = f.advance(b"5\r\nhel").unwrap();
        assert_eq!(consumed1, 6); // consumed the size line "5\r\n", 3 of the 5 data bytes
        assert!(!done1);
        let (consumed2, done2) = f.advance(b"lo\r\n0\r\n\r\n").unwrap();
        assert_eq!(consumed2, 9);
        assert!(done2);
    }

    #[test]
    fn chunked_with_trailer_headers() {
        let mut f = BodyFraming::start(None, true);
        let buf = b"0\r\nX-Trailer: value\r\n\r\n";
        let (consumed, done) = f.advance(buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert!(done);
    }

    #[test]
    fn malformed_chunk_size_line_is_an_error() {
        let mut f = BodyFraming::start(None, true);
        assert!(f.advance(b"not-hex\r\nfoo").is_err());
    }

    #[test]
    fn chunk_data_not_immediately_followed_by_crlf_is_an_error() {
        let mut f = BodyFraming::start(None, true);
        // Declares 3 data bytes ("foo") but is followed by "XX" instead of
        // an immediate CRLF -- a chunked-grammar violation, not merely
        // "need more data" (the eventual "\r\n" later in the buffer must
        // not be treated as satisfying the immediate-CRLF requirement).
        assert!(f.advance(b"3\r\nfooXX\r\n0\r\n\r\n").is_err());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd crates/http1_codec && cargo test body_framing
```

Expected: FAIL to compile — `BodyFraming` not defined.

- [ ] **Step 3: Implement `BodyFraming`**

Add above the test module in `crates/http1_codec/src/body_framing.rs`:

```rust
/// Tracks where a request's body ends, WITHOUT storing or exposing any of
/// its bytes -- this daemon's only consumer of parsed HTTP (microsegmentation
/// policy matching) needs correct framing so pipelined requests parse
/// correctly, not body content. See the design spec for why body content
/// isn't exposed.
pub enum BodyFraming {
    None,
    ContentLength(usize),
    ChunkedSize,
    ChunkedData(usize),
    ChunkedTrailer,
}

impl BodyFraming {
    pub fn start(content_length: Option<usize>, chunked: bool) -> BodyFraming {
        if chunked {
            BodyFraming::ChunkedSize
        } else {
            match content_length {
                Some(0) | None => BodyFraming::None,
                Some(n) => BodyFraming::ContentLength(n),
            }
        }
    }

    /// Consumes as much of `buf` as belongs to the body (advancing internal
    /// state), returning `Ok((bytes_consumed, framing_complete))`. When
    /// `framing_complete` is false, the caller must call `advance` again
    /// with more data (starting from byte `bytes_consumed` onward -- the
    /// caller is expected to drain consumed bytes from its own buffer, as
    /// Task 5's `Http1Parser` does). Returns `Err(())` for malformed
    /// chunked-encoding input -- an unparseable chunk-size line, or
    /// chunk-data not immediately followed by CRLF -- rather than silently
    /// misframing (an earlier version of this code treated an unparseable
    /// size as the zero-size terminator, silently truncating a body early)
    /// or stalling forever with no forward progress and no error signal
    /// (an unbounded buffer-growth / memory-exhaustion vector on a single
    /// malformed connection, since nothing ever drains past the stuck
    /// point).
    pub fn advance(&mut self, buf: &[u8]) -> Result<(usize, bool), ()> {
        match self {
            BodyFraming::None => Ok((0, true)),
            BodyFraming::ContentLength(remaining) => {
                let take = (*remaining).min(buf.len());
                *remaining -= take;
                Ok((take, *remaining == 0))
            }
            BodyFraming::ChunkedSize | BodyFraming::ChunkedData(_) | BodyFraming::ChunkedTrailer => {
                self.advance_chunked(buf)
            }
        }
    }

    fn advance_chunked(&mut self, buf: &[u8]) -> Result<(usize, bool), ()> {
        let mut pos = 0;
        loop {
            match self {
                BodyFraming::ChunkedSize => match find_crlf(&buf[pos..]) {
                    None => return Ok((pos, false)),
                    Some(line_len) => {
                        let line = &buf[pos..pos + line_len];
                        let hex_part = line.split(|&b| b == b';').next().unwrap_or(line);
                        let size = match std::str::from_utf8(hex_part)
                            .ok()
                            .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
                        {
                            Some(size) => size,
                            None => return Err(()),
                        };
                        pos += line_len + 2;
                        *self = if size == 0 { BodyFraming::ChunkedTrailer } else { BodyFraming::ChunkedData(size) };
                    }
                },
                BodyFraming::ChunkedData(remaining) => {
                    let available = buf.len() - pos;
                    let take = (*remaining).min(available);
                    pos += take;
                    *remaining -= take;
                    if *remaining > 0 {
                        return Ok((pos, false));
                    }
                    // Deliberately NOT using find_crlf here: it searches for
                    // a CRLF ANYWHERE later in the buffer, but the grammar
                    // requires the CRLF to be the IMMEDIATE next two bytes.
                    // Treating a later, unrelated CRLF as satisfying this
                    // check was the exact bug being fixed.
                    let tail = &buf[pos..];
                    if tail.len() < 2 {
                        return Ok((pos, false)); // not enough bytes yet to check
                    }
                    if &tail[..2] != b"\r\n" {
                        return Err(());
                    }
                    pos += 2;
                    *self = BodyFraming::ChunkedSize;
                }
                BodyFraming::ChunkedTrailer => match find_crlf(&buf[pos..]) {
                    None => return Ok((pos, false)),
                    Some(0) => {
                        pos += 2;
                        return Ok((pos, true));
                    }
                    Some(line_len) => {
                        pos += line_len + 2;
                    }
                },
                BodyFraming::None | BodyFraming::ContentLength(_) => unreachable!(),
            }
        }
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}
```

- [ ] **Step 4: Wire the module into `lib.rs`**

In `crates/http1_codec/src/lib.rs`, replace:

```rust
mod header_parser;
mod request_target;
```

with:

```rust
mod body_framing;
mod header_parser;
mod request_target;
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd crates/http1_codec && cargo test body_framing
```

Expected: all 10 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/http1_codec/src/body_framing.rs crates/http1_codec/src/lib.rs
git commit -m "Add Rust body-framing state machine for http1_codec

BodyFraming tracks Content-Length countdown and chunked Transfer-Encoding
chunk boundaries (including trailer headers) to correctly locate where one
pipelined request's body ends and the next request begins -- without
storing or exposing any body bytes, since nothing downstream consumes them."
```

---

### Task 5: The `Http1Parser` cxx-bridged type and `dispatch()`

**Files:**
- Modify: `crates/http1_codec/src/lib.rs`
- Modify: `tests/http1_codec_smoke_test.cc` → will be superseded; see Step 7

**Interfaces:**
- Consumes: `header_parser::try_parse_headers` (Task 3), `body_framing::BodyFraming` (Task 4) — note `BodyFraming::advance()` returns `Result<(usize, bool), ()>` (corrected after Task 4's own review found two real bugs in the original `(usize, bool)` shape; see Task 4's header note), so `dispatch()`'s body-phase branch below handles both the `Ok` and `Err` arms.
- Produces the real `cxx` bridge, replacing the Task 1 smoke-test bridge entirely:
  ```rust
  #[cxx::bridge(namespace = "http1_codec")]
  mod ffi {
      struct HeaderField { name: String, value: String }
      struct ParsedHeader {
          method: String, path: String, host: String,
          fields: Vec<HeaderField>,
          parse_state: i32, // 0 = Continue, 1 = Done, 2 = Error
      }
      extern "Rust" {
          type Http1Parser;
          fn new_http1_parser() -> Box<Http1Parser>;
          fn dispatch(self: &mut Http1Parser, data: &[u8]) -> ParsedHeader;
      }
  }
  ```
  Task 6's C++ adapter is the consumer.

- [ ] **Step 1: Write the failing tests**

Add a test module to `crates/http1_codec/src/lib.rs` (after the `ffi` module and its supporting code, written in the next step):

```rust
#[cfg(test)]
mod integration_tests {
    use super::Http1Parser;

    const DONE: i32 = 1;
    const CONTINUE: i32 = 0;

    #[test]
    fn incremental_across_two_calls_matches_existing_cpp_test() {
        let mut p = Http1Parser::new();
        let r1 = p.dispatch(b"POST https://1.2.3.4:8888/internal/platform/waf/");
        assert_eq!(r1.parse_state, CONTINUE);
        assert_eq!(r1.method, "");
        assert_eq!(r1.path, "");
        assert_eq!(r1.host, "");

        let r2 = p.dispatch(b"service?cluster=123 HTTP/1.1\r\ncontent-length: 3\r\n\r\n123");
        assert_eq!(r2.parse_state, DONE);
        assert_eq!(r2.method, "POST");
        assert_eq!(r2.path, "/internal/platform/waf/service");
        assert_eq!(r2.host, "1.2.3.4");
    }

    #[test]
    fn single_call_matches_existing_cpp_test_dispatch1() {
        let mut p = Http1Parser::new();
        let put = b"PUT /internal/platform/waf/service?cluster=123 HTTP/1.1\r\nHost: abc.com:9090\r\nContent-Type: application/json\r\nContent-Length: 39\r\n\r\n{\n  \"id\": 94,\n\"name\": \"x\"\n}";
        let r = p.dispatch(put);
        assert_eq!(r.parse_state, DONE);
        assert_eq!(r.host, "abc.com");
        assert_eq!(r.path, "/internal/platform/waf/service");
    }

    #[test]
    fn pipelined_requests_in_one_call_returns_only_the_last() {
        let mut p = Http1Parser::new();
        let buf = b"GET /first HTTP/1.1\r\n\r\nGET /second HTTP/1.1\r\n\r\n";
        let r = p.dispatch(buf);
        assert_eq!(r.parse_state, DONE);
        assert_eq!(r.path, "/second");
    }

    #[test]
    fn chunked_body_does_not_corrupt_next_pipelined_request() {
        let mut p = Http1Parser::new();
        let buf = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n0\r\n\r\nGET /next HTTP/1.1\r\n\r\n";
        let r = p.dispatch(buf);
        assert_eq!(r.parse_state, DONE);
        assert_eq!(r.path, "/next");
    }

    #[test]
    fn error_on_malformed_input() {
        let mut p = Http1Parser::new();
        let r = p.dispatch(b"NOT A REQUEST\r\n\r\n");
        assert_eq!(r.parse_state, 2 /* Error */);
    }

    #[test]
    fn error_on_malformed_chunked_body() {
        let mut p = Http1Parser::new();
        // Headers parse fine; the chunked body that follows violates the
        // chunked grammar (chunk-data not immediately followed by CRLF) --
        // this must surface as Error through the full dispatch() path, not
        // just at the body_framing unit-test level.
        let buf = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfooXX\r\n0\r\n\r\n";
        let r = p.dispatch(buf);
        assert_eq!(r.parse_state, 2 /* Error */);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd crates/http1_codec && cargo test integration_tests
```

Expected: FAIL to compile — `Http1Parser::new()`/`dispatch()` not defined with this shape yet (Task 1's placeholder `rust_ping` bridge is still in place).

- [ ] **Step 3: Replace the placeholder bridge with the real one**

In `crates/http1_codec/src/lib.rs`, replace the entire Task-1 placeholder content:

```rust
#[cxx::bridge(namespace = "http1_codec")]
mod ffi {
    extern "Rust" {
        fn rust_ping() -> i32;
    }
}

fn rust_ping() -> i32 {
    42
}
```

with:

```rust
mod body_framing;
mod header_parser;
mod request_target;

use body_framing::BodyFraming;

#[cxx::bridge(namespace = "http1_codec")]
mod ffi {
    #[derive(Default)]
    struct HeaderField {
        name: String,
        value: String,
    }

    #[derive(Default)]
    struct ParsedHeader {
        method: String,
        path: String,
        host: String,
        fields: Vec<HeaderField>,
        /// 0 = Continue (need more data to complete a message), 1 = Done
        /// (a message's headers just completed in this call), 2 = Error --
        /// mirrors http::ParseState's three variants exactly.
        parse_state: i32,
    }

    extern "Rust" {
        type Http1Parser;

        fn new_http1_parser() -> Box<Http1Parser>;
        fn dispatch(self: &mut Http1Parser, data: &[u8]) -> ParsedHeader;
    }
}

const PARSE_STATE_CONTINUE: i32 = 0;
const PARSE_STATE_DONE: i32 = 1;
const PARSE_STATE_ERROR: i32 = 2;

enum Phase {
    Headers,
    Body(BodyFraming),
}

pub struct Http1Parser {
    buf: Vec<u8>,
    phase: Phase,
}

fn new_http1_parser() -> Box<Http1Parser> {
    Box::new(Http1Parser::new())
}

impl Http1Parser {
    pub fn new() -> Self {
        Http1Parser { buf: Vec::new(), phase: Phase::Headers }
    }

    /// Feeds `data` in, advancing internal state. Accumulates across calls
    /// (TCP segments arrive in arbitrary chunks) -- mirrors llhttp_t's
    /// persistent-parser-state contract, reimplemented on top of httparse's
    /// one-shot-per-call API by re-parsing the accumulated buffer.
    ///
    /// If this single call's data contains more than one complete pipelined
    /// request, only the LAST one's parsed header is returned -- earlier
    /// ones in the same call are not surfaced. This matches the old
    /// llhttp-based C++ wrapper's behavior exactly (its `header_` member got
    /// overwritten on each new message within one `dispatch()` call; not
    /// something this migration fixes, see the design spec).
    ///
    /// A `Continue`-state result never carries forward a PRIOR call's
    /// completed header data (unlike the old C++, which left `header_`'s
    /// fields at whatever they last held). This is an intentional,
    /// behavior-preserving simplification: the only real caller
    /// (`net::ConnectionManager::DispatchMicroseg`) only reads `Header`'s
    /// fields when `parseState_ == Done`, discarding the result entirely
    /// otherwise -- so whether a discarded result carries stale data or
    /// fresh defaults is unobservable to every actual caller.
    pub fn dispatch(&mut self, data: &[u8]) -> ffi::ParsedHeader {
        self.buf.extend_from_slice(data);
        let mut result: Option<ffi::ParsedHeader> = None;

        loop {
            match &mut self.phase {
                Phase::Headers => match header_parser::try_parse_headers(&self.buf) {
                    Err(()) => {
                        return ffi::ParsedHeader { parse_state: PARSE_STATE_ERROR, ..Default::default() };
                    }
                    Ok(None) => break,
                    Ok(Some(parsed)) => {
                        let consumed = parsed.consumed;
                        let framing = BodyFraming::start(parsed.content_length, parsed.chunked);
                        result = Some(ffi::ParsedHeader {
                            method: parsed.method,
                            path: parsed.path,
                            host: parsed.host,
                            fields: parsed
                                .fields
                                .into_iter()
                                .map(|(name, value)| ffi::HeaderField { name, value })
                                .collect(),
                            parse_state: PARSE_STATE_DONE,
                        });
                        self.buf.drain(..consumed);
                        self.phase = Phase::Body(framing);
                    }
                },
                Phase::Body(framing) => match framing.advance(&self.buf) {
                    Err(()) => {
                        return ffi::ParsedHeader { parse_state: PARSE_STATE_ERROR, ..Default::default() };
                    }
                    Ok((consumed, complete)) => {
                        self.buf.drain(..consumed);
                        if !complete {
                            break;
                        }
                        self.phase = Phase::Headers;
                    }
                },
            }
        }

        result.unwrap_or_else(|| ffi::ParsedHeader { parse_state: PARSE_STATE_CONTINUE, ..Default::default() })
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd crates/http1_codec && cargo test
```

Expected: all tests across `request_target`, `header_parser`, `body_framing`, and `integration_tests` PASS.

- [ ] **Step 5: Update the smoke test file to match the new bridge**

`tests/http1_codec_smoke_test.cc` (from Task 1) references `http1_codec::rust_ping()`, which no longer exists. Replace its entire content:

```cpp
#include <gtest/gtest.h>
#include "http1_codec_cxxbridge/lib.h"

TEST(Http1CodecSmokeTest, RustPingReturns42) {
  EXPECT_EQ(http1_codec::rust_ping(), 42);
}
```

with:

```cpp
#include <gtest/gtest.h>
#include "http1_codec_cxxbridge/lib.h"

TEST(Http1CodecSmokeTest, ParserConstructsAndDispatchesOneRequest) {
  auto parser = http1_codec::new_http1_parser();
  auto result = parser->dispatch(rust::Slice<const uint8_t>(
      reinterpret_cast<const uint8_t*>("GET /foo HTTP/1.1\r\n\r\n"), 22));
  EXPECT_EQ(result.parse_state, 1);
  EXPECT_EQ(std::string(result.method), "GET");
  EXPECT_EQ(std::string(result.path), "/foo");
}
```

- [ ] **Step 6: Build and run the smoke test**

```bash
cd build && make -j2 && cd ..
./build/net_rule_grpc_test --gtest_filter='Http1CodecSmokeTest.*'
```

Expected: build succeeds, test passes.

- [ ] **Step 7: Commit**

```bash
git add crates/http1_codec/src/lib.rs tests/http1_codec_smoke_test.cc
git commit -m "Add the Http1Parser cxx-bridged type and dispatch()

Combines header_parser and body_framing into the real cxx bridge --
ParsedHeader (method/path/host/fields/parse_state) crosses the FFI
boundary as owned data. dispatch() accumulates bytes across calls
(httparse has no persistent parser state, unlike llhttp_t) and preserves
the old wrapper's last-message-wins-within-one-call behavior for pipelined
requests. Updates the smoke test to exercise the real bridge instead of
the placeholder rust_ping()."
```

---

### Task 6: Rewrite `http/http1/codec.h`/`codec.cc` as the C++ adapter

**Files:**
- Modify: `http/http1/codec.h`
- Modify: `http/http1/codec.cc`

**Interfaces:**
- Consumes: `http1_codec::new_http1_parser()`/`Http1Parser::dispatch()` (Task 5), via `#include "http1_codec_cxxbridge/lib.h"`.
- Produces: `http::http1::ConnectionImpl` — same class name, same namespace, same public interface (`dispatch(string_view)`, `dispatch(packet)`, `addFilter`, `setFilterManager`, `getHost()`, constructor signature) as before, so `http/connection.cc`'s `createCodec` needs zero changes and `tests/codec_test.cc`'s two existing tests need zero changes.

This is a direct rewrite in place, not a new file — `http/connection.cc:50`'s `codec_ = std::make_unique<http1::ConnectionImpl>(server_side_, filters_manager_);` call site is unaffected by this task.

- [ ] **Step 1: Rewrite `http/http1/codec.h`**

Replace the entire file content:

```cpp
#pragma once

#include "http/codec.h"
#include "http/connection.h"
#include "http/filter.h"
#include "http/header.h"
#include "llhttp.h"

// #include "http/http1/http_parser.h"
#include <string>
#include <string_view>
#include <vector>

namespace http {
namespace http1 {
class ConnectionImpl : public Codec {
public:
  ConnectionImpl(bool serverSide, HttpFilterManagerPtr filterManager);

  ~ConnectionImpl();

  const Header &dispatch(std::string_view data) override;

  const FilterStatus dispatch(seastar::net::packet data) override;

  void addFilter(HttpFilterPtr filter) override;

  void setFilterManager(HttpFilterManagerPtr filterManager) override;

  inline void setPath(std::string_view path) { header_.path_ = path; }

  inline void setHost(std::string_view host) { header_.host_ = host; }

  inline void setMethod(std::string_view method) { header_.method_ = method; }

  inline std::string_view getHost() const { return host_; }

  void onUrl(std::string_view url);

  void onUrlComplete();

  void onHeadersComplete();

  int onBodyComplete(std::string_view body);

  void onHeaderField(std::string field) {
    header_fields_.push_back(field);
  };

  void resetState() {
    url_.clear();
    header_ = {"", "", "", ParseState::Continue};
    header_fields_.clear();
    header_values_.clear();
    headerMap_.clear();
  }

  void onHeaderValue(std::string value) {
    header_values_.push_back(value);
  };

private:
  // http_parser parser_;
  // http_parser_settings settings_;
  llhttp_t parser_;
  llhttp_settings_t settings_;
  // http_parser_settings settings_;
  Header header_;
  std::string url_;
  std::string_view host_;
  std::vector<std::string> header_fields_;
  std::vector<std::string> header_values_;
  HttpFilterManagerPtr filters_manager_;
  RequestHeaderMap headerMap_;
  bool serverSide_;
  FilterStatus status_;
};
} // namespace http1
} // namespace http
```

with:

```cpp
#pragma once

#include "http/codec.h"
#include "http/connection.h"
#include "http/filter.h"
#include "http/header.h"
#include "http1_codec_cxxbridge/lib.h"
#include "rust/cxx.h"

#include <memory>
#include <string>
#include <string_view>

namespace http {
namespace http1 {

// Thin C++ adapter over crates/http1_codec's Rust parser. Keeps the exact
// class name, namespace, constructor signature, and public interface the
// old llhttp-based implementation had, so http/connection.cc's createCodec
// call site and tests/codec_test.cc's existing tests need no changes --
// see docs/superpowers/plans/2026-08-06-phase3a-http1-codec.md Task 6.
class ConnectionImpl : public Codec {
public:
  ConnectionImpl(bool serverSide, HttpFilterManagerPtr filterManager);

  ~ConnectionImpl();

  const Header &dispatch(std::string_view data) override;

  const FilterStatus dispatch(seastar::net::packet data) override;

  void addFilter(HttpFilterPtr filter) override;

  void setFilterManager(HttpFilterManagerPtr filterManager) override;

  // Returns the raw (port-included) value of the most recently seen Host
  // header, or empty if none was seen -- mirrors the old private host_
  // member exactly, including that it's distinct from header_.host_'s
  // resolved-and-possibly-port-stripped value. Has no production caller
  // (see the design spec); kept only so tests/codec_test.cc's existing
  // Dispatch1 test needs no changes.
  std::string getHost() const { return raw_host_header_; }

private:
  const Header &applyParsedHeader(const http1_codec::ParsedHeader &parsed);

  rust::Box<http1_codec::Http1Parser> parser_;
  Header header_;
  std::string raw_host_header_;
  HttpFilterManagerPtr filters_manager_;
  RequestHeaderMap headerMap_;
  bool serverSide_;
  FilterStatus status_;
};
} // namespace http1
} // namespace http
```

- [ ] **Step 2: Rewrite `http/http1/codec.cc`**

Replace the entire file content:

```cpp
#include "codec.h"

#include <cctype>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <memory>
#include <ostream>
#include <string_view>
#include <utility>

// #include "http/http1/http_parser.h"
#include "common/utility.h"
#include "glog/logging.h"
// #include "http/connection_manager.h"
#include "http/filter.h"
#include "llhttp.h"

#include "http/codec.h"
#include "http/url.hh"
#include "http/utility.h"

namespace http {
namespace http1 {
const Header& ConnectionImpl::dispatch(std::string_view data) {
  // auto ret =
  //     http_parser_execute(&parser_, &settings_, data.data(), data.length());
  // if (HTTP_PARSER_ERRNO(&parser_) != HPE_OK &&
  //     HTTP_PARSER_ERRNO(&parser_) != HPE_PAUSED) {
  //   std::cout << "parse err: " << HTTP_PARSER_ERRNO(&parser_) << std::endl;
  //   return Header{};
  // }
  auto ret = llhttp_execute(&parser_, data.data(), data.length());
  if (ret != HPE_OK && ret != HPE_PAUSED) {
    LOG(ERROR) << "parse err: " << llhttp_errno_name(ret);
    // std::cout << "parse err: " << llhttp_errno_name(ret) << std::endl;
    header_.parseState_ = ParseState::Error;
    return header_;
  }
  std::cout << "parsed bytes: " << ret << std::endl;
  return header_;
}

const FilterStatus ConnectionImpl::dispatch(seastar::net::packet pkt) {
  auto data = pkt.get_header(0, pkt.len());
  VLOG(8) << "dispatching " << pkt.len() << " bytes data";

  auto ret = llhttp_execute(&parser_, data, pkt.len());
  if (ret != HPE_OK && ret != HPE_PAUSED) {
    LOG(ERROR) << "parse err: " << llhttp_errno_name(ret);
    // std::cout << "parse err: " << llhttp_errno_name(ret) << std::endl;
    header_.parseState_ = ParseState::Error;
    return status_;
  }
  VLOG(4) << "parsed bytes: " << ret << " status: " << int(status_);
  return status_;
}

void ConnectionImpl::addFilter(HttpFilterPtr filter) { filters_manager_->addFilter(filter); }

void ConnectionImpl::setFilterManager(HttpFilterManagerPtr filterManager) {
  filters_manager_ = filterManager;
}

void ConnectionImpl::onUrl(std::string_view url) {
  url_.append(url);
  VLOG(6) << "url : " << url_ << std::endl;
}

void ConnectionImpl::onUrlComplete() {
  Url u;
  u.initialize(url_, false);
  setHost(u.host());
  setPath(u.path());
  VLOG(4) << "url complete: " << header_;
  // header_.completed = true;
}

void ConnectionImpl::onHeadersComplete() {
  if (header_fields_.size() != header_values_.size()) {
    return;
  }
  for (size_t i = 0; i < header_fields_.size(); i++) {
    if (header_fields_[i] == "Host" || header_fields_[i] == "host") {
      host_ = header_values_[i];
      if (header_.host_ == "") {
        auto n = host_.find_last_of(":");
        header_.host_ = host_.substr(0, n);
      }
    }

    headerMap_.add(utility::toLow(header_fields_[i]), utility::toLow(header_values_[i]));
  }

  headerMap_.add({":host"}, header_.host_);
  headerMap_.add({":method"}, header_.method_);
  headerMap_.add({":path"}, header_.path_);

  header_.parseState_ = ParseState::Done;
  status_ = filters_manager_->decodeHeaders(headerMap_, serverSide_);
}

int ConnectionImpl::onBodyComplete(std::string_view body) {
  auto p = seastar::net::packet::from_static_data(body.data(), body.length());
  status_ = filters_manager_->decodeBody(std::move(p), serverSide_);
  return 0;
}

ConnectionImpl::ConnectionImpl(bool serverSide, HttpFilterManagerPtr filterManager)
    : parser_(), settings_(), header_{"", "", "", ParseState::Continue}, url_(),
      filters_manager_(filterManager), serverSide_(serverSide) {

  // filters_manager_ = std::make_unique<HttpFilterManager>(serverSide);
  // http_parser_settings_init(&settings_);
  // settings_.on_url = [](http_parser *parser, const char *at,
  //                       size_t length) -> int {
  //   auto codec = reinterpret_cast<ConnectionImpl *>(parser->data);

  //   std::string_view url_str(at, length);
  //   codec->onUrl(url_str);
  //   auto method = http_method(parser->method);
  //   codec->setMethod(http_method_str(method));
  //   return 0;
  // };
  // http_parser_init(&parser_, HTTP_REQUEST);

  llhttp_settings_init(&settings_);
  settings_.on_message_begin = [](llhttp_t* parser) -> int {
    reinterpret_cast<ConnectionImpl*>(parser->data)->resetState();
    return 0;
  };
  settings_.on_method = [](llhttp_t* parser, const char* at, size_t length) -> int { return 0; };
  settings_.on_method_complete = [](llhttp_t* parser) -> int {
    VLOG(6) << "method: " << llhttp_method_name((llhttp_method_t)parser->method) << std::endl;
    return 0;
  };

  settings_.on_url = [](llhttp_t* parser, const char* at, size_t length) -> int {
    auto codec = reinterpret_cast<ConnectionImpl*>(parser->data);
    codec->onUrl(std::string_view{at, length});
    return 0;
  };

  settings_.on_url_complete = [](llhttp_t* parser) -> int {
    auto method = llhttp_method_name((llhttp_method_t)parser->method);
    auto codec = reinterpret_cast<ConnectionImpl*>(parser->data);
    codec->setMethod(std::string_view{method, strlen(method)});
    codec->onUrlComplete();
    return 0;
  };

  settings_.on_header_field = [](llhttp_t* parser, const char* at, size_t length) -> int {
    auto codec = reinterpret_cast<ConnectionImpl*>(parser->data);
    std::string field{at, length};
    VLOG(6) << "header field: " << field;
    codec->onHeaderField(field);
    return 0;
  };

  settings_.on_header_value = [](llhttp_t* parser, const char* at, size_t length) -> int {
    auto codec = reinterpret_cast<ConnectionImpl*>(parser->data);
    std::string value{at, length};
    VLOG(6) << "header value: " << value;
    codec->onHeaderValue(value);
    return 0;
  };

  settings_.on_headers_complete = [](llhttp_t* parser) -> int {
    auto codec = reinterpret_cast<ConnectionImpl*>(parser->data);
    codec->onHeadersComplete();
    return 0;
  };

  settings_.on_body = [](llhttp_t* parser, const char* at, size_t length) -> int {
    auto codec = reinterpret_cast<ConnectionImpl*>(parser->data);
    VLOG(4) << "body length: " << length;
    std::string_view body{at, length};
    codec->onBodyComplete(body);
    return 0;
  };

  llhttp_init(&parser_, HTTP_BOTH, &settings_);
  parser_.data = this;
}

ConnectionImpl::~ConnectionImpl() {
  // llhttp_free(&parser_);
}
} // namespace http1
} // namespace http
```

with:

```cpp
#include "codec.h"

#include <cstdint>
#include <utility>

#include "common/utility.h"
#include "glog/logging.h"
#include "http/filter.h"

namespace http {
namespace http1 {

ConnectionImpl::ConnectionImpl(bool serverSide, HttpFilterManagerPtr filterManager)
    : parser_(http1_codec::new_http1_parser()), header_{"", "", "", ParseState::Continue},
      filters_manager_(filterManager), serverSide_(serverSide) {}

ConnectionImpl::~ConnectionImpl() = default;

// Mirrors the old onHeadersComplete()'s headerMap_ construction and
// filters_manager_->decodeHeaders call exactly -- see the design spec's
// Non-Goal "any change to what the filter chain does with parsed headers."
// Only invoked when parsed.parse_state == Done.
const Header& ConnectionImpl::applyParsedHeader(const http1_codec::ParsedHeader& parsed) {
  header_.method_ = std::string(parsed.method);
  header_.path_ = std::string(parsed.path);
  header_.host_ = std::string(parsed.host);
  header_.parseState_ = ParseState::Done;

  headerMap_.clear();
  raw_host_header_.clear();
  for (const auto& f : parsed.fields) {
    std::string name(f.name);
    std::string value(f.value);
    if (name == "Host" || name == "host") {
      raw_host_header_ = value;
    }
    headerMap_.add(utility::toLow(name), utility::toLow(value));
  }
  headerMap_.add({":host"}, header_.host_);
  headerMap_.add({":method"}, header_.method_);
  headerMap_.add({":path"}, header_.path_);

  status_ = filters_manager_->decodeHeaders(headerMap_, serverSide_);
  return header_;
}

const Header& ConnectionImpl::dispatch(std::string_view data) {
  auto parsed = parser_->dispatch(
      rust::Slice<const uint8_t>(reinterpret_cast<const uint8_t*>(data.data()), data.length()));
  if (parsed.parse_state == /*Error*/ 2) {
    LOG(ERROR) << "http1_codec parse error";
    header_.parseState_ = ParseState::Error;
    return header_;
  }
  if (parsed.parse_state == /*Continue*/ 0) {
    header_.parseState_ = ParseState::Continue;
    return header_;
  }
  return applyParsedHeader(parsed);
}

const FilterStatus ConnectionImpl::dispatch(seastar::net::packet pkt) {
  auto data = pkt.get_header(0, pkt.len());
  VLOG(8) << "dispatching " << pkt.len() << " bytes data";

  auto parsed = parser_->dispatch(
      rust::Slice<const uint8_t>(reinterpret_cast<const uint8_t*>(data), pkt.len()));
  if (parsed.parse_state == /*Error*/ 2) {
    LOG(ERROR) << "http1_codec parse error";
    header_.parseState_ = ParseState::Error;
    return status_;
  }
  if (parsed.parse_state == /*Continue*/ 0) {
    header_.parseState_ = ParseState::Continue;
    return status_;
  }
  applyParsedHeader(parsed);
  return status_;
}

void ConnectionImpl::addFilter(HttpFilterPtr filter) { filters_manager_->addFilter(filter); }

void ConnectionImpl::setFilterManager(HttpFilterManagerPtr filterManager) {
  filters_manager_ = filterManager;
}

} // namespace http1
} // namespace http
```

Note: `onBodyComplete`'s old call to `filters_manager_->decodeBody(...)` has no replacement — this is intentional, per the design spec's framing-only decision (body content is never parsed out, so there is nothing to hand to `decodeBody`). `decodeBody`'s only real effect was iterating `filters_` (empty in production, per the WAF-removal branch's `LogFilter` finding), so this drops no observable production behavior.

- [ ] **Step 3: Build**

```bash
cd build && make -j2 && cd ..
```

Expected: build succeeds.

- [ ] **Step 4: Run the existing tests to confirm zero changes were needed to them**

```bash
./build/net_rule_test --gtest_filter='Http1CodecTest.*'
```

Expected: both `Http1CodecTest.Dispatch` and `Http1CodecTest.Dispatch1` PASS, unmodified from before this task.

- [ ] **Step 5: Commit**

```bash
git add http/http1/codec.h http/http1/codec.cc
git commit -m "Rewrite http/http1/codec.{h,cc} as a thin adapter over http1_codec

ConnectionImpl keeps its exact class name, namespace, constructor
signature, and public interface -- http/connection.cc's createCodec call
site and tests/codec_test.cc's existing two tests need zero changes. The
llhttp-based parsing logic is replaced by calls into the new Rust
http1_codec crate; onHeadersComplete's headerMap_ construction and
filters_manager_->decodeHeaders call are preserved exactly. decodeBody is
no longer called -- there is no body content to hand it, per the
framing-only design; its only production effect was iterating an
empty filter list anyway (see the WAF-removal branch's LogFilter finding)."
```

---

### Task 7: New test coverage (chunked, pipelining, host-resolution edge cases)

**Files:**
- Modify: `tests/codec_test.cc`

**Interfaces:**
- Consumes: `http::http1::ConnectionImpl` (Task 6), unchanged interface.
- Produces: new `TEST_F` cases in the existing `Http1CodecTest` fixture, covering behavior that had zero prior coverage (per the design spec's Testing & Rollout section).

- [ ] **Step 1: Add new test cases**

In `tests/codec_test.cc`, insert the following new tests immediately after the existing `Http1CodecTest, Dispatch1` test (before the closing `} // namespace http`):

```cpp
TEST_F(Http1CodecTest, ChunkedRequestBodyDoesNotBlockHeaderParsing) {
  const char* req = "POST /upload HTTP/1.1\r\nHost: example.com\r\n"
                     "Transfer-Encoding: chunked\r\n\r\n"
                     "3\r\nfoo\r\n0\r\n\r\n";
  auto header = codec_.dispatch(std::string_view{req, strlen(req)});
  EXPECT_EQ(header.parseState_, ParseState::Done);
  EXPECT_EQ(header.method_, "POST");
  EXPECT_EQ(header.path_, "/upload");
  EXPECT_EQ(header.host_, "example.com");
}

TEST_F(Http1CodecTest, PipelinedRequestsInOneCallReturnOnlyTheLastOne) {
  const char* req = "GET /first HTTP/1.1\r\n\r\nGET /second HTTP/1.1\r\n\r\n";
  auto header = codec_.dispatch(std::string_view{req, strlen(req)});
  EXPECT_EQ(header.parseState_, ParseState::Done);
  EXPECT_EQ(header.path_, "/second");
}

TEST_F(Http1CodecTest, ChunkedBodyDoesNotCorruptFollowingPipelinedRequest) {
  const char* req = "POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
                     "3\r\nfoo\r\n0\r\n\r\n"
                     "GET /next HTTP/1.1\r\n\r\n";
  auto header = codec_.dispatch(std::string_view{req, strlen(req)});
  EXPECT_EQ(header.parseState_, ParseState::Done);
  EXPECT_EQ(header.path_, "/next");
}

TEST_F(Http1CodecTest, OriginFormHostFallsBackToHostHeaderWithPortStripped) {
  const char* req = "GET /foo HTTP/1.1\r\nHost: example.com:9090\r\n\r\n";
  auto header = codec_.dispatch(std::string_view{req, strlen(req)});
  EXPECT_EQ(header.parseState_, ParseState::Done);
  EXPECT_EQ(header.host_, "example.com");
  EXPECT_EQ(codec_.getHost(), "example.com:9090");
}

TEST_F(Http1CodecTest, HostHeaderWithoutPortIsNotTruncated) {
  const char* req = "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n";
  auto header = codec_.dispatch(std::string_view{req, strlen(req)});
  EXPECT_EQ(header.host_, "example.com");
}

TEST_F(Http1CodecTest, AbsoluteFormHostWinsOverHostHeader) {
  const char* req = "GET https://1.2.3.4:8888/foo HTTP/1.1\r\nHost: other.example.com\r\n\r\n";
  auto header = codec_.dispatch(std::string_view{req, strlen(req)});
  EXPECT_EQ(header.host_, "1.2.3.4");
  EXPECT_EQ(header.path_, "/foo");
}

TEST_F(Http1CodecTest, MalformedRequestLineReportsError) {
  const char* req = "NOT A REQUEST\r\n\r\n";
  auto header = codec_.dispatch(std::string_view{req, strlen(req)});
  EXPECT_EQ(header.parseState_, ParseState::Error);
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd build && make -j2 && cd ..
./build/net_rule_test --gtest_filter='Http1CodecTest.*'
```

Expected: FAIL only if Task 6 has a real bug — since Task 6 already built and its two original tests passed, these new tests should mostly pass immediately; treat any failure here as a genuine bug in Task 6's adapter to fix, not an expected-fail step (unlike a from-scratch TDD task, this test is verifying an already-implemented adapter).

- [ ] **Step 3: Fix any failures, then confirm all pass**

```bash
./build/net_rule_test --gtest_filter='Http1CodecTest.*'
```

Expected: all 9 tests (2 original + 7 new) PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/codec_test.cc
git commit -m "Add HTTP/1.1 codec test coverage for chunked/pipelining/host-resolution

Covers behavior that had zero prior test coverage: chunked
Transfer-Encoding body framing, multiple pipelined requests within one
dispatch() call (only the last is returned, matching preserved old
behavior), a chunked body not corrupting a following pipelined request,
origin-form host resolution falling back to a port-stripped Host header,
a Host header with no port not being truncated, absolute-form
request-target host winning over a present Host header, and malformed
input reporting ParseState::Error."
```

---

### Task 8: Full-repo verification build and test run

**Files:** none (verification only).

- [ ] **Step 1: Clean rebuild**

```bash
rm -rf build && mkdir build && cd build && cmake .. && make -j2 && cd ..
cargo check --workspace
```

Expected: both succeed with no errors or warnings-as-errors.

- [ ] **Step 2: Run `net_rule_test` three times**

```bash
for i in 1 2 3; do ./build/net_rule_test || echo "RUN $i FAILED"; done
```

Expected: all three runs report 0 failures, including the 9 `Http1CodecTest` cases.

- [ ] **Step 3: Run `net_rule_grpc_test` three times with the routine filter**

```bash
for i in 1 2 3; do
  ./build/net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*' \
    || echo "RUN $i FAILED"
done
```

Expected: all three runs report 0 failures, including `Http1CodecSmokeTest`.

- [ ] **Step 4: Run the Rust crate's own test suite**

```bash
cd crates/http1_codec && cargo test && cd ../..
```

Expected: all tests across `request_target`, `header_parser`, `body_framing`, and `integration_tests` PASS.

- [ ] **Step 5: Confirm `http_parser.{h,c}` is untouched and `url.cc` still compiles**

```bash
git diff --stat main -- http/http1/http_parser.h http/http1/http_parser.c http/url.cc http/url.hh
```

Expected: no output — none of these four files were touched by this plan, per the Global Constraints.

- [ ] **Step 6: Report**

No commit for this task (verification only). Report the three run counts (Steps 2-3), the Rust test results (Step 4), and the confirmation from Step 5, then proceed to the final whole-branch review per `superpowers:subagent-driven-development`.
