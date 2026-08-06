# Phase 3a: HTTP/1.1 Codec Migration Design

## Overview

This spec covers Phase 3a of the C++ → Rust migration roadmap (`docs/superpowers/specs/2026-07-29-cpp-to-rust-migration-design.md`, sequenced per `docs/superpowers/specs/2026-08-06-phase7-decommission-scoping.md`): migrating the daemon's HTTP/1.1 request-line/header parser to Rust.

Investigation before design turned up two facts that materially change this phase's actual scope from what the roadmap assumed:

1. **`http/http1/http_parser.{h,c}` (3,026 lines — vendored joyent `http-parser` v2.9.4) is fully dead code.** The real, currently-used parser is `llhttp` (linked separately as `llhttp::llhttp_static`); every call site for the joyent API in `http/http1/codec.{cc,h}` is commented out, left over from a prior migration to llhttp that was never cleaned up.
2. **Body content is not consumed by anything in production today.** `Header` (`http/codec.h`) — what microsegmentation actually matches L7 policy against — has only `method_`/`path_`/`host_`, no body. The generic filter chain that used to consume parsed body bytes (`HttpFilterManager::decodeBody`) is the same one the WAF-removal branch found to be unreachable in production (its only real filter, `LogFilter`, has zero remaining production callers — see `docs/superpowers/specs/2026-08-06-waf-removal-design.md`'s aftermath). Body *framing* (locating where one request ends and the next begins, via `Content-Length` or chunked `Transfer-Encoding`) is still required for correct pipelined-request parsing, even though the bytes themselves go nowhere.

Both facts were confirmed by reading the actual current code, not assumed from the roadmap's row description — the same discipline applied throughout the WAF-removal work.

## Goals

- Migrate `http/http1/codec.{h,cc}` (268 lines — the actually-used llhttp-based parser) to a new Rust crate using `httparse` for header parsing plus a small hand-rolled body-framing state machine.
- **Framing only — no body content exposed.** Content-Length is counted down; chunked `Transfer-Encoding` is skipped chunk-by-chunk to its terminator; neither is stored or handed back to the caller. This matches actual current need exactly, since nothing downstream consumes body bytes today. If a filter needing bodies is reconnected later, that's a scope addition for whichever future work reconnects the filter chain — not built speculatively here.
- Delete the dead vendored `http/http1/http_parser.{h,c}` (3,026 lines) as part of this same phase.
- Expose the new parser to C++ via `cxx`, following the same shape already established by `net_flow_engine`/`net_policy_engine`: an opaque Rust struct (`Http1Parser`), one instance per connection, with a `dispatch(&mut self, data: &[u8]) -> ParsedHeader`-shaped method returning owned `method`/`path`/`host` strings and a parse-state enum — no raw or borrowed data crossing the FFI boundary.
- Preserve, exactly:
  - What's currently observable through `Header` (`method_`/`path_`/`host_`/`parseState_`).
  - The incremental multi-call `dispatch()` contract — TCP segments arrive in arbitrary chunks; the codec accumulates across calls until a full request is parsed. `httparse::Request::parse()` is a one-shot, immutable-buffer parse with no persistent resumable state (unlike `llhttp_t`), so the Rust side re-runs `httparse` over the whole accumulated buffer on each call until it either needs more data or completes — `httparse`'s standard documented usage pattern for streaming input.
  - Absolute-form request-line handling (`POST https://host:port/path ...`, not just origin-form `POST /path ...`) — already exercised by the existing (thin) test suite.
  - The existing "last-message-wins-within-one-call" limitation: today, if a single `dispatch()` call's input contains more than one complete pipelined request, `llhttp_execute` fires callbacks for all of them internally, but the C++ wrapper's `header_` is overwritten on each new message and `dispatch()` returns only the last one completed within that call. This is a pre-existing limitation, not something Phase 3a introduces or fixes — migrating it as-is matches this project's established practice of not bundling unplanned improvements into a migration phase.
- `http/connection.cc`'s `createCodec` gets a runtime toggle: construct either the old C++ `http1::ConnectionImpl` or a thin C++ adapter over the new `cxx`-exposed Rust type, per connection. `http1::ConnectionImpl` is deleted only after the Rust path is canaried per-pod and validated — this phase does not delete it immediately.

## Non-Goals

- `http/http2/*` (Phase 3b), `http/http_inspector.*`/`http/filter.*`/`http/connection.*`/`http/header.*`/`http/url.*`/etc. (Phase 3c) — untouched.
- Any change to what `net/connection_manager.h` or the filter chain do with parsed headers.
- Removing `llhttp`/`nghttp2`/`fmt` from the C++ link line — doesn't happen until Phase 3c, since `http/http_inspector.cc` also calls real `llhttp` (for HTTP/1-vs-2 protocol sniffing via the h2 connection-preface check) independently of `http/http1/codec.cc`.
- Fixing the "last-message-wins-within-one-call" pipelining limitation — preserved as-is (see Goals).
- Exposing body content — explicitly out of scope per the framing-only decision above.

## Architecture

- **New crate:** `crates/http1_codec`, following the established opaque-Rust-struct-plus-`cxx`-bridge pattern used by every other crate in this codebase (`net_flow_engine`, `net_policy_engine`, etc.) — not a novel FFI shape.
- **Incremental parsing:** accumulate bytes across `dispatch()` calls into a growable buffer; re-run `httparse` on the full accumulated buffer each call. This is `httparse`'s standard streaming-input pattern, not something invented for this migration.
- **Body-framing state machine**, entered once headers complete:
  - `Content-Length` present → count down that many bytes (discarded, not stored).
  - `Transfer-Encoding: chunked` → skip chunk-size-prefixed segments until the zero-length terminator chunk and trailing CRLF (discarded, not stored).
  - Neither → request has no body.
  - Once framing completes, state resets for the next pipelined request on the same connection, mirroring today's `on_message_begin`-triggered `resetState()`.
- **C++ integration:** `http/connection.cc`'s `createCodec` constructs the new type (via a thin C++ adapter implementing `Codec`'s virtual interface — `dispatch`, `addFilter`, `setFilterManager`) in place of `http1::ConnectionImpl`, gated by the runtime toggle described in Goals. This mirrors the pattern `net::ConnectionManager` already uses for its own Rust-backed internals.
- **Dead code removal:** `http/http1/http_parser.{h,c}` deleted; `CMakeLists.txt`'s `net-rule`/`net_rule_grpc_test`/`net_rule_test` `SOURCES` updated to drop it.

## Testing & Rollout

- **Validation strategy:** follows the roadmap's standard per-phase strategy unchanged — port tests, differential harness, runtime toggle, per-pod canary. This phase's toggle point (construct old-vs-new codec at `createCodec` time) is cheap, unlike Phase 6d's much harder whole-event-loop toggle problem flagged in the Phase 7 scoping doc.
- **Existing coverage is thin and must be built out, not just ported.** `tests/codec_test.cc`'s two tests (`Dispatch`, `Dispatch1`) cover absolute-form request lines and basic incremental multi-call parsing — that is the *entire* current coverage. Zero existing coverage exists for chunked encoding, pipelining, or the last-message-wins-within-one-call behavior. New coverage is needed for all three, both as Rust unit tests inside the new crate (mirroring `net_flow_engine`'s `#[cfg(test)]` pattern) and as a C++ FFI integration test exercising the real `cxx` boundary (mirroring `tests/net_flow_engine_ffi_test.cc`'s style).
- **Differential harness scope is narrower than a full llhttp behavior diff, by design.** Since body content is no longer exposed, the comparison is old-vs-new `Header` (method/host/path/parseState) for the same inputs — not byte-for-byte parity on everything llhttp does internally. This follows directly from the framing-only decision, not a validation-strategy gap.
- Canary: per-pod, via the same runtime-toggle mechanism prior phases used.

## Final State

- `http/http1/codec.{h,cc}` deleted; replaced by a thin C++ adapter over a new `crates/http1_codec` Rust crate, reachable via `cxx`.
- `http/http1/http_parser.{h,c}` deleted (dead vendored code).
- `http/connection.cc`'s `createCodec` constructs the Rust-backed adapter unconditionally (toggle removed) once canaried and validated.
- No change yet to `llhttp`/`nghttp2`/`fmt` link-line presence — that's Phase 3c.
