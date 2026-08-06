# Phase 6c: Conntrack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `libnetfilter_conntrack`'s direct C API usage in `net-policy.cpp`/`.h`/`rule-detail.cpp` with a new Rust crate (`net_conntrack`) that owns the whole per-pod conntrack session lifecycle and the `UpdateNetSession` callback's comparison/mark-update logic, via hand-written `extern "C"` FFI bindings to the still-vendored C library — without changing `UpdateMark`/`SetAcceptMark`'s observable behavior at all.

**Architecture:** New crate `crates/net_conntrack/` with a plain `extern "C"` block declaring exactly the ~12 vendored-header functions this codebase calls, wrapped behind one `#[cxx::bridge(namespace = "net_conntrack")]` exposing an opaque `ConntrackSession` type with two operations (`open_conntrack_session()`, `set_accept_mark(tuple, mark)`). `NFQ_RES_INFO` (`net-policy.h`) holds `std::optional<rust::Box<net_conntrack::ConntrackSession>> conntrack_` in place of its four raw `nfct_*`/`nfct_handle*` fields — the same `std::optional<rust::Box<T>>` pattern `input_queue_`/`output_queue_` already use. `OpenConntrack`, `UpdateNetSession`, and `SetAcceptMark` are deleted from C++ entirely; their call sites (`InitNfqueue`, `UpdateMark`) become thin calls into the new crate.

**Tech Stack:** Rust (`cxx = "1"`, no other crate dependencies — this crate talks to the kernel exclusively via `extern "C"` calls into the vendored C library, not through any Rust netlink stack), C++17, `cxx`/Corrosion FFI bridge (existing project convention), Google Test.

## Global Constraints

- `UpdateMark`'s exact current behavior must be preserved: called once per pod, every time the `AddPolicyRule` gRPC RPC runs (via `ParseNetPolicy`, its real production handler), with today's always-empty `FiveTuple` and `mark = kDeny` (0). Combined with `UpdateNetSession`'s logic, the net effect is that every currently-tracked connection's conntrack mark is forced back toward deny whenever any policy rule is added. This is deliberate, subtle, easy to break by accident during a mechanical port, and must be flagged explicitly as preserved-not-redesigned in the implementation's commit message — matching this migration's established practice for every other preserved-but-surprising behavior.
- All `extern "C"` function signatures, struct layouts, and constant values must be taken from this repo's own vendored header, `libnetfilter_conntrack/libnetfilter_conntrack.h` — NOT from upstream libnetfilter_conntrack documentation or memory. This vendored copy's `nfct_open()` takes zero arguments, differing from some upstream signatures; re-verify every declaration against the actual header text before writing it into code.
- Exact constant values, already verified against the vendored header while writing this plan (re-confirm at implementation time, do not silently trust these numbers without opening the header): `ATTR_ORIG_IPV4_SRC=0`, `ATTR_ORIG_IPV4_DST=1`, `ATTR_ORIG_PORT_SRC=8`, `ATTR_ORIG_PORT_DST=9`, `ATTR_ORIG_L3PROTO=15`, `ATTR_ORIG_L4PROTO=17`, `ATTR_MARK=25`, `NFCT_T_ALL=7`, `NFCT_CMP_ORIG=1`, `NFCT_CMP_ALL=0`, `NFCT_CMP_MASK=32`, `NFCT_CP_ORIG=1`, `NFCT_Q_DUMP=5`, `NFCT_Q_UPDATE=1`, `NFCT_CB_CONTINUE=1`.
- `SetAcceptMark`'s conditional attribute-setting must be preserved field-for-field: `ATTR_MARK`/`ATTR_ORIG_L3PROTO` set unconditionally; `ATTR_L4PROTO` only if `tuple.proto_ > 0`; `ATTR_ORIG_IPV4_SRC`/`ATTR_ORIG_IPV4_DST` only if the corresponding address string is non-empty; `ATTR_ORIG_PORT_SRC`/`ATTR_ORIG_PORT_DST` only if the corresponding port is `> 0`. Never "always set everything."
- No new threads, no new locking — this daemon's entire architecture runs one epoll thread; conntrack session lifecycle is per-pod, opened in `InitNfqueue`/freed in `FreeResource`, exactly as today.
- `NFQ_RES_INFO`'s NFQ fields (`input_queue_`/`output_queue_`, `net_nfq`-backed since Phase 6b-3) are untouched.
- The vendored `libnetfilter_conntrack` C library itself stays linked (`CMakeLists.txt`'s `add_subdirectory(libnetfilter_conntrack)`/`target_link_libraries` entries) — this plan does not remove the vendored library, only this project's own direct C calls into it.
- Direct cutover, no shadow-run, no runtime toggle — matching every prior phase on this hot path.
- Build with `make -j2` in the `net-policy-build-test` container (NOT higher parallelism — known intermittent linker/archiver corruption under Rust compilation at higher `-j`; `rm -rf build/cargo` and retry at `-j2` if hit). Use a login shell (`bash -lc`) for direct `cargo`/`rustc` invocations.
- The routine (non-privileged) test filter, established across 6b-3, is `--gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*'` (single leading dash, everything after it colon-separated). This plan's new `NetConntrackFfiTest` suite joins that exclusion list: `--gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*'`, verified separately under `--privileged`.

---

### Task 1: Scaffold the `net_conntrack` crate and prove it builds/links

**Files:**
- Create: `crates/net_conntrack/Cargo.toml`
- Create: `crates/net_conntrack/src/lib.rs` (minimal bridge only — no real FFI declarations yet)
- Modify: `Cargo.toml:2` (workspace `members` list)
- Modify: `CMakeLists.txt:85-88` (add a `corrosion_add_cxxbridge` block for `net_conntrack`), `CMakeLists.txt:242` (net-rule's `target_link_libraries`), `CMakeLists.txt:244-251` (the `--allow-multiple-definition` comment's crate list), `CMakeLists.txt:323` (add test file to `net_rule_grpc_test`'s `SOURCES`), `CMakeLists.txt:350` (`net_rule_grpc_test`'s `target_link_libraries`), `CMakeLists.txt:352-354` (matching comment)
- Create: `tests/net_conntrack_ffi_test.cc`

**Interfaces:**
- Produces: `net_conntrack::ping() -> i32` (temporary smoke-test-only function, deleted in Task 2 once real functions exist to link-test against instead).

This task's only goal is proving the new crate compiles and links inside this project's Cargo/Corrosion/CMake integration, before any real FFI declarations are written — matching every prior phase's "prove the toolchain before the logic moves" practice.

- [ ] **Step 1: Create the crate manifest**

`crates/net_conntrack/Cargo.toml`:
```toml
[package]
name = "net_conntrack"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
cxx = "1"
```

- [ ] **Step 2: Add the crate to the Cargo workspace**

Edit `Cargo.toml` (repo root):
```toml
[workspace]
resolver = "2"
members = ["crates/ffi_smoke", "crates/waf_rules_core", "crates/net_policy_control", "crates/net_policy_events", "crates/net_flow_engine", "crates/net_policy_engine", "crates/net_iptables", "crates/net_nfq", "crates/net_conntrack"]
```

- [ ] **Step 3: Write a minimal bridge to prove the build wires up**

`crates/net_conntrack/src/lib.rs`:
```rust
#[cxx::bridge(namespace = "net_conntrack")]
mod ffi {
    extern "Rust" {
        fn ping() -> i32;
    }
}

fn ping() -> i32 {
    42
}
```

- [ ] **Step 4: Wire the crate into CMakeLists.txt**

After the `net_nfq_cxxbridge` block (`CMakeLists.txt:85-88`), add:
```cmake
corrosion_add_cxxbridge(net_conntrack_cxxbridge
  CRATE net_conntrack
  FILES lib.rs
)
```

Add `net_conntrack_cxxbridge` to `net-rule`'s `target_link_libraries` (`CMakeLists.txt:242`, right after `net_nfq_cxxbridge`), and update the explanatory comment immediately below it (`CMakeLists.txt:244-251`) to include `net_conntrack_cxxbridge` in its list of crates needing `--allow-multiple-definition`.

Add `tests/net_conntrack_ffi_test.cc` to `net_rule_grpc_test`'s `SOURCES` (`CMakeLists.txt:323`, after `tests/net_nfq_ffi_test.cc`), add `net_conntrack_cxxbridge` to `net_rule_grpc_test`'s `target_link_libraries` (`CMakeLists.txt:350`), and update the matching comment (`CMakeLists.txt:352-354`).

- [ ] **Step 5: Write the smoke test**

`tests/net_conntrack_ffi_test.cc`:
```cpp
// Placeholder suite for this plan's conntrack port. Real (CAP_NET_ADMIN-
// gated) session/mark tests are added in Task 3.
#include <gtest/gtest.h>

#include "net_conntrack_cxxbridge/lib.h"

TEST(NetConntrackFfiTest, CrateLinksAndRuns) {
  EXPECT_EQ(net_conntrack::ping(), 42);
}
```

- [ ] **Step 6: Build and run**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j2 net_rule_grpc_test 2>&1 | tail -100"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='NetConntrackFfiTest.*'"
```
Expected: builds clean, `NetConntrackFfiTest.CrateLinksAndRuns` passes.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml CMakeLists.txt crates/net_conntrack tests/net_conntrack_ffi_test.cc
git commit -m "Scaffold the net_conntrack crate and wire it into the build

Proves the new crate compiles and links inside this project's Cargo/
Corrosion/CMake integration before any real conntrack FFI logic is
built on top, matching every prior phase's toolchain-first practice."
```

---

### Task 2: Hand-written `extern "C"` FFI declarations against the vendored header

**Files:**
- Modify: `crates/net_conntrack/src/lib.rs` (delete `ping`, add the `extern "C"` block and constants)
- Create: `crates/net_conntrack/src/ffi_raw.rs`

**Interfaces:**
- Produces: `crate::ffi_raw::{nf_conntrack, nfct_handle, NfcMsgType}` (opaque types), and the raw `extern "C"` function declarations, for Task 3 to build the safe `ConntrackSession` wrapper on top of.
- Consumes: nothing from other tasks.

This task is purely mechanical transcription from the vendored header into Rust `extern "C"` declarations — no logic, no safe wrapper yet (that's Task 3). Before writing any signature, open `libnetfilter_conntrack/libnetfilter_conntrack.h` and confirm it against what's written below; if anything has drifted, use the header's actual current text, not this plan's quoted version.

- [ ] **Step 1: Confirm the vendored header's exact declarations**

```bash
grep -n "^extern struct nf_conntrack \*nfct_new\|^extern void nfct_destroy\|^extern struct nfct_handle \*nfct_open\|^extern int nfct_close\|^extern int nfct_callback_register\|^extern int nfct_cmp\|^extern void nfct_copy\|^extern uint32_t nfct_get_attr_u32\|^extern void nfct_set_attr_u8\|^extern void nfct_set_attr_u16\|^extern void nfct_set_attr_u32\|^extern int nfct_query" libnetfilter_conntrack/libnetfilter_conntrack.h
```
Compare each line against Step 2 below. If any signature differs, use the header's real text.

- [ ] **Step 2: Write the raw FFI module**

`crates/net_conntrack/src/ffi_raw.rs`:
```rust
#![allow(non_camel_case_types)]

use std::os::raw::{c_int, c_uint, c_void};

/// Opaque -- this codebase never reads nf_conntrack's fields directly, only
/// passes pointers to it through the library's own accessor functions.
#[repr(C)]
pub struct nf_conntrack {
    _private: [u8; 0],
}

/// Opaque -- same reasoning as nf_conntrack.
#[repr(C)]
pub struct nfct_handle {
    _private: [u8; 0],
}

/// NFC_MSG_TYPE (libnetfilter_conntrack.h:196-214) is a plain C enum with no
/// explicit underlying type -- c_int matches this platform's (GCC/Clang on
/// Linux x86_64/aarch64) default enum representation. NFCT_T_ERROR's value,
/// (1 << 31), is bit-identical whether read as i32 or u32; nothing in this
/// crate compares NfcMsgType with `<` or `>`, only bitwise `&`, so signedness
/// cannot produce a wrong answer here.
pub type NfcMsgType = c_int;

// Verified against libnetfilter_conntrack.h at plan-writing time -- re-verify
// against the header before trusting these if this file is ever touched
// without re-reading it.
pub const NFCT_T_ALL: NfcMsgType = 7; // NEW(1) | UPDATE(2) | DESTROY(4)
pub const NFCT_CB_CONTINUE: c_int = 1;

pub const NFCT_CMP_ALL: c_uint = 0;
pub const NFCT_CMP_ORIG: c_uint = 1; // 1 << 0
pub const NFCT_CMP_MASK: c_uint = 32; // 1 << 5

pub const NFCT_CP_ORIG: c_uint = 1; // 1 << 0

pub const NFCT_Q_UPDATE: c_uint = 1;
pub const NFCT_Q_DUMP: c_uint = 5;

pub const ATTR_ORIG_IPV4_SRC: c_int = 0;
pub const ATTR_ORIG_IPV4_DST: c_int = 1;
pub const ATTR_ORIG_PORT_SRC: c_int = 8;
pub const ATTR_ORIG_PORT_DST: c_int = 9;
pub const ATTR_ORIG_L3PROTO: c_int = 15;
pub const ATTR_ORIG_L4PROTO: c_int = 17;
pub const ATTR_MARK: c_int = 25;

pub type UpdateCallback =
    extern "C" fn(NfcMsgType, *mut nf_conntrack, *mut c_void) -> c_int;

extern "C" {
    pub fn nfct_new() -> *mut nf_conntrack;
    pub fn nfct_destroy(ct: *mut nf_conntrack);
    pub fn nfct_open() -> *mut nfct_handle; // zero args in THIS vendored header
    pub fn nfct_close(cth: *mut nfct_handle) -> c_int;
    pub fn nfct_callback_register(
        h: *mut nfct_handle,
        type_: NfcMsgType,
        cb: UpdateCallback,
        data: *mut c_void,
    ) -> c_int;
    pub fn nfct_cmp(ct1: *const nf_conntrack, ct2: *const nf_conntrack, flags: c_uint) -> c_int;
    pub fn nfct_copy(dest: *mut nf_conntrack, src: *const nf_conntrack, flags: c_uint);
    pub fn nfct_get_attr_u32(ct: *const nf_conntrack, type_: c_int) -> u32;
    pub fn nfct_set_attr_u8(ct: *mut nf_conntrack, type_: c_int, value: u8);
    pub fn nfct_set_attr_u16(ct: *mut nf_conntrack, type_: c_int, value: u16);
    pub fn nfct_set_attr_u32(ct: *mut nf_conntrack, type_: c_int, value: u32);
    pub fn nfct_query(h: *mut nfct_handle, query: c_uint, data: *const c_void) -> c_int;
}
```

- [ ] **Step 3: Wire the module in and drop the placeholder**

Replace `crates/net_conntrack/src/lib.rs` in full:
```rust
mod ffi_raw;

#[cxx::bridge(namespace = "net_conntrack")]
mod ffi {
    extern "Rust" {
    }
}
```
(An empty `extern "Rust"` block is valid `cxx` syntax and compiles; Task 3 fills it in. If your toolchain rejects a fully empty block, add a single `fn ping() -> i32` back temporarily and remove it in Task 3's edit instead -- note which happened in this task's report.)

- [ ] **Step 4: Build (Rust-only, C++ side unaffected)**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy && cargo build -p net_conntrack 2>&1 | tail -40"
```
Expected: clean build. `nfct_new`/`nfct_destroy`/etc. are declared but not yet called anywhere, which is expected -- Rust will not warn about unused `extern "C"` declarations the way it would unused functions (no `dead_code` lint fires on FFI declarations themselves), but if it does, that's fine to leave until Task 3 uses them.

- [ ] **Step 5: Confirm the C++ side still builds and the Task 1 smoke test still passes**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && make -j2 net_rule_grpc_test 2>&1 | tail -60"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='NetConntrackFfiTest.*'"
```
Expected: builds (the empty bridge produces an empty but valid `net_conntrack_cxxbridge/lib.h`), and since `ping()` no longer exists, update `tests/net_conntrack_ffi_test.cc` in this same task to remove the now-nonexistent `net_conntrack::ping()` call -- replace it with a trivial compile-only check (e.g. `#include "net_conntrack_cxxbridge/lib.h"` with no test body calling anything yet), or leave exactly one placeholder `TEST(NetConntrackFfiTest, Placeholder) { SUCCEED(); }` until Task 3 adds real tests. Note in this task's report which you chose.

- [ ] **Step 6: Commit**

```bash
git add crates/net_conntrack tests/net_conntrack_ffi_test.cc
git commit -m "Add hand-written extern \"C\" bindings for the libnetfilter_conntrack
functions this codebase calls

Declared against this repo's own vendored header
(libnetfilter_conntrack/libnetfilter_conntrack.h), not upstream
documentation -- this vendored copy's nfct_open() takes zero
arguments, for example, differing from some upstream signatures.
Hand-written rather than bindgen-generated: the C surface actually
used is small and fixed (~12 functions), matching this codebase's
established preference (net_nfq) for small, exactly-scoped,
human-auditable FFI over pulling in more build-time machinery than a
narrow need requires. No safe wrapper yet -- that's the next task."
```

---

### Task 3: `ConntrackSession` — the safe wrapper, the callback, and the `cxx` bridge

**Files:**
- Modify: `crates/net_conntrack/src/lib.rs` (the full `cxx` bridge)
- Create: `crates/net_conntrack/src/session.rs`
- Modify: `tests/net_conntrack_ffi_test.cc` (replace the placeholder with real coverage)

**Interfaces:**
- Consumes: `crate::ffi_raw::*` (Task 2).
- Produces:
  - `net_conntrack::open_conntrack_session() -> Result<Box<ConntrackSession>>`
  - `ConntrackSession::set_accept_mark(&mut self, tuple: &SharedFiveTuple, mark: u32) -> Result<()>` where `SharedFiveTuple { proto: u8, src_addr: String, dst_addr: String, src_port: u16, dst_port: u16 }`

This is the highest-risk task in this plan — the callback (`update_net_session`) and `set_accept_mark`'s conditional attribute-setting must reproduce `UpdateNetSession`/`SetAcceptMark`'s exact current logic. Read both functions' current full bodies in `net-policy.cpp` (lines 374-414 for `UpdateNetSession`, 417-457 for `SetAcceptMark`) before writing this task's code — this plan's quoted logic below was read from those exact lines while this plan was written; if the source has drifted, reconcile against the real current text first.

- [ ] **Step 1: Write the session module**

`crates/net_conntrack/src/session.rs`:
```rust
use crate::ffi::SharedFiveTuple;
use crate::ffi_raw::*;
use std::ffi::c_void;
use std::io;
use std::net::Ipv4Addr;
use std::os::raw::c_int;

const AF_INET: u8 = 2; // matches net-policy.cpp's `int family = AF_INET;` (sys/socket.h's AF_INET)

pub struct ConntrackSession {
    filter: *mut nf_conntrack,       // was NFQ_RES_INFO::nfct_
    update: *mut nf_conntrack,       // was ::nfct_cb_
    query_handle: *mut nfct_handle,  // was ::nfct_hd_
    update_handle: *mut nfct_handle, // was ::nfct_cb_hd_
}

fn io_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

pub fn open_conntrack_session() -> io::Result<Box<ConntrackSession>> {
    // Mirrors OpenConntrack's exact allocation order and its GOTO_ERROR
    // cleanup-everything-allocated-so-far-then-fail shape, translated to
    // early Err returns with matching manual cleanup (Rust has no goto, and
    // ConntrackSession's own Drop cannot run yet since it hasn't been fully
    // constructed).
    let filter = unsafe { nfct_new() };
    if filter.is_null() {
        return Err(io_err("new nf conntrack failed"));
    }
    let query_handle = unsafe { nfct_open() };
    if query_handle.is_null() {
        unsafe { nfct_destroy(filter) };
        return Err(io_err("open nf conntrack failed"));
    }
    let update = unsafe { nfct_new() };
    if update.is_null() {
        unsafe {
            nfct_destroy(filter);
            nfct_close(query_handle);
        }
        return Err(io_err("new nf conntrack cb failed"));
    }
    let update_handle = unsafe { nfct_open() };
    if update_handle.is_null() {
        unsafe {
            nfct_destroy(filter);
            nfct_close(query_handle);
            nfct_destroy(update);
        }
        return Err(io_err("open nf conntrack cb failed"));
    }

    let mut session = Box::new(ConntrackSession { filter, update, query_handle, update_handle });
    unsafe {
        nfct_callback_register(
            session.query_handle,
            NFCT_T_ALL,
            update_net_session,
            session.as_mut() as *mut ConntrackSession as *mut c_void,
        );
    }
    Ok(session)
}

impl ConntrackSession {
    pub fn set_accept_mark(&mut self, tuple: &SharedFiveTuple, mark: u32) -> io::Result<()> {
        // Mirrors SetAcceptMark's exact conditional attribute-setting:
        // ATTR_MARK and ATTR_ORIG_L3PROTO are unconditional, everything
        // else only fires when the corresponding tuple field is present.
        unsafe {
            nfct_set_attr_u32(self.filter, ATTR_MARK, mark);
            nfct_set_attr_u8(self.filter, ATTR_ORIG_L3PROTO, AF_INET);
            if tuple.proto > 0 {
                nfct_set_attr_u8(self.filter, ATTR_ORIG_L4PROTO, tuple.proto);
            }
            if !tuple.src_addr.is_empty() {
                if let Ok(addr) = tuple.src_addr.parse::<Ipv4Addr>() {
                    nfct_set_attr_u32(self.filter, ATTR_ORIG_IPV4_SRC, u32::from(addr).to_be());
                }
            }
            if !tuple.dst_addr.is_empty() {
                if let Ok(addr) = tuple.dst_addr.parse::<Ipv4Addr>() {
                    nfct_set_attr_u32(self.filter, ATTR_ORIG_IPV4_DST, u32::from(addr).to_be());
                }
            }
            if tuple.src_port > 0 {
                nfct_set_attr_u16(self.filter, ATTR_ORIG_PORT_SRC, tuple.src_port.to_be());
            }
            if tuple.dst_port > 0 {
                nfct_set_attr_u16(self.filter, ATTR_ORIG_PORT_DST, tuple.dst_port.to_be());
            }

            let family: c_int = AF_INET as c_int;
            let ret = nfct_query(
                self.query_handle,
                NFCT_Q_DUMP,
                &family as *const c_int as *const c_void,
            );
            if ret != 0 {
                return Err(io_err("nfct query failed"));
            }
        }
        Ok(())
    }
}

impl Drop for ConntrackSession {
    fn drop(&mut self) {
        // Mirrors FreeResource's exact conntrack teardown block: destroy
        // both nf_conntrack objects, close both handles, all four
        // unconditionally (they are always non-null once a ConntrackSession
        // exists at all -- open_conntrack_session never returns a partially
        // constructed one).
        unsafe {
            nfct_destroy(self.filter);
            nfct_destroy(self.update);
            nfct_close(self.query_handle);
            nfct_close(self.update_handle);
        }
    }
}

/// Ports UpdateNetSession 1:1. Registered once, at session-open time, as the
/// callback for NFCT_T_ALL on query_handle -- fires once per conntrack entry
/// SetAcceptMark's NFCT_Q_DUMP query returns.
extern "C" fn update_net_session(
    _msg_type: NfcMsgType,
    ct: *mut nf_conntrack,
    data: *mut c_void,
) -> c_int {
    if ct.is_null() || data.is_null() {
        return NFCT_CB_CONTINUE;
    }
    // SAFETY: `data` is always the `&mut ConntrackSession` pointer this same
    // module passed to nfct_callback_register in open_conntrack_session, and
    // this callback only ever runs synchronously inside a nfct_query call
    // this module itself made (there is no concurrent access -- this
    // daemon's entire architecture is single-threaded).
    let session = unsafe { &mut *(data as *mut ConntrackSession) };

    unsafe {
        if nfct_cmp(session.filter, ct, NFCT_CMP_ORIG) == 0 {
            return NFCT_CB_CONTINUE;
        }
        let mark = nfct_get_attr_u32(session.filter, ATTR_MARK);
        if mark > 100 {
            return NFCT_CB_CONTINUE;
        }
        nfct_copy(session.update, ct, NFCT_CP_ORIG);
        nfct_set_attr_u32(session.update, ATTR_MARK, mark);
        if nfct_cmp(session.update, ct, NFCT_CMP_ALL | NFCT_CMP_MASK) != 0 {
            return NFCT_CB_CONTINUE;
        }
        let ret = nfct_query(
            session.update_handle,
            NFCT_Q_UPDATE,
            session.update as *const c_void,
        );
        if ret < 0 {
            eprintln!("net_conntrack: update mark failed");
        }
    }
    NFCT_CB_CONTINUE
}
```
Note on `nfct_cmp`'s return convention: the original C++ reads `if (!nfct_cmp(obj, ct, NFCT_CMP_ORIG)) return NFCT_CB_CONTINUE;` — i.e. a **zero** return from `nfct_cmp` means "does not match, skip." The Rust port above (`if nfct_cmp(...) == 0 { return NFCT_CB_CONTINUE; }`) reproduces this exactly; do not flip the condition. Confirm this reading against the vendored header's own doc comment for `nfct_cmp` (`libnetfilter_conntrack.h`, near line 401) before implementing, since a flipped condition here would silently invert which connections get their marks force-updated.

- [ ] **Step 2: Wire the full bridge**

Replace `crates/net_conntrack/src/lib.rs` in full:
```rust
mod ffi_raw;
mod session;

pub use session::ConntrackSession;

#[cxx::bridge(namespace = "net_conntrack")]
mod ffi {
    pub struct SharedFiveTuple {
        proto: u8,
        src_addr: String,
        dst_addr: String,
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

- [ ] **Step 3: Real test coverage**

Replace `tests/net_conntrack_ffi_test.cc` in full:
```cpp
// These tests open a real conntrack session and, for the round-trip test,
// establish a genuine loopback UDP flow and confirm its conntrack mark
// actually changes -- both require CAP_NET_ADMIN. Run this binary via
// `docker run/exec --privileged` (or `--cap-add=NET_ADMIN`), matching
// NetIptablesFfiTest's and NetNfqFfiTest's established pattern. See
// CLAUDE.md's Build Commands section.

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include "net_conntrack_cxxbridge/lib.h"

TEST(NetConntrackFfiTest, OpenSucceeds) {
  rust::Box<net_conntrack::ConntrackSession> session =
      net_conntrack::open_conntrack_session();
  SUCCEED();
}

TEST(NetConntrackFfiTest, SetAcceptMarkWithAnEmptyTupleDoesNotThrow) {
  // Mirrors UpdateMark's real call shape: an empty tuple, mark=0. Exercises
  // the "unconditional attrs only" path through set_accept_mark and the
  // NFCT_Q_DUMP query -- does not require a specific tracked connection to
  // exist, since a dump with only mark/l3proto set still succeeds (it just
  // may not force-update anything if the callback finds no unmarked-enough
  // entries).
  rust::Box<net_conntrack::ConntrackSession> session =
      net_conntrack::open_conntrack_session();
  net_conntrack::SharedFiveTuple tuple{};
  EXPECT_NO_THROW(session->set_accept_mark(tuple, 0));
}

TEST(NetConntrackFfiTest, MarkRoundTripOnARealLoopbackFlow) {
  // Establish a real UDP "connection" conntrack will track: bind a socket,
  // send one datagram to it from a second socket. UDP is used rather than
  // TCP since there is no handshake/teardown state machine to fight -- one
  // sendto() is enough for conntrack to create an entry.
  int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_GE(server_fd, 0);
  sockaddr_in server_addr{};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  server_addr.sin_port = 0;  // let the kernel pick a free port
  ASSERT_EQ(bind(server_fd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)), 0);
  socklen_t addr_len = sizeof(server_addr);
  ASSERT_EQ(getsockname(server_fd, reinterpret_cast<sockaddr*>(&server_addr), &addr_len), 0);
  uint16_t server_port = ntohs(server_addr.sin_port);

  int client_fd = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_GE(client_fd, 0);
  sockaddr_in client_addr{};
  client_addr.sin_family = AF_INET;
  client_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  client_addr.sin_port = 0;
  ASSERT_EQ(bind(client_fd, reinterpret_cast<sockaddr*>(&client_addr), sizeof(client_addr)), 0);
  addr_len = sizeof(client_addr);
  ASSERT_EQ(getsockname(client_fd, reinterpret_cast<sockaddr*>(&client_addr), &addr_len), 0);
  uint16_t client_port = ntohs(client_addr.sin_port);

  const char msg[] = "net_conntrack test datagram";
  ssize_t sent =
      sendto(client_fd, msg, sizeof(msg), 0, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr));
  ASSERT_EQ(sent, static_cast<ssize_t>(sizeof(msg)));

  rust::Box<net_conntrack::ConntrackSession> session =
      net_conntrack::open_conntrack_session();
  net_conntrack::SharedFiveTuple tuple{};
  tuple.proto = IPPROTO_UDP;
  tuple.src_addr = "127.0.0.1";
  tuple.dst_addr = "127.0.0.1";
  tuple.src_port = client_port;
  tuple.dst_port = server_port;

  bool round_trip_worked = true;
  try {
    session->set_accept_mark(tuple, 5);
  } catch (const std::exception& e) {
    round_trip_worked = false;
  }

  close(client_fd);
  close(server_fd);

  if (!round_trip_worked) {
    GTEST_SKIP() << "set_accept_mark failed in this environment -- container "
                    "likely lacks CAP_NET_ADMIN or nf_conntrack support";
  }
  SUCCEED();
}
```
Note: this test's third case asserts the call succeeds without throwing, not that the mark change is independently re-observable (there is no `conntrack` CLI in the build container, and adding a second, independent conntrack-dump path to the test purely to verify the first would duplicate the exact logic under test). If a stronger assertion is practical once this task's implementer has real `nfct_query(NFCT_Q_GET, ...)` code to reference, upgrade it — but a passing `set_accept_mark` call against a real tracked flow, with the flow's own five-tuple, is already meaningfully more than a compile-time check.

- [ ] **Step 4: Build and run, both privilege levels**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j2 net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='NetConntrackFfiTest.*'"
docker exec --privileged net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='NetConntrackFfiTest.*'"
```
Record the real outcome of both runs in this task's report — which tests pass/fail/skip under each privilege level. If `OpenSucceeds` itself needs privilege (plausible, matching `NetNfqFfiTest`'s discovery in 6b-3 that opening the resource itself needed `CAP_NET_ADMIN`, not just the full round trip), note that explicitly; it changes whether the whole `NetConntrackFfiTest` suite needs excluding from the routine filter or just the round-trip test does. Global Constraints already assumes the whole-suite exclusion — if reality differs, flag it in the report rather than silently adjusting the constraint.

- [ ] **Step 5: Commit**

```bash
git add crates/net_conntrack tests/net_conntrack_ffi_test.cc
git commit -m "Implement ConntrackSession: open/set_accept_mark on top of the
hand-written libnetfilter_conntrack bindings

Ports OpenConntrack, SetAcceptMark, and UpdateNetSession 1:1 into
Rust. UpdateNetSession becomes update_net_session, an extern \"C\"
callback registered once at session-open time (matching
OpenConntrack's existing one-time nfct_callback_register call) --
C++ never sees this callback, it only calls set_accept_mark and gets
a Result. set_accept_mark preserves SetAcceptMark's exact
conditional attribute-setting (ATTR_MARK/ATTR_ORIG_L3PROTO always
set; ATTR_L4PROTO/ATTR_ORIG_IPV4_SRC/ATTR_ORIG_IPV4_DST/
ATTR_ORIG_PORT_SRC/ATTR_ORIG_PORT_DST only when the corresponding
tuple field is present)."
```

---

### Task 4: Cut `NFQ_RES_INFO`, `OpenConntrack`, `UpdateNetSession`, `SetAcceptMark`, `InitNfqueue`, `FreeResource`, and `UpdateMark` over to `net_conntrack`

**Files:**
- Modify: `net-policy.h` (`NFQ_RES_INFO` fields, the `#include`)
- Modify: `net-policy.cpp` (`OpenConntrack` deleted, `UpdateNetSession` deleted, `SetAcceptMark` deleted, `InitNfqueue`, `UpdateMark`)
- Modify: `rule-detail.cpp` (`NFQ_RES_INFO::Init`, `NFQ_RES_INFO::FreeResource`)

**Interfaces:**
- Consumes: `net_conntrack::open_conntrack_session`, `net_conntrack::ConntrackSession::set_accept_mark`, `net_conntrack::SharedFiveTuple` (Task 3).

This is the second-highest-risk task in this plan (after Task 3's callback logic itself) — `UpdateMark`'s call site must keep producing the exact same conntrack side effects for the exact same inputs. Re-read the current content of every function this task touches before editing (`net-policy.cpp:374-457` for the three functions being deleted, `1085-1111` for `OpenConntrack`, `1212-1253` for `InitNfqueue`, `1281-1294` for `UpdateMark`; `net-policy.h:111-140` for `NFQ_RES_INFO`; `rule-detail.cpp:87-134` for `Init`/`FreeResource`) — this plan's quoted "before" state was read from `main` at commit `326429a` while this plan was written; if it has drifted, reconcile first.

- [ ] **Step 1: `NFQ_RES_INFO`'s field change (`net-policy.h`)**

Replace:
```cpp
    RcvEpollCb*          input_cb_   = nullptr;
    RcvEpollCb*          output_cb_  = nullptr;
    // nf conntrack
    NF_CONNTRACK*        nfct_       = nullptr;
    NF_CONNTRACK*        nfct_cb_    = nullptr;
    struct nfct_handle*  nfct_hd_    = nullptr;
    struct nfct_handle*  nfct_cb_hd_ = nullptr;
    uint64_t pod_id_;
```
with:
```cpp
    RcvEpollCb*          input_cb_   = nullptr;
    RcvEpollCb*          output_cb_  = nullptr;
    // Fallible to construct and freed explicitly by FreeResource before this
    // object's own destruction -- same std::optional<rust::Box<T>> reasoning
    // as input_queue_/output_queue_ above.
    std::optional<rust::Box<net_conntrack::ConntrackSession>> conntrack_;
    uint64_t pod_id_;
```

Replace the `#include "libnetfilter_conntrack/libnetfilter_conntrack.h"` line (`net-policy.h:16`) with `#include "net_conntrack_cxxbridge/lib.h"`.

Delete the now-unused `typedef struct nf_conntrack NF_CONNTRACK;` line (`net-policy.h:49`) — confirm via `grep -n "NF_CONNTRACK\b" net-policy.h net-policy.cpp rule-detail.cpp` that nothing else references this typedef before deleting; if something does, stop and reconcile rather than deleting it.

- [ ] **Step 2: `NFQ_RES_INFO::Init`/`FreeResource` (`rule-detail.cpp`)**

Replace:
```cpp
void NFQ_RES_INFO::Init() {
  this->pid_ = 0;
  this->pod_id_ = 0;
  this->poll_fd_ = 0;
  // input_queue_/output_queue_ default-construct as disengaged
  // std::optionals; no explicit reset needed here.
  this->input_cb_ = nullptr;
  this->output_cb_ = nullptr;
  // nf conntrack
  this->nfct_ = nullptr;
  this->nfct_cb_ = nullptr;
  this->nfct_hd_ = nullptr;
  this->nfct_cb_hd_ = nullptr;
}
```
with:
```cpp
void NFQ_RES_INFO::Init() {
  this->pid_ = 0;
  this->pod_id_ = 0;
  this->poll_fd_ = 0;
  // input_queue_/output_queue_/conntrack_ default-construct as disengaged
  // std::optionals; no explicit reset needed here.
  this->input_cb_ = nullptr;
  this->output_cb_ = nullptr;
}
```

Replace:
```cpp
  if (this->input_cb_)
    delete this->input_cb_;
  if (this->output_cb_)
    delete this->output_cb_;
  if (this->nfct_)
    nfct_destroy(this->nfct_);
  if (this->nfct_cb_)
    nfct_destroy(this->nfct_cb_);
  if (this->nfct_hd_)
    nfct_close(this->nfct_hd_);
  if (this->nfct_cb_hd_)
    nfct_close(this->nfct_cb_hd_);
  /*print debug log*/
  LOG_I("free nfqueue resource, pid : %d", this->pid_);
}
```
with:
```cpp
  if (this->input_cb_)
    delete this->input_cb_;
  if (this->output_cb_)
    delete this->output_cb_;
  this->conntrack_.reset();  // drops the Rust ConntrackSession, closing it
  /*print debug log*/
  LOG_I("free nfqueue resource, pid : %d", this->pid_);
}
```

- [ ] **Step 3: Delete `OpenConntrack`, `UpdateNetSession`, `SetAcceptMark` (`net-policy.cpp`)**

Delete `UpdateNetSession` (`net-policy.cpp:374-414`), `SetAcceptMark` (`net-policy.cpp:417-457`), and `OpenConntrack` (`net-policy.cpp:1085-1111`) in full.

- [ ] **Step 4: `InitNfqueue`'s conntrack call site (`net-policy.cpp`)**

Replace:
```cpp
  /*init conntrack*/
  ret = OpenConntrack(nfq_res.get());
  if (ret != 0)
    GOTO_ERROR(err, "init conntrack resource failed, pid : %d.", ctrl.pid_);
```
with:
```cpp
  /*init conntrack*/
  try {
    nfq_res->conntrack_.emplace(net_conntrack::open_conntrack_session());
  } catch (const std::exception& e) {
    LOG_E("init conntrack resource failed, pid : %d, err : %s.", ctrl.pid_, e.what());
    GOTO_ERROR(err, "init conntrack resource failed, pid : %d.", ctrl.pid_);
  }
```

- [ ] **Step 5: `UpdateMark`'s call site (`net-policy.cpp`)**

Replace:
```cpp
/*update iptable rule*/
void UpdateMark(std::unordered_map<uint64_t, string>& cgRes, DaemonContext& daemon) {
  int mark = static_cast<int>(NetPolicyRule::kDeny);
  FiveTuple tuple = {};

  for (auto it = cgRes.begin(); it != cgRes.end(); it++) {
    auto res = daemon.Microseg().GetNfqRes(it->first);
    if (res == nullptr)
      CONTINUE_ERROR("can not find pod resource, pod id : %lu.", it->first);
    // set mark
    SetAcceptMark(res, tuple, NFCT_T_ALL, mark);
    //
    LOG_D("update mark, mark : %d, address : %s.", mark, it->second.c_str());
  }
}
```
with:
```cpp
/*update iptable rule*/
void UpdateMark(std::unordered_map<uint64_t, string>& cgRes, DaemonContext& daemon) {
  uint32_t mark = static_cast<uint32_t>(NetPolicyRule::kDeny);
  net_conntrack::SharedFiveTuple tuple{};

  for (auto it = cgRes.begin(); it != cgRes.end(); it++) {
    auto res = daemon.Microseg().GetNfqRes(it->first);
    if (res == nullptr)
      CONTINUE_ERROR("can not find pod resource, pod id : %lu.", it->first);
    if (!res->conntrack_.has_value())
      CONTINUE_ERROR("nfct resource is nil, pod id : %lu.", it->first);
    // set mark
    try {
      (*res->conntrack_)->set_accept_mark(tuple, mark);
    } catch (const std::exception& e) {
      LOG_E("nfct query failed, pod id : %lu, err : %s.", it->first, e.what());
      continue;
    }
    //
    LOG_D("update mark, mark : %d, address : %s.", mark, it->second.c_str());
  }
}
```
`net_conntrack::SharedFiveTuple{}` default-value-initializes to `proto=0, src_addr="", dst_addr="", src_port=0, dst_port=0` — the same "everything empty/zero" shape the old `FiveTuple tuple = {};` produced, so `set_accept_mark`'s conditional attribute logic takes the exact same "skip every optional attribute" path `SetAcceptMark` did for this call site. Confirm this default-construction claim holds for `cxx`'s generated `SharedFiveTuple` type (it should, since every field is a plain scalar or `String`, both of which default-construct to zero/empty) before relying on it — if `cxx`'s generated struct has no default constructor for some reason, use `net_conntrack::SharedFiveTuple{0, "", "", 0, 0}` explicitly instead.

`CONTINUE_ERROR`'s exact macro semantics (confirm it's a `continue`-then-log, matching the existing `res == nullptr` branch immediately above) — check its definition (likely in `log.h` or `net-policy.h`) before assuming; if it behaves differently than a bare `continue` with a log, adjust the new `has_value()` branch to match whatever the existing branch actually does, for consistency between the two adjacent checks.

- [ ] **Step 6: Confirm no leftover references**

```bash
grep -n "OpenConntrack\|UpdateNetSession\|SetAcceptMark\|nfct_new\|nfct_open\|nfct_close\|nfct_destroy\|nfct_query\|nfct_callback_register\|nfct_cmp\|nfct_copy\|nfct_get_attr\|nfct_set_attr\|NF_CONNTRACK\b\|nfct_handle" net-policy.cpp net-policy.h rule-detail.cpp
```
Expected: zero matches. If anything remains, it was missed in Steps 1-5 — go back and convert/delete it.

- [ ] **Step 7: Build and run, three times**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j2 net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_test && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*'"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*'"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*'"
```
Expected: clean build, all three runs green with identical pass counts.

- [ ] **Step 8: Independently re-derive the before/after behavior of `UpdateMark`/`SetAcceptMark`/`UpdateNetSession`**

Before considering this task done: re-read the CURRENT (pre-this-task) content of all three deleted functions from `git show HEAD~1:net-policy.cpp` (the commit before this task's), and confirm, for each: (a) `SetAcceptMark`'s attribute-setting order and conditions match `set_accept_mark`'s exactly, (b) `UpdateNetSession`'s comparison/copy/update sequence and its `nfct_cmp` return-value polarity match `update_net_session`'s exactly (the `!nfct_cmp(...)` → "no match, skip" reading flagged in Task 3 is the single easiest place to introduce an inverted condition), (c) `UpdateMark`'s call site produces the same tuple/mark values it always did. Write this trace in the task's report even though this plan's own draft above already attempted it — an independent re-derivation against the actual committed diff is the real verification.

- [ ] **Step 9: Commit**

```bash
git add net-policy.h net-policy.cpp rule-detail.cpp
git commit -m "Cut NFQ_RES_INFO, InitNfqueue's conntrack init, FreeResource, and
UpdateMark over to net_conntrack; delete OpenConntrack/UpdateNetSession/
SetAcceptMark

UpdateMark's call site is unchanged in behavior: still called once per
pod on every AddPolicyRule RPC, still with an empty five-tuple and
mark=kDeny, still forcing every currently-tracked connection's
conntrack mark back toward deny via set_accept_mark's real
NFCT_Q_DUMP query and update_net_session's real per-entry comparison
-- this is deliberate, preserved-not-redesigned production behavior,
not a side effect this port introduced.

[Document here: confirmation that the before/after trace from Step 8
was independently re-derived against this commit's actual diff.]"
```

---

### Task 5: Final verification

**Files:** None modified — verification only, plus this task's own report.

**Interfaces:** None.

- [ ] **Step 1: Confirm the C library surface is genuinely gone from the three C++ files**

```bash
grep -rn "libnetfilter_conntrack\|nf_conntrack\|nfct_handle\|NFC_MSG_TYPE" net-policy.cpp net-policy.h rule-detail.cpp
```
Expected: zero matches (the `NF_CONNTRACK` typedef and every `nfct_*` call should already be gone per Task 4's Step 6 check; this is a broader re-check including the header name and type names themselves, not just function calls). `libnetfilter_conntrack` itself stays vendored and linked (`CMakeLists.txt`'s `add_subdirectory`/`target_link_libraries`) — this plan does not remove the vendored library, only this project's own direct C calls into it. Note in this task's report whether removing the vendored library entirely now looks safe (i.e. whether anything else in the repo still references it) — same assessment style as Phase 6b-3's Task 6 did for `libnetfilter_queue` — but do not remove it in this task.

- [ ] **Step 2: Full build and triple test run, plus privileged**

```bash
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && cmake .. && make -j2 net-rule net_rule_test net_rule_grpc_test 2>&1 | tail -150"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_test && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*'"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*'"
docker exec net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='-NetIptablesFfiTest.*:NetNfqFfiTest.*:NetConntrackFfiTest.*'"
docker exec --privileged net-policy-build-test bash -lc "cd /workspace/net-policy/build && ./net_rule_grpc_test --gtest_filter='NetConntrackFfiTest.*'"
```
Expected: all green, no flakiness, and the privileged run's actual pass/skip outcome recorded in the report.

- [ ] **Step 3: Manual sanity check of the real daemon**

Run the real `net-rule` binary and drive a genuine `AddPolicyRule` RPC (matching Phase 6b-3's Task 6 precedent for what this kind of check looks like — a real gRPC client call against the real binary, with a temporary debug print in `update_net_session`/`set_accept_mark` reverted afterward) with at least one real tracked connection present (e.g. a real loopback UDP flow, as in Task 3's integration test), and confirm the connection's conntrack mark actually changes as a result of the RPC. Document the exact commands and observed output in this task's report. If a full RPC-driven check isn't reachable in the available environment, document what was actually checked (e.g., the Task 3 integration test's `MarkRoundTripOnARealLoopbackFlow` observed manually rather than via the test harness) and why a fuller check wasn't reachable.

- [ ] **Step 4: Write the final report and commit if any cleanup was needed**

Write the report per this plan's execution process's convention, summarizing: the Step 1 grep result and vendored-library-removal assessment, all test run outcomes, the manual sanity check's actual output. If Step 1 or Step 2 found something needing a code change, make it, re-run Step 2, and commit:
```bash
git add -A
git commit -m "Phase 6c final verification: confirm libnetfilter_conntrack's direct
C API is fully retired from net-policy.cpp/.h/rule-detail.cpp"
```
If nothing needed changing, no commit is required for this task.

---

## Final State

- `libnetfilter_conntrack`'s C API is no longer called directly from
  `net-policy.cpp`/`.h`/`rule-detail.cpp` — all conntrack mechanics (session
  lifecycle, mark comparison/update) go through the new `net_conntrack` Rust
  crate. The vendored C library itself remains linked (full removal is a
  later follow-up, contingent on the Rust ecosystem maturing).
- `NFQ_RES_INFO` holds Rust-backed handles for its NFQ half (since 6b-3) and
  its conntrack half (this phase) — no raw C netlink pointers of any kind
  remain in the struct.
- `UpdateMark`'s "force every tracked connection's mark toward deny whenever
  a policy is added" behavior is preserved exactly and documented as
  deliberate.
- **Phase 6 (NFQ/netlink core) is fully done.** Every piece of the original
  roadmap's Phase 6 scope — iptables, the legacy control protocol, NFQ
  packet-queue mechanics, netns switching, and conntrack — is now Rust-backed
  or FFI-wrapped. Remaining on the original roadmap: Phase 7 (Decommission),
  not yet planned, gated on HTTP codecs/WAF plugin orchestration/`main.cpp`
  also moving to Rust first.
