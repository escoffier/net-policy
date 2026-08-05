# Why this crate is vendored

This is a vendored, minimally-patched copy of the `nfq` crate, version
0.2.5, as published on crates.io (`nbdd0121/nfq-rs`). Vendored here rather
than depended on directly because 0.2.5 -- the newest version this crate
has ever published -- has no way to expose its underlying netlink socket's
file descriptor: `Queue`'s `fd` field is private, and the crate has no
`AsRawFd` implementation or public accessor for it in this version.

This project's daemon is built entirely around a single-threaded epoll
loop (see `net-policy.cpp`'s `RunNetPolicyDaemon`); every I/O source it
reacts to -- the NFQ queues themselves, the gRPC control-dispatch eventfd,
the periodic reaper timerfd, the post-notification socket -- is registered
into that one `epoll_wait` set via its raw fd. Without a way to read
`Queue`'s fd, this crate cannot be wired into that loop at all.

The crate's own unreleased git `master` branch (commit `fc838b4d`, which
will presumably become 0.2.6 at some point) does add `AsRawFd`/`AsFd` --
but it is a much larger jump than "add one accessor": it bumps to edition
2024 (MSRV 1.85), and it rewrites internal fd handling from raw `libc`
calls onto `OwnedFd`/`rustix`, pulling in `bytes`, `rustix`, and `zerocopy`
as new transitive dependencies. Depending on an unreleased, still-moving
upstream commit for a production build was judged worse than vendoring:
this vendored copy is exactly the tested, published 0.2.5 release plus one
additive, non-invasive method.

## Changes from upstream 0.2.5

Two, both in `src/lib.rs`:

1. One method added to `impl Queue`, immediately before `Queue::open`:

   ```rust
   pub fn as_raw_fd(&self) -> std::os::raw::c_int {
       self.fd
   }
   ```

2. `Message::get_hw_addr` made an implicit reference-through-raw-pointer-deref
   explicit (`&(*self.hwaddr).hw_addr[..len]` -> `&(&(*self.hwaddr).hw_addr)[..len]`).
   Unrelated to the fd accessor: 0.2.5 as published does not compile at all
   under this project's Rust toolchain (1.97.1) without this change --
   `dangerous_implicit_autorefs` is a deny-by-default lint added after 0.2.5
   shipped, and it fires on this exact pattern. Behavior is identical; only
   the reference is spelled out.

Everything else in `src/`, `Cargo.toml`, `LICENSE-APACHE`, `LICENSE-MIT`,
and `README.md` is the unmodified 0.2.5 source as published on crates.io
(fetched via `cargo`'s local registry cache).

## Provenance

- Source: `nfq = "0.2.5"` from crates.io (`nbdd0121/nfq-rs`), MIT/Apache-2.0
  dual-licensed -- both license files are preserved unmodified in this
  directory.
- `crates/net_nfq/Cargo.toml` depends on this vendored copy via a local
  `path` dependency rather than the crates.io version.

## Follow-up

If/when `nbdd0121/nfq-rs` publishes a release with a public fd accessor,
switch `crates/net_nfq/Cargo.toml` back to a normal crates.io version
dependency and delete this directory.
