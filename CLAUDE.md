# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Configure and build (CMake - recommended)
mkdir -p build && cd build
cmake ..
make -j$(nproc)

# Run the main executable
./build/net-rule

# Run all tests
./build/net_rule_test

# Run a single test (Google Test filter)
./build/net_rule_test --gtest_filter=TestSuiteName.TestName

# Legacy Makefile
make all
make clean
```

The build uses C++17, enforces `-Wall -Werror`, and links against llhttp, nghttp2, pcre2, glog, gflags, gperftools, and libunwind. Netlink submodules (libmnl, libnetfilter_queue, libnetfilter_conntrack, libnfnetlink) are vendored under the repo root.

## Architecture Overview

This is a **kernel-integrated network policy enforcement daemon** for containerized workloads (Kubernetes-style pods). It intercepts packets via Linux Netfilter (NFQ), applies Layer 3-4 policy rules, and performs Layer 7 HTTP inspection and WAF filtering.

### Data Flow

```
Kernel Netfilter Hook
    │
    ▼
NFQ (libnetfilter_queue) via EPOLL event loop
    │
    ▼
Five-Tuple extraction (src/dst IP, src/dst port, protocol)
    │
    ├──── Network Policy Match (Layer 3-4) ─── allow/deny/mark verdict
    │
    └──── HTTP Inspection (Layer 7) ──── WAF rule evaluation ─── NF_ACCEPT / NF_DROP
```

### Key Components

| Component | Files | Role |
|-----------|-------|------|
| **Policy Manager** | `net-policy.h`, `net-policy.cpp` | Main entrypoint; owns two `PolicyTree`s (InputTree/OutputTree for ingress/egress); manages NFQ resources per pod; drives EPOLL loop |
| **Rule Matching** | `rule-detail.cpp`, `policy/engine.{h,cc}` | Converts 5-tuple to policy decision; CIDR-aware IP matching; supports DENY/ALLOW/MARK/ALLOW_REQ/ALLOW_RSP actions with priority |
| **HTTP Layer** | `http/http_inspector.{h,cc}`, `http/filter.{h,cc}`, `http/http_filter_factory.{h,cc}` | Protocol detection, header parsing, per-connection HTTP filter chain |
| **HTTP/1.1 Codec** | `http/http1/codec.{h,cc}`, `http/http1/http_parser.{h,c}` | llhttp-based HTTP/1.1 parsing |
| **HTTP/2 Codec** | `http/http2/codec.{hh,cc}` | nghttp2-based HTTP/2 parsing |
| **WAF System** | `waf/plugin.{h,cc}`, `waf/rule.{h,cc}` | PCRE2 regex pattern matching; `PluginRootContext` owns global rules, `PluginContext` is per-connection |
| **Network Filters** | `net/filter.{h,cc}`, `net/filter_factory.{h,cc}`, `net/ip.{h,cc}`, `net/tcp.{h,cc}`, `net/udp.{h,cc}` | Packet-level filtering at IP/TCP/UDP layers |
| **Connection Tracking** | `net/connection_manager.h` | Tracks active TCP/UDP connections |

### Core Data Structures (net-policy.h)

- `PolicyRule` — top-level container; owns `InputTree` (ingress) and `OutputTree` (egress)
- `PolicyTree` — hierarchical rule chain for one traffic direction
- `RuleChain` — flat rule storage indexed by match keys
- `RuleGroup` — collection of rules sharing the same key pattern
- `RuleDetail` — single rule (proto, IP/CIDR, port, action, priority)
- `FiveTuple` — packet identity: (src IP, dst IP, src port, dst port, protocol)

### Control Plane Messages (NET_DATA_TYPE enum)

The daemon receives control messages over a socket on port 9999:
- `POD_PID` / `POD_DIE` — pod lifecycle events
- `ADD_RULE` / `DEL_RULE` — network policy CRUD
- `ADD_WAF_RULE` / `DEL_WAF_RULE` — WAF rule CRUD
- `HEAP_DUMP` / `CONF_DUMP` / `CONN_DUMP` — debugging
- `LOG_LEVEL` / `RESET` — runtime config

### Logging

Macros in `log.h`: `LOG_E()`, `LOG_W()`, `LOG_I()`, `LOG_D()`, `LOG_V()`, `LOG_T()` (Error/Warning/Info/Debug/Verbose/Trace). Controlled by the `gzLogLevel` global at runtime via `LOG_LEVEL` control message.

## Development Environment

A devcontainer is provided (`.devcontainer/`). It uses Ubuntu 22.04 with all build dependencies pre-installed. Open in VS Code with the Remote Containers extension or use `docker build .devcontainer/`.

## Tests

Tests live in `tests/` and use Google Test:
- `http_inspector_test.cc` — HTTP header parsing
- `codec_test.cc` — HTTP/1.1 and HTTP/2 codecs
- `connection_manager_test.cc` — connection tracking
- `http2/` — HTTP/2-specific tests
