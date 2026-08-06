// common/utf8_check.h
#pragma once

#include <stdexcept>
#include <string>

#include "rust/cxx.h"

// rust::Str requires valid UTF-8 and throws std::invalid_argument
// otherwise. Attacker-controlled bytes (HTTP path/Host/X-Forwarded-For,
// request bodies, five-tuple-derived strings, WAF attack payloads) carry
// no such guarantee, so every call site constructing a rust::Str/rust::String
// from such data must check this first and fail closed (skip/no-match)
// rather than let the exception escape uncaught and crash the daemon via
// std::terminate. Kept at global scope (not inside a namespace) so
// existing bare-name call sites (e.g. rule-detail.cpp) don't need to change
// when this moves out of its old anonymous namespace.
inline bool IsValidUtf8(const std::string& s) {
    try {
        (void)rust::Str(s);
        return true;
    } catch (const std::invalid_argument&) {
        return false;
    }
}
