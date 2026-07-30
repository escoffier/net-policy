#include <gtest/gtest.h>
#include "waf/rule.h"

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

// Regression test for the final-review fix: MatchDomain forwards `src` (the
// Host/authority header, attacker-controlled) straight into a
// waf_rules::match_domain FFI call taking a rust::Str, which previously
// threw std::invalid_argument uncaught on invalid UTF-8, crashing the
// daemon. MatchDomain must now fail closed (return false) instead.
TEST(WafRulesTest, MatchDomainReturnsFalseOnInvalidUtf8SrcInsteadOfCrashing) {
  Rules rules;
  rules.InitRule();
  std::string a = "example.com";
  rules.AddDomain(a);

  std::string src = "example";
  src += '\xFF';
  EXPECT_FALSE(rules.MatchDomain(src));
}

// Regression test: isIPAddress (waf/plugin.cc's domain-is-literal-IP check
// on the Host header) forwards attacker-controlled bytes straight into
// waf_rules::is_ip_address, which previously threw uncaught on invalid
// UTF-8. It is the FIRST FFI call on every request.
TEST(WafRulesTest, IsIPAddressReturnsFalseOnInvalidUtf8InsteadOfCrashing) {
  std::string src = "abc";
  src += '\xFF';
  EXPECT_FALSE(isIPAddress(src));
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

// Regression test for the final-review fix: MatchIgnoreType is called on
// essentially every request (the always-reached default path) and forwards
// `src` (the request path, attacker-controlled) straight into a
// waf_rules::match_ignore_type FFI call taking a rust::Str. A lone
// continuation-style byte (0xFF here, with no valid UTF-8 lead byte) is
// invalid UTF-8 on its own and previously threw std::invalid_argument
// uncaught, crashing the daemon via std::terminate on a single crafted
// request. MatchIgnoreType must now fail closed (return false) instead.
TEST(WafRulesTest, MatchIgnoreTypeReturnsFalseOnInvalidUtf8SrcInsteadOfCrashing) {
  Rules rules;
  rules.InitRule();
  std::string jpg = ".jpg";
  rules.AddIgnoreType(jpg);

  std::string src = "/static/logo";
  src += '\xFF';
  EXPECT_FALSE(rules.MatchIgnoreType(src));
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

// Regression test for Task 13's security fix: a lone continuation-style byte
// (0xFF here) with no valid UTF-8 lead byte is invalid UTF-8 on its own.
// Rules::Pcre2Regex converts src into a rust::Str for the FFI call into Rust,
// which performs UTF-8 validation and throws std::invalid_argument on
// malformed input; Pcre2Regex must catch that and report "no match" instead
// of letting the exception escape and crash the daemon.
TEST(WafRulesTest, Pcre2RegexReturnsNulloptOnInvalidUtf8SrcInsteadOfCrashing) {
  Rules rules;
  std::string expr = "\\d+";
  std::string src = "abc";
  src += '\xFF';
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

// MatchForceWhiteList always returns true (only policy.action_ differs
// between match and no-match), so the test above alone can't tell a real
// match from a broken always-true implementation. This is the negative half
// of that pair: a non-matching IP against the same CIDR entry must report
// ATCTION_DROP.
TEST(WafRulesTest, MatchForceWhiteListNonMatchingCidrReturnsDropAction) {
  Rules rules;
  rules.InitRule();
  BWList bw;
  bw.mode_ = "strong-white";
  bw.expr_ = "10.0.0.0/8";
  rules.AddForceWhiteList(bw);

  std::vector<std::string> ips = {"192.168.1.1"};
  std::string path = "/anything";
  BWList policy;
  EXPECT_TRUE(rules.MatchForceWhiteList(ips, path, policy));
  EXPECT_EQ(policy.action_, ATCTION_DROP);
}

// Regression test for the final-review fix: MatchForceWhiteList's CIDR case
// calls waf_rules::ipv4_network_address(ip, mask) for each candidate IP,
// where `ip` comes from the X-Forwarded-For-derived `ips` vector and may be
// invalid UTF-8. An invalid IP must be skipped (treated as non-matching)
// rather than crash, and matching must still succeed against a later, valid
// IP in the same list.
TEST(WafRulesTest, MatchForceWhiteListSkipsInvalidUtf8IpInsteadOfCrashing) {
  Rules rules;
  rules.InitRule();
  BWList bw;
  bw.mode_ = "strong-white";
  bw.expr_ = "10.0.0.0/8";
  rules.AddForceWhiteList(bw);

  std::string bad_ip = "1.2.3.";
  bad_ip += '\xFF';
  std::vector<std::string> ips = {bad_ip, "10.1.2.3"};
  std::string path = "/anything";
  BWList policy;
  EXPECT_TRUE(rules.MatchForceWhiteList(ips, path, policy));
  EXPECT_EQ(policy.action_, ACTION_BYPASS);
  EXPECT_EQ(policy.mode_, "10.1.2.3");
}

// Same guard, but for MatchBlackWhiteList's CIDR case (a separate call site
// hitting the same waf_rules::ipv4_network_address FFI call).
TEST(WafRulesTest, MatchBlackWhiteListCidrSkipsInvalidUtf8IpInsteadOfCrashing) {
  Rules rules;
  rules.InitRule();
  BWList bw;
  bw.mode_ = "black";
  bw.expr_ = "(ip CIDR \"10.0.0.0/8\")";
  rules.AddBlackWhiteList(bw);

  std::string bad_ip = "1.2.3.";
  bad_ip += '\xFF';
  std::vector<std::string> ips = {bad_ip, "10.1.2.3"};
  std::string path = "/anything";
  BWList policy;
  EXPECT_TRUE(rules.MatchBlackWhiteList(ips, path, policy));
  EXPECT_EQ(policy.action_, ATCTION_DROP);
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

// The test above uses a single-component rule: MatchBlackWhiteList's
// aCount==0 fast path handles it and eval_bool_expr is never called. A rule
// combining a single operator type (e.g. only "&&") ALSO short-circuits via
// the orNum==0 "all && operation expression" fast path -- so even a
// naively "compound" `A && B` rule bypasses eval_bool_expr too. Only a
// genuinely MIXED expression (both && and || present) falls through to the
// bottom "replace and eval" branch that calls waf_rules::eval_bool_expr.
// This test uses such a mixed rule and asserts (at runtime, via
// policy.oprexpr_) that the compiled expression really is mixed before
// trusting the match result -- confirming this exercises the real
// C++ -> Rust eval_bool_expr handoff, not one of the fast paths.
TEST(WafRulesTest, MatchBlackWhiteListEvaluatesCompoundAndOrExpressionViaEvalBoolExpr) {
  Rules rules;
  rules.InitRule();
  BWList bw;
  bw.mode_ = "black";
  bw.expr_ = "(path matches \"^/admin\") && (ip == \"1.2.3.4\") || (ip == \"9.9.9.9\")";
  rules.AddBlackWhiteList(bw);

  // Positive: path matches and the first ip matches (the && operand is
  // true), so regardless of how the || combines, the overall result must be
  // true.
  {
    std::vector<std::string> ips = {"1.2.3.4"};
    std::string path = "/admin/delete-everything";
    BWList policy;
    bool matched = rules.MatchBlackWhiteList(ips, path, policy);
    ASSERT_NE(policy.oprexpr_.find("&&"), std::string::npos)
        << "expected a genuinely mixed oprexpr_, got: " << policy.oprexpr_;
    ASSERT_NE(policy.oprexpr_.find("||"), std::string::npos)
        << "expected a genuinely mixed oprexpr_, got: " << policy.oprexpr_;
    EXPECT_TRUE(matched);
    EXPECT_EQ(policy.action_, ATCTION_DROP);
  }

  // Negative: path doesn't match and neither ip matches -- all three
  // operands are false, so "(false)&&(false)||(false)" must be false no
  // matter how && vs || are grouped.
  {
    std::vector<std::string> ips = {"8.8.8.8"};
    std::string path = "/public/index.html";
    BWList policy;
    bool matched = rules.MatchBlackWhiteList(ips, path, policy);
    ASSERT_NE(policy.oprexpr_.find("&&"), std::string::npos);
    ASSERT_NE(policy.oprexpr_.find("||"), std::string::npos);
    EXPECT_FALSE(matched);
  }
}
