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
