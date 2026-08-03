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
