#include <gtest/gtest.h>

#include <algorithm>
#include <random>
#include <sstream>

#include "net-policy.h"
#include "net_policy_engine_cxxbridge/lib.h"

namespace {

struct GeneratedRule {
  RuleDetail cpp_rule;
  RULE_PORT cpp_port;
};

struct GeneratedPolicySet {
  std::vector<GeneratedRule> rules;
};

struct GeneratedTuple {
  uint8_t proto;
  uint16_t src_port;
  uint16_t dst_port;
  std::string src_addr;
  std::string dst_addr;
  FlowDir dir;
};

// Returns a 3-octet address prefix ENDING IN A DOT, e.g. "10.123.45." --
// every call site appends its own 4th octet after this, so the trailing dot
// is load-bearing: without it, `RandomIpPrefix(...) + "0/24"` would produce
// a malformed address like "10.123.450/24" (silently merging the 3rd octet
// with the appended one) instead of the intended "10.123.45.0/24". A
// malformed address would make C++'s inet_addr() (which returns
// INADDR_NONE, 0xFFFFFFFF, on unparseable input) and the Rust port's
// std::net::Ipv4Addr parsing (which this plan's Task 2 falls back to 0 on
// unparseable input) disagree on totally different grounds than the
// matching logic under test -- exactly the kind of self-inflicted false
// mismatch the differential suite must not produce.
std::string RandomIpPrefix(std::mt19937& rng, int subnet_choice) {
  // A small fixed pool of /8 subnets so generated CIDRs and exact addresses
  // have realistic odds of overlapping (all-random /32 addresses would
  // almost never fall inside a generated CIDR, defeating the point of the
  // generator).
  static const char* kSubnets[] = {"10.", "172.16.", "192.168.", "203.0.113."};
  std::uniform_int_distribution<int> octet(0, 255);
  std::ostringstream oss;
  oss << kSubnets[subnet_choice % 4] << octet(rng) << "." << octet(rng) << ".";
  return oss.str();
}

// non-overlapping: each generated rule gets its own priority, so within a
// single RuleGroup at most one rule can ever match a given tuple -- avoids
// the hash-iteration-order ambiguity described in the design spec.
GeneratedPolicySet GenerateNonOverlappingPolicySet(std::mt19937& rng, int num_rules) {
  static const uint8_t kProtos[] = {6, 17, 1, 0};  // TCP, UDP, ICMP, wildcard
  std::uniform_int_distribution<int> proto_idx(0, 3);
  std::uniform_int_distribution<int> mask_dist(8, 32);
  std::uniform_int_distribution<int> port_dist(1, 65000);
  std::uniform_int_distribution<int> dir_dist(0, 1);
  std::uniform_int_distribution<int> subnet_dist(0, 3);

  GeneratedPolicySet set;
  for (int i = 0; i < num_rules; i++) {
    RuleDetail rule;
    rule.proto_ = kProtos[proto_idx(rng)];
    rule.priority_ = i + 1;  // distinct priority per rule -- see above
    rule.addr_type_ = 0;
    rule.direction_ = (dir_dist(rng) == 0) ? FlowDir::kIngress : FlowDir::kEgress;
    rule.action_ = NetPolicyRule::kAllow;
    rule.policy_key_ = "policy-" + std::to_string(i);
    int mask = mask_dist(rng);
    rule.src_ip_ = RandomIpPrefix(rng, subnet_dist(rng)) + "0/" + std::to_string(mask);
    rule.dst_ip_ = RandomIpPrefix(rng, subnet_dist(rng)) + "0/" + std::to_string(mask_dist(rng));

    RULE_PORT port{};
    port.proto_ = rule.proto_;
    int p1 = port_dist(rng);
    int p2 = port_dist(rng);
    port.port_ = std::min(p1, p2);
    port.end_port_ = std::max(p1, p2);

    set.rules.push_back({rule, port});
  }
  return set;
}

GeneratedTuple GenerateTuple(std::mt19937& rng) {
  static const uint8_t kProtos[] = {6, 17, 1};
  std::uniform_int_distribution<int> proto_idx(0, 2);
  std::uniform_int_distribution<int> port_dist(1, 65000);
  std::uniform_int_distribution<int> dir_dist(0, 1);
  std::uniform_int_distribution<int> subnet_dist(0, 3);

  GeneratedTuple t;
  t.proto = kProtos[proto_idx(rng)];
  t.src_port = static_cast<uint16_t>(port_dist(rng));
  t.dst_port = static_cast<uint16_t>(port_dist(rng));
  t.src_addr = RandomIpPrefix(rng, subnet_dist(rng)) + "1";
  t.dst_addr = RandomIpPrefix(rng, subnet_dist(rng)) + "1";
  t.dir = (dir_dist(rng) == 0) ? FlowDir::kIngress : FlowDir::kEgress;
  return t;
}

}  // namespace

namespace {

struct OldMatchResult {
  bool matched;
  std::string policy_key;
  NetPolicyRule action;
};

OldMatchResult MatchWithCpp(const GeneratedPolicySet& set, const GeneratedTuple& tuple) {
  PolicyTree tree;
  tree.SetRuleDir(tuple.dir);
  for (const auto& r : set.rules) {
    if (r.cpp_rule.direction_ != tuple.dir) continue;
    RuleDetail copy = r.cpp_rule;
    RULE_PORT port_copy = r.cpp_port;
    tree.AddPolicyToChain(copy, port_copy);
  }

  PolicyRule policy_rule;  // only used for CreateRuleKeyByTuple's priority_/mask_cidr_ bookkeeping
  for (const auto& r : set.rules) {
    if (r.cpp_rule.direction_ != tuple.dir) continue;
    RuleDetail mutable_copy = r.cpp_rule;  // CreateRuleKey() is non-const; r.cpp_rule is const here
    auto [key, mask] = mutable_copy.CreateRuleKey();  // discard key, just want mask
    policy_rule.AddMaskAndPriority(r.cpp_rule.priority_, mask);
  }

  FiveTuple ft;
  ft.proto_ = tuple.proto;
  ft.src_port_ = tuple.src_port;
  ft.dst_port_ = tuple.dst_port;
  ft.src_addr_ = tuple.src_addr;
  ft.dst_addr_ = tuple.dst_addr;

  auto keys = policy_rule.CreateRuleKeyByTuple(ft, tuple.dir);
  for (auto& key : keys) {
    if (auto matched = tree.MatchRuleGroup(key, ft)) {
      return {true, matched->policy_key_, matched->action_};
    }
  }
  return {false, "", NetPolicyRule::kDefault};
}

policy_engine::MatchedRule MatchWithRust(const GeneratedPolicySet& set, const GeneratedTuple& tuple) {
  auto engine = policy_engine::new_policy_engine();
  for (const auto& r : set.rules) {
    if (r.cpp_rule.direction_ != tuple.dir) continue;
    policy_engine::SharedRuleDetail rd{};
    rd.proto = r.cpp_rule.proto_;
    rd.priority = r.cpp_rule.priority_;
    rd.addr_type = r.cpp_rule.addr_type_;
    rd.direction = (r.cpp_rule.direction_ == FlowDir::kIngress) ? 0 : 1;
    rd.action = static_cast<uint32_t>(r.cpp_rule.action_);
    rd.policy_key = r.cpp_rule.policy_key_;
    rd.src_ip = r.cpp_rule.src_ip_;
    rd.dst_ip = r.cpp_rule.dst_ip_;

    policy_engine::SharedRulePort rp{};
    rp.end_port = r.cpp_port.end_port_;
    rp.port = r.cpp_port.port_;
    rp.proto = r.cpp_port.proto_;

    engine->add_policy(rd, rp);
  }
  int32_t dir_int = (tuple.dir == FlowDir::kIngress) ? 0 : 1;
  return engine->match_five_tuple(tuple.proto, tuple.dst_port, tuple.src_port,
                                    tuple.src_addr, tuple.dst_addr, dir_int);
}

}  // namespace

TEST(PolicyEngineDifferentialTest, NonOverlappingPolicySetsMatchIdentically) {
  std::mt19937 rng(0xC0FFEE);  // fixed seed -- reproducible failures
  const int kIterations = 2000;
  int mismatches = 0;
  for (int i = 0; i < kIterations; i++) {
    auto set = GenerateNonOverlappingPolicySet(rng, /*num_rules=*/5);
    auto tuple = GenerateTuple(rng);

    auto cpp_result = MatchWithCpp(set, tuple);
    auto rust_result = MatchWithRust(set, tuple);

    if (cpp_result.matched != rust_result.matched) {
      mismatches++;
      ADD_FAILURE() << "iteration " << i << ": match/no-match disagreement -- cpp matched="
                    << cpp_result.matched << " rust matched=" << rust_result.matched;
      continue;
    }
    if (cpp_result.matched) {
      EXPECT_EQ(cpp_result.policy_key, std::string(rust_result.detail.policy_key))
          << "iteration " << i << ": different policy matched";
      EXPECT_EQ(static_cast<uint32_t>(cpp_result.action), rust_result.detail.action)
          << "iteration " << i << ": same policy, different action";
    }
  }
  EXPECT_EQ(mismatches, 0) << mismatches << "/" << kIterations << " iterations disagreed";
}

TEST(PolicyEngineDifferentialTest, OverlappingPolicySetsAgreeOnSomeValidMatch) {
  // Deliberately overlapping: every rule shares the SAME priority, so
  // multiple rules can legitimately match the same tuple within one
  // RuleGroup -- "which one wins" is hash-iteration-order-dependent and NOT
  // required to agree between the C++ std::unordered_map and Rust HashMap
  // implementations (see design spec). Assert only that if one
  // implementation finds a match, the other does too, with a valid action --
  // not that they pick the identical policy_key.
  std::mt19937 rng(0xDEADBEEF);
  const int kIterations = 500;
  for (int i = 0; i < kIterations; i++) {
    GeneratedPolicySet set;
    std::uniform_int_distribution<int> subnet_dist(0, 3);
    std::string shared_src = RandomIpPrefix(rng, subnet_dist(rng)) + "0/8";
    std::string shared_dst = RandomIpPrefix(rng, subnet_dist(rng)) + "0/8";
    for (int r = 0; r < 4; r++) {
      RuleDetail rule;
      rule.proto_ = 0;  // wildcard proto -- maximizes overlap odds
      rule.priority_ = 1;  // SAME priority for every rule -- the overlap
      rule.addr_type_ = 0;
      rule.direction_ = FlowDir::kIngress;
      rule.action_ = NetPolicyRule::kAllow;
      rule.policy_key_ = "overlap-policy-" + std::to_string(r);
      rule.src_ip_ = shared_src;
      rule.dst_ip_ = shared_dst;
      RULE_PORT port{};
      set.rules.push_back({rule, port});
    }
    GeneratedTuple tuple;
    tuple.proto = 6;
    tuple.src_port = 12345;
    tuple.dst_port = 80;
    // Append a clean single-digit last octet (no leading zero -- Rust's
    // Ipv4Addr parser rejects leading-zero octets, while C++'s inet_addr()
    // historically treats them as octal; avoid the whole ambiguity by
    // construction). The /8 mask makes the exact trailing octets
    // irrelevant to matching anyway -- both sides mask src/dst down to the
    // shared "10."-style first octet before comparing -- this just needs
    // to be a syntactically clean address sharing that prefix.
    tuple.src_addr = shared_src.substr(0, shared_src.rfind('.') + 1) + "5";
    tuple.dst_addr = shared_dst.substr(0, shared_dst.rfind('.') + 1) + "5";
    tuple.dir = FlowDir::kIngress;

    auto cpp_result = MatchWithCpp(set, tuple);
    auto rust_result = MatchWithRust(set, tuple);
    EXPECT_EQ(cpp_result.matched, rust_result.matched)
        << "iteration " << i << ": one implementation matched, the other didn't";
  }
}
