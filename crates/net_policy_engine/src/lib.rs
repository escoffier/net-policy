#[cxx::bridge(namespace = "policy_engine")]
mod ffi {
    extern "Rust" {
        fn policy_engine_ffi_smoke() -> i32;
    }
}

fn policy_engine_ffi_smoke() -> i32 {
    42
}

fn parse_cidr(cidr: &str) -> (String, i32) {
    let (ip_str, mask): (&str, i32) = match cidr.find('/') {
        Some(idx) => (&cidr[..idx], cidr[idx + 1..].parse().unwrap_or(32)),
        None => (cidr, 32),
    };
    let ip_u32: u32 = ip_str.parse::<std::net::Ipv4Addr>().map(u32::from).unwrap_or(0);
    let net_mask: u32 = (!0u32).wrapping_shl((32 - mask) as u32);
    let masked = ip_u32 & net_mask;
    (std::net::Ipv4Addr::from(masked).to_string(), mask)
}

fn ipv4_cidr_to_ip(ip: &str, mask: i32) -> String {
    let ip_u32: u32 = ip.parse::<std::net::Ipv4Addr>().map(u32::from).unwrap_or(0);
    let net_mask: u32 = (!0u32).wrapping_shl((32 - mask) as u32);
    std::net::Ipv4Addr::from(ip_u32 & net_mask).to_string()
}

use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlowDir {
    Ingress,
    Egress,
}

#[derive(Clone, Debug)]
struct RulePort {
    end_port: u16,
    port: u16,
    proto: u8,
}

#[derive(Clone, Debug)]
struct RuleDetail {
    proto: u8,
    priority: i32,
    addr_type: i32,
    direction: FlowDir,
    action: u32,
    action_dsc: String,
    policy_key: String,
    src_ip: String,
    dst_ip: String,
    ports: Vec<RulePort>,
}

const IPPROTO_ICMP: u8 = 1;

impl RuleDetail {
    /// Mirrors RuleDetail::CreateRuleKey (rule-detail.cpp) exactly, including
    /// which address gets CIDR-masked per direction.
    fn create_rule_key(&self) -> (String, i32) {
        match self.direction {
            FlowDir::Ingress => {
                let (ip, mask) = parse_cidr(&self.src_ip);
                (format!("{}-{}-{}/{}-{}", self.priority, self.proto, ip, mask, self.dst_ip), mask)
            }
            FlowDir::Egress => {
                let (ip, mask) = parse_cidr(&self.dst_ip);
                (format!("{}-{}-{}-{}/{}", self.priority, self.proto, self.src_ip, ip, mask), mask)
            }
        }
    }

    /// Mirrors RuleDetail::MatchRuleDetail exactly, including the ICMP
    /// protocol special-case (packet protocol is overwritten with the rule's
    /// own proto before comparing, forcing the protocol check to pass for
    /// ICMP regardless of the rule's configured protocol), the
    /// end_port == 0 "any port" sentinel, and the DNS (port 53) short-circuit.
    fn matches(&self, proto: u8, dst_port: u16, src_port: u16) -> bool {
        let mut protocol = proto;
        if protocol == IPPROTO_ICMP {
            protocol = self.proto;
        }
        if !(self.proto == 0 || protocol == self.proto) {
            return false;
        }
        let mut is_match = self.ports.is_empty() || proto == IPPROTO_ICMP;
        for port in &self.ports {
            if port.end_port == 0 {
                is_match = true;
                break;
            }
            if dst_port > port.end_port {
                continue;
            }
            if dst_port < port.port {
                continue;
            }
            is_match = true;
            break;
        }
        if !is_match {
            return false;
        }
        if src_port == 53 || dst_port == 53 {
            return true;
        }
        true
    }
}

struct RuleGroup {
    /// keyed by policy_key, mirroring RuleGroup::rules_
    rules: HashMap<String, RuleDetail>,
}

impl RuleGroup {
    fn new() -> Self {
        RuleGroup { rules: HashMap::new() }
    }

    /// Mirrors RuleGroup::AddRuleDetail: clears the incoming rule's ports,
    /// then either inserts it fresh (with just the one port) or, if a rule
    /// with the same policy_key already exists in this group, appends the
    /// port to the existing entry's port list instead of overwriting it.
    fn add_rule_detail(&mut self, mut rule: RuleDetail, port: RulePort) {
        rule.ports.clear();
        match self.rules.get_mut(&rule.policy_key) {
            None => {
                rule.ports.push(port);
                self.rules.insert(rule.policy_key.clone(), rule);
            }
            Some(existing) => {
                existing.ports.push(port);
            }
        }
    }

    fn delete_rule(&mut self, policy_name: &str) {
        self.rules.remove(policy_name);
    }

    /// Mirrors RuleGroup::MatchRule. Iteration order over `rules` is a
    /// HashMap here (vs. C++'s std::unordered_map) -- if a generated test
    /// case has multiple genuinely overlapping rules in the same group, the
    /// two implementations may legitimately disagree on which one "wins",
    /// since neither language guarantees hash-iteration order. This is
    /// expected and handled by Task 6's differential-test design, not a bug
    /// to fix here.
    fn match_rule(&self, proto: u8, dst_port: u16, src_port: u16) -> Option<RuleDetail> {
        self.rules.values().find(|r| r.matches(proto, dst_port, src_port)).cloned()
    }

    fn size(&self) -> usize {
        self.rules.len()
    }
}

struct RuleChain {
    dir: FlowDir,
    /// keyed by rule key (RuleDetail::create_rule_key's output), mirroring
    /// RuleChain::chain_
    chain: HashMap<String, RuleGroup>,
}

impl RuleChain {
    fn new(dir: FlowDir) -> Self {
        RuleChain { dir, chain: HashMap::new() }
    }

    fn size(&self) -> usize {
        self.chain.len()
    }

    fn clear(&mut self) {
        self.chain.clear();
    }

    fn match_rule_group(&self, key: &str, proto: u8, dst_port: u16, src_port: u16) -> Option<RuleDetail> {
        self.chain.get(key)?.match_rule(proto, dst_port, src_port)
    }

    fn add_rule_to_chain(&mut self, key: String, policy: RuleDetail, port: RulePort) {
        self.chain.entry(key).or_insert_with(RuleGroup::new).add_rule_detail(policy, port);
    }

    /// Mirrors RuleChain::DeleteRuleFromChain: removes the named rule from
    /// the group at `rule_key`, then removes the whole group if it's now
    /// empty (mirroring the C++ behavior exactly -- an empty group is
    /// pruned, not left as a dangling empty entry).
    fn delete_rule_from_chain(&mut self, policy_name: &str, rule_key: &str) {
        if let Some(group) = self.chain.get_mut(rule_key) {
            group.delete_rule(policy_name);
            if group.size() == 0 {
                self.chain.remove(rule_key);
            }
        }
    }
}

struct PolicyTree {
    chain: RuleChain,
    /// policy_key -> {rule_key: dir}, mirroring PolicyTree::tree_
    tree: HashMap<String, HashMap<String, FlowDir>>,
}

impl PolicyTree {
    fn new(dir: FlowDir) -> Self {
        PolicyTree { chain: RuleChain::new(dir), tree: HashMap::new() }
    }

    fn size(&self) -> usize {
        self.chain.size()
    }

    fn tree_size(&self) -> usize {
        self.tree.len()
    }

    fn clear(&mut self) {
        self.tree.clear();
        self.chain.clear();
    }

    /// Mirrors PolicyTree::AddPolicyToChain: derives the rule key from the
    /// policy (mask is discarded here -- the caller, PolicyRule, extracts it
    /// separately for AddMaskAndPriority), adds to the chain, then records
    /// the {rule_key: direction} mapping under this policy_key for later
    /// deletion.
    fn add_policy_to_chain(&mut self, policy: RuleDetail, port: RulePort) {
        let (key, _mask) = policy.create_rule_key();
        let direction = policy.direction;
        let policy_key = policy.policy_key.clone();
        self.chain.add_rule_to_chain(key.clone(), policy, port);
        self.tree.entry(policy_key).or_default().insert(key, direction);
    }

    /// Mirrors PolicyTree::DeletePolicyFromTree: removes every chain entry
    /// this policy_key ever added, then clears the whole tree if nothing is
    /// left (mirroring the C++ behavior exactly).
    fn delete_policy_from_tree(&mut self, name: &str) {
        let Some(rules) = self.tree.remove(name) else {
            return;
        };
        for key in rules.keys() {
            self.chain.delete_rule_from_chain(name, key);
        }
        if self.tree.is_empty() {
            self.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_masks_to_network_address() {
        assert_eq!(parse_cidr("10.1.2.3/24"), ("10.1.2.0".to_string(), 24));
        assert_eq!(parse_cidr("192.168.5.9/16"), ("192.168.0.0".to_string(), 16));
    }

    #[test]
    fn parse_cidr_bare_ip_defaults_to_slash_32() {
        assert_eq!(parse_cidr("10.1.2.3"), ("10.1.2.3".to_string(), 32));
    }

    #[test]
    fn parse_cidr_slash_32_is_identity() {
        assert_eq!(parse_cidr("10.1.2.3/32"), ("10.1.2.3".to_string(), 32));
    }

    #[test]
    fn ipv4_cidr_to_ip_masks_to_network_address() {
        assert_eq!(ipv4_cidr_to_ip("10.1.2.3", 24), "10.1.2.0");
        assert_eq!(ipv4_cidr_to_ip("10.1.2.3", 32), "10.1.2.3");
    }
}

#[cfg(test)]
mod policy_tree_tests {
    use super::*;

    fn sample_rule(policy_key: &str, priority: i32, proto: u8, dir: FlowDir, src: &str, dst: &str) -> RuleDetail {
        RuleDetail {
            proto,
            priority,
            addr_type: 0,
            direction: dir,
            action: 1,
            action_dsc: String::new(),
            policy_key: policy_key.to_string(),
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            ports: Vec::new(),
        }
    }

    #[test]
    fn match_rule_detail_any_port_sentinel() {
        let mut rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        rule.ports.push(RulePort { end_port: 0, port: 0, proto: 6 });
        assert!(rule.matches(6, 9999, 12345));
    }

    #[test]
    fn match_rule_detail_port_range() {
        let mut rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        rule.ports.push(RulePort { end_port: 8080, port: 8000, proto: 6 });
        assert!(rule.matches(6, 8050, 12345));
        assert!(!rule.matches(6, 9000, 12345));
    }

    #[test]
    fn match_rule_detail_icmp_ignores_configured_protocol() {
        let rule = sample_rule("p1", 10, 6 /* TCP */, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        // packet protocol is ICMP (1); the ICMP special-case in matches()
        // overwrites it with the rule's own proto (6) before comparing, so
        // this must match despite the rule being configured for TCP.
        assert!(rule.matches(IPPROTO_ICMP, 0, 0));
    }

    // NOTE: deviates from the task-3-brief.md Step 2 test, which asserted
    // `rule.matches(6, 53, 12345)` is true here and named this test
    // "..._bypasses_port_list". Verified against rule-detail.cpp
    // (RuleDetail::MatchRuleDetail, lines ~233-236): `if(!bIsMatch) return
    // false;` runs BEFORE the `src_port_ == 53 || dst_port_ == 53` DNS
    // check, so DNS traffic does NOT bypass the port-range match -- the DNS
    // check only ever fires once bIsMatch is already true (in which case
    // the function returns true regardless of the DNS check). In the C++
    // original the DNS check's real purpose is to skip a debug-log
    // statement that indexes `ports_.at(p)`, which would be out-of-bounds
    // when ports_ is empty; it has no effect on the match outcome. This
    // implementation mirrors that faithfully, so a DNS-port packet against
    // a rule whose configured port range excludes port 53 correctly does
    // NOT match.
    #[test]
    fn match_rule_detail_dns_port_does_not_bypass_port_range() {
        let mut rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        rule.ports.push(RulePort { end_port: 9999, port: 9000, proto: 6 });
        assert!(!rule.matches(6, 53, 12345));
    }

    #[test]
    fn match_rule_detail_dns_port_matches_when_in_range() {
        // When bIsMatch is already true via the port-range check, the DNS
        // check is a no-op (the function returns true either way).
        let mut rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        rule.ports.push(RulePort { end_port: 60, port: 50, proto: 6 });
        assert!(rule.matches(6, 53, 12345));
    }

    #[test]
    fn policy_tree_add_then_match_ingress() {
        let mut tree = PolicyTree::new(FlowDir::Ingress);
        let rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        let (key, _mask) = rule.create_rule_key();
        tree.add_policy_to_chain(rule, RulePort { end_port: 0, port: 0, proto: 6 });
        let matched = tree.chain.match_rule_group(&key, 6, 80, 12345);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().policy_key, "p1");
    }

    #[test]
    fn policy_tree_delete_removes_all_chain_entries_for_policy() {
        let mut tree = PolicyTree::new(FlowDir::Ingress);
        let rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        let (key, _mask) = rule.create_rule_key();
        tree.add_policy_to_chain(rule, RulePort { end_port: 0, port: 0, proto: 6 });
        assert_eq!(tree.size(), 1);
        tree.delete_policy_from_tree("p1");
        assert_eq!(tree.size(), 0);
        assert!(tree.chain.match_rule_group(&key, 6, 80, 12345).is_none());
    }

    #[test]
    fn rule_group_add_rule_detail_appends_port_for_existing_policy() {
        let mut group = RuleGroup::new();
        let rule = sample_rule("p1", 10, 6, FlowDir::Ingress, "10.0.0.0/8", "1.2.3.4");
        group.add_rule_detail(rule.clone(), RulePort { end_port: 100, port: 100, proto: 6 });
        group.add_rule_detail(rule, RulePort { end_port: 200, port: 200, proto: 6 });
        assert_eq!(group.rules.get("p1").unwrap().ports.len(), 2);
    }
}
