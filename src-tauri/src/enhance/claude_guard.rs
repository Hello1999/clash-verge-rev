use serde_yaml_ng::{Mapping, Value};

pub const OUTBOUND: &str = "CV Claude Protected";
pub const GATEWAY_PORT: u16 = 17891;
pub const EXPECTED_EXIT: &str = "103.5.250.92";
const PROTECTED_DNS: &str = "https://8.8.8.8/dns-query#CV Claude Protected";
pub const DOMAINS: &[&str] = &[
    "claude.ai",
    "claude.com",
    "anthropic.com",
    "claudeusercontent.com",
    "anthropicusercontent.com",
];

pub fn check_mode(enabled: bool, mode: &str) -> Result<(), &'static str> {
    if enabled && mode != "rule" {
        return Err("Claude exit protection requires rule mode. Disable protection before changing modes.");
    }
    Ok(())
}

pub fn enforce(config: &mut Mapping) {
    config.insert("mode".into(), "rule".into());
    let mut proxies = config
        .get("proxies")
        .and_then(Value::as_sequence)
        .cloned()
        .unwrap_or_default();
    proxies.retain(|proxy| proxy.get("name").and_then(Value::as_str) != Some(OUTBOUND));
    let chain_active = config
        .get("proxy-groups")
        .and_then(Value::as_sequence)
        .is_some_and(|groups| {
            groups
                .iter()
                .any(|group| group.get("name").and_then(Value::as_str) == Some(super::auto_chain::GROUP))
        });
    let mut gateway = Mapping::new();
    gateway.insert("name".into(), OUTBOUND.into());
    if chain_active {
        gateway.insert("type".into(), "select".into());
        gateway.insert("proxies".into(), vec![Value::from(super::auto_chain::GROUP)].into());
    } else {
        gateway.insert("type".into(), "http".into());
        gateway.insert("server".into(), "127.0.0.1".into());
        gateway.insert("port".into(), GATEWAY_PORT.into());
        proxies.push(Value::Mapping(gateway.clone()));
    }
    config.insert("proxies".into(), proxies.into());

    if let Some(Value::Sequence(groups)) = config.get_mut("proxy-groups") {
        groups.retain(|group| group.get("name").and_then(Value::as_str) != Some(OUTBOUND));
        if chain_active {
            groups.push(gateway.into());
        }
    }

    let mut rules: Vec<Value> = DOMAINS
        .iter()
        // Unsupported UDP must be rejected explicitly: some cores skip non-UDP outbounds.
        .map(|domain| format!("AND,((DOMAIN-SUFFIX,{domain}),(NETWORK,UDP)),REJECT").into())
        .chain(
            DOMAINS
                .iter()
                .map(|domain| format!("DOMAIN-SUFFIX,{domain},{OUTBOUND}").into()),
        )
        .collect();
    if let Some(existing) = config.get("rules").and_then(Value::as_sequence) {
        for rule in existing {
            if !rules.contains(rule) {
                rules.push(rule.clone());
            }
        }
    }
    config.insert("rules".into(), rules.into());
    enforce_dns(config);
}

fn enforce_dns(config: &mut Mapping) {
    let mut dns = config
        .get("dns")
        .and_then(Value::as_mapping)
        .cloned()
        .unwrap_or_default();
    dns.insert("enable".into(), true.into());
    // The protected HTTP gateway carries TCP only; HTTP/3 cannot use this path.
    dns.insert("prefer-h3".into(), false.into());
    dns.insert("direct-nameserver-follow-policy".into(), true.into());
    if dns
        .get("nameserver")
        .and_then(Value::as_sequence)
        .is_none_or(Vec::is_empty)
    {
        dns.insert("nameserver".into(), vec![Value::from("system")].into());
    }
    for field in ["nameserver-policy", "proxy-server-nameserver-policy"] {
        if field == "proxy-server-nameserver-policy"
            && dns
                .get("proxy-server-nameserver")
                .and_then(Value::as_sequence)
                .is_none_or(Vec::is_empty)
        {
            dns.remove(field);
            continue;
        }
        let mut policy = Mapping::new();
        if let Some(existing) = dns.get(field).and_then(Value::as_mapping) {
            for (key, value) in existing {
                if let Some(key) = key.as_str() {
                    // More-specific subscription entries would override a suffix policy.
                    let remaining: Vec<_> = key.split(',').filter(|entry| !is_protected_policy(entry)).collect();
                    if !remaining.is_empty() {
                        policy.insert(remaining.join(",").into(), value.clone());
                    }
                }
            }
        }
        for domain in DOMAINS {
            policy.insert(format!("+.{domain}").into(), PROTECTED_DNS.into());
        }
        dns.insert(field.into(), policy.into());
    }
    config.insert("dns".into(), dns.into());
}

fn is_protected_policy(key: &str) -> bool {
    let name = key
        .trim()
        .trim_start_matches(['+', '*', '.'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    DOMAINS
        .iter()
        .any(|domain| name == *domain || name.ends_with(&format!(".{domain}")))
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests assert valid fixtures")]
mod tests {
    use super::*;

    #[test]
    fn protection_precedes_catch_all_and_cannot_inherit_a_chain() {
        let mut config: Mapping = serde_yaml_ng::from_str(
            "mode: global\nproxies:\n- {name: CV Claude Protected, type: direct, dialer-proxy: HongKong}\nproxy-groups:\n- {name: CV Claude Protected, type: select, proxies: [DIRECT]}\nrules: ['MATCH,DIRECT']\n",
        ).expect("fixture");
        let original_rules = config["rules"].clone();
        enforce(&mut config);
        let once = config.clone();
        enforce(&mut config);
        assert_eq!(config, once);
        assert_eq!(config["mode"].as_str(), Some("rule"));
        assert_eq!(config["dns"]["nameserver"][0].as_str(), Some("system"));
        assert!(config["dns"].get("proxy-server-nameserver-policy").is_none());
        let proxy = &config["proxies"].as_sequence().expect("proxies")[0];
        assert_eq!(proxy["server"].as_str(), Some("127.0.0.1"));
        assert!(proxy.get("dialer-proxy").is_none());
        assert!(config["proxy-groups"].as_sequence().expect("groups").is_empty());
        let rules = config["rules"].as_sequence().expect("rules");
        assert_eq!(
            &rules[DOMAINS.len() * 2..],
            original_rules.as_sequence().expect("rules")
        );
        assert!(rules[0].as_str().expect("rule").contains("NETWORK,UDP"));
    }

    #[test]
    fn automatic_chain_carries_both_claude_and_dns_without_the_legacy_gateway() {
        let mut config: Mapping = serde_yaml_ng::from_str(
            "proxy-groups:\n- {name: CV Auto Chain, type: select, proxies: [REJECT]}\nproxies:\n- {name: CV Claude Protected, type: http, server: 127.0.0.1, port: 17891}\nrules: ['MATCH,CV Auto Chain']\n"
        ).expect("fixture");
        enforce(&mut config);
        let once = config.clone();
        enforce(&mut config);
        assert_eq!(config, once);
        assert!(config["proxies"].as_sequence().expect("proxies").is_empty());
        assert_eq!(
            config["proxy-groups"][1]["proxies"][0].as_str(),
            Some(super::super::auto_chain::GROUP)
        );
        assert_eq!(config["proxy-groups"][0]["proxies"][0].as_str(), Some("REJECT"));
        for domain in DOMAINS {
            assert_eq!(
                config["dns"]["nameserver-policy"][format!("+.{domain}")].as_str(),
                Some(PROTECTED_DNS)
            );
            assert!(
                config["rules"]
                    .as_sequence()
                    .expect("rules")
                    .contains(&Value::from(format!("DOMAIN-SUFFIX,{domain},{OUTBOUND}")))
            );
        }
    }

    #[test]
    fn protected_mode_rejects_global_and_direct() {
        assert!(check_mode(true, "global").is_err());
        assert!(check_mode(true, "direct").is_err());
        assert!(check_mode(true, "rule").is_ok());
        assert!(check_mode(false, "global").is_ok());
    }

    #[test]
    fn protected_dns_overrides_specific_entries_without_replacing_school_dns() {
        let mut config: Mapping = serde_yaml_ng::from_str(
            "dns:\n  enable: false\n  prefer-h3: true\n  nameserver: [223.5.5.5]\n  fallback: [8.8.8.8]\n  direct-nameserver: [system]\n  proxy-server-nameserver: [223.5.5.5]\n  nameserver-policy:\n    'api.anthropic.com,examw.hsas.edu.cn': 192.168.5.1\n    '*.Claude.ai': 114.114.114.114\n    '+.claude.ai': 223.5.5.5\n    'notclaude.ai': 192.168.5.1\n  proxy-server-nameserver-policy:\n    'api.anthropic.com': 114.114.114.114\n",
        ).expect("fixture");
        enforce(&mut config);
        let once = config.clone();
        enforce(&mut config);
        assert_eq!(config, once);
        let dns = config["dns"].as_mapping().expect("dns");
        assert_eq!(dns["enable"].as_bool(), Some(true));
        assert_eq!(dns["prefer-h3"].as_bool(), Some(false));
        assert_eq!(dns["direct-nameserver-follow-policy"].as_bool(), Some(true));
        assert_eq!(dns["nameserver"][0].as_str(), Some("223.5.5.5"));
        assert_eq!(dns["fallback"][0].as_str(), Some("8.8.8.8"));
        for field in ["nameserver-policy", "proxy-server-nameserver-policy"] {
            let policy = dns[field].as_mapping().expect("policy");
            assert!(!policy.contains_key("api.anthropic.com"));
            assert!(!policy.contains_key("*.Claude.ai"));
            for domain in DOMAINS {
                assert_eq!(policy[format!("+.{domain}")].as_str(), Some(PROTECTED_DNS));
            }
        }
        assert_eq!(
            dns["nameserver-policy"]["examw.hsas.edu.cn"].as_str(),
            Some("192.168.5.1")
        );
        assert_eq!(dns["nameserver-policy"]["notclaude.ai"].as_str(), Some("192.168.5.1"));
    }
}
