use serde_yaml_ng::{Mapping, Value};

pub const OUTBOUND: &str = "CV Claude Protected";
pub const GATEWAY_PORT: u16 = 17891;
pub const EXPECTED_EXIT: &str = "103.5.250.92";
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
    let mut gateway = Mapping::new();
    gateway.insert("name".into(), OUTBOUND.into());
    gateway.insert("type".into(), "http".into());
    gateway.insert("server".into(), "127.0.0.1".into());
    gateway.insert("port".into(), GATEWAY_PORT.into());
    proxies.push(Value::Mapping(gateway));
    config.insert("proxies".into(), proxies.into());

    if let Some(Value::Sequence(groups)) = config.get_mut("proxy-groups") {
        groups.retain(|group| group.get("name").and_then(Value::as_str) != Some(OUTBOUND));
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
    fn protected_mode_rejects_global_and_direct() {
        assert!(check_mode(true, "global").is_err());
        assert!(check_mode(true, "direct").is_err());
        assert!(check_mode(true, "rule").is_ok());
        assert!(check_mode(false, "global").is_ok());
    }
}
