use serde_yaml_ng::{Mapping, Value};

pub const OUTBOUND: &str = "CV Claude Protected";
pub const EXPECTED_EXIT: &str = "103.5.250.92";
pub const LISTENER_PORT: u16 = 7898;
pub const REALITY_EXIT: &str = "JP-REALITY-SOCKS";
pub const DOMAINS: &[&str] = &[
    "claude.ai",
    "claude.com",
    "anthropic.com",
    "claudeusercontent.com",
    "anthropicusercontent.com",
];
pub const PROCESSES: &[&str] = &["claude.exe", "Claude.exe", "cowork-svc.exe", "chrome-native-host.exe"];

pub fn enabled(requested: Option<bool>) -> bool {
    cfg!(target_os = "windows") || requested.unwrap_or(false)
}

pub fn check_mode(requested: bool, mode: &str) -> Result<(), &'static str> {
    if enabled(Some(requested)) && mode != "rule" {
        return Err("Claude fixed-exit protection requires rule mode.");
    }
    Ok(())
}

pub fn is_fixed_exit(proxy: &Value) -> bool {
    is_reality_exit(proxy)
        || is_hysteria_exit(proxy)
        || (proxy.get("type").and_then(Value::as_str) == Some("socks5")
            && proxy.get("server").and_then(Value::as_str) == Some(EXPECTED_EXIT)
            && proxy.get("port").and_then(Value::as_u64) == Some(443)
            && proxy
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name != OUTBOUND))
}

fn is_hysteria_exit(proxy: &Value) -> bool {
    // This authenticated inbound terminates at the fixed SOCKS exit; port 24443 does not.
    cfg!(target_os = "windows")
        && proxy.get("type").and_then(Value::as_str) == Some("hysteria2")
        && proxy.get("server").and_then(Value::as_str) == Some("45.76.49.46")
        && proxy.get("port").and_then(Value::as_u64) == Some(24444)
        && proxy.get("sni").and_then(Value::as_str) == Some("jp2.yanwenjie.space")
        && proxy.get("skip-cert-verify").and_then(Value::as_bool) == Some(false)
        && proxy.get("dialer-proxy").is_none()
        && proxy
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| name != OUTBOUND)
}

fn is_reality_exit(proxy: &Value) -> bool {
    // This named profile terminates SOCKS on the server; its VLESS entry is not the egress IP.
    proxy.get("name").and_then(Value::as_str) == Some(REALITY_EXIT)
        && proxy.get("type").and_then(Value::as_str) == Some("vless")
        && proxy.get("tls").and_then(Value::as_bool) == Some(true)
        && proxy.get("reality-opts").and_then(Value::as_mapping).is_some()
        && proxy.get("dialer-proxy").is_none()
}

pub fn enforce(config: &mut Mapping) {
    enforce_with_gateway(config, cfg!(target_os = "macos"));
}

fn enforce_with_gateway(config: &mut Mapping, use_gateway: bool) {
    config.insert("mode".into(), "rule".into());
    config.insert("find-process-mode".into(), "always".into());
    let mut proxies = config
        .get("proxies")
        .and_then(Value::as_sequence)
        .cloned()
        .unwrap_or_default();
    proxies.retain(|proxy| proxy.get("name").and_then(Value::as_str) != Some(OUTBOUND));
    let mut groups = config
        .get("proxy-groups")
        .and_then(Value::as_sequence)
        .cloned()
        .unwrap_or_default();
    groups.retain(|group| group.get("name").and_then(Value::as_str) != Some(OUTBOUND));
    if use_gateway {
        // The local gate verifies the fixed exit and fails closed independently
        // of subscription names. Never add an alternate route around it.
        let mut gateway = Mapping::new();
        gateway.insert("name".into(), OUTBOUND.into());
        gateway.insert("type".into(), "http".into());
        gateway.insert("server".into(), "127.0.0.1".into());
        gateway.insert("port".into(), 17891.into());
        gateway.insert("udp".into(), false.into());
        proxies.push(gateway.into());
    } else {
        let group_names: Vec<_> = groups
            .iter()
            .filter_map(|g| g.get("name").and_then(Value::as_str))
            .collect();
        let mut routes = Vec::new();
        for proxy in &mut proxies {
            if is_fixed_exit(proxy) {
                let name = proxy["name"].as_str().unwrap_or_default();
                // Name collisions must not redirect a fixed endpoint through a group.
                if !group_names.contains(&name) {
                    routes.push(Value::from(name));
                    if let Some(proxy) = proxy.as_mapping_mut() {
                        proxy.insert("udp".into(), false.into());
                    }
                }
            }
        }
        // Use complete chains when available; never fall back to a bare relay or DIRECT.
        let chained: Vec<_> = routes
            .iter()
            .filter(|r| r.as_str().is_some_and(|s| s.starts_with("CV Chain / ")))
            .cloned()
            .collect();
        let use_auto_chain = groups.iter().any(|group| {
            group.get("name").and_then(Value::as_str) == Some(super::auto_chain::GROUP)
                && group
                    .get("proxies")
                    .and_then(Value::as_sequence)
                    .is_some_and(|members| {
                        members.iter().any(|name| chained.contains(name))
                            && members
                                .iter()
                                .all(|name| name.as_str() == Some("REJECT") || chained.contains(name))
                    })
        });
        if use_auto_chain {
            routes = vec![Value::from(super::auto_chain::GROUP)];
        } else if routes.contains(&Value::from(REALITY_EXIT)) {
            routes = vec![Value::from(REALITY_EXIT)];
        } else if !chained.is_empty() {
            routes = chained;
        }
        if routes.is_empty() {
            routes.push("REJECT".into());
        }
        let mut group = Mapping::new();
        group.insert("name".into(), OUTBOUND.into());
        group.insert("type".into(), if use_auto_chain { "select" } else { "url-test" }.into());
        group.insert("proxies".into(), routes.into());
        group.insert("url".into(), "https://www.gstatic.com/generate_204".into());
        group.insert("interval".into(), 60.into());
        group.insert("timeout".into(), 15000.into());
        group.insert("lazy".into(), true.into());
        groups.push(group.into());
    }
    config.insert("proxies".into(), proxies.into());
    config.insert("proxy-groups".into(), groups.into());
    enforce_dns(config);

    let mut listeners = config
        .get("listeners")
        .and_then(Value::as_sequence)
        .cloned()
        .unwrap_or_default();
    listeners.retain(|l| {
        l.get("name").and_then(Value::as_str) != Some("claude-fixed-ip")
            && l.get("port").and_then(Value::as_u64) != Some(u64::from(LISTENER_PORT))
    });
    let mut listener = Mapping::new();
    listener.insert("name".into(), "claude-fixed-ip".into());
    listener.insert("type".into(), "mixed".into());
    listener.insert("listen".into(), "127.0.0.1".into());
    listener.insert("port".into(), LISTENER_PORT.into());
    listener.insert("proxy".into(), OUTBOUND.into());
    listener.insert("udp".into(), false.into());
    listeners.push(listener.into());
    config.insert("listeners".into(), listeners.into());

    let matches: Vec<_> = DOMAINS
        .iter()
        .map(|d| format!("DOMAIN-SUFFIX,{d}"))
        .chain(PROCESSES.iter().map(|p| format!("PROCESS-NAME,{p}")))
        .collect();
    let mut rules: Vec<Value> = matches
        .iter()
        .map(|m| format!("AND,(({m}),(NETWORK,UDP)),REJECT").into())
        .chain(matches.iter().map(|m| format!("{m},{OUTBOUND}").into()))
        .collect();
    if cfg!(target_os = "windows") {
        rules.extend(super::local_access::RULES.iter().map(|rule| Value::from(*rule)));
    }
    if let Some(existing) = config.get("rules").and_then(Value::as_sequence) {
        for rule in existing {
            if !rules.contains(rule) {
                rules.push(rule.clone());
            }
        }
    }
    config.insert("rules".into(), rules.into());
    if cfg!(target_os = "windows") {
        enforce_domestic_routes(config);
    }
}

const DOMESTIC_DNS_DOMAINS: &[&str] = &[
    "cn",
    "baidu.com",
    "bdstatic.com",
    "bdimg.com",
    "bilibili.com",
    "biliapi.com",
    "biliapi.net",
    "bilivideo.com",
    "hdslb.com",
    "qq.com",
    "gtimg.com",
    "163.com",
    "126.com",
    "126.net",
    "netease.com",
    "taobao.com",
    "tmall.com",
    "alicdn.com",
    "jd.com",
    "360buyimg.com",
    "zhihu.com",
    "zhimg.com",
];

fn enforce_domestic_routes(config: &mut Mapping) {
    let additions = [
        "IP-CIDR,8.134.107.154/32,DIRECT,no-resolve",
        "GEOSITE,cn,DIRECT",
        "GEOIP,CN,DIRECT",
    ];
    let mut rules = config
        .get("rules")
        .and_then(Value::as_sequence)
        .cloned()
        .unwrap_or_default();
    rules.retain(|r| !r.as_str().is_some_and(|s| additions.contains(&s)));
    let end = rules
        .iter()
        .position(|r| {
            r.as_str()
                .is_some_and(|s| s.starts_with("MATCH,") || s.starts_with("FINAL,"))
        })
        .unwrap_or(rules.len());
    rules.splice(end..end, additions.into_iter().map(Value::from));
    config.insert("rules".into(), rules.into());
    let mut tun = config
        .get("tun")
        .and_then(Value::as_mapping)
        .cloned()
        .unwrap_or_default();
    let mut excluded = tun
        .get("route-exclude-address")
        .and_then(Value::as_sequence)
        .cloned()
        .unwrap_or_default();
    let server = Value::from("8.134.107.154/32");
    if !excluded.contains(&server) {
        excluded.push(server);
    }
    tun.insert("route-exclude-address".into(), excluded.into());
    config.insert("tun".into(), tun.into());
}

fn enforce_dns(config: &mut Mapping) {
    let groups: Vec<_> = config
        .get("proxy-groups")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(|g| g.get("name").and_then(Value::as_str))
        .collect();
    let target = config
        .get("rules")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .find_map(|r| {
            let (kind, name) = r.split_once(',')?;
            if matches!(kind, "MATCH" | "FINAL")
                && groups.contains(&name)
                && !matches!(name, "DIRECT" | "PASS" | "GLOBAL")
            {
                Some(name.to_owned())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "REJECT".to_owned());
    let doh = |group: &str| {
        Value::Sequence(vec![
            format!("https://1.1.1.1/dns-query#{group}").into(),
            format!("https://8.8.8.8/dns-query#{group}").into(),
        ])
    };
    let mut dns = config
        .get("dns")
        .and_then(Value::as_mapping)
        .cloned()
        .unwrap_or_default();
    let mut policy = dns
        .get("nameserver-policy")
        .and_then(Value::as_mapping)
        .cloned()
        .unwrap_or_default();
    let local = ["localhost", "lan", "local", "home.arpa", "in-addr.arpa", "ip6.arpa"];
    policy.retain(|key, _| {
        key.as_str().is_some_and(|key| {
            let key = key.trim_start_matches("+.").trim_start_matches("*.");
            local
                .iter()
                .any(|suffix| key == *suffix || key.ends_with(&format!(".{suffix}")))
        })
    });
    for domain in local {
        policy
            .entry(Value::from(format!("+.{domain}")))
            .or_insert_with(|| vec![Value::from("system")].into());
    }
    let domestic = Value::Sequence(vec![
        "https://223.5.5.5/dns-query#DIRECT".into(),
        "https://223.6.6.6/dns-query#DIRECT".into(),
    ]);
    for domain in DOMESTIC_DNS_DOMAINS {
        policy.insert(format!("+.{domain}").into(), domestic.clone());
    }
    for domain in DOMAINS {
        policy.insert(format!("+.{domain}").into(), doh(OUTBOUND));
    }
    dns.insert("enable".into(), true.into());
    dns.insert("prefer-h3".into(), false.into());
    dns.insert("respect-rules".into(), false.into());
    dns.insert("direct-nameserver-follow-policy".into(), true.into());
    dns.insert("nameserver".into(), doh(&target));
    dns.insert("direct-nameserver".into(), doh(&target));
    dns.insert("fallback".into(), Value::Sequence(Vec::new()));
    dns.insert(
        "default-nameserver".into(),
        vec![Value::from("https://223.5.5.5/dns-query")].into(),
    );
    dns.insert(
        "proxy-server-nameserver".into(),
        vec![Value::from("https://223.5.5.5/dns-query#DIRECT")].into(),
    );
    dns.remove("proxy-server-nameserver-policy");
    dns.insert("nameserver-policy".into(), policy.into());
    config.insert("dns".into(), dns.into());
    let mut tun = config
        .get("tun")
        .and_then(Value::as_mapping)
        .cloned()
        .unwrap_or_default();
    let mut hijack = tun
        .get("dns-hijack")
        .and_then(Value::as_sequence)
        .cloned()
        .unwrap_or_default();
    for value in ["any:53", "tcp://any:53"] {
        if !hijack.contains(&Value::from(value)) {
            hijack.push(value.into());
        }
    }
    tun.insert("dns-hijack".into(), hijack.into());
    config.insert("tun".into(), tun.into());
}
#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests assert valid fixtures")]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "windows")]
    fn pinned_hysteria_exit_survives_renames_and_rejects_unsafe_variants() {
        let proxy: Value = serde_yaml_ng::from_str(
            "{name: JP2-HY2-SOCKS, type: hysteria2, server: 45.76.49.46, port: 24444, sni: jp2.yanwenjie.space, skip-cert-verify: false}",
        ).expect("fixture");
        for name in ["JP2-HY2-SOCKS", "renamed fixed exit"] {
            let mut node = proxy.clone();
            node["name"] = name.into();
            let mut config: Mapping = serde_yaml_ng::from_str(
                "proxy-groups: [{name: Japan2, type: select, proxies: [DIRECT]}]\nrules: ['MATCH,Japan2']",
            )
            .expect("fixture");
            config.insert("proxies".into(), vec![node].into());
            enforce(&mut config);
            assert_eq!(config["proxy-groups"][1]["proxies"], Value::Sequence(vec![name.into()]));
            assert_eq!(config["proxies"][0]["udp"], Value::Bool(false));
            let once = config.clone();
            enforce(&mut config);
            assert_eq!(config, once);
        }
        for (field, value) in [
            ("server", Value::from("203.0.113.1")),
            ("port", Value::from(24443)),
            ("type", Value::from("direct")),
            ("sni", Value::from("untrusted.example")),
            ("skip-cert-verify", Value::Bool(true)),
            ("skip-cert-verify", Value::Null),
            ("dialer-proxy", Value::from("Japan2")),
        ] {
            let mut node = proxy.clone();
            node[field] = value;
            let mut config: Mapping = serde_yaml_ng::from_str("rules: ['MATCH,DIRECT']").expect("fixture");
            config.insert("proxies".into(), vec![node].into());
            enforce(&mut config);
            assert_eq!(
                config["proxy-groups"][0]["proxies"],
                Value::Sequence(vec!["REJECT".into()])
            );
        }
        let mut config: Mapping = serde_yaml_ng::from_str(
            "proxy-groups: [{name: JP2-HY2-SOCKS, type: select, proxies: [DIRECT]}]\nrules: ['MATCH,DIRECT']",
        )
        .expect("fixture");
        config.insert("proxies".into(), vec![proxy].into());
        enforce(&mut config);
        assert_eq!(
            config["proxy-groups"][1]["proxies"],
            Value::Sequence(vec!["REJECT".into()])
        );
    }

    #[test]
    fn gateway_survives_subscription_changes_and_shadowed_names() {
        for name in ["JP2-HY2-SOCKS", "renamed relay", "JP-REALITY-SOCKS"] {
            let mut config: Mapping = serde_yaml_ng::from_str(&format!(
                "proxies: [{{name: '{name}', type: direct}}, {{name: CV Claude Protected, type: direct}}]\nproxy-groups: [{{name: CV Claude Protected, type: select, proxies: [DIRECT]}}]\nrules: ['MATCH,DIRECT']"
            )).expect("fixture");
            enforce_with_gateway(&mut config, true);
            let proxies = config["proxies"].as_sequence().expect("proxies");
            let gateway = proxies
                .iter()
                .find(|p| p["name"].as_str() == Some(OUTBOUND))
                .expect("gate");
            assert_eq!(gateway["type"].as_str(), Some("http"));
            assert_eq!(gateway["server"].as_str(), Some("127.0.0.1"));
            assert_eq!(gateway["port"].as_u64(), Some(17891));
            assert_eq!(gateway["udp"], Value::Bool(false));
            assert!(config["proxy-groups"].as_sequence().expect("groups").is_empty());
            assert_eq!(config["listeners"][0]["proxy"].as_str(), Some(OUTBOUND));
            assert_eq!(
                config["dns"]["nameserver-policy"]["+.claude.ai"][0].as_str(),
                Some("https://1.1.1.1/dns-query#CV Claude Protected")
            );
            let once = config.clone();
            enforce_with_gateway(&mut config, true);
            assert_eq!(config, once);
        }
    }

    #[test]
    fn protected_traffic_follows_the_verified_auto_chain_selection() {
        let mut config: Mapping = serde_yaml_ng::from_str(
            "proxies:\n- {name: 'CV Chain / Relay', type: socks5, server: 103.5.250.92, port: 443, dialer-proxy: Relay}\n- {name: Relay, type: socks5, server: 127.0.0.1, port: 1080}\nproxy-groups:\n- {name: CV Auto Chain, type: select, proxies: [REJECT, 'CV Chain / Relay']}\nrules: ['MATCH,CV Auto Chain']"
        ).expect("fixture");
        enforce_with_gateway(&mut config, false);
        assert_eq!(config["proxy-groups"][1]["type"].as_str(), Some("select"));
        assert_eq!(
            config["proxy-groups"][1]["proxies"],
            Value::Sequence(vec![super::super::auto_chain::GROUP.into()])
        );
        let once = config.clone();
        enforce_with_gateway(&mut config, false);
        assert_eq!(config, once);
        config["proxy-groups"][0]["proxies"]
            .as_sequence_mut()
            .expect("members")
            .push("DIRECT".into());
        enforce_with_gateway(&mut config, false);
        assert_eq!(
            config["proxy-groups"][1]["proxies"],
            Value::Sequence(vec!["CV Chain / Relay".into()])
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn reality_exit_and_lan_routes_survive_regeneration() {
        let mut config: Mapping = serde_yaml_ng::from_str(
            "proxies:\n- {name: JP-REALITY-SOCKS, type: vless, tls: true, reality-opts: {public-key: fixture}, server: example.com, port: 443}\n- {name: 'CV Chain / Japan', type: socks5, server: 103.5.250.92, port: 443, dialer-proxy: Relay}\nproxy-groups: [{name: Japan, type: select, proxies: [JP-REALITY-SOCKS]}]\nrules: ['IP-CIDR,192.168.0.0/16,Japan,no-resolve', 'MATCH,Japan']\n"
        ).expect("fixture");
        for _ in 0..3 {
            enforce_with_gateway(&mut config, false);
            assert_eq!(
                config["proxy-groups"][1]["proxies"],
                Value::Sequence(vec![REALITY_EXIT.into()])
            );
            assert_eq!(config["listeners"][0]["proxy"].as_str(), Some(OUTBOUND));
            let rules = config["rules"].as_sequence().expect("rules");
            let guard = rules
                .iter()
                .position(|r| r.as_str() == Some("DOMAIN-SUFFIX,claude.ai,CV Claude Protected"))
                .expect("guard");
            let local = rules
                .iter()
                .position(|r| r.as_str() == Some("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"))
                .expect("local");
            let conflicting = rules
                .iter()
                .position(|r| r.as_str() == Some("IP-CIDR,192.168.0.0/16,Japan,no-resolve"))
                .expect("subscription");
            assert!(guard < local && local < conflicting);
            let once = config.clone();
            enforce_with_gateway(&mut config, false);
            assert_eq!(config, once);
            config = serde_yaml_ng::from_str(&serde_yaml_ng::to_string(&config).expect("serialize")).expect("reload");
        }
    }

    #[test]
    fn missing_or_shadowed_reality_exit_never_uses_japan_group() {
        for proxy in [
            "{name: JP-REALITY-Direct, type: vless, tls: true, reality-opts: {}}",
            "{name: JP-REALITY-SOCKS, type: direct}",
            "{name: JP-REALITY-SOCKS, type: vless, tls: true, reality-opts: {}, dialer-proxy: Japan}",
            "{name: JP-REALITY-SOCKS, type: vless, tls: true, reality-opts: {}}",
        ] {
            let mut config: Mapping = serde_yaml_ng::from_str(&format!(
                "proxies: [{proxy}]\nproxy-groups: [{{name: JP-REALITY-SOCKS, type: select, proxies: [DIRECT]}}]\nrules: ['MATCH,DIRECT']\n"
            )).expect("fixture");
            enforce_with_gateway(&mut config, false);
            assert_eq!(config["proxy-groups"][1]["proxies"][0].as_str(), Some("REJECT"));
        }
    }

    #[test]
    fn dns_protection_survives_conflicting_overrides_without_changing_local_services() {
        let mut config: Mapping = serde_yaml_ng::from_str(
            "tun: {enable: false, dns-hijack: ['any:53']}\ndns:\n  nameserver: [223.5.5.5]\n  nameserver-policy:\n    api.anthropic.com: [223.5.5.5]\n    '+.claude.ai': [8.8.8.8]\n    st.dl.eccdnx.com: [192.168.5.1]\n"
        ).expect("fixture");
        enforce_with_gateway(&mut config, false);
        assert_eq!(config["tun"]["enable"], Value::Bool(false));
        assert_eq!(config["tun"]["dns-hijack"].as_sequence().expect("hijack").len(), 2);
        let dns = &config["dns"];
        assert_eq!(dns["nameserver"][0].as_str(), Some("https://1.1.1.1/dns-query#REJECT"));
        let policy = dns["nameserver-policy"].as_mapping().expect("policy");
        assert!(!policy.contains_key("api.anthropic.com"));
        assert!(!policy.contains_key("st.dl.eccdnx.com"));
        for domain in DOMAINS {
            let entries = policy[format!("+.{domain}")].as_sequence().expect("resolvers");
            assert_eq!(entries.len(), 2);
            assert!(
                entries
                    .iter()
                    .all(|entry| entry.as_str().expect("url").ends_with("#CV Claude Protected"))
            );
        }
        assert_eq!(config["proxy-groups"][0]["proxies"][0].as_str(), Some("REJECT"));
        let once = config.clone();
        enforce_with_gateway(&mut config, false);
        assert_eq!(config, once);
    }

    #[test]
    fn missing_exit_rejects_even_with_old_gateway() {
        let mut config: Mapping = serde_yaml_ng::from_str(
            "mode: global\nproxies:\n- {name: CV Claude Protected, type: http, server: 127.0.0.1, port: 17891}\n- {name: Japan, type: socks5, server: 1.2.3.4, port: 443}\nrules: ['MATCH,DIRECT']\n"
        ).expect("fixture");
        enforce_with_gateway(&mut config, false);
        assert_eq!(config["proxy-groups"][0]["proxies"][0].as_str(), Some("REJECT"));
        assert_eq!(config["proxies"].as_sequence().expect("proxies").len(), 1);
        assert_eq!(config["listeners"][0]["proxy"].as_str(), Some(OUTBOUND));
        assert_eq!(config["listeners"][0]["port"].as_u64(), Some(7898));
        let once = config.clone();
        enforce_with_gateway(&mut config, false);
        assert_eq!(config, once);
    }

    #[test]
    fn only_fixed_socks_endpoints_are_eligible() {
        let mut config: Mapping = serde_yaml_ng::from_str(
            "proxies:\n- {name: Exit, type: socks5, server: 103.5.250.92, port: 443}\n- {name: 'CV Chain / Japan', type: socks5, server: 103.5.250.92, port: 443, dialer-proxy: Japan}\n- {name: Japan, type: socks5, server: 1.2.3.4, port: 443}\n- {name: WrongType, type: direct, server: 103.5.250.92, port: 443}\nproxy-groups:\n- {name: Main, type: select, proxies: [Japan, DIRECT]}\nrules: ['MATCH,Main']"
        ).expect("fixture");
        enforce_with_gateway(&mut config, false);
        assert_eq!(
            config["proxy-groups"][1]["proxies"],
            Value::Sequence(vec!["CV Chain / Japan".into()])
        );
        assert_eq!(config["proxies"][1]["dialer-proxy"].as_str(), Some("Japan"));
        assert_eq!(config["proxies"][1]["udp"], Value::Bool(false));
        assert_eq!(
            config["rules"]
                .as_sequence()
                .expect("rules")
                .last()
                .and_then(Value::as_str),
            Some("MATCH,Main")
        );
        assert!(
            config["rules"]
                .as_sequence()
                .expect("rules")
                .iter()
                .any(|r| r.as_str() == Some("PROCESS-NAME,claude.exe,CV Claude Protected"))
        );
        let once = config.clone();
        enforce_with_gateway(&mut config, false);
        assert_eq!(config, once);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn domestic_routes_survive_cached_runtime_and_keep_protection_first() {
        let mut config: Mapping = serde_yaml_ng::from_str("tun: {enable: false}\nrules: ['MATCH,Japan']\nproxy-groups: [{name: Japan, type: select, proxies: [REJECT]}]\n").expect("fixture");
        for _ in 0..3 {
            config.insert("rules".into(), vec![Value::from("MATCH,Japan")].into());
            enforce_with_gateway(&mut config, false);
            let rules = config["rules"].as_sequence().expect("rules");
            let domestic = rules
                .iter()
                .position(|r| r.as_str() == Some("GEOSITE,cn,DIRECT"))
                .expect("domestic rule");
            let process = rules
                .iter()
                .position(|r| r.as_str() == Some("PROCESS-NAME,claude.exe,CV Claude Protected"))
                .expect("process guard");
            assert!(process < domestic && domestic < rules.len() - 1);
            assert_eq!(config["proxy-groups"][1]["proxies"][0].as_str(), Some("REJECT"));
            assert_eq!(
                config["tun"]["route-exclude-address"][0].as_str(),
                Some("8.134.107.154/32")
            );
            assert_eq!(config["tun"]["enable"], Value::Bool(false));
            assert_eq!(
                config["dns"]["nameserver"][0].as_str(),
                Some("https://1.1.1.1/dns-query#Japan")
            );
            assert_eq!(
                config["dns"]["nameserver-policy"]["+.bilibili.com"][0].as_str(),
                Some("https://223.5.5.5/dns-query#DIRECT")
            );
            config = serde_yaml_ng::from_str(&serde_yaml_ng::to_string(&config).expect("serialize")).expect("reload");
        }
    }

    #[test]
    fn protected_mode_rejects_global_and_direct() {
        assert!(check_mode(true, "global").is_err());
        assert!(check_mode(true, "direct").is_err());
        assert!(check_mode(true, "rule").is_ok());
        if cfg!(target_os = "windows") {
            assert!(check_mode(false, "direct").is_err());
        }
    }
}
