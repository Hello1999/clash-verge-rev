use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashSet};

use crate::{config::IProfiles, utils::dirs};

pub const GROUP: &str = "CV Auto Chain";
pub const PREFIX: &str = "CV Chain / ";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AutoChainSettings {
    pub enabled: bool,
    pub profile_uid: String,
    #[serde(default)]
    pub entry_sources: Option<Vec<String>>,
    pub exit_source: String,
    pub exit_name: String,
    #[serde(default)]
    pub target_group: String,
    pub interval: u64,
    pub tolerance: u64,
    #[serde(default = "default_max_latency")]
    pub max_latency: u64,
    pub url: String,
}

pub const fn default_max_latency() -> u64 {
    1000
}

impl AutoChainSettings {
    pub fn active_for(&self, profiles: &IProfiles) -> bool {
        self.enabled && profiles.current.as_deref() == Some(self.profile_uid.as_str())
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            (5..=3600).contains(&self.interval),
            "Check interval must be between 5 and 3600 seconds"
        );
        ensure!(
            (200..=5000).contains(&self.max_latency),
            "High latency threshold must be between 200 and 5000 ms"
        );
        ensure!(self.tolerance <= 1000, "Switch tolerance must not exceed 1000 ms");
        ensure!(
            self.entry_sources.as_ref().is_none_or(|sources| !sources.is_empty()),
            "Choose at least one relay subscription"
        );
        let url = tauri::Url::parse(&self.url).context("Invalid health check URL")?;
        ensure!(
            url.scheme() == "https" && url.host_str().is_some(),
            "Use an HTTPS health check URL"
        );
        ensure!(!self.exit_name.is_empty(), "Choose a fixed exit");
        Ok(())
    }
}

#[derive(Serialize)]
pub struct ExitOption {
    pub source: String,
    pub source_label: String,
    pub name: String,
    pub route_id: String,
}

#[derive(Serialize)]
pub struct SubscriptionOption {
    pub source: String,
    pub label: String,
    pub count: usize,
}

#[derive(Serialize)]
pub struct AutoChainOptions {
    pub exits: Vec<ExitOption>,
    pub subscriptions: Vec<SubscriptionOption>,
    pub warnings: Vec<String>,
}

pub struct Candidate {
    pub source: String,
    pub source_label: String,
    pub proxy: Mapping,
}

pub struct Catalog {
    pub nodes: Vec<Candidate>,
    pub warnings: Vec<String>,
}

impl Catalog {
    pub fn options(&self) -> AutoChainOptions {
        AutoChainOptions {
            exits: self
                .nodes
                .iter()
                .filter_map(|node| {
                    Some(ExitOption {
                        source: node.source.clone(),
                        source_label: node.source_label.clone(),
                        name: node.proxy.get("name")?.as_str()?.to_owned(),
                        route_id: identity(&node.proxy).ok()?[..12].to_owned(),
                    })
                })
                .collect(),
            subscriptions: {
                let mut sources: BTreeMap<String, SubscriptionOption> = BTreeMap::new();
                for node in &self.nodes {
                    let source = node.source.split("/provider/").next().unwrap_or(&node.source);
                    sources
                        .entry(source.to_owned())
                        .or_insert_with(|| SubscriptionOption {
                            source: source.to_owned(),
                            label: node
                                .source_label
                                .split(" / ")
                                .next()
                                .unwrap_or(&node.source_label)
                                .to_owned(),
                            count: 0,
                        })
                        .count += 1;
                }
                sources.into_values().collect()
            },
            warnings: self.warnings.clone(),
        }
    }
}

fn add_nodes(catalog: &mut Catalog, source: &str, label: &str, nodes: &[Value]) {
    for node in nodes {
        let Some(proxy) = node.as_mapping() else { continue };
        let Some(name) = proxy.get("name").and_then(Value::as_str) else {
            continue;
        };
        if name.starts_with(PREFIX) || !proxy.contains_key("server") || !proxy.contains_key("port") {
            continue;
        }
        catalog.nodes.push(Candidate {
            source: source.to_owned(),
            source_label: label.to_owned(),
            proxy: proxy.clone(),
        });
    }
}

async fn collect_mapping(catalog: &mut Catalog, source: &str, label: &str, config: &Mapping) -> Result<()> {
    if let Some(nodes) = config.get("proxies").and_then(Value::as_sequence) {
        add_nodes(catalog, source, label, nodes);
    }
    let Some(providers) = config.get("proxy-providers").and_then(Value::as_mapping) else {
        return Ok(());
    };
    for (name, provider) in providers {
        let name = name.as_str().unwrap_or_default();
        let nodes = if let Some(payload) = provider.get("payload").and_then(Value::as_sequence) {
            Some(payload.clone())
        } else if let Some(path) = provider.get("path").and_then(Value::as_str) {
            let path = dirs::app_home_dir()?.join(path);
            match tokio::fs::read_to_string(path).await {
                Ok(content) => serde_yaml_ng::from_str::<Mapping>(&content)
                    .ok()
                    .and_then(|mut data| data.remove("proxies"))
                    .and_then(|nodes| nodes.as_sequence().cloned()),
                Err(_) => None,
            }
        } else {
            None
        };
        let Some(mut nodes) = nodes else {
            catalog.warnings.push(format!(
                "{label} / {name}: provider cache is unavailable; update this provider first"
            ));
            continue;
        };
        // Provider filters and overrides affect the actual connection, not just its display name.
        let filter = provider
            .get("filter")
            .and_then(Value::as_str)
            .map(regex::Regex::new)
            .transpose()?;
        let exclude = provider
            .get("exclude-filter")
            .and_then(Value::as_str)
            .map(regex::Regex::new)
            .transpose()?;
        nodes.retain(|node| {
            let name = node.get("name").and_then(Value::as_str).unwrap_or_default();
            filter.as_ref().is_none_or(|re| re.is_match(name)) && exclude.as_ref().is_none_or(|re| !re.is_match(name))
        });
        if let Some(overrides) = provider.get("override").and_then(Value::as_mapping) {
            for node in &mut nodes {
                if let Some(node) = node.as_mapping_mut() {
                    for (key, value) in overrides {
                        if !matches!(key.as_str(), Some("additional-prefix" | "additional-suffix")) {
                            node.insert(key.clone(), value.clone());
                        }
                    }
                    let prefix = overrides
                        .get("additional-prefix")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let suffix = overrides
                        .get("additional-suffix")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let name = node.get("name").and_then(Value::as_str).unwrap_or_default();
                    node.insert("name".into(), format!("{prefix}{name}{suffix}").into());
                }
            }
        }
        add_nodes(
            catalog,
            &format!("{source}/provider/{name}"),
            &format!("{label} / {name}"),
            &nodes,
        );
    }
    Ok(())
}

pub async fn collect(profiles: &IProfiles, runtime: &Mapping) -> Result<Catalog> {
    let mut catalog = Catalog {
        nodes: Vec::new(),
        warnings: Vec::new(),
    };
    collect_mapping(&mut catalog, "runtime", "Current profile", runtime).await?;
    for item in profiles.items.iter().flatten() {
        if !matches!(item.itype.as_deref(), Some("remote" | "local")) {
            continue;
        }
        let Some(uid) = item.uid.as_deref() else { continue };
        let label = item.name.as_deref().unwrap_or(uid);
        match item
            .read_file()
            .await
            .and_then(|content| Ok(serde_yaml_ng::from_str::<Mapping>(&content)?))
        {
            Ok(config) => collect_mapping(&mut catalog, uid, label, &config).await?,
            Err(_) => catalog
                .warnings
                .push(format!("{label}: subscription file is unavailable")),
        }
    }
    Ok(catalog)
}

fn identity(proxy: &Mapping) -> Result<String> {
    let fields: BTreeMap<_, _> = proxy
        .iter()
        .filter_map(|(key, value)| {
            let key = key.as_str()?;
            (key != "name").then_some((key, value))
        })
        .collect();
    Ok(Sha256::digest(serde_json::to_vec(&fields)?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn build(config: &mut Mapping, settings: &AutoChainSettings, catalog: &Catalog) -> Result<()> {
    settings.validate()?;
    let mut proxies = config
        .get("proxies")
        .and_then(Value::as_sequence)
        .cloned()
        .unwrap_or_default();
    let mut groups = config
        .get("proxy-groups")
        .and_then(Value::as_sequence)
        .cloned()
        .unwrap_or_default();
    ensure!(
        !proxies.iter().chain(groups.iter()).any(|node| {
            node.get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name == GROUP || name.starts_with(PREFIX))
        }),
        "Reserved automatic chain names already exist in this profile"
    );

    let exit = catalog.nodes.iter().find(|node| {
        node.source == settings.exit_source
            && node.proxy.get("name").and_then(Value::as_str) == Some(settings.exit_name.as_str())
    });
    let mut routes = Vec::new();
    let mut seen = HashSet::new();
    if let Some(exit) = exit {
        let exit_id = identity(&exit.proxy)?;
        for candidate in &catalog.nodes {
            if !settings.entry_sources.as_ref().is_none_or(|sources| {
                sources.iter().any(|source| {
                    candidate.source == *source || candidate.source.starts_with(&format!("{source}/provider/"))
                })
            }) {
                continue;
            }
            let entry = &candidate.proxy;
            if entry.contains_key("dialer-proxy") {
                continue;
            }
            let id = identity(entry)?;
            if id == exit_id || !seen.insert(id.clone()) {
                continue;
            }
            let label = entry.get("name").and_then(Value::as_str).unwrap_or_default();
            let entry_name = format!("{PREFIX}entry / {id}");
            let route_name = format!("{PREFIX}{label} / {}", &id[..12]);
            let mut entry = entry.clone();
            entry.insert("name".into(), entry_name.clone().into());
            proxies.push(entry.into());
            let mut route = exit.proxy.clone();
            route.insert("name".into(), route_name.clone().into());
            route.insert("dialer-proxy".into(), entry_name.into());
            proxies.push(route.into());
            routes.push(Value::from(route_name));
        }
    }
    // Never bypass the chosen exit when its subscription disappears or no entries remain.
    routes.insert(0, "REJECT".into());
    let mut group = Mapping::new();
    group.insert("name".into(), GROUP.into());
    group.insert("type".into(), "select".into());
    group.insert("proxies".into(), routes.into());
    groups.push(group.into());
    config.insert("proxies".into(), proxies.into());
    config.insert("proxy-groups".into(), groups.into());
    // Unified delay times a reused request and omits the chain's connection handshakes.
    config.insert("unified-delay".into(), false.into());
    Ok(())
}

pub fn without_generated(mut config: Mapping) -> Mapping {
    if let Some(nodes) = config.get_mut("proxies").and_then(Value::as_sequence_mut) {
        nodes.retain(|node| {
            !node
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.starts_with(PREFIX))
        });
    }
    if let Some(groups) = config.get_mut("proxy-groups").and_then(Value::as_sequence_mut) {
        groups.retain(|group| group.get("name").and_then(Value::as_str) != Some(GROUP));
        for group in groups {
            if let Some(members) = group.get_mut("proxies").and_then(Value::as_sequence_mut) {
                members.retain(|name| name.as_str() != Some(GROUP));
            }
        }
    }
    config
}

pub fn routes_proxy_traffic(config: &Mapping) -> bool {
    let has_chain_rule = |rules: &Value| {
        rules.as_sequence().is_some_and(|rules| {
            rules.iter().filter_map(Value::as_str).any(|rule| {
                !rule.starts_with("SUB-RULE,")
                    && rule
                        .split(',')
                        .rev()
                        .find(|field| field.trim() != "no-resolve")
                        .is_some_and(|policy| policy.trim() == GROUP)
            })
        })
    };
    config.get("mode").and_then(Value::as_str) == Some("rule")
        && (config.get("rules").is_some_and(has_chain_rule)
            || config
                .get("sub-rules")
                .and_then(Value::as_mapping)
                .is_some_and(|rules| rules.values().any(has_chain_rule)))
}

pub fn route_all_proxy_traffic(config: &mut Mapping, selected: &BTreeMap<String, String>) {
    fn resolve<'a>(
        name: &'a str,
        config: &'a Mapping,
        selected: &'a BTreeMap<String, String>,
        seen: &mut HashSet<String>,
    ) -> &'a str {
        if name == GROUP || matches!(name, "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS") {
            return name;
        }
        if !seen.insert(name.to_owned()) {
            return GROUP;
        }
        if let Some(proxy) = config.get("proxies").and_then(Value::as_sequence).and_then(|nodes| {
            nodes
                .iter()
                .find(|node| node.get("name").and_then(Value::as_str) == Some(name))
        }) {
            return match proxy.get("type").and_then(Value::as_str) {
                Some("direct" | "reject" | "dns")
                    if !proxy
                        .as_mapping()
                        .is_some_and(|proxy| proxy.contains_key("dialer-proxy")) =>
                {
                    name
                }
                _ => GROUP,
            };
        }
        let group = config
            .get("proxy-groups")
            .and_then(Value::as_sequence)
            .and_then(|groups| {
                groups
                    .iter()
                    .find(|group| group.get("name").and_then(Value::as_str) == Some(name))
            });
        if let Some(group) = group
            && group.get("type").and_then(Value::as_str) == Some("select")
        {
            let members = group.get("proxies").and_then(Value::as_sequence);
            let choice = selected
                .get(name)
                .map(String::as_str)
                .or_else(|| members.and_then(|members| members.first()).and_then(Value::as_str));
            if let Some(choice) = choice {
                return resolve(choice, config, selected, seen);
            }
        }
        GROUP
    }

    fn rewrite(rules: &mut Value, config: &Mapping, selected: &BTreeMap<String, String>) {
        let Some(rules) = rules.as_sequence_mut() else { return };
        for rule in rules {
            let Some(text) = rule.as_str() else { continue };
            // SUB-RULE names are rule lists, not outbound policies.
            if text.starts_with("SUB-RULE,") {
                continue;
            }
            let mut fields: Vec<_> = text.split(',').collect();
            let index = fields
                .len()
                .saturating_sub(if fields.last() == Some(&"no-resolve") { 2 } else { 1 });
            if index == 0 {
                continue;
            }
            let policy = resolve(fields[index].trim(), config, selected, &mut HashSet::new());
            fields[index] = policy;
            *rule = fields.join(",").into();
        }
    }

    let original = config.clone();
    if let Some(rules) = config.get_mut("rules") {
        rewrite(rules, &original, selected);
    }
    if let Some(sub_rules) = config.get_mut("sub-rules").and_then(Value::as_mapping_mut) {
        for rules in sub_rules.values_mut() {
            rewrite(rules, &original, selected);
        }
    }
    config.insert("mode".into(), "rule".into());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> AutoChainSettings {
        AutoChainSettings {
            enabled: true,
            profile_uid: "p".into(),
            entry_sources: None,
            exit_source: "exit".into(),
            exit_name: "Home".into(),
            target_group: "Proxy".into(),
            interval: 5,
            tolerance: 50,
            max_latency: default_max_latency(),
            url: "https://www.gstatic.com/generate_204".into(),
        }
    }

    fn fixture() -> Result<(Mapping, Catalog)> {
        let config = serde_yaml_ng::from_str("proxy-groups:\n- {name: Proxy, type: select, proxies: [DIRECT]}\n")?;
        let mut catalog = Catalog {
            nodes: Vec::new(),
            warnings: Vec::new(),
        };
        for (source, host, name) in [
            ("a", "entry-a.example", "HK"),
            ("b", "entry-b.example", "HK"),
            ("duplicate", "entry-a.example", "Renamed"),
            ("exit", "exit.example", "Home"),
        ] {
            let proxy = serde_yaml_ng::from_str(&format!("name: {name}\ntype: socks5\nserver: {host}\nport: 1080\n"))?;
            catalog.nodes.push(Candidate {
                source: source.into(),
                source_label: source.into(),
                proxy,
            });
        }
        Ok((config, catalog))
    }

    #[test]
    fn shared_endpoint_keeps_distinct_protocols_and_accounts_as_relays() -> Result<()> {
        let mut config = Mapping::new();
        let mut catalog = Catalog {
            nodes: Vec::new(),
            warnings: Vec::new(),
        };
        for (name, kind, credential) in [
            ("HY2", "hysteria2", "a"),
            ("Reality", "vless", "b"),
            ("Exit", "vless", "c"),
            ("Exit alias", "vless", "c"),
        ] {
            catalog.nodes.push(Candidate {
                source: "ywj".into(),
                source_label: "ywj".into(),
                proxy: serde_yaml_ng::from_str(&format!(
                    "name: {name}\ntype: {kind}\nserver: shared.example\nport: 443\npassword: {credential}\n"
                ))?,
            });
        }
        let mut settings = settings();
        settings.exit_source = "ywj".into();
        settings.exit_name = "Exit".into();
        settings.entry_sources = Some(vec!["ywj".into()]);
        build(&mut config, &settings, &catalog)?;
        let routes = config["proxy-groups"][0]["proxies"].as_sequence().context("routes")?;
        assert_eq!(
            routes.len(),
            3,
            "Two relays plus REJECT; exclude only the exit and its alias"
        );
        assert!(routes[1].as_str().context("route")?.contains("HY2"));
        assert!(routes[2].as_str().context("route")?.contains("Reality"));
        for proxy in config["proxies"]
            .as_sequence()
            .context("proxies")?
            .iter()
            .filter(|proxy| proxy.get("dialer-proxy").is_some())
        {
            assert_eq!(proxy["password"].as_str(), Some("c"));
        }
        Ok(())
    }

    #[test]
    fn unified_rules_preserve_bypasses_and_route_all_proxy_policies() -> Result<()> {
        let mut config: Mapping = serde_yaml_ng::from_str(
            r"
mode: global
proxies:
- {name: Exit, type: socks5, server: 127.0.0.1, port: 1080}
proxy-groups:
- {name: CV Auto Chain, type: select, proxies: [REJECT]}
- {name: NCloud, type: select, proxies: [Exit, DIRECT]}
- {name: Google, type: select, proxies: [NCloud]}
- {name: ChinaMax, type: select, proxies: [DIRECT, Exit]}
- {name: Ads, type: select, proxies: [REJECT, Exit]}
- {name: Provider, type: select, proxies: [DIRECT], use: [subscription]}
rules:
- DOMAIN,school.example,DIRECT
- DOMAIN,ad.example,Ads
- DOMAIN,china.example,ChinaMax
- DOMAIN,google.example,Google
- DOMAIN,provider.example,Provider
- IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
- RULE-SET,foreign,NCloud,no-resolve
- AND,((NETWORK,TCP),(DST-PORT,443)),Exit
- SUB-RULE,(NETWORK,TCP),nested
- MATCH,NCloud
sub-rules:
  nested:
  - DOMAIN,nested.example,Exit
  - MATCH,REJECT-DROP
",
        )?;
        let selected = BTreeMap::from([("Provider".into(), "cached-provider-node".into())]);
        assert!(!routes_proxy_traffic(&config));
        route_all_proxy_traffic(&mut config, &selected);
        assert!(routes_proxy_traffic(&config));
        let expected = [
            "DOMAIN,school.example,DIRECT",
            "DOMAIN,ad.example,REJECT",
            "DOMAIN,china.example,DIRECT",
            "DOMAIN,google.example,CV Auto Chain",
            "DOMAIN,provider.example,CV Auto Chain",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "RULE-SET,foreign,CV Auto Chain,no-resolve",
            "AND,((NETWORK,TCP),(DST-PORT,443)),CV Auto Chain",
            "SUB-RULE,(NETWORK,TCP),nested",
            "MATCH,CV Auto Chain",
        ];
        assert_eq!(
            config["rules"],
            Value::from(expected.into_iter().map(Value::from).collect::<Vec<_>>())
        );
        assert_eq!(
            config["sub-rules"]["nested"][0].as_str(),
            Some("DOMAIN,nested.example,CV Auto Chain")
        );
        assert_eq!(config["sub-rules"]["nested"][1].as_str(), Some("MATCH,REJECT-DROP"));
        assert_eq!(config["mode"].as_str(), Some("rule"));
        let once = config.clone();
        route_all_proxy_traffic(&mut config, &selected);
        assert_eq!(config, once);
        config.insert("mode".into(), "direct".into());
        assert!(!routes_proxy_traffic(&config));
        config.insert("mode".into(), "rule".into());
        config.remove("rules");
        assert!(routes_proxy_traffic(&config));
        config.remove("sub-rules");
        assert!(!routes_proxy_traffic(&config));
        let mut settings = settings();
        settings.target_group.clear();
        settings.validate()?;
        Ok(())
    }

    #[test]
    fn measures_each_entry_through_the_same_exit_and_deduplicates() -> Result<()> {
        let (mut config, catalog) = fixture()?;
        build(&mut config, &settings(), &catalog)?;
        let proxies = config["proxies"].as_sequence().context("Missing proxies")?;
        let groups = config["proxy-groups"].as_sequence().context("Missing groups")?;
        let group = groups.last().context("Missing automatic group")?;
        assert_eq!(proxies.len(), 4);
        assert_eq!(group["type"].as_str(), Some("select"));
        assert_eq!(config["unified-delay"], Value::Bool(false));
        let routes = group["proxies"].as_sequence().context("Missing routes")?;
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].as_str(), Some("REJECT"));
        assert_ne!(routes[1], routes[2], "Identical subscription names must not collide");
        for route in &routes[1..] {
            let exit = proxies
                .iter()
                .find(|proxy| proxy.get("name") == Some(route))
                .context("Missing exit")?;
            assert_eq!(exit["server"].as_str(), Some("exit.example"));
            let entry = proxies
                .iter()
                .find(|proxy| proxy.get("name") == exit.get("dialer-proxy"))
                .context("Missing entry")?;
            assert_ne!(entry["server"], exit["server"]);
            assert!(entry.get("dialer-proxy").is_none());
        }
        assert_eq!(groups[0]["proxies"][0].as_str(), Some("DIRECT"));
        let mut rebuilt = without_generated(config.clone());
        build(&mut rebuilt, &settings(), &catalog)?;
        assert_eq!(rebuilt, config, "An unchanged catalog must not trigger a reload");
        Ok(())
    }

    #[test]
    fn selected_subscriptions_include_their_providers_but_not_other_sources() -> Result<()> {
        let (mut config, mut catalog) = fixture()?;
        catalog.nodes[0].source = "a/provider/relay".into();
        let mut settings = settings();
        settings.entry_sources = Some(vec!["a".into(), "b".into()]);
        build(&mut config, &settings, &catalog)?;
        assert_eq!(
            config["proxy-groups"][1]["proxies"]
                .as_sequence()
                .context("Expected generated proxy list")?
                .len(),
            3
        );
        settings.entry_sources = Some(vec!["a".into()]);
        let mut config = without_generated(config);
        build(&mut config, &settings, &catalog)?;
        assert_eq!(
            config["proxy-groups"][1]["proxies"]
                .as_sequence()
                .context("Expected generated proxy list")?
                .len(),
            2
        );
        assert_eq!(config["proxies"][0]["server"].as_str(), Some("entry-a.example"));
        assert_eq!(config["proxies"][1]["server"].as_str(), Some("exit.example"));
        settings.entry_sources = Some(vec![]);
        assert!(settings.validate().is_err());
        settings.entry_sources = Some(vec!["missing".into()]);
        let mut config = without_generated(config);
        build(&mut config, &settings, &catalog)?;
        assert_eq!(config["proxy-groups"][1]["proxies"][0].as_str(), Some("REJECT"));
        Ok(())
    }

    #[test]
    fn all_subscriptions_include_new_sources_and_legacy_settings_load() -> Result<()> {
        let (mut config, mut catalog) = fixture()?;
        let mut legacy = serde_json::to_value(settings())?;
        legacy
            .as_object_mut()
            .context("Expected serialized settings object")?
            .remove("max_latency");
        let settings: AutoChainSettings = serde_json::from_value(legacy)?;
        assert_eq!(settings.max_latency, 1000);
        build(&mut config, &settings, &catalog)?;
        let count = config["proxy-groups"][1]["proxies"]
            .as_sequence()
            .context("Expected generated proxy list")?
            .len();
        catalog.nodes.push(Candidate {
            source: "new-subscription".into(),
            source_label: "New".into(),
            proxy: serde_yaml_ng::from_str("name: New\ntype: socks5\nserver: new.example\nport: 1080\n")?,
        });
        let mut config = without_generated(config);
        build(&mut config, &settings, &catalog)?;
        assert_eq!(
            config["proxy-groups"][1]["proxies"]
                .as_sequence()
                .context("Expected generated proxy list")?
                .len(),
            count + 1
        );
        Ok(())
    }

    #[test]
    fn missing_exit_or_entries_never_fall_back_to_direct() -> Result<()> {
        for keep_exit in [false, true] {
            let (mut config, mut catalog) = fixture()?;
            catalog.nodes.retain(|node| (node.source == "exit") == keep_exit);
            build(&mut config, &settings(), &catalog)?;
            assert_eq!(
                config["proxy-groups"][1]["proxies"],
                Value::Sequence(vec!["REJECT".into()])
            );
        }
        Ok(())
    }

    #[test]
    fn preexisting_chains_are_not_reused_as_independent_entries() -> Result<()> {
        let (mut config, mut catalog) = fixture()?;
        for node in &mut catalog.nodes {
            if node.source != "exit" {
                node.proxy.insert("dialer-proxy".into(), "Home".into());
            }
        }
        build(&mut config, &settings(), &catalog)?;
        assert_eq!(config["proxies"], Value::Sequence(Vec::new()));
        Ok(())
    }
}
