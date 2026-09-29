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
    pub target_group: String,
    pub interval: u64,
    pub tolerance: u64,
    pub url: String,
}

impl AutoChainSettings {
    pub fn active_for(&self, profiles: &IProfiles) -> bool {
        self.enabled && profiles.current.as_deref() == Some(self.profile_uid.as_str())
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            (5..=300).contains(&self.interval),
            "Check interval must be between 5 and 300 seconds"
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
        ensure!(
            !self.exit_name.is_empty() && !self.target_group.is_empty(),
            "Choose an exit and a target group"
        );
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
        for candidate in &catalog.nodes {
            if !settings.entry_sources.as_ref().is_none_or(|sources| {
                sources.iter().any(|source| {
                    candidate.source == *source || candidate.source.starts_with(&format!("{source}/provider/"))
                })
            }) {
                continue;
            }
            let entry = &candidate.proxy;
            if entry.contains_key("dialer-proxy")
                || (entry.get("server") == exit.proxy.get("server") && entry.get("port") == exit.proxy.get("port"))
            {
                continue;
            }
            let id = identity(entry)?;
            if !seen.insert(id.clone()) {
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
    if routes.is_empty() {
        routes.push("REJECT".into());
    }
    let mut group = Mapping::new();
    group.insert("name".into(), GROUP.into());
    group.insert("type".into(), "url-test".into());
    group.insert("proxies".into(), routes.into());
    group.insert("url".into(), settings.url.clone().into());
    group.insert("interval".into(), settings.interval.into());
    group.insert("tolerance".into(), settings.tolerance.into());
    group.insert("timeout".into(), 2000.into());
    group.insert("max-failed-times".into(), 1.into());
    group.insert("lazy".into(), false.into());
    if settings.target_group != "GLOBAL" {
        let target = groups
            .iter_mut()
            .find(|group| group.get("name").and_then(Value::as_str) == Some(settings.target_group.as_str()))
            .context("The target proxy group no longer exists")?;
        ensure!(
            target.get("type").and_then(Value::as_str) == Some("select"),
            "Choose a manual selection group"
        );
        let target = target.as_mapping_mut().context("Invalid target group")?;
        let members = target
            .entry(Value::from("proxies"))
            .or_insert_with(|| Value::Sequence(Vec::new()));
        members
            .as_sequence_mut()
            .context("Invalid target group members")?
            .insert(0, GROUP.into());
    }
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
    fn measures_each_entry_through_the_same_exit_and_deduplicates() -> Result<()> {
        let (mut config, catalog) = fixture()?;
        build(&mut config, &settings(), &catalog)?;
        let proxies = config["proxies"].as_sequence().context("Missing proxies")?;
        let groups = config["proxy-groups"].as_sequence().context("Missing groups")?;
        let group = groups.last().context("Missing automatic group")?;
        assert_eq!(proxies.len(), 4);
        assert_eq!(group["lazy"], Value::Bool(false));
        assert_eq!(config["unified-delay"], Value::Bool(false));
        let routes = group["proxies"].as_sequence().context("Missing routes")?;
        assert_eq!(routes.len(), 2);
        assert_ne!(routes[0], routes[1], "Identical subscription names must not collide");
        for route in routes {
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
        assert_eq!(groups[0]["proxies"][0].as_str(), Some(GROUP));
        assert_eq!(groups[0]["proxies"][1].as_str(), Some("DIRECT"));
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
        assert_eq!(config["proxy-groups"][1]["proxies"].as_sequence().unwrap().len(), 2);
        settings.entry_sources = Some(vec!["a".into()]);
        let mut config = without_generated(config);
        build(&mut config, &settings, &catalog)?;
        assert_eq!(config["proxy-groups"][1]["proxies"].as_sequence().unwrap().len(), 1);
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
