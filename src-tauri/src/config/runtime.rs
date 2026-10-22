use serde_yaml_ng::{Mapping, Value};
use smartstring::alias::String;
use std::collections::{HashMap, HashSet};

use crate::enhance::field::use_keys;
use anyhow::{Result, ensure};

const PATCH_CONFIG_INNER: [&str; 5] = ["allow-lan", "ipv6", "log-level", "unified-delay", "tunnels"];

#[derive(Default, Clone)]
pub struct IRuntime {
    pub config: Option<Mapping>,
    pub(crate) dns_override: Option<super::dns::DnsOverrideState>,
    // Keys seen in the profile pipeline, including merge and script output.
    pub exists_keys: HashSet<String>,
    // TODO 或许可以用 FixMap 来存储以提升效率
    pub chain_logs: HashMap<String, Vec<(String, String)>>,
    pub(crate) manual_chain_base: Option<Value>,
}

impl IRuntime {
    #[inline]
    pub fn patch_config(&mut self, patch: &Mapping) {
        let config = if let Some(config) = self.config.as_mut() {
            config
        } else {
            return;
        };

        for key in PATCH_CONFIG_INNER.iter() {
            if let Some(value) = patch.get(key) {
                config.insert((*key).into(), value.clone());
            }
        }

        let Some(patch_tun) = patch.get("tun") else {
            return;
        };

        let tun_key = Value::from("tun");
        if !matches!(config.get(&tun_key), Some(Value::Mapping(_))) {
            config.insert(tun_key.clone(), Value::Mapping(Mapping::new()));
        }

        if let (Some(patch_tun_mapping), Some(Value::Mapping(tun))) = (patch_tun.as_mapping(), config.get_mut(&tun_key))
        {
            for key in use_keys(patch_tun_mapping) {
                if let Some(value) = patch_tun_mapping.get(key.as_str()) {
                    tun.insert(Value::from(key.as_str()), value.clone());
                }
            }
        }
    }

    /// Restores subscription links before applying or removing a temporary manual chain.
    #[inline]
    pub fn update_proxy_chain_config(&mut self, proxy_chain_config: Option<Value>) -> Result<()> {
        let config = self
            .config
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Runtime configuration is unavailable"))?;
        let base = self.manual_chain_base.as_ref().or_else(|| config.get("proxies"));
        let mut proxies = base.and_then(Value::as_sequence).cloned().unwrap_or_default();
        if let Some(chain) = &proxy_chain_config {
            let chain = chain
                .as_sequence()
                .ok_or_else(|| anyhow::anyhow!("Expected an ordered list of proxy names"))?;
            ensure!(chain.len() >= 2, "A manual chain needs at least two nodes");
            let mut seen = HashSet::new();
            for name in chain {
                let name = name.as_str().ok_or_else(|| anyhow::anyhow!("Expected a proxy name"))?;
                ensure!(seen.insert(name), "A manual chain cannot repeat a node");
                ensure!(
                    proxies
                        .iter()
                        .any(|proxy| proxy.get("name").and_then(Value::as_str) == Some(name)),
                    "Unknown manual chain node: {name}"
                );
            }
            for pair in chain.windows(2) {
                for proxy in &mut proxies {
                    if proxy.get("name") == Some(&pair[1]) {
                        proxy["dialer-proxy"] = pair[0].clone();
                    }
                }
            }
            if self.manual_chain_base.is_none() {
                self.manual_chain_base = config.get("proxies").cloned();
            }
        } else {
            self.manual_chain_base = None;
        }
        config.insert("proxies".into(), proxies.into());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_chain_changes_restore_original_links_without_restarting() -> Result<()> {
        let config: Mapping = serde_yaml_ng::from_str(
            "proxies:\n- {name: A, type: socks5, server: localhost, port: 1001}\n- {name: B, type: socks5, server: localhost, port: 1002}\n- {name: Exit, type: socks5, server: localhost, port: 1003, dialer-proxy: A}\n- {name: Native, type: socks5, server: localhost, port: 1004, dialer-proxy: B}\n",
        )?;
        let mut runtime = IRuntime {
            config: Some(config.clone()),
            ..IRuntime::default()
        };
        runtime.update_proxy_chain_config(Some(vec![Value::from("B"), "Exit".into()].into()))?;
        let nodes = runtime
            .config
            .as_ref()
            .and_then(|config| config.get("proxies"))
            .ok_or_else(|| anyhow::anyhow!("proxies"))?;
        assert_eq!(nodes[2]["dialer-proxy"].as_str(), Some("B"));
        assert_eq!(nodes[3]["dialer-proxy"].as_str(), Some("B"));
        runtime.update_proxy_chain_config(Some(vec![Value::from("A"), "B".into()].into()))?;
        runtime.update_proxy_chain_config(None)?;
        assert_eq!(runtime.config, Some(config));
        assert!(runtime.manual_chain_base.is_none());
        Ok(())
    }

    #[test]
    fn invalid_manual_chains_leave_the_runtime_unchanged() -> Result<()> {
        let config = serde_yaml_ng::from_str("proxies: [{name: A, type: direct}, {name: B, type: direct}]")?;
        let mut runtime = IRuntime {
            config: Some(config),
            ..IRuntime::default()
        };
        for chain in [vec!["A", "A"], vec!["A", "missing"], vec!["A"]] {
            let before = runtime.config.clone();
            assert!(
                runtime
                    .update_proxy_chain_config(Some(chain.into_iter().map(Value::from).collect::<Vec<_>>().into()))
                    .is_err()
            );
            assert_eq!(runtime.config, before);
            assert!(runtime.manual_chain_base.is_none());
        }
        Ok(())
    }
}
