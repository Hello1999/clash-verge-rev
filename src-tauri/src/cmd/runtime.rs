use super::CmdResult;
use crate::{cmd::StringifyErr as _, config::Config, core::CoreManager, utils::yaml_emitter};
use anyhow::{Context as _, anyhow};
use serde_yaml_ng::Mapping;
use smartstring::alias::String;
use std::collections::HashMap;

#[tauri::command]
pub async fn get_runtime_config() -> CmdResult<Option<Mapping>> {
    Ok(Config::runtime().await.latest_arc().config.clone())
}

#[tauri::command]
pub async fn get_runtime_yaml() -> CmdResult<String> {
    let runtime = Config::runtime().await;
    let runtime = runtime.latest_arc();

    let config = runtime.config.as_ref();
    config
        .ok_or_else(|| anyhow!("failed to parse config to yaml file"))
        .and_then(|config| {
            yaml_emitter::to_mihomo_config_string(config)
                .context("failed to convert config to yaml")
                .map(|s| s.into())
        })
        .stringify_err()
}

#[tauri::command]
pub async fn get_runtime_logs() -> CmdResult<HashMap<String, Vec<(String, String)>>> {
    Ok(Config::runtime().await.latest_arc().chain_logs.clone())
}

#[tauri::command]
pub fn take_discarded_keys_notice() -> Option<String> {
    crate::enhance::take_discarded_keys_notice()
}

#[tauri::command]
pub async fn get_runtime_proxy_chain_config(proxy_chain_exit_node: String) -> CmdResult<String> {
    let runtime = Config::runtime().await;
    let runtime = runtime.latest_arc();

    let config = runtime
        .config
        .as_ref()
        .ok_or_else(|| anyhow!("failed to parse config to yaml file"))
        .stringify_err()?;

    if let Some(serde_yaml_ng::Value::Sequence(proxies)) = config.get("proxies") {
        let mut proxy_name = Some(Some(proxy_chain_exit_node.as_str()));
        let mut proxies_chain = Vec::new();

        while let Some(proxy) = proxies.iter().find(|proxy| {
            if let serde_yaml_ng::Value::Mapping(proxy_map) = proxy {
                proxy_map.get("name").map(|x| x.as_str()) == proxy_name && proxy_map.get("dialer-proxy").is_some()
            } else {
                false
            }
        }) {
            proxies_chain.push(proxy.to_owned());
            proxy_name = proxy.get("dialer-proxy").map(|x| x.as_str());
        }

        if let Some(entry_proxy) = proxies
            .iter()
            .find(|proxy| proxy.get("name").map(|x| x.as_str()) == proxy_name)
            && !proxies_chain.is_empty()
        {
            proxies_chain.push(entry_proxy.to_owned());
        }

        proxies_chain.reverse();

        let mut config: HashMap<String, Vec<serde_yaml_ng::Value>> = HashMap::new();

        config.insert("proxies".into(), proxies_chain);

        yaml_emitter::to_mihomo_config_string(&config)
            .context("YAML generation failed")
            .map(|s| s.into())
            .stringify_err()
    } else {
        Err("failed to get proxies or proxy-groups".into())
    }
}

#[tauri::command]
pub async fn update_proxy_chain_config_in_runtime(proxy_chain_config: Option<serde_yaml_ng::Value>) -> CmdResult<()> {
    let profiles = Config::profiles().await.data_arc();
    if Config::verge()
        .await
        .data_arc()
        .auto_chain
        .as_ref()
        .is_some_and(|settings| settings.active_for(&profiles))
    {
        return Err("Disable automatic chain selection before editing a manual chain".into());
    }
    match CoreManager::global()
        .update_runtime_config(|d| d.update_proxy_chain_config(proxy_chain_config))
        .await
    {
        Ok(outcome) if outcome.is_valid() => Ok(()),
        Ok(outcome) => Err(format!("Failed to apply runtime proxy chain config: {outcome}").into()),
        Err(err) => Err(format!("Failed to apply runtime proxy chain config: {err:#}").into()),
    }
}

#[tauri::command]
pub async fn get_auto_chain_options() -> CmdResult<crate::enhance::auto_chain::AutoChainOptions> {
    let profiles = Config::profiles().await.data_arc();
    let runtime = Config::runtime().await.data_arc();
    let config = runtime
        .config
        .as_ref()
        .ok_or("The runtime configuration is unavailable")?;
    crate::enhance::auto_chain::collect(&profiles, config)
        .await
        .map(|catalog| catalog.options())
        .stringify_err()
}

#[derive(serde::Serialize)]
pub struct AutoChainRouteStatus {
    name: std::string::String,
    alive: bool,
    delay: Option<u16>,
    checked_at: Option<std::string::String>,
}

#[derive(serde::Serialize)]
pub struct AutoChainStatus {
    selected: Option<std::string::String>,
    routes: Vec<AutoChainRouteStatus>,
    healthy: usize,
    total: usize,
    in_use: bool,
    fixed: bool,
    delay: Option<u16>,
    checked_at: Option<std::string::String>,
}

#[tauri::command]
pub async fn get_auto_chain_status() -> CmdResult<Option<AutoChainStatus>> {
    use crate::enhance::auto_chain::GROUP;
    let profiles = Config::profiles().await.data_arc();
    let Some(settings) = Config::verge()
        .await
        .data_arc()
        .auto_chain
        .clone()
        .filter(|settings| settings.active_for(&profiles))
    else {
        return Ok(None);
    };
    let proxies = crate::core::handle::Handle::mihomo()
        .get_proxies()
        .await
        .stringify_err()?
        .proxies;
    let group = proxies
        .get(GROUP)
        .ok_or("The automatic chain is not loaded in the core")?;
    let members = group.all.as_deref().unwrap_or_default();
    let state = |name: &str| proxies.get(name).and_then(|proxy| proxy.extra.get(&settings.url));
    let last = group
        .now
        .as_deref()
        .and_then(state)
        .and_then(|state| state.history.last());
    let mode = Config::runtime()
        .await
        .data_arc()
        .config
        .as_ref()
        .and_then(|config| config.get("mode"))
        .and_then(|mode| mode.as_str())
        .unwrap_or("rule")
        .to_owned();
    Ok(Some(AutoChainStatus {
        selected: group.now.clone(),
        routes: members
            .iter()
            .filter(|name| name.as_str() != "REJECT")
            .map(|name| {
                let state = state(name);
                let sample = state.and_then(|state| state.history.last());
                let alive = state.is_some_and(|state| state.alive) && sample.is_some_and(|sample| sample.delay > 0);
                AutoChainRouteStatus {
                    name: name.clone(),
                    alive,
                    delay: sample.filter(|_| alive).map(|sample| sample.delay),
                    checked_at: sample.map(|sample| sample.time.clone()),
                }
            })
            .collect(),
        healthy: members
            .iter()
            .filter(|name| {
                state(name)
                    .is_some_and(|state| state.alive && state.history.last().is_some_and(|sample| sample.delay > 0))
            })
            .count(),
        total: members.iter().filter(|name| name.as_str() != "REJECT").count(),
        in_use: mode != "direct"
            && (mode == "global") == (settings.target_group == "GLOBAL")
            && proxies
                .get(&settings.target_group)
                .and_then(|group| group.now.as_deref())
                == Some(GROUP),
        fixed: group.fixed.as_ref().is_some_and(|fixed| !fixed.is_empty()),
        delay: last
            .filter(|_| group.now.as_deref().and_then(state).is_some_and(|state| state.alive))
            .map(|sample| sample.delay),
        checked_at: last.map(|sample| sample.time.clone()),
    }))
}

#[tauri::command]
pub async fn get_claude_guard_status() -> CmdResult<serde_json::Value> {
    use crate::enhance::claude_guard::{self, DOMAINS, EXPECTED_EXIT, OUTBOUND};
    let enabled = claude_guard::enabled(Config::verge().await.data_arc().claude_guard_enabled);
    let runtime = Config::runtime().await.data_arc();
    let routes: Vec<_> = runtime
        .config
        .as_ref()
        .and_then(|c| c.get("proxies"))
        .and_then(serde_yaml_ng::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter(|p| claude_guard::is_fixed_exit(p))
        .filter_map(|p| p.get("name").and_then(serde_yaml_ng::Value::as_str))
        .collect();
    let live = crate::core::handle::Handle::mihomo().get_proxies().await.ok();
    let members = live
        .as_ref()
        .and_then(|p| p.proxies.get(OUTBOUND))
        .and_then(|p| p.all.as_ref());
    let routing_ready = enabled
        && members.is_some_and(|names| !names.is_empty() && names.iter().all(|name| routes.contains(&name.as_str())));
    Ok(serde_json::json!({
        "enabled": enabled, "locked": cfg!(target_os = "windows"),
        "routing_ready": routing_ready, "exit_verified": false,
        "expected_exit": EXPECTED_EXIT, "domains": DOMAINS,
        "system_filter_verified": false
    }))
}
