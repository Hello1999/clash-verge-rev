use std::time::{Duration, Instant};

use futures::{StreamExt as _, stream};

use anyhow::Result;
use clash_verge_logging::{Type, logging};
use serde_yaml_ng::Value;

use crate::{
    config::Config,
    core::{CoreManager, handle::Handle, manager::RunningMode},
    enhance::auto_chain::{self, AutoChainSettings, GROUP},
    process::AsyncHandler,
};

async fn active_settings() -> Option<AutoChainSettings> {
    let profiles = Config::profiles().await.data_arc();
    Config::verge()
        .await
        .data_arc()
        .auto_chain
        .clone()
        .filter(|settings| settings.active_for(&profiles))
}

const PROBE_TIMEOUT: u32 = 5000;

#[derive(Default)]
struct SelectionState {
    selected: Option<String>,
    failures: u8,
    slow: u8,
    switched_at: Option<Instant>,
    warm: Vec<String>,
}

impl SelectionState {
    fn observe(&mut self, selected: &str, delay: Option<u32>, threshold: u64) {
        if self.selected.as_deref() != Some(selected) {
            self.selected = Some(selected.to_owned());
            self.failures = 0;
            self.slow = 0;
        }
        self.failures = if delay.is_none() {
            self.failures.saturating_add(1)
        } else {
            0
        };
        self.slow = if delay.is_some_and(|delay| u64::from(delay) > threshold) {
            self.slow.saturating_add(1)
        } else {
            0
        };
    }

    fn should_switch(&self, current: &str, delay: Option<u32>, best: u32, tolerance: u64) -> bool {
        current == "REJECT"
            || self.failures >= 2
            || (self.slow >= 3
                && self
                    .switched_at
                    .is_none_or(|time| time.elapsed() >= Duration::from_secs(30))
                && delay.is_some_and(|delay| u64::from(delay) > u64::from(best) + tolerance))
    }

    fn switched(&mut self, name: &str) {
        self.selected = Some(name.to_owned());
        self.failures = 0;
        self.slow = 0;
        self.switched_at = Some(Instant::now());
    }
}

async fn probe(name: &str, settings: &AutoChainSettings) -> Option<u32> {
    let result = tokio::time::timeout(
        Duration::from_millis(u64::from(PROBE_TIMEOUT) + 1000),
        Handle::mihomo().delay_proxy_by_name(name, &settings.url, PROBE_TIMEOUT),
    )
    .await
    .ok()?
    .ok()?;
    (result.delay > 0).then_some(result.delay)
}

async fn probe_active_routes(settings: &AutoChainSettings, selection: &mut SelectionState) -> Result<()> {
    let core = Handle::mihomo();
    let proxies = core.get_proxies().await?.proxies;
    let Some(group) = proxies.get(GROUP) else { return Ok(()) };
    let current = group.now.as_deref().unwrap_or("REJECT");
    let mut ranked: Vec<_> = group
        .all
        .iter()
        .flatten()
        .filter_map(|name| {
            if name == current || name == "REJECT" {
                return None;
            }
            let state = proxies.get(name)?.extra.get(&settings.url)?;
            let sample = state.history.last()?;
            let checked = chrono::DateTime::parse_from_rfc3339(&sample.time).ok()?;
            let age = chrono::Utc::now().signed_duration_since(checked).num_seconds();
            (state.alive && sample.delay > 0 && (0..=30).contains(&age)).then_some((sample.delay, name.clone()))
        })
        .collect();
    ranked.sort();
    // Refresh backups before using them; full-scan results alone never authorize a switch.
    let mut names: Vec<_> = std::iter::once(current.to_owned())
        .chain(ranked.into_iter().take(2).map(|(_, name)| name))
        .collect();
    for name in selection.warm.iter().chain(group.all.iter().flatten()) {
        if names.len() >= 3 {
            break;
        }
        if name != "REJECT" && !names.contains(name) && group.all.as_ref().is_some_and(|members| members.contains(name))
        {
            names.push(name.clone());
        }
    }
    selection.warm = names.iter().filter(|name| name.as_str() != "REJECT").cloned().collect();
    let results = futures::future::join_all(names.iter().map(|name| async move {
        if name == "REJECT" {
            None
        } else {
            probe(name, settings).await
        }
    }))
    .await;
    selection.observe(current, results[0], settings.max_latency);
    let best = names
        .iter()
        .zip(&results)
        .skip(1)
        .filter_map(|(name, delay)| delay.map(|delay| (delay, name)))
        .min_by_key(|(delay, _)| *delay);
    let next = match best {
        Some((delay, name)) if selection.should_switch(current, results[0], delay, settings.tolerance) => {
            Some(name.as_str())
        }
        _ if selection.failures >= 2 && current != "REJECT" => Some("REJECT"),
        _ => None,
    };
    if let Some(next) = next {
        let _write = Config::lock_config_write().await;
        if active_settings().await.as_ref() == Some(settings) {
            core.select_node_for_group(GROUP, next).await?;
            selection.switched(next);
            logging!(info, Type::Core, "Automatic chain switched from {current} to {next}");
        }
    }
    Ok(())
}

async fn scan_routes(settings: &AutoChainSettings) -> Result<()> {
    let proxies = Handle::mihomo().get_proxies().await?.proxies;
    let Some(group) = proxies.get(GROUP) else { return Ok(()) };
    let mut names = group.all.clone().unwrap_or_default();
    names.retain(|name| name != "REJECT" && Some(name.as_str()) != group.now.as_deref());
    let mut pending = stream::iter(names.into_iter().map(|name| async move {
        if active_settings().await.as_ref() == Some(settings) {
            probe(&name, settings).await;
        }
    }))
    .buffer_unordered(4);
    while pending.next().await.is_some() {}
    Ok(())
}

async fn refresh_catalog(settings: &AutoChainSettings) -> Result<()> {
    if matches!(*CoreManager::global().get_running_mode(), RunningMode::NotRunning) {
        return Ok(());
    }
    let profiles = Config::profiles().await.data_arc();
    let Some(config) = Config::runtime().await.data_arc().config.clone() else {
        return Ok(());
    };
    if !config
        .get("proxy-groups")
        .and_then(Value::as_sequence)
        .is_some_and(|groups| {
            groups
                .iter()
                .any(|group| group.get("name").and_then(Value::as_str) == Some(GROUP))
        })
    {
        return Ok(());
    }
    let mut rebuilt = auto_chain::without_generated(config.clone());
    let catalog = auto_chain::collect(&profiles, &rebuilt).await?;
    auto_chain::build(&mut rebuilt, settings, &catalog)?;
    if rebuilt.get("proxies") != config.get("proxies") {
        let _write = Config::lock_config_write().await;
        if active_settings().await.as_ref() == Some(settings) {
            CoreManager::global().update_config_checked().await?;
            Handle::refresh_clash();
        }
    }
    Ok(())
}

pub fn start() {
    AsyncHandler::spawn(|| async {
        let mut previous = None;
        let mut selection = SelectionState::default();
        loop {
            let current = active_settings().await;
            if previous != current {
                selection = SelectionState::default();
                previous = current.clone();
            }
            if let Some(settings) = current
                && let Err(error) = probe_active_routes(&settings, &mut selection).await
            {
                logging!(debug, Type::Core, "Automatic chain probe will retry: {error:#}");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    AsyncHandler::spawn(|| async {
        loop {
            let settings = active_settings().await;
            if let Some(settings) = &settings
                && let Err(error) = scan_routes(settings).await
            {
                logging!(debug, Type::Core, "Automatic chain scan will retry: {error:#}");
            }
            tokio::time::sleep(Duration::from_secs(settings.map_or(2, |settings| settings.interval))).await;
        }
    });
    AsyncHandler::spawn(|| async {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            if let Some(settings) = active_settings().await
                && let Err(error) = refresh_catalog(&settings).await
            {
                logging!(
                    warn,
                    Type::Core,
                    "Automatic chain candidate refresh will retry: {error:#}"
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_routes_do_not_chase_lower_latency() {
        let mut state = SelectionState::default();
        for _ in 0..10 {
            state.observe("current", Some(700), 1000);
            assert!(!state.should_switch("current", Some(700), 100, 50));
        }
    }

    #[test]
    fn failures_require_confirmation_and_bypass_cooldown() {
        let mut state = SelectionState::default();
        state.switched("current");
        state.observe("current", None, 1000);
        assert!(!state.should_switch("current", None, 100, 50));
        state.observe("current", Some(300), 1000);
        assert_eq!(state.failures, 0);
        state.observe("current", None, 1000);
        state.observe("current", None, 1000);
        assert!(state.should_switch("current", None, 100, 50));
    }

    #[test]
    fn sustained_latency_requires_improvement_and_cooldown() {
        let mut state = SelectionState::default();
        for _ in 0..2 {
            state.observe("current", Some(1500), 1000);
            assert!(!state.should_switch("current", Some(1500), 200, 50));
        }
        state.observe("current", Some(1500), 1000);
        assert!(state.should_switch("current", Some(1500), 200, 50));
        assert!(!state.should_switch("current", Some(1500), 1480, 50));
        state.switched_at = Some(Instant::now());
        assert!(!state.should_switch("current", Some(1500), 200, 50));
        state.observe("current", Some(700), 1000);
        assert_eq!(state.slow, 0);
        assert!(state.should_switch("REJECT", None, 200, 50));
    }
}
