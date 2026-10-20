use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

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

static MANUAL: tokio::sync::Mutex<Option<(AutoChainSettings, String)>> = tokio::sync::Mutex::const_new(None);
static SCAN: tokio::sync::Notify = tokio::sync::Notify::const_new();
static SCAN_VERSION: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct SelectionState {
    selected: Option<String>,
    failures: u8,
    switched_at: Option<Instant>,
    reviewed_scan: u64,
}

impl SelectionState {
    fn observe(&mut self, selected: &str, delay: Option<u32>) {
        if self.selected.as_deref() != Some(selected) {
            self.switched(selected);
        }
        self.failures = if delay.is_none() {
            self.failures.saturating_add(1)
        } else {
            0
        };
    }

    fn review_due(&mut self, scan_version: u64, interval: u64) -> bool {
        let due = scan_version != self.reviewed_scan
            && self
                .switched_at
                .is_some_and(|time| time.elapsed() >= Duration::from_secs(interval.max(600)));
        if due {
            self.reviewed_scan = scan_version;
        }
        due
    }

    fn should_switch(
        &self,
        current: &str,
        delay: Option<u32>,
        best: u32,
        tolerance: u64,
        review: bool,
        manual: bool,
    ) -> bool {
        current == "REJECT"
            || self.failures >= 2
            || (!manual && review && delay.is_some_and(|delay| u64::from(delay) > u64::from(best) + tolerance))
    }

    fn switched(&mut self, name: &str) {
        self.selected = Some(name.to_owned());
        self.failures = 0;
        self.switched_at = Some(Instant::now());
    }
}

pub async fn select_route(name: &str) -> Result<()> {
    let _write = Config::lock_config_write().await;
    let settings = active_settings()
        .await
        .ok_or_else(|| anyhow::anyhow!("Automatic chain is disabled"))?;
    let core = Handle::mihomo();
    let proxies = core.get_proxies().await?.proxies;
    anyhow::ensure!(
        name != "REJECT"
            && proxies
                .get(GROUP)
                .and_then(|group| group.all.as_ref())
                .is_some_and(|members| members.iter().any(|member| member == name)),
        "Unknown automatic chain route"
    );
    core.select_node_for_group(GROUP, name).await?;
    *MANUAL.lock().await = Some((settings, name.to_owned()));
    Ok(())
}

pub async fn manual_route(settings: &AutoChainSettings) -> Option<String> {
    MANUAL
        .lock()
        .await
        .as_ref()
        .filter(|(saved, _)| saved == settings)
        .map(|(_, name)| name.clone())
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
    let manual_choice = manual_route(settings).await;
    let current_delay = if current == "REJECT" {
        None
    } else {
        probe(current, settings).await
    };
    selection.observe(current, current_delay);
    let scan_version = SCAN_VERSION.load(Ordering::Acquire);
    let review = selection.review_due(scan_version, settings.interval);
    let failed = current == "REJECT" || selection.failures >= 2;
    if !failed && (!review || manual_choice.as_deref() == Some(current)) {
        return Ok(());
    }
    if failed {
        SCAN.notify_one();
    }
    let mut ranked: Vec<_> = group
        .all
        .iter()
        .flatten()
        .filter(|name| name.as_str() != "REJECT" && name.as_str() != current)
        .map(|name| {
            let delay = proxies
                .get(name)
                .and_then(|proxy| proxy.extra.get(&settings.url))
                .filter(|state| state.alive)
                .and_then(|state| state.history.last())
                .filter(|sample| sample.delay > 0)
                .map_or(u16::MAX, |sample| sample.delay);
            (delay, name.clone())
        })
        .collect();
    ranked.sort();
    // Cached rankings only prioritize candidates; verify each complete route before switching.
    let best = futures::future::join_all(
        ranked
            .into_iter()
            .take(3)
            .map(|(_, name)| async move { probe(&name, settings).await.map(|delay| (delay, name)) }),
    )
    .await
    .into_iter()
    .flatten()
    .min_by_key(|(delay, _)| *delay);
    let next = match best {
        Some((delay, name))
            if selection.should_switch(
                current,
                current_delay,
                delay,
                settings.tolerance,
                review,
                manual_choice.as_deref() == Some(current),
            ) =>
        {
            Some(name)
        }
        _ if failed && current != "REJECT" => Some("REJECT".to_owned()),
        _ => None,
    };
    if let Some(next) = next {
        let _write = Config::lock_config_write().await;
        if active_settings().await.as_ref() == Some(settings)
            && manual_route(settings).await == manual_choice
            && core
                .get_proxies()
                .await?
                .proxies
                .get(GROUP)
                .and_then(|group| group.now.as_deref())
                == Some(current)
        {
            core.select_node_for_group(GROUP, &next).await?;
            *MANUAL.lock().await = None;
            selection.switched(&next);
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
                if current.is_none() {
                    *MANUAL.lock().await = None;
                }
                SCAN.notify_one();
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
            SCAN_VERSION.fetch_add(1, Ordering::Release);
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(settings.map_or(2, |settings| settings.interval.max(600)))) => {},
                _ = SCAN.notified() => {},
            }
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
    fn legacy_short_intervals_still_wait_ten_minutes() {
        let mut state = SelectionState::default();
        state.switched("current");
        state.switched_at = Some(Instant::now() - Duration::from_secs(599));
        assert!(!state.review_due(1, 15));
        state.switched_at = Some(Instant::now() - Duration::from_secs(600));
        assert!(state.review_due(1, 15));
        assert!(!state.review_due(1, 15));
        state.switched("replacement");
        assert!(!state.review_due(2, 600));
    }

    #[test]
    fn healthy_routes_wait_for_periodic_review() {
        let mut state = SelectionState::default();
        for _ in 0..10 {
            state.observe("current", Some(4000));
            assert!(!state.should_switch("current", Some(4000), 100, 50, false, false));
        }
        assert!(state.should_switch("current", Some(4000), 100, 50, true, false));
        assert!(!state.should_switch("current", Some(4000), 3980, 50, true, false));
    }

    #[test]
    fn manual_routes_ignore_periodic_review_until_failure() {
        let mut state = SelectionState::default();
        state.observe("manual", Some(4000));
        assert!(!state.should_switch("manual", Some(4000), 100, 50, true, true));
        state.observe("manual", None);
        assert!(!state.should_switch("manual", None, 100, 50, true, true));
        state.observe("manual", Some(300));
        assert_eq!(state.failures, 0);
        state.observe("manual", None);
        state.observe("manual", None);
        assert!(state.should_switch("manual", None, 100, 50, false, true));
        assert!(state.should_switch("REJECT", None, 100, 50, false, false));
    }
}
