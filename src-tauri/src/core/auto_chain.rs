use std::{
    collections::HashMap,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use futures::{StreamExt as _, stream};

use anyhow::Result;
use clash_verge_logging::{Type, logging};
use serde_yaml_ng::Value;
use tauri_plugin_mihomo::models::Extra;

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

const BACKUP_INTERVAL: u64 = 15;
pub const HEALTH_MAX_AGE: i64 = 60;

static PROBE_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
static CHANGED: tokio::sync::Notify = tokio::sync::Notify::const_new();
type ProbeState = Arc<tokio::sync::Mutex<Option<(Instant, Option<u32>)>>>;
static PROBES: LazyLock<tokio::sync::Mutex<HashMap<(AutoChainSettings, String), ProbeState>>> =
    LazyLock::new(|| tokio::sync::Mutex::new(HashMap::new()));

static MANUAL: tokio::sync::Mutex<Option<(AutoChainSettings, String)>> = tokio::sync::Mutex::const_new(None);
static SCAN: tokio::sync::Notify = tokio::sync::Notify::const_new();
static SCAN_VERSION: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct SelectionState {
    selected: Option<String>,
    failures: u8,
    switched_at: Option<Instant>,
    reviewed_scan: u64,
    initial_scan: bool,
    stale_routes: Vec<String>,
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
            && (self.initial_scan
                || self
                    .switched_at
                    .is_some_and(|time| time.elapsed() >= Duration::from_secs(interval.max(600))));
        if due {
            self.reviewed_scan = scan_version;
            self.initial_scan = false;
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
            || self.failures >= 1
            || (!manual && review && delay.is_some_and(|delay| u64::from(delay) > u64::from(best) + tolerance))
    }

    fn replacement(
        &self,
        current: &str,
        delay: Option<u32>,
        best: Option<(u32, String)>,
        tolerance: u64,
        review: bool,
        manual: bool,
    ) -> Option<String> {
        best.filter(|(best, _)| self.should_switch(current, delay, *best, tolerance, review, manual))
            .map(|(_, name)| name)
    }

    fn switched(&mut self, name: &str) {
        if let Some(previous) = self
            .selected
            .take()
            .filter(|previous| previous != name && previous != "REJECT")
        {
            self.stale_routes.push(previous);
        }
        self.selected = Some(name.to_owned());
        self.failures = 0;
        self.switched_at = Some(Instant::now());
    }
}

pub async fn select_route(name: &str) -> Result<()> {
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
    anyhow::ensure!(
        probe(
            name,
            &settings,
            fresh_delay(proxies.get(name).and_then(|proxy| proxy.extra.get(&settings.url)))
        )
        .await
        .is_some(),
        "The complete chain failed its connection test"
    );
    let _write = Config::lock_config_write().await;
    anyhow::ensure!(
        active_settings().await.as_ref() == Some(&settings),
        "Automatic chain settings changed during the test"
    );
    let previous = core
        .get_proxies()
        .await?
        .proxies
        .get(GROUP)
        .and_then(|group| group.now.clone());
    core.select_node_for_group(GROUP, name).await?;
    *MANUAL.lock().await = Some((settings, name.to_owned()));
    if let Some(previous) = previous.filter(|previous| previous != name) {
        close_connections(&[&previous]).await?;
    }
    Ok(())
}

pub fn settings_changed() {
    CHANGED.notify_one();
    SCAN.notify_one();
}

pub fn fresh_delay(state: Option<&Extra>) -> Option<u16> {
    let state = state.filter(|state| state.alive)?;
    let sample = state.history.last().filter(|sample| sample.delay > 0)?;
    let checked = chrono::DateTime::parse_from_rfc3339(&sample.time).ok()?;
    (0..=HEALTH_MAX_AGE)
        .contains(&chrono::Utc::now().signed_duration_since(checked).num_seconds())
        .then_some(sample.delay)
}

pub async fn close_connections(names: &[&str]) -> Result<()> {
    if names.is_empty() {
        return Ok(());
    }
    let core = Handle::mihomo();
    for connection in core.get_connections().await?.connections.into_iter().flatten() {
        if connection.chains.iter().any(|name| names.contains(&name.as_str())) {
            core.close_connection(&connection.id).await?;
        }
    }
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

fn probe_timeout(maximum: u32, last_delay: Option<u16>) -> u32 {
    last_delay.map_or(maximum, |delay| (u32::from(delay) * 3).max(5000).min(maximum))
}

async fn probe(name: &str, settings: &AutoChainSettings, last_delay: Option<u16>) -> Option<u32> {
    coalesced_probe(name, settings, async {
        let _permit = PROBE_SLOTS.acquire().await.ok()?;
        if active_settings().await.as_ref() != Some(settings) {
            return None;
        }
        let timeout = probe_timeout(settings.timeout, last_delay);
        tokio::time::timeout(
            Duration::from_millis(u64::from(timeout) + 1000),
            Handle::mihomo().delay_proxy_by_name(name, &settings.url, timeout),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .map(|result| result.delay)
        .filter(|delay| *delay > 0)
    })
    .await
}

async fn coalesced_probe(
    name: &str,
    settings: &AutoChainSettings,
    request: impl std::future::Future<Output = Option<u32>>,
) -> Option<u32> {
    let requested = Instant::now();
    let state = Arc::clone(
        PROBES
            .lock()
            .await
            .entry((settings.clone(), name.to_owned()))
            .or_default(),
    );
    let mut sample = state.lock().await;
    if let Some((finished, delay)) = *sample
        && finished >= requested
    {
        return delay;
    }
    let result = request.await;
    *sample = Some((Instant::now(), result));
    result
}

async fn probe_active_routes(settings: &AutoChainSettings, selection: &mut SelectionState) -> Result<()> {
    let core = Handle::mihomo();
    let proxies = core.get_proxies().await?.proxies;
    let Some(group) = proxies.get(GROUP) else { return Ok(()) };
    let current = group.now.as_deref().unwrap_or("REJECT");
    let manual_choice = manual_route(settings).await;
    if !selection.stale_routes.is_empty() {
        close_connections(&selection.stale_routes.iter().map(String::as_str).collect::<Vec<_>>()).await?;
        selection.stale_routes.clear();
    }
    let current_delay = if current == "REJECT" {
        None
    } else {
        probe(
            current,
            settings,
            fresh_delay(proxies.get(current).and_then(|proxy| proxy.extra.get(&settings.url))),
        )
        .await
    };
    selection.observe(current, current_delay);
    let scan_version = SCAN_VERSION.load(Ordering::Acquire);
    let review = selection.review_due(scan_version, settings.interval);
    let failed = current == "REJECT" || selection.failures >= 1;
    if !failed && (!review || manual_choice.as_deref() == Some(current)) {
        return Ok(());
    }
    if failed && selection.failures == 1 {
        SCAN.notify_one();
    }
    let mut ranked: Vec<_> = group
        .all
        .iter()
        .flatten()
        .filter(|name| name.as_str() != "REJECT" && name.as_str() != current)
        .map(|name| {
            let delay =
                fresh_delay(proxies.get(name).and_then(|proxy| proxy.extra.get(&settings.url))).unwrap_or(u16::MAX);
            (delay, name.clone())
        })
        .collect();
    ranked.sort();
    // Cached rankings only prioritize candidates; verify each complete route before switching.
    let states = &proxies;
    let best = probe_candidates(ranked.into_iter().map(|(_, name)| name).collect(), |name| async move {
        let delay = fresh_delay(states.get(&name).and_then(|proxy| proxy.extra.get(&settings.url)));
        probe(&name, settings, delay).await.map(|delay| (delay, name))
    })
    .await;
    let next = selection.replacement(
        current,
        current_delay,
        best,
        settings.tolerance,
        review,
        manual_choice.as_deref() == Some(current),
    );
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
            selection.initial_scan |= failed;
            Handle::refresh_proxy_config();
            logging!(info, Type::Core, "Automatic chain switched from {current} to {next}");
        }
    }
    if !selection.stale_routes.is_empty() {
        close_connections(&selection.stale_routes.iter().map(String::as_str).collect::<Vec<_>>()).await?;
        selection.stale_routes.clear();
    }
    Ok(())
}

async fn probe_candidates<F, Fut>(names: Vec<String>, probe: F) -> Option<(u32, String)>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Option<(u32, String)>>,
{
    // Recovery considers the entire pool; an unavailable early batch cannot hide later relays.
    for batch in names.chunks(2) {
        if let Some(best) = futures::future::join_all(batch.iter().cloned().map(&probe))
            .await
            .into_iter()
            .flatten()
            .min_by_key(|(delay, _)| *delay)
        {
            return Some(best);
        }
    }
    None
}

async fn scan_routes(settings: &AutoChainSettings) -> Result<()> {
    let proxies = Handle::mihomo().get_proxies().await?.proxies;
    let Some(group) = proxies.get(GROUP) else { return Ok(()) };
    let mut names = group.all.clone().unwrap_or_default();
    names.retain(|name| name != "REJECT" && Some(name.as_str()) != group.now.as_deref());
    let states = &proxies;
    let mut pending = stream::iter(names.into_iter().map(|name| async move {
        if active_settings().await.as_ref() == Some(settings) {
            probe(
                &name,
                settings,
                fresh_delay(states.get(&name).and_then(|proxy| proxy.extra.get(&settings.url))),
            )
            .await;
        }
    }))
    .buffer_unordered(1);
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
                PROBES
                    .lock()
                    .await
                    .retain(|(settings, _), _| Some(settings) == current.as_ref());
                selection = SelectionState {
                    initial_scan: true,
                    reviewed_scan: SCAN_VERSION.load(Ordering::Acquire),
                    ..SelectionState::default()
                };
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
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(2)) => {},
                _ = CHANGED.notified() => {},
            }
        }
    });
    AsyncHandler::spawn(|| async {
        loop {
            let settings = active_settings().await;
            if let Some(settings) = &settings {
                match scan_routes(settings).await {
                    Ok(()) if active_settings().await.as_ref() == Some(settings) => {
                        SCAN_VERSION.fetch_add(1, Ordering::Release);
                    }
                    Ok(()) => {}
                    Err(error) => logging!(debug, Type::Core, "Automatic chain scan will retry: {error:#}"),
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(settings.map_or(2, |_| BACKUP_INTERVAL))) => {},
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

    #[tokio::test]
    async fn monitoring_and_scanning_share_an_overlapping_probe_but_later_checks_are_fresh() -> Result<()> {
        let settings: AutoChainSettings = serde_yaml_ng::from_str(
            "enabled: true\nprofile_uid: test\nexit_source: test\nexit_name: test\ninterval: 600\ntolerance: 50\nurl: https://example.com\n",
        )?;
        let calls = AtomicU64::new(0);
        let request = || async {
            calls.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(10)).await;
            Some(100)
        };
        assert_eq!(
            futures::future::join(
                coalesced_probe("overlap", &settings, request()),
                coalesced_probe("overlap", &settings, request())
            )
            .await,
            (Some(100), Some(100))
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        coalesced_probe("overlap", &settings, request()).await;
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        Ok(())
    }

    #[test]
    fn fast_routes_fail_over_quickly_without_rejecting_slow_handshakes() {
        assert_eq!(probe_timeout(15000, Some(100)), 5000);
        assert_eq!(probe_timeout(15000, Some(8300)), 15000);
        assert_eq!(probe_timeout(15000, None), 15000);
        assert_eq!(probe_timeout(3000, Some(100)), 3000);
    }

    #[tokio::test]
    async fn recovery_reaches_the_fourth_candidate_and_chooses_the_faster_verified_route() {
        let names = ["dead-a", "dead-b", "dead-c", "working"].map(str::to_owned).to_vec();
        assert_eq!(
            probe_candidates(names, |name| async move { (name == "working").then_some((80, name)) }).await,
            Some((80, "working".into()))
        );
        assert_eq!(
            probe_candidates(vec!["slow".into(), "fast".into()], |name| async move {
                Some((if name == "fast" { 80 } else { 300 }, name))
            })
            .await,
            Some((80, "fast".into()))
        );
    }

    #[test]
    fn initial_scan_picks_the_best_route_without_waiting_ten_minutes() {
        let mut state = SelectionState {
            initial_scan: true,
            ..SelectionState::default()
        };
        state.switched("first-reachable");
        assert!(state.review_due(1, 600));
        assert!(!state.review_due(2, 600));
    }

    #[test]
    fn stale_successes_are_not_healthy_backups() {
        use tauri_plugin_mihomo::models::DelayHistory;
        let mut state = Extra {
            alive: true,
            history: vec![DelayHistory {
                time: (chrono::Utc::now() - chrono::Duration::seconds(HEALTH_MAX_AGE + 1)).to_rfc3339(),
                delay: 100,
            }],
        };
        assert_eq!(fresh_delay(Some(&state)), None);
        state.history[0].time = chrono::Utc::now().to_rfc3339();
        assert_eq!(fresh_delay(Some(&state)), Some(100));
        state.alive = false;
        assert_eq!(fresh_delay(Some(&state)), None);
    }

    #[test]
    fn failed_backup_checks_never_replace_the_current_route_with_reject() {
        let mut state = SelectionState::default();
        state.observe("current", None);
        state.observe("current", None);
        assert_eq!(state.replacement("current", None, None, 50, false, true), None);
        assert_eq!(
            state.replacement("current", None, Some((8300, "backup".into())), 50, false, true),
            Some("backup".into())
        );
    }

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
        assert!(state.should_switch("manual", None, 100, 50, true, true));
        state.observe("manual", Some(300));
        assert_eq!(state.failures, 0);
        state.observe("manual", None);
        state.observe("manual", None);
        assert!(state.should_switch("manual", None, 100, 50, false, true));
        assert!(state.should_switch("REJECT", None, 100, 50, false, false));
    }
}
