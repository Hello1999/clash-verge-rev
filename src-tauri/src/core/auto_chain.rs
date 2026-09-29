use std::time::Duration;

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

async fn probe_active_routes(settings: &AutoChainSettings, warm: &mut Vec<String>) -> Result<()> {
    let core = Handle::mihomo();
    let proxies = core.get_proxies().await?.proxies;
    let Some(group) = proxies.get(GROUP) else { return Ok(()) };
    let mut ranked: Vec<_> = group
        .all
        .iter()
        .flatten()
        .filter_map(|name| {
            let state = proxies.get(name)?.extra.get(&settings.url)?;
            let delay = state.history.last()?.delay;
            (state.alive && delay > 0).then_some((delay, name.clone()))
        })
        .collect();
    ranked.sort_by_key(|(delay, _)| *delay);
    let mut names: Vec<_> = group
        .now
        .iter()
        .filter(|name| name.as_str() != "REJECT")
        .cloned()
        .collect();
    for (_, name) in ranked {
        if names.len() >= 3 {
            break;
        }
        if !names.contains(&name) {
            names.push(name);
        }
    }
    // Keep probing recent backups when they fail, rather than waiting for a full scan to revive them.
    for name in warm.iter().chain(group.all.iter().flatten()) {
        if names.len() >= 3 {
            break;
        }
        if name != "REJECT" && !names.contains(name) && group.all.as_ref().is_some_and(|members| members.contains(name))
        {
            names.push(name.clone());
        }
    }
    futures::future::join_all(names.iter().map(|name| async {
        // This probes the exit wrapper, so an outage in either hop invalidates this route.
        let _ = tokio::time::timeout(
            Duration::from_secs(4),
            core.delay_proxy_by_name(name, &settings.url, 2000),
        )
        .await;
    }))
    .await;
    *warm = names;
    if active_settings().await.as_ref() == Some(settings) {
        // URL-test caches its choice for 10 seconds; reset that choice after fresh probes.
        // The core still applies its tolerance and keeps established connections intact.
        core.unfixed_proxy(GROUP).await?;
    }
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
        let mut warm = Vec::new();
        loop {
            let current = active_settings().await;
            if previous != current {
                warm.clear();
                previous = current.clone();
            }
            if let Some(settings) = current
                && let Err(error) = probe_active_routes(&settings, &mut warm).await
            {
                logging!(debug, Type::Core, "Automatic chain probe will retry: {error:#}");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
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
