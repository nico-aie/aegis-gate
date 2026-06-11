//! CONFIG-PLANE (2026-05-27) — shared-store config watcher.
//!
//! Polls the versioned [`ConfigStore`] (backed by the runtime
//! `StateBackend`) and applies a new config version on every node,
//! reusing the same [`crate::config_source::reload`] apply helpers the
//! file + etcd watchers use (route table, detector mask, IP rate-limit,
//! TLS resolver, then the `ArcSwap` swap). This is how a console edit on
//! one node propagates to the whole fleet and survives leader failover —
//! the config lives in the store, not in any node's process.
//!
//! Invariants (see `plans/future/cluster-config-sync-and-scaling.md`):
//! - **ACK**: after a successful apply the node records its applied
//!   version via [`ConfigStore::record_applied`]; the console reads the
//!   per-node map to surface drift.
//! - **NACK**: a version whose blob fails to parse/validate is *not*
//!   applied — the node keeps its last-good `ArcSwap` config and emits a
//!   `config_reload_failed` audit. A bad version can never take a node
//!   out of rotation.
//! - **Fail-static**: when the store is unreachable the node keeps
//!   serving its current config and retries on the next tick.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

use aegis_core::audit::{AuditBus, AuditClass, AuditEvent};
use aegis_core::config::WafConfig;
use aegis_core::fleet::FleetBus;

use super::config_store::{ConfigStore, CONFIG_BUMP_CHANNEL};
use super::reload;

/// Default poll cadence. Full-fleet convergence is ≤ one interval when the
/// pub/sub nudge is off; with the nudge wired (N2) the writer and peers
/// apply in ~ms and this is just the loss-tolerant backstop.
pub const DEFAULT_POLL: Duration = Duration::from_secs(3);

/// Bound on the config-bump subscription channel. A burst of writes
/// coalesces into a single re-poll, so a small buffer is plenty.
const NUDGE_CHANNEL_BOUND: usize = 16;

/// Handles the data-plane state that a config swap must rebuild, mirrored
/// from the etcd watcher's parameter list so both sources apply identical
/// side effects.
pub struct ApplyTargets {
    pub detector_mask: Option<aegis_security::detectors::SharedDetectorMask>,
    pub proxy_ctx: Option<Arc<crate::proxy::ProxyContext>>,
    pub ip_rate_limiter: Option<Arc<aegis_security::rate_limit::IpRateLimiter>>,
    pub tls_resolver: Option<Arc<crate::listener::tls::DynamicResolver>>,
    /// 2026-05-27 (Phase B) — AI detector runtime gate, re-derived from
    /// `cfg.ai.enabled` on each swap so a folded AI toggle propagates.
    pub ai_toggle: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// 2026-05-30 (NT-07 / R2-006) — AI `confidence_threshold` atomic,
    /// re-derived from `cfg.ai.confidence_threshold` on each swap so
    /// the threshold actually propagates to every node's AiDetector,
    /// not just the originator. Closes the TODO(live-propagate) gap.
    pub ai_threshold: Option<Arc<std::sync::atomic::AtomicU32>>,
    /// 2026-05-27 (Phase B) — response-filter rungs, re-derived from
    /// `cfg.response_filter` so a folded response-filter toggle propagates.
    pub response_filter_writer:
        Option<Arc<dyn aegis_control::api::response_filter::ResponseFilterWriter>>,
    /// 2026-05-27 (Phase B) — per-tier settings (`risk_threshold` +
    /// `challenges_enabled`), re-derived from `cfg.tiers` on each swap.
    pub tiers: Option<Arc<aegis_control::api::tiers::TierStore>>,
    /// 2026-05-27 (Phase B rules fold) — the dashboard `RuleStore`,
    /// re-derived from `cfg.rules.inline` on each swap (the inline list
    /// is the source of truth).
    pub rules: Option<Arc<aegis_control::api::rules::RuleStore>>,
    /// 2026-05-27 (Phase B rules fold) — the live engine `RuleSet`
    /// (`pipeline.rules_arc()`), rebuilt from the re-derived `RuleStore`
    /// so a folded rule CRUD takes effect on every node.
    pub active_ruleset: Option<Arc<aegis_security::RuleSet>>,
    /// 2026-05-27 (Phase B upstreams fold) — the live `PoolRegistry`
    /// (as an `UpstreamWriter`). `cfg.upstreams` is resolved per-node
    /// (async DNS) + applied on each swap so a folded upstream PUT
    /// rebuilds pools on every node.
    pub upstream_writer:
        Option<Arc<dyn aegis_control::api::upstreams_config::UpstreamWriter>>,
    /// N1 (2026-06-11) — shared alert-receiver list, re-derived from
    /// `cfg.alerting.receivers` on each swap so a receiver configured on
    /// any node propagates to every node. `None` ⇒ not wired (the legacy
    /// node-local receiver store stays as-is).
    pub receiver_writer:
        Option<Arc<arc_swap::ArcSwap<Vec<aegis_control::slo::AlertReceiver>>>>,
}

/// Spawn the shared-store config watcher. Exits when the last strong
/// reference to `cfg` is dropped.
///
/// `nudge` (N2) is the optional config-plane pub/sub bus. When wired, the
/// loop subscribes to [`CONFIG_BUMP_CHANNEL`] and re-polls the instant a
/// peer (or this node) activates a new version, so convergence drops from
/// ≤`poll_interval` to ~ms. `None` ⇒ pure interval polling (single-node /
/// in-memory / nudge disabled).
#[allow(clippy::too_many_arguments)]
pub fn spawn_watcher(
    store: ConfigStore,
    node_id: String,
    cfg: Arc<ArcSwap<WafConfig>>,
    bus: AuditBus,
    targets: ApplyTargets,
    poll_interval: Duration,
    nudge: Option<Arc<dyn FleetBus>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        watch_loop(store, node_id, cfg, bus, targets, poll_interval, nudge).await;
    })
}

#[allow(clippy::too_many_arguments)]
async fn watch_loop(
    store: ConfigStore,
    node_id: String,
    cfg: Arc<ArcSwap<WafConfig>>,
    bus: AuditBus,
    targets: ApplyTargets,
    poll_interval: Duration,
    nudge: Option<Arc<dyn FleetBus>>,
) {
    // The version this node currently has applied. 0 = boot config (from
    // file/etcd) still in force; the store's first version is 1.
    let mut applied_version: u64 = 0;

    // N2 — subscribe to the config bump channel so an activate anywhere in
    // the fleet (incl. our own writes) wakes this loop immediately. The
    // poll below is the loss-tolerant backstop.
    let mut bump_rx = nudge
        .as_ref()
        .map(|b| b.subscribe(CONFIG_BUMP_CHANNEL, NUDGE_CHANNEL_BOUND));

    tracing::info!(
        node_id = %node_id,
        poll_interval_ms = poll_interval.as_millis() as u64,
        nudge = bump_rx.is_some(),
        "shared-store config watcher started",
    );

    loop {
        match store.load().await {
            Ok(Some(doc)) => {
                if doc.version == applied_version {
                    // No change — re-stamp our ACK so the roster stays fresh.
                    let _ = store.record_applied(&node_id, applied_version).await;
                } else {
                    match aegis_core::load_config_str(&doc.blob) {
                        Ok(new_cfg) => {
                            apply_and_swap(&new_cfg, &cfg, &bus, &targets, doc.version).await;
                            applied_version = doc.version;
                            // ACK the version we just applied.
                            let _ = store.record_applied(&node_id, applied_version).await;
                            bus.emit(reload_event(
                                "config_reload",
                                format!("applied shared config version {}", doc.version),
                                &node_id,
                                doc.version,
                            ));
                            tracing::info!(
                                node_id = %node_id,
                                version = doc.version,
                                "applied shared config version",
                            );
                        }
                        Err(e) => {
                            // NACK — keep last-good, do NOT advance
                            // applied_version (so the console drift view shows
                            // this node stuck behind). Page-worthy.
                            tracing::error!(
                                node_id = %node_id,
                                version = doc.version,
                                error = %e,
                                "shared config version failed to validate; keeping last-good (NACK)",
                            );
                            bus.emit(reload_event(
                                "config_reload_failed",
                                format!("shared config v{} rejected: {e}", doc.version),
                                &node_id,
                                doc.version,
                            ));
                        }
                    }
                }
            }
            Ok(None) => {
                // No config activated yet — boot config stays in force.
            }
            Err(e) => {
                // Fail-static: the store is unreachable. Keep serving the
                // current config; retry next tick.
                tracing::debug!(
                    node_id = %node_id,
                    error = %e,
                    "shared config store unreachable; keeping current config",
                );
            }
        }

        wait_for_tick_or_nudge(bump_rx.as_mut(), poll_interval).await;
    }
}

/// Wait until the next poll tick **or** a config bump arrives, whichever is
/// first. The bump (N2) collapses convergence from ≤`poll_interval` to ~ms;
/// the timer is the loss-tolerant backstop. A burst of bumps coalesces into
/// a single re-poll. A closed channel falls back to plain interval waits so
/// a dropped subscriber can never hot-loop.
async fn wait_for_tick_or_nudge(
    bump_rx: Option<&mut tokio::sync::mpsc::Receiver<Vec<u8>>>,
    poll_interval: Duration,
) {
    match bump_rx {
        Some(rx) => {
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {}
                msg = rx.recv() => {
                    match msg {
                        // Coalesce a burst into one re-poll.
                        Some(_) => while rx.try_recv().is_ok() {},
                        // Bus closed — don't spin; wait out the interval.
                        None => tokio::time::sleep(poll_interval).await,
                    }
                }
            }
        }
        None => tokio::time::sleep(poll_interval).await,
    }
}

/// Run the four hot-swap helpers then atomic-swap `cfg`. Mirrors the
/// etcd watcher; route-table failure is the one we surface loudly since
/// a bad route rebuild would otherwise silently keep stale routing.
async fn apply_and_swap(
    new_cfg: &WafConfig,
    cfg: &Arc<ArcSwap<WafConfig>>,
    bus: &AuditBus,
    targets: &ApplyTargets,
    version: u64,
) {
    let _ = reload::apply_cfg_change_to_mask(new_cfg, targets.detector_mask.as_ref());

    if let reload::RouteReloadOutcome::Failed { reason } =
        reload::apply_cfg_change_to_routes(new_cfg, targets.proxy_ctx.as_ref())
    {
        tracing::error!(
            version,
            reason = %reason,
            "shared config: route table rebuild failed; live routes unchanged",
        );
        bus.emit(reload_event(
            "routes_reload_failed",
            reason,
            "",
            version,
        ));
    }

    let _ = reload::apply_cfg_change_to_rate_limit(new_cfg, targets.ip_rate_limiter.as_ref());
    let _ = reload::apply_cfg_change_to_tls(new_cfg, targets.tls_resolver.as_ref());
    // Phase B fold-toggles: re-derive the AI runtime gate from
    // `cfg.ai.enabled` so an activated config flips AI on every node.
    let _ = reload::apply_cfg_change_to_ai(
        new_cfg,
        targets.ai_toggle.as_ref(),
        targets.detector_mask.as_ref(),
        targets.ai_threshold.as_ref(),
    );
    let _ = reload::apply_cfg_change_to_response_filter(
        new_cfg,
        targets.response_filter_writer.as_ref(),
    );
    let _ = reload::apply_cfg_change_to_tiers(new_cfg, targets.tiers.as_ref());
    // N1 — re-derive the alert-receiver list so a fleet-managed channel
    // propagates to every node (no-op when `cfg.alerting` is unset).
    let _ = reload::apply_cfg_change_to_receivers(new_cfg, targets.receiver_writer.as_ref());
    let _ = reload::apply_cfg_change_to_rules(
        new_cfg,
        targets.rules.as_ref(),
        targets.active_ruleset.as_ref(),
    );
    if let reload::UpstreamsReloadOutcome::Failed { reason } =
        reload::apply_cfg_change_to_upstreams(new_cfg, targets.upstream_writer.as_ref()).await
    {
        tracing::error!(
            version,
            reason = %reason,
            "shared config: upstream pool rebuild failed; live pools unchanged",
        );
        bus.emit(reload_event("upstreams_reload_failed", reason, "", version));
    }

    cfg.store(Arc::new(new_cfg.clone()));
}

fn reload_event(action: &str, reason: String, node_id: &str, version: u64) -> AuditEvent {
    AuditEvent {
        schema_version: 1,
        ts: chrono::Utc::now(),
        request_id: String::new(),
        class: AuditClass::Admin,
        tenant_id: None,
        tier: None,
        action: action.into(),
        reason,
        client_ip: String::new(),
        route_id: None,
        rule_id: None,
        risk_score: None,
        method: None,
        path: None,
        mode: None,
        fields: serde_json::json!({
            "source": "shared",
            "node_id": node_id,
            "version": version,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::sync::mpsc;

    // N2 — the watcher's wait point: bump wakes immediately, the timer is
    // the backstop, and a closed channel must never hot-loop.

    #[tokio::test]
    async fn nudge_wakes_before_poll_interval() {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
        tx.try_send(vec![1]).unwrap();
        let start = Instant::now();
        wait_for_tick_or_nudge(Some(&mut rx), Duration::from_secs(30)).await;
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "a queued bump must wake the loop well before the poll interval",
        );
    }

    #[tokio::test]
    async fn nudge_coalesces_burst_into_one_wakeup() {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
        for _ in 0..5 {
            tx.try_send(vec![1]).unwrap();
        }
        wait_for_tick_or_nudge(Some(&mut rx), Duration::from_secs(30)).await;
        assert!(
            rx.try_recv().is_err(),
            "a burst of bumps must drain to a single re-poll",
        );
    }

    #[tokio::test]
    async fn no_bus_waits_the_interval() {
        let start = Instant::now();
        wait_for_tick_or_nudge(None, Duration::from_millis(50)).await;
        assert!(start.elapsed() >= Duration::from_millis(40));
    }

    #[tokio::test]
    async fn closed_channel_falls_back_to_interval() {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
        drop(tx); // close → recv yields None
        let start = Instant::now();
        wait_for_tick_or_nudge(Some(&mut rx), Duration::from_millis(50)).await;
        assert!(
            start.elapsed() >= Duration::from_millis(40),
            "a closed channel must wait out the interval, not hot-loop",
        );
    }
}
