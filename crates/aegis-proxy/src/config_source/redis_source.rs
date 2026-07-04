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

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

use aegis_core::audit::{AuditBus, AuditClass, AuditEvent};
use aegis_core::config::WafConfig;
use aegis_core::config_backend::ConfigWatch;

use super::config_store::{Activate, ConfigStore};
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
    /// BUG-dns-refresh-not-spawned-for-live-added-hostnames — live
    /// DNS-refresh task manager, so a config-plane upstream swap
    /// reconciles per-pool refresh tasks for hostname members added or
    /// changed after boot (not just node-local-until-restart). `None`
    /// when the resolver failed to build at boot.
    pub dns_refresh: Option<Arc<crate::upstream::dns_refresh::DnsRefreshManager>>,
    /// N1 (2026-06-11) — shared alert-receiver list, re-derived from
    /// `cfg.alerting.receivers` on each swap so a receiver configured on
    /// any node propagates to every node. `None` ⇒ not wired (the legacy
    /// node-local receiver store stays as-is).
    pub receiver_writer:
        Option<Arc<arc_swap::ArcSwap<Vec<aegis_control::slo::AlertReceiver>>>>,
    /// SLO-P4 — live SLO engine; objectives re-derived from
    /// `cfg.slo` on each swap so a threshold edit propagates
    /// fleet-wide (SLI history untouched). `None` ⇒ not wired
    /// (test bundle).
    pub slo_engine: Option<Arc<aegis_control::slo::SloEngine>>,
    /// SLO-P4 — telemetry-absent watchdog knob, read each tick by
    /// the evaluation loop; re-derived from
    /// `cfg.slo.telemetry_absent_after_secs` on each swap.
    pub slo_absent_after_secs: Option<Arc<std::sync::atomic::AtomicU64>>,
    /// SLO-P5 — HotReloadFailed alerts into the SLO dispatch loop
    /// when a fetched shared-config version fails validation
    /// (NACK). `None` ⇒ not wired (test bundle).
    pub alert_tx: Option<tokio::sync::mpsc::UnboundedSender<aegis_control::slo::AlertEvent>>,
    /// A2 (2026-06-14) — live inbound (downstream) mTLS trust store,
    /// re-derived from `cfg.zero_trust.downstream.ca_bundle` on each swap
    /// so a Zero Trust CA rotation activated on any node converges on every
    /// node instead of staying node-local-until-restart. `None` ⇒ inbound
    /// mTLS not wired at boot (operators flipping it on at runtime still
    /// need a restart, same as the file watcher). Mirrors the file-watcher
    /// path (`supervisor.rs`) which already calls
    /// `apply_cfg_change_to_client_auth`.
    pub client_auth: Option<crate::listener::client_trust::ClientTrustStore>,
    /// 2026-06-18 (runtime_gate_toggles_not_durable) — gate runtimes whose
    /// PUT handlers publish to `config:waf:doc` but had no read-back helper,
    /// so a restart reverted them to the waf.yaml value. Re-derived from the
    /// converged doc on each swap, matching the boot install in `run()`.
    /// `None` ⇒ not wired (e.g. a test bundle without the proxy).
    pub ddos: Option<Arc<aegis_security::ddos::DdosRuntime>>,
    /// Live risk tracker — re-derives cumulative thresholds + Strike-Block.
    pub risk: Option<aegis_security::risk::RiskTracker>,
    /// Canary honeypot path set.
    pub canary_paths: Option<aegis_security::detectors::canary::CanaryPaths>,
    /// Bot-classifier gate toggle (shared `AtomicBool`).
    pub bots_enabled: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// AC-P2-b — the chain-resident brute-force detector, so a converged
    /// `count_scope` change re-derives on every node.
    pub brute_force: Option<Arc<aegis_security::detectors::brute_force::BruteForceDetector>>,
}

/// Spawn the shared-store config watcher. Exits when the last strong
/// reference to `cfg` is dropped.
///
/// `nudge` (N2) is the optional config-plane [`ConfigWatch`]. When wired,
/// the loop subscribes via [`ConfigWatch::watch`] and re-reads the instant a
/// peer (or this node) activates a new version, so convergence drops from
/// ≤`poll_interval` to ~ms. `None` ⇒ pure interval polling (single-node /
/// in-memory / nudge disabled).
#[allow(clippy::too_many_arguments)]
pub fn spawn_watcher(
    store: ConfigStore,
    node_id: String,
    cfg: Arc<ArcSwap<WafConfig>>,
    // H2a — immutable bootstrap half, used to reconstruct the merged runtime
    // config from each new DYNAMIC doc (see `WafConfig::from_parts`).
    boot: Arc<aegis_core::BootstrapConfig>,
    bus: AuditBus,
    targets: ApplyTargets,
    poll_interval: Duration,
    nudge: Option<Arc<dyn ConfigWatch>>,
    config_store_degraded: Arc<AtomicBool>,
    marker_path: Option<PathBuf>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        watch_loop(
            store,
            node_id,
            cfg,
            boot,
            bus,
            targets,
            poll_interval,
            nudge,
            config_store_degraded,
            marker_path,
        )
        .await;
    })
}

#[allow(clippy::too_many_arguments)]
async fn watch_loop(
    store: ConfigStore,
    node_id: String,
    cfg: Arc<ArcSwap<WafConfig>>,
    boot: Arc<aegis_core::BootstrapConfig>,
    bus: AuditBus,
    targets: ApplyTargets,
    poll_interval: Duration,
    nudge: Option<Arc<dyn ConfigWatch>>,
    // 2026-06-18 (runtime-config-lost-on-redis-data-loss report) — set true
    // when the store comes back empty after we'd applied a version (Redis
    // data loss → silent revert to file baseline). Reported on /healthz/ready.
    config_store_degraded: Arc<AtomicBool>,
    // Optional local last-known-good marker path; lets a *cold* boot after a
    // Redis bounce distinguish data loss from a legitimate first run.
    marker_path: Option<PathBuf>,
) {
    // The version this node currently has applied. 0 = boot config (from
    // file/etcd) still in force; the store's first version is 1.
    let mut applied_version: u64 = 0;

    // Highest version ever applied by this node, including across process
    // restarts via the persisted marker. Drives empty-store detection.
    let mut highest_seen = read_marker_version(marker_path.as_ref());
    // Emit the revert alert once per episode, not every poll tick.
    let mut revert_alerted = false;

    // N2 — subscribe to the config bump channel so an activate anywhere in
    // the fleet (incl. our own writes) wakes this loop immediately. The
    // poll below is the loss-tolerant backstop.
    let mut bump_rx = nudge.as_ref().map(|w| w.watch(NUDGE_CHANNEL_BOUND));

    tracing::info!(
        node_id = %node_id,
        poll_interval_ms = poll_interval.as_millis() as u64,
        nudge = bump_rx.is_some(),
        "shared-store config watcher started",
    );

    loop {
        match store.load().await {
            Ok(Some(doc)) => {
                // The shared store has a doc — config provenance is healthy
                // again. Clear any prior empty-store revert flag.
                config_store_degraded.store(false, Ordering::Relaxed);
                revert_alerted = false;
                if doc.version == applied_version {
                    // No change — re-stamp our ACK so the roster stays fresh.
                    let _ = store.record_applied(&node_id, applied_version).await;
                } else {
                    // H2a — the doc blob is the DYNAMIC config. Validate it as
                    // such (strips any legacy bootstrap keys from a pre-H2a
                    // doc), then reconstruct the merged runtime config taking
                    // the bootstrap half from the immutable boot config — the
                    // doc can never override how this node came up.
                    match aegis_core::load_dynamic_str(&doc.blob) {
                        Ok(dynamic) => {
                            let new_cfg =
                                aegis_core::WafConfig::from_parts(&boot, dynamic);
                            apply_and_swap(&new_cfg, &cfg, &bus, &targets, doc.version).await;
                            applied_version = doc.version;
                            highest_seen = highest_seen.max(doc.version);
                            write_marker_version(marker_path.as_ref(), doc.version);
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
                            // SLO-P5 — surface the NACK as an
                            // operator alert: this node keeps
                            // serving last-known-good while the
                            // fleet doc says otherwise.
                            if let Some(tx) = targets.alert_tx.as_ref() {
                                let _ = tx.send(
                                    aegis_control::slo::AlertEvent::HotReloadFailed {
                                        fired_at: chrono::Utc::now(),
                                        reason: format!(
                                            "shared config v{} rejected: {e}",
                                            doc.version,
                                        ),
                                        last_known_good_version: applied_version,
                                    },
                                );
                            }
                        }
                    }
                }
            }
            Ok(None) => {
                // The store is reachable but holds no config doc. Two cases:
                //  - genuine first boot (nothing ever activated) → silent;
                //  - the store LOST a doc we'd applied (Redis restarted
                //    without persistence) → the node silently reverted to the
                //    on-disk file baseline, dropping runtime-added pools/
                //    routes. Surface that loudly. (2026-06-18 report.)
                if is_store_revert(applied_version, highest_seen) {
                    config_store_degraded.store(true, Ordering::Relaxed);
                    if !revert_alerted {
                        revert_alerted = true;
                        let lost = highest_seen.max(applied_version);
                        tracing::error!(
                            node_id = %node_id,
                            last_version = lost,
                            "shared config store empty after applying a version — \
                             reverted to file baseline; runtime pools/routes may be lost. \
                             Check Redis persistence (AOF/RDB).",
                        );
                        bus.emit(reload_event(
                            "config_store_reverted_to_baseline",
                            format!(
                                "shared config store returned empty after applying version \
                                 {lost}; node fell back to the on-disk file baseline \
                                 (runtime-added pools/routes dropped). Check Redis \
                                 persistence (AOF/RDB)."
                            ),
                            &node_id,
                            lost,
                        ));
                    }
                }
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
    // SLO-P4 — re-derive SLO objectives + watchdog knob (no-op when
    // `cfg.slo` is unset; invalid sections rejected, previous set stays).
    let _ = reload::apply_cfg_change_to_slo(
        new_cfg,
        targets.slo_engine.as_ref(),
        targets.slo_absent_after_secs.as_ref(),
    );
    let _ = reload::apply_cfg_change_to_rules(
        new_cfg,
        targets.rules.as_ref(),
        targets.active_ruleset.as_ref(),
    );
    if let reload::UpstreamsReloadOutcome::Failed { reason } =
        reload::apply_cfg_change_to_upstreams(
            new_cfg,
            targets.upstream_writer.as_ref(),
            targets.dns_refresh.as_ref(),
        )
        .await
    {
        tracing::error!(
            version,
            reason = %reason,
            "shared config: upstream pool rebuild failed; live pools unchanged",
        );
        bus.emit(reload_event("upstreams_reload_failed", reason, "", version));
    }

    // A2 — re-derive the inbound (downstream) mTLS trust store from the
    // converged config so a Zero Trust CA rotation propagates fleet-wide.
    // Mirrors the file watcher (`supervisor.rs`): NoStore / SkippedDisabled
    // are no-ops; Applied emits `zero_trust_reloaded`; MissingCaBundle /
    // Failed keep the live store and emit `zero_trust_reload_failed`.
    apply_client_auth_and_audit(new_cfg, bus, targets.client_auth.as_ref(), version);

    // A4 — rebuild the AI Operator Copilot from the converged config so an
    // enable/disable / model / key-rotation activated on the config plane
    // takes effect on every node, not just the originator. The file watcher
    // already did this via `apply_folded_stores`; the shared-store watcher
    // was missing it (caught by the structural guard test). Per-node key
    // resolution happens inside the helper.
    let _ = reload::apply_cfg_change_to_copilot(new_cfg).await;

    // 2026-06-18 (runtime_gate_toggles_not_durable) — re-derive the gate
    // runtimes from the converged doc. Their PUT handlers publish a new
    // `config:waf:doc` version (the write side), but without these calls a
    // restart rebuilt `DdosRuntime` / `RiskTracker` / the bots toggle from
    // waf.yaml and nothing re-installed the operator's change (the read-back
    // side). rate-limit was already covered above via the ip_rate_limiter
    // target; these close the remaining gates.
    let _ = reload::apply_cfg_change_to_ddos(new_cfg, targets.ddos.as_ref());
    let _ = reload::apply_cfg_change_to_risk(
        new_cfg,
        targets.risk.as_ref(),
        targets.canary_paths.as_ref(),
    );
    let _ = reload::apply_cfg_change_to_bots(new_cfg, targets.bots_enabled.as_ref());
    // AC-P2-b — re-derive the brute-force count scope (fleet vs per-node)
    // so a converged scope flip applies on every node, not just the one
    // that handled the PUT.
    let _ = reload::apply_cfg_change_to_brute_force(new_cfg, targets.brute_force.as_ref());
    // 2026-06-21 — reconcile the per-pool response (smart) cache from the
    // converged doc so a dashboard "Response cache" enable/add/change/remove
    // applies fleet-wide without a restart (was node-local-until-restart).
    let _ = reload::apply_cfg_change_to_cache(new_cfg, targets.proxy_ctx.as_ref());
    // Tier-1A — reconcile the GraphQL query guard from the converged doc so a
    // graphql enable/disable or limit change applies on every node.
    let _ = reload::apply_cfg_change_to_graphql(new_cfg, targets.proxy_ctx.as_ref());

    cfg.store(Arc::new(new_cfg.clone()));
}

/// A2 — apply the inbound mTLS trust-store reload from a converged config
/// and audit the outcome on the shared bus. Split out of [`apply_and_swap`]
/// so the match stays readable; mirrors the file-watcher emission shape in
/// `supervisor.rs` with `source: "shared"`.
fn apply_client_auth_and_audit(
    new_cfg: &WafConfig,
    bus: &AuditBus,
    trust_store: Option<&crate::listener::client_trust::ClientTrustStore>,
    version: u64,
) {
    use reload::ClientAuthReloadOutcome as Outcome;
    match reload::apply_cfg_change_to_client_auth(new_cfg, trust_store) {
        // Nothing to do: inbound mTLS not wired, or disabled in new cfg.
        Outcome::NoStore | Outcome::SkippedDisabled => {}
        Outcome::Applied { cert_count, mode } => {
            tracing::info!(
                version,
                cert_count,
                mode = ?mode,
                "shared config: mtls trust store swapped",
            );
            let mut ev = reload_event(
                "zero_trust_reloaded",
                format!("mtls trust store rebuilt with {cert_count} CA certificate(s)"),
                "",
                version,
            );
            ev.fields = serde_json::json!({
                "source": "shared",
                "version": version,
                "cert_count": cert_count,
                "mode": format!("{mode:?}").to_lowercase(),
            });
            bus.emit(ev);
        }
        Outcome::MissingCaBundle => {
            tracing::error!(
                version,
                "shared config: mtls reload skipped — non-disabled mode but ca_bundle missing",
            );
            bus.emit(reload_event(
                "zero_trust_reload_failed",
                "client_auth.ca_bundle missing for non-disabled mode".into(),
                "",
                version,
            ));
        }
        Outcome::Failed { reason } => {
            tracing::error!(
                version,
                reason = %reason,
                "shared config: mtls trust store load failed; live trust unchanged",
            );
            bus.emit(reload_event("zero_trust_reload_failed", reason, "", version));
        }
    }
}

/// Local last-known-good marker — the highest shared-config version this node
/// has ever applied. Persisted next to the boot config so a *cold* boot after
/// a Redis data-loss can still distinguish "the store legitimately has no
/// config yet" (first run) from "the store lost a config we'd applied" (alert).
#[derive(serde::Serialize, serde::Deserialize)]
struct ConfigMarker {
    version: u64,
    ts: String,
}

/// Read the persisted last-applied version. Returns 0 when the marker is
/// absent or unreadable (treated as "never applied" — first boot).
fn read_marker_version(path: Option<&PathBuf>) -> u64 {
    let Some(p) = path else { return 0 };
    match std::fs::read_to_string(p) {
        Ok(s) => serde_json::from_str::<ConfigMarker>(&s)
            .map(|m| m.version)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// Persist the last-applied version (best-effort; a write failure is logged
/// and ignored — the in-memory `applied_version` still drives detection while
/// the process stays up).
fn write_marker_version(path: Option<&PathBuf>, version: u64) {
    let Some(p) = path else { return };
    let marker = ConfigMarker {
        version,
        ts: chrono::Utc::now().to_rfc3339(),
    };
    if let Ok(json) = serde_json::to_string(&marker) {
        if let Err(e) = std::fs::write(p, json) {
            tracing::warn!(path = %p.display(), error = %e, "failed to persist config marker");
        }
    }
}

/// Pure decision: given the highest version we've ever applied (in-memory or
/// from the marker), is an *empty* shared store a data-loss revert (`true`) or
/// a legitimate fresh boot with no config yet (`false`)?
fn is_store_revert(applied_version: u64, highest_seen: u64) -> bool {
    applied_version > 0 || highest_seen > 0
}

/// Outcome of the boot-time genesis seed. Returned (not just logged) so the
/// decision is unit-testable; the caller in `run.rs` only logs it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SeedOutcome {
    /// Published the boot file as the first config version.
    Seeded { version: u64 },
    /// A version was applied before (marker present) — a normal restart, or a
    /// post-wipe boot whose empty store is owned by the revert *detection*
    /// (`is_store_revert`), not by a silent re-seed. Never seed once initialized.
    SkippedAlreadyInitialized,
    /// A peer activated between our marker check and our CAS — they won; we
    /// stand down (no version bump).
    SkippedConflict { current: u64 },
    /// No boot file on disk to seed from (e.g. `ConfigReloadSource::None`).
    SkippedNoFile,
    /// Reading the file or writing the store failed; boot proceeds on the lazy
    /// fallback (`load_active_config_doc` seeds from the file on first mutation).
    Failed,
}

/// FEAT-config-boot-seed-doc-v0 — eagerly publish the boot YAML as config
/// version 1 at startup so `config:waf:doc` is populated from the first moment,
/// closing the boot↔first-mutation divergence window. **Genesis-only:** gated on
/// an absent last-applied marker (`read_marker_version == 0`) so a cold boot
/// after a shared-store wipe is left to the revert detection in `watch_loop`,
/// never masked by a re-seed. Idempotent across restarts (marker present →
/// skip) and safe on a multi-node cold start (CAS → exactly one winner).
pub(crate) async fn seed_boot_config_if_genesis(
    store: &ConfigStore,
    config_yaml_path: Option<&std::path::Path>,
    marker_path: Option<&PathBuf>,
) -> SeedOutcome {
    let Some(path) = config_yaml_path else {
        return SeedOutcome::SkippedNoFile;
    };

    // Genesis gate: once any version has been applied (marker present), never
    // seed again. A marker with an empty store is a *wipe* — owned by the
    // revert detection in `watch_loop` (`is_store_revert`), not by a re-seed.
    if read_marker_version(marker_path) > 0 {
        return SeedOutcome::SkippedAlreadyInitialized;
    }

    // The boot file is already validated (the process booted from it), so the
    // seed stores its verbatim text — the same single-validation surface the
    // lazy fallback uses, preserving `${secret:...}` refs for load-time resolve.
    let blob = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                path = %path.display(), error = %e,
                "config boot-seed: cannot read boot file; relying on the lazy fallback",
            );
            return SeedOutcome::Failed;
        }
    };

    match store
        .activate(0, blob, "boot-seed", "genesis seed of boot config")
        .await
    {
        Ok(Activate::Applied { version }) => {
            tracing::info!(version, "config plane seeded from boot file (genesis)");
            SeedOutcome::Seeded { version }
        }
        Ok(Activate::Conflict { current }) => {
            tracing::info!(
                current,
                "config plane already seeded (peer won the cold-start race); skipping boot-seed",
            );
            SeedOutcome::SkippedConflict { current }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "config boot-seed activate failed; relying on the lazy fallback",
            );
            SeedOutcome::Failed
        }
    }
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
    use crate::state::in_memory::InMemoryBackend;
    use std::time::Instant;
    use tokio::sync::mpsc;

    // FEAT-config-boot-seed-doc-v0 — eager genesis seed of the boot config
    // into `config:waf:doc` v1, gated so it never masks a wipe.

    fn empty_store() -> ConfigStore {
        ConfigStore::new(Arc::new(InMemoryBackend::new()))
    }

    #[tokio::test]
    async fn seed_writes_v1_on_genesis() {
        let store = empty_store();
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("waf.yaml");
        // H2a — the seed activates through the store, which strips bootstrap
        // keys; the doc holds the DYNAMIC projection (no `listeners`/`state`).
        std::fs::write(
            &cfg_path,
            "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n  admin:\n    bind: \"127.0.0.1:9090\"\nstate:\n  backend: in_memory\nroutes:\n  - id: marker-route\n    path: \"/\"\n    upstream: u\nupstreams:\n  u:\n    members:\n      - addr: \"127.0.0.1:3000\"\n",
        )
        .unwrap();
        let marker = dir.path().join(".aegis_last_applied_config.json"); // absent → genesis

        let outcome =
            seed_boot_config_if_genesis(&store, Some(cfg_path.as_path()), Some(&marker)).await;

        assert_eq!(outcome, SeedOutcome::Seeded { version: 1 });
        let doc = store.load().await.unwrap().expect("doc should be seeded");
        assert_eq!(doc.version, 1);
        assert_eq!(doc.actor, "boot-seed");
        assert!(doc.blob.contains("marker-route"), "dynamic content seeded");
        assert!(!doc.blob.contains("listeners"), "bootstrap stripped from the doc");
        assert!(!doc.blob.contains("in_memory"), "state stripped from the doc");
    }

    #[tokio::test]
    async fn seed_skips_when_marker_present_so_a_wipe_is_left_for_detection() {
        let store = empty_store();
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("waf.yaml");
        std::fs::write(&cfg_path, "x: 1").unwrap();
        let marker = dir.path().join("marker.json");
        write_marker_version(Some(&marker), 7); // we applied v7 before → not genesis

        let outcome =
            seed_boot_config_if_genesis(&store, Some(cfg_path.as_path()), Some(&marker)).await;

        assert_eq!(outcome, SeedOutcome::SkippedAlreadyInitialized);
        assert!(
            store.load().await.unwrap().is_none(),
            "empty store after a wipe must stay empty so the revert detector fires",
        );
    }

    #[tokio::test]
    async fn seed_skips_on_conflict_when_a_peer_already_seeded() {
        let store = empty_store();
        // A peer activated v1 already; our local marker is still absent.
        store
            .activate(0, "peer: true".into(), "peer", "")
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("waf.yaml");
        std::fs::write(&cfg_path, "ours: true").unwrap();
        let marker = dir.path().join("marker.json"); // absent

        let outcome =
            seed_boot_config_if_genesis(&store, Some(cfg_path.as_path()), Some(&marker)).await;

        assert_eq!(outcome, SeedOutcome::SkippedConflict { current: 1 });
        let doc = store.load().await.unwrap().unwrap();
        assert_eq!(doc.version, 1, "no version bump — the peer's v1 stands");
        assert!(doc.blob.contains("peer"), "our blob did not overwrite the peer's");
    }

    #[tokio::test]
    async fn seed_skips_without_a_config_path() {
        let store = empty_store();
        let outcome = seed_boot_config_if_genesis(&store, None, None).await;
        assert_eq!(outcome, SeedOutcome::SkippedNoFile);
        assert!(store.load().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn seed_fails_gracefully_on_unreadable_file() {
        let store = empty_store();
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.yaml");
        let marker = dir.path().join("marker.json"); // absent → genesis path

        let outcome =
            seed_boot_config_if_genesis(&store, Some(missing.as_path()), Some(&marker)).await;

        assert_eq!(outcome, SeedOutcome::Failed);
        assert!(
            store.load().await.unwrap().is_none(),
            "a read failure must not partially write the store",
        );
    }

    // 2026-06-18 (runtime-config-lost-on-redis-data-loss report) — empty-store
    // revert detection + the local marker.

    #[test]
    fn empty_store_is_revert_only_after_a_version_applied() {
        // Fresh boot: never applied, no marker → empty store is legitimate.
        assert!(!is_store_revert(0, 0));
        // Applied a version this run, store now empty → data loss.
        assert!(is_store_revert(3, 0));
        // Cold boot: in-memory reset to 0 but marker remembers a version.
        assert!(is_store_revert(0, 5));
    }

    #[test]
    fn marker_round_trips_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("last_applied.json");
        assert_eq!(read_marker_version(Some(&path)), 0, "absent → 0");
        write_marker_version(Some(&path), 7);
        assert_eq!(read_marker_version(Some(&path)), 7);
        // Overwrite with a newer version.
        write_marker_version(Some(&path), 9);
        assert_eq!(read_marker_version(Some(&path)), 9);
    }

    #[test]
    fn marker_absent_or_garbage_reads_as_zero() {
        assert_eq!(read_marker_version(None), 0);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.json");
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(read_marker_version(Some(&path)), 0);
    }

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

    // A4 — structural regression guard. `apply_and_swap` is a hand-
    // maintained list of `reload::apply_cfg_change_to_*` calls; a new
    // config section is silently node-local-until-restart until someone
    // adds its helper call here (exactly how the Zero Trust A2 bug
    // happened). This test enumerates every `apply_cfg_change_to_*` helper
    // defined in `reload.rs` and asserts the shared-store watcher invokes
    // each one, so adding a helper without wiring it fails CI.
    #[test]
    fn apply_and_swap_invokes_every_reload_helper() {
        let reload_src = include_str!("reload.rs");
        let watcher_src = include_str!("redis_source.rs");

        let helpers: Vec<String> = reload_src
            .lines()
            .filter_map(|l| {
                let l = l.trim_start();
                let rest = l
                    .strip_prefix("pub fn apply_cfg_change_to_")
                    .or_else(|| l.strip_prefix("pub async fn apply_cfg_change_to_"))?;
                let name = rest.split('(').next().unwrap_or("");
                Some(format!("apply_cfg_change_to_{name}"))
            })
            .collect();

        assert!(
            helpers.len() >= 10,
            "sanity: expected to discover the reload helpers, found {}",
            helpers.len(),
        );

        for h in &helpers {
            let call = format!("reload::{h}(");
            assert!(
                watcher_src.contains(&call),
                "config-plane regression guard: `{h}` is defined in reload.rs but \
                 is never invoked from the shared-store watcher (apply_and_swap in \
                 redis_source.rs). A config section whose reload helper isn't called \
                 here stays node-local-until-restart — wire it in (this is exactly \
                 how the Zero Trust A2 bug happened).",
            );
        }
    }

    // ---- A2 — Zero Trust inbound mTLS converges via the config watcher ----

    /// Write a self-signed CA to a temp file; return (pem_bytes, path).
    fn make_ca(name: &str) -> (Vec<u8>, std::path::PathBuf) {
        use std::io::Write;
        let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem().into_bytes();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{name}.pem"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&pem).unwrap();
        f.sync_all().unwrap();
        std::mem::forget(dir); // keep the path valid for the test
        (pem, path)
    }

    fn zero_trust_yaml(ca_path: &std::path::Path) -> String {
        format!(
            concat!(
                "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n",
                "  admin: {{ bind: \"127.0.0.1:9090\" }}\n",
                "routes:\n  - {{ id: catch-all, path: \"/\", upstream: pool }}\n",
                "upstreams:\n  pool: {{ members: [{{ addr: \"127.0.0.1:3000\" }}] }}\n",
                "state: {{ backend: in_memory }}\n",
                "tls:\n  certificates: []\n",
                "zero_trust:\n  downstream:\n    mode: required\n",
                "    ca_bundle: {ca_path}\n    apply_to: [data]\n",
            ),
            ca_path = ca_path.display(),
        )
    }

    // A2 — a Zero Trust CA rotation activated on the config plane must
    // converge on every node via the shared-store watcher, exactly like
    // detectors / routes / tiers already do. Pre-fix `apply_and_swap`
    // never called `apply_cfg_change_to_client_auth`, so an inbound-mTLS
    // CA change stayed node-local-until-restart. We assert the watcher
    // emits a `zero_trust_reloaded` audit after the activation — proof
    // the trust store was rebuilt from the converged config.
    #[tokio::test]
    async fn zero_trust_ca_converges_via_config_watcher() {
        use crate::listener::client_trust::ClientTrustStore;
        use crate::state::in_memory::InMemoryBackend;

        // Live trust starts on CA-A; the activated config points at CA-B.
        let (pem_a, _path_a) = make_ca("zt-ca-a");
        let trust = ClientTrustStore::load_from_pem_bytes(&pem_a).unwrap();
        let (_pem_b, path_b) = make_ca("zt-ca-b");

        let backend: Arc<dyn aegis_core::state::StateBackend> =
            Arc::new(InMemoryBackend::new());
        let boot = aegis_core::load_config_str(&zero_trust_yaml(&path_b)).unwrap();
        let cfg_swap = Arc::new(ArcSwap::from_pointee(boot.clone()));
        let boot_half = Arc::new(aegis_core::BootstrapConfig::from(&boot));

        let bus = AuditBus::new(64);
        let mut rx = bus.subscribe();

        let targets = ApplyTargets {
            detector_mask: None,
            proxy_ctx: None,
            ip_rate_limiter: None,
            tls_resolver: None,
            ai_toggle: None,
            ai_threshold: None,
            response_filter_writer: None,
            tiers: None,
            rules: None,
            active_ruleset: None,
            upstream_writer: None,
            dns_refresh: None,
            receiver_writer: None,
            slo_engine: None,
            slo_absent_after_secs: None,
            alert_tx: None,
            // The one target under test.
            client_auth: Some(trust),
            ddos: None,
            risk: None,
            canary_paths: None,
            bots_enabled: None,
            brute_force: None,
        };

        let store_w = ConfigStore::new(backend.clone());
        let handle = spawn_watcher(
            store_w,
            "waf-zt".to_string(),
            cfg_swap.clone(),
            boot_half,
            bus.clone(),
            targets,
            Duration::from_millis(50),
            None,
            Arc::new(AtomicBool::new(false)),
            None,
        );

        // Activate a new version carrying the rotated CA bundle.
        let store_a = ConfigStore::new(backend.clone());
        store_a
            .activate(0, zero_trust_yaml(&path_b), "operator", "rotate zt ca")
            .await
            .unwrap();

        // Within the SLA the watcher applies it and emits the reload audit.
        let mut reloaded = false;
        for _ in 0..40 {
            while let Ok(ev) = rx.try_recv() {
                if ev.action.as_str() == "zero_trust_reloaded" {
                    reloaded = true;
                    break;
                }
            }
            if reloaded {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        handle.abort();
        assert!(
            reloaded,
            "Zero Trust CA rotation must converge via the config watcher \
             (emit a zero_trust_reloaded audit), not stay node-local",
        );
    }
}
