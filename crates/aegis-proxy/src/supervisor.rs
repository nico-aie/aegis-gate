use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use aegis_core::audit::{AuditBus, AuditClass, AuditEvent};
use aegis_core::config::{load_config, WafConfig};

// ─────────────────── In-Flight Tracker ─────────────────────────

/// Tracks the number of in-flight requests for graceful drain.
#[derive(Debug)]
pub struct InFlightTracker {
    count: AtomicUsize,
    draining: AtomicBool,
}

impl InFlightTracker {
    pub fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
            draining: AtomicBool::new(false),
        }
    }

    /// Increment the in-flight count. Returns `false` if draining (reject new work).
    pub fn acquire(&self) -> bool {
        if self.draining.load(Ordering::Acquire) {
            return false;
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Decrement the in-flight count.
    pub fn release(&self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Current in-flight count.
    pub fn in_flight(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Enter drain mode — stop accepting new requests.
    pub fn start_drain(&self) {
        self.draining.store(true, Ordering::Release);
    }

    /// Whether we are draining.
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }
}

impl Default for InFlightTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle for coordinating graceful drain.
pub struct DrainHandle {
    tracker: Arc<InFlightTracker>,
    drain_timeout: Duration,
}

impl DrainHandle {
    pub fn new(tracker: Arc<InFlightTracker>, drain_timeout: Duration) -> Self {
        Self {
            tracker,
            drain_timeout,
        }
    }

    /// Initiate graceful drain: stop accepting, wait for in-flight to reach 0,
    /// or timeout. Returns the number of requests that were still in-flight
    /// when the timeout expired (0 = clean drain).
    pub async fn drain(&self) -> usize {
        self.tracker.start_drain();
        tracing::info!("drain started, waiting up to {:?}", self.drain_timeout);

        let deadline = tokio::time::Instant::now() + self.drain_timeout;
        let mut interval = tokio::time::interval(Duration::from_millis(50));

        loop {
            interval.tick().await;
            let remaining = self.tracker.in_flight();
            if remaining == 0 {
                tracing::info!("drain complete, 0 in-flight");
                return 0;
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!("drain timeout, {remaining} requests still in-flight");
                return remaining;
            }
        }
    }
}

/// Spawn a background task that watches `path` for changes and hot-reloads the
/// configuration into `cfg` via atomic swap.
///
/// On successful reload an `AuditClass::Admin` event is emitted on the bus.
/// On failure the old config is kept and the error is logged + emitted.
///
/// `detector_mask`, when supplied, is re-derived from
/// `new_cfg.detectors` after every successful reload and run through
/// the compliance clamp (`apply_live_mask_with_compliance`). Without
/// this pass an operator who flips a compliance-locked detector
/// class off in waf.yaml AND has `cfg.compliance.modes` set would
/// silently bypass the mandate until the next PUT /api/detectors.
/// `None` keeps the legacy "swap cfg only" behaviour for tests that
/// don't have a mask in scope.
///
/// `proxy_ctx`, when supplied, gets its `route_table` rebuilt from
/// `new_cfg.routes` and atomic-swapped on every successful reload.
/// `None` skips route hot-reload (tests / bin variants without a
/// live data plane).
///
/// `ip_rate_limiter`, when supplied, has its config re-derived
/// from `new_cfg.rate_limit.buckets` and atomic-swapped on every
/// successful reload. Per-IP timestamp state is preserved so
/// flooding sources don't get a free reset.
///
/// `tls_resolver`, when supplied, has its `CertStore` rebuilt
/// from `new_cfg.tls.certificates` and atomic-swapped. In-flight
/// TLS handshakes that already loaded the old store finish on
/// it; new handshakes pick up the rotated certs immediately.
#[allow(clippy::too_many_arguments)]
pub fn spawn_config_watcher(
    path: PathBuf,
    cfg: Arc<ArcSwap<WafConfig>>,
    bus: AuditBus,
    detector_mask: Option<aegis_security::detectors::SharedDetectorMask>,
    proxy_ctx: Option<Arc<crate::proxy::ProxyContext>>,
    ip_rate_limiter: Option<Arc<aegis_security::rate_limit::IpRateLimiter>>,
    tls_resolver: Option<Arc<crate::listener::tls::DynamicResolver>>,
    // MTLS-T5 — when present, the watcher re-parses
    // `cfg.tls.client_auth.ca_bundle` and atomic-swaps it into
    // this trust store on every successful reload. `None` for
    // boots without inbound mTLS (the proxy doesn't pass a
    // store; the helper short-circuits).
    client_trust: Option<crate::listener::client_trust::ClientTrustStore>,
    // 2026-05-08 NEW-1 — risk threshold hot-reload. Mirrors the
    // detector-mask / route / rate-limit / TLS / mTLS swaps
    // already wired here. When present, the watcher detects
    // changes to `cfg.risk.thresholds` and atomic-swaps the live
    // tracker via `set_thresholds`. `None` for tests + bin
    // variants that don't drive the risk pipeline. `RiskTracker`
    // is internally `Arc<...>` + `Clone`, so passing by value is
    // cheap (matches the rest of run.rs's risk-passing pattern).
    risk_tracker: Option<aegis_security::risk::RiskTracker>,
    // 2026-05-28 (Phase B fold parity) — handles for the folded stores
    // (AI / response-filter / tiers / rules / upstream pools) so a file
    // reload re-derives them too, matching the redis config-plane watcher.
    folded: crate::config_source::reload::FoldedReloadTargets,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = watch_loop(
            path,
            cfg,
            bus,
            detector_mask,
            proxy_ctx,
            ip_rate_limiter,
            tls_resolver,
            client_trust,
            risk_tracker,
            folded,
        )
        .await
        {
            tracing::error!("config watcher exited with error: {e}");
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn watch_loop(
    path: PathBuf,
    cfg: Arc<ArcSwap<WafConfig>>,
    bus: AuditBus,
    detector_mask: Option<aegis_security::detectors::SharedDetectorMask>,
    proxy_ctx: Option<Arc<crate::proxy::ProxyContext>>,
    ip_rate_limiter: Option<Arc<aegis_security::rate_limit::IpRateLimiter>>,
    tls_resolver: Option<Arc<crate::listener::tls::DynamicResolver>>,
    client_trust: Option<crate::listener::client_trust::ClientTrustStore>,
    risk_tracker: Option<aegis_security::risk::RiskTracker>,
    folded: crate::config_source::reload::FoldedReloadTargets,
) -> aegis_core::Result<()> {
    let (tx, mut rx) = mpsc::channel::<notify::Result<Event>>(64);

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.blocking_send(res);
        },
        notify::Config::default(),
    )
    .map_err(|e| aegis_core::WafError::Config(format!("watcher init: {e}")))?;

    watcher
        .watch(&path, RecursiveMode::NonRecursive)
        .map_err(|e| aegis_core::WafError::Config(format!("watcher start: {e}")))?;

    tracing::info!("config watcher started on {}", path.display());

    // Keep watcher alive for the duration of this task.
    let _watcher = watcher;

    while let Some(event_result) = rx.recv().await {
        let event = match event_result {
            Ok(ev) => ev,
            Err(e) => {
                tracing::warn!("file watch error: {e}");
                continue;
            }
        };

        // Only react to content modifications.
        if !matches!(
            event.kind,
            EventKind::Modify(_) | EventKind::Create(_)
        ) {
            continue;
        }

        // Small debounce — editors may trigger multiple events.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        tracing::info!("config file changed, reloading…");

        match load_config(&path) {
            Ok(new_cfg) => {
                // Re-derive the detector mask from the new cfg
                // (cfg.detectors may have flipped class enables) and
                // run the compliance clamp before swapping cfg, so
                // the data plane never sees a non-compliant mask.
                // Shared logic with the etcd watcher lives in
                // `config_source::reload::apply_cfg_change_to_mask`.
                if let crate::config_source::reload::ReloadOutcome::AppliedWithCompliance { forced } =
                    crate::config_source::reload::apply_cfg_change_to_mask(
                        &new_cfg,
                        detector_mask.as_ref(),
                    )
                {
                    tracing::warn!(
                        forced = ?forced,
                        "config hot-reload: cfg.detectors had classes disabled that compliance modes pin to ON; forcing them back on",
                    );
                    bus.emit(AuditEvent {
                        schema_version: 1,
                        ts: chrono::Utc::now(),
                        request_id: String::new(),
                        class: AuditClass::Admin,
                        tenant_id: None,
                        tier: None,
                        action: "compliance_clamp_applied".into(),
                        reason: format!(
                            "config hot-reload forced classes back on: {}",
                            forced.join(", "),
                        ),
                        client_ip: String::new(),
                        route_id: None,
                        rule_id: None,
                        risk_score: None,
                        method: None,
                        path: None,
                        mode: None,
                        fields: serde_json::json!({
                            "path": path.display().to_string(),
                            "forced": forced,
                            "source": "file",
                        }),
                    });
                }

                // Route hot-reload — rebuild + atomic-swap the
                // proxy's `route_table` from `new_cfg.routes`. A
                // validation failure here keeps the live table
                // intact (operator gets `routes_reload_failed` in
                // the audit chain) but DOESN'T abort the cfg swap
                // — every other field is still valid, and rolling
                // back cfg on a route-only failure would produce
                // an even more confusing operator state.
                match crate::config_source::reload::apply_cfg_change_to_routes(
                    &new_cfg,
                    proxy_ctx.as_ref(),
                ) {
                    crate::config_source::reload::RouteReloadOutcome::NoCtx
                    | crate::config_source::reload::RouteReloadOutcome::Applied => {}
                    crate::config_source::reload::RouteReloadOutcome::Failed { reason } => {
                        tracing::error!(
                            reason = %reason,
                            "config hot-reload: route table rebuild failed; live routes unchanged",
                        );
                        bus.emit(AuditEvent {
                            schema_version: 1,
                            ts: chrono::Utc::now(),
                            request_id: String::new(),
                            class: AuditClass::Admin,
                            tenant_id: None,
                            tier: None,
                            action: "routes_reload_failed".into(),
                            reason: reason.clone(),
                            client_ip: String::new(),
                            route_id: None,
                            rule_id: None,
                            risk_score: None,
                            method: None,
                            path: None,
                            mode: None,
                            fields: serde_json::json!({
                                "path": path.display().to_string(),
                                "source": "file",
                                "reason": reason,
                            }),
                        });
                    }
                }

                // 2026-05-08 NEW-1 — risk threshold hot-reload.
                // Mirrors the detector-mask / route / rate-limit
                // pattern: detect change vs the live snapshot and
                // atomic-swap. Per-IP risk state is preserved
                // because `set_thresholds` only swaps the threshold
                // ArcSwap, not the per-IP score map. Audit-emit on
                // every applied change so operators see threshold
                // moves in the same trail as PUT /api/risk/thresholds.
                if let Some(tracker) = risk_tracker.as_ref() {
                    let new_thresholds = new_cfg.risk.thresholds.clone();
                    let old_thresholds = tracker.thresholds();
                    if new_thresholds != old_thresholds {
                        tracker.set_thresholds(new_thresholds.clone());
                        tracing::info!(
                            challenge_at = new_thresholds.challenge_at,
                            block_at     = new_thresholds.block_at,
                            max          = new_thresholds.max,
                            "config hot-reload: risk thresholds swapped",
                        );
                        bus.emit(AuditEvent {
                            schema_version: 1,
                            ts: chrono::Utc::now(),
                            request_id: String::new(),
                            class: AuditClass::Admin,
                            tenant_id: None,
                            tier: None,
                            action: "risk_thresholds_reloaded".into(),
                            reason: format!(
                                "risk thresholds reloaded: challenge_at={} block_at={} max={}",
                                new_thresholds.challenge_at,
                                new_thresholds.block_at,
                                new_thresholds.max,
                            ),
                            client_ip: String::new(),
                            route_id: None,
                            rule_id: None,
                            risk_score: None,
                            method: None,
                            path: None,
                            mode: None,
                            fields: serde_json::json!({
                                "path": path.display().to_string(),
                                "source": "file",
                                "before": {
                                    "challenge_at": old_thresholds.challenge_at,
                                    "block_at":     old_thresholds.block_at,
                                    "max":          old_thresholds.max,
                                },
                                "after": {
                                    "challenge_at": new_thresholds.challenge_at,
                                    "block_at":     new_thresholds.block_at,
                                    "max":          new_thresholds.max,
                                },
                            }),
                        });
                    }
                }

                // Rate-limit hot-reload — re-derive the IP
                // limiter cfg from `new_cfg.rate_limit.buckets`
                // and atomic-swap. Per-IP state preserved.
                if let crate::config_source::reload::RateLimitReloadOutcome::Applied {
                    limit,
                    window_secs,
                } = crate::config_source::reload::apply_cfg_change_to_rate_limit(
                    &new_cfg,
                    ip_rate_limiter.as_ref(),
                ) {
                    tracing::info!(
                        limit,
                        window_secs,
                        "config hot-reload: ip rate-limit cfg swapped",
                    );
                    bus.emit(AuditEvent {
                        schema_version: 1,
                        ts: chrono::Utc::now(),
                        request_id: String::new(),
                        class: AuditClass::Admin,
                        tenant_id: None,
                        tier: None,
                        action: "rate_limit_reloaded".into(),
                        reason: format!(
                            "ip rate-limit reloaded: {limit} per {window_secs}s",
                        ),
                        client_ip: String::new(),
                        route_id: None,
                        rule_id: None,
                        risk_score: None,
                        method: None,
                        path: None,
                        mode: None,
                        fields: serde_json::json!({
                            "path": path.display().to_string(),
                            "source": "file",
                            "limit": limit,
                            "window_secs": window_secs,
                        }),
                    });
                }

                // TLS cert hot-reload — rebuild + atomic-swap
                // the cert store in the live `DynamicResolver`.
                // `SkippedEmpty` is the no-op path (new cfg has
                // no `tls:` block); `Failed` keeps the live
                // store responsive and emits an audit event.
                match crate::config_source::reload::apply_cfg_change_to_tls(
                    &new_cfg,
                    tls_resolver.as_ref(),
                ) {
                    crate::config_source::reload::TlsReloadOutcome::NoResolver
                    | crate::config_source::reload::TlsReloadOutcome::SkippedEmpty => {}
                    crate::config_source::reload::TlsReloadOutcome::Applied {
                        cert_count,
                    } => {
                        tracing::info!(
                            cert_count,
                            "config hot-reload: tls cert store swapped",
                        );
                        bus.emit(AuditEvent {
                            schema_version: 1,
                            ts: chrono::Utc::now(),
                            request_id: String::new(),
                            class: AuditClass::Admin,
                            tenant_id: None,
                            tier: None,
                            action: "tls_reloaded".into(),
                            reason: format!(
                                "tls cert store rebuilt with {cert_count} certificate(s)",
                            ),
                            client_ip: String::new(),
                            route_id: None,
                            rule_id: None,
                            risk_score: None,
                            method: None,
                            path: None,
                            mode: None,
                            fields: serde_json::json!({
                                "path": path.display().to_string(),
                                "source": "file",
                                "cert_count": cert_count,
                            }),
                        });
                    }
                    crate::config_source::reload::TlsReloadOutcome::Failed { reason } => {
                        tracing::error!(
                            reason = %reason,
                            "config hot-reload: tls cert load failed; live certs unchanged",
                        );
                        bus.emit(AuditEvent {
                            schema_version: 1,
                            ts: chrono::Utc::now(),
                            request_id: String::new(),
                            class: AuditClass::Admin,
                            tenant_id: None,
                            tier: None,
                            action: "tls_reload_failed".into(),
                            reason: reason.clone(),
                            client_ip: String::new(),
                            route_id: None,
                            rule_id: None,
                            risk_score: None,
                            method: None,
                            path: None,
                            mode: None,
                            fields: serde_json::json!({
                                "path": path.display().to_string(),
                                "source": "file",
                                "reason": reason,
                            }),
                        });
                    }
                }

                // MTLS-T5 — client-auth (mTLS inbound) trust
                // store hot-reload. Re-parses
                // `new_cfg.tls.client_auth.ca_bundle` and
                // atomic-swaps it into the live ClientTrustStore.
                // SkippedDisabled is the no-op path; Failed
                // keeps the live store responsive and emits
                // an audit event.
                match crate::config_source::reload::apply_cfg_change_to_client_auth(
                    &new_cfg,
                    client_trust.as_ref(),
                ) {
                    crate::config_source::reload::ClientAuthReloadOutcome::NoStore
                    | crate::config_source::reload::ClientAuthReloadOutcome::SkippedDisabled => {}
                    crate::config_source::reload::ClientAuthReloadOutcome::Applied {
                        cert_count,
                        mode,
                    } => {
                        tracing::info!(
                            cert_count,
                            mode = ?mode,
                            "config hot-reload: mtls trust store swapped",
                        );
                        bus.emit(AuditEvent {
                            schema_version: 1,
                            ts: chrono::Utc::now(),
                            request_id: String::new(),
                            class: AuditClass::Admin,
                            tenant_id: None,
                            tier: None,
                            action: "zero_trust_reloaded".into(),
                            reason: format!(
                                "mtls trust store rebuilt with {cert_count} CA certificate(s)",
                            ),
                            client_ip: String::new(),
                            route_id: None,
                            rule_id: None,
                            risk_score: None,
                            method: None,
                            path: None,
                            mode: None,
                            fields: serde_json::json!({
                                "path": path.display().to_string(),
                                "source": "file",
                                "cert_count": cert_count,
                                "mode": format!("{mode:?}").to_lowercase(),
                            }),
                        });
                    }
                    crate::config_source::reload::ClientAuthReloadOutcome::MissingCaBundle => {
                        tracing::error!(
                            "config hot-reload: mtls reload skipped — non-disabled mode but ca_bundle missing",
                        );
                        bus.emit(AuditEvent {
                            schema_version: 1,
                            ts: chrono::Utc::now(),
                            request_id: String::new(),
                            class: AuditClass::Admin,
                            tenant_id: None,
                            tier: None,
                            action: "zero_trust_reload_failed".into(),
                            reason: "client_auth.ca_bundle missing for non-disabled mode".into(),
                            client_ip: String::new(),
                            route_id: None,
                            rule_id: None,
                            risk_score: None,
                            method: None,
                            path: None,
                            mode: None,
                            fields: serde_json::json!({
                                "path": path.display().to_string(),
                                "source": "file",
                                "reason": "missing_ca_bundle",
                            }),
                        });
                    }
                    crate::config_source::reload::ClientAuthReloadOutcome::Failed { reason } => {
                        tracing::error!(
                            reason = %reason,
                            "config hot-reload: mtls trust store load failed; live trust unchanged",
                        );
                        bus.emit(AuditEvent {
                            schema_version: 1,
                            ts: chrono::Utc::now(),
                            request_id: String::new(),
                            class: AuditClass::Admin,
                            tenant_id: None,
                            tier: None,
                            action: "zero_trust_reload_failed".into(),
                            reason: reason.clone(),
                            client_ip: String::new(),
                            route_id: None,
                            rule_id: None,
                            risk_score: None,
                            method: None,
                            path: None,
                            mode: None,
                            fields: serde_json::json!({
                                "path": path.display().to_string(),
                                "source": "file",
                                "reason": reason,
                            }),
                        });
                    }
                }

                // F-CONTRACT-003 (2026-05-17 s-tester audit): if the
                // YAML edit changed `cfg.upstreams`, warn the operator
                // that the file-watcher reload does NOT rebuild
                // `ctx.pools` (the live pool registry is operated via
                // the audit-mutated PUT path at `/api/upstreams`). Pre-
                // fix the file reload silently swapped the cfg snapshot
                // but left the pools stale, so an operator who edited
                // YAML saw new config in `/api/config` but old pool
                // members in `/api/upstreams`. Now they get a clear
                // warning + an audit event pointing at the right
                // remediation.
                {
                    // PoolConfig implements neither PartialEq nor
                    // Serialize (adding either would cascade through
                    // a dozen nested types). Compare via Debug
                    // formatting — cheap enough for a reload-rate
                    // event and good enough to detect any field
                    // change in the upstreams map.
                    let old_dbg = format!("{:?}", cfg.load().upstreams);
                    let new_dbg = format!("{:?}", new_cfg.upstreams);
                    if old_dbg != new_dbg {
                        tracing::warn!(
                            path = %path.display(),
                            "config hot-reload: cfg.upstreams diff detected but pools are NOT rebuilt from file/etcd reload. \
                             Use `PUT /api/upstreams` (audit-mutated dashboard path) for live pool changes, or restart the WAF.",
                        );
                        bus.emit(AuditEvent {
                            schema_version: 1,
                            ts: chrono::Utc::now(),
                            request_id: String::new(),
                            class: AuditClass::Admin,
                            tenant_id: None,
                            tier: None,
                            action: "upstreams_reload_skipped".into(),
                            reason: "cfg.upstreams diff detected on file reload; pools NOT auto-rebuilt (operator must use audit-mutated PUT or restart)".into(),
                            client_ip: String::new(),
                            route_id: None,
                            rule_id: None,
                            risk_score: None,
                            method: None,
                            path: None,
                            mode: None,
                            fields: serde_json::json!({
                                "path": path.display().to_string(),
                                "source": "file",
                            }),
                        });
                    }
                }
                // 2026-05-28 (Phase B fold parity) — re-derive the
                // folded stores (AI / response-filter / tiers / rules /
                // upstream pools) from the new file config, matching the
                // redis config-plane watcher. Without this a file reload
                // of those fields needed a restart.
                crate::config_source::reload::apply_folded_stores(&new_cfg, &folded).await;
                cfg.store(Arc::new(new_cfg));
                tracing::info!("config reloaded successfully");
                bus.emit(AuditEvent {
                    schema_version: 1,
                    ts: chrono::Utc::now(),
                    request_id: String::new(),
                    class: AuditClass::Admin,
                    tenant_id: None,
                    tier: None,
                    action: "config_reload".into(),
                    reason: "file changed".into(),
                    client_ip: String::new(),
                    route_id: None,
                    rule_id: None,
                    risk_score: None,
                    method: None,
                    path: None,
                    mode: None,
                    fields: serde_json::json!({"path": path.display().to_string()}),
                });
            }
            Err(e) => {
                tracing::error!("config reload failed, keeping previous config: {e}");
                bus.emit(AuditEvent {
                    schema_version: 1,
                    ts: chrono::Utc::now(),
                    request_id: String::new(),
                    class: AuditClass::Admin,
                    tenant_id: None,
                    tier: None,
                    action: "config_reload_failed".into(),
                    reason: format!("{e}"),
                    client_ip: String::new(),
                    route_id: None,
                    rule_id: None,
                    risk_score: None,
                    method: None,
                    path: None,
                    mode: None,
                    fields: serde_json::json!({"path": path.display().to_string()}),
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use std::io::Write;

    fn minimal_yaml() -> String {
        r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#
        .into()
    }

    #[tokio::test]
    async fn reload_on_file_change() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("waf.yaml");
        std::fs::write(&config_path, minimal_yaml()).unwrap();

        let initial = load_config(&config_path).unwrap();
        let cfg = Arc::new(ArcSwap::from_pointee(initial));
        let bus = AuditBus::new(16);
        let mut rx = bus.subscribe();

        let handle = spawn_config_watcher(config_path.clone(), cfg.clone(), bus, None, None, None, None, None, None, Default::default());

        // Give watcher time to register.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Mutate the file (change the bind address).
        let updated = minimal_yaml().replace("127.0.0.1:8080", "127.0.0.1:8888");
        {
            let mut f = std::fs::File::create(&config_path).unwrap();
            f.write_all(updated.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }

        // Wait for reload.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let loaded = cfg.load();
        assert_eq!(
            loaded.listeners.data[0].bind,
            "127.0.0.1:8888".parse().unwrap(),
        );

        // Should have received an audit event.
        let ev = rx.try_recv().unwrap();
        assert!(matches!(ev.class, AuditClass::Admin));
        assert_eq!(ev.action, "config_reload");

        handle.abort();
    }

    #[tokio::test]
    async fn bad_config_keeps_old() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("waf.yaml");
        std::fs::write(&config_path, minimal_yaml()).unwrap();

        let initial = load_config(&config_path).unwrap();
        let original_bind = initial.listeners.data[0].bind;
        let cfg = Arc::new(ArcSwap::from_pointee(initial));
        let bus = AuditBus::new(16);
        let mut rx = bus.subscribe();

        let handle = spawn_config_watcher(config_path.clone(), cfg.clone(), bus, None, None, None, None, None, None, Default::default());
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Drain any spurious events from watcher startup.
        while rx.try_recv().is_ok() {}

        // Write invalid YAML.
        {
            let mut f = std::fs::File::create(&config_path).unwrap();
            f.write_all(b"not: [valid: yaml: config").unwrap();
            f.sync_all().unwrap();
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Config should be unchanged.
        let loaded = cfg.load();
        assert_eq!(loaded.listeners.data[0].bind, original_bind);

        // Should have a failure event (find it among any events).
        let mut found_failure = false;
        while let Ok(ev) = rx.try_recv() {
            if ev.action == "config_reload_failed" {
                assert!(matches!(ev.class, AuditClass::Admin));
                found_failure = true;
                break;
            }
        }
        assert!(found_failure, "expected config_reload_failed audit event");

        handle.abort();
    }

    fn yaml_with_pci_and_sqli_disabled() -> String {
        // PCI mode active + cfg.detectors.sqli.enabled: false.
        // Without the clamp this would silently disable a
        // PCI-pinned class on hot-reload. With the clamp we
        // expect sqli forced back on + a `compliance_clamp_applied`
        // audit event.
        r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
detectors:
  sqli:
    enabled: false
compliance:
  modes: [pci]
"#
        .into()
    }

    #[tokio::test]
    async fn hot_reload_does_not_clamp_compliance_while_lock_is_deferred() {
        // 2026-05-10 — compliance lock is deferred. Hot-reload of a
        // config that disables sqli with PCI declared applies the
        // mask change verbatim (no force-back, no clamp event in
        // audit). Restore the pre-deferral assertions when
        // COMPLIANCE_PINNED is repopulated.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("waf.yaml");

        // Boot from a clean config — sqli ON.
        std::fs::write(&config_path, minimal_yaml()).unwrap();
        let initial = load_config(&config_path).unwrap();
        let cfg = Arc::new(ArcSwap::from_pointee(initial));

        let mask = aegis_security::detectors::SharedDetectorMask::from_config(
            &cfg.load().detectors,
        );
        assert!(mask.load().is_enabled(
            aegis_security::detectors::DetectorClass::Sqli,
        ));

        let bus = AuditBus::new(64);
        let mut rx = bus.subscribe();
        let handle = spawn_config_watcher(
            config_path.clone(),
            cfg.clone(),
            bus,
            Some(mask.clone()),
            None,
            None,
            None,
            None,
            None,
            Default::default(),
        );

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Hot-reload the file with sqli disabled + PCI mode active.
        {
            let mut f = std::fs::File::create(&config_path).unwrap();
            f.write_all(yaml_with_pci_and_sqli_disabled().as_bytes())
                .unwrap();
            f.sync_all().unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Lock deferred: sqli flips OFF as the YAML requested.
        assert!(
            !mask.load().is_enabled(
                aegis_security::detectors::DetectorClass::Sqli,
            ),
            "lock is deferred — sqli stays off after hot-reload",
        );

        // No clamp event should have fired.
        let mut clamp_seen = false;
        let mut reload_seen = false;
        while let Ok(ev) = rx.try_recv() {
            match ev.action.as_str() {
                "compliance_clamp_applied" => clamp_seen = true,
                "config_reload" => reload_seen = true,
                _ => {}
            }
        }
        assert!(!clamp_seen, "no clamp event expected while lock is deferred");
        assert!(reload_seen, "expected config_reload audit event");

        handle.abort();
    }

    fn yaml_with_route(id: &str, path: &str) -> String {
        format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: {id}
    path: "{path}"
    upstream: pool
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  pool:
    members:
      - addr: "127.0.0.1:3000"
  default:
    members:
      - addr: "127.0.0.1:3001"
state:
  backend: in_memory
"#
        )
    }

    #[tokio::test]
    async fn hot_reload_swaps_route_table() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("waf.yaml");
        std::fs::write(&config_path, yaml_with_route("v1", "/api/v1")).unwrap();

        let initial = load_config(&config_path).unwrap();
        let cfg = Arc::new(ArcSwap::from_pointee(initial));

        // Build a real ProxyContext so the supervisor can hot-swap
        // its route_table in place.
        let proxy_ctx = std::sync::Arc::new(
            crate::proxy::ProxyContext::build(
                &cfg.load(),
                std::sync::Arc::new(aegis_security::NoopPipeline),
            )
            .unwrap(),
        );

        // Boot route table resolves /api/v1 → v1.
        let r = proxy_ctx
            .route_table
            .resolve("any", "/api/v1", &http::Method::GET)
            .unwrap();
        assert_eq!(r.route_id, "v1");

        let bus = AuditBus::new(64);
        let mut rx = bus.subscribe();
        let handle = spawn_config_watcher(
            config_path.clone(),
            cfg.clone(),
            bus,
            None,
            Some(proxy_ctx.clone()),
            None,
            None,
            None,
            None,
            Default::default(),
        );

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Hot-reload to a v2 route.
        {
            let mut f = std::fs::File::create(&config_path).unwrap();
            f.write_all(yaml_with_route("v2", "/api/v2").as_bytes())
                .unwrap();
            f.sync_all().unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // /api/v1 now falls through to catch-all (live data plane
        // sees the swap).
        let r = proxy_ctx
            .route_table
            .resolve("any", "/api/v1", &http::Method::GET)
            .unwrap();
        assert_eq!(r.route_id, "catch-all");

        // /api/v2 resolves to the new route.
        let r = proxy_ctx
            .route_table
            .resolve("any", "/api/v2", &http::Method::GET)
            .unwrap();
        assert_eq!(r.route_id, "v2");

        // Audit chain should NOT carry a routes_reload_failed
        // event (success path).
        while let Ok(ev) = rx.try_recv() {
            assert_ne!(
                ev.action.as_str(),
                "routes_reload_failed",
                "unexpected route reload failure on the success path",
            );
        }

        handle.abort();
    }

    /// PR2: pre-PR2 this returned a config without any catch-all
    /// (which used to fail the build). Post-PR2 the build accepts
    /// such configs (deny-by-default), so to test the
    /// `routes_reload_failed` audit path we instead return a config
    /// that has TWO `default: true` routes in the same host scope —
    /// the new build-time invariant rejects that.
    fn yaml_no_catch_all(_id: &str, _path: &str) -> String {
        r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: a
    path: "/api"
    default: true
    upstream: pool
  - id: b
    path: "/web"
    default: true
    upstream: pool
upstreams:
  pool:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#.to_string()
    }

    #[tokio::test]
    async fn hot_reload_routes_failed_emits_audit_event() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("waf.yaml");
        std::fs::write(&config_path, yaml_with_route("v1", "/api/v1")).unwrap();

        let initial = load_config(&config_path).unwrap();
        let cfg = Arc::new(ArcSwap::from_pointee(initial));
        let proxy_ctx = std::sync::Arc::new(
            crate::proxy::ProxyContext::build(
                &cfg.load(),
                std::sync::Arc::new(aegis_security::NoopPipeline),
            )
            .unwrap(),
        );

        let bus = AuditBus::new(64);
        let mut rx = bus.subscribe();
        let handle = spawn_config_watcher(
            config_path.clone(),
            cfg.clone(),
            bus,
            None,
            Some(proxy_ctx.clone()),
            None,
            None,
            None,
            None,
            Default::default(),
        );

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Drain spurious startup events.
        while rx.try_recv().is_ok() {}

        // Write a config that PASSES `WafConfig::validate` but
        // FAILS the route table rebuild (no catch-all). The
        // supervisor stores the new cfg, emits
        // `routes_reload_failed`, and KEEPS the previous route
        // table live so the data plane keeps serving.
        std::fs::write(&config_path, yaml_no_catch_all("only", "/foo")).unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Live route table untouched: /api/v1 still resolves.
        let r = proxy_ctx
            .route_table
            .resolve("any", "/api/v1", &http::Method::GET)
            .unwrap();
        assert_eq!(r.route_id, "v1");

        let mut saw_routes_failed = false;
        while let Ok(ev) = rx.try_recv() {
            if ev.action == "routes_reload_failed" {
                saw_routes_failed = true;
                assert!(
                    ev.reason.contains("default") && ev.reason.contains("at most one"),
                    "expected double-default rejection, got: {}",
                    ev.reason
                );
            }
        }
        assert!(
            saw_routes_failed,
            "expected routes_reload_failed event since rebuild rejects double-default",
        );

        handle.abort();
    }

    fn yaml_with_rate_limit_bucket(limit: u64, window_secs: u64) -> String {
        format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
rate_limit:
  buckets:
    - id: ip-global
      scope: global
      key: ip
      algo: sliding_window
      limit: {limit}
      window: {window_secs}s
"#
        )
    }

    #[tokio::test]
    async fn hot_reload_swaps_ip_rate_limit_cfg() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("waf.yaml");
        std::fs::write(&config_path, yaml_with_rate_limit_bucket(100, 60)).unwrap();

        let initial = load_config(&config_path).unwrap();
        let cfg = Arc::new(ArcSwap::from_pointee(initial));
        let initial_rl =
            crate::config_source::reload::derive_ip_rate_cfg(&cfg.load());
        let limiter = std::sync::Arc::new(
            aegis_security::rate_limit::IpRateLimiter::new(initial_rl),
        );
        assert_eq!(limiter.config().limit, 100);

        let bus = AuditBus::new(64);
        let mut rx = bus.subscribe();
        let handle = spawn_config_watcher(
            config_path.clone(),
            cfg.clone(),
            bus,
            None,
            None,
            Some(limiter.clone()),
            None,
            None,
            None,
            Default::default(),
        );

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Hot-reload to limit=500 / 30s.
        {
            let mut f = std::fs::File::create(&config_path).unwrap();
            f.write_all(yaml_with_rate_limit_bucket(500, 30).as_bytes())
                .unwrap();
            f.sync_all().unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Live limiter sees the swap.
        assert_eq!(limiter.config().limit, 500);
        assert_eq!(limiter.config().window.as_secs(), 30);

        // Audit chain carries `rate_limit_reloaded`.
        let mut saw_reload_event = false;
        while let Ok(ev) = rx.try_recv() {
            if ev.action == "rate_limit_reloaded" {
                saw_reload_event = true;
                assert!(ev.reason.contains("500"));
            }
        }
        assert!(
            saw_reload_event,
            "expected rate_limit_reloaded audit event",
        );

        handle.abort();
    }

    // 2026-05-08 NEW-1 — risk threshold hot-reload regression
    // guard. Mirrors `hot_reload_swaps_ip_rate_limit_cfg` shape.
    // Pre-fix: the watcher had no risk block, so editing
    // `risk.thresholds.challenge_at` in the YAML had no effect on
    // the live tracker — the challenge tier could only be reached
    // by a full process restart.
    fn yaml_with_risk_thresholds(challenge_at: u32, block_at: u32, max: u32) -> String {
        format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
risk:
  thresholds:
    challenge_at: {challenge_at}
    block_at:     {block_at}
    max:          {max}
"#
        )
    }

    #[tokio::test]
    async fn hot_reload_swaps_risk_thresholds() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("waf.yaml");
        std::fs::write(&config_path, yaml_with_risk_thresholds(40, 80, 100)).unwrap();

        let initial = load_config(&config_path).unwrap();
        let cfg = Arc::new(ArcSwap::from_pointee(initial));
        let tracker = aegis_security::risk::RiskTracker::new(&cfg.load().risk);
        assert_eq!(tracker.thresholds().challenge_at, 40);
        assert_eq!(tracker.thresholds().block_at,     80);

        let bus = AuditBus::new(64);
        let mut rx = bus.subscribe();
        let handle = spawn_config_watcher(
            config_path.clone(),
            cfg.clone(),
            bus,
            None,
            None,
            None,
            None,
            None,
            Some(tracker.clone()),
            Default::default(),
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Hot-reload: bump challenge_at to 50, block_at to 90.
        {
            let mut f = std::fs::File::create(&config_path).unwrap();
            f.write_all(yaml_with_risk_thresholds(50, 90, 100).as_bytes())
                .unwrap();
            f.sync_all().unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Live tracker sees the swap.
        assert_eq!(
            tracker.thresholds().challenge_at, 50,
            "challenge_at must propagate via hot-reload",
        );
        assert_eq!(
            tracker.thresholds().block_at, 90,
            "block_at must propagate via hot-reload",
        );

        // Audit chain carries `risk_thresholds_reloaded`.
        let mut saw_reload_event = false;
        while let Ok(ev) = rx.try_recv() {
            if ev.action == "risk_thresholds_reloaded" {
                saw_reload_event = true;
                assert!(ev.reason.contains("challenge_at=50"));
                assert!(ev.reason.contains("block_at=90"));
            }
        }
        assert!(
            saw_reload_event,
            "expected risk_thresholds_reloaded audit event",
        );

        handle.abort();
    }

    #[tokio::test]
    async fn hot_reload_skips_risk_emit_when_thresholds_unchanged() {
        // Defensive: re-saving the same YAML should not emit a
        // bogus `risk_thresholds_reloaded` event. The watch loop
        // compares against the live snapshot before swapping.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("waf.yaml");
        std::fs::write(&config_path, yaml_with_risk_thresholds(40, 80, 100)).unwrap();

        let initial = load_config(&config_path).unwrap();
        let cfg = Arc::new(ArcSwap::from_pointee(initial));
        let tracker = aegis_security::risk::RiskTracker::new(&cfg.load().risk);

        let bus = AuditBus::new(64);
        let mut rx = bus.subscribe();
        let handle = spawn_config_watcher(
            config_path.clone(),
            cfg.clone(),
            bus,
            None,
            None,
            None,
            None,
            None,
            Some(tracker.clone()),
            Default::default(),
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Re-write identical content (touch-style edit).
        {
            let mut f = std::fs::File::create(&config_path).unwrap();
            f.write_all(yaml_with_risk_thresholds(40, 80, 100).as_bytes())
                .unwrap();
            f.sync_all().unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let mut saw_reload_event = false;
        while let Ok(ev) = rx.try_recv() {
            if ev.action == "risk_thresholds_reloaded" {
                saw_reload_event = true;
            }
        }
        assert!(
            !saw_reload_event,
            "risk_thresholds_reloaded must not fire when thresholds unchanged",
        );

        handle.abort();
    }

    fn generate_self_signed_cert(domains: &[&str]) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(
            domains.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        params.is_ca = rcgen::IsCa::NoCa;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    fn write_pem_file(path: &std::path::Path, content: &str) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.sync_all().unwrap();
    }

    fn yaml_with_tls_certs(cert_path: &str, key_path: &str, host: &str) -> String {
        format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
tls:
  certificates:
    - hosts: ["{host}"]
      cert_path: "{cert_path}"
      key_ref: "{key_path}"
"#
        )
    }

    #[tokio::test]
    async fn hot_reload_swaps_tls_cert_store() {
        use crate::listener::tls::{CertStore, DynamicResolver};
        use arc_swap::ArcSwap;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("waf.yaml");

        // Boot with cert A.
        let (cert_a, key_a) = generate_self_signed_cert(&["original.example.com"]);
        let cert_a_path = dir.path().join("a.crt");
        let key_a_path = dir.path().join("a.key");
        write_pem_file(&cert_a_path, &cert_a);
        write_pem_file(&key_a_path, &key_a);

        std::fs::write(
            &config_path,
            yaml_with_tls_certs(
                cert_a_path.to_str().unwrap(),
                key_a_path.to_str().unwrap(),
                "original.example.com",
            ),
        )
        .unwrap();

        let initial = load_config(&config_path).unwrap();
        let cfg = Arc::new(ArcSwap::from_pointee(initial));

        // Build the resolver from the boot cfg.
        let entries = vec![(
            cert_a_path.clone(),
            key_a_path.clone(),
            vec!["original.example.com".to_string()],
        )];
        let entries_ref: Vec<(_, _, &[String])> = entries
            .iter()
            .map(|(c, k, h)| (c.clone(), k.clone(), &h[..]))
            .collect();
        let store = CertStore::load(&entries_ref).unwrap();
        let resolver = std::sync::Arc::new(DynamicResolver::new(
            std::sync::Arc::new(ArcSwap::from_pointee(store)),
        ));

        let bus = AuditBus::new(64);
        let mut rx = bus.subscribe();
        let handle = spawn_config_watcher(
            config_path.clone(),
            cfg.clone(),
            bus,
            None,
            None,
            None,
            Some(resolver.clone()),
            None,
            None,
            Default::default(),
        );

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Generate a fresh cert B and rewrite the YAML to point
        // at it. The supervisor should rebuild the cert store.
        let (cert_b, key_b) = generate_self_signed_cert(&["rotated.example.com"]);
        let cert_b_path = dir.path().join("b.crt");
        let key_b_path = dir.path().join("b.key");
        write_pem_file(&cert_b_path, &cert_b);
        write_pem_file(&key_b_path, &key_b);

        std::fs::write(
            &config_path,
            yaml_with_tls_certs(
                cert_b_path.to_str().unwrap(),
                key_b_path.to_str().unwrap(),
                "rotated.example.com",
            ),
        )
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Audit chain should carry `tls_reloaded`.
        let mut tls_reloaded_seen = false;
        while let Ok(ev) = rx.try_recv() {
            if ev.action == "tls_reloaded" {
                tls_reloaded_seen = true;
                assert!(ev.reason.contains("1 certificate"));
            }
        }
        assert!(tls_reloaded_seen, "expected tls_reloaded audit event");

        // The resolver's store now resolves the new SNI.
        let store_handle = resolver.store_handle();
        let resolved = store_handle.load().resolve(Some("rotated.example.com"));
        assert!(resolved.is_some(), "rotated cert should resolve");

        handle.abort();
    }

    #[tokio::test]
    async fn hot_reload_tls_failed_keeps_old_certs_live() {
        use crate::listener::tls::{CertStore, DynamicResolver};
        use arc_swap::ArcSwap;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("waf.yaml");
        let (cert_a, key_a) = generate_self_signed_cert(&["a.example.com"]);
        let cert_a_path = dir.path().join("a.crt");
        let key_a_path = dir.path().join("a.key");
        write_pem_file(&cert_a_path, &cert_a);
        write_pem_file(&key_a_path, &key_a);
        std::fs::write(
            &config_path,
            yaml_with_tls_certs(
                cert_a_path.to_str().unwrap(),
                key_a_path.to_str().unwrap(),
                "a.example.com",
            ),
        )
        .unwrap();
        let initial = load_config(&config_path).unwrap();
        let cfg = Arc::new(ArcSwap::from_pointee(initial));

        let entries = vec![(
            cert_a_path.clone(),
            key_a_path.clone(),
            vec!["a.example.com".to_string()],
        )];
        let entries_ref: Vec<(_, _, &[String])> = entries
            .iter()
            .map(|(c, k, h)| (c.clone(), k.clone(), &h[..]))
            .collect();
        let store = CertStore::load(&entries_ref).unwrap();
        let resolver = std::sync::Arc::new(DynamicResolver::new(
            std::sync::Arc::new(ArcSwap::from_pointee(store)),
        ));

        let bus = AuditBus::new(64);
        let mut rx = bus.subscribe();
        let handle = spawn_config_watcher(
            config_path.clone(),
            cfg.clone(),
            bus,
            None,
            None,
            None,
            Some(resolver.clone()),
            None,
            None,
            Default::default(),
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Drain spurious events.
        while rx.try_recv().is_ok() {}

        // Rewrite cfg pointing at a non-existent cert path.
        std::fs::write(
            &config_path,
            yaml_with_tls_certs(
                "/nonexistent/path/cert.pem",
                "/nonexistent/path/key.pem",
                "broken.example.com",
            ),
        )
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Old store still resolves the original SNI.
        let store_handle = resolver.store_handle();
        let still_works = store_handle.load().resolve(Some("a.example.com"));
        assert!(still_works.is_some(), "old cert resolvable after failed reload");

        // tls_reload_failed event landed.
        let mut saw_failure = false;
        while let Ok(ev) = rx.try_recv() {
            if ev.action == "tls_reload_failed" {
                saw_failure = true;
            }
        }
        assert!(saw_failure, "expected tls_reload_failed audit event");

        handle.abort();
    }

    // ─── In-flight tracker tests ───

    #[test]
    fn tracker_acquire_release() {
        let t = InFlightTracker::new();
        assert!(t.acquire());
        assert!(t.acquire());
        assert_eq!(t.in_flight(), 2);
        t.release();
        assert_eq!(t.in_flight(), 1);
        t.release();
        assert_eq!(t.in_flight(), 0);
    }

    #[test]
    fn tracker_rejects_during_drain() {
        let t = InFlightTracker::new();
        assert!(t.acquire());
        t.start_drain();
        assert!(t.is_draining());
        assert!(!t.acquire()); // rejected
        assert_eq!(t.in_flight(), 1); // existing request still counted
    }

    #[tokio::test]
    async fn drain_completes_when_empty() {
        let tracker = Arc::new(InFlightTracker::new());
        let handle = DrainHandle::new(tracker.clone(), Duration::from_secs(5));
        let remaining = handle.drain().await;
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn drain_waits_for_inflight() {
        let tracker = Arc::new(InFlightTracker::new());
        tracker.acquire();
        tracker.acquire();

        let t2 = tracker.clone();
        // Simulate requests finishing after 100ms.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            t2.release();
            t2.release();
        });

        let handle = DrainHandle::new(tracker, Duration::from_secs(5));
        let remaining = handle.drain().await;
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn drain_times_out() {
        let tracker = Arc::new(InFlightTracker::new());
        tracker.acquire(); // Never released.

        let handle = DrainHandle::new(tracker, Duration::from_millis(200));
        let remaining = handle.drain().await;
        assert_eq!(remaining, 1);
    }
}
