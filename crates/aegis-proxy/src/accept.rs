//! PRE-T7 (part of) — admin + data-plane accept loops
//! extracted from `lib.rs`.
//!
//! ## Scope
//!
//! - [`admin_accept_loop`] — long-running loop that accepts
//!   admin/dashboard connections and dispatches each request
//!   through [`crate::admin_dispatch::handle_admin_request`].
//!   Owns the per-connection `service_fn` closure that
//!   forwards every request through the full admin pipeline.
//!   Also intercepts `/dashboard/sse` for streaming bodies
//!   (B4-T4) before falling through to the buffered router.
//! - [`accept_loop`] — same shape for data-plane TCP
//!   listeners. Each per-connection task calls
//!   [`crate::data_plane::handle_data_request`] (the
//!   `#[tracing::instrument]` wrapper that records the
//!   resolved `action` for OTel) and records
//!   `waf_requests_total{action}` per request.
//!
//! Visibility: `pub(crate)` for both. Single call sites in
//! `lib.rs::run` (the boot orchestrator).

use std::convert::Infallible;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;

use aegis_core::config::WafConfig;
use aegis_core::{AuditBus, ReadinessSignal};

use crate::admin_dispatch::{handle_admin_request, read_cert_inventory, stamp_interop_response};
use crate::admin_sse;
use crate::data_plane::handle_data_request;

/// PROXY-04 (LT-RUN-11, 2026-06-19) — slowloris guard. hyper's builders impose
/// no header-read deadline by default, so a client that opens a connection and
/// dribbles request-header bytes pins a tokio task + socket indefinitely (the
/// `LoadShedder` only gates request *processing*, reached after headers are
/// read). Bounding the header-read phase closes the classic slow-header
/// slowloris while leaving long-lived post-request streams (SSE, WebSocket
/// upgrades) untouched — it caps only the time to finish reading the request
/// head, not the connection lifetime.
const HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(feature = "redis")]
/// Broadcast capacity for the fleet-event bus (cluster Phase 2). Peers'
/// events fan in here for the SSE merge; a slow dashboard drops the
/// oldest (lossy monitor feed).
const FLEET_EVENT_BUS_CAP: usize = 1024;

/// Cluster Phase 2 (§2b) — wire the cross-node event fanout when
/// SLO-P5 — dispatch one alert event through the dedup cache to
/// the live receiver list, folding delivery outcomes into the
/// `/api/alert-receivers` ring. The single path every alert class
/// takes (SLO burn, watchdog, pool health, DDoS gate, certs,
/// hot-reload) so routing/dedup behavior can't drift per class.
///
/// (VipTalk dispatch with the `alerts` feature off is a logged
/// no-op counted in `delivered` — see CC-T2.1.b for the summary
/// split.)
async fn dispatch_and_record(
    event: &aegis_control::slo::AlertEvent,
    receivers: &[aegis_control::slo::AlertReceiver],
    dedup: &aegis_control::slo::AlertDedupCache,
    ring: &aegis_control::api::alert_receivers::DispatchOutcomeRing,
) {
    let summary =
        aegis_control::slo::dispatch::dispatch_event(event, receivers, Some(dedup)).await;
    let now = chrono::Utc::now().timestamp();
    for name in &summary.delivered {
        ring.record_delivered(name, now);
    }
    for name in &summary.external {
        ring.record_external(name, now);
    }
    for (name, reason) in &summary.failed {
        ring.record_failed(name, now, reason);
    }
    tracing::info!(
        severity = ?event.severity(),
        delivered = summary.delivered.len(),
        external = summary.external.len(),
        failed = summary.failed.len(),
        "alert event dispatched",
    );
}

/// `cluster.fleet_events` is enabled AND a Redis state backend is
/// configured. Spawns the publisher (drains the local bus → Redis) and
/// subscriber (Redis → the returned fleet bus) tasks, and returns the
/// fleet-event bus the dashboard SSE merges in. Returns `None` for
/// single-node / cluster-off / non-redis builds — the SSE feed then
/// stays local-only (today's behaviour), and nothing is spawned.
fn spawn_fleet_event_fanout(
    cfg: &WafConfig,
    local_bus: &AuditBus,
    our_node: &str,
) -> Option<AuditBus> {
    let fe = &cfg.cluster.fleet_events;
    if !fe.enabled
        || !matches!(cfg.state.backend, aegis_core::config::StateBackendKind::Redis)
    {
        return None;
    }
    #[cfg(feature = "redis")]
    {
        let Some(url) = cfg.state.redis.as_ref().and_then(|r| r.urls.first().cloned()) else {
            tracing::warn!("cluster.fleet_events enabled but no redis url; cross-node feed disabled");
            return None;
        };
        match crate::state::RedisFleetBus::connect(&url) {
            Ok(fb) => {
                let fb: Arc<dyn aegis_core::fleet::FleetBus> = Arc::new(fb);
                let fleet_event_bus = AuditBus::new(FLEET_EVENT_BUS_CAP);
                crate::fleet_events::spawn_fleet_publisher(
                    local_bus.clone(),
                    Arc::clone(&fb),
                    fe.channel.clone(),
                    our_node.to_string(),
                    fe.max_publish_rate_per_s,
                );
                crate::fleet_events::spawn_fleet_subscriber(
                    fb,
                    fe.channel.clone(),
                    fleet_event_bus.clone(),
                    our_node.to_string(),
                );
                tracing::info!(
                    channel = %fe.channel,
                    "cluster fleet events: cross-node fanout active"
                );
                Some(fleet_event_bus)
            }
            Err(e) => {
                tracing::warn!(error = %e, "cluster.fleet_events: redis connect failed; cross-node feed disabled");
                None
            }
        }
    }
    #[cfg(not(feature = "redis"))]
    {
        let _ = (local_bus, our_node);
        tracing::warn!(
            "cluster.fleet_events enabled but binary built without the `redis` feature; cross-node feed disabled"
        );
        None
    }
}

/// Window (seconds) the fleet-snapshot captures + reports. Fixed for
/// v1 — the merged traffic panels report this window regardless of the
/// client's `?window=` (the snapshot fixes it).
const FLEET_SNAPSHOT_WINDOW_SECS: u32 = 300;

/// Cluster Phase 3 (§2a) — spawn the fleet-snapshot publish/merge task
/// when `cluster.fleet_view` is enabled AND a shared (non-`in_memory`)
/// state backend is present. Each tick: publish this node's traffic
/// snapshot to `fleet:snap:<node>` (TTL self-evict), then scan+merge
/// every peer's snapshot into the returned `FleetCache` (which the
/// dashboard traffic GET handlers read). Returns `None` for single-node
/// / `in_memory` — the panels then stay local-only (today's behaviour),
/// and nothing is spawned.
fn spawn_fleet_snapshot_task(
    cfg: &WafConfig,
    state_backend: Arc<dyn aegis_core::state::StateBackend>,
    stats_agg: Arc<aegis_control::api::stats::StatsAggregator>,
    attacks_agg: Arc<aegis_control::api::attacks::AttacksAggregator>,
    // Composite RiskKey buckets for the fleet-merged Top Attackers table
    // (Arc-shared with the data-plane producer; cheap to clone).
    risk: aegis_security::risk::RiskTracker,
    // IF-P1b — firing SLO alerts for the fleet Incidents roll-up.
    tracking: Arc<aegis_control::api::tracking::TrackingHandler>,
    hist: Arc<aegis_control::metrics::request_duration::RequestStageHistogram>,
    // F6 (2026-06-11) — the local audit ring, so the same publish tick
    // also ships this node's bounded audit tail for the fleet backfill.
    audit_ring: Arc<aegis_control::api::audit::AuditRing>,
    our_node: &str,
    // PB / F6 (2026-06-11) — live cluster roster (in-memory, lease-poll
    // backed). When it knows peers, the merge fans out by `GET
    // fleet:*:<node>` per id instead of a whole-keyspace `SCAN MATCH`,
    // which times out on a busy/remote/sharded Redis. `None` (or a
    // roster that only knows self) falls back to the legacy scan.
    roster: Option<Arc<aegis_control::api::tracking::RosterView>>,
) -> (
    Option<aegis_control::metrics::fleet_snapshot::FleetCache>,
    Option<aegis_control::metrics::fleet_audit::FleetAuditCache>,
) {
    use aegis_control::metrics::fleet_audit as fa;
    use aegis_control::metrics::fleet_snapshot as fs;
    let fv = &cfg.cluster.fleet_view;
    if !fv.enabled || matches!(cfg.state.backend, aegis_core::config::StateBackendKind::InMemory) {
        return (None, None);
    }
    let cache = fs::FleetCache::new();
    let cache_writer = cache.clone();
    let audit_cache = fa::FleetAuditCache::new();
    let audit_cache_writer = audit_cache.clone();
    let node = our_node.to_string();
    let publish_interval =
        std::time::Duration::from_millis(fv.publish_interval_ms.max(250));
    let ttl = std::time::Duration::from_millis(fv.snapshot_ttl_ms.max(fv.publish_interval_ms));
    let top_k = fv.top_attackers_k;
    tokio::spawn(async move {
        let key = fs::snapshot_key(&node);
        let audit_tail_key = fa::audit_key(&node);
        let mut tick = tokio::time::interval(publish_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            // 1. Build + publish our own snapshot (best-effort, off the
            //    hot path — reads already-collected local aggregates).
            let firing = tracking.active_alerts();
            let snap = fs::build_snapshot(
                &node,
                FLEET_SNAPSHOT_WINDOW_SECS,
                top_k as u32,
                &stats_agg,
                &attacks_agg,
                &risk,
                &firing,
                &hist,
                aegis_control::metrics::request_duration::stage::TOTAL,
            );
            let published = match serde_json::to_vec(&snap) {
                Ok(bytes) => state_backend.set(&key, &bytes, ttl).await.is_ok(),
                Err(_) => false,
            };
            // 1b. Publish our bounded audit tail (newest N events, each
            //     already carrying `fields.node_id`) for the fleet
            //     backfill — same self-evicting TTL pattern.
            let tail = audit_ring.recent(fa::AUDIT_TAIL_LIMIT);
            if let Ok(bytes) = serde_json::to_vec(&tail) {
                let _ = state_backend.set(&audit_tail_key, &bytes, ttl).await;
            }
            // PB / F6 — node roster for the merge. When the lease-backed
            // roster knows peers, fan out by `GET fleet:*:<node>` per id
            // (bounded, timeout-safe, cluster-Redis-safe) instead of a
            // whole-keyspace `SCAN MATCH`. `our_node` is always included
            // (the roster may or may not list self). A roster that only
            // knows self (cold start / single node / not wired) falls
            // back to the legacy scan.
            let node_ids: Vec<String> = match &roster {
                Some(rv) => {
                    let mut ids: Vec<String> =
                        rv.members().into_iter().map(|p| p.id).collect();
                    if !ids.iter().any(|i| i == &node) {
                        ids.push(node.clone());
                    }
                    ids
                }
                None => Vec::new(),
            };
            let use_roster = node_ids.len() > 1;

            // 2. Merge every live peer snapshot into the cache.
            let merged = if use_roster {
                fs::merge_from_roster(state_backend.as_ref(), &node_ids, top_k).await
            } else {
                fs::scan_and_merge(state_backend.as_ref(), top_k).await
            };
            if merged.nodes == 0 && published {
                // Nothing merged → at least show our own.
                cache_writer.store(fs::merge(std::slice::from_ref(&snap), top_k));
            } else {
                cache_writer.store(merged);
            }
            // 2b. Same for the audit tail.
            let merged_audit = if use_roster {
                fa::merge_audit_from_roster(
                    state_backend.as_ref(),
                    &node_ids,
                    fa::AUDIT_TAIL_LIMIT,
                )
                .await
            } else {
                fa::scan_and_merge_audit(state_backend.as_ref(), fa::AUDIT_TAIL_LIMIT).await
            };
            if merged_audit.is_empty() {
                // Nothing merged → at least show our own.
                audit_cache_writer.store(tail);
            } else {
                audit_cache_writer.store(merged_audit);
            }
        }
    });
    tracing::info!("cluster fleet view: snapshot publish/merge active (metrics + audit tail)");
    (Some(cache), Some(audit_cache))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn admin_accept_loop(
    tcp: tokio::net::TcpListener,
    cfg: Arc<WafConfig>,
    readiness: ReadinessSignal,
    bus: AuditBus,
    mask: aegis_security::detectors::SharedDetectorMask,
    risk: aegis_security::risk::RiskTracker,
    ip_rate_limiter: Arc<aegis_security::rate_limit::IpRateLimiter>,
    load_gauge: aegis_core::LoadGauge,
    verbosity: aegis_core::SharedVerbosity,
    metrics: aegis_control::metrics::MetricsRegistry,
    lease_store: Arc<dyn aegis_core::cluster::LeaseStore>,
    interop: Option<Arc<aegis_control::interop::InteropRuntime>>,
    // CC-T1.1.b — typed-erased writer for the proxy's `PoolRegistry`.
    // Wired by `run()` from `upstream_ctx.pools` so the audit-mutated
    // `/api/upstreams/config` PUT/DELETE handlers can hot-swap the
    // pool table.
    upstream_writer: Arc<dyn aegis_control::api::upstreams_config::UpstreamWriter>,
    // RT-T5 — same indirection for the live route table. Wired by
    // `run()` from `upstream_ctx.route_table` so the audit-mutated
    // PUT/DELETE `/api/routes/{id}` handlers can hot-swap routes.
    route_writer: Arc<dyn aegis_control::api::routes_config::RouteWriter>,
    // AI-T10 — runtime on/off handle for the AI detector. `None`
    // when the binary boots without `--features ai` OR
    // `cfg.ai.enabled = false`. The audit-mutated
    // `PUT /api/ai/enabled` handler in `admin_mutate.rs` reads
    // it from `services.ai_toggle` (set further down).
    ai_toggle: Option<Arc<std::sync::atomic::AtomicBool>>,
    // 2026-05-29 — parallel handle for the AI detector's
    // `confidence_threshold`. Stores the `f32` gate as
    // `to_bits` in an `AtomicU32`; updated by the audit-mutated
    // `PUT /api/ai/confidence` handler and read per-inference
    // via `AiDetector::threshold()`. Same `None` rules as
    // `ai_toggle`.
    ai_threshold: Option<Arc<std::sync::atomic::AtomicU32>>,
    // The `cfg.ai.confidence_threshold` value loaded at boot —
    // surfaced as `default` in the GET so the dashboard can
    // show "current vs. config" without re-parsing YAML.
    ai_threshold_default: f32,
    // AI model hot-reload bridge — stashed on `services.ai_reload` so the
    // audit-mutated `POST /api/ai/reload` handler can re-read the model file
    // and atomically swap it in. `None` in non-ai builds / batch mode.
    ai_model_reloader: Option<Arc<dyn aegis_control::api::ai_reload::AiReloadWriter>>,
    // 2026-05-11 PR #7 — live `Pipeline` whose `ResponseFilterConfig`
    // the audit-mutated `PUT /api/response-filter` handler flips.
    // Same `Arc<Pipeline>` instance the data plane reads
    // `on_body_frame` through via `upstream_ctx.pipeline`; stashing
    // it here instead of downcasting the trait object keeps the
    // writer-trait machinery decoupled from `SecurityPipeline`.
    response_filter_pipeline: Arc<aegis_security::Pipeline>,
    // SC-T1 — typed-erased state backend handle so the
    // `/api/state` endpoint can call `health()` without a separate
    // provider closure. Passed through to `services.state_backend`.
    state_backend: Arc<dyn aegis_core::state::StateBackend>,
    // MTLS-T3 — shared per-identity tracker. Created once in
    // `run.rs` so the data-plane `accept_loop` can also feed
    // it (T3 records every authenticated request); the admin
    // listener stashes it on `services.identity_tracker` for
    // `/api/mtls/*` reads.
    identity_tracker: Arc<aegis_control::identity_tracker::IdentityTracker>,
    // HACK-T3 — same detector list the data-plane runs;
    // stashed on `services.detectors` so
    // `POST /api/rules/simulate` evaluates against an
    // identical chain.
    detectors: Arc<Vec<Box<dyn aegis_security::detectors::Detector>>>,
    // 2026-05-20 — shared hot-swappable canary honeypot path set.
    // Same `CanaryPaths` handle the data-plane `CanaryDetector`
    // holds; stashed on `services.canary_paths` so the audit-mutated
    // `PUT /api/risk/canary-paths` handler edits the live set with
    // no chain rebuild or restart.
    canary_paths: aegis_security::detectors::canary::CanaryPaths,
    // Phase-1 analytics — shared with the data plane so
    // `/api/analytics/latency` reads from the same series the
    // data plane records into.
    request_stage_hist: Arc<aegis_control::metrics::request_duration::RequestStageHistogram>,
    // Phase-3 per-route latency. Same histogram the data plane
    // records into; admin reads percentiles from it.
    route_latency_hist: Arc<aegis_control::metrics::route_latency::RouteLatencyHistogram>,
    // P5 (2026-05-11) — same per-route sliding-window counter the
    // data plane writes to. Admin reads it for the
    // `/api/analytics/route-activity` endpoint.
    route_activity: aegis_control::metrics::route_activity::RouteActivityWindow,
    // Per-detector evaluation-duration histogram. Recorded by
    // the data plane around each `Detector::inspect` call.
    detector_latency_hist: Arc<aegis_control::metrics::detector_latency::DetectorLatencyHistogram>,
    // MTLS-T10 Phase 2 — live `ClientTrustStore`. Surfaced as
    // `services.trust_anchor_writer` so the audit-mutated PUT
    // `/api/mtls/ca-bundle?apply=true` handler can hot-swap roots.
    // `None` for plain-TLS / no-mTLS deployments — the handler
    // falls back to Phase 1 preview-only behaviour.
    client_trust: Option<crate::listener::client_trust::ClientTrustStore>,
    // FDP-T4 wiring — shared in-flight counter. Each accepted
    // admin connection admits a guard; the guard lives for the
    // connection's full task lifetime so the SIGUSR2 handover's
    // drain phase can wait for in-flight=0 before exiting.
    inflight: crate::hotbin::InFlightCounter,
    // FIX 2026-05-03 — optional TLS acceptor for the admin
    // listener. When `Some`, every admin connection completes
    // a TLS handshake before the HTTP service runs.
    // `cfg.admin.tls` controls whether this is wired at boot;
    // operators wanting plain HTTP on the admin port (dev
    // setups) leave `cfg.admin.tls` unset → None → existing
    // plain-HTTP path.
    admin_tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    // FIX 2026-05-03 — shared ProxyContext so the admin plane
    // can (a) plug the same blacklist/whitelist Arcs into
    // DashboardServices that the data plane consults at the
    // top of `handle_data_request`, and (b) install the GeoIP
    // adapter for `kind: country` matching after the MaxMind
    // reader is opened below.
    upstream_ctx: Arc<crate::proxy::ProxyContext>,
    // 2026-05-19 — source-of-truth waf.yaml path. `Some` when
    // `reload_source` is `ConfigReloadSource::File`; `None` for
    // etcd / static / test boots. Stashed on
    // `services.config_yaml_path` so the dashboard's
    // "Configuration backup (YAML)" download can read the file
    // at request time.
    config_yaml_path: Option<std::path::PathBuf>,
    // 2026-05-27 (config-plane fold-toggles) — the shared `TierStore`,
    // created in `run()` so the config-plane watcher can re-derive
    // per-tier settings from `cfg.tiers` on a config swap. Threaded into
    // `DashboardServices` so `services.tiers` IS this instance (also
    // shared with the data-plane `ProxyContext`).
    tiers: Arc<aegis_control::api::tiers::TierStore>,
    // 2026-05-27 (Phase B rules fold) — the shared `RuleStore`, created
    // in `run()` so the config-plane watcher re-derives the rule set
    // from `cfg.rules.inline` on a swap. Threaded into `DashboardServices`
    // so `services.rules` IS this instance — the same store the folded
    // rule-CRUD handlers and `GET /api/rules` read.
    rules: Arc<aegis_control::api::rules::RuleStore>,
    // N2 (2026-06-11) — config-plane change-notification seam. Stashed on
    // `services.config_nudge` so the audit-mutated config write handlers fire
    // a change notification on a successful activate. `None` for single-node
    // / cluster-off / nudge-disabled (interval polling only). H2b — narrow
    // [`aegis_core::config_backend::ConfigWatch`] (was `FleetBus`).
    config_nudge: Option<Arc<dyn aegis_core::config_backend::ConfigWatch>>,
    // H2b — the durable config-plane backend selected from
    // `config_plane.store` (etcd or shared_state). Stashed on
    // `services.config_backend` so the audit-mutated config write handlers
    // activate versions on the SAME store the convergence watcher reads.
    config_backend: Arc<dyn aegis_core::config_backend::ConfigBackend>,
    // N1 (2026-06-11) — shared alert-receiver list, created in `run()` so
    // the config-plane watcher (`ApplyTargets.receiver_writer`) and this
    // admin loop (GET/PUT/DELETE/test + SLO dispatch) share one ArcSwap.
    // A receiver edit folds into `cfg.alerting` and propagates fleet-wide.
    shared_receivers: Arc<arc_swap::ArcSwap<Vec<aegis_control::slo::AlertReceiver>>>,
    // SLO-P4 — SLO engine + watchdog knob, created in `run()` so the
    // config-plane watcher (`ApplyTargets.slo_engine` /
    // `.slo_absent_after_secs`) and this loop's evaluation task share
    // the same instances. An objective edit folds into `cfg.slo` and
    // propagates fleet-wide.
    slo_engine: Arc<aegis_control::slo::SloEngine>,
    slo_absent_after_secs: Arc<std::sync::atomic::AtomicU64>,
    // SLO-P5 — alert-event channel drained by the SLO dispatch
    // loop; senders live in the pool health monitors and the
    // hot-reload failure paths.
    alert_rx: tokio::sync::mpsc::UnboundedReceiver<aegis_control::slo::AlertEvent>,
) {
    let startup = aegis_control::health::StartupProbe::default();
    startup.mark_started();
    // F-T10: metrics registry is now built in `run()` so the
    // data-plane histogram series is registered into the same
    // registry the `/metrics` endpoint scrapes.

    // Build the dashboard service bundle once at boot. The drain
    // task runs for the lifetime of the admin listener — see
    // `aegis-control::dashboard_services` (D-M2-T2.7).
    //
    // Live pool health: the closure captures `upstream_writer`
    // (which wraps the proxy's PoolRegistry) and reads each
    // member's AtomicBool on every dashboard fetch. Members
    // start `healthy: true` and flip to `false` only when the
    // health probe records a failure — same flag the data plane
    // routes against.
    let upstream_writer_for_snapshot = upstream_writer.clone();
    let pool_provider: aegis_control::dashboard_services::PoolSnapshotProvider =
        Arc::new(move || upstream_writer_for_snapshot.live_snapshot());

    // F-T1 — auth runtime. Session store HMAC key derives from
    // `csrf_secret_ref`; the configured admin identity loads from
    // `password_hash_ref` (single-user model until RBAC). The
    // rate-limiter flattens the YAML's per-IP / per-user / lockout
    // blocks into the runtime config.
    let auth = &cfg.admin.dashboard_auth;
    // 2026-06-06 — boot secret hygiene. The session-cookie HMAC key is
    // blake3(csrf_secret); an empty/short secret weakens cookie integrity and,
    // in a multi-node deploy, MUST be identical on every node. An empty
    // password hash means nobody can log in (operators locked out). Surface
    // both loudly at boot rather than failing silently.
    {
        let secret = auth.csrf_secret_ref.trim();
        if secret.is_empty() {
            tracing::warn!(
                "admin auth: cfg.admin.dashboard_auth.csrf_secret is EMPTY — \
                 session cookies are signed with a fixed key. Set a random \
                 ≥32-char secret, IDENTICAL on every node.",
            );
        } else if secret.len() < 16 {
            tracing::warn!(
                len = secret.len(),
                "admin auth: csrf_secret is short (<16 chars) — use a random ≥32-char value.",
            );
        }
        if auth.password_hash_ref.trim().is_empty() && auth.accounts.is_empty() {
            tracing::warn!(
                "admin auth: no admin password configured \
                 (cfg.admin.dashboard_auth.password_hash empty, no accounts) — \
                 dashboard login is DISABLED; operators cannot sign in.",
            );
        }
        // TOTP-2 (TF-1) — enforcement is the default; an explicit opt-out
        // is a dev/CI convenience and must be loud in a real deploy.
        if !auth.require_totp {
            tracing::warn!(
                "admin auth: require_totp is DISABLED (explicit opt-out) — a \
                 password alone grants admin access. Keep this false only for \
                 dev/CI; production deployments should enforce TOTP.",
            );
        }
    }
    let session_key = aegis_control::api::login::derive_session_key(&auth.csrf_secret_ref);
    // F-HIGH-admin (2026-05-17): respect the operator-configured
    // session TTLs. Pre-fix the hard-coded values inside
    // `SessionStore::new` ignored these knobs entirely. Convert
    // from `std::time::Duration` (cfg shape) to `chrono::Duration`
    // (session module shape) — both lossless on practical values.
    let idle = chrono::Duration::from_std(auth.session_ttl_idle)
        .unwrap_or_else(|_| chrono::Duration::minutes(30));
    let absolute = chrono::Duration::from_std(auth.session_ttl_absolute)
        .unwrap_or_else(|_| chrono::Duration::hours(8));
    // 2026-06-06 — back admin sessions with the shared state backend so they
    // are fleet-wide (Redis ⇒ login on any node works, survives restart) and
    // auto-reaped at the idle TTL (no unbounded session-map growth). On the
    // in_memory backend this is the auto-reaped local store.
    let auth_sessions = Arc::new(
        aegis_control::admin_auth::session::SessionStore::with_backend(
            session_key,
            state_backend.clone(),
            idle,
            absolute,
        ),
    );
    let login_rate_limiter = aegis_control::api::login::build_rate_limiter(auth);
    // TOTP-1 (TF-4) — the full named-account set. Legacy single-admin
    // YAMLs (top-level `password_hash_ref`/`totp_*`) fold into one
    // `admin` entry via `effective_accounts()`; the `accounts:` block
    // supplies N named admins, each with its own password hash, TOTP
    // state, and replay guard (per-principal counter monotonicity —
    // guards zero-init at boot, correct: tracking starts at the first
    // verify).
    // TOTP-3 (TF-1a) — runtime enrollment store on the SAME state
    // backend as admin sessions: Redis ⇒ fleet-wide (enroll on node A,
    // log in on node B) + restart-durable; in_memory ⇒ process-lifetime
    // only (YAML + CLI stay the durable bootstrap — see the storage
    // decision in plans/issues/FEAT-totp-google-authenticator-2026-07.md).
    let totp_store = Arc::new(
        aegis_control::admin_auth::totp_store::TotpEnrollmentStore::with_backend(
            state_backend.clone(),
        ),
    );
    // AM-P2a — runtime admin-account store on the same backend (fleet-wide +
    // durable). Overlaid by the login directory (create/reset/delete without
    // a YAML edit) and shared with the account-management API via
    // `DashboardServices`.
    let admin_account_store = Arc::new(
        aegis_control::admin_auth::account_store::AdminAccountStore::with_backend(
            state_backend.clone(),
        ),
    );
    let admin_directory = Arc::new(
        aegis_control::api::login::AdminDirectory::from_config(auth)
            .with_totp_store(Arc::clone(&totp_store))
            .with_account_store(Arc::clone(&admin_account_store)),
    );
    let session_idle_seconds = auth.session_ttl_idle.as_secs();

    // Leaderless roster (Phase 1) — build a shared `RosterView`
    // and start a background poller that rebuilds the flat peer
    // list from the `members:*` heartbeat keys. There is no
    // cluster leader: every node is equal, and singleton
    // side-tasks (ACME, GitOps) coordinate via their own per-task
    // leases below — not a global leader lease. The admin handler
    // reads this view synchronously when `/api/cluster` is fetched.
    let our_node_id = lease_store.self_id().as_str().to_string();
    let roster_view = Arc::new(
        aegis_control::api::tracking::RosterView::new(our_node_id),
    );

    // HA-T4 — membership heartbeat + roster poller.
    //
    // Each node publishes its identity by holding the lease
    // `members:<our_node_id>` (15s TTL, refreshed every
    // ~7.5s by the heartbeat layer). The roster poller below
    // enumerates `members:*` keys every 5s and feeds the result
    // into `RosterView::members`, which the admin handler then
    // serialises as `/api/cluster.peers[]`.
    {
        let lease_store_for_membership = Arc::clone(&lease_store);
        let our_node = lease_store.self_id();
        crate::cluster_lease::spawn_with_lease(
            lease_store_for_membership,
            // The `acquire` semantics work here because each
            // node uses its OWN node-id-suffixed key — no
            // contention.
            format!("members:{}", our_node.as_str()),
            std::time::Duration::from_secs(15),
            move |_holder, lost| async move {
                lost.notified().await;
            },
        );
    }
    {
        let store: Arc<dyn aegis_core::cluster::LeaseStore> =
            Arc::clone(&lease_store);
        let lv = Arc::clone(&roster_view);
        let cfg_version = env!("CARGO_PKG_VERSION").to_string();
        tokio::spawn(async move {
            let prefix = "members:".to_string();
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                match store.list_keys_with_prefix(&prefix).await {
                    Ok(keys) => {
                        let mut peers: Vec<aegis_control::api::tracking::ClusterPeer> =
                            Vec::with_capacity(keys.len());
                        for full in keys {
                            let id = full
                                .strip_prefix(&prefix)
                                .map(|s| s.to_string())
                                .unwrap_or(full);
                            // M008 (2026-05-07) — skip phantom
                            // entries from stale Redis state. A key
                            // shaped `g:lease:members:` (empty
                            // node id, e.g. left over from a crash
                            // with a no-TTL write) produces an
                            // empty id here. Surfacing it as a
                            // peer renders the dashboard's "DOWN
                            // peer with no node ID" mystery.
                            if id.trim().is_empty() {
                                continue;
                            }
                            peers.push(
                                aegis_control::api::tracking::ClusterPeer {
                                    id,
                                    addr: String::new(),
                                    version: cfg_version.clone(),
                                    last_heartbeat: chrono::Utc::now(),
                                    leases: Vec::new(),
                                },
                            );
                        }
                        // Sort by id so the dashboard ordering
                        // is stable across polls.
                        peers.sort_by(|a, b| a.id.cmp(&b.id));
                        lv.set_members(peers);
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "members poll failed");
                    }
                }
            }
        });
    }

    // Cluster Phase 2 (§2b) — cross-node fleet event fanout. Clones
    // the local bus for the publisher BEFORE `bus` is moved into the
    // services constructor below. `None` (single-node / cluster-off /
    // non-redis) keeps the SSE feed local-only.
    let fleet_event_bus = spawn_fleet_event_fanout(
        &cfg,
        &bus,
        lease_store.self_id().as_str(),
    );

    let (services, _drain) = aegis_control::dashboard_services::DashboardServices::spawn_with_mask_and_roster(
        bus,
        pool_provider,
        cfg.admin.environment.clone(),
        mask,
        risk,
        ip_rate_limiter,
        load_gauge,
        verbosity,
        auth_sessions,
        login_rate_limiter,
        admin_directory,
        session_idle_seconds,
        Some(Arc::clone(&roster_view)),
        Arc::clone(&tiers),
        Arc::clone(&rules),
        // 2026-06-24 (redis-interim-durability A0) — hand the resolved
        // state backend to the incidents (P1) / stats-counter (P3)
        // trackers so they can persist to `control:waf:*`. Gated on the
        // `redis` feature; `None` otherwise keeps the in-memory path. Inert
        // in A0 (no write-through yet) — activated by A1/A3.
        {
            #[cfg(feature = "redis")]
            {
                Some(Arc::clone(&state_backend))
            }
            #[cfg(not(feature = "redis"))]
            {
                None
            }
        },
    );
    // Hand the interop Runtime to the admin control plane via
    // `services.interop`. Same Arc that the data-plane
    // accept_loop already holds, so all surfaces see one shared
    // ModeStore + audit sink.
    let mut services = services;

    // FIX 2026-05-03 — share access-list stores between
    // DashboardServices (CRUD via /api/blacklist + /api/whitelist)
    // and ProxyContext (runtime matcher in the data-plane
    // handler). Before this commit they were distinct Arc
    // instances, so adds via the dashboard never reached the
    // data plane. Now they're the same Arc.
    services.blacklist = upstream_ctx.blacklist.clone();
    services.whitelist = upstream_ctx.whitelist.clone();
    services.interop = interop.clone();
    // Cluster Phase 2 — the dashboard SSE handler merges this in.
    services.fleet_event_bus = fleet_event_bus;
    // Cluster Phase 3 — fleet metrics snapshot publish/merge. Reads the
    // same local aggregators the dashboard does; the traffic GET
    // handlers serve the merged view when this cache is populated.
    let (fleet_cache, fleet_audit_cache) = spawn_fleet_snapshot_task(
        &cfg,
        state_backend.clone(),
        services.stats_agg.clone(),
        services.attacks_agg.clone(),
        services.risk.clone(),
        services.tracking.clone(),
        request_stage_hist.clone(),
        services.audit_ring.clone(),
        lease_store.self_id().as_str(),
        Some(Arc::clone(&roster_view)),
    );
    services.fleet_cache = fleet_cache;
    services.fleet_audit_cache = fleet_audit_cache;
    // N2 — config-plane nudge: write handlers publish `config:waf:bump`
    // on activate so peers (and this node) converge in ~ms, not a poll tick.
    services.config_nudge = config_nudge;
    // H2b — the selected config-plane backend for the write handlers.
    services.config_backend = Some(config_backend);
    // SC-1 — expose the data-plane response cache stats to GET /api/cache/stats
    // via a JSON-returning closure (keeps aegis-control free of aegis-proxy
    // types). Empty pools map until an upstream opts into `cache:`.
    {
        let cache = upstream_ctx.cache.clone();
        services.cache_stats = Some(std::sync::Arc::new(move || {
            serde_json::to_string(&serde_json::json!({ "pools": cache.stats() }))
                .unwrap_or_else(|_| "{\"pools\":[]}".to_string())
        }));
    }
    // 2026-05-19 — surface the source-of-truth YAML path so the
    // dashboard's Configuration Backup card can fetch it.
    services.config_yaml_path = config_yaml_path;

    // 2026-05-23/25/27 — seed per-tier settings from the `tiers:` config
    // block onto the `defaults_for`-seeded store before the data plane
    // shares it, so a profile's declared posture is live from the first
    // request. Goes through the same helper the config-plane watcher uses
    // (`apply_cfg_change_to_tiers`) so boot + hot-reload stay identical:
    // risk_threshold + challenges_enabled + the richer block_threshold /
    // cumulative_* / pipeline fields. Tiers omitted from config keep their
    // code default.
    let _ = crate::config_source::reload::apply_cfg_change_to_tiers(
        &cfg,
        Some(&services.tiers),
    );

    // 2026-05-10 — share the TierStore between DashboardServices
    // (PUT /api/tiers/{name}) and ProxyContext (data plane reads
    // per-tier challenge/block thresholds + challenges_enabled
    // for Option B). Single Arc so dashboard edits become live in
    // the data plane on the next request, no restart.
    let _ = upstream_ctx.tiers.set(services.tiers.clone());

    // 2026-05-05 — late-register the AttacksAggregator's reset
    // cleaner with the v2.3 control plane. The aggregator backs the
    // dashboard's Top Attackers / By-Detector / Bot Mix charts; per
    // §2.4 it counts as "temporary client/session metadata" and
    // MUST be cleared on `POST /__waf_control/reset_state`. Done
    // here (not at build_interop_runtime time) because services
    // doesn't exist yet when the runtime is constructed.
    if let Some(rt) = interop.as_ref() {
        // AU-1 — give the control plane the audit bus so
        // `reset_state` leaves an Admin-class trail BEFORE it wipes.
        rt.control.set_audit_bus(services.bus.clone());

        let agg_for_reset = services.attacks_agg.clone();
        rt.control.register_reset_callback(std::sync::Arc::new(move || {
            agg_for_reset.reset();
        }));

        // 2026-06-24 (redis-interim-durability P1, A1) — incidents are now
        // durable, so `reset_state` must clear BOTH the in-memory overlay
        // (sync) and the durable `control:waf:incidents` hash (async UNLINK),
        // or a reset would leave the operator overlay to resurrect on the
        // next boot (durability plan §4). The async-half is a no-op without
        // a backend, matching the StateBackend ephemeral wipe pattern.
        let incidents_local_reset = services.incidents.clone();
        rt.control.register_reset_callback(std::sync::Arc::new(move || {
            incidents_local_reset.clear_local();
        }));
        let incidents_durable_reset = services.incidents.clone();
        rt.control
            .register_async_reset_callback(std::sync::Arc::new(move || {
                let incidents = incidents_durable_reset.clone();
                Box::pin(async move {
                    incidents.unlink_durable().await;
                })
            }));

        // 2026-06-24 (redis-interim-durability P3, A3) — lifetime stats
        // counters (blocks_total, …) are now durable per-node, so
        // `reset_state` must zero the in-memory counters (sync) AND drop this
        // node's durable field (async HDEL). Mirrors the incidents pattern.
        let stats_local_reset = services.stats_agg.clone();
        rt.control.register_reset_callback(std::sync::Arc::new(move || {
            stats_local_reset.reset_counters();
        }));
        let stats_durable_reset = services.stats_agg.clone();
        let stats_reset_node = lease_store.self_id().as_str().to_string();
        rt.control
            .register_async_reset_callback(std::sync::Arc::new(move || {
                let stats = stats_durable_reset.clone();
                let node = stats_reset_node.clone();
                Box::pin(async move {
                    stats.forget_durable(&node).await;
                })
            }));
    }

    // 2026-06-24 (redis-interim-durability P1, A1) — hydrate the durable
    // incident overlay into the in-memory read cache before serving so an
    // ack/snooze/resolve survives a restart. No-op without a durable backend
    // (single-node / no-Redis). The overlay is tiny (per-admin-action), so a
    // brief await at boot is acceptable — unlike the large risk hash (A2),
    // which hydrates in the background.
    services.incidents.hydrate().await;

    // IF-P1c — periodic cross-node overlay convergence. Re-read the shared
    // `control:waf:incidents` overlay on a timer so an ack/snooze/resolve on
    // ANY node lands here within a tick (LWW on `updated_at`, clobber-safe).
    // Only when a shared backend is attached; single-node / no-Redis skips.
    if services.incidents.has_durable_backend() {
        let incidents = services.incidents.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                incidents.refresh_from_durable().await;
            }
        });
    }

    // 2026-06-24 (redis-interim-durability P3, A3) — spawn the per-node stats
    // counter durability: a background boot-hydrate (so the Overview top-line
    // survives a restart) + a periodic flush. Off the request path entirely;
    // no-op without a durable backend.
    // Detached on purpose (fire-and-forget) — `let _` makes that explicit.
    let _ = services
        .stats_agg
        .spawn_persistence(lease_store.self_id().as_str().to_string());

    // CI-T5 — seed `services.routes` from `cfg.routes` as the
    // boot-time fallback for /api/routes. Route hot-reload HAS
    // landed since this seam was written: the GET handler prefers
    // `route_writer.current_routes()` (live, reload-aware,
    // admin_get.rs) and only falls back to this static seed when
    // no writer is wired.
    // PR1: priority is computed from the same routes the trie
    // sees, so dashboard ordering matches resolution.
    services
        .routes
        .set(crate::route::route_summaries(&cfg.routes));

    // CI-T4 / SLO-P4 — the SLO engine now arrives from `run()`
    // (built from `cfg.slo` or the compiled defaults) so the
    // config-plane watcher can hot-swap objectives. It is fed by
    // the audit-bus drain task spawned below so /api/slo +
    // /api/alerts return live data.
    services.tracking.set_slo_engine(Arc::clone(&slo_engine));

    // CI-T4 — wire the cert inventory provider. Reads PEM files
    // referenced by `cfg.tls.certificates` on every /api/certs
    // call — cheap (small files, parsed off the hot path) and
    // reflects hot-reloads automatically.
    // SLO-P5 — the SLO loop's hourly cert sweep shares the same
    // provider (None when no TLS certs are configured).
    let mut cert_provider_for_alerts: Option<
        aegis_control::api::tracking::CertInventoryProvider,
    > = None;
    if let Some(tls) = cfg.tls.as_ref() {
        let certs_cfg: Vec<aegis_core::config::CertConfig> = tls.certificates.clone();
        let provider: aegis_control::api::tracking::CertInventoryProvider =
            Arc::new(move || {
                let mut out = Vec::new();
                for c in &certs_cfg {
                    if let Some(entry) = read_cert_inventory(c) {
                        out.push(entry);
                    }
                }
                out
            });
        cert_provider_for_alerts = Some(provider.clone());
        services.tracking.set_cert_provider(provider);
    }

    // CI-T8 — wire a GeoIP reader into the AttacksHandler so
    // /api/attacks/top rows carry country + ASN. Behind a feature
    // flag because the MaxMind DB reader pulls in `maxminddb` as
    // a dependency. Without the feature, the trait is still
    // available but no enrichment happens.
    #[cfg(feature = "geoip")]
    {
        let country = cfg.geoip.country_db.clone();
        let asn = cfg.geoip.asn_db.clone();
        if country.is_some() || asn.is_some() {
            match aegis_security::geoip::MaxMindReader::open(
                country.as_deref(),
                asn.as_deref(),
            ) {
                Ok(reader) => {
                    let reader_arc: Arc<dyn aegis_security::geoip::GeoIpLookup> =
                        Arc::new(reader);
                    services.attacks.set_geo_lookup(reader_arc.clone());
                    // 2026-05-18 (QC follow-up TLS-wiring batch —
                    // F-CRITICAL-015 activation): share the reader
                    // with the data plane so `BotSignals` can
                    // populate `asn` + `asn_classification` from
                    // the live MaxMind DB. `set` returns Err if
                    // somehow already installed — log + ignore.
                    if upstream_ctx
                        .geoip
                        .set(reader_arc.clone())
                        .is_err()
                    {
                        tracing::debug!(
                            "geoip reader already installed on ProxyContext; \
                             skipping duplicate",
                        );
                    }
                    // FIX 2026-05-03 — wrap the reader in an
                    // AccessListCountryLookup adapter so the
                    // runtime matcher resolves `kind: country`
                    // entries against the same .mmdb. Without
                    // this, country entries silently miss.
                    struct GeoIpToAccessListAdapter(
                        Arc<dyn aegis_security::geoip::GeoIpLookup>,
                    );
                    impl aegis_control::api::blacklist::AccessListCountryLookup
                        for GeoIpToAccessListAdapter
                    {
                        fn country_of(
                            &self,
                            peer: std::net::IpAddr,
                        ) -> Option<String> {
                            self.0.country(peer)
                        }
                        // AC-P2-c (2026-07-03) — forward ASN so `kind: asn`
                        // access-list entries resolve against the same reader.
                        fn asn_of(
                            &self,
                            peer: std::net::IpAddr,
                        ) -> Option<u32> {
                            self.0.asn(peer)
                        }
                    }
                    let adapter: Arc<dyn aegis_control::api::blacklist::AccessListCountryLookup> =
                        Arc::new(GeoIpToAccessListAdapter(reader_arc));
                    if upstream_ctx
                        .access_list_country_lookup
                        .set(adapter)
                        .is_err()
                    {
                        tracing::debug!(
                            "access-list country lookup already set; \
                             skipping duplicate install",
                        );
                    }
                    tracing::info!(
                        country = ?cfg.geoip.country_db,
                        asn = ?cfg.geoip.asn_db,
                        "geoip reader wired into AttacksHandler + access-list matcher",
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "failed to open MaxMind DBs; /api/attacks/top will not carry geo",
                    );
                }
            }
        }
    }

    // CC-T2.1 — wire the alert-receivers handler. A shared
    // ArcSwap'd receiver list backs both the SLO dispatch task
    // (further below) and the GET `/api/alert-receivers` handler.
    // CC-T2.1.b adds the audit-mutated PUT/DELETE/POST-test
    // handlers; N1 (2026-06-11) routes those through the config
    // doc so a receiver edit propagates fleet-wide. The ArcSwap is
    // created in `run()` (seeded from `cfg.alerting` or env) and shared
    // with the config-plane watcher, which re-derives it on each swap.
    let dispatch_ring =
        aegis_control::api::alert_receivers::DispatchOutcomeRing::new();
    {
        let provider_share = Arc::clone(&shared_receivers);
        let handler = aegis_control::api::alert_receivers::AlertReceiversHandler::new(
            move || (**provider_share.load()).clone(),
            dispatch_ring.clone(),
        );
        services.alert_receivers = Some(Arc::new(handler));
        services.alert_receivers_store = Some(Arc::clone(&shared_receivers));
        services.alert_receivers_ring = Some(dispatch_ring.clone());
    }

    // CC-T1.1.b — share the proxy's PoolRegistry through the
    // typed-erased UpstreamWriter trait so the audit-mutated
    // /api/upstreams/config PUT/DELETE handlers can hot-swap the
    // pool table without bouncing the proxy. `upstream_writer`
    // arrived as a parameter (wired by `run()` from
    // `upstream_ctx.pools.clone()`) so the data plane and the
    // control plane share the same `Arc<PoolRegistry>`. A
    // successful PUT is visible to new requests immediately
    // while in-flight requests finish on their already-grabbed
    // Arc<Pool>.
    services.upstream_writer = Some(upstream_writer);
    services.route_writer = Some(route_writer);
    if let Some(toggle) = ai_toggle {
        services.ai_toggle = Some(
            toggle as Arc<dyn aegis_control::api::ai_toggle::AiToggleWriter>,
        );
    }
    // 2026-05-29 — same coercion shape as `ai_toggle`: the
    // `Arc<AtomicU32>` returned by `AiDetector::runtime_threshold()`
    // coerces to `Arc<dyn AiThresholdWriter>` because the writer
    // trait is implemented on the bare `AtomicU32`. The
    // `ai_threshold_default` (cfg value) is always surfaced even
    // when the writer is `None`, so the dashboard can render a
    // sensible value before the operator changes anything.
    services.ai_threshold_default = ai_threshold_default;
    if let Some(holder) = ai_threshold {
        services.ai_threshold = Some(
            holder as Arc<dyn aegis_control::api::ai_threshold::AiThresholdWriter>,
        );
    }
    // Already an `Arc<dyn AiReloadWriter>` (the concrete reloader is built in
    // run.rs where the aegis-security model handle is in scope), so just stash.
    services.ai_reload = ai_model_reloader;
    // 2026-05-11 PR #7 — surface the live `Pipeline` as the
    // response-filter writer so `PUT /api/response-filter` can
    // 2026-05-17 F-CRITICAL-001 (control audit): share the Pipeline's
    // live `Arc<RuleSet>` with both `DashboardServices` (so admin
    // CRUD can hot-swap rules) AND `ProxyContext.active_ruleset` (so
    // the data plane reads the live set on every request). All three
    // surfaces — Pipeline, DashboardServices, ProxyContext — now
    // point at the same `Arc<RuleSet>`, whose internal `ArcSwap`
    // gives lock-free hot-swap semantics. Pre-fix the dashboard
    // wrote to a separate `RuleStore` while the engine read an empty
    // `RuleSet::new()` from boot — "Save rule" was a no-op. Done
    // BEFORE the `response_filter_writer` move below because that
    // coerces `response_filter_pipeline` into `Arc<dyn ...>` and
    // loses the concrete `Pipeline` type.
    let live_ruleset = response_filter_pipeline.rules_arc();
    services.active_ruleset = Some(Arc::clone(&live_ruleset));
    let _ = upstream_ctx.active_ruleset.set(live_ruleset);

    // hot-swap `ResponseFilterConfig` rungs. Same Arc instance the
    // data plane reads `on_body_frame` through.
    services.response_filter_writer = Some(
        response_filter_pipeline
            as Arc<dyn aegis_control::api::response_filter::ResponseFilterWriter>,
    );

    // MTLS-T6 — wire the IdentityTracker so the read-only
    // /api/mtls/* endpoints have a live data source. MTLS-T3
    // populates `record_request` from the data-plane accept
    // loop; here we only load the CA bundle summary so
    // `/api/mtls/ca-summary` lights up immediately at boot.
    if let Some(ca_path) = cfg
        .zero_trust
        .as_ref()
        .and_then(|z| z.downstream.as_ref())
        .and_then(|ca| ca.ca_bundle.as_ref())
    {
        match aegis_control::identity_tracker::parse_ca_bundle(ca_path) {
            Ok(summary) => {
                tracing::info!(
                    bundle_path = %ca_path.display(),
                    cert_count = summary.certificates.len(),
                    "mtls ca bundle loaded for /api/mtls/ca-summary",
                );
                identity_tracker.set_ca_summary(Some(summary));
            }
            Err(e) => {
                tracing::warn!(
                    bundle_path = %ca_path.display(),
                    error = %e,
                    "mtls ca bundle parse failed; /api/mtls/ca-summary will return empty",
                );
            }
        }
    }
    services.identity_tracker = Some(identity_tracker);
    // MTLS-T8 — seed the runtime mode store with the configured
    // `cfg.tls.client_auth.mode` so `/api/mtls/mode` can render
    // the configured / override / effective triple correctly.
    {
        let configured_mode = cfg
            .zero_trust
            .as_ref()
            .and_then(|z| z.downstream.as_ref())
            .map(|ca| ca.mode)
            .unwrap_or(aegis_core::config::DownstreamMtlsMode::Disabled);
        services.mtls_mode_store = Arc::new(
            aegis_control::api::zero_trust::mode::DownstreamMtlsModeStore::with_configured(configured_mode),
        );
    }
    // MTLS-T10 — surface the operator's opt-in for the CA bundle
    // upload card. Default off; flip via
    // `cfg.admin.dashboard_auth.allow_ca_upload: true`.
    services.allow_ca_upload = cfg.admin.dashboard_auth.allow_ca_upload;
    // TOTP-3 — swap the default in-memory enrollment store for the
    // backend-wired one built above (same instance the login directory
    // overlays), so /api/admin/totp/enroll|confirm and authenticate()
    // read/write identical state.
    services.totp_store = Arc::clone(&totp_store);
    // AM-P2a — same story for the runtime account store: the account-mgmt
    // API mutates it through `services`, and the login directory overlays
    // the same instance, so create/reset/delete converge with authenticate().
    services.admin_account_store = Arc::clone(&admin_account_store);
    // MTLS-T10 Phase 2 — share the live trust store as a type-erased
    // writer so the audit-mutated PUT handler can hot-swap roots.
    services.trust_anchor_writer = client_trust
        .clone()
        .map(|store| -> Arc<dyn aegis_control::api::zero_trust::ca_bundle::TrustAnchorWriter> {
            Arc::new(store)
        });
    // SC-T1 — wire the live `StateBackend` so `/api/state` can
    // call `health()`. The handle is the same metered backend
    // every other consumer reads, so the dashboard sees the same
    // round-trip latency the data plane does.
    services.state_backend = Some(state_backend);
    // Phase-1 analytics — share the per-stage duration histogram
    // so `/api/analytics/latency` can compute p50/p95/p99 from
    // the same series the data plane records.
    services.request_stage_hist = Some(request_stage_hist.clone());
    services.route_latency_hist = Some(route_latency_hist.clone());
    services.route_activity = Some(route_activity.clone());
    services.detector_latency_hist = Some(detector_latency_hist.clone());

    // 2026-05-27 (Phase C) — when a shared state backend is wired, spawn
    // the per-counter-class flush tasks that mirror the local rings into
    // cluster-wide `INCRBY` counters + refresh the aggregate caches the
    // dashboard endpoints serve. On `in_memory` single-node the local
    // rings already are the whole truth, so we skip the machinery.
    if cfg.state.backend != aegis_core::config::StateBackendKind::InMemory {
        if let Some(state) = services.state_backend.clone() {
            use aegis_control::metrics::window_flush::{
                spawn_flush_task, AggregateCache, BucketSource,
            };
            const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
            // P5 route activity — 60 s window, TTL 2× window.
            let ra_cache = AggregateCache::new();
            services.route_activity_cache = Some(ra_cache.clone());
            std::mem::drop(spawn_flush_task(
                Arc::new(route_activity.clone()) as Arc<dyn BucketSource>,
                state.clone(),
                services.bus.clone(),
                ra_cache,
                "waf:route".into(),
                std::time::Duration::from_secs(120),
                FLUSH_INTERVAL,
            ));
            // P4 access-list hits — 24 h window, TTL 48 h.
            let hit_ttl = std::time::Duration::from_secs(86_400 * 2);
            let bl_cache = AggregateCache::new();
            services.blacklist_hits_cache = Some(bl_cache.clone());
            std::mem::drop(spawn_flush_task(
                services.blacklist.clone() as Arc<dyn BucketSource>,
                state.clone(),
                services.bus.clone(),
                bl_cache,
                "waf:hits:bl".into(),
                hit_ttl,
                FLUSH_INTERVAL,
            ));
            let wl_cache = AggregateCache::new();
            services.whitelist_hits_cache = Some(wl_cache.clone());
            std::mem::drop(spawn_flush_task(
                services.whitelist.clone() as Arc<dyn BucketSource>,
                state,
                services.bus.clone(),
                wl_cache,
                "waf:hits:wl".into(),
                hit_ttl,
                FLUSH_INTERVAL,
            ));
            tracing::info!(
                "Phase C: spawned cluster metrics flush tasks (route-activity + access-list hits)",
            );
        }
    }
    // HACK-T3 — wire the same detector list the data plane
    // runs so `/api/rules/simulate` can evaluate against an
    // identical chain.
    services.detectors = Some(detectors);
    // 2026-05-20 — share the live canary path handle so
    // `PUT /api/risk/canary-paths` mutates the same set the
    // data-plane CanaryDetector reads.
    services.canary_paths = canary_paths;
    // 2026-05-21 — share the bot-classifier gate toggle so
    // `PUT /api/gates/bots` flips the same flag the data-plane
    // listener reads from `ProxyContext.bots_enabled`.
    services.bots_enabled = upstream_ctx.bots_enabled.clone();
    services.load_shed_enabled = upstream_ctx.load_shed_enabled.clone();
    // EG-2 observe gate — share the data plane's atomic so PUT
    // /api/gates/egress hot-flips the live observe rung.
    services.egress_observe_enabled = upstream_ctx.egress_observe_enabled.clone();
    // MTLS-T7 — Allowed SAN allowlist. Seeded from
    // `cfg.tls.client_auth.allowed_sans` (empty when client-auth
    // is disabled or no SANs were configured). The store is hot-
    // reloadable: dashboard PUT/DELETE handlers call
    // `store.store(..)` / `store.remove(..)` to rotate it without
    // a restart, and the listener identity extractor consults it
    // through `extract_identity_with_allowlist`.
    {
        let initial: Vec<String> = cfg
            .zero_trust
            .as_ref()
            .and_then(|z| z.downstream.as_ref())
            .map(|ca| ca.allowed_sans.clone())
            .unwrap_or_default();
        services.allowed_sans = Some(
            aegis_control::api::zero_trust::downstream::AllowedSansStore::from(initial),
        );
    }

    // 2026-05-09 — share the DDoS runtime (already installed on
    // ProxyContext at boot in `run.rs`) with the dashboard so
    // `/api/gates/ddos` can read live telemetry. `OnceLock::get`
    // returns `None` until the proxy boot path has installed it
    // and `ProxyContext::ddos.set(...)` has been called; the
    // dashboard renders an empty-state card in that case.
    services.ddos = upstream_ctx.ddos.get().cloned();
    // SLO-P6 (P4b) — share the watchdog knob with /api/slo/config.
    services.slo_absent_after = Some(Arc::clone(&slo_absent_after_secs));

    // DURABLE-T1 — audit chain durability. For each Jsonl sink the
    // operator configured under `cfg.audit.sinks`, open a real
    // file-backed `JsonlSink` and spawn (1) a persist task that
    // subscribes to the audit bus and batches events to disk with
    // daily rotation, and (2) a TTL task that prunes files older
    // than `retention_days` once an hour. Both run on background
    // tokio tasks — the data-plane hot path stays untouched.
    {
        use aegis_core::config::AuditSinkConfig;
        use aegis_control::audit::sinks::jsonl::{
            run_persist_task, run_ttl_task, JsonlConfig, JsonlSink,
        };

        let mut jsonl_sinks: Vec<Arc<JsonlSink>> = Vec::new();
        let mut max_batch_global = 100usize;
        let mut flush_interval_global = std::time::Duration::from_secs(1);
        for entry in &cfg.audit.sinks {
            if let AuditSinkConfig::Jsonl {
                path,
                retention_days,
                max_batch,
                flush_interval,
            } = entry
            {
                let cfg_jsonl = JsonlConfig {
                    path: path.clone(),
                    retention_days: *retention_days,
                    max_batch: *max_batch,
                    flush_interval: *flush_interval,
                };
                match JsonlSink::open(cfg_jsonl).await {
                    Ok(sink) => {
                        jsonl_sinks.push(Arc::new(sink));
                        max_batch_global = max_batch_global.min(*max_batch).max(1);
                        flush_interval_global =
                            flush_interval_global.min(*flush_interval);
                    }
                    Err(e) => {
                        tracing::error!(
                            path = %path.display(),
                            error = %e,
                            "audit jsonl sink open failed; durability disabled for this sink",
                        );
                    }
                }
            }
        }
        if !jsonl_sinks.is_empty() {
            tracing::info!(
                sinks = jsonl_sinks.len(),
                max_batch = max_batch_global,
                flush_interval_ms = flush_interval_global.as_millis() as u64,
                "audit jsonl persistence wired",
            );
            let sinks_for_persist = jsonl_sinks.clone();
            let bus_for_persist = services.bus.clone();
            tokio::spawn(async move {
                run_persist_task(
                    bus_for_persist,
                    sinks_for_persist,
                    max_batch_global,
                    flush_interval_global,
                ).await;
            });
            // TTL prune every hour. The work is cheap (one stat per
            // file) and operators don't want disk to creep.
            let sinks_for_ttl = jsonl_sinks;
            tokio::spawn(async move {
                run_ttl_task(
                    sinks_for_ttl,
                    std::time::Duration::from_secs(3600),
                ).await;
            });
        }
    }

    // HACK-T5 — Tier-C bonus: stream the audit bus to a remote
    // syslog / CEF receiver. Each `AuditSinkConfig::Syslog`
    // entry spawns a dedicated forwarder task. Failures (UDP
    // send error, TCP reconnect) log + drop from this sink
    // only — JSONL persistence is unaffected.
    {
        use aegis_core::config::AuditSinkConfig;
        use aegis_control::audit::sinks::syslog::{
            run_forward_task, SyslogConfig, SyslogSink,
        };

        for entry in &cfg.audit.sinks {
            if let AuditSinkConfig::Syslog {
                address,
                transport,
                format,
                facility,
                app_name,
                ca_bundle,
                server_name,
            } = entry
            {
                let cfg_syslog = SyslogConfig {
                    address: address.clone(),
                    transport: *transport,
                    format: *format,
                    facility: *facility,
                    app_name: app_name.clone(),
                    ca_bundle: ca_bundle.clone(),
                    server_name: server_name.clone(),
                };
                match SyslogSink::connect(cfg_syslog.clone()).await {
                    Ok(sink) => {
                        tracing::info!(
                            address = %address,
                            transport = ?transport,
                            format = ?format,
                            "audit syslog forwarder wired",
                        );
                        let sink_arc = Arc::new(sink);
                        let bus = services.bus.clone();
                        tokio::spawn(async move {
                            run_forward_task(bus, sink_arc).await;
                        });
                    }
                    Err(e) => {
                        tracing::error!(
                            address = %address,
                            error = %e,
                            "audit syslog forwarder connect failed; sink disabled",
                        );
                    }
                }
            }
        }
    }

    let services = Arc::new(services);

    // CI-T4 / SLO-P1 — drive the SLO engine from the audit bus.
    // Availability now counts only *service* outcomes
    // (`slo::classify`): `allow` is good unless the forwarded
    // origin status was 5xx (`fields.status`); `timeout` /
    // `circuit_breaker` are bad. Security enforcement (`block` /
    // `challenge` / `rate_limit`) is EXCLUDED — the WAF doing its
    // job is not an outage — and lands on the enforcement counter
    // instead. Admin/system events are ignored (pre-P1 both they
    // and enforcement recorded 0.0 availability samples, so a
    // blocked attack wave drained the budget and could page).
    // The old per-event 1.0 AuditDeliveryRate sample is gone with
    // its tautological objective.
    {
        use aegis_control::slo::classify::{classify_event, SliClass};
        let engine = Arc::clone(&slo_engine);
        let mut rx = services.bus.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => match classify_event(&ev) {
                        Some(class @ (SliClass::Good | SliClass::Bad)) => {
                            engine.record(aegis_control::slo::SliSample {
                                kind: aegis_control::slo::SliKind::DataPlaneAvailability,
                                value: if class == SliClass::Good { 1.0 } else { 0.0 },
                                ts: ev.ts,
                            });
                        }
                        Some(SliClass::Enforcement) => engine.record_enforcement(ev.ts),
                        None => {}
                    },
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
        });
    }

    // CI-T7 — periodic SLO evaluation + alert dispatch. Calls
    // `engine.evaluate()` every 30 s; every newly-fired alert is
    // piped through `slo::dispatch::send_alert(...)` which (with
    // `aegis-control/alerts` on) delivers to VipTalk. Without the
    // feature flag, dispatch logs the alert and counts it as
    // "external" (operator-side delivery). The dispatch outcome is
    // recorded in `dispatch_ring` so /api/alert-receivers shows
    // last-delivery state per receiver.
    {
        let engine = Arc::clone(&slo_engine);
        let shared = Arc::clone(&shared_receivers);
        let ring = dispatch_ring.clone();
        let slo_absent_after = Arc::clone(&slo_absent_after_secs);
        let ddos = services.ddos.clone();
        let cert_provider = cert_provider_for_alerts.clone();
        let mut alert_rx = alert_rx;
        tokio::spawn(async move {
            // 2026-05-20 alerts refactor — a process-lifetime dedup
            // cache so a multi-tick burn-rate breach in the same
            // window fires VipTalk once (with a `(+N suppressed)`
            // note on the next emission) instead of every 30 s.
            let dedup = aegis_control::slo::AlertDedupCache::default_window();
            let mut absent_slis: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            // SLO-P5 — producer state owned by this loop.
            let mut cert_state =
                aegis_control::slo::producers::CertAlertState::default();
            let mut ddos_active_since: Option<chrono::DateTime<chrono::Utc>> = None;
            // Cert expiry moves daily; sweep hourly (120 × 30s
            // ticks), starting with the first tick so an
            // already-critical cert alerts ~30s after boot.
            const CERT_SWEEP_EVERY_TICKS: u64 = 120;
            let mut tick_count: u64 = 0;
            let mut tick =
                tokio::time::interval(std::time::Duration::from_secs(30));
            tick.tick().await; // skip the immediate first tick
            loop {
                // SLO-P5 — external producers (pool health,
                // hot-reload failures) land between ticks and
                // dispatch immediately through the same
                // dedup/receivers/outcome-ring path.
                // (`Some(ev) = recv()` disables the branch when the
                // channel is closed, degrading to a tick-only loop.)
                let channel_event = tokio::select! {
                    Some(ev) = alert_rx.recv() => Some(ev),
                    _ = tick.tick() => None,
                };
                if let Some(event) = channel_event {
                    let receivers = (**shared.load()).clone();
                    dispatch_and_record(&event, &receivers, &dedup, &ring).await;
                    continue;
                }
                let new_alerts = engine.evaluate();

                // SLO-P3 — telemetry-absent watchdog. Burn-rate
                // alerts cannot see a total blackout (no samples
                // → no evaluation; the engine deliberately keeps
                // a fired alert active through silence), so every
                // objective SLI that served traffic and then went
                // silent raises its own Ticket. Fires once per
                // SLI transition; recovery is logged. SLO-P4: the
                // threshold comes from `cfg.slo.telemetry_absent_
                // after_secs` (hot-swapped by the config watcher);
                // 0 disables the watchdog.
                let absent_after_secs = slo_absent_after
                    .load(std::sync::atomic::Ordering::Relaxed);
                let now_utc = chrono::Utc::now();
                let now_absent: std::collections::HashSet<String> = if absent_after_secs == 0 {
                    std::collections::HashSet::new()
                } else {
                    engine
                        .telemetry_absent_slis(
                            chrono::Duration::seconds(absent_after_secs as i64),
                            now_utc,
                        )
                        .into_iter()
                        .map(|kind| format!("{kind:?}"))
                        .collect()
                };
                for sli in absent_slis.difference(&now_absent) {
                    tracing::info!(
                        sli = %sli,
                        "telemetry-absent watchdog: samples resumed",
                    );
                }
                let watchdog_events: Vec<aegis_control::slo::AlertEvent> =
                    now_absent
                        .difference(&absent_slis)
                        .map(|sli| {
                            aegis_control::slo::AlertEvent::TelemetryAbsent {
                                fired_at: now_utc,
                                sli: sli.clone(),
                                silent_seconds: absent_after_secs,
                            }
                        })
                        .collect();
                absent_slis = now_absent;
                let mut producer_events = watchdog_events;

                // SLO-P5 — DDoS spike-gate transitions, polled per
                // tick like the watchdog (the auto-trigger flips
                // state inside aegis-security; this loop is the
                // alert-facing observer).
                if let Some(d) = ddos.as_ref() {
                    let active = d.is_spike_active();
                    match (active, ddos_active_since) {
                        (true, None) => {
                            ddos_active_since = Some(now_utc);
                            producer_events.push(
                                aegis_control::slo::AlertEvent::DdosModeEntered {
                                    fired_at: now_utc,
                                    trigger: format!(
                                        "rps spike: {} rps (baseline {})",
                                        d.current_rps(),
                                        d.baseline_rps(),
                                    ),
                                    observed_rps: d.current_rps().min(u32::MAX as u64)
                                        as u32,
                                },
                            );
                        }
                        (false, Some(since)) => {
                            ddos_active_since = None;
                            producer_events.push(
                                aegis_control::slo::AlertEvent::DdosModeCleared {
                                    fired_at: now_utc,
                                    duration_seconds: (now_utc - since)
                                        .num_seconds()
                                        .max(0)
                                        as u64,
                                },
                            );
                        }
                        _ => {}
                    }
                }

                // SLO-P5 — hourly cert-expiry sweep; band
                // transitions alert once per band per host
                // (Warning=Ticket <30d, Critical=Page <7d).
                if tick_count % CERT_SWEEP_EVERY_TICKS == 0 {
                    if let Some(provider) = cert_provider.as_ref() {
                        let observations: Vec<
                            aegis_control::slo::producers::CertObservation,
                        > = provider()
                            .into_iter()
                            .map(|e| {
                                let days =
                                    (e.expires_at - now_utc).num_days().max(0) as u32;
                                aegis_control::slo::producers::CertObservation {
                                    host: e.host,
                                    days_remaining: days,
                                    not_after: e.expires_at,
                                }
                            })
                            .collect();
                        producer_events.extend(cert_state.observe(&observations, now_utc));
                    }
                }
                tick_count += 1;

                if new_alerts.is_empty() && producer_events.is_empty() {
                    continue;
                }
                let receivers = (**shared.load()).clone();
                for event in &producer_events {
                    dispatch_and_record(event, &receivers, &dedup, &ring).await;
                }
                for alert in &new_alerts {
                    let event =
                        aegis_control::slo::AlertEvent::Slo(alert.clone());
                    dispatch_and_record(&event, &receivers, &dedup, &ring).await;
                    tracing::info!(
                        sli = ?alert.sli,
                        severity = ?alert.severity,
                        burn_rate = alert.burn_rate,
                        "slo alert dispatched",
                    );
                }
            }
        });
    }

    // Copilot P4 — scheduled situational briefing. Off unless the copilot
    // is enabled AND the briefing cadence is > 0. The cadence comes from
    // `observability.copilot.briefing_interval_secs` (centralized config);
    // the legacy `LLM_BRIEFING_INTERVAL_SECS` env var is honored only as a
    // fallback when the config value is 0 (back-compat). Every interval it
    // builds a telemetry snapshot, asks the copilot for a brief, and pushes
    // it into the alerts pipeline as an `OperatorBriefing` (Info) event so
    // it lands in the operator's chat next to SLO / DDoS alerts. Dispatched
    // WITHOUT the dedup cache — each scheduled brief is distinct content.
    {
        let interval_secs = if cfg.observability.copilot.briefing_interval_secs > 0 {
            cfg.observability.copilot.briefing_interval_secs
        } else {
            std::env::var("LLM_BRIEFING_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
        };
        if interval_secs > 0 && aegis_control::copilot::service::global().enabled() {
            // Floor at 60s — briefings are billable LLM calls.
            let period = std::time::Duration::from_secs(interval_secs.max(60));
            let services = services.clone();
            let shared = Arc::clone(&shared_receivers);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(period);
                tick.tick().await; // skip the immediate first tick
                loop {
                    tick.tick().await;
                    let snapshot = crate::admin_get::build_copilot_snapshot(&services, 60);
                    match aegis_control::copilot::service::global().summary(snapshot).await {
                        Ok(brief) => {
                            let event = aegis_control::slo::AlertEvent::OperatorBriefing {
                                fired_at: chrono::Utc::now(),
                                body: brief.text,
                            };
                            let receivers = (**shared.load()).clone();
                            let _ = aegis_control::slo::dispatch::dispatch_event(
                                &event, &receivers, None,
                            )
                            .await;
                            tracing::info!("copilot briefing dispatched");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "copilot briefing generation failed");
                        }
                    }
                }
            });
            tracing::info!(interval_secs, "copilot briefing scheduler started");
        }
    }

    loop {
        let (stream, peer) = match tcp.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("admin accept error: {e}");
                continue;
            }
        };

        let cfg = cfg.clone();
        let readiness = readiness.clone();
        let startup = startup.clone();
        let metrics = metrics.clone();
        let services = services.clone();
        let conn_inflight = inflight.clone();
        let conn_tls_acceptor = admin_tls_acceptor.clone();

        tokio::spawn(async move {
            // FDP-T4 — admit one in-flight slot for this admin
            // connection. Guard drops when the spawned task
            // ends (clean close OR panic); drain reads the
            // counter to know when in-flight=0.
            let _admit = conn_inflight.admit();
            // Optional TLS handshake — when admin_tls is
            // configured, complete the rustls handshake before
            // the HTTP service runs. Plain-HTTP path is the
            // legacy default for dev setups.
            enum AdminIo {
                Plain(tokio::net::TcpStream),
                Tls(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
            }
            let io = match conn_tls_acceptor.as_ref() {
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(tls_stream) => AdminIo::Tls(tls_stream),
                    Err(e) => {
                        tracing::debug!(
                            error = %e,
                            "admin TLS handshake failed from {peer}",
                        );
                        return;
                    }
                },
                None => AdminIo::Plain(stream),
            };
            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let cfg = cfg.clone();
                let readiness = readiness.clone();
                let startup = startup.clone();
                let metrics = metrics.clone();
                let services = services.clone();
                async move {
                    // B4-T4: streaming SSE branches before the
                    // buffered admin pipeline. Everything else
                    // returns `Full<Bytes>` and is boxed into
                    // the unified streaming body type.
                    if req.method() == hyper::Method::GET
                        && req.uri().path() == "/dashboard/sse"
                    {
                        let query = req.uri().query().unwrap_or("").to_string();
                        // P1 (2026-07-02) — this node's roster identity
                        // lets a `?node=` scope match local events
                        // (which carry no origin_node stamp). None on
                        // single-node deployments.
                        let self_node = services
                            .roster_view
                            .as_ref()
                            .map(|r| r.our_node.clone());
                        return Ok::<_, Infallible>(admin_sse::sse_response(
                            &services.bus,
                            services.fleet_event_bus.as_ref(),
                            &query,
                            self_node,
                        ));
                    }
                    // F-CRITICAL-002 / 004 / 005 (2026-05-17 Phase 3
                    // step 4+5): run the auth gate before dispatch.
                    // Open endpoints (login, health, dashboard assets,
                    // /__waf_control/*) pass through without an
                    // identity; everything else requires a valid
                    // session cookie OR a service-account bearer
                    // token. On Authenticated we strip the client-
                    // supplied `X-Actor` header and inject the
                    // validated actor name as `X-Aegis-Actor` so
                    // mutation handlers stamp the audit chain with
                    // the real identity (closes F-CRITICAL-004).
                    use crate::admin_auth_middleware::{admit, Admit};
                    let auth_sessions = services.auth_sessions.clone();
                    let resp = match admit(&req, peer, &cfg, &auth_sessions).await {
                        Admit::Denied(r) => r,
                        Admit::OpenEndpoint => {
                            let mut req = req;
                            crate::admin_auth_middleware::strip_client_actor(&mut req);
                            handle_admin_request(
                                req, peer, &cfg, &readiness, &startup, &metrics, &services,
                            )
                            .await
                        }
                        Admit::Authenticated(identity) => {
                            let mut req = req;
                            crate::admin_auth_middleware::strip_client_actor(&mut req);
                            if let Ok(v) = hyper::header::HeaderValue::from_str(&identity.actor) {
                                req.headers_mut().insert("x-aegis-actor", v);
                            }
                            // RC-5a / V9: stamp the authenticated actor's real
                            // client IP (the TCP peer) so mutation handlers can
                            // record *where* an admin change came from. The
                            // client-supplied copy was just stripped above; this
                            // insert is the only trusted source.
                            if let Ok(v) =
                                hyper::header::HeaderValue::from_str(&peer.ip().to_string())
                            {
                                req.headers_mut().insert("x-aegis-client-ip", v);
                            }
                            handle_admin_request(
                                req, peer, &cfg, &readiness, &startup, &metrics, &services,
                            )
                            .await
                        }
                    };
                    Ok::<_, Infallible>(admin_sse::into_boxed(resp))
                }
            });

            match io {
                AdminIo::Tls(tls_stream) => {
                    let io = TokioIo::new(tls_stream);
                    if let Err(e) = http1::Builder::new()
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(HEADER_READ_TIMEOUT)
                        .serve_connection(io, svc)
                        .await
                    {
                        tracing::debug!("admin TLS connection from {peer} closed: {e}");
                    }
                }
                AdminIo::Plain(stream) => {
                    let io = TokioIo::new(stream);
                    if let Err(e) = http1::Builder::new()
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(HEADER_READ_TIMEOUT)
                        .serve_connection(io, svc)
                        .await
                    {
                        tracing::debug!("admin connection from {peer} closed: {e}");
                    }
                }
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn accept_loop(
    tcp: tokio::net::TcpListener,
    detectors: Arc<Vec<Box<dyn aegis_security::detectors::Detector>>>,
    mask: aegis_security::detectors::SharedDetectorMask,
    risk: aegis_security::risk::RiskTracker,
    ip_rate_limiter: Arc<aegis_security::rate_limit::IpRateLimiter>,
    load_gauge: aegis_core::LoadGauge,
    verbosity: aegis_core::SharedVerbosity,
    request_stage_hist: Arc<aegis_control::metrics::request_duration::RequestStageHistogram>,
    route_latency_hist: Arc<aegis_control::metrics::route_latency::RouteLatencyHistogram>,
    // P5 (2026-05-11) — sliding-window route activity counter.
    // Recorded after route resolution so the dashboard's pulse
    // pill can distinguish "live" from "dead" routes.
    route_activity: aegis_control::metrics::route_activity::RouteActivityWindow,
    detector_latency_hist: Arc<aegis_control::metrics::detector_latency::DetectorLatencyHistogram>,
    bus: AuditBus,
    upstream_ctx: Arc<crate::proxy::ProxyContext>,
    tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    // B5 carry-over — when `Some(port)` AND this listener serves
    // TLS (`tls_acceptor.is_some()`), every data-plane response
    // is stamped with an `Alt-Svc:` header advertising the
    // supplied UDP port for HTTP/3. `None` emits nothing.
    advertise_h3_port: Option<u16>,
    interop: Option<Arc<aegis_control::interop::InteropRuntime>>,
    // PROM-T1 — per-decision counter; recorded once per request
    // after `handle_data_request` returns its DecisionTag.
    decision_metrics: Arc<aegis_control::metrics::decisions::DecisionMetrics>,
    // PROM-T2 — per-class detector-hit counter; recorded inside
    // `handle_data_request` for every detector that emits ≥ 1
    // signal on a request.
    detector_hit_metrics: Arc<aegis_control::metrics::detector_hits::DetectorHitMetrics>,
    // MTLS-T3 — when present, every TLS connection carries a
    // per-identity sliding-window count via `record_request`.
    // `None` for tests / non-TLS configs that don't wire mTLS.
    identity_tracker: Option<Arc<aegis_control::identity_tracker::IdentityTracker>>,
    // 2026-05-08 NEW-2 — state backend, passed through to the
    // /__waf_control/challenge_verify handler for nonce
    // single-use enforcement. Same Arc the rest of the WAF uses
    // (rate-limit, risk, blacklist).
    state_backend: Arc<dyn aegis_core::state::StateBackend>,
    // PROXY-T1/T2 — per-listener PROXY-protocol mode. `Off` (default)
    // skips the pre-TLS read entirely; `Strict`/`Optional` read+parse
    // the asserted client IP ahead of TLS, enforce the trusted-proxy
    // boundary, and override the effective peer. See
    // `listener::proxy_protocol`.
    proxy_mode: aegis_core::config::ProxyProtocolMode,
    // PROXY-T3 — shared event counter, recorded once per connection on
    // an opted-in listener. Cheap clone (Arc-shared CounterVec).
    proxy_protocol_metrics: Arc<aegis_control::metrics::proxy_protocol::ProxyProtocolMetrics>,
) {
    loop {
        // `peer` is `mut` because a trusted PROXY-protocol header
        // (PROXY-T2) rebinds it to the asserted client address before
        // TLS. Without `accept_proxy`, it is never reassigned.
        let (mut stream, mut peer) = match tcp.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("accept error: {e}");
                continue;
            }
        };
        // Pre-handler scheduler-wait clock. Captured the instant
        // `accept()` returns; read once inside the spawned task to record
        // the `queue_wait` stage (tokio run-queue dispatch delay). This is
        // the blind spot the in-handler `total` clock can't see — under CPU
        // saturation requests queue here while in-handler stages stay fast,
        // which is why measured WAF latency looks fast as RPS collapses.
        // `Instant` is `Copy`, so it moves into the task for free.
        let accept_t0 = std::time::Instant::now();

        // GAP 2 — accept-time connection cap (anti connection-exhaustion).
        // Acquire one permit BEFORE any per-connection work (TLS handshake,
        // task spawn, and critically the in-flight `admit()`). `try_acquire`
        // (not `acquire().await`) so a full cap rejects instantly instead of
        // damming new connections into the OS backlog. On exhaustion we drop
        // the socket — closing at TCP, since pre-TLS we can't send a polite
        // HTTP 503 cheaply — and `continue` WITHOUT admitting, so a rejected
        // connection never inflates the drain gauge (reject-before-admit;
        // keeps the SIGUSR2 handover correct). The permit moves into the
        // task below and releases on its end. Per-request overload (after
        // TLS) remains the load-shedder's job (503). See
        // plans/issues/PLAN-conn-layer-dos-gaps-2026-06-20.md (§2.4).
        let conn_permit = match upstream_ctx.conn_limit.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                // debug, not warn: under a connection-flood this fires per
                // rejected socket — a warn here would be its own log-flood
                // self-DoS. Off by default in prod; on for dev triage.
                tracing::debug!(
                    peer = %peer,
                    "connection cap reached — rejecting connection at TCP"
                );
                drop(stream);
                continue;
            }
        };

        let detectors = detectors.clone();
        let mask = mask.clone();
        let risk = risk.clone();
        let ip_rate_limiter = ip_rate_limiter.clone();
        let load_gauge = load_gauge.clone();
        let verbosity = verbosity.clone();
        let request_stage_hist = request_stage_hist.clone();
        let route_latency_hist = route_latency_hist.clone();
        let route_activity = route_activity.clone();
        let detector_latency_hist = detector_latency_hist.clone();
        let bus = bus.clone();
        let upstream_ctx = upstream_ctx.clone();
        let interop = interop.clone();
        let state_backend_for_interop = state_backend.clone();
        let acceptor = tls_acceptor.clone();
        let decision_metrics = decision_metrics.clone();
        let detector_hit_metrics = detector_hit_metrics.clone();
        let proxy_protocol_metrics = proxy_protocol_metrics.clone();
        let identity_tracker = identity_tracker.clone();
        // FDP-T4 — admit a slot in the shared in-flight counter
        // for this data-plane connection. Cloned out here so it
        // moves into the spawned task; guard drops when the
        // task ends. Used by the SIGUSR2 handover's drain
        // phase to know when in-flight=0.
        let conn_inflight = upstream_ctx.inflight.clone();
        tokio::spawn(async move {
            // GAP 2 — hold the connection-cap permit for the whole task
            // lifetime; it releases (returns the slot) when the task ends,
            // alongside the in-flight guard. Order is irrelevant since both
            // are RAII and drop together on every exit path.
            let _conn_permit = conn_permit;
            let _admit = conn_inflight.admit();
            // Record the run-queue dispatch delay: time from `accept()`
            // returning to this task's first poll. Grows under CPU
            // saturation while the in-handler stages stay sub-millisecond —
            // surfacing the latency the `total` clock structurally misses.
            // One sample per accepted connection; sub-µs cost.
            let queue_wait = accept_t0.elapsed();
            request_stage_hist.record(
                aegis_control::metrics::request_duration::stage::QUEUE_WAIT,
                queue_wait,
            );
            // Feed the same dispatch-delay sample into the load shedder so
            // it actually opens under CPU starvation. `record_rtt` sees
            // only WAF-inspection time (sub-ms even at 100% CPU), so
            // without this the limit pins at max and the shedder never
            // sheds when the box — not the backend — is the bottleneck.
            if let Some(shedder) = upstream_ctx.load_shedder.get() {
                shedder.record_queue_wait(queue_wait);
            }
            // PROXY-T3 — the real LB transport hop, captured before a
            // trusted header rebinds `peer` to the client. `None` unless
            // an override happens; flows to the audit `proxy_via` field.
            let mut proxy_via: Option<std::net::IpAddr> = None;
            // PROXY-T2 — when this listener opted in (`accept_proxy !=
            // off`), consume + parse the PROXY header off the raw socket
            // BEFORE the TLS handshake, enforce the trusted-proxy
            // boundary, and rebind the effective `peer` to the asserted
            // client IP. Everything downstream (rate-limit, risk, geoip,
            // audit `ip`) then keys on the real client with no further
            // change. TLS — and so JA3/JA4 and any mTLS client-cert
            // check — still runs on the client's own ClientHello. The
            // default-off path never enters this branch: no extra read.
            if proxy_mode.is_enabled() {
                use crate::listener::proxy_protocol::{
                    decide_peer_action, metric_label, read_proxy_header, PeerAction,
                    ProxyProtocolModeRef,
                };
                let mode_ref = match proxy_mode {
                    aegis_core::config::ProxyProtocolMode::Strict => ProxyProtocolModeRef::Strict,
                    aegis_core::config::ProxyProtocolMode::Optional => {
                        ProxyProtocolModeRef::Optional
                    }
                    // `is_enabled()` already excluded `Off`.
                    aegis_core::config::ProxyProtocolMode::Off => return,
                };
                let outcome = read_proxy_header(&mut stream, mode_ref).await;
                // Honour a header only when the real TCP peer (the LB) is
                // a trusted proxy — the anti-spoofing boundary (§3.3).
                let trusted_lb = upstream_ctx
                    .trusted_proxies
                    .iter()
                    .any(|net| net.contains(&peer.ip()));
                // PROXY-T3 — one counter sample per connection, before
                // the disposition is applied. `untrusted_source` is a
                // distinct label from `parsed` (a clean parse that is
                // nonetheless closed for trust).
                proxy_protocol_metrics.record(metric_label(outcome, trusted_lb));
                match decide_peer_action(outcome, trusted_lb) {
                    PeerAction::Override(client) => {
                        tracing::debug!(
                            lb_peer = %peer,
                            asserted_client = %client,
                            result = outcome.label(),
                            "proxy-protocol: effective peer overridden",
                        );
                        // Keep the real LB hop as `proxy_via` (audit
                        // forensics) before adopting the client as peer.
                        proxy_via = Some(peer.ip());
                        peer = client;
                    }
                    PeerAction::Proceed => {
                        tracing::trace!(
                            lb_peer = %peer,
                            trusted_lb,
                            result = outcome.label(),
                            "proxy-protocol: proceeding with transport peer",
                        );
                    }
                    PeerAction::Close => {
                        tracing::debug!(
                            lb_peer = %peer,
                            trusted_lb,
                            result = outcome.label(),
                            "proxy-protocol: closing connection (fail-closed)",
                        );
                        return;
                    }
                }
            }
            // MTLS-T3 — per-connection identity. We set it from
            // the TLS handshake (when a TLS acceptor is wired)
            // before the service_fn is built; plain-HTTP
            // connections stay Anonymous (no cert was offered).
            //
            // The handshake runs *here*, ahead of building the
            // service_fn, so the captured identity is stable for
            // every request on this connection. Closure-cloned
            // once into `conn_identity_for_svc`; then service_fn
            // re-clones the Arc per request (cheap).
            let conn_identity: std::sync::Arc<aegis_core::ClientIdentity>;
            // `served_io` is the resolved per-connection IO:
            // `Some(TlsIo)` on the TLS branch, `None` triggers
            // the plain-HTTP path below. Built ahead so the
            // service_fn captures the identity BEFORE serving.
            enum ServedIo {
                Tls(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
                Plain(tokio::net::TcpStream),
            }
            // 2026-05-18 (QC TLS wire-up): per-connection TLS
            // fingerprint, captured from rustls's post-handshake
            // ServerConnection. `Some` on the TLS branch, `None`
            // on the plain branch. Cloned into the service_fn
            // closure so each request gets `view.tls` pointing at
            // a stable per-connection Arc.
            let conn_tls_fp: Option<std::sync::Arc<aegis_core::TlsFingerprint>>;
            let served = match acceptor {
                Some(acc) => match acc.accept(stream).await {
                    Ok(tls_stream) => {
                        // Pull peer cert chain off the verified
                        // session. `chain_ok = true` because the
                        // verifier ran (MTLS-T2) — Optional mode
                        // can produce `None` if no cert was
                        // offered, which T3 maps to Anonymous.
                        let (id, fp) = {
                            let (_io, conn) = tls_stream.get_ref();
                            let id = crate::listener::identity::extract_identity_from_peer_certs(
                                conn.peer_certificates(),
                                true,
                            );
                            // 2026-05-18: compute the post-
                            // handshake fingerprint (see
                            // `listener/tls.rs` for the format).
                            let fp = crate::listener::tls::compute_post_handshake_fingerprint(conn);
                            (id, fp)
                        };
                        conn_tls_fp = Some(std::sync::Arc::new(fp));
                        if !matches!(
                            id,
                            aegis_core::ClientIdentity::Anonymous
                        ) {
                            tracing::debug!(
                                peer = %peer,
                                kind = id.kind(),
                                principal = ?id.principal(),
                                "mtls peer identity extracted",
                            );
                        }
                        conn_identity = std::sync::Arc::new(id);
                        Some(ServedIo::Tls(tls_stream))
                    }
                    Err(e) => {
                        tracing::debug!(
                            "tls handshake from {peer} failed: {e}"
                        );
                        // Connection ends here; nothing to serve.
                        return;
                    }
                },
                None => {
                    conn_identity =
                        std::sync::Arc::new(aegis_core::ClientIdentity::Anonymous);
                    // No TLS → no fingerprint. Downstream features
                    // (DeviceIpTracker observe, brute_force device
                    // axis, bots known-bad-JA4 lookup) silently
                    // skip when view.tls is None.
                    conn_tls_fp = None;
                    Some(ServedIo::Plain(stream))
                }
            };
            let conn_identity_for_svc = conn_identity.clone();
            let conn_tls_fp_for_svc = conn_tls_fp.clone();
            let identity_tracker_for_svc = identity_tracker.clone();
            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let conn_identity = conn_identity_for_svc.clone();
                let conn_tls_fp = conn_tls_fp_for_svc.clone();
                let identity_tracker = identity_tracker_for_svc.clone();
                let detectors = detectors.clone();
                let mask = mask.clone();
                let risk = risk.clone();
                let ip_rate_limiter = ip_rate_limiter.clone();
                let load_gauge = load_gauge.clone();
                let verbosity = verbosity.clone();
                let request_stage_hist = request_stage_hist.clone();
                let route_latency_hist = route_latency_hist.clone();
                let route_activity = route_activity.clone();
                let detector_latency_hist = detector_latency_hist.clone();
                let bus = bus.clone();
                let upstream_ctx = upstream_ctx.clone();
                let interop = interop.clone();
                let state_backend_for_interop = state_backend_for_interop.clone();
                let decision_metrics = decision_metrics.clone();
                let detector_hit_metrics = detector_hit_metrics.clone();
                async move {
                    // 2026-05-08 — capture earliest-possible per-
                    // request timestamp for the X-WAF-Overhead-
                    // Latency response header. Sub-microsecond cost
                    // (single Instant::now()); stamped at response
                    // time inside `stamp_interop_response`.
                    let request_start = std::time::Instant::now();
                    let method = req.method().clone();
                    // v2.3 §6 — audit `path` MUST include the query
                    // string. `.path()` strips it; `.path_and_query()`
                    // preserves the full request-target as the client
                    // sent it. The control-endpoint `starts_with`
                    // check below is unaffected (the prefix is
                    // identical with or without query).
                    let path = req
                        .uri()
                        .path_and_query()
                        .map(|p| p.as_str())
                        .unwrap_or_else(|| req.uri().path())
                        .to_string();
                    // v2.5 contract §4 — challenge verify is the
                    // benchmarker-facing public endpoint (different
                    // from the local-only control plane). Mount on
                    // the data plane so the external benchmarker
                    // can POST solutions without an SSH tunnel.
                    // No admin auth, no loopback gate; the PoW MAC
                    // + single-use nonce store provide the security.
                    if method == hyper::Method::POST && path.split('?').next() == Some("/challenge/verify") {
                        let resp = crate::admin_dispatch::handle_challenge_verify(
                            req,
                            upstream_ctx.pow_issuer.get(),
                            Some(&state_backend_for_interop),
                        ).await;
                        let resp = crate::admin_dispatch::stamp_interop_response(
                            resp,
                            aegis_control::interop::headers::DecisionTag::allow(),
                            interop.as_ref(),
                            peer,
                            &method,
                            &path,
                            0,
                            request_start,
                        );
                        // Phase 1 (SSE): box the buffered Full response into
                        // DataBody so this closure has one body type (the
                        // data path now serves DataBody from handle_data_request).
                        return Ok::<_, Infallible>(crate::body::boxed(resp));
                    }
                    // `/__waf_control/*` is a reserved namespace with two
                    // independent invariants:
                    //
                    //   1. CRIT-1 (§2.1) — it MUST NOT be proxied to
                    //      upstream. So we ALWAYS intercept it here, ahead
                    //      of routing/risk-gate; a control path never falls
                    //      through to the catch-all (the old loopback gate
                    //      did fall through → upstream echo, the bug).
                    //
                    //   2. Loopback/admin-only (committee bind contract +
                    //      2026-06-13 posture decision) — defence-in-depth
                    //      stays. The benchmarker SSH-tunnels in and calls
                    //      from loopback; `X-Benchmark-Secret` (§2.2) is the
                    //      second factor checked inside the handler. A
                    //      non-loopback caller (e.g. anyone arriving via a
                    //      public L4 VIP, where source IPs collapse to one
                    //      identity and peer-trust is meaningless) gets a
                    //      local 404 that HIDES the namespace's existence —
                    //      never the upstream echo, and never a 403 that
                    //      would confirm the surface is there.
                    match classify_control_request(&path, &peer) {
                        ControlDisposition::Passthrough => {}
                        disposition => {
                            let resp = if disposition == ControlDisposition::Dispatch {
                                if let Some(rt) = interop.as_ref() {
                                    // v2.5 (2026-05-19) — challenge_verify
                                    // is no longer on /__waf_control/*; it
                                    // moved to the public /challenge/verify
                                    // data-plane mount above this branch.
                                    crate::admin_dispatch::handle_interop_control_with_rt(
                                        req,
                                        rt.as_ref(),
                                    )
                                    .await
                                } else {
                                    // Loopback control path but the interop
                                    // surface isn't wired — still MUST NOT
                                    // proxy; answer a local 404.
                                    control_not_found()
                                }
                            } else {
                                control_not_found()
                            };
                            // F-CRITICAL-001 (2026-05-17 s-tester audit):
                            // stamp the 6 mandatory v2.3 §5 headers
                            // (`X-WAF-Request-Id`, `-Action`, `-Mode`,
                            // `-Cache`, `-Risk-Score`, `-Overhead-Latency`)
                            // uniformly — including on the hidden-404 path,
                            // so it's indistinguishable from any other
                            // data-plane 404.
                            let resp = crate::admin_dispatch::stamp_interop_response(
                                resp,
                                aegis_control::interop::headers::DecisionTag::allow(),
                                interop.as_ref(),
                                peer,
                                &method,
                                &path,
                                0,
                                request_start,
                            );
                            // Phase 1 (SSE): box into DataBody (see above).
                            return Ok::<_, Infallible>(crate::body::boxed(resp));
                        }
                    }
                    // 2026-05-03 — capture bot-classification
                    // signals BEFORE handle_data_request consumes
                    // the request. Cheap (~5 string lookups), no
                    // body reads. Used in the audit emit below so
                    // the Investigation page's BotMix card lights
                    // up with real signal instead of 100 %
                    // "unknown".
                    let user_agent = req
                        .headers()
                        .get(hyper::header::USER_AGENT)
                        .and_then(|h| h.to_str().ok())
                        .map(|s| s.to_string());
                    let has_cookies = req
                        .headers()
                        .get(hyper::header::COOKIE)
                        .is_some();
                    // BUG-audit-detail Fix A — capture the cumulative-risk
                    // bucket key (ip + device_fp + session axes) BEFORE
                    // `handle_data_request` consumes the request, so the allow
                    // audit below can surface it in the Request Detail drawer.
                    // Built the same way as the risk gate's key
                    // (`build_risk_key`), so the rendered bucket matches the
                    // one traffic actually accumulates under. Cheap (no hash);
                    // it's only RENDERED (`risk_key_audit_value`, which hashes)
                    // on the allow emit below — block returns early and the
                    // data plane already audited its own risk_key.
                    let risk_key_for_audit = crate::data_plane::build_risk_key(
                        peer.ip(),
                        req.headers(),
                        conn_tls_fp.as_ref().map(|arc| arc.as_ref()),
                    );
                    // BUG-audit-detail Fix B — request-header echo for ALL
                    // requests (incl. `allow`), gated behind an elevated
                    // verbosity level so it's OFF by default. Detection/block
                    // paths already echo at `verbosity >= Info`; the allow path
                    // is noisier + higher-volume to sinks, so it rides the
                    // stricter `Debug` rung. Captured here (redacted headers,
                    // no body — the body is consumed by `handle_data_request`)
                    // and merged into the allow audit `fields` below; it then
                    // flows to every audit sink unchanged. Reuses
                    // `request_echo_fields`' auth/cookie/token redaction.
                    let allow_header_echo = if verbosity
                        .current()
                        .is_at_least(aegis_core::VerbosityLevel::Debug)
                    {
                        Some(crate::data_plane::request_echo_fields(req.headers(), None))
                    } else {
                        None
                    };
                    let (resp, decision) = handle_data_request(
                        req,
                        peer,
                        proxy_via,
                        &detectors,
                        &mask,
                        &risk,
                        &ip_rate_limiter,
                        &load_gauge,
                        &verbosity,
                        &request_stage_hist,
                        &route_latency_hist,
                        &route_activity,
                        &detector_latency_hist,
                        &bus,
                        &upstream_ctx,
                        &detector_hit_metrics,
                        // MTLS-T4 — per-connection identity threads
                        // through to the route-scoped policy gate.
                        &conn_identity,
                        // 2026-05-18 (QC TLS wire-up): per-conn
                        // post-handshake fingerprint. None on the
                        // plain branch.
                        conn_tls_fp.as_ref().map(|arc| arc.as_ref()),
                    ).await;
                    // PROM-T1 — record one increment of
                    // `waf_requests_total{action}` per request.
                    // Cost: ~30 ns (label lookup + atomic inc).
                    decision_metrics.record(decision.action);
                    // B5 carry-over — Alt-Svc auto-stamp on every
                    // TLS-served response when an h3 advertise port
                    // was configured. Capable browsers cache the
                    // hint for 24 h and switch subsequent requests
                    // to QUIC. Idempotent: skips if the data plane
                    // already added the header.
                    let mut resp = resp;
                    if let Some(port) = advertise_h3_port {
                        if !resp.headers().contains_key(crate::listener::http3::ALT_SVC_HEADER) {
                            if let Ok(v) = hyper::header::HeaderValue::from_str(
                                &crate::listener::http3::default_alt_svc(port),
                            ) {
                                resp.headers_mut().insert(
                                    crate::listener::http3::ALT_SVC_HEADER,
                                    v,
                                );
                            }
                        }
                    }
                    let resp = resp;
                    // OTEL-T3 note: action is recorded on the
                    // request span from inside handle_data_request
                    // (the span is only active during that
                    // function's body, not at this call site).
                    // 2026-05-21 — prefer the score the data plane
                    // stamped on the decision: it was computed under
                    // the correct composite RiskKey and is what the
                    // X-WAF-Risk-Score header already reports. The
                    // peer-IP snapshot below is a fallback for paths
                    // that don't stamp one (clean allows). Without
                    // this, a detected-but-allowed request (e.g. an AI
                    // hit under the tier threshold) showed `rule_id=ai`
                    // with `risk 0` — the snapshot keyed on the bare
                    // TCP peer missed the composite-key score, and the
                    // audit disagreed with the response header.
                    let risk_score = decision.risk_score.unwrap_or_else(|| {
                        risk.snapshot(peer.ip()).map(|s| s.score).unwrap_or(0)
                    });

                    // CI-T11 — broadcast every request decision to
                    // the audit bus so /dashboard/sse Live Feed is
                    // truly live. The bus subscriber count drives
                    // whether send() actually reaches anyone; this
                    // is a cheap fire-and-forget on the hot path.
                    //
                    // 2026-05-03 / 2026-06-21 — audit-emit ownership is now
                    // centralised in `interop::headers::listener_emits_audit`.
                    // The data plane self-emits a richer Detection event
                    // (XFF-resolved `client_ip`, `fields.detectors[]`,
                    // `strikes`, `load_mode`, route tier) for every decision
                    // it terminates itself — `block`, `challenge`, AND
                    // `rate_limit`. Re-emitting any of those here produced TWO
                    // feed rows per request (the bug: a `rate_limit` denial
                    // showed a data-plane BLOCK twin + this listener
                    // RATE_LIMIT row; blocks doubled `/api/attacks/top`). The
                    // listener stays the SOLE emitter for `allow` and the
                    // upstream-failure verdicts the data plane does not
                    // self-audit (`timeout`, `circuit_breaker`).
                    let action = decision.action.as_str();
                    if !aegis_control::interop::headers::listener_emits_audit(decision.action) {
                        // Update MTLS tracker + interop response
                        // stamping below, but skip the
                        // bus.emit() entirely — the data plane
                        // already audited this decision.
                        if let (Some(tracker), Some(principal)) = (
                            identity_tracker.as_ref(),
                            conn_identity.principal(),
                        ) {
                            tracker.record_request(
                                principal,
                                conn_identity.kind(),
                                decision.action.as_str(),
                            );
                        }
                        let resp = stamp_interop_response(
                            resp,
                            decision,
                            interop.as_ref(),
                            peer,
                            &method,
                            &path,
                            risk_score,
                            request_start,
                        );
                        return Ok::<_, Infallible>(resp);
                    }
                    let class = match action {
                        "allow" => aegis_core::audit::AuditClass::Access,
                        _      => aegis_core::audit::AuditClass::Detection,
                    };
                    // v2.3 §5.1 — UUID v4 (`getrandom` under the hood)
                    // gives a cryptographically-random, collision-free
                    // ID. The earlier blake3(peer:nanos:path) form was
                    // deterministic on those three inputs and collided
                    // when two requests shared a nanosecond timestamp
                    // (common under burst load).
                    let request_id = uuid::Uuid::new_v4().to_string();
                    // 2026-05-03 — classify the request's bot tier
                    // and stash it on `fields.bot_category` so the
                    // AttacksAggregator (`bot_category_from_fields`)
                    // groups it for the BotMix dashboard card.
                    // Skip the field when the verdict is Human or
                    // Unknown — only actual bot tiers count toward
                    // bot-mix.  The classifier is stateless +
                    // cheap (~10 string ops), so no shared instance
                    // needed.
                    // 2026-05-18 (QC follow-up TLS-wiring batch —
                    // F-CRITICAL-015 activation): look up peer ASN
                    // via the GeoIP reader if it's installed, then
                    // map ASN → ownership class via the hardcoded
                    // table in `aegis_security::bots::classify_asn`.
                    // No reader installed → ASN stays None and the
                    // classifier's ladder branch is a no-op. Cheap:
                    // one MaxMindReader lookup + one linear scan
                    // over ~20 entries.
                    let (peer_asn, asn_class) = match upstream_ctx
                        .geoip
                        .get()
                    {
                        Some(reader) => {
                            let asn_opt = reader.asn(peer.ip());
                            let class = asn_opt
                                .map(aegis_security::bots::classify_asn)
                                .unwrap_or(
                                    aegis_security::bots::AsnClassification::Unknown,
                                );
                            (asn_opt, class)
                        }
                        None => {
                            (None, aegis_security::bots::AsnClassification::Unknown)
                        }
                    };
                    let bot_signals = aegis_security::bots::BotSignals {
                        // 2026-05-18 (QC TLS wire-up): populate the
                        // JA4-light fingerprint when the connection
                        // is TLS-terminated. Plain HTTP connections
                        // stay None — they have no handshake.
                        ja4_fingerprint: conn_tls_fp
                            .as_ref()
                            .map(|fp| fp.ja4.clone()),
                        h2_fingerprint: None,
                        user_agent: user_agent.clone(),
                        has_cookies,
                        has_js_challenge_pass: false,
                        failed_challenges: 0,
                        reverse_dns: None,
                        asn: peer_asn,
                        asn_classification: asn_class,
                    };
                    // 2026-05-21 — gate-style toggle. When the bot
                    // classifier is disabled (PUT /api/gates/bots →
                    // upstream_ctx.bots_enabled = false), skip
                    // classification entirely and leave bot_category
                    // unset.
                    let bot_category = if upstream_ctx
                        .bots_enabled
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        match aegis_security::bots::BotClassifier::default()
                            .classify(&bot_signals)
                        {
                            aegis_security::bots::BotTier::GoodBot   => Some("verified"),
                            aegis_security::bots::BotTier::LikelyBot => Some("suspect"),
                            aegis_security::bots::BotTier::KnownBad  => Some("malicious"),
                            // Human + Unknown do not count toward bot-mix.
                            _ => None,
                        }
                    } else {
                        None
                    };
                    let event = aegis_core::audit::AuditEvent {
                        schema_version: 1,
                        ts: chrono::Utc::now(),
                        request_id: request_id.clone(),
                        class,
                        tenant_id: None,
                        // 2026-05-05 — surface the route's tier so
                        // Live Feed shows critical / high / medium /
                        // low instead of falling back to a risk-bucket
                        // label. Populated by `DecisionTag::with_tier`
                        // on every post-classify_tier exit point in
                        // the data plane.
                        tier: decision.tier,
                        action: action.to_string().into(),
                        // 2026-05-21 — for an under-threshold detection
                        // the data plane sets `decision.rule_id` to the
                        // fired detector tags on the forwarded `allow`
                        // tag, so both this audit `rule_id` AND the
                        // `X-WAF-Rule-Id` response header (stamped from
                        // the same `decision.rule_id`) carry the
                        // detectors and stay in lock-step.
                        // RF-FP (2026-07-08 QC) — a filtered-but-unattributed
                        // allow is named `response_filter` here too, so the
                        // audit `rule_id`/`reason` match the X-WAF-Rule-Id
                        // header (lock-step). A real detector attribution is
                        // preserved.
                        reason: aegis_control::interop::headers::rule_id_with_filter_fallback(
                            decision.rule_id.clone(),
                            decision.response_filtered.is_some(),
                        )
                        .unwrap_or_else(|| action.to_string()),
                        client_ip: peer.ip().to_string(),
                        route_id: None,
                        rule_id: aegis_control::interop::headers::rule_id_with_filter_fallback(
                            decision.rule_id.clone(),
                            decision.response_filtered.is_some(),
                        ),
                        risk_score: Some(risk_score),
                        method: None,
                        path: None,
                        mode: None,
                        fields: {
                            let mut f = serde_json::json!({
                                "method": method.as_str(),
                                "path": path,
                                // Only present when classifier returns
                                // a real bot tier — Human / Unknown
                                // are skipped so they don't count
                                // toward the bot-mix chart.
                                "bot_category": bot_category,
                                "status": resp.status().as_u16(),
                                // BUG-audit-detail Fix A — cumulative-risk
                                // bucket axes for the drawer, on EVERY allow
                                // (not just blocks). Lets operators confirm
                                // same-IP requests share (or don't) a bucket.
                                "risk_key": crate::data_plane::risk_key_audit_value(&risk_key_for_audit),
                            });
                            // BUG-audit-detail Fix B — merge the redacted
                            // request-header echo on the allow path when the
                            // verbosity dial is at Debug+ (captured above; None
                            // at the default Info level ⇒ no change to the hot
                            // path or sink volume).
                            if let (serde_json::Value::Object(ref mut map), Some(echo)) =
                                (&mut f, allow_header_echo)
                            {
                                map.extend(echo);
                            }
                            // 2026-05-21 — per-request detector score for
                            // a detected-but-allowed request (sum of this
                            // request's signals), distinct from the
                            // cumulative `risk_score`. Absent on clean
                            // allows.
                            if let (serde_json::Value::Object(ref mut map), Some(rs)) =
                                (&mut f, decision.detector_score)
                            {
                                map.insert("request_score".to_string(), serde_json::json!(rs));
                            }
                            // SSE — for a streamed (header-inspected-only)
                            // response, record explicitly WHY the body
                            // wasn't inspected so the security team sees it
                            // in the feed (SSE plan decision 3).
                            if decision.streamed {
                                if let serde_json::Value::Object(ref mut map) = f {
                                    map.insert("streamed".to_string(), serde_json::json!(true));
                                    map.insert(
                                        "response_inspection_skipped".to_string(),
                                        serde_json::json!(true),
                                    );
                                    map.insert("reason".to_string(), serde_json::json!("streaming"));
                                }
                            }
                            // RF-FP (2026-07-08 QC) — fold the response-filter
                            // signal into THIS request's own record (drawer
                            // detail) instead of emitting a separate Detection
                            // row. Byte delta only — never the redacted value.
                            if let (serde_json::Value::Object(ref mut map), Some(sig)) =
                                (&mut f, decision.response_filtered)
                            {
                                map.insert("response_filtered".to_string(), serde_json::json!(true));
                                map.insert(
                                    "response_filter_bytes_before".to_string(),
                                    serde_json::json!(sig.bytes_before),
                                );
                                map.insert(
                                    "response_filter_bytes_after".to_string(),
                                    serde_json::json!(sig.bytes_after),
                                );
                            }
                            f
                        },
                    };
                    // Only listener-owned actions (`allow`, `timeout`,
                    // `circuit_breaker`) reach this point — `block`,
                    // `challenge`, and `rate_limit` took the early return above
                    // because the data plane already audited them
                    // (see `listener_emits_audit`). Emit the single row.
                    bus.emit(event);

                    // MTLS-T3 — record this request against the
                    // per-identity sliding-window tracker so the
                    // `/api/mtls/connections` dashboard surface
                    // (MTLS-T6, already shipped) lights up with
                    // real data. Only fire when (a) the tracker
                    // is wired AND (b) the connection presented
                    // a non-Anonymous identity. Decision label
                    // is the contract action — drives the per-
                    // identity allow / block / challenge breakdown.
                    if let (Some(tracker), Some(principal)) = (
                        identity_tracker.as_ref(),
                        conn_identity.principal(),
                    ) {
                        tracker.record_request(
                            principal,
                            conn_identity.kind(),
                            decision.action.as_str(),
                        );
                    }

                    let resp = stamp_interop_response(
                        resp,
                        decision,
                        interop.as_ref(),
                        peer,
                        &method,
                        &path,
                        risk_score,
                        request_start,
                    );
                    Ok::<_, Infallible>(resp)
                }
            });

            // Carry-over 5 — when the listener is configured
            // for TLS, do the rustls handshake first, then
            // serve hyper over the encrypted stream. Otherwise
            // serve plain HTTP/1.1 directly.
            //
            // CI-T10 — the TLS branch uses
            // `hyper_util::server::conn::auto::Builder` so an
            // ALPN-negotiated `h2` actually serves over HTTP/2;
            // before this, ALPN advertised h2 but the listener
            // only spoke h1. The plain branch stays h1-only —
            // there's no h2-without-TLS in our deployment shape
            // (h2c isn't on the supported list).
            // Serve hyper using the IO resolved during the
            // pre-handshake step above. The handshake already
            // ran (or returned early on failure); this branch
            // only does plumbing.
            match served {
                Some(ServedIo::Tls(tls_stream)) => {
                    let io = TokioIo::new(tls_stream);
                    let mut builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    // PROXY-04 — bound the header-read phase (h1 path). The h2
                    // path has its own keep-alive/settings timers. A Timer must
                    // be configured or header_read_timeout panics at runtime.
                    builder.http1().timer(hyper_util::rt::TokioTimer::new());
                    builder.http1().header_read_timeout(HEADER_READ_TIMEOUT);
                    if let Err(e) =
                        builder.serve_connection_with_upgrades(io, svc).await
                    {
                        tracing::debug!(
                            "tls connection from {peer} closed: {e}"
                        );
                    }
                }
                Some(ServedIo::Plain(stream)) => {
                    let io = TokioIo::new(stream);
                    // `.with_upgrades()` is REQUIRED for WebSocket: without
                    // it hyper's low-level http1 connection rejects the
                    // `hyper::upgrade::on()` the WS bridge needs, failing
                    // with "upgrade expected but low level API in use" so
                    // the client gets a 101 then an immediate drop (no
                    // frames, bare 1006). The TLS branch already enables
                    // upgrades via `serve_connection_with_upgrades`; the
                    // plain branch must match or WS only works over TLS.
                    if let Err(e) = http1::Builder::new()
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(HEADER_READ_TIMEOUT)
                        .serve_connection(io, svc)
                        .with_upgrades()
                        .await
                    {
                        tracing::debug!("connection from {peer} closed: {e}");
                    }
                }
                None => {} // unreachable — handshake-failure path returned above
            }
        });
    }
}

/// Disposition of a request against the reserved `/__waf_control/*`
/// namespace. Two invariants are folded in here:
///
///  - **§2.1 — never proxy control paths to upstream.** Any path under
///    the prefix is handled locally; the only way to reach a backend is
///    [`ControlDisposition::Passthrough`], which is returned ONLY for
///    non-control paths.
///  - **Loopback/admin-only (committee bind contract + 2026-06-13
///    posture decision).** Only loopback peers may invoke control
///    ([`ControlDisposition::Dispatch`]); a control path from any other
///    peer is [`ControlDisposition::HideNotFound`] — answered with a
///    local 404 that hides the namespace's existence (never the upstream
///    echo, never a 403 that would confirm the surface).
#[derive(Debug, PartialEq, Eq)]
enum ControlDisposition {
    /// Loopback control path — dispatch to the secret-gated handler.
    Dispatch,
    /// Control path from a non-loopback peer — answer a local 404.
    HideNotFound,
    /// Not a control path — continue the normal request pipeline.
    Passthrough,
}

/// Classify a request against the control namespace. See
/// [`ControlDisposition`] for the policy this encodes.
fn classify_control_request(path: &str, peer: &std::net::SocketAddr) -> ControlDisposition {
    if !path.starts_with("/__waf_control/") {
        return ControlDisposition::Passthrough;
    }
    if peer.ip().is_loopback() {
        ControlDisposition::Dispatch
    } else {
        ControlDisposition::HideNotFound
    }
}

/// A minimal local `404` for a control-namespace request we refuse to
/// dispatch (non-loopback caller, or interop surface not wired). It is
/// deliberately generic so it's indistinguishable from any other
/// data-plane 404 — the existence of `/__waf_control/*` is not
/// confirmed to off-host callers. NEVER proxies to upstream.
fn control_not_found() -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    hyper::Response::builder()
        .status(hyper::StatusCode::NOT_FOUND)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(http_body_util::Full::new(hyper::body::Bytes::from_static(
            b"not found\n",
        )))
        .expect("static 404 response always builds")
}

#[cfg(test)]
mod control_gate_tests {
    use super::{classify_control_request, ControlDisposition};
    use std::net::SocketAddr;

    fn lo() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 50_000))
    }

    fn lo_v6() -> SocketAddr {
        // ::1 is loopback as well
        "[::1]:50000".parse().unwrap()
    }

    fn remote_v4() -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 7], 50_000))
    }

    fn remote_v6() -> SocketAddr {
        "[2001:db8::1]:50000".parse().unwrap()
    }

    // Loopback control paths dispatch to the secret-gated handler.
    #[test]
    fn loopback_control_dispatches() {
        assert_eq!(
            classify_control_request("/__waf_control/capabilities", &lo()),
            ControlDisposition::Dispatch
        );
        assert_eq!(
            classify_control_request("/__waf_control/reset_state", &lo()),
            ControlDisposition::Dispatch
        );
        assert_eq!(
            classify_control_request("/__waf_control/capabilities", &lo_v6()),
            ControlDisposition::Dispatch
        );
    }

    // 2026-06-13 posture decision — control is loopback/admin-only.
    // A non-loopback caller (incl. anyone behind an L4 VIP) gets the
    // hidden 404 — NOT a dispatch and NOT a proxy to upstream.
    #[test]
    fn non_loopback_control_is_hidden() {
        assert_eq!(
            classify_control_request("/__waf_control/capabilities", &remote_v4()),
            ControlDisposition::HideNotFound
        );
        assert_eq!(
            classify_control_request("/__waf_control/reset_state", &remote_v4()),
            ControlDisposition::HideNotFound
        );
        assert_eq!(
            classify_control_request("/__waf_control/set_profile", &remote_v6()),
            ControlDisposition::HideNotFound
        );
    }

    // CRIT-1 invariant: a control path is NEVER Passthrough (the only
    // disposition that proxies to upstream) — for ANY peer. Loopback →
    // Dispatch, everyone else → HideNotFound, but never upstream.
    #[test]
    fn control_paths_are_never_passthrough() {
        for peer in [lo(), lo_v6(), remote_v4(), remote_v6()] {
            assert_ne!(
                classify_control_request("/__waf_control/reset_state", &peer),
                ControlDisposition::Passthrough,
                "control path would proxy to upstream for peer {peer}"
            );
        }
    }

    #[test]
    fn non_control_path_passes_through() {
        assert_eq!(
            classify_control_request("/", &lo()),
            ControlDisposition::Passthrough
        );
        assert_eq!(
            classify_control_request("/api/health", &remote_v4()),
            ControlDisposition::Passthrough
        );
        // Defensive — the control namespace lives ONLY under the
        // `/__waf_control/` prefix; anything that merely *contains* the
        // substring deeper in the path routes/proxies normally.
        assert_eq!(
            classify_control_request("/x/__waf_control/capabilities", &lo()),
            ControlDisposition::Passthrough
        );
        assert_eq!(
            classify_control_request("/x/__waf_control/capabilities", &remote_v4()),
            ControlDisposition::Passthrough
        );
    }
}
