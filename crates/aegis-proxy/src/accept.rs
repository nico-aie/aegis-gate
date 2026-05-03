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
    // Phase-1 analytics — shared with the data plane so
    // `/api/analytics/latency` reads from the same series the
    // data plane records into.
    request_stage_hist: Arc<aegis_control::metrics::request_duration::RequestStageHistogram>,
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
    let session_key = aegis_control::api::login::derive_session_key(&auth.csrf_secret_ref);
    let auth_sessions = Arc::new(
        aegis_control::admin_auth::session::SessionStore::new(session_key),
    );
    let login_rate_limiter = aegis_control::api::login::build_rate_limiter(auth);
    let admin_identity = Arc::new(aegis_control::api::login::AdminIdentity {
        // Single-admin model: hard-code "admin" until RBAC lands.
        user: "admin".into(),
        password_hash: auth.password_hash_ref.clone(),
    });
    let session_idle_seconds = auth.session_ttl_idle.as_secs();

    // Carry-over 3 (post-2026-04-29 cluster smoke) — build a
    // shared `LeaderView` and start a background poller that
    // updates it from `lease_store.holder("leader:cluster")`
    // every two seconds. The admin handler reads this view
    // synchronously when `/api/cluster` is fetched.
    let our_node_id = lease_store.self_id().as_str().to_string();
    let leader_view = Arc::new(
        aegis_control::api::tracking::LeaderView::new(our_node_id),
    );

    // Singleton "I am the cluster leader" lease — distinct
    // from the per-task leases (`leader:acme`, `leader:gitops`,
    // …) above. The runner does no work; it just holds the
    // lease so exactly one node is identifiable as
    // *the* cluster leader for admin / dashboard surfaces.
    {
        let lease_store_for_cluster = lease_store.clone();
        // TTL kept tight (5 s) because this lease has zero
        // task body — the failover budget is just
        // TTL + retry-half-TTL + leader-view-poll-period
        // (5 + 2.5 + 2 ≈ 10 s) which keeps
        // `tests/cluster/02-leader-failover.sh` predictable.
        crate::cluster_lease::spawn_with_lease(
            lease_store_for_cluster,
            "leader:cluster",
            std::time::Duration::from_secs(5),
            move |_holder, lost| async move {
                // No-op factory — just wait until the lease
                // is lost. The wrapper takes care of release.
                lost.notified().await;
            },
        );
    }

    {
        let store: Arc<dyn aegis_core::cluster::LeaseStore> =
            Arc::clone(&lease_store);
        let lv = Arc::clone(&leader_view);
        tokio::spawn(async move {
            let key = "leader:cluster".to_string();
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                match store.holder(&key).await {
                    Ok(holder) => {
                        let h: Option<String> =
                            holder.map(|n: aegis_core::cluster::NodeId| {
                                n.as_str().to_string()
                            });
                        lv.set_holder(h);
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "leader-view poll failed");
                    }
                }
            }
        });
    }

    // HA-T4 — membership heartbeat + roster poller.
    //
    // Each node publishes its identity by holding the lease
    // `members:<our_node_id>` (15s TTL, refreshed every
    // ~7.5s by the heartbeat layer). The same poller that
    // tracks `leader:cluster` enumerates `members:*` keys
    // every 5s and feeds the result into
    // `LeaderView::members`, which the admin handler then
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
        let lv = Arc::clone(&leader_view);
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

    let (services, _drain) = aegis_control::dashboard_services::DashboardServices::spawn_with_mask_and_leader(
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
        admin_identity,
        session_idle_seconds,
        Some(Arc::clone(&leader_view)),
    );
    // Hand the interop Runtime to the admin control plane via
    // `services.interop`. Same Arc that the data-plane
    // accept_loop already holds, so all surfaces see one shared
    // ModeStore + audit sink.
    let mut services = services;
    services.interop = interop.clone();

    // CI-T5 — seed `services.routes` from `cfg.routes` so
    // /api/routes returns the live routing trie. Hot-reload
    // re-invokes this through `cfg_swap` (TODO when route
    // hot-reload lands; today routes are boot-time only).
    services.routes.set(
        cfg.routes
            .iter()
            .map(|r| aegis_control::api::routes::RouteSummary {
                id: r.id.clone(),
                host: r.host.clone(),
                path: r.path.clone(),
                match_type: match r.match_type {
                    aegis_core::config::MatchType::Exact => "exact",
                    aegis_core::config::MatchType::Prefix => "prefix",
                    aegis_core::config::MatchType::Regex => "regex",
                    aegis_core::config::MatchType::Glob => "glob",
                }
                .to_string(),
                methods: r.methods.clone().unwrap_or_default(),
                upstream: r.upstream.clone(),
                tier_override: r.tier_override.map(|t| match t {
                    aegis_core::tier::Tier::Critical => "critical",
                    aegis_core::tier::Tier::High => "high",
                    aegis_core::tier::Tier::Medium => "medium",
                    aegis_core::tier::Tier::CatchAll => "catch_all",
                }
                .to_string()),
            })
            .collect(),
    );

    // CI-T4 — wire the SLO engine. `default_objectives()` covers
    // availability + audit delivery + overhead. The engine is
    // also fed by the audit-bus drain task spawned below so
    // /api/slo + /api/alerts return live data.
    let slo_engine = Arc::new(
        aegis_control::slo::SloEngine::new(aegis_control::slo::default_objectives()),
    );
    services.tracking.set_slo_engine(Arc::clone(&slo_engine));

    // CI-T4 — wire the cert inventory provider. Reads PEM files
    // referenced by `cfg.tls.certificates` on every /api/certs
    // call — cheap (small files, parsed off the hot path) and
    // reflects hot-reloads automatically.
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
                    services.attacks.set_geo_lookup(Arc::new(reader));
                    tracing::info!(
                        country = ?cfg.geoip.country_db,
                        asn = ?cfg.geoip.asn_db,
                        "geoip reader wired into AttacksHandler",
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
    // handlers that mutate the same ArcSwap + ring.
    let shared_receivers: Arc<arc_swap::ArcSwap<Vec<aegis_control::slo::AlertReceiver>>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(
            aegis_control::slo::default_receivers(),
        ));
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

    // MTLS-T6 — wire the IdentityTracker so the read-only
    // /api/mtls/* endpoints have a live data source. MTLS-T3
    // populates `record_request` from the data-plane accept
    // loop; here we only load the CA bundle summary so
    // `/api/mtls/ca-summary` lights up immediately at boot.
    if let Some(ca_path) = cfg
        .tls
        .as_ref()
        .and_then(|t| t.client_auth.as_ref())
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
    // SC-T1 — wire the live `StateBackend` so `/api/state` can
    // call `health()`. The handle is the same metered backend
    // every other consumer reads, so the dashboard sees the same
    // round-trip latency the data plane does.
    services.state_backend = Some(state_backend);
    // Phase-1 analytics — share the per-stage duration histogram
    // so `/api/analytics/latency` can compute p50/p95/p99 from
    // the same series the data plane records.
    services.request_stage_hist = Some(request_stage_hist.clone());
    // HACK-T3 — wire the same detector list the data plane
    // runs so `/api/rules/simulate` can evaluate against an
    // identical chain.
    services.detectors = Some(detectors);
    // MTLS-T7 — Allowed SAN allowlist. Seeded from
    // `cfg.tls.client_auth.allowed_sans` (empty when client-auth
    // is disabled or no SANs were configured). The store is hot-
    // reloadable: dashboard PUT/DELETE handlers call
    // `store.store(..)` / `store.remove(..)` to rotate it without
    // a restart, and the listener identity extractor consults it
    // through `extract_identity_with_allowlist`.
    {
        let initial: Vec<String> = cfg
            .tls
            .as_ref()
            .and_then(|t| t.client_auth.as_ref())
            .map(|ca| ca.allowed_sans.clone())
            .unwrap_or_default();
        services.allowed_sans = Some(
            aegis_control::api::mtls::AllowedSansStore::from(initial),
        );
    }

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

    // CI-T4 — drive the SLO engine from the audit bus. Every
    // `Detection` / `Access` event with `action == "allow"` is a
    // 1.0 availability sample; everything else (block, challenge,
    // rate_limit) is a 0.0 sample. Every event landing here also
    // counts as a 1.0 audit-delivery sample (we observed it).
    {
        let engine = Arc::clone(&slo_engine);
        let mut rx = services.bus.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        let allow = ev.action == "allow";
                        engine.record(aegis_control::slo::SliSample {
                            kind: aegis_control::slo::SliKind::DataPlaneAvailability,
                            value: if allow { 1.0 } else { 0.0 },
                            ts: ev.ts,
                        });
                        engine.record(aegis_control::slo::SliSample {
                            kind: aegis_control::slo::SliKind::AuditDeliveryRate,
                            value: 1.0,
                            ts: ev.ts,
                        });
                    }
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
        tokio::spawn(async move {
            let mut tick =
                tokio::time::interval(std::time::Duration::from_secs(30));
            tick.tick().await; // skip the immediate first tick
            loop {
                tick.tick().await;
                let new_alerts = engine.evaluate();
                if new_alerts.is_empty() {
                    continue;
                }
                let receivers = (**shared.load()).clone();
                for alert in &new_alerts {
                    let summary =
                        aegis_control::slo::dispatch::send_alert(alert, &receivers).await;
                    let now = chrono::Utc::now().timestamp();
                    for name in &summary.delivered {
                        // VipTalk dispatch with the `alerts`
                        // feature off is logged as a no-op +
                        // counted in `delivered` — the dispatch
                        // module currently treats both states
                        // the same on the summary side. Until
                        // we split that signal, mark `delivered`
                        // as `ok`; the dashboard can layer on
                        // `skipped_no_feature` when CC-T2.1.b
                        // refactors `DispatchSummary` to carry
                        // it explicitly.
                        ring.record_delivered(name, now);
                    }
                    for name in &summary.external {
                        ring.record_external(name, now);
                    }
                    for (name, reason) in &summary.failed {
                        ring.record_failed(name, now, reason);
                    }
                    tracing::info!(
                        sli = ?alert.sli,
                        severity = ?alert.severity,
                        burn_rate = alert.burn_rate,
                        delivered = summary.delivered.len(),
                        failed = summary.failed.len(),
                        external = summary.external.len(),
                        "slo alert dispatched",
                    );
                }
            }
        });
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

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
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
                        return Ok::<_, Infallible>(admin_sse::sse_response(
                            &services.bus,
                            &query,
                        ));
                    }
                    let resp = handle_admin_request(
                        req, peer, &cfg, &readiness, &startup, &metrics, &services,
                    )
                    .await;
                    Ok::<_, Infallible>(admin_sse::into_boxed(resp))
                }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!("admin connection from {peer} closed: {e}");
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
    bus: AuditBus,
    upstream_ctx: Arc<crate::proxy::ProxyContext>,
    tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
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
) {
    loop {
        let (stream, peer) = match tcp.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("accept error: {e}");
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
        let bus = bus.clone();
        let upstream_ctx = upstream_ctx.clone();
        let interop = interop.clone();
        let acceptor = tls_acceptor.clone();
        let decision_metrics = decision_metrics.clone();
        let detector_hit_metrics = detector_hit_metrics.clone();
        let identity_tracker = identity_tracker.clone();
        tokio::spawn(async move {
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
            let served = match acceptor {
                Some(acc) => match acc.accept(stream).await {
                    Ok(tls_stream) => {
                        // Pull peer cert chain off the verified
                        // session. `chain_ok = true` because the
                        // verifier ran (MTLS-T2) — Optional mode
                        // can produce `None` if no cert was
                        // offered, which T3 maps to Anonymous.
                        let id = {
                            let (_io, conn) = tls_stream.get_ref();
                            crate::listener::identity::extract_identity_from_peer_certs(
                                conn.peer_certificates(),
                                true,
                            )
                        };
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
                    Some(ServedIo::Plain(stream))
                }
            };
            let conn_identity_for_svc = conn_identity.clone();
            let identity_tracker_for_svc = identity_tracker.clone();
            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let conn_identity = conn_identity_for_svc.clone();
                let identity_tracker = identity_tracker_for_svc.clone();
                let detectors = detectors.clone();
                let mask = mask.clone();
                let risk = risk.clone();
                let ip_rate_limiter = ip_rate_limiter.clone();
                let load_gauge = load_gauge.clone();
                let verbosity = verbosity.clone();
                let request_stage_hist = request_stage_hist.clone();
                let bus = bus.clone();
                let upstream_ctx = upstream_ctx.clone();
                let interop = interop.clone();
                let decision_metrics = decision_metrics.clone();
                let detector_hit_metrics = detector_hit_metrics.clone();
                async move {
                    let method = req.method().clone();
                    let path = req.uri().path().to_string();
                    let (resp, decision) = handle_data_request(
                        req,
                        peer,
                        &detectors,
                        &mask,
                        &risk,
                        &ip_rate_limiter,
                        &load_gauge,
                        &verbosity,
                        &request_stage_hist,
                        &bus,
                        &upstream_ctx,
                        &detector_hit_metrics,
                        // MTLS-T4 — per-connection identity threads
                        // through to the route-scoped policy gate.
                        &conn_identity,
                    ).await;
                    // PROM-T1 — record one increment of
                    // `waf_requests_total{action}` per request.
                    // Cost: ~30 ns (label lookup + atomic inc).
                    decision_metrics.record(decision.action);
                    // OTEL-T3 note: action is recorded on the
                    // request span from inside handle_data_request
                    // (the span is only active during that
                    // function's body, not at this call site).
                    let risk_score = risk
                        .snapshot(peer.ip())
                        .map(|s| s.score)
                        .unwrap_or(0);

                    // CI-T11 — broadcast every request decision to
                    // the audit bus so /dashboard/sse Live Feed is
                    // truly live. The bus subscriber count drives
                    // whether send() actually reaches anyone; this
                    // is a cheap fire-and-forget on the hot path.
                    let action = decision.action.as_str();
                    let class = match action {
                        "allow" => aegis_core::audit::AuditClass::Access,
                        _      => aegis_core::audit::AuditClass::Detection,
                    };
                    let request_id = blake3::hash(
                        format!(
                            "{peer}:{}:{path}",
                            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                        )
                        .as_bytes(),
                    )
                    .to_hex()
                    .to_string();
                    let event = aegis_core::audit::AuditEvent {
                        schema_version: 1,
                        ts: chrono::Utc::now(),
                        request_id: request_id.clone(),
                        class,
                        tenant_id: None,
                        tier: None,
                        action: action.to_string(),
                        reason: decision
                            .rule_id
                            .clone()
                            .unwrap_or_else(|| action.to_string()),
                        client_ip: peer.ip().to_string(),
                        route_id: None,
                        rule_id: decision.rule_id.clone(),
                        risk_score: Some(risk_score),
                        fields: serde_json::json!({
                            "method": method.as_str(),
                            "path": path,
                            "status": resp.status().as_u16(),
                        }),
                    };
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
                    let builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
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
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, svc)
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
