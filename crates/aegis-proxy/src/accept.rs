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
        // 2026-05-17 F-CRITICAL-003 — TOTP fields plumbed from cfg
        // so `api::login::authenticate` runs the second-factor step
        // when `dashboard_auth.totp_enabled = true`.
        totp_secret_b32: auth.totp_secret_b32.clone(),
        totp_enabled: auth.totp_enabled,
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

    // FIX 2026-05-03 — share access-list stores between
    // DashboardServices (CRUD via /api/blacklist + /api/whitelist)
    // and ProxyContext (runtime matcher in the data-plane
    // handler). Before this commit they were distinct Arc
    // instances, so adds via the dashboard never reached the
    // data plane. Now they're the same Arc.
    services.blacklist = upstream_ctx.blacklist.clone();
    services.whitelist = upstream_ctx.whitelist.clone();
    services.interop = interop.clone();

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
        let agg_for_reset = services.attacks_agg.clone();
        rt.control.register_reset_callback(std::sync::Arc::new(move || {
            agg_for_reset.reset();
        }));
    }

    // CI-T5 — seed `services.routes` from `cfg.routes` so
    // /api/routes returns the live routing trie. Hot-reload
    // re-invokes this through `cfg_swap` (TODO when route
    // hot-reload lands; today routes are boot-time only).
    // PR1: priority is computed from the same routes the trie
    // sees, so dashboard ordering matches resolution.
    services
        .routes
        .set(crate::route::route_summaries(&cfg.routes));

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
                    let reader_arc: Arc<dyn aegis_security::geoip::GeoIpLookup> =
                        Arc::new(reader);
                    services.attacks.set_geo_lookup(reader_arc.clone());
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
    services.route_writer = Some(route_writer);
    if let Some(toggle) = ai_toggle {
        services.ai_toggle = Some(
            toggle as Arc<dyn aegis_control::api::ai_toggle::AiToggleWriter>,
        );
    }
    // 2026-05-11 PR #7 — surface the live `Pipeline` as the
    // response-filter writer so `PUT /api/response-filter` can
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
    // MTLS-T8 — seed the runtime mode store with the configured
    // `cfg.tls.client_auth.mode` so `/api/mtls/mode` can render
    // the configured / override / effective triple correctly.
    {
        let configured_mode = cfg
            .tls
            .as_ref()
            .and_then(|t| t.client_auth.as_ref())
            .map(|ca| ca.mode)
            .unwrap_or(aegis_core::config::ClientAuthMode::Disabled);
        services.mtls_mode_store = Arc::new(
            aegis_control::api::mtls_mode::ClientAuthModeStore::with_configured(configured_mode),
        );
    }
    // MTLS-T10 — surface the operator's opt-in for the CA bundle
    // upload card. Default off; flip via
    // `cfg.admin.dashboard_auth.allow_ca_upload: true`.
    services.allow_ca_upload = cfg.admin.dashboard_auth.allow_ca_upload;
    // MTLS-T10 Phase 2 — share the live trust store as a type-erased
    // writer so the audit-mutated PUT handler can hot-swap roots.
    services.trust_anchor_writer = client_trust
        .clone()
        .map(|store| -> Arc<dyn aegis_control::api::mtls_ca_bundle::TrustAnchorWriter> {
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

    // 2026-05-09 — share the DDoS runtime (already installed on
    // ProxyContext at boot in `run.rs`) with the dashboard so
    // `/api/gates/ddos` can read live telemetry. `OnceLock::get`
    // returns `None` until the proxy boot path has installed it
    // and `ProxyContext::ddos.set(...)` has been called; the
    // dashboard renders an empty-state card in that case.
    services.ddos = upstream_ctx.ddos.get().cloned();

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

            match io {
                AdminIo::Tls(tls_stream) => {
                    let io = TokioIo::new(tls_stream);
                    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                        tracing::debug!("admin TLS connection from {peer} closed: {e}");
                    }
                }
                AdminIo::Plain(stream) => {
                    let io = TokioIo::new(stream);
                    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
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
        let identity_tracker = identity_tracker.clone();
        // FDP-T4 — admit a slot in the shared in-flight counter
        // for this data-plane connection. Cloned out here so it
        // moves into the spawned task; guard drops when the
        // task ends. Used by the SIGUSR2 handover's drain
        // phase to know when in-flight=0.
        let conn_inflight = upstream_ctx.inflight.clone();
        tokio::spawn(async move {
            let _admit = conn_inflight.admit();
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
                    // v2.3 contract (deploy/STAGING-BENCHMARK.md §7.5):
                    // the OC benchmarker hits /__waf_control/* on the
                    // public TLS data plane, not the admin port. Short-
                    // circuit the security pipeline here so the control
                    // surface is reachable on whichever listener the
                    // operator exposes externally. Auth via
                    // X-Benchmark-Secret is enforced inside the handler.
                    if path.starts_with("/__waf_control/") {
                        if let Some(rt) = interop.as_ref() {
                            // NEW-2 (2026-05-08) — pass through
                            // the PoW issuer + state backend so
                            // /__waf_control/challenge_verify can
                            // validate solutions. Both are
                            // installed once at boot from run.rs.
                            let resp = crate::admin_dispatch::handle_interop_control_with_rt(
                                req,
                                rt.as_ref(),
                                upstream_ctx.pow_issuer.get(),
                                Some(&state_backend_for_interop),
                            ).await;
                            // F-CRITICAL-001 (2026-05-17 s-tester
                            // audit): control-endpoint responses
                            // previously short-circuited before
                            // `stamp_interop_response`, so the 6
                            // mandatory v2.3 §5 headers
                            // (`X-WAF-Request-Id`, `-Action`,
                            // `-Mode`, `-Cache`, `-Risk-Score`,
                            // `-Overhead-Latency`) were missing on
                            // every /__waf_control/* call. Stamp
                            // them now with a DecisionTag::allow
                            // — control endpoints are not security
                            // decisions, but the OC harness asserts
                            // header presence uniformly across the
                            // listener.
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
                            return Ok::<_, Infallible>(resp);
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
                        &route_latency_hist,
                        &route_activity,
                        &detector_latency_hist,
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
                    let risk_score = risk
                        .snapshot(peer.ip())
                        .map(|s| s.score)
                        .unwrap_or(0);

                    // CI-T11 — broadcast every request decision to
                    // the audit bus so /dashboard/sse Live Feed is
                    // truly live. The bus subscriber count drives
                    // whether send() actually reaches anyone; this
                    // is a cheap fire-and-forget on the hot path.
                    //
                    // 2026-05-03 — skip the listener-side emit on
                    // BLOCK actions: the data-plane block path
                    // (`forward_allow_to_upstream` → detector
                    // chain) already emitted a richer Detection
                    // event with `fields.detectors[]` + `strikes`
                    // + `load_mode` + the XFF-resolved
                    // `client_ip`.  Double-writing here was
                    // creating two audit rows per blocked
                    // request — one with peer-IP + bot_category,
                    // one with XFF-resolved client_ip + detectors
                    // — which inflated /api/attacks/top with a
                    // phantom loopback attacker and doubled the
                    // by-detector counts.  For allow / challenge
                    // we keep the listener emit (no data-plane
                    // block path runs there).
                    let action = decision.action.as_str();
                    if action == "block" {
                        // Update MTLS tracker + interop response
                        // stamping below, but skip the
                        // bus.emit() entirely — the data plane
                        // already audited this block.
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
                    let bot_signals = aegis_security::bots::BotSignals {
                        ja4_fingerprint: None,
                        h2_fingerprint: None,
                        user_agent: user_agent.clone(),
                        has_cookies,
                        has_js_challenge_pass: false,
                        failed_challenges: 0,
                        reverse_dns: None,
                    };
                    let bot_category = match aegis_security::bots::BotClassifier::default()
                        .classify(&bot_signals)
                    {
                        aegis_security::bots::BotTier::GoodBot   => Some("verified"),
                        aegis_security::bots::BotTier::LikelyBot => Some("suspect"),
                        aegis_security::bots::BotTier::KnownBad  => Some("malicious"),
                        // Human + Unknown do not count toward bot-mix.
                        _ => None,
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
                            // Only present when classifier returns
                            // a real bot tier — Human / Unknown
                            // are skipped so they don't count
                            // toward the bot-mix chart.
                            "bot_category": bot_category,
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
