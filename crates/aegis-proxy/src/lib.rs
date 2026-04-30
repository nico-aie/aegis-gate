// aegis-proxy: data-plane proxy core (M1)
//
// Owns: listeners, TLS, routing, upstream pools, transforms,
//       state backend impls, service discovery, caching, load shedding.

use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Response;
use hyper_util::rt::TokioIo;

use aegis_core::config::WafConfig;
use aegis_core::pipeline::SecurityPipeline;
use aegis_core::state::StateBackend;
use aegis_core::{AuditBus, ReadinessSignal};

pub mod acme;
pub mod acme_instant;
pub mod admin_sse;
pub mod benchmark;
pub mod cache;
pub mod cluster;
pub mod cluster_lease;
pub mod dr;
pub mod hotbin;
pub mod listener;
pub mod ocsp;
pub mod proto;
pub mod proxy;
pub mod quota;
pub mod route;
pub mod sd;
pub mod secrets;
pub mod session;
pub mod shed;
pub mod state;
pub mod supervisor;
pub mod traffic;
pub mod transform;
pub mod upstream;

/// Boot the data-plane proxy + admin (control-plane) listener.
///
/// Binds each listener in `cfg.listeners.data`, spawns accept loops, and
/// starts the admin listener on `cfg.listeners.admin.bind`.
/// Serves until the process receives SIGTERM / Ctrl-C.
///
/// `lease_store` provides the cluster-wide lease used to gate
/// leader-only tasks (B1-T4 — ACME today; GitOps / threat-intel /
/// witness once they're wired). For single-node deployments
/// `aegis-bin` passes an `InProcessLease`; for multi-node it
/// passes a `RedisLease`.
pub async fn run(
    cfg: Arc<WafConfig>,
    _pipeline: Arc<dyn SecurityPipeline>,
    state: Arc<dyn StateBackend>,
    lease_store: Arc<dyn aegis_core::cluster::LeaseStore>,
    bus: AuditBus,
    readiness: ReadinessSignal,
) -> aegis_core::Result<()> {
    let mut handles = Vec::new();

    // Build the detector set once, shared across all data-plane listeners.
    let detectors: Arc<Vec<Box<dyn aegis_security::detectors::Detector>>> =
        Arc::new(aegis_security::detectors::default_detectors());

    // Hot-reloadable detector class mask. Initial state mirrors
    // `cfg.detectors`; the control plane swaps it via PUT
    // `/api/detectors` (P2 of the security-toggle plan).
    let mask = aegis_security::detectors::SharedDetectorMask::from_config(&cfg.detectors);

    // P6 risk tracker. Per-IP score + lifetime strikes shared
    // between data plane (records signals + classifies for
    // adaptive mitigation) and control plane (renders /api/risk
    // + handles operator reset).
    let risk = aegis_security::risk::RiskTracker::new(&cfg.risk);

    // F-T2 — per-IP rate limiter. Built from the first
    // `cfg.rate_limit.buckets` entry that scopes globally to
    // the IP discriminator. Falls back to library defaults
    // (1 000 req / 60 s) when no such bucket is configured —
    // safer than running with no volumetric guard at all.
    let ip_rate_cfg = cfg
        .rate_limit
        .buckets
        .iter()
        .find(|b| {
            matches!(b.scope, aegis_core::config::RlScope::Global)
                && matches!(b.key, aegis_core::config::RlKey::Ip)
        })
        .map(|b| aegis_security::rate_limit::IpRateLimitConfig {
            limit: b.limit.min(u32::MAX as u64) as u32,
            window: b.window,
        })
        .unwrap_or_default();
    let ip_rate_limiter = Arc::new(
        aegis_security::rate_limit::IpRateLimiter::new(ip_rate_cfg),
    );

    // F-T10 — per-stage latency histogram. Build the metrics
    // registry once here so both the data plane (which now
    // emits `waf_request_duration_ms`) and the admin plane
    // (which exposes `/metrics`) share the same series.
    let metrics = aegis_control::metrics::MetricsRegistry::init();
    let request_stage_hist = std::sync::Arc::new(
        aegis_control::metrics::request_duration::RequestStageHistogram::register(&metrics)
            .expect("histogram registration failed"),
    );

    // P7 load gauge. Hot path bumps the request counter; the
    // background sampler reads it and updates the live LoadMode.
    // Hot path + control plane share the same handle.
    let load_gauge = aegis_core::LoadGauge::new(cfg.load_mode.clone());
    let _sampler = load_gauge.clone().spawn_sampler();

    // P8 verbosity. Operator-controlled audit-emission filter.
    // Hot path skips event emission below this level; control
    // plane reads/writes via /api/logging.
    let verbosity = aegis_core::SharedVerbosity::from_config(&cfg.logging);

    // Carry-over A (post-2026-04-29 perf re-run) — the Allow
    // branch in `handle_data_request` previously returned a
    // synthetic `OK\n` body; we now resolve a real upstream
    // member via `crate::proxy::ProxyContext` and call
    // `crate::upstream::forward::forward()`. The `pipeline`
    // field on ProxyContext is unused by the forward path,
    // so passing the workspace `NoopPipeline` here is a
    // placeholder until the parallel pipelines converge.
    let upstream_ctx = Arc::new(
        crate::proxy::ProxyContext::build(
            &cfg,
            Arc::new(aegis_security::NoopPipeline),
        )?,
    );

    // Carry-over 5 (post-2026-04-29 cluster smoke) — build a
    // single `TlsAcceptor` once if `cfg.tls.certificates` is
    // populated. Each data listener that flips
    // `tls: true` reuses this acceptor; the rest stay plain
    // TCP. `key_ref` is treated as a file path here; secret-
    // manager resolution (`${secret:vault:...}`) for keys is a
    // separate task.
    let tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>> =
        match cfg.tls.as_ref() {
            Some(tls_cfg) if !tls_cfg.certificates.is_empty() => {
                let entries: Vec<(_, _, &[String])> = tls_cfg
                    .certificates
                    .iter()
                    .map(|c| {
                        let hosts: &[String] = &c.hosts;
                        (c.cert_path.clone(), std::path::PathBuf::from(&c.key_ref), hosts)
                    })
                    .collect();
                let store = crate::listener::tls::CertStore::load(&entries)
                    .map_err(|e| {
                        aegis_core::WafError::Config(format!(
                            "tls.certificates: failed to load cert/key pairs: {e}"
                        ))
                    })?;
                let resolver = Arc::new(crate::listener::tls::DynamicResolver::new(
                    Arc::new(arc_swap::ArcSwap::from_pointee(store)),
                ));
                let mut server_cfg = crate::listener::tls_policy::build_hardened_server_config(
                    resolver,
                    tls_cfg.min_version.as_deref(),
                )
                .map_err(|e| {
                    aegis_core::WafError::Config(format!(
                        "tls: rustls config build failed: {e}"
                    ))
                })?;
                // Carry-over 5: the data-plane handler in
                // `accept_loop` runs HTTP/1.1 only — restrict
                // ALPN here so curl + browsers don't negotiate
                // HTTP/2 and stall waiting for an H2 server.
                // Auto-detecting HTTP/2 on the data plane is a
                // separate task.
                server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
                Some(Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(
                    server_cfg,
                ))))
            }
            _ => None,
        };

    // external interop contract surface . Built
    // here so it's available to the data-plane accept_loop and
    // later threaded into `DashboardServices` for the admin
    // control plane. Opted in via `cfg.interop.enabled`.
    let interop_runtime = build_interop_runtime(
        &cfg,
        &risk,
        &ip_rate_limiter,
    );
    if let Some(rt) = interop_runtime.as_ref() {
        if let Some(sink) = rt.audit.as_ref() {
            tracing::info!(
                audit_path = %sink.path().display(),
                "external interop contract enabled — control plane on /__waf_control",
            );
        } else {
            tracing::info!(
                "external interop contract enabled (audit log path not configured)",
            );
        }
    }

    // Data-plane listeners.
    for listener_cfg in &cfg.listeners.data {
        let addr = listener_cfg.bind;
        let tcp = tokio::net::TcpListener::bind(addr).await?;
        let listener_tls = listener_cfg.tls;
        tracing::info!(
            "data-plane listening on {addr} (tls={})",
            listener_tls
        );
        if listener_tls && tls_acceptor.is_none() {
            return Err(aegis_core::WafError::Config(format!(
                "listener {addr} has tls: true but no `tls.certificates` configured"
            )));
        }

        let detectors = detectors.clone();
        let mask = mask.clone();
        let risk = risk.clone();
        let ip_rate_limiter = ip_rate_limiter.clone();
        let load_gauge = load_gauge.clone();
        let verbosity = verbosity.clone();
        let request_stage_hist = request_stage_hist.clone();
        let bus = bus.clone();
        let upstream_ctx_l = upstream_ctx.clone();
        let acceptor = if listener_tls { tls_acceptor.clone() } else { None };
        let interop_l = interop_runtime.clone();
        handles.push(tokio::spawn(accept_loop(
            tcp,
            detectors,
            mask,
            risk,
            ip_rate_limiter,
            load_gauge,
            verbosity,
            request_stage_hist,
            bus,
            upstream_ctx_l,
            acceptor,
            interop_l,
        )));
    }

    // P5 ACME challenge store. Shared between the AcmeManager
    // (which publishes new tokens) and the force-https listener
    // (which serves them on `/.well-known/acme-challenge/`).
    let challenges = crate::acme::ChallengeStore::new();

    // F-T8 + B1-T4 — wire AcmeManager + renewal scheduler when
    // `tls.acme` is set in YAML, gated on the leader lease so
    // exactly one node in a cluster issues each cert. The
    // data-plane listener stays plain HTTP today (the
    // cert-store hot-swap into a TLS listener is a deeper
    // migration, deferred); but first-issuance, persistence,
    // and the renewal loop run on the lease holder.
    if let Some(acme_yaml) = cfg.tls.as_ref().and_then(|t| t.acme.as_ref()) {
        let acme_cfg = crate::acme::AcmeConfig::from_core(acme_yaml);
        let provider = std::sync::Arc::new(crate::acme_instant::InstantAcmeProvider::new());

        // The cert writer is the integration seam. Today it
        // logs + relies on persist_issued having already
        // written the PEMs to disk in
        // InstantAcmeProvider::finalize_and_download. A future
        // commit replaces this stub with `cert_store.store(...)`
        // once the data-plane listener terminates TLS.
        let cert_writer: crate::acme::CertWriter = std::sync::Arc::new(|issued| {
            tracing::info!(
                domains = ?issued.domains,
                "acme: cert issued and persisted to disk \
                 (cert-store hot-swap deferred)",
            );
            Ok(())
        });

        let manager = std::sync::Arc::new(crate::acme::AcmeManager::new(
            acme_cfg,
            provider,
            challenges.clone(),
            cert_writer,
        ));
        let cert_dir = manager.config().cert_dir.clone();

        // ACME runs only on the leader. The lease key is the
        // contract — every node uses the same string. TTL is
        // 60s, comfortably longer than a typical issue
        // round-trip (~5–15s) and short enough to fail over
        // within a minute if the leader dies. The runner
        // re-acquires after each loss with a half-TTL backoff.
        let lease_store_for_acme = lease_store.clone();
        let manager_for_runner = std::sync::Arc::clone(&manager);
        handles.push(crate::cluster_lease::spawn_with_lease(
            lease_store_for_acme,
            "leader:acme",
            std::time::Duration::from_secs(60),
            move |_holder, lost| {
                let manager = std::sync::Arc::clone(&manager_for_runner);
                let cert_dir = cert_dir.clone();
                async move {
                    // Initial issuance, then the renewal
                    // scheduler. Both are cancelled if the
                    // lease is lost.
                    let inventory: crate::acme::CertInventory = std::sync::Arc::new(move || {
                        let mut out = Vec::new();
                        if let Ok(rd) = std::fs::read_dir(&cert_dir) {
                            for entry in rd.flatten() {
                                let p = entry.path().join("cert.pem");
                                if let Ok(bytes) = std::fs::read(&p) {
                                    out.push(bytes);
                                }
                            }
                        }
                        out
                    });
                    let renewer = crate::acme::spawn_renewal_scheduler(
                        std::sync::Arc::clone(&manager),
                        inventory,
                    );

                    if let Err(e) = manager.issue().await {
                        tracing::warn!(
                            error = %e,
                            "acme: initial issuance failed; renewal scheduler will retry",
                        );
                    } else {
                        tracing::info!("acme: initial issuance succeeded (leader)");
                    }

                    // Park here until the lease is lost. When
                    // it fires, abort the renewal task and
                    // return so the runner re-acquires.
                    lost.notified().await;
                    renewer.abort();
                    tracing::info!("acme: lease lost; renewal task aborted");
                }
            },
        ));
    }

    // TODO(B1-T4 follow-up): when GitOps poll, witness export,
    // and threat-intel fetcher are wired into the boot path,
    // gate each on a `"leader:<name>"` lease using the same
    // `crate::cluster_lease::spawn_with_lease(...)` pattern.
    // None of those subsystems run as background tasks today,
    // so there's no live code to gate; documenting the seam here
    // so the next dev knows where it goes.

    // P4 force-HTTPS redirect listener (optional). Spawns only if
    // `listeners.force_https` is set. Also responds to HTTP-01
    // challenges from the ACME directory when it has a token to
    // serve (P5).
    if let Some(redirect_cfg) = cfg.listeners.force_https.as_ref() {
        let addr = redirect_cfg.bind;
        let status = redirect_cfg.status;
        let tcp = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("force-https redirect listening on {addr}");
        let challenges = challenges.clone();
        handles.push(tokio::spawn(force_https_loop(tcp, status, challenges)));
    }

    // Admin (control-plane) listener.
    let admin_addr = cfg.listeners.admin.bind;
    let admin_tcp = tokio::net::TcpListener::bind(admin_addr).await?;
    tracing::info!("admin-plane listening on {admin_addr}");

    let admin_cfg = cfg.clone();
    let admin_readiness = readiness.clone();
    let admin_bus = bus;
    let admin_mask = mask.clone();
    let admin_risk = risk.clone();
    let admin_ip_rate_limiter = ip_rate_limiter.clone();
    let admin_load_gauge = load_gauge.clone();
    let admin_verbosity = verbosity.clone();
    let admin_metrics = metrics.clone();
    let admin_lease_store = lease_store.clone();
    let admin_interop = interop_runtime.clone();
    handles.push(tokio::spawn(admin_accept_loop(
        admin_tcp,
        admin_cfg,
        admin_readiness,
        admin_bus,
        admin_mask,
        admin_risk,
        admin_ip_rate_limiter,
        admin_load_gauge,
        admin_verbosity,
        admin_metrics,
        admin_lease_store,
        admin_interop,
    )));

    readiness.config_loaded.store(true, Ordering::Relaxed);
    readiness.certs_loaded.store(true, Ordering::Relaxed);
    readiness.pool_has_healthy.store(true, Ordering::Relaxed);

    // B1-T5 — readiness gate. Hold `state_backend_up` at false
    // until the rehydrate probe round-trips through the
    // `StateBackend`. While that flag is false, the existing
    // `ReadinessSignal::is_ready()` returns false, so
    // `/healthz/ready` continues to return 503 — exactly the
    // behaviour we want for a fresh node booted against a
    // shared Redis. The deadline comes from
    // `cfg.state.reconcile.readiness_warm_ms` (default 5 s).
    //
    // Even if rehydrate fails (e.g. unreachable Redis, bad
    // password) we flip readiness to true at the deadline — a
    // mis-configured backend must never permanently 503 the
    // node; the operator gets a `tracing::warn` line + a
    // detailed error in the result.
    {
        let store = std::sync::Arc::clone(&state);
        let readiness_for_warmup = readiness.clone();
        let deadline = cfg.state.reconcile.readiness_warm_ms;
        tokio::spawn(async move {
            let result = crate::state::rehydrate(store, deadline).await;
            if result.completed {
                tracing::info!(
                    elapsed_ms = result.elapsed.as_millis() as u64,
                    "state backend rehydrate succeeded; readiness flipped to ready",
                );
            } else {
                tracing::warn!(
                    elapsed_ms = result.elapsed.as_millis() as u64,
                    deadline_ms = deadline.as_millis() as u64,
                    error = result.error.unwrap_or_default(),
                    "state backend rehydrate did not complete; flipping readiness anyway to avoid permanent 503",
                );
            }
            readiness_for_warmup
                .state_backend_up
                .store(true, Ordering::Relaxed);
        });
    }

    // Hold alive until shutdown signal.
    //
    // HA-T5 — drain-on-SIGTERM. The signal handler flips
    // `readiness.draining` first, holds for `drain_grace_ms`
    // (default 5 s) so external LBs notice via /healthz/ready
    // and stop sending us new traffic, then aborts the listeners.
    // In-flight requests have until the grace period to complete.
    let shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut term = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            ) {
                Ok(s) => s,
                Err(_) => {
                    ctrl_c.await.ok();
                    return;
                }
            };
            tokio::select! {
                _ = ctrl_c => {}
                _ = term.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
        }
    };
    shutdown.await;
    tracing::info!("shutdown signal received; flipping draining");
    readiness
        .draining
        .store(true, std::sync::atomic::Ordering::Release);
    let grace = std::time::Duration::from_millis(
        std::env::var("AEGIS_DRAIN_GRACE_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(5_000),
    );
    tracing::info!(grace_ms = grace.as_millis() as u64, "draining; awaiting grace");
    tokio::time::sleep(grace).await;
    tracing::info!("grace expired; aborting listeners");

    for h in handles {
        h.abort();
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn admin_accept_loop(
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
) {
    let startup = aegis_control::health::StartupProbe::default();
    startup.mark_started();
    // F-T10: metrics registry is now built in `run()` so the
    // data-plane histogram series is registered into the same
    // registry the `/metrics` endpoint scrapes.

    // Build the dashboard service bundle once at boot. The drain
    // task runs for the lifetime of the admin listener — see
    // `aegis-control::dashboard_services` (D-M2-T2.7).
    let pool_provider =
        aegis_control::dashboard_services::pool_snapshot_provider(&cfg);

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
    let services = Arc::new(services);

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

/// Async wrapper around the sync [`admin_router`]. Endpoints that
/// need to consume a request body (PUT/POST mutations) branch here
/// first — the rest fall through to the existing sync path.
async fn handle_admin_request(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    cfg: &WafConfig,
    readiness: &ReadinessSignal,
    startup: &aegis_control::health::StartupProbe,
    metrics: &aegis_control::metrics::MetricsRegistry,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    // F-T1 — auth front door. Login is open (rate-limited);
    // logout reads the session cookie. Both bypass the regular
    // admin_router because they need access to the auth runtime.
    if method == hyper::Method::POST && path == "/admin/login" {
        return handle_admin_login(req, peer, services).await;
    }
    if method == hyper::Method::POST && path == "/admin/logout" {
        return handle_admin_logout(req, services);
    }

    // HA-T5 — operator-initiated drain. Flips
    // `readiness.draining` so subsequent `/healthz/ready` probes
    // return 503; LBs (HAProxy / Nginx / k8s endpoints) stop
    // routing new traffic to this node within the next health
    // check interval. In-flight requests continue.
    if method == hyper::Method::POST && path == "/admin/drain" {
        return handle_admin_drain(req, readiness, services).await;
    }

    // external interop contract control plane .
    // Always under `/__waf_control/*`; auth via `X-Benchmark-Secret`.
    // No-op (404) when the binary was built without the
    // interop surface.
    if path.starts_with("/__waf_control/") {
        return handle_interop_control(req, services).await;
    }

    // P2 mutating endpoint: PUT /api/detectors. Reads body
    // asynchronously, runs through AuditedMutate.
    if method == hyper::Method::PUT && path == "/api/detectors" {
        return handle_detectors_put(req, cfg, services).await;
    }

    // P6 mutating endpoint: PUT /api/risk/{ip}/reset. Audit-mutated
    // operator override that clears strikes + score for one client.
    if method == hyper::Method::PUT && path.starts_with("/api/risk/") {
        if let Some(ip_seg) = path
            .strip_prefix("/api/risk/")
            .and_then(|s| s.strip_suffix("/reset"))
        {
            return handle_risk_reset(req, ip_seg, services).await;
        }
    }

    // P7 mutating endpoint: PUT /api/loadmode. Audit-mutated
    // operator override that pins / clears the live LoadMode.
    if method == hyper::Method::PUT && path == "/api/loadmode" {
        return handle_loadmode_put(req, services).await;
    }

    // P8 mutating endpoint: PUT /api/logging. Audit-mutated
    // verbosity level change.
    if method == hyper::Method::PUT && path == "/api/logging" {
        return handle_logging_put(req, services).await;
    }

    admin_router(req, cfg, readiness, startup, metrics, services)
}

async fn handle_logging_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let csrf_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_csrf"))
        .map(|s| s.to_string());
    let csrf_header = req
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let actor = req
        .headers()
        .get("x-actor")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("admin")
        .to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            blake3::hash(
                format!(
                    "logging-put:{}",
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string()
        });

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(
                    "failed to read request body".into(),
                ),
            );
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let parsed: aegis_control::api::logging::LoggingPutBody =
        match serde_json::from_str(body_str) {
            Ok(b) => b,
            Err(e) => {
                return mutation_error_response(
                    aegis_control::api::mutation::MutationError::Validation(e.to_string()),
                );
            }
        };

    let before = serde_json::to_value(services.verbosity.snapshot())
        .unwrap_or(serde_json::Value::Null);
    let after = serde_json::json!({"level": parsed.level});
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: csrf_cookie.as_deref(),
        csrf_header: csrf_header.as_deref(),
        actor: &actor,
        request_id: &request_id,
        resource: "/api/logging",
        action: "verbosity_set",
        reason: "operator changes verbosity",
    };
    let verbosity = services.verbosity.clone();
    let outcome = services.mutate.apply(&req_ctx, before, after, || {
        aegis_control::api::logging::apply_logging_put(&verbosity, parsed)
    });

    match outcome {
        Ok(_) => json_body_response(
            200,
            aegis_control::api::logging::render_logging_get(&services.verbosity),
            "private, no-store",
        ),
        Err(e) => mutation_error_response(e),
    }
}

async fn handle_loadmode_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let csrf_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_csrf"))
        .map(|s| s.to_string());
    let csrf_header = req
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let actor = req
        .headers()
        .get("x-actor")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("admin")
        .to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            blake3::hash(
                format!(
                    "loadmode-put:{}",
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string()
        });

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(
                    "failed to read request body".into(),
                ),
            );
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let parsed: aegis_control::api::load_mode::LoadModePutBody =
        match serde_json::from_str(if body_str.is_empty() { "{}" } else { body_str }) {
            Ok(b) => b,
            Err(e) => {
                return mutation_error_response(
                    aegis_control::api::mutation::MutationError::Validation(e.to_string()),
                );
            }
        };

    let before = serde_json::to_value(services.load_gauge.snapshot())
        .unwrap_or(serde_json::Value::Null);
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: csrf_cookie.as_deref(),
        csrf_header: csrf_header.as_deref(),
        actor: &actor,
        request_id: &request_id,
        resource: "/api/loadmode",
        action: "loadmode_set",
        reason: "operator pins load mode",
    };
    let gauge = services.load_gauge.clone();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        serde_json::Value::Null,
        || aegis_control::api::load_mode::apply_put_body(&gauge, parsed),
    );

    match outcome {
        Ok(_) => json_body_response(
            200,
            aegis_control::api::load_mode::render_get(&services.load_gauge),
            "private, no-store",
        ),
        Err(e) => mutation_error_response(e),
    }
}

async fn handle_risk_reset(
    req: hyper::Request<hyper::body::Incoming>,
    ip_segment: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let Some(ip) = aegis_control::api::risk::parse_ip_segment(ip_segment) else {
        return json_response(
            400,
            &serde_json::json!({"error": "invalid_ip", "segment": ip_segment}),
        );
    };

    let csrf_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_csrf"))
        .map(|s| s.to_string());
    let csrf_header = req
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let actor = req
        .headers()
        .get("x-actor")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("admin")
        .to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            blake3::hash(
                format!(
                    "risk-reset:{}:{}",
                    ip,
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string()
        });

    let resource = format!("/api/risk/{ip}/reset");
    let before = services
        .risk
        .snapshot_wire(ip)
        .map(|s| serde_json::to_value(s).unwrap_or(serde_json::Value::Null))
        .unwrap_or(serde_json::Value::Null);

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: csrf_cookie.as_deref(),
        csrf_header: csrf_header.as_deref(),
        actor: &actor,
        request_id: &request_id,
        resource: &resource,
        action: "risk_reset",
        reason: "operator clears risk state",
    };
    let risk = services.risk.clone();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        serde_json::json!({"score": 0, "strikes": 0}),
        || {
            let removed = risk.reset(ip);
            Ok::<bool, String>(removed)
        },
    );
    match outcome {
        Ok(o) => json_body_response(
            200,
            serde_json::json!({
                "ok": true,
                "ip": ip.to_string(),
                "had_state": o.value,
            })
            .to_string(),
            "private, no-store",
        ),
        Err(err) => mutation_error_response(err),
    }
}

async fn handle_detectors_put(
    req: hyper::Request<hyper::body::Incoming>,
    cfg: &WafConfig,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    // Pull CSRF cookie + header before consuming the body.
    let csrf_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_csrf"))
        .map(|s| s.to_string());
    let csrf_header = req
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let actor = req
        .headers()
        .get("x-actor")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("admin")
        .to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            blake3::hash(
                format!(
                    "detectors-put:{}",
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string()
        });

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            let err = aegis_control::api::mutation::MutationError::Internal(
                "failed to read request body".into(),
            );
            return mutation_error_response(err);
        }
    };
    let body_str = match std::str::from_utf8(body_bytes.as_ref()) {
        Ok(s) => s,
        Err(_) => {
            let err = aegis_control::api::mutation::MutationError::Validation(
                "request body is not valid UTF-8".into(),
            );
            return mutation_error_response(err);
        }
    };

    let put_body = match aegis_control::api::detectors::parse_full_put_body(body_str) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            );
        }
    };

    let modes: Vec<aegis_core::config::ComplianceMode> = cfg
        .compliance
        .as_ref()
        .map(|c| c.modes.clone())
        .unwrap_or_default();

    // Snapshot before/after states for the audit-chain diff. The
    // dashboard reads `diff.before` / `diff.after` to render a
    // "what changed" tooltip on the audit log row.
    let before_state = services.detector_mask.load_state();
    let proposed_state = match aegis_control::api::detectors::apply_put_body(
        before_state.clone(),
        put_body,
        &modes,
    ) {
        Ok(s) => s,
        Err(violations) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(violations.join("; ")),
            );
        }
    };

    let before = mask_state_to_json(&before_state);
    let after = mask_state_to_json(&proposed_state);

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: csrf_cookie.as_deref(),
        csrf_header: csrf_header.as_deref(),
        actor: &actor,
        request_id: &request_id,
        resource: "/api/detectors",
        action: "update",
        reason: "detector class toggle",
    };
    let mask_handle = services.detector_mask.clone();
    let outcome = services.mutate.apply(&req_ctx, before, after, || {
        mask_handle.store_state(proposed_state.clone());
        Ok::<(), String>(())
    });

    match outcome {
        Ok(_) => {
            let body = aegis_control::api::detectors::render_get(
                &services.detector_mask,
                &modes,
            );
            json_body_response(200, body, "private, no-store")
        }
        Err(e) => mutation_error_response(e),
    }
}

fn mutation_error_response(
    err: aegis_control::api::mutation::MutationError,
) -> Response<Full<Bytes>> {
    json_body_response(err.http_status(), err.to_body(), "private, no-store")
}

async fn handle_admin_login(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let user_agent = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return json_body_response(
                400,
                serde_json::json!({"ok":false,"reason":"bad_request",
                                   "message":"failed to read request body"})
                    .to_string(),
                "private, no-store",
            );
        }
    };
    process_admin_login(services, peer, &user_agent, body_bytes.as_ref())
}

/// Pure body of the login handler — no `Incoming`, so unit
/// tests can drive it without faking a TCP body. The async
/// wrapper above just collects the body and delegates here.
fn process_admin_login(
    services: &aegis_control::dashboard_services::DashboardServices,
    peer: std::net::SocketAddr,
    user_agent: &str,
    body_bytes: &[u8],
) -> Response<Full<Bytes>> {
    let body_str = std::str::from_utf8(body_bytes).unwrap_or("");
    let outcome = aegis_control::api::login::authenticate(
        body_str,
        &services.admin_identity,
        &services.login_rate_limiter,
        &services.auth_sessions,
        &services.sessions,
        &peer.ip().to_string(),
        user_agent,
        services.session_idle_seconds,
    );

    use aegis_control::api::login::LoginOutcome;
    match outcome {
        LoginOutcome::Ok {
            session_cookie,
            csrf_cookie,
            body,
        } => Response::builder()
            .status(200)
            .header("content-type", "application/json; charset=utf-8")
            .header("cache-control", "no-store")
            .header("set-cookie", session_cookie)
            .header("set-cookie", csrf_cookie)
            .body(Full::new(Bytes::from(body)))
            .unwrap(),
        LoginOutcome::Unauthorized { body } => {
            json_body_response(401, body, "no-store")
        }
        LoginOutcome::RateLimited {
            retry_after_seconds,
            body,
        } => Response::builder()
            .status(429)
            .header("content-type", "application/json; charset=utf-8")
            .header("cache-control", "no-store")
            .header("retry-after", retry_after_seconds.to_string())
            .body(Full::new(Bytes::from(body)))
            .unwrap(),
        LoginOutcome::BadRequest { body } => {
            json_body_response(400, body, "no-store")
        }
    }
}

fn handle_admin_logout(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let cookie_value = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_session"))
        .map(|s| s.to_string());
    process_admin_logout(services, cookie_value.as_deref())
}

/// Pure body of logout — same testability story as
/// [`process_admin_login`].
fn process_admin_logout(
    services: &aegis_control::dashboard_services::DashboardServices,
    session_cookie: Option<&str>,
) -> Response<Full<Bytes>> {
    let outcome = aegis_control::api::login::logout(
        session_cookie,
        &services.auth_sessions,
        &services.sessions,
    );
    use aegis_control::api::login::LogoutOutcome;
    let (clear_session, clear_csrf) = match outcome {
        LogoutOutcome::Ok {
            clear_session_cookie,
            clear_csrf_cookie,
        }
        | LogoutOutcome::NoSession {
            clear_session_cookie,
            clear_csrf_cookie,
        } => (clear_session_cookie, clear_csrf_cookie),
    };
    Response::builder()
        .status(204)
        .header("cache-control", "no-store")
        .header("set-cookie", clear_session)
        .header("set-cookie", clear_csrf)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// HA-T5 — operator drain handler. Authenticated POST endpoint
/// that flips `readiness.draining` to true. Subsequent
/// `/healthz/ready` probes return 503 so external load
/// balancers stop routing new traffic. In-flight requests
/// continue. Idempotent — calling twice is a no-op.
async fn handle_admin_drain(
    req: hyper::Request<hyper::body::Incoming>,
    readiness: &ReadinessSignal,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use std::sync::atomic::Ordering;

    // Auth: require a valid admin session cookie. We don't gate
    // on CSRF the way mutating dashboard endpoints do — drain is
    // a server-local op that doesn't touch persisted config.
    let session_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_session"))
        .map(|s| s.to_string());
    let session_ok = match session_cookie.as_deref() {
        Some(sid) => services.auth_sessions.validate(sid).is_some(),
        None => false,
    };
    // Allow unauthenticated drain when the admin password
    // hash is the empty default (test/dev builds with no real
    // admin configured) OR when the operator has set
    // `AEGIS_DRAIN_TOKEN` and the request carries it as a
    // matching `X-Aegis-Drain-Token` header. The token path
    // exists so that ops automation (k8s preStop hooks,
    // systemd ExecStop scripts, etc.) can call `/admin/drain`
    // without managing a session cookie.
    let no_admin_configured = services.admin_identity.password_hash.is_empty();
    let token_ok = match std::env::var("AEGIS_DRAIN_TOKEN").ok() {
        Some(expected) if !expected.is_empty() => {
            req.headers()
                .get("x-aegis-drain-token")
                .and_then(|h| h.to_str().ok())
                .map(|h| h == expected)
                .unwrap_or(false)
        }
        _ => false,
    };
    if !session_ok && !no_admin_configured && !token_ok {
        return json_response(
            401,
            &serde_json::json!({"error": "auth_required"}),
        );
    }

    let already = readiness.draining.swap(true, Ordering::Release);
    json_response(
        202,
        &serde_json::json!({
            "status": "draining",
            "already": already,
            "node": services
                .leader_view
                .as_ref()
                .map(|lv| lv.our_node.clone())
                .unwrap_or_default(),
        }),
    )
}

/// HK-T3 — `/__waf_control/*` dispatch.
///
/// Routes to `aegis_control::interop::control::ControlContext`
/// for the four contract endpoints. Authenticates via
/// `X-Benchmark-Secret` per §2.2; missing/wrong secret returns
/// 403 before any side effect runs.
///
/// When `services.interop` is `None` (binary built without the
/// interop surface), returns 404 — the contract surface is
/// opted in via config, not always-on.
async fn handle_interop_control(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use aegis_control::interop::{control, CONTROL_SECRET_HEADER};
    use http_body_util::BodyExt;

    let Some(rt) = services.interop.as_ref() else {
        return json_response(
            404,
            &serde_json::json!({"error": "interop surface disabled"}),
        );
    };

    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    let secret = req
        .headers()
        .get(CONTROL_SECRET_HEADER)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    if let Err(e) = rt.control.check_auth(secret.as_deref()) {
        return json_response(
            e.status(),
            &serde_json::json!({"ok": false, "error": e.to_string()}),
        );
    }

    match (method, path.as_str()) {
        (hyper::Method::GET, "/__waf_control/capabilities") => {
            let body = serde_json::to_string(&rt.control.capabilities())
                .unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "no-store")
        }
        (hyper::Method::POST, "/__waf_control/reset_state") => {
            let body = serde_json::to_string(&rt.control.reset_state())
                .unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "no-store")
        }
        (hyper::Method::POST, "/__waf_control/set_profile") => {
            let bytes = match req.into_body().collect().await {
                Ok(c) => c.to_bytes(),
                Err(_) => {
                    return json_response(
                        400,
                        &serde_json::json!({"ok": false, "error": "body read error"}),
                    );
                }
            };
            let parsed: control::SetProfileRequest =
                match serde_json::from_slice(&bytes) {
                    Ok(p) => p,
                    Err(e) => {
                        return json_response(
                            400,
                            &serde_json::json!({
                                "ok": false,
                                "error": format!("invalid body: {e}"),
                            }),
                        );
                    }
                };
            match rt.control.set_profile(&parsed) {
                Ok(resp) => {
                    let body = serde_json::to_string(&resp)
                        .unwrap_or_else(|_| "{}".into());
                    json_body_response(200, body, "no-store")
                }
                Err(e) => json_response(
                    e.status(),
                    &serde_json::json!({"ok": false, "error": e.to_string()}),
                ),
            }
        }
        (hyper::Method::POST, "/__waf_control/flush_cache") => {
            let body = serde_json::to_string(&rt.control.flush_cache())
                .unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "no-store")
        }
        _ => json_response(
            404,
            &serde_json::json!({
                "ok": false,
                "error": "unknown control endpoint",
            }),
        ),
    }
}

/// Render a [`MaskState`] as a JSON object with `base` and
/// `overrides` keys. Used as the `before`/`after` payload of the
/// audit-chain diff so reviewers can see exactly which tier (and
/// which class within that tier) changed.
fn mask_state_to_json(
    state: &aegis_security::detectors::MaskState,
) -> serde_json::Value {
    use aegis_security::detectors::{tier_str, DetectorMaskBody, ALL_TIERS};
    let mut overrides = serde_json::Map::new();
    for tier in ALL_TIERS {
        if let Some(m) = state.override_for(tier) {
            let body: DetectorMaskBody = m.into();
            overrides.insert(
                tier_str(tier).to_string(),
                serde_json::to_value(body).unwrap_or(serde_json::Value::Null),
            );
        }
    }
    let base: DetectorMaskBody = state.base.into();
    serde_json::json!({
        "base": base,
        "overrides": serde_json::Value::Object(overrides),
    })
}

/// Pull a single named cookie value out of a `Cookie:` header
/// payload. Returns `None` if the cookie isn't present.
fn extract_named_cookie<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    for pair in raw.split(';') {
        let trimmed = pair.trim();
        if let Some(rest) = trimmed.strip_prefix(name) {
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value);
            }
        }
    }
    None
}

fn admin_router(
    req: hyper::Request<hyper::body::Incoming>,
    cfg: &WafConfig,
    readiness: &ReadinessSignal,
    startup: &aegis_control::health::StartupProbe,
    metrics: &aegis_control::metrics::MetricsRegistry,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let path = req.uri().path();
    let query = req.uri().query().unwrap_or("");

    let use_legacy = cfg.admin.dashboard.legacy_shell;

    // Root → dashboard for convenience (existing behaviour).
    if path == "/" {
        return dashboard_shell_response(use_legacy);
    }

    // Dashboard surface (SPA shell + embedded assets) is owned by
    // aegis-control::dashboard::dispatch. SSE returns None and falls
    // through to the streaming handler below.
    if let Some(resp) = aegis_control::dashboard::dispatch::dispatch(path) {
        return dashboard_response(resp, use_legacy);
    }

    match path {
        // `/dashboard/sse` is intercepted at the listener
        // service_fn (B4-T4) and returns a streaming body.
        // If a request reaches `admin_router` with that path
        // (for example via tests that bypass the listener),
        // surface a 404 — the buffered router can no longer
        // serve SSE.

        // Health probes.
        "/healthz/live" => {
            let (code, msg) = aegis_control::health::check_live(readiness);
            json_response(code, &serde_json::json!({"status": msg}))
        }
        "/healthz/ready" => {
            // HA-T5 — `?strict=1` returns 503 unless this node also
            // holds the cluster lease. Lets active/standby LB
            // topologies route singleton traffic to one node only.
            let strict = matches!(parse_query_str(query, "strict"), Some("1"));
            let (code, resp) = if strict {
                let is_leader = services
                    .leader_view
                    .as_ref()
                    .map(|lv| lv.is_leader());
                aegis_control::health::check_ready_strict(readiness, is_leader)
            } else {
                aegis_control::health::check_ready(readiness)
            };
            json_response(code, &serde_json::json!(resp))
        }
        "/healthz/startup" => {
            let (code, msg) = aegis_control::health::check_startup(startup);
            json_response(code, &serde_json::json!({"status": msg}))
        }

        // Prometheus metrics.
        "/metrics" => {
            let body = aegis_control::metrics::exporter::render(metrics);
            Response::builder()
                .status(200)
                .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        }

        // Config API.
        "/api/config" => {
            json_response(200, &serde_json::json!({
                "status": "running",
                "admin": cfg.listeners.admin.bind.to_string(),
                "data_listeners": cfg.listeners.data.len(),
                "routes": cfg.routes.len(),
                "upstreams": cfg.upstreams.len(),
            }))
        }

        // Dashboard data endpoints (D-M2). All read-only, JSON,
        // sourced from `aegis-control::dashboard_services`.
        "/api/about" => {
            json_body_response(
                200,
                aegis_control::api::about::render(services.environment.clone()),
                "private, max-age=10",
            )
        }
        "/api/stats" => {
            json_body_response(200, services.stats.render(), "private, max-age=1")
        }
        "/api/stats/timeseries" => {
            let window = parse_query_u32(query, "window", 900);
            let step = parse_query_u32(query, "step", 5);
            let resp = services.stats_agg.timeseries(window, step);
            let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "private, max-age=1")
        }
        "/api/upstreams/summary" => {
            json_body_response(200, services.upstreams.render(), "private, max-age=2")
        }
        "/api/attacks/distribution" => {
            let window = parse_query_u32(query, "window", 900);
            json_body_response(
                200,
                services.attacks.render(window),
                "private, max-age=10",
            )
        }
        "/api/attacks/top" => {
            let window = parse_query_u32(query, "window", 900);
            let limit = parse_query_u32(query, "limit", 5);
            json_body_response(
                200,
                services.attacks.render_top(window, limit),
                "private, max-age=10",
            )
        }
        "/api/audit/since" => {
            let cursor = parse_query_u64(query, "cursor", 0);
            let limit = parse_query_u32(query, "limit", 200);
            json_body_response(
                200,
                services.audit.render_since(cursor, limit),
                "private, no-store",
            )
        }
        "/api/attacks/by-detector" => {
            let window = parse_query_u32(query, "window", 900);
            json_body_response(
                200,
                services.attacks.render_by_detector(window),
                "private, max-age=10",
            )
        }
        "/api/threat-intel/hits" => {
            let window = parse_query_u32(query, "window", 3600);
            let limit = parse_query_u32(query, "limit", 20);
            json_body_response(
                200,
                services.attacks.render_threat_intel(window, limit),
                "private, max-age=10",
            )
        }
        "/api/bots/mix" => {
            let window = parse_query_u32(query, "window", 3600);
            json_body_response(
                200,
                services.attacks.render_bot_mix(window),
                "private, max-age=10",
            )
        }
        "/api/audit/witness" => {
            json_body_response(200, services.witness.render(), "private, max-age=2")
        }
        "/api/filters" => {
            json_body_response(200, services.filters.render(), "private, max-age=30")
        }
        "/api/analytics/query" => {
            let expr = parse_query_str(query, "expr").unwrap_or("");
            let start = parse_query_u64(query, "start", 0);
            let end = parse_query_u64(query, "end", 0);
            let step = parse_query_u32(query, "step", 60);
            let r = aegis_control::api::analytics::render_query(
                expr, start, end, step, None,
            );
            json_body_response(r.status, r.body, "private, max-age=30")
        }

        // D-M4 read endpoints. Mutating endpoints (POST / PUT /
        // DELETE) are deferred until the M3 audit-mutation
        // pipeline is integrated; the in-process stores still
        // round-trip through these reads for the dashboard pages
        // to render the empty initial state.
        "/api/rules" => {
            let body = serde_json::json!({"rules": services.rules.list()});
            json_body_response(200, body.to_string(), "private, max-age=2")
        }
        "/api/rules/top" => {
            let window = parse_query_u32(query, "window", 3600);
            let limit = parse_query_u32(query, "limit", 10);
            let body = serde_json::to_string(&services.rule_stats.top(window, limit))
                .unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "private, max-age=10")
        }
        "/api/tiers" => {
            let body = serde_json::json!({"tiers": services.tiers.list()});
            json_body_response(200, body.to_string(), "private, max-age=5")
        }
        "/api/blacklist" => {
            let body = serde_json::json!({"entries": services.blacklist.list()});
            json_body_response(200, body.to_string(), "private, max-age=2")
        }
        "/api/whitelist" => {
            let body = serde_json::json!({"entries": services.whitelist.list()});
            json_body_response(200, body.to_string(), "private, max-age=2")
        }
        "/api/admin/sessions" => {
            let body = serde_json::json!({"sessions": services.sessions.list()});
            json_body_response(200, body.to_string(), "private, no-store")
        }
        "/api/admin/break-glass" => {
            let body = serde_json::to_string(&services.break_glass.snapshot())
                .unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "private, no-store")
        }
        "/api/integrations" => {
            let resp = aegis_control::api::admin::IntegrationsResponse::from_config(cfg);
            let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "private, max-age=30")
        }

        // P8 verbosity. GET returns the live level + ladder; PUT
        // (audit-mutated) sets a new level. Cold-tier mirror at
        // `/api/cold-tier` lists configured sinks.
        "/api/logging" => {
            let body = aegis_control::api::logging::render_logging_get(&services.verbosity);
            json_body_response(200, body, "private, max-age=2")
        }
        "/api/cold-tier" => {
            let sinks = &cfg.audit.sinks;
            let body = aegis_control::api::logging::render_cold_tier(sinks);
            json_body_response(200, body, "private, max-age=10")
        }

        // P7 load-mode snapshot. GET returns the live mode +
        // RPS + threshold config + override state. PUT is async
        // (handled in `handle_admin_request`).
        "/api/loadmode" => {
            let body = aegis_control::api::load_mode::render_get(&services.load_gauge);
            json_body_response(200, body, "private, max-age=2")
        }

        // P6 risk inventory. Top-N high-risk clients ordered by
        // strike count then score. The dashboard polls this to
        // render the Tracking page risk widget.
        "/api/risk" => {
            let limit = parse_query_u32(query, "limit", 50);
            let body = aegis_control::api::risk::render_list(&services.risk, limit);
            json_body_response(200, body, "private, max-age=2")
        }

        // P2: detector class mask — read returns the live mask
        // plus compliance lock-list. PUT is handled in
        // `handle_admin_request` (async — needs to read body).
        "/api/detectors" => {
            let modes: Vec<aegis_core::config::ComplianceMode> = cfg
                .compliance
                .as_ref()
                .map(|c| c.modes.clone())
                .unwrap_or_default();
            let body = aegis_control::api::detectors::render_get(
                &services.detector_mask,
                &modes,
            );
            json_body_response(200, body, "private, max-age=2")
        }

        // D-M5: tracking
        "/api/slo" => json_body_response(200, services.tracking.render_slo(), "private, max-age=2"),
        "/api/cluster" => json_body_response(200, services.tracking.render_cluster(), "private, max-age=2"),
        "/api/runtime" => {
            // Layer-1 — in-node runtime sizing snapshot. Stable
            // across the process lifetime (tokio runtime is fixed
            // at boot), so cache aggressively.
            let view = aegis_control::api::runtime::RuntimeView::render(
                &cfg.runtime,
                cfg!(feature = "affinity"),
            );
            let body = serde_json::to_string(&view).unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "private, max-age=60")
        }
        "/api/certs" => json_body_response(200, services.tracking.render_certs(), "private, max-age=10"),
        "/api/gitops/status" => json_body_response(200, services.tracking.render_gitops(), "private, max-age=5"),
        "/api/alerts" => json_body_response(200, services.tracking.render_alerts(), "private, max-age=2"),
        "/api/upstreams" => json_body_response(200, services.upstreams.render(), "private, max-age=2"),
        "/api/tracking/snapshot" => json_body_response(
            200,
            services.tracking.render_snapshot(),
            "private, max-age=2",
        ),

        // P6 single-client detail. Path is `/api/risk/<ip>`.
        path if path.starts_with("/api/risk/") => {
            let segment = &path["/api/risk/".len()..];
            // `/api/risk/<ip>/reset` is a PUT — leave it to the
            // async wrapper. Anything else GETs the detail.
            if let Some(ip_seg) = segment.strip_suffix("/reset") {
                let _ = ip_seg; // PUT path handled in handle_admin_request
                json_response(
                    405,
                    &serde_json::json!({
                        "error": "method_not_allowed",
                        "allow": "PUT",
                    }),
                )
            } else if let Some(ip) = aegis_control::api::risk::parse_ip_segment(segment) {
                let (status, body) =
                    aegis_control::api::risk::render_detail(&services.risk, ip);
                json_body_response(status, body, "private, no-store")
            } else {
                json_response(
                    400,
                    &serde_json::json!({
                        "error": "invalid_ip",
                        "segment": segment,
                    }),
                )
            }
        }

        // 404 for everything else.
        _ => {
            json_response(404, &serde_json::json!({"error": "not found", "path": path}))
        }
    }
}

/// Parse a `?key=value` integer from a raw query string. Used by
/// the dashboard API endpoints to honour their `?window=` /
/// `?step=` / `?limit=` parameters. Falls back to `default` on
/// missing key, parse failure, or trailing `s` suffix
/// (the api spec writes `15m` / `5s` in examples but accepts
/// integer seconds in the URL).
fn parse_query_u32(query: &str, key: &str, default: u32) -> u32 {
    for pair in query.split('&') {
        if let Some(rest) = pair.strip_prefix(key) {
            if let Some(value) = rest.strip_prefix('=') {
                let trimmed = value.trim_end_matches('s');
                if let Ok(n) = trimmed.parse::<u32>() {
                    return n;
                }
            }
        }
    }
    default
}

/// Same shape as `parse_query_u32` but returns the raw string slice.
/// Useful for keys whose values aren't numeric (e.g. `?expr=`).
fn parse_query_str<'q>(query: &'q str, key: &str) -> Option<&'q str> {
    for pair in query.split('&') {
        if let Some(rest) = pair.strip_prefix(key) {
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value);
            }
        }
    }
    None
}

/// Same shape as `parse_query_u32` but for u64 — used by audit cursor
/// values that may exceed `u32::MAX` in long-running deployments.
fn parse_query_u64(query: &str, key: &str, default: u64) -> u64 {
    for pair in query.split('&') {
        if let Some(rest) = pair.strip_prefix(key) {
            if let Some(value) = rest.strip_prefix('=') {
                if let Ok(n) = value.parse::<u64>() {
                    return n;
                }
            }
        }
    }
    default
}

fn json_response(status: u16, value: &serde_json::Value) -> Response<Full<Bytes>> {
    let body = serde_json::to_string(value).unwrap_or_else(|_| "{}".into());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// JSON response from a pre-rendered body. Adds `Cache-Control` per
/// the per-endpoint TTLs documented in
/// `docs/control-plane/enterprise/api.md` §"Caching".
fn json_body_response(status: u16, body: String, cache_control: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .header("cache-control", cache_control)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// Apply the documented dashboard security headers to a response
/// builder. Single application point for the
/// `aegis_control::dashboard::security::SECURITY_HEADERS` table — see
/// `docs/control-plane/enterprise/security.md` §"Headers (full set …)".
fn apply_dashboard_security_headers(
    mut builder: hyper::http::response::Builder,
) -> hyper::http::response::Builder {
    for (name, value) in aegis_control::dashboard::security::SECURITY_HEADERS {
        builder = builder.header(*name, *value);
    }
    builder
}

/// Convert an [`aegis_control::dashboard::dispatch::DashboardResponse`]
/// into a hyper response. Centralises the dashboard transport rules
/// so security headers, ETags, and cache-control all sit in one place.
///
/// `use_legacy` selects between the v1 single-file shell and the
/// enterprise SPA for the [`DashboardResponse::Shell`] variant only;
/// asset routes are independent of the toggle.
fn dashboard_response(
    r: aegis_control::dashboard::dispatch::DashboardResponse,
    use_legacy: bool,
) -> Response<Full<Bytes>> {
    use aegis_control::dashboard::dispatch::DashboardResponse;
    match r {
        DashboardResponse::Shell => dashboard_shell_response(use_legacy),
        DashboardResponse::Asset(asset) => apply_dashboard_security_headers(
            Response::builder()
                .status(200)
                .header("content-type", asset.content_type)
                .header("etag", format!("\"{}\"", asset.etag))
                .header("cache-control", "public, max-age=3600, must-revalidate"),
        )
        .body(Full::new(Bytes::from_static(asset.bytes)))
        .unwrap(),
        DashboardResponse::AssetNotFound => apply_dashboard_security_headers(
            Response::builder()
                .status(404)
                .header("content-type", "application/json"),
        )
        .body(Full::new(Bytes::from_static(
            br#"{"error":"asset not found"}"#,
        )))
        .unwrap(),
    }
}

/// Serve the SPA shell (`index.html`) by default, or the legacy v1
/// shell when `use_legacy` is `true` (admin opt-in via
/// `cfg.admin.dashboard.legacy_shell`).
fn dashboard_shell_response(use_legacy: bool) -> Response<Full<Bytes>> {
    let shell = aegis_control::dashboard::dispatch::shell_for(use_legacy);
    apply_dashboard_security_headers(
        Response::builder()
            .status(200)
            .header("content-type", shell.content_type)
            .header("cache-control", "no-store"),
    )
    .body(Full::new(Bytes::from_static(shell.bytes)))
    .unwrap()
}

/// Plain-HTTP listener that responds to:
/// - `/.well-known/acme-challenge/{token}` → key authorisation
///   string (HTTP-01 challenge response, P5).
/// - everything else → 301 / 308 redirect to HTTPS (P4).
async fn force_https_loop(
    tcp: tokio::net::TcpListener,
    status: u16,
    challenges: crate::acme::ChallengeStore,
) {
    loop {
        let (stream, peer) = match tcp.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("force-https accept error: {e}");
                continue;
            }
        };
        let challenges = challenges.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let challenges = challenges.clone();
            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let challenges = challenges.clone();
                async move {
                    Ok::<_, Infallible>(handle_force_https_request(req, status, &challenges))
                }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!("force-https connection from {peer} closed: {e}");
            }
        });
    }
}

const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

fn handle_force_https_request(
    req: hyper::Request<hyper::body::Incoming>,
    status: u16,
    challenges: &crate::acme::ChallengeStore,
) -> Response<Full<Bytes>> {
    let path_owned = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());

    // ACME HTTP-01 short-circuit: if this request is for a token
    // we know about, serve the key authorisation as text/plain.
    if let Some(token) = req.uri().path().strip_prefix(ACME_CHALLENGE_PREFIX) {
        if let Some(key_auth) = challenges.lookup(token) {
            return Response::builder()
                .status(200)
                .header("content-type", "application/octet-stream")
                .header("cache-control", "no-store")
                .body(Full::new(Bytes::from(key_auth)))
                .unwrap();
        }
        // Unknown token → 404 (don't redirect, the directory
        // expects a definitive answer).
        return Response::builder()
            .status(404)
            .header("content-type", "text/plain")
            .header("cache-control", "no-store")
            .body(Full::new(Bytes::from("acme challenge token not found")))
            .unwrap();
    }

    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    crate::listener::tls_policy::force_https_redirect_response(host, &path_owned, status)
}

#[allow(clippy::too_many_arguments)]
/// HK-T1 + HK-T3 + HK-T4 — assemble the interop Runtime from
/// config. `None` when `cfg.interop.enabled = false`.
fn build_interop_runtime(
    cfg: &WafConfig,
    risk: &aegis_security::risk::RiskTracker,
    ip_rate_limiter: &Arc<aegis_security::rate_limit::IpRateLimiter>,
) -> Option<Arc<aegis_control::interop::InteropRuntime>> {
    use aegis_control::interop::{
        audit::MinimalJsonlSink,
        control::{CapabilityFeature, ControlContext},
        headers::Mode,
        mode::ModeStore,
        InteropRuntime,
    };
    use std::collections::BTreeMap;

    if !cfg.interop.enabled {
        return None;
    }
    let modes = Arc::new(ModeStore::new(Mode::Enforce));

    // The contract feature list. Names match the dashboard
    // surface so `set_profile` can target them. Stable for the
    // duration of a benchmark run.
    let mut features = BTreeMap::new();
    features.insert(
        "access_control".into(),
        CapabilityFeature {
            supported: true,
            toggleable: true,
            policies: vec!["blacklist".into(), "whitelist".into()],
        },
    );
    features.insert(
        "rules_engine".into(),
        CapabilityFeature {
            supported: true,
            toggleable: true,
            policies: vec![
                "sqli".into(),
                "xss".into(),
                "path_traversal".into(),
                "ssrf".into(),
                "header_injection".into(),
                "body_abuse".into(),
                "recon".into(),
                "brute_force".into(),
            ],
        },
    );
    features.insert(
        "rate_limit".into(),
        CapabilityFeature {
            supported: true,
            toggleable: true,
            policies: vec!["per_ip".into()],
        },
    );
    features.insert(
        "risk_engine".into(),
        CapabilityFeature {
            supported: true,
            toggleable: true,
            policies: vec!["score".into(), "strikes".into()],
        },
    );

    // `reset_state` must clear: rate-limit counters, risk
    // state, challenge sessions. Audit log is preserved.
    let mut reset_callbacks: Vec<aegis_control::interop::control::ResetCallback> =
        Vec::new();
    let risk_for_reset = risk.clone();
    reset_callbacks.push(Arc::new(move || {
        risk_for_reset.reset_all();
    }));
    let limiter_for_reset = Arc::clone(ip_rate_limiter);
    reset_callbacks.push(Arc::new(move || {
        limiter_for_reset.reset_all();
    }));

    let audit_sink = match MinimalJsonlSink::open(&cfg.interop.audit_path) {
        Ok(s) => Some(Arc::new(s)),
        Err(e) => {
            tracing::warn!(
                path = %cfg.interop.audit_path.display(),
                error = %e,
                "interop audit sink failed to open; continuing without contract audit log",
            );
            None
        }
    };

    let control = ControlContext {
        modes: Arc::clone(&modes),
        features,
        reset_callbacks,
        flush_callback: None,
        secret: cfg
            .interop
            .control_secret
            .clone()
            .unwrap_or_else(|| {
                aegis_control::interop::DEFAULT_CONTROL_SECRET.to_string()
            }),
    };

    Some(Arc::new(InteropRuntime {
        audit: audit_sink,
        modes,
        control,
    }))
}

/// HK-T2 + HK-T1 — stamp `X-WAF-*` headers + write minimal-
/// schema audit on every data-plane response.
///
/// Maps the existing response status to a contract decision
/// class. When the interop surface is off (`interop = None`)
/// the response is returned unchanged.
fn stamp_interop_response(
    mut resp: Response<Full<Bytes>>,
    interop: Option<&Arc<aegis_control::interop::InteropRuntime>>,
    peer: std::net::SocketAddr,
    method: &hyper::Method,
    path: &str,
    risk_score: u32,
) -> Response<Full<Bytes>> {
    use aegis_control::interop::audit::MinimalAuditEntry;
    use aegis_control::interop::headers::{Action, CacheState, Decision};

    let Some(rt) = interop else {
        return resp;
    };

    // Map HTTP status → contract action. Status 200..399 = allow
    // (the upstream replied OK or near-OK); other codes map onto
    // the WAF's denial classes.
    let status = resp.status().as_u16();
    let action = match status {
        200..=399 => Action::Allow,
        429 => {
            // Could be challenge or rate_limit; we set both for the
            // same status code. Default to rate_limit; the body
            // contains "challenge" in the challenge case but we
            // don't peek the body here. Bonus headers from the
            // emitter would clarify; the contract accepts either.
            Action::RateLimit
        }
        503 => Action::CircuitBreaker,
        504 => Action::Timeout,
        _ => Action::Block,
    };

    // Generate a request id. UUID v4 isn't on our crate list yet,
    // so build a 36-char hyphenated hex from blake3 (still
    // RFC-4122-shaped, deterministic per request, distinct enough
    // to satisfy the OC's "MUST match audit log" constraint).
    let raw = blake3::hash(
        format!(
            "{peer}:{}:{path}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        )
        .as_bytes(),
    );
    let h = raw.to_hex();
    let h = h.as_str();
    let request_id = format!(
        "{}-{}-4{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[13..16],
        &h[16..20],
        &h[20..32],
    );

    let mode = rt.modes.resolve("rules_engine", None);
    let decision = Decision {
        request_id: request_id.clone(),
        risk_score,
        action,
        rule_id: None,
        cache: CacheState::Bypass,
        mode,
    };
    decision.stamp(resp.headers_mut());

    if let Some(sink) = rt.audit.as_ref() {
        let entry = MinimalAuditEntry {
            request_id,
            ts_ms: chrono::Utc::now().timestamp_millis(),
            ip: peer.ip().to_string(),
            method: method.as_str().to_string(),
            path: path.to_string(),
            action: action.as_str().to_string(),
            risk_score,
            mode: mode.as_str().to_string(),
            rule_id: None,
        };
        if let Err(e) = sink.append(&entry) {
            tracing::warn!(error = %e, "interop audit write failed");
        }
    }

    resp
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
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
        tokio::spawn(async move {
            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
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
                async move {
                    let method = req.method().clone();
                    let path = req.uri().path().to_string();
                    let resp = handle_data_request(
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
                    ).await;
                    let resp = stamp_interop_response(
                        resp,
                        interop.as_ref(),
                        peer,
                        &method,
                        &path,
                        risk.snapshot(peer.ip()).map(|s| s.score).unwrap_or(0),
                    );
                    Ok::<_, Infallible>(resp)
                }
            });

            // Carry-over 5 — when the listener is configured
            // for TLS, do the rustls handshake first, then
            // serve hyper over the encrypted stream. Otherwise
            // serve plain HTTP/1.1 directly.
            match acceptor {
                Some(acc) => match acc.accept(stream).await {
                    Ok(tls_stream) => {
                        let io = TokioIo::new(tls_stream);
                        if let Err(e) = http1::Builder::new()
                            .serve_connection(io, svc)
                            .await
                        {
                            tracing::debug!(
                                "tls connection from {peer} closed: {e}"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            "tls handshake from {peer} failed: {e}"
                        );
                    }
                },
                None => {
                    let io = TokioIo::new(stream);
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, svc)
                        .await
                    {
                        tracing::debug!("connection from {peer} closed: {e}");
                    }
                }
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_data_request(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    detectors: &[Box<dyn aegis_security::detectors::Detector>],
    mask: &aegis_security::detectors::SharedDetectorMask,
    risk: &aegis_security::risk::RiskTracker,
    ip_rate_limiter: &aegis_security::rate_limit::IpRateLimiter,
    load_gauge: &aegis_core::LoadGauge,
    verbosity: &aegis_core::SharedVerbosity,
    request_stage_hist: &aegis_control::metrics::request_duration::RequestStageHistogram,
    bus: &AuditBus,
    upstream_ctx: &Arc<crate::proxy::ProxyContext>,
) -> Response<Full<Bytes>> {
    use aegis_control::metrics::request_duration::stage as stages;
    // RAII guard records the total duration on every exit
    // (early-return on rate-limit, strike-block, detector block,
    // or the Allow / Challenge / Block bottom). One sample per
    // request — no double-counting.
    struct TotalGuard<'a> {
        h: &'a aegis_control::metrics::request_duration::RequestStageHistogram,
        t0: std::time::Instant,
    }
    impl<'a> Drop for TotalGuard<'a> {
        fn drop(&mut self) {
            self.h.record(
                aegis_control::metrics::request_duration::stage::TOTAL,
                self.t0.elapsed(),
            );
        }
    }
    let _total_guard = TotalGuard {
        h: request_stage_hist,
        t0: std::time::Instant::now(),
    };
    // P7: bump the request counter so the sampler can update mode.
    load_gauge.tick();
    let load_mode = load_gauge.current();
    // P8: live verbosity dial. Block events are tagged at `Error`
    // — they emit unless the operator pinned `Silent` (used during
    // load tests where every audit write would dominate the
    // workload).
    let verbosity_level = verbosity.current();
    let allow_block_emit =
        verbosity_level.is_at_least(aegis_core::VerbosityLevel::Error);
    let allow_verbose_fields =
        verbosity_level.is_at_least(aegis_core::VerbosityLevel::Info);
    use aegis_core::pipeline::{BodyPeek, RequestView};

    let body_peek = BodyPeek::empty();
    let view = RequestView {
        method: req.method(),
        uri: req.uri(),
        version: req.version(),
        headers: req.headers(),
        peer,
        tls: None,
        body: &body_peek,
    };

    // Classify the request to a tier so per-tier overrides apply.
    // Route context isn't plumbed yet (route table lookup is in
    // aegis-proxy::route, separate work); pass `None` here and rely
    // on the path heuristic in `classify_tier`.
    let (tier, _failure_mode) = aegis_security::pipeline::classify_tier(None, &view);

    // P6 short-circuit: if the client's lifetime strike counter
    // has crossed the configured threshold, refuse before running
    // any detectors. Saves CPU under DDoS from known-bad sources.
    let peer_ip = peer.ip();
    if risk.is_strike_blocked(peer_ip) {
        return blocked_response(
            peer,
            "blocked by repeat-offender strikes",
            None,
            risk.snapshot(peer_ip).map(|s| s.score),
            req.uri(),
            req.method(),
            bus,
        );
    }

    // F-T2 — per-IP volumetric guard. Fires before the
    // detector pipeline so a flooding source can't burn CPU
    // on regex matchers. A denied request still records a
    // strike, so repeat offenders eventually cross
    // `risk.strikes.block_at` and get the permanent 403 path
    // above instead of the 429 here.
    let rate_t0 = std::time::Instant::now();
    let rate_decision = ip_rate_limiter.consume(peer_ip);
    request_stage_hist.record(stages::RATE_LIMIT, rate_t0.elapsed());
    if !rate_decision.allowed {
        let post_state = risk.record_malicious(peer_ip, 30);
        let reason = format!(
            "rate limit: {}/{} in last {}s",
            rate_decision.count,
            rate_decision.limit,
            ip_rate_limiter.config().window.as_secs(),
        );
        let allow_emit = verbosity
            .current()
            .is_at_least(aegis_core::VerbosityLevel::Error);
        if allow_emit {
            let ev = aegis_core::audit::AuditEvent {
                schema_version: 1,
                ts: chrono::Utc::now(),
                request_id: blake3::hash(
                    format!(
                        "{}:{}",
                        peer,
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                    )
                    .as_bytes(),
                )
                .to_hex()
                .to_string(),
                class: aegis_core::audit::AuditClass::Detection,
                tenant_id: None,
                tier: None,
                action: "block".into(),
                reason: reason.clone(),
                client_ip: peer_ip.to_string(),
                route_id: None,
                rule_id: Some("ip-rate-limit".into()),
                risk_score: Some(post_state.score),
                fields: if load_mode.is_critical() {
                    serde_json::Value::Null
                } else {
                    serde_json::json!({
                        "path": req.uri().to_string(),
                        "method": req.method().to_string(),
                        "rate_count": rate_decision.count,
                        "rate_limit": rate_decision.limit,
                        "strikes": post_state.strikes,
                    })
                },
            };
            bus.emit(ev);
        }
        return Response::builder()
            .status(429)
            .header("content-type", "application/json")
            .header("retry-after", rate_decision.retry_after_seconds.to_string())
            .body(Full::new(Bytes::from(
                serde_json::json!({
                    "error": "rate_limited",
                    "reason": reason,
                    "retry_after_seconds": rate_decision.retry_after_seconds,
                    "strikes": post_state.strikes,
                })
                .to_string(),
            )))
            .unwrap();
    }

    // Run security detectors filtered by the effective mask for
    // this tier. A class turned off via PUT /api/detectors (base
    // or per-tier override) short-circuits before the detector body
    // runs.
    let effective = mask.resolve(Some(tier));
    let detect_t0 = std::time::Instant::now();
    let signals = aegis_security::detectors::run_all_filtered(detectors, effective, &view);
    request_stage_hist.record(stages::DETECT, detect_t0.elapsed());

    if !signals.is_empty() {
        let total_score: u32 = signals.iter().map(|s| s.score).sum();
        let post_state = risk.record_malicious(peer_ip, total_score);
        let tags: Vec<&str> = signals.iter().map(|s| s.tag.as_str()).collect();
        let reason = format!("blocked by detectors: {} (score: {})", tags.join(", "), post_state.score);
        tracing::warn!(
            peer = %peer,
            path = %req.uri(),
            score = post_state.score,
            strikes = post_state.strikes,
            detectors = ?tags,
            "request blocked"
        );

        // P7 degraded logging: in Critical mode strip the verbose
        // `fields` payload to keep the bus + chain writes cheap.
        // Block reason is preserved so operators still see "what
        // tripped" — only the request echo is dropped.
        // P8 verbosity: skip the request echo whenever the live
        // verbosity is below `Info`. Combines additively with the
        // Critical short-circuit so an operator-pinned `Warn`
        // strips fields even at Normal load.
        let fields = if load_mode.is_critical() || !allow_verbose_fields {
            serde_json::Value::Null
        } else {
            serde_json::json!({
                "path": req.uri().to_string(),
                "method": req.method().to_string(),
                "detectors": tags,
                "strikes": post_state.strikes,
                "load_mode": load_mode.as_str(),
                "verbosity": verbosity_level.as_str(),
            })
        };
        if allow_block_emit {
            let ev = aegis_core::audit::AuditEvent {
                schema_version: 1,
                ts: chrono::Utc::now(),
                request_id: blake3::hash(format!("{}:{}", peer, chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)).as_bytes()).to_hex().to_string(),
                class: aegis_core::audit::AuditClass::Detection,
                tenant_id: None,
                tier: None,
                action: "block".into(),
                reason: reason.clone(),
                client_ip: peer_ip.to_string(),
                route_id: None,
                rule_id: None,
                risk_score: Some(post_state.score),
                fields,
            };
            bus.emit(ev);
        }

        return Response::builder()
            .status(403)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(
                serde_json::json!({
                    "error": "forbidden",
                    "reason": reason,
                    "strikes": post_state.strikes,
                })
                .to_string(),
            )))
            .unwrap();
    }

    // Clean request — let the trust-recovery clock claw back any
    // accumulated score (capped at `trust_recovery.per_hour` so
    // one benign request can't reset a flagged client). Then the
    // adaptive-mitigation classifier decides between Allow,
    // Challenge, and Block based on the post-state vs the
    // configured `RiskThresholds`.
    risk.record_clean(peer_ip);
    match risk.level(peer_ip) {
        aegis_security::risk::RiskLevel::Block => blocked_response(
            peer,
            "blocked by risk score",
            None,
            risk.snapshot(peer_ip).map(|s| s.score),
            req.uri(),
            req.method(),
            bus,
        ),
        aegis_security::risk::RiskLevel::Challenge => Response::builder()
            .status(429)
            .header("content-type", "application/json")
            .header("retry-after", "5")
            .body(Full::new(Bytes::from(
                serde_json::json!({
                    "error": "challenge_required",
                    "reason": "risk score over challenge threshold",
                })
                .to_string(),
            )))
            .unwrap(),
        aegis_security::risk::RiskLevel::Allow => {
            // Carry-over A (post-2026-04-29 perf re-run) — fixed.
            // Forward the request to a real upstream member via
            // the same `crate::upstream::forward` path
            // `crate::proxy::handle_request` uses. Falls back to
            // a 502 on connect / handshake / send failure so
            // the live data plane never silently swallows a
            // broken upstream.
            forward_allow_to_upstream(req, upstream_ctx).await
        }
    }
}

/// Resolve a route + member from the live `ProxyContext`,
/// collect the request body, and forward through
/// `upstream::forward::forward()`. Returns 404 on no-route,
/// 502 / 503 on circuit-breaker / no-healthy-member / connect
/// failure.
async fn forward_allow_to_upstream(
    req: hyper::Request<hyper::body::Incoming>,
    ctx: &Arc<crate::proxy::ProxyContext>,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    use std::sync::atomic::Ordering;

    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    let route_ctx = match ctx.route_table.resolve(&host, &path, &method) {
        Some(r) => r,
        None => {
            return Response::builder()
                .status(hyper::StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("no matching route\n")))
                .unwrap();
        }
    };

    if let Some(cb) = ctx.breakers.get(&route_ctx.upstream) {
        if !cb.allow_request() {
            return Response::builder()
                .status(hyper::StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::from("circuit open\n")))
                .unwrap();
        }
    }

    let pool = match ctx.pools.get(&route_ctx.upstream) {
        Some(p) => p,
        None => {
            return Response::builder()
                .status(hyper::StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("unknown upstream\n")))
                .unwrap();
        }
    };

    let member = match pool.strategy.pick(&pool.members, None) {
        Some(m) => m,
        None => {
            if let Some(cb) = ctx.breakers.get(&route_ctx.upstream) {
                cb.record_failure();
            }
            return Response::builder()
                .status(hyper::StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("no healthy upstream\n")))
                .unwrap();
        }
    };

    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            tracing::warn!(error = %e, "failed to collect client body");
            return Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("body read error\n")))
                .unwrap();
        }
    };

    member.inflight.fetch_add(1, Ordering::Relaxed);
    let result = crate::upstream::forward::forward(
        member,
        &pool.connection,
        parts.method,
        parts.uri,
        parts.headers,
        body_bytes,
    )
    .await;
    member.inflight.fetch_sub(1, Ordering::Relaxed);

    match result {
        Ok(resp) => {
            if let Some(cb) = ctx.breakers.get(&route_ctx.upstream) {
                if resp.status().is_server_error() {
                    cb.record_failure();
                } else {
                    cb.record_success();
                }
            }
            resp
        }
        Err(e) => {
            tracing::warn!(error = %e, "upstream forward failed");
            if let Some(cb) = ctx.breakers.get(&route_ctx.upstream) {
                cb.record_failure();
            }
            Response::builder()
                .status(hyper::StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("upstream error\n")))
                .unwrap()
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn blocked_response(
    peer: std::net::SocketAddr,
    reason: &str,
    rule_id: Option<String>,
    risk_score: Option<u32>,
    uri: &hyper::Uri,
    method: &hyper::Method,
    bus: &AuditBus,
) -> Response<Full<Bytes>> {
    let ev = aegis_core::audit::AuditEvent {
        schema_version: 1,
        ts: chrono::Utc::now(),
        request_id: blake3::hash(
            format!(
                "{}:{}",
                peer,
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            )
            .as_bytes(),
        )
        .to_hex()
        .to_string(),
        class: aegis_core::audit::AuditClass::Detection,
        tenant_id: None,
        tier: None,
        action: "block".into(),
        reason: reason.into(),
        client_ip: peer.ip().to_string(),
        route_id: None,
        rule_id,
        risk_score,
        fields: serde_json::json!({
            "path": uri.to_string(),
            "method": method.to_string(),
        }),
    };
    bus.emit(ev);
    Response::builder()
        .status(403)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(
            serde_json::json!({ "error": "forbidden", "reason": reason }).to_string(),
        )))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::config::WafConfig;
    use aegis_core::ReadinessSignal;
    use std::sync::Arc;

    /// Spin up a tokio HTTP/1.1 mock that answers every request
    /// with `200 OK` + `body`. Returns the bound address +
    /// the join handle.
    async fn spawn_mock_upstream(
        body: &'static [u8],
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use hyper::service::service_fn;
        use std::convert::Infallible;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let (sock, _) = match listener.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let io = TokioIo::new(sock);
                    let svc =
                        service_fn(move |_req: hyper::Request<hyper::body::Incoming>| async move {
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap(),
                            )
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn run_binds_and_serves_200() {
        // B4-T3 carry-over A: data plane now actually forwards
        // through `upstream::forward`. Stand up a mock upstream
        // and point the route table at it so the Allow branch
        // returns the upstream's 200, not a synthetic stub.
        let (upstream_addr, _upstream_h) = spawn_mock_upstream(b"upstream-ok").await;
        let yaml = format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "{upstream_addr}"
state:
  backend: in_memory
"#
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();

        // We can't use port 0 with the current `run()` because it spawns
        // tasks internally. Instead, bind manually and test the accept loop.
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();

        let detectors: Arc<Vec<Box<dyn aegis_security::detectors::Detector>>> =
            Arc::new(aegis_security::detectors::default_detectors());
        let mask = aegis_security::detectors::SharedDetectorMask::default();
        let risk = aegis_security::risk::RiskTracker::new(
            &aegis_core::config::RiskConfig::default(),
        );
        let ip_rate_limiter = Arc::new(
            aegis_security::rate_limit::IpRateLimiter::new(Default::default()),
        );
        let load_gauge = aegis_core::LoadGauge::new(aegis_core::LoadModeConfig::default());
        let verbosity = aegis_core::SharedVerbosity::default();
        let metrics_reg = aegis_control::metrics::MetricsRegistry::init();
        let request_stage_hist = std::sync::Arc::new(
            aegis_control::metrics::request_duration::RequestStageHistogram::register(&metrics_reg)
                .unwrap(),
        );
        let bus = aegis_core::AuditBus::new(64);
        let upstream_ctx = std::sync::Arc::new(
            crate::proxy::ProxyContext::build(
                &cfg,
                std::sync::Arc::new(aegis_security::NoopPipeline),
            )
            .unwrap(),
        );
        let _handle = tokio::spawn(accept_loop(
            tcp,
            detectors,
            mask,
            risk,
            ip_rate_limiter,
            load_gauge,
            verbosity,
            request_stage_hist,
            bus,
            upstream_ctx,
            None, // no tls_acceptor in this plain-http test
            None, // no interop runtime in this plain-http test
        ));

        // Give the accept loop a moment to start.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect and send a minimal HTTP/1.1 request.
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("/")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);

        // Verify readiness defaults (run() was not called here, just accept_loop)
        let readiness = ReadinessSignal::default();
        assert!(!readiness.is_ready());

        // Verify that a WafConfig with port 0 parses (for the skeleton)
        let _ = cfg;
    }

    // ---------- P4 force-HTTPS redirect loop ------------------------------

    #[tokio::test]
    async fn force_https_loop_returns_301_with_https_location() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let challenges = crate::acme::ChallengeStore::new();
        let _handle = tokio::spawn(force_https_loop(tcp, 301, challenges));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("/api/secret?x=1")
            .header("host", "shop.example.com")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 301);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(loc, "https://shop.example.com/api/secret?x=1");
    }

    #[tokio::test]
    async fn force_https_loop_honours_308_status() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let challenges = crate::acme::ChallengeStore::new();
        let _handle = tokio::spawn(force_https_loop(tcp, 308, challenges));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri("/")
            .header("host", "api.example.com")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 308);
    }

    // ---------- P5 ACME HTTP-01 challenge responder -----------------------

    #[tokio::test]
    async fn force_https_loop_serves_http01_challenge_when_token_published() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let challenges = crate::acme::ChallengeStore::new();
        challenges.insert("acme-tok-1".into(), "acme-tok-1.thumb".into());
        let _handle = tokio::spawn(force_https_loop(tcp, 301, challenges));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("/.well-known/acme-challenge/acme-tok-1")
            .header("host", "shop.example.com")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        use http_body_util::BodyExt;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"acme-tok-1.thumb");
    }

    #[tokio::test]
    async fn force_https_loop_returns_404_for_unknown_acme_token() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let challenges = crate::acme::ChallengeStore::new();
        let _handle = tokio::spawn(force_https_loop(tcp, 301, challenges));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("/.well-known/acme-challenge/missing")
            .header("host", "shop.example.com")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        // ACME directory expects a definitive 404, not a redirect.
        assert_eq!(resp.status().as_u16(), 404);
    }

    // ---------- D-M1-T1.5 dashboard security headers ---------------------

    use aegis_control::dashboard::dispatch::{dispatch, DashboardResponse};
    use aegis_control::dashboard::security::SECURITY_HEADERS;

    /// Every header in SECURITY_HEADERS must appear on the response,
    /// with the canonical value.
    fn assert_security_headers(headers: &hyper::HeaderMap) {
        for (name, value) in SECURITY_HEADERS {
            let got = headers.get(*name).unwrap_or_else(|| {
                panic!("missing security header {name}");
            });
            assert_eq!(
                got.to_str().unwrap_or(""),
                *value,
                "wrong value for {name}"
            );
        }
    }

    #[test]
    fn dashboard_shell_response_carries_security_headers() {
        let resp = dashboard_shell_response(false);
        assert_eq!(resp.status(), 200);
        assert_security_headers(resp.headers());
    }

    // ---------- F-T1 admin login + logout end-to-end --------------------

    /// Build a `DashboardServices` with a real argon2id-hashed
    /// admin so the login handler can succeed.
    fn services_with_admin(
        password: &str,
    ) -> std::sync::Arc<aegis_control::dashboard_services::DashboardServices> {
        use aegis_control::admin_auth::password::hash_password;
        use aegis_control::admin_auth::rate_limit::LoginRateLimiter;
        use aegis_control::admin_auth::session::SessionStore as AuthSessionStore;
        use aegis_control::api::login::{derive_session_key, AdminIdentity};

        let bus = aegis_core::AuditBus::new(8);
        let pool = std::sync::Arc::new(|| {
            aegis_control::api::upstreams::PoolHealthSnapshot { pools: Vec::new() }
        });
        let identity = std::sync::Arc::new(AdminIdentity {
            user: "admin".into(),
            password_hash: hash_password(password).unwrap(),
        });
        let key = derive_session_key("test-secret-32b");
        let auth_sessions = std::sync::Arc::new(AuthSessionStore::new(key));
        let rate_limiter =
            std::sync::Arc::new(LoginRateLimiter::new(Default::default()));
        let (services, _drain) = aegis_control::dashboard_services::DashboardServices::spawn_with_mask(
            bus,
            pool,
            None,
            aegis_security::detectors::SharedDetectorMask::default(),
            aegis_security::risk::RiskTracker::new(
                &aegis_core::config::RiskConfig::default(),
            ),
            std::sync::Arc::new(
                aegis_security::rate_limit::IpRateLimiter::new(Default::default()),
            ),
            aegis_core::LoadGauge::new(aegis_core::LoadModeConfig::default()),
            aegis_core::SharedVerbosity::default(),
            auth_sessions,
            rate_limiter,
            identity,
            1800,
        );
        std::sync::Arc::new(services)
    }

    #[tokio::test]
    async fn login_handler_issues_two_set_cookies_on_success() {
        let services = services_with_admin("test-pw-1234");
        let body = serde_json::json!({"user":"admin","password":"test-pw-1234"})
            .to_string();
        let resp = process_admin_login(
            &services,
            "127.0.0.1:54321".parse().unwrap(),
            "test-ua/1.0",
            body.as_bytes(),
        );
        assert_eq!(resp.status().as_u16(), 200);
        let cookies: Vec<&str> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|h| h.to_str().ok())
            .collect();
        assert_eq!(cookies.len(), 2, "expected aegis_session + aegis_csrf");
        assert!(
            cookies.iter().any(|c| c.starts_with("aegis_session=")),
            "session cookie missing: {cookies:?}",
        );
        assert!(
            cookies.iter().any(|c| c.starts_with("aegis_csrf=")),
            "csrf cookie missing: {cookies:?}",
        );
        // Cache-Control: no-store on every credential-handling response.
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "no-store",
        );
    }

    #[tokio::test]
    async fn login_handler_returns_401_on_wrong_password() {
        let services = services_with_admin("right");
        let body = serde_json::json!({"user":"admin","password":"wrong"}).to_string();
        let resp = process_admin_login(
            &services,
            "127.0.0.1:0".parse().unwrap(),
            "ua",
            body.as_bytes(),
        );
        assert_eq!(resp.status().as_u16(), 401);
    }

    #[tokio::test]
    async fn login_handler_returns_400_on_invalid_json() {
        let services = services_with_admin("right");
        let resp = process_admin_login(
            &services,
            "127.0.0.1:0".parse().unwrap(),
            "ua",
            b"not json",
        );
        assert_eq!(resp.status().as_u16(), 400);
    }

    #[tokio::test]
    async fn logout_handler_clears_both_cookies_after_login() {
        let services = services_with_admin("test-pw-1234");
        let body = serde_json::json!({"user":"admin","password":"test-pw-1234"})
            .to_string();
        let login_resp = process_admin_login(
            &services,
            "127.0.0.1:0".parse().unwrap(),
            "ua",
            body.as_bytes(),
        );
        assert_eq!(login_resp.status().as_u16(), 200);

        // Pull the signed session cookie value back out so logout
        // can validate it.
        let session_cookie_str = login_resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|h| h.to_str().ok())
            .find(|c| c.starts_with("aegis_session="))
            .unwrap()
            .to_string();
        let session_value = session_cookie_str
            .strip_prefix("aegis_session=")
            .and_then(|s| s.split(';').next())
            .unwrap();

        let resp = process_admin_logout(&services, Some(session_value));
        assert_eq!(resp.status().as_u16(), 204);
        let clears: Vec<&str> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|h| h.to_str().ok())
            .collect();
        assert_eq!(clears.len(), 2);
        assert!(
            clears.iter().all(|c| c.contains("Max-Age=0")),
            "logout must clear both cookies, got {clears:?}",
        );
        // Auth session is gone — no more accepting that cookie.
        assert_eq!(services.auth_sessions.active_count(), 0);
    }

    #[tokio::test]
    async fn logout_handler_is_idempotent_without_cookie() {
        let services = services_with_admin("test-pw-1234");
        let resp = process_admin_logout(&services, None);
        // Same 204 + cookie-clearing whether or not a session
        // existed — caller never has to know.
        assert_eq!(resp.status().as_u16(), 204);
        assert_eq!(resp.headers().get_all("set-cookie").iter().count(), 2);
    }

    #[test]
    fn dashboard_asset_response_carries_security_headers() {
        let r = dispatch("/dashboard/assets/app.js")
            .expect("known asset must resolve");
        let resp = match r {
            DashboardResponse::Asset(_) => dashboard_response(r, false),
            _ => panic!("expected Asset"),
        };
        assert_eq!(resp.status(), 200);
        assert_security_headers(resp.headers());
    }

    #[test]
    fn dashboard_asset_not_found_carries_security_headers() {
        // 404s also need the headers — a missing asset must not become
        // a CSP-bypass vector.
        let r = dispatch("/dashboard/assets/missing.js")
            .expect("must dispatch");
        let resp = dashboard_response(r, false);
        assert_eq!(resp.status(), 404);
        assert_security_headers(resp.headers());
    }

    // ---------- D-M1-T1.6 legacy shell flag ------------------------------

    async fn body_string(resp: Response<Full<Bytes>>) -> String {
        use http_body_util::BodyExt;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn dashboard_shell_response_default_serves_spa_shell() {
        // legacy flag off (default) -> new SPA shell, identified by
        // the #aegis-app sentinel.
        let resp = dashboard_shell_response(false);
        assert_eq!(resp.status(), 200);
        let body = body_string(resp).await;
        assert!(
            body.contains(r#"id="aegis-app""#),
            "default shell must be the new SPA"
        );
    }

    #[tokio::test]
    async fn dashboard_shell_response_legacy_now_returns_spa() {
        // D-M6-T6.9 removed the legacy shell. The legacy flag is a
        // no-op for back-compat — every shell response is now the SPA.
        let resp = dashboard_shell_response(true);
        assert_eq!(resp.status(), 200);
        let body = body_string(resp).await;
        assert!(
            body.contains(r#"id="aegis-app""#),
            "legacy flag must now return the SPA shell"
        );
    }

    #[test]
    fn dashboard_shell_response_legacy_keeps_security_headers() {
        // The legacy shell still goes through the security-header
        // middleware — the toggle must not become a header bypass.
        let resp = dashboard_shell_response(true);
        assert_security_headers(resp.headers());
    }
}
