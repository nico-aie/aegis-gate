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
pub mod config_source;
mod admin_login;
mod data_plane;
mod responses;
use admin_login::{handle_admin_login, handle_admin_logout};
use data_plane::handle_data_request;
use responses::{
    dashboard_response, dashboard_shell_response, extract_named_cookie,
    json_body_response, json_response, mutation_error_response,
};
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

/// Source of hot-reloadable configuration. The boot snapshot is
/// always derived from the value present at `run()` entry; this
/// enum tells the proxy which background watcher (if any) to
/// spawn so subsequent edits drive the detector mask + compliance
/// clamp + audit-event flow.
///
/// Listener binds, runtime-thread sizing, and state-backend
/// selection are still boot-only: tokio's accept loops bind once
/// at startup. Hot-reload covers `cfg.detectors` (via the shared
/// [`config_source::reload::apply_cfg_change_to_mask`]) and emits
/// `config_reload` / `compliance_clamp_applied` audit events.
/// Per-handler routes / upstreams / limits remain boot-snapshotted
/// today; plumbing those through `cfg.load()` is a follow-up that
/// builds on this scaffold.
pub enum ConfigReloadSource {
    /// No watcher — config is static for the lifetime of the
    /// process. Use this from tests and one-shot CLI commands
    /// (`waf validate`, `waf snapshot`).
    None,
    /// Filesystem watcher rooted at the given YAML path.
    File(std::path::PathBuf),
    /// etcd v3 REST gateway watcher. Available under
    /// `--features etcd`; without the feature the variant is
    /// inaccessible.
    #[cfg(feature = "etcd")]
    Etcd(crate::config_source::etcd_source::EtcdConfigSource),
}

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
///
/// `reload_source` selects the config-reload watcher (file /
/// etcd / none). The boot snapshot is taken from `cfg_swap.load_full()`;
/// subsequent watcher events atomic-swap into `cfg_swap` and run
/// the shared compliance clamp on the detector mask.
pub async fn run(
    cfg_swap: Arc<arc_swap::ArcSwap<WafConfig>>,
    _pipeline: Arc<dyn SecurityPipeline>,
    state: Arc<dyn StateBackend>,
    lease_store: Arc<dyn aegis_core::cluster::LeaseStore>,
    bus: AuditBus,
    readiness: ReadinessSignal,
    reload_source: ConfigReloadSource,
) -> aegis_core::Result<()> {
    // Boot snapshot — every existing read site keeps `cfg` as
    // `Arc<WafConfig>`. Future per-handler `cfg.load()` calls
    // can read the latest revision without churning the whole
    // function.
    let cfg: Arc<WafConfig> = cfg_swap.load_full();
    let mut handles = Vec::new();

    // Build the detector set once, shared across all data-plane listeners.
    let detectors: Arc<Vec<Box<dyn aegis_security::detectors::Detector>>> =
        Arc::new(aegis_security::detectors::default_detectors());

    // Hot-reloadable detector class mask. Initial state mirrors
    // `cfg.detectors`; the control plane swaps it via PUT
    // `/api/detectors` (P2 of the security-toggle plan).
    let mask = aegis_security::detectors::SharedDetectorMask::from_config(&cfg.detectors);

    // CC-T (compliance-on-boot) — `cfg.detectors.<class>.enabled:
    // false` flipped together with `cfg.compliance.modes: [pci|...]`
    // would silently bypass the compliance mandate without this
    // pass: `from_config` doesn't know about modes, and the
    // snapshot-load below only runs when a persistence file
    // exists. Run the live clamp first so the cfg-derived mask
    // is correct even before any snapshot is applied; the
    // snapshot overwrite below carries its own clamp.
    let compliance_modes: Vec<aegis_core::config::ComplianceMode> = cfg
        .compliance
        .as_ref()
        .map(|c| c.modes.clone())
        .unwrap_or_default();
    if !compliance_modes.is_empty() {
        use aegis_control::api::detectors_persist::ApplyOutcome;
        match aegis_control::api::detectors_persist::apply_live_mask_with_compliance(
            &mask,
            &compliance_modes,
        ) {
            ApplyOutcome::Applied => {}
            ApplyOutcome::AppliedWithCompliance { forced } => {
                tracing::warn!(
                    forced = ?forced,
                    modes = ?compliance_modes,
                    "cfg.detectors had classes disabled that compliance modes pin to ON; forcing them back on at boot",
                );
            }
        }
    }

    // DURABLE-T2 — if the operator wired
    // `cfg.detectors.persistence.path`, try to load the previous
    // snapshot and overlay it onto the cfg-derived initial state.
    // Compliance clamps re-run on load; any class disabled by the
    // snapshot but locked-on by current compliance modes is forced
    // back on with a warn log (operators who change compliance
    // modes between restarts can't accidentally keep a non-
    // compliant disable). Missing file is normal on first boot.
    if let Some(persist_cfg) = cfg.detectors.persistence.as_ref() {
        match aegis_control::api::detectors_persist::load_snapshot(&persist_cfg.path).await {
            Ok(snap) => {
                use aegis_control::api::detectors_persist::ApplyOutcome;
                let outcome =
                    aegis_control::api::detectors_persist::apply_snapshot_with_compliance(
                        snap,
                        &mask,
                        &compliance_modes,
                    );
                match outcome {
                    ApplyOutcome::Applied => {
                        tracing::info!(
                            path = %persist_cfg.path.display(),
                            "detector mask snapshot rehydrated cleanly",
                        );
                    }
                    ApplyOutcome::AppliedWithCompliance { forced } => {
                        tracing::warn!(
                            path = %persist_cfg.path.display(),
                            forced = ?forced,
                            "detector mask snapshot rehydrated; compliance forced classes back on",
                        );
                    }
                }
            }
            Err(aegis_control::api::detectors_persist::LoadError::NotFound) => {
                tracing::info!(
                    path = %persist_cfg.path.display(),
                    "detector mask snapshot not found (first boot or fresh install); using cfg defaults",
                );
            }
            Err(e) => {
                tracing::warn!(
                    path = %persist_cfg.path.display(),
                    error = %e,
                    "detector mask snapshot load failed; falling back to cfg defaults",
                );
            }
        }
    }

    // Watcher spawn is deferred until after `upstream_ctx` is
    // built so the watcher can hot-swap the route table too.
    // See the spawn block further down.

    // P6 risk tracker. Per-IP score + lifetime strikes shared
    // between data plane (records signals + classifies for
    // adaptive mitigation) and control plane (renders /api/risk
    // + handles operator reset).
    let risk = aegis_security::risk::RiskTracker::new(&cfg.risk);

    // F-T2 — per-IP rate limiter. Selection rule lives in the
    // shared `derive_ip_rate_cfg` so the boot path and the
    // hot-reload watchers (`apply_cfg_change_to_rate_limit`)
    // pick the same bucket. Falls back to library defaults
    // (1 000 req / 60 s) when no `scope: Global, key: Ip`
    // bucket is configured — safer than running with no
    // volumetric guard at all.
    let ip_rate_limiter = Arc::new(
        aegis_security::rate_limit::IpRateLimiter::new(
            crate::config_source::reload::derive_ip_rate_cfg(&cfg),
        ),
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
    // PROM-T1 — per-decision counter `waf_requests_total{action}`.
    // Lights up the WAF Overview "Decision mix" panel.
    let decision_metrics = std::sync::Arc::new(
        aegis_control::metrics::decisions::DecisionMetrics::register(&metrics)
            .expect("decision metrics registration failed"),
    );
    // PROM-T1 — upstream pool health gauges
    // `waf_upstream_members_healthy{pool}` /
    // `waf_upstream_members_total{pool}`. Synced once at boot
    // from the live PoolRegistry; subsequent PUTs to
    // `/api/upstreams/config` re-sync via the admin plane.
    let upstream_pool_metrics = std::sync::Arc::new(
        aegis_control::metrics::upstream_pools::UpstreamPoolMetrics::register(&metrics)
            .expect("upstream pool metrics registration failed"),
    );
    // PROM-T2 — per-class detector-hit counter
    // `waf_detector_hits_total{class}`. Recorded once per fired
    // detector per request; lights up the WAF Overview "Detector
    // hits" panel.
    let detector_hit_metrics = std::sync::Arc::new(
        aegis_control::metrics::detector_hits::DetectorHitMetrics::register(&metrics)
            .expect("detector hit metrics registration failed"),
    );
    // PROM-T3 — per-op state-backend counter
    // `waf_state_backend_ops_total{op,outcome}`. Wraps the
    // resolved state backend with a delegating impl that
    // records every dispatch — every downstream consumer of
    // `state` is automatically instrumented.
    let state_op_metrics =
        aegis_control::metrics::state_ops::StateOpMetrics::register(&metrics)
            .expect("state op metrics registration failed");
    let state: Arc<dyn aegis_core::state::StateBackend> = Arc::new(
        aegis_control::metrics::state_ops::MeteredStateBackend::new(
            state,
            state_op_metrics,
        ),
    );
    // PROM-T3 — audit event counter `waf_audit_events_total{class}`.
    // Recorded by a metrics-only AuditBus subscriber spawned
    // alongside the existing dashboard SSE drain. Cost = one
    // bounded broadcast Receiver + one tokio task; no per-emit
    // call-site changes.
    let audit_event_metrics = std::sync::Arc::new(
        aegis_control::metrics::audit_events::AuditEventMetrics::register(&metrics)
            .expect("audit event metrics registration failed"),
    );
    {
        let bus_sub = bus.clone();
        let m = audit_event_metrics.clone();
        tokio::spawn(async move {
            let mut rx = bus_sub.subscribe();
            loop {
                match rx.recv().await {
                    Ok(ev) => m.record(ev.class),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(
                            dropped = n,
                            "audit event metrics subscriber lagged",
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

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

    // Watcher spawn deferred until after the TLS resolver is
    // built so it can be threaded through. See spawn block
    // below the TLS construction.

    // Carry-over 5 (post-2026-04-29 cluster smoke) — build a
    // single `TlsAcceptor` once if `cfg.tls.certificates` is
    // populated. Each data listener that flips
    // `tls: true` reuses this acceptor; the rest stay plain
    // TCP. `key_ref` is treated as a file path here; secret-
    // manager resolution (`${secret:vault:...}`) for keys is a
    // separate task.
    //
    // The `DynamicResolver` returned alongside the acceptor is
    // kept in scope so the cfg-reload watchers
    // (`apply_cfg_change_to_tls`) can call
    // `resolver.swap(new_store)` to rotate certs without
    // bouncing listeners. The acceptor wraps the resolver via
    // an `Arc`, so swapping the resolver's inner `ArcSwap`
    // surfaces immediately on the next handshake.
    let (tls_acceptor, tls_resolver): (
        Option<Arc<tokio_rustls::TlsAcceptor>>,
        Option<Arc<crate::listener::tls::DynamicResolver>>,
    ) = match cfg.tls.as_ref() {
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
                resolver.clone(),
                tls_cfg.min_version.as_deref(),
            )
            .map_err(|e| {
                aegis_core::WafError::Config(format!(
                    "tls: rustls config build failed: {e}"
                ))
            })?;
            // CI-T10 — the data-plane TLS branch in
            // `accept_loop` now uses
            // `hyper_util::server::conn::auto::Builder`, so
            // ALPN can advertise both h2 and http/1.1 and
            // the right protocol stack handles the negotiated
            // outcome. (`build_hardened_server_config` already
            // sets this list — keep it explicit here so a
            // future refactor can't accidentally regress.)
            server_cfg.alpn_protocols =
                vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            (
                Some(Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(
                    server_cfg,
                )))),
                Some(resolver),
            )
        }
        _ => (None, None),
    };

    // Spawn the configured config-reload watcher. Both file and
    // etcd watchers atomic-swap into `cfg_swap`, run the shared
    // `apply_cfg_change_to_mask` (detector base + compliance
    // clamp), rebuild `upstream_ctx.route_table` from
    // `new_cfg.routes`, hot-swap the IP rate-limiter cfg, and
    // (when present) rotate the TLS cert store via the live
    // `DynamicResolver`. Per-tier detector overrides set by
    // PUT /api/detectors are preserved.
    // `ConfigReloadSource::None` skips the spawn entirely (used
    // by tests + one-shot CLI commands).
    match reload_source {
        ConfigReloadSource::None => {
            tracing::info!("config reload watcher: disabled (ConfigReloadSource::None)");
        }
        ConfigReloadSource::File(path) => {
            tracing::info!(
                path = %path.display(),
                "config reload watcher: file",
            );
            // Drop the JoinHandle; the watcher runs for the
            // lifetime of the proxy and tokio::spawn keeps the
            // task alive regardless of handle ownership.
            std::mem::drop(supervisor::spawn_config_watcher(
                path,
                cfg_swap.clone(),
                bus.clone(),
                Some(mask.clone()),
                Some(upstream_ctx.clone()),
                Some(ip_rate_limiter.clone()),
                tls_resolver.clone(),
            ));
        }
        #[cfg(feature = "etcd")]
        ConfigReloadSource::Etcd(src) => {
            tracing::info!(
                endpoints = ?src.endpoints,
                key = %src.key,
                "config reload watcher: etcd",
            );
            std::mem::drop(config_source::etcd_source::spawn_watcher(
                src,
                cfg_swap.clone(),
                bus.clone(),
                Some(mask.clone()),
                Some(upstream_ctx.clone()),
                Some(ip_rate_limiter.clone()),
                tls_resolver.clone(),
            ));
        }
    }

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
        let decision_metrics_l = decision_metrics.clone();
        let detector_hit_metrics_l = detector_hit_metrics.clone();
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
            decision_metrics_l,
            detector_hit_metrics_l,
        )));
    }

    // PROM-T1 — sync upstream pool gauges at boot, then keep
    // them fresh via a 5 s tick. Off the per-request hot path:
    // the periodic task only runs on its own tokio task, and
    // each tick is one PoolRegistry snapshot read + a bounded
    // walk over the (typically 2-10) pools. Resets the gauges
    // before each set so deleted pools stop reporting cleanly.
    {
        let pools = upstream_ctx.pools.clone();
        upstream_pool_metrics.sync_from_snapshot(&pools.health_counts());
        let metrics = upstream_pool_metrics.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            tick.tick().await; // skip immediate
            loop {
                tick.tick().await;
                metrics.sync_from_snapshot(&pools.health_counts());
            }
        });
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
    let admin_upstream_writer: Arc<dyn aegis_control::api::upstreams_config::UpstreamWriter> =
        Arc::new(upstream_ctx.pools.clone());
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
        admin_upstream_writer,
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
    // CC-T1.1.b — typed-erased writer for the proxy's `PoolRegistry`.
    // Wired by `run()` from `upstream_ctx.pools` so the audit-mutated
    // `/api/upstreams/config` PUT/DELETE handlers can hot-swap the
    // pool table.
    upstream_writer: Arc<dyn aegis_control::api::upstreams_config::UpstreamWriter>,
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
    // /api/mtls/* endpoints have a live data source. The
    // tracker stays empty until MTLS-T2 / T3 land the rustls
    // wiring + identity-extraction stage; what we can populate
    // today is the CA bundle summary if the operator has
    // already configured `cfg.tls.client_auth.ca_bundle`. That
    // gives operators an immediate "validate my CA path +
    // expiry" surface BEFORE flipping mode to required.
    let identity_tracker = std::sync::Arc::new(
        aegis_control::identity_tracker::IdentityTracker::new(),
    );
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

    // CI-T12 — PUT /api/risk/thresholds — audit-mutated;
    // hot-applies new challenge_at / block_at / max via
    // RiskTracker::set_thresholds.
    if method == hyper::Method::PUT && path == "/api/risk/thresholds" {
        return handle_risk_thresholds_put(req, services).await;
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

    // DD-T6 — rule CRUD. Audit-mutated; CSRF-gated; writes the
    // before / after state into the audit chain.
    if method == hyper::Method::POST && path == "/api/rules" {
        return handle_rules_post(req, services).await;
    }
    if method == hyper::Method::PUT && path.starts_with("/api/rules/") {
        let suffix = &path["/api/rules/".len()..];
        if let Some(rule_id) = suffix.strip_suffix("/toggle") {
            return handle_rules_toggle(req, rule_id, services).await;
        }
        if !suffix.is_empty() && !suffix.contains('/') {
            return handle_rules_put(req, suffix, services).await;
        }
    }
    if method == hyper::Method::DELETE && path.starts_with("/api/rules/") {
        let id = &path["/api/rules/".len()..];
        if !id.is_empty() && !id.contains('/') {
            return handle_rules_delete(req, id, services).await;
        }
    }

    // CI-T4 — alert ack. Audit-mutated; CSRF-gated. The ack
    // store lives on `services.tracking`; render_alerts() then
    // moves the alert from `firing` to `resolved`.
    if method == hyper::Method::POST && path.starts_with("/api/alerts/") {
        let suffix = &path["/api/alerts/".len()..];
        if let Some(alert_id) = suffix.strip_suffix("/ack") {
            if !alert_id.is_empty() && !alert_id.contains('/') {
                return handle_alert_ack(req, alert_id, services).await;
            }
        }
    }

    // CI-T6 — global enforce / log_only toggle (shadow mode).
    // Wraps the interop ModeStore so dashboard mutations and the
    // /__waf_control mutations route through the same global
    // mode plane. Audit-mutated; CSRF-gated.
    if method == hyper::Method::PUT && path == "/api/mode" {
        return handle_mode_put(req, services).await;
    }

    // CC-T2.1.b — alert-receivers writes. Audit-mutated; CSRF-
    // gated. Three handlers:
    //   PUT    /api/alert-receivers           whole-list replace
    //   DELETE /api/alert-receivers/{name}    single remove
    //   POST   /api/alert-receivers/{name}/test  synthetic delivery
    if method == hyper::Method::PUT && path == "/api/alert-receivers" {
        return handle_alert_receivers_put(req, services).await;
    }
    if let Some(suffix) = path.strip_prefix("/api/alert-receivers/") {
        if method == hyper::Method::POST {
            if let Some(name) = suffix.strip_suffix("/test") {
                if !name.is_empty() && !name.contains('/') {
                    return handle_alert_receiver_test(req, name, services).await;
                }
            }
        }
        if method == hyper::Method::DELETE
            && !suffix.is_empty()
            && !suffix.contains('/')
        {
            return handle_alert_receiver_delete(req, suffix, services).await;
        }
    }

    // CC-T1.1.b — upstream pool writes. Audit-mutated; CSRF-gated.
    //   PUT    /api/upstreams/config           whole-map replace
    //   PUT    /api/upstreams/pool/{id}        single-pool upsert
    //   DELETE /api/upstreams/pool/{id}        single-pool delete (route-ref guarded)
    if method == hyper::Method::PUT && path == "/api/upstreams/config" {
        return handle_upstreams_config_put(req, cfg, services).await;
    }
    if let Some(suffix) = path.strip_prefix("/api/upstreams/pool/") {
        if !suffix.is_empty() && !suffix.contains('/') {
            if method == hyper::Method::PUT {
                return handle_pool_upsert(req, suffix, cfg, services).await;
            }
            if method == hyper::Method::DELETE {
                return handle_pool_delete(req, suffix, cfg, services).await;
            }
        }
    }

    admin_router(req, cfg, readiness, startup, metrics, services)
}

async fn handle_mode_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "mode-put");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal("body read failed".into()),
        ),
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let parsed: serde_json::Value =
        serde_json::from_str(if body_str.is_empty() { "{}" } else { body_str })
            .unwrap_or(serde_json::Value::Null);
    let mode_str = parsed
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let new_mode = match mode_str {
        "enforce" => aegis_control::interop::headers::Mode::Enforce,
        "log_only" | "shadow" => aegis_control::interop::headers::Mode::LogOnly,
        _ => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(
                "mode must be 'enforce' or 'log_only'".into(),
            ),
        ),
    };

    let Some(rt) = services.interop.as_ref() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "interop runtime not wired".into(),
            ),
        );
    };
    let before = serde_json::json!({"mode": rt.modes.current().default.as_str()});
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/mode",
        action: "mode_set",
        reason: "operator pins global mode",
    };
    let modes = rt.modes.clone();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before,
        serde_json::json!({"mode": new_mode.as_str()}),
        || {
            modes.set_all(new_mode);
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "mode": new_mode.as_str(),
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

// ---------------------------------------------------------------------------
// CC-T2.1.b — alert-receivers writes (PUT / DELETE / POST-test)
// ---------------------------------------------------------------------------

/// Build the redacted audit-chain projection of a receiver list.
/// The durable audit log MUST NOT carry plaintext bot tokens or
/// webhook URLs — every secret is squashed to `****<last4>` before
/// serialisation.
fn redact_receivers_for_audit(
    receivers: &[aegis_control::slo::AlertReceiver],
) -> serde_json::Value {
    use aegis_control::api::alert_receivers::RedactedKind;
    let entries: Vec<serde_json::Value> = receivers
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "kind": RedactedKind::from_kind(&r.kind),
            })
        })
        .collect();
    serde_json::json!({ "receivers": entries })
}

// ---------------------------------------------------------------------------
// CC-T1.1.b — upstream pool writes (PUT whole-map / PUT pool / DELETE pool)
// ---------------------------------------------------------------------------

/// Build the audit-chain projection of the current upstream config.
/// Pool configs hold no secrets so the projection is the same shape
/// the GET handler returns — keeps the chain entry diffable against
/// the dashboard's view of state.
fn upstreams_audit_view(
    cfg_snapshot: &aegis_core::config::WafConfig,
    pools: &std::collections::HashMap<String, aegis_core::config::PoolConfig>,
) -> serde_json::Value {
    // Build a synthetic WafConfig with just `upstreams` swapped so
    // we can reuse `UpstreamsConfigView::from_config`. The view
    // pre-computes `referenced_by_routes` from the live route list,
    // which we want for both before/after.
    let mut cfg = cfg_snapshot.clone();
    cfg.upstreams = pools.clone();
    let view =
        aegis_control::api::upstreams_config::UpstreamsConfigView::from_config(&cfg);
    serde_json::to_value(&view).unwrap_or(serde_json::Value::Null)
}

async fn handle_upstreams_config_put(
    req: hyper::Request<hyper::body::Incoming>,
    cfg: &aegis_core::config::WafConfig,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "upstreams-config-put");

    let Some(writer) = services.upstream_writer.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "upstream writer not wired".into(),
            ),
        );
    };

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(
                    "body read failed".into(),
                ),
            )
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");

    #[derive(serde::Deserialize)]
    struct Body {
        pools: std::collections::HashMap<String, aegis_core::config::PoolConfig>,
    }
    let parsed: Body = match serde_json::from_str(if body_str.is_empty() {
        "{\"pools\":{}}"
    } else {
        body_str
    }) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    let before = upstreams_audit_view(cfg, &cfg.upstreams);
    let after = upstreams_audit_view(cfg, &parsed.pools);
    let count = parsed.pools.len();
    let names: Vec<String> = {
        let mut v: Vec<String> = parsed.pools.keys().cloned().collect();
        v.sort();
        v
    };

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/upstreams/config",
        action: "upstreams_set",
        reason: "operator replaced upstream pool table",
    };
    let writer_for_apply = Arc::clone(&writer);
    let pools_for_apply = parsed.pools;
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        after,
        move || writer_for_apply.apply(&pools_for_apply),
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "count": count,
                "names": names,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

async fn handle_pool_upsert(
    req: hyper::Request<hyper::body::Incoming>,
    pool_id: &str,
    cfg: &aegis_core::config::WafConfig,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "pool-upsert");
    let Some(writer) = services.upstream_writer.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "upstream writer not wired".into(),
            ),
        );
    };

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(
                    "body read failed".into(),
                ),
            )
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let pool_cfg: aegis_core::config::PoolConfig = match serde_json::from_str(body_str) {
        Ok(p) => p,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    // Build the candidate map: existing minus this pool, plus the
    // new entry. Read-modify-write under the registry's atomic
    // swap.
    let mut next = cfg.upstreams.clone();
    next.insert(pool_id.to_string(), pool_cfg);

    let before = upstreams_audit_view(cfg, &cfg.upstreams);
    let after = upstreams_audit_view(cfg, &next);
    let resource = format!("/api/upstreams/pool/{pool_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "pool_upsert",
        reason: "operator upserted upstream pool",
    };
    let writer_for_apply = Arc::clone(&writer);
    let pool_id_owned = pool_id.to_string();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        after,
        move || writer_for_apply.apply(&next),
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "pool": pool_id_owned,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

async fn handle_pool_delete(
    req: hyper::Request<hyper::body::Incoming>,
    pool_id: &str,
    cfg: &aegis_core::config::WafConfig,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "pool-delete");
    let Some(writer) = services.upstream_writer.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "upstream writer not wired".into(),
            ),
        );
    };

    if !cfg.upstreams.contains_key(pool_id) {
        // 400-class validation rather than 500: caller passed a
        // name that doesn't exist. Distinct error message so the
        // dashboard can render the "no such pool" toast directly.
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(format!(
                "no pool named '{pool_id}'"
            )),
        );
    }

    // Refuse with the route-reference list when the pool is still
    // referenced. This is the audit-finding-driven contract: the
    // dashboard's delete confirm modal surfaces this list so the
    // operator knows what to fix first.
    let refs = aegis_control::api::upstreams_config::routes_referencing(cfg, pool_id);
    if !refs.is_empty() {
        let body = serde_json::json!({
            "ok": false,
            "reason": "pool_referenced",
            "message": format!(
                "pool '{pool_id}' is still referenced by {} route(s); update those routes before deleting",
                refs.len()
            ),
            "referenced_by_routes": refs,
        });
        return json_body_response(409, body.to_string(), "private, no-store");
    }

    let mut next = cfg.upstreams.clone();
    next.remove(pool_id);

    let before = upstreams_audit_view(cfg, &cfg.upstreams);
    let after = upstreams_audit_view(cfg, &next);
    let resource = format!("/api/upstreams/pool/{pool_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "DELETE",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "pool_delete",
        reason: "operator removed upstream pool",
    };
    let writer_for_apply = Arc::clone(&writer);
    let pool_id_owned = pool_id.to_string();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        after,
        move || writer_for_apply.apply(&next),
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "removed": pool_id_owned,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

async fn handle_alert_receivers_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "alert-receivers-put");

    let Some(store) = services.alert_receivers_store.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "alert receivers store not wired".into(),
            ),
        );
    };
    let ring = services.alert_receivers_ring.clone();

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(
                    "body read failed".into(),
                ),
            )
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");

    #[derive(serde::Deserialize)]
    struct Body {
        receivers: Vec<aegis_control::slo::AlertReceiver>,
    }
    let parsed: Body = match serde_json::from_str(if body_str.is_empty() {
        "{\"receivers\":[]}"
    } else {
        body_str
    }) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    if let Err(e) =
        aegis_control::api::alert_receivers::validate_receivers(&parsed.receivers)
    {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(e.to_string()),
        );
    }

    let current = (**store.load()).clone();
    let before = redact_receivers_for_audit(&current);
    let after = redact_receivers_for_audit(&parsed.receivers);

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/alert-receivers",
        action: "alert_receivers_set",
        reason: "operator updated alert channel list",
    };

    let store_for_apply = Arc::clone(&store);
    let next_for_apply = parsed.receivers;
    let ring_for_apply = ring.clone();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        after,
        || {
            // Delegate to the pure helper in aegis-control so the
            // validate→swap→prune sequence is unit-tested in one
            // place. Validation already ran above; this call
            // returns Ok in all reachable paths.
            let placeholder_ring =
                aegis_control::api::alert_receivers::DispatchOutcomeRing::new();
            let r = ring_for_apply.as_ref().unwrap_or(&placeholder_ring);
            aegis_control::api::alert_receivers::apply_replace(
                &store_for_apply,
                r,
                next_for_apply,
            )
        },
    );
    match outcome {
        Ok(out) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "count": out.value.count,
                "names": out.value.names,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

async fn handle_alert_receiver_delete(
    req: hyper::Request<hyper::body::Incoming>,
    name: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "alert-receiver-delete");

    let Some(store) = services.alert_receivers_store.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "alert receivers store not wired".into(),
            ),
        );
    };
    let ring = services.alert_receivers_ring.clone();

    let current = (**store.load()).clone();
    let next: Vec<aegis_control::slo::AlertReceiver> = current
        .iter()
        .filter(|r| r.name != name)
        .cloned()
        .collect();
    if next.len() == current.len() {
        // Name not found — surface a validation-class error so the
        // dashboard can show "no such receiver" without 500-ing.
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(format!(
                "no receiver named '{name}'"
            )),
        );
    }

    let before = redact_receivers_for_audit(&current);
    let after = redact_receivers_for_audit(&next);
    let resource = format!("/api/alert-receivers/{name}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "DELETE",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "alert_receiver_delete",
        reason: "operator removed alert channel",
    };

    let store_for_apply = Arc::clone(&store);
    let ring_for_apply = ring.clone();
    let target_name = name.to_string();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        after,
        move || {
            let placeholder_ring =
                aegis_control::api::alert_receivers::DispatchOutcomeRing::new();
            let r = ring_for_apply.as_ref().unwrap_or(&placeholder_ring);
            aegis_control::api::alert_receivers::apply_delete(
                &store_for_apply,
                r,
                &target_name,
            )
        },
    );
    match outcome {
        Ok(o) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "removed": o.value.removed,
                "remaining": o.value.remaining,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

async fn handle_alert_receiver_test(
    req: hyper::Request<hyper::body::Incoming>,
    name: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "alert-receiver-test");

    let Some(store) = services.alert_receivers_store.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "alert receivers store not wired".into(),
            ),
        );
    };

    // Resolve the receiver by name. Done *before* CSRF validation
    // would matter — `services.mutate.apply` enforces CSRF inside;
    // the lookup itself is a read.
    let current = (**store.load()).clone();
    let receiver = match current.iter().find(|r| r.name == name).cloned() {
        Some(r) => r,
        None => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(format!(
                    "no receiver named '{name}'"
                )),
            );
        }
    };

    // Synthetic alert — fixed shape, never derived from operator
    // input, so the test path is bounded.
    let synthetic = aegis_control::slo::SloAlert {
        sli: aegis_control::slo::SliKind::AuditDeliveryRate,
        severity: aegis_control::slo::AlertSeverity::Ticket,
        fired_at: chrono::Utc::now(),
        resolved_at: None,
        burn_rate: 0.0,
        budget_consumed_pct: 0.0,
        window_hours: 1,
        runbook_url: "https://runbooks.aegis.local/test".into(),
    };

    // Audit-mutate envelope first (CSRF + chain entry), then run
    // the actual delivery in a `tokio::spawn` afterwards. We can't
    // `.await` inside the synchronous mutator closure — the
    // existing `apply` signature takes `FnOnce() -> Result<T, E>`.
    // The chain entry records the *intent* to test; the dispatch
    // outcome lands in `DispatchOutcomeRing` once delivery returns.
    let resource = format!("/api/alert-receivers/{name}/test");
    let before = serde_json::json!({});
    let after = serde_json::json!({
        "test_target": name,
        "kind": aegis_control::api::alert_receivers::RedactedKind::from_kind(&receiver.kind),
    });
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "POST",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "alert_receiver_test",
        reason: "operator fired test alert",
    };
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before,
        after,
        || Ok(()),
    );
    if let Err(e) = outcome {
        return mutation_error_response(e);
    }

    // Deliver the synthetic alert against the targeted receiver
    // (length-1 slice — only this channel fires).
    let summary = aegis_control::slo::dispatch::send_alert(
        &synthetic,
        std::slice::from_ref(&receiver),
    )
    .await;

    if let Some(ring) = services.alert_receivers_ring.as_ref() {
        let now = chrono::Utc::now().timestamp();
        for n in &summary.delivered {
            ring.record_delivered(n, now);
        }
        for n in &summary.external {
            ring.record_external(n, now);
        }
        for (n, reason) in &summary.failed {
            ring.record_failed(n, now, reason);
        }
    }

    let body = serde_json::json!({
        "ok": summary.failed.is_empty(),
        "name": name,
        "delivered": summary.delivered,
        "external": summary.external,
        "failed": summary.failed
            .iter()
            .map(|(n, r)| serde_json::json!({"name": n, "reason": r}))
            .collect::<Vec<_>>(),
        "request_id": pre.request_id,
    });
    json_response(200, &body)
}

async fn handle_alert_ack(
    req: hyper::Request<hyper::body::Incoming>,
    alert_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "alert-ack");
    let resource = format!("/api/alerts/{alert_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "POST",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "alert_ack",
        reason: "operator acknowledged alert",
    };
    let tracking = services.tracking.clone();
    let alert_id_owned = alert_id.to_string();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        serde_json::Value::Null,
        serde_json::json!({"alert_id": alert_id, "acked": true}),
        || {
            tracking.ack(&alert_id_owned);
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "alert_id": alert_id,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
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

// ---------- DD-T6 — rule CRUD handlers --------------------------------

#[derive(serde::Deserialize)]
struct RulePostBody {
    id: String,
    body: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(serde::Deserialize)]
struct RulePutBody {
    body: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Helper: read the standard mutation preamble (CSRF cookie +
/// header, actor, request_id) into one struct so the four CRUD
/// handlers don't repeat boilerplate.
struct MutationPreamble {
    csrf_cookie: Option<String>,
    csrf_header: Option<String>,
    actor: String,
    request_id: String,
}

fn mutation_preamble(req: &hyper::Request<hyper::body::Incoming>, prefix: &str) -> MutationPreamble {
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
                    "{prefix}:{}",
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string()
        });
    MutationPreamble { csrf_cookie, csrf_header, actor, request_id }
}

async fn handle_rules_post(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "rules-post");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal("body read failed".into()),
        ),
    };
    let parsed: RulePostBody = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(e) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(e.to_string()),
        ),
    };

    if services.rules.get(&parsed.id).is_some() {
        return json_response(
            409,
            &serde_json::json!({"error": "rule_exists", "id": parsed.id}),
        );
    }

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "POST",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/rules",
        action: "rule_create",
        reason: "operator creates rule",
    };
    let rules_store = services.rules.clone();
    let rule_id = parsed.id.clone();
    let rule_body = parsed.body.clone();
    let rule_enabled = parsed.enabled;
    let outcome = services.mutate.apply(
        &req_ctx,
        serde_json::Value::Null,
        serde_json::json!({"id": parsed.id, "body": parsed.body, "enabled": parsed.enabled}),
        || {
            let v = rules_store.upsert(&rule_id, &rule_body, rule_enabled);
            if v.ok {
                Ok(())
            } else {
                Err(aegis_control::api::mutation::MutationError::Validation(
                    v.errors
                        .first()
                        .map(|m| format!("line {}: {}", m.line, m.message))
                        .unwrap_or_else(|| "rule body invalid".into()),
                ))
            }
        },
    );

    match outcome {
        Ok(_) => json_response(
            201,
            &serde_json::json!({
                "ok": true,
                "id": parsed.id,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

async fn handle_rules_put(
    req: hyper::Request<hyper::body::Incoming>,
    rule_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "rules-put");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal("body read failed".into()),
        ),
    };
    let parsed: RulePutBody = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(e) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(e.to_string()),
        ),
    };

    let before = services
        .rules
        .get(rule_id)
        .map(|r| serde_json::json!({"id": r.id, "body": r.body, "enabled": r.enabled}))
        .unwrap_or(serde_json::Value::Null);
    if before.is_null() {
        return json_response(
            404,
            &serde_json::json!({"error": "rule_not_found", "id": rule_id}),
        );
    }

    let resource = format!("/api/rules/{rule_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "rule_update",
        reason: "operator updates rule",
    };
    let rules_store = services.rules.clone();
    let rule_id_owned = rule_id.to_string();
    let rule_body = parsed.body.clone();
    let rule_enabled = parsed.enabled;
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        serde_json::json!({"id": rule_id, "body": parsed.body, "enabled": parsed.enabled}),
        || {
            let v = rules_store.upsert(&rule_id_owned, &rule_body, rule_enabled);
            if v.ok {
                Ok(())
            } else {
                Err(aegis_control::api::mutation::MutationError::Validation(
                    v.errors
                        .first()
                        .map(|m| format!("line {}: {}", m.line, m.message))
                        .unwrap_or_else(|| "rule body invalid".into()),
                ))
            }
        },
    );

    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "id": rule_id,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

async fn handle_rules_delete(
    req: hyper::Request<hyper::body::Incoming>,
    rule_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "rules-delete");

    let before = services
        .rules
        .get(rule_id)
        .map(|r| serde_json::json!({"id": r.id, "body": r.body, "enabled": r.enabled}))
        .unwrap_or(serde_json::Value::Null);
    if before.is_null() {
        return json_response(
            404,
            &serde_json::json!({"error": "rule_not_found", "id": rule_id}),
        );
    }

    let resource = format!("/api/rules/{rule_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "DELETE",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "rule_delete",
        reason: "operator deletes rule",
    };
    let rules_store = services.rules.clone();
    let rule_id_owned = rule_id.to_string();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        serde_json::Value::Null,
        || {
            if rules_store.delete(&rule_id_owned) {
                Ok(())
            } else {
                Err(aegis_control::api::mutation::MutationError::Internal(
                    "rule disappeared concurrently".into(),
                ))
            }
        },
    );

    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "id": rule_id,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

async fn handle_rules_toggle(
    req: hyper::Request<hyper::body::Incoming>,
    rule_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "rules-toggle");

    let current = match services.rules.get(rule_id) {
        Some(r) => r,
        None => return json_response(
            404,
            &serde_json::json!({"error": "rule_not_found", "id": rule_id}),
        ),
    };

    let next_enabled = !current.enabled;
    let resource = format!("/api/rules/{rule_id}/toggle");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "rule_toggle",
        reason: "operator toggles rule",
    };
    let rules_store = services.rules.clone();
    let rule_id_owned = rule_id.to_string();
    let rule_body = current.body.clone();
    let outcome = services.mutate.apply(
        &req_ctx,
        serde_json::json!({"id": current.id, "enabled": current.enabled}),
        serde_json::json!({"id": current.id, "enabled": next_enabled}),
        || {
            let v = rules_store.upsert(&rule_id_owned, &rule_body, next_enabled);
            if v.ok {
                Ok(())
            } else {
                Err(aegis_control::api::mutation::MutationError::Internal(
                    "toggle revalidation failed".into(),
                ))
            }
        },
    );

    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "id": rule_id,
                "enabled": next_enabled,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

async fn handle_risk_thresholds_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "risk-thresholds-put");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal("body read failed".into()),
        ),
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");

    #[derive(serde::Deserialize)]
    struct Body {
        challenge_at: Option<u32>,
        block_at: Option<u32>,
        max: Option<u32>,
    }
    let parsed: Body = match serde_json::from_str(if body_str.is_empty() { "{}" } else { body_str }) {
        Ok(b) => b,
        Err(e) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(e.to_string()),
        ),
    };

    let current = services.risk.thresholds();
    let next = aegis_core::config::RiskThresholds {
        challenge_at: parsed.challenge_at.unwrap_or(current.challenge_at),
        block_at:     parsed.block_at.unwrap_or(current.block_at),
        max:          parsed.max.unwrap_or(current.max),
    };

    // Sanity: enforce ordering invariants the rule engine assumes.
    if next.challenge_at >= next.block_at {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(
                format!("challenge_at ({}) must be < block_at ({})", next.challenge_at, next.block_at),
            ),
        );
    }
    if next.block_at > next.max {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(
                format!("block_at ({}) must be <= max ({})", next.block_at, next.max),
            ),
        );
    }

    let before = serde_json::json!({
        "challenge_at": current.challenge_at,
        "block_at":     current.block_at,
        "max":          current.max,
    });
    let after = serde_json::json!({
        "challenge_at": next.challenge_at,
        "block_at":     next.block_at,
        "max":          next.max,
    });
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/risk/thresholds",
        action: "risk_thresholds_set",
        reason: "operator updated risk thresholds",
    };
    let tracker = services.risk.clone();
    let next_for_apply = next.clone();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before,
        after,
        || {
            tracker.set_thresholds(next_for_apply.clone());
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "challenge_at": next.challenge_at,
                "block_at":     next.block_at,
                "max":          next.max,
                "request_id":   pre.request_id,
            }),
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
            // DURABLE-T2 — best-effort persist after the in-memory
            // swap succeeds. Disk write failure does NOT fail the
            // PUT — the live mask is already updated, the audit
            // chain entry committed, and next successful PUT will
            // retry persistence. We log a warn so operators can
            // see the durability gap.
            if let Some(persist_cfg) = cfg.detectors.persistence.as_ref() {
                let snap = aegis_control::api::detectors_persist::DetectorMaskSnapshot::from_state(
                    &services.detector_mask.load_state(),
                );
                if let Err(e) = aegis_control::api::detectors_persist::save_snapshot(
                    &persist_cfg.path,
                    &snap,
                ).await {
                    tracing::warn!(
                        path = %persist_cfg.path.display(),
                        error = %e,
                        "detector mask snapshot save failed; live state intact, retry on next PUT",
                    );
                }
            }
            let body = aegis_control::api::detectors::render_get(
                &services.detector_mask,
                &modes,
            );
            json_body_response(200, body, "private, no-store")
        }
        Err(e) => mutation_error_response(e),
    }
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

        // DD-T7 — config-version visibility for hot-reload UI.
        // Returns the current rules-store revision so the dashboard
        // can poll after a mutation and surface "Applied in X.Xs".
        // The version increments on every successful audit-mutation
        // (rule CRUD, detector toggle, loadmode pin, etc.) — every
        // surface that flows through `services.mutate.apply()` is
        // counted automatically, so adding a new mutating endpoint
        // doesn't need a parallel version bump.
        "/api/config/version" => {
            let v = services.mutate.chain_len();
            let body = serde_json::json!({
                "version": v,
                "applied_at_ms": chrono::Utc::now().timestamp_millis(),
                "applied_on_node": services
                    .leader_view
                    .as_ref()
                    .map(|lv| lv.our_node.clone())
                    .unwrap_or_default(),
            });
            json_body_response(200, body.to_string(), "private, no-store")
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
        "/api/routes" => {
            // Read-only view of the routing trie seeded from
            // `cfg.routes` at boot. Cached 30 s — config is
            // hot-reloadable but doesn't change on every request.
            json_body_response(200, services.routes.render(), "private, max-age=30")
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

        // CI-T6 — current global enforce / log_only mode (interop
        // ModeStore). Mirror surface of `/__waf_control/mode`
        // gated behind dashboard auth. PUT lands at the matching
        // mutation handler in dispatch.
        "/api/mode" => {
            let mode = services
                .interop
                .as_ref()
                .map(|rt| rt.modes.current().default.as_str())
                .unwrap_or("enforce");
            let body = serde_json::json!({"mode": mode}).to_string();
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

        // CI-T12 — current risk thresholds. Mirrors the PUT body
        // shape so a roundtrip {GET → modify → PUT} works.
        "/api/risk/thresholds" => {
            let t = services.risk.thresholds();
            let body = serde_json::json!({
                "challenge_at": t.challenge_at,
                "block_at":     t.block_at,
                "max":          t.max,
            })
            .to_string();
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
        // CC-T2.1 — alert-channel management surface. Returns
        // every configured `slo::AlertReceiver` with secrets
        // redacted to last-4 chars, plus per-receiver
        // last-delivery state. Empty body when the proxy hasn't
        // wired the handler (e.g. tests that boot DashboardServices
        // standalone) — keeps the dashboard's empty-state path
        // working without a 404.
        "/api/alert-receivers" => match services.alert_receivers.as_ref() {
            Some(h) => json_body_response(200, h.render(), "private, max-age=2"),
            None => json_body_response(
                200,
                String::from("{\"receivers\":[]}"),
                "private, max-age=2",
            ),
        },
        // MTLS-T6 — read-only mTLS observability surface. Four
        // endpoints. Each works with `identity_tracker: None`
        // (returns empty-state body) so the dashboard renders
        // before MTLS-T2's rustls wiring lands.
        "/api/mtls" => json_body_response(
            200,
            aegis_control::api::mtls::MtlsConfigView::from_config(cfg).render(),
            "private, max-age=2",
        ),
        "/api/mtls/connections" => json_body_response(
            200,
            aegis_control::api::mtls::render_connections(
                services.identity_tracker.as_ref(),
            ),
            "private, max-age=2",
        ),
        "/api/mtls/failures" => json_body_response(
            200,
            aegis_control::api::mtls::render_failures(
                services.identity_tracker.as_ref(),
            ),
            "private, max-age=2",
        ),
        "/api/mtls/ca-summary" => json_body_response(
            200,
            aegis_control::api::mtls::render_ca_summary(
                services.identity_tracker.as_ref(),
            ),
            "private, max-age=2",
        ),
        "/api/upstreams" => json_body_response(200, services.upstreams.render(), "private, max-age=2"),
        // CC-T1.1 — full upstream-pool configuration view. Reads
        // `cfg.upstreams` plus pre-computed route references so
        // the dashboard's edit page renders without a second
        // fetch. Read-only today; the audit-mutated PUT / DELETE
        // handlers ship in CC-T1.1.b once the proxy hot-swap of
        // `ProxyContext.pools` lands.
        "/api/upstreams/config" => {
            let view = aegis_control::api::upstreams_config::UpstreamsConfigView::from_config(cfg);
            json_body_response(200, view.render(), "private, max-age=2")
        }
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

/// CI-T4 — parse one configured cert into the dashboard's
/// inventory shape. Returns `None` when the file is missing or
/// can't be parsed as PEM (the cert provider is best-effort —
/// the real cert loader in `listener::tls` already failed loudly
/// at boot if certs are bad, so silent skips are safe here).
fn read_cert_inventory(
    cfg: &aegis_core::config::CertConfig,
) -> Option<aegis_control::api::tracking::CertInventoryEntry> {
    use std::io::BufReader;
    use x509_parser::prelude::FromDer;

    let pem_bytes = std::fs::read(&cfg.cert_path).ok()?;
    let mut reader = BufReader::new(pem_bytes.as_slice());
    let first = rustls_pemfile::certs(&mut reader)
        .next()
        .and_then(|r| r.ok())?;
    let (_rest, parsed) = x509_parser::certificate::X509Certificate::from_der(&first).ok()?;

    let issuer = parsed
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| parsed.issuer().to_string());

    let host = cfg
        .hosts
        .first()
        .cloned()
        .unwrap_or_else(|| cfg.cert_path.display().to_string());

    let not_after_secs = parsed.validity().not_after.timestamp();
    let expires_at = chrono::DateTime::<chrono::Utc>::from_timestamp(not_after_secs, 0)?;

    Some(aegis_control::api::tracking::CertInventoryEntry {
        host,
        issuer,
        expires_at,
        source: "static".into(),
    })
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

/// AF-T1 — stamp `X-WAF-*` headers + write the minimal-schema
/// audit line on every data-plane response.
///
/// Reads the contract action from the [`DecisionTag`] the
/// data-plane handler attached, NOT from the HTTP status. This
/// matters for `challenge` responses (status 429, body carries
/// "challenge", contract action MUST be `challenge` not
/// `rate_limit`) and for upstream failure modes that map onto
/// `circuit_breaker` / `timeout` rather than the generic
/// `block` an HTTP 502 would suggest.
///
/// When the interop surface is off (`interop = None`) the
/// response is returned unchanged.
fn stamp_interop_response(
    mut resp: Response<Full<Bytes>>,
    decision_tag: aegis_control::interop::headers::DecisionTag,
    interop: Option<&Arc<aegis_control::interop::InteropRuntime>>,
    peer: std::net::SocketAddr,
    method: &hyper::Method,
    path: &str,
    risk_score: u32,
) -> Response<Full<Bytes>> {
    use aegis_control::interop::audit::MinimalAuditEntry;
    use aegis_control::interop::headers::{CacheState, Decision};

    let Some(rt) = interop else {
        return resp;
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
        action: decision_tag.action,
        rule_id: decision_tag.rule_id.clone(),
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
            action: decision_tag.action.as_str().to_string(),
            risk_score,
            mode: mode.as_str().to_string(),
            rule_id: decision_tag.rule_id,
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
    // PROM-T1 — per-decision counter; recorded once per request
    // after `handle_data_request` returns its DecisionTag.
    decision_metrics: Arc<aegis_control::metrics::decisions::DecisionMetrics>,
    // PROM-T2 — per-class detector-hit counter; recorded inside
    // `handle_data_request` for every detector that emits ≥ 1
    // signal on a request.
    detector_hit_metrics: Arc<aegis_control::metrics::detector_hits::DetectorHitMetrics>,
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
            match acceptor {
                Some(acc) => match acc.accept(stream).await {
                    Ok(tls_stream) => {
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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_login::{process_admin_login, process_admin_logout};
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
            std::sync::Arc::new(
                aegis_control::metrics::decisions::DecisionMetrics::register(&metrics_reg)
                    .unwrap(),
            ),
            std::sync::Arc::new(
                aegis_control::metrics::detector_hits::DetectorHitMetrics::register(&metrics_reg)
                    .unwrap(),
            ),
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
        // DD-T1: the redesign mounts at #root via React 18.
        let resp = dashboard_shell_response(false);
        assert_eq!(resp.status(), 200);
        let body = body_string(resp).await;
        assert!(
            body.contains(r#"id="root""#),
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
            body.contains(r#"id="root""#),
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
