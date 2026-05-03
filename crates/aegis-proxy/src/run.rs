//! PRE-T7 (final) — `pub async fn run` boot orchestration
//! extracted from `lib.rs`.
//!
//! ## Scope
//!
//! - [`ConfigReloadSource`] — public enum describing the
//!   config-reload source for the boot path (None / File /
//!   Etcd). Re-exported from `lib.rs` for `aegis-bin`.
//! - [`run`] — the public boot entry point. ~700 lines that
//!   wire every long-running task: detector mask + compliance
//!   clamp + persistence rehydrate, identity tracker, risk
//!   tracker, ip rate-limiter, metrics registry, decision /
//!   detector-hit / state-op metric counter wiring, dashboard
//!   services + audit bus drain, audit-jsonl persist + TTL
//!   tasks, mTLS CA bundle pre-flight parse, ACME issuance
//!   loop, OCSP fetch loop, GitOps poll, threat-intel fetch
//!   loop, SLO evaluate task, lease-store leader heartbeat,
//!   PoolRegistry + DynamicResolver hot-swap handles, file +
//!   etcd cfg-reload watcher spawn, force-https listener,
//!   admin listener, data-plane listeners.
//! - [`force_https_loop`] — plain-HTTP listener that handles
//!   ACME-01 challenges + force-https redirects.
//! - [`build_interop_runtime`] — assembles the
//!   `aegis_control::interop::InteropRuntime` from
//!   `cfg.interop` + risk + rate-limit handles. Returns
//!   `None` when interop is disabled.
//!
//! ## Visibility
//!
//! `run` + `ConfigReloadSource` are `pub`; the helpers are
//! `pub(crate)`. `lib.rs` re-exports `run` and
//! `ConfigReloadSource` so the public API surface stays
//! identical.

use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;

use aegis_core::audit::AuditBus;
use aegis_core::config::WafConfig;
use aegis_core::pipeline::SecurityPipeline;
use aegis_core::state::StateBackend;
use aegis_core::ReadinessSignal;

use crate::accept::{accept_loop, admin_accept_loop};
use crate::admin_dispatch::handle_force_https_request;
#[cfg(feature = "etcd")]
use crate::config_source;
use crate::supervisor;

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
    // Phase-3 per-route latency. Cardinality bounded by the
    // route_id key space (configured `routes:`); each request
    // records one sample after the route resolves.
    let route_latency_hist = std::sync::Arc::new(
        aegis_control::metrics::route_latency::RouteLatencyHistogram::register(&metrics)
            .expect("route latency histogram registration failed"),
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
    // SC-T4 — tokio runtime metrics. Always registered so the
    // /metrics surface is stable; the gauges read 0 unless the
    // build was made with RUSTFLAGS="--cfg tokio_unstable", in
    // which case `sample_now` populates real numbers from
    // `tokio::runtime::Handle::current().metrics()`. The
    // background sampler ticks every 5 s — same cadence as the
    // upstream-pool sync — so the cost is negligible (one
    // atomic-loads-and-set every 5 s).
    let runtime_metrics =
        aegis_control::metrics::runtime::RuntimeMetrics::register(&metrics)
            .expect("runtime metrics registration failed");
    runtime_metrics.spawn_sampler(std::time::Duration::from_secs(5));
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

    // Spawn live health-check tasks for every pool that carries
    // a `health:` block. Without this, configured probes never
    // ran and the dashboard's "members up" stayed at the
    // boot-time default forever.
    let _health_handles = upstream_ctx.spawn_health_checks(&cfg, &bus);

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
    let (tls_acceptor, tls_resolver, client_trust): (
        Option<Arc<tokio_rustls::TlsAcceptor>>,
        Option<Arc<crate::listener::tls::DynamicResolver>>,
        Option<crate::listener::client_trust::ClientTrustStore>,
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

            // MTLS-T2 — when `cfg.tls.client_auth` is set and its
            // `apply_to` includes `Data`, build a
            // `WebPkiClientVerifier` from the configured CA bundle
            // and wire it into the server config. Otherwise fall
            // through to the existing no-client-auth path.
            //
            // Boot-time CA-bundle parse failures fail the boot
            // (operator opted in; silently downgrading to
            // no-client-auth would be a security regression).
            let client_auth_for_data = tls_cfg.client_auth.as_ref().filter(|ca| {
                ca.mode != aegis_core::config::ClientAuthMode::Disabled
                    && ca.apply_to.contains(&aegis_core::config::ClientAuthScope::Data)
            });

            // MTLS-T5 — keep the parsed `ClientTrustStore`
            // around so the cfg-reload watcher can swap it on
            // future cfg changes. `None` when client auth is
            // disabled or scoped to admin only.
            let mut client_trust_for_reload: Option<crate::listener::client_trust::ClientTrustStore> =
                None;
            let mut server_cfg = if let Some(ca) = client_auth_for_data {
                let bundle = ca.ca_bundle.as_ref().ok_or_else(|| {
                    aegis_core::WafError::Config(
                        "tls.client_auth.ca_bundle is required when mode != disabled"
                            .into(),
                    )
                })?;
                let trust = crate::listener::client_trust::ClientTrustStore::load_from_pem_file(bundle)?;
                tracing::info!(
                    mode = ?ca.mode,
                    apply_to = ?ca.apply_to,
                    ca_bundle = %bundle.display(),
                    "mtls inbound client auth enabled (data plane)",
                );
                let server_cfg = crate::listener::tls_policy::build_hardened_server_config_with_client_auth(
                    resolver.clone(),
                    tls_cfg.min_version.as_deref(),
                    &trust,
                    ca.mode,
                )
                .map_err(|e| {
                    aegis_core::WafError::Config(format!(
                        "tls: rustls (with client auth) config build failed: {e}"
                    ))
                })?;
                client_trust_for_reload = Some(trust);
                server_cfg
            } else {
                crate::listener::tls_policy::build_hardened_server_config(
                    resolver.clone(),
                    tls_cfg.min_version.as_deref(),
                )
                .map_err(|e| {
                    aegis_core::WafError::Config(format!(
                        "tls: rustls config build failed: {e}"
                    ))
                })?
            };
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
                client_trust_for_reload,
            )
        }
        _ => (None, None, None),
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
                client_trust.clone(),
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

    // MTLS-T3 — create the per-identity sliding-window tracker
    // here, ahead of both accept loops, so the data-plane
    // (`accept_loop`) can record requests against it AND the
    // admin-plane (`admin_accept_loop`) can stash it on
    // `services.identity_tracker` for `/api/mtls/*` to read.
    // CA-bundle summary loading stays inside `admin_accept_loop`
    // (it knows when boot is "settled").
    let identity_tracker = std::sync::Arc::new(
        aegis_control::identity_tracker::IdentityTracker::new(),
    );

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
        let route_latency_hist_l = route_latency_hist.clone();
        let bus = bus.clone();
        let upstream_ctx_l = upstream_ctx.clone();
        let acceptor = if listener_tls { tls_acceptor.clone() } else { None };
        let interop_l = interop_runtime.clone();
        let decision_metrics_l = decision_metrics.clone();
        let detector_hit_metrics_l = detector_hit_metrics.clone();
        let identity_tracker_l = identity_tracker.clone();
        handles.push(tokio::spawn(accept_loop(
            tcp,
            detectors,
            mask,
            risk,
            ip_rate_limiter,
            load_gauge,
            verbosity,
            request_stage_hist,
            route_latency_hist_l,
            bus,
            upstream_ctx_l,
            acceptor,
            interop_l,
            decision_metrics_l,
            detector_hit_metrics_l,
            // MTLS-T3 — wires per-connection identities into
            // the per-identity sliding-window counter that
            // `/api/mtls/connections` reads.
            Some(identity_tracker_l),
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

    // Boot-time visibility into cookie hardening — a missed-cookie
    // CSRF rejection without this line takes hours to debug.
    if aegis_control::admin_auth::csrf::insecure_cookies_enabled() {
        tracing::warn!(
            "AEGIS_INSECURE_COOKIES=1 — session + CSRF cookies issued WITHOUT Secure flag. \
             Use only on plain-HTTP dev admin listeners; never in production."
        );
    } else {
        tracing::info!(
            "session + CSRF cookies issued with HttpOnly + Secure + SameSite=Strict"
        );
    }

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
    let admin_state_backend = state.clone();
    let admin_identity_tracker = identity_tracker.clone();
    let admin_detectors = detectors.clone();
    let admin_request_stage_hist = request_stage_hist.clone();
    let admin_route_latency_hist = route_latency_hist.clone();
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
        admin_state_backend,
        admin_identity_tracker,
        admin_detectors,
        admin_request_stage_hist,
        admin_route_latency_hist,
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

pub(crate) async fn force_https_loop(
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

pub(crate) fn build_interop_runtime(
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
