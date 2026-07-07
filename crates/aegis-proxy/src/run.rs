//! PRE-T7 (final) — `pub async fn run` boot orchestration
//! extracted from `lib.rs`.
//!
//! ## Scope
//!
//! - [`ConfigReloadSource`] — public enum describing the
//!   config-reload source for the boot path (None / File).
//!   Re-exported from `lib.rs` for `aegis-bin`.
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
use aegis_core::state::StateBackend;
use aegis_core::ReadinessSignal;

use crate::accept::{accept_loop, admin_accept_loop};
use crate::admin_dispatch::handle_force_https_request;
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
/// Resolve the copilot's `api_key_ref` (`${secret:env:…}` /
/// `${secret:vault:…}` / etc.) to the actual key, or `None` when the
/// ref is unset / empty / fails to resolve. Shared by boot wiring and
/// the config-plane fold so the secret is resolved per-node and never
/// stored in the clear. Resolution failure logs a warning and disables
/// the copilot rather than erroring the WAF.
pub(crate) async fn resolve_copilot_api_key(
    cc: &aegis_core::config::CopilotConfig,
) -> Option<String> {
    let raw = cc.api_key_ref.as_deref().map(str::trim).filter(|r| !r.is_empty())?;
    match crate::secrets::expand_secrets_async(raw).await {
        Ok(v) if !v.trim().is_empty() => Some(v),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(error = %e, "copilot api_key_ref failed to resolve — copilot disabled");
            None
        }
    }
}

/// `reload_source` selects the config-reload watcher (file /
/// etcd / none). The boot snapshot is taken from `cfg_swap.load_full()`;
/// subsequent watcher events atomic-swap into `cfg_swap` and run
/// the shared compliance clamp on the detector mask.
pub async fn run(
    cfg_swap: Arc<arc_swap::ArcSwap<WafConfig>>,
    // 2026-05-11 PR #7 — concrete `Arc<Pipeline>` (no longer the
    // trait object) so the boot path can hand the same instance
    // to both `ProxyContext` (via `Arc<dyn SecurityPipeline>`
    // coercion) and `DashboardServices::response_filter_writer`
    // (via `Arc<dyn ResponseFilterWriter>` coercion). The data
    // plane reads `on_body_frame` through the trait object on
    // `ProxyContext.pipeline`; the dashboard flips
    // `ResponseFilterConfig` rungs through the same `Pipeline`
    // instance via the writer trait.
    pipeline: Arc<aegis_security::Pipeline>,
    state: Arc<dyn StateBackend>,
    lease_store: Arc<dyn aegis_core::cluster::LeaseStore>,
    bus: AuditBus,
    readiness: ReadinessSignal,
    reload_source: ConfigReloadSource,
) -> aegis_core::Result<()> {
    // LT-P7 (2026-07-03) — surface broad private/loopback trusted_proxies
    // at boot. `validate()` already REJECTS the internet-wide default
    // route; these ranges are accepted (the single-host front-WAF sidecar
    // is legitimate), but trusting an entire `10.0.0.0/8` / `127.0.0.0/8`
    // for X-Forwarded-For lets any host inside it spoof the client IP, so
    // it's worth a boot-time advisory.
    for net in cfg_swap.load().proxy.parsed_trusted_proxies() {
        if let Some(msg) = aegis_core::config::trusted_proxy_advisory(&net) {
            tracing::warn!("{msg}");
        }
    }

    // 2026-05-11 (PR-DNS-1 boot, PR-DNS-2 soft-failure + refresh
    // specs). Resolve hostname-shaped upstream members before the
    // boot snapshot. The expansion is idempotent on IP-only
    // configs (`MemberAddrSpec::Ip` passes through). With PR-DNS-2
    // we ALSO grab the operator-authored refresh specs ahead of
    // expansion so the per-pool refresh task can re-resolve from
    // the original hostnames; once the registry is built later in
    // this function the task gets spawned (search "PR-DNS-2 spawn"
    // below).
    //
    // Failure policy is `SoftSkip` because the refresh task will
    // retry any hostname that didn't resolve at boot — Phase 1's
    // strict abort is still used by the dashboard PUT path so
    // operators catch typos at config-set time.
    // BUG-dns-refresh-not-spawned-for-live-added-hostnames — capture the
    // operator-authored upstreams (pre Phase-1 hostname expansion) so the
    // DNS-refresh manager can reconcile per-pool refresh tasks at boot and
    // again on every later config apply (dashboard PUT / cluster
    // convergence), not just at boot.
    let boot_authored_upstreams = {
        let raw = cfg_swap.load_full();
        raw.upstreams.clone()
    };
    {
        let raw = cfg_swap.load_full();
        let mut next: WafConfig = (*raw).clone();
        next.upstreams = crate::upstream::dns_resolve::expand_hostname_members_with_policy(
            next.upstreams,
            crate::upstream::dns_resolve::ResolveFailurePolicy::SoftSkip,
        )
        .await
        .map_err(|e| aegis_core::WafError::Config(e.to_string()))?;
        cfg_swap.store(Arc::new(next));
    }

    // 2026-06-09 (P4 4a-ii / trust bundles) — materialize state-sourced
    // Zero Trust material (the shared upstream identity's PUBLIC cert +
    // any console-uploaded backend-CA trust bundles a pool references)
    // from the Redis config plane before the (sync) pool build path
    // (`ProxyContext::build` has no `StateBackend`). Reference-only:
    // only PUBLIC cert/CA material is folded into the cfg snapshot; the
    // private key stays a `key_ref`. Fail closed — a `source: state`
    // identity that can't be materialized (or a corrupt referenced
    // trust bundle) aborts boot rather than silently dialing without
    // client auth / pinning. See
    // `upstream::identity::materialize_zero_trust_state`.
    {
        let raw = cfg_swap.load_full();
        if let Some(next) =
            crate::upstream::identity::materialize_zero_trust_state(&raw, &state).await?
        {
            cfg_swap.store(Arc::new(next));
            tracing::info!(
                "zero_trust: materialized PUBLIC upstream-mTLS material from the \
                 config plane (identity cert and/or backend-CA trust bundles)"
            );
        }
    }

    // Boot snapshot — every existing read site keeps `cfg` as
    // `Arc<WafConfig>`. Future per-handler `cfg.load()` calls
    // can read the latest revision without churning the whole
    // function.
    let cfg: Arc<WafConfig> = cfg_swap.load_full();
    let mut handles = Vec::new();

    // 2026-06-02 (observability alert P1) — install the process alert
    // identity once so every SLO alert message names the deployment it
    // fired from (service · node · env) instead of being anonymous.
    aegis_control::slo::dispatch::set_alert_identity(aegis_control::slo::dispatch::AlertIdentity {
        service: "aegis-gate".to_string(),
        node: cfg.node.id.clone(),
        environment: cfg.admin.environment.clone(),
    });

    // 2026-06-03 — build the AI Operator Copilot from
    // `observability.copilot` and install it as the live service. The API
    // key is a `${secret:...}` reference resolved here (env / file / vault
    // / cloud) so it never sits inline in config or transits the cluster
    // doc; the config plane later hot-swaps the service via
    // `apply_cfg_change_to_copilot`. When the copilot block is absent /
    // disabled we fall back to the legacy `LLM_*` env build so pure-env
    // deployments keep working; an absent provider just means the copilot
    // endpoints return 503.
    {
        let cc = &cfg.observability.copilot;
        let svc = if cc.enabled {
            let api_key = resolve_copilot_api_key(cc).await;
            aegis_control::copilot::service::CopilotService::from_config(cc, api_key)
        } else {
            aegis_control::copilot::service::CopilotService::from_env()
        };
        aegis_control::copilot::service::set_global(svc);
    }

    // 2026-05-27 (Phase B) — seed the response-filter rungs from
    // `cfg.response_filter` at boot so an operator-authored YAML value
    // (e.g. `redact_dlp: false`) is honored. Defaults are all-true, so a
    // config that omits the block leaves the pipeline at its prior
    // default — byte-identical boot behaviour.
    pipeline.set_filter_config(aegis_security::pipeline::ResponseFilterConfig {
        scrub_stack_traces: cfg.response_filter.scrub_stack_traces,
        mask_internal_ips: cfg.response_filter.mask_internal_ips,
        redact_dlp: cfg.response_filter.redact_dlp,
        strip_response_headers: cfg.response_filter.strip_response_headers,
    });

    // 2026-05-27 (Phase B) — create the shared TierStore here so the same
    // Arc threads into BOTH the config-plane watcher (re-derives per-tier
    // settings from `cfg.tiers` on a swap) AND `DashboardServices` (where
    // it's boot-seeded + shared with the data plane). Boot seeding from
    // `cfg.tiers` happens in `admin_accept_loop`.
    let tier_store = Arc::new(aegis_control::api::tiers::TierStore::new());

    // 2026-05-27 (Phase B rules fold) — create the shared RuleStore here
    // (same template as TierStore) so one Arc threads into BOTH the
    // config-plane watcher AND `DashboardServices` (`services.rules`).
    // Seed it from `cfg.rules.inline` and rebuild the live engine ruleset
    // (`pipeline.rules_arc()`, the same Arc `admin_accept_loop` later
    // shares with `ProxyContext`) so operator rules are durable across
    // restarts and live from the first request — not just after a CRUD.
    let rule_store = Arc::new(aegis_control::api::rules::RuleStore::new());
    {
        let live_ruleset = pipeline.rules_arc();
        match crate::config_source::reload::apply_cfg_change_to_rules(
            &cfg,
            Some(&rule_store),
            Some(&live_ruleset),
        ) {
            crate::config_source::reload::RulesReloadOutcome::Applied {
                live_rules,
                rejected,
            } => {
                if !rejected.is_empty() {
                    tracing::warn!(
                        rejected = ?rejected,
                        "cfg.rules.inline had entries that failed validation; skipped at boot seed",
                    );
                }
                tracing::info!(
                    live_rules,
                    inline = cfg.rules.inline.len(),
                    "seeded RuleStore from cfg.rules.inline",
                );
            }
            crate::config_source::reload::RulesReloadOutcome::NoStore => {}
        }
    }

    // FDP-T2 — adopt listener FDs from an exec'ing parent if
    // present. `AEGIS_LISTEN_FDS=N` + `AEGIS_LISTEN_FD_NAMES=...`
    // signals "first-boot path is fresh-bind" vs "hot-handover
    // path is adopt". Misconfigured (non-empty count but bad
    // env shape) fails fast — silent fresh-bind would race the
    // parent's still-alive FD on the same port.
    let mut inherited_listeners = match crate::hotbin::adopt_inherited_listeners() {
        crate::hotbin::AdoptOutcome::NoInheritance => {
            tracing::info!("hotbin: no inherited listeners — fresh-bind every listener");
            std::collections::HashMap::new()
        }
        crate::hotbin::AdoptOutcome::Inherited(map) => {
            tracing::info!(
                names = ?map.keys().cloned().collect::<Vec<_>>(),
                "hotbin: adopted inherited listener FDs",
            );
            map
        }
        crate::hotbin::AdoptOutcome::Misconfigured(reason) => {
            return Err(aegis_core::WafError::Config(format!(
                "hotbin: AEGIS_LISTEN_FD* env is set but malformed: {reason}",
            )));
        }
    };

    // FDP drain refactor — record (name, RawFd) for every
    // listener we adopt-or-bind so the SIGUSR2 polling task
    // can build a `SuccessorPlan` without re-walking the
    // tokio listener tree. The FDs stay valid for the proxy
    // lifetime because each accept loop owns the listener
    // (which holds the FD); we only read the value here for
    // dup2 in the post-fork child.
    #[cfg(unix)]
    let mut listener_fd_registry: Vec<(String, std::os::fd::RawFd)> = Vec::new();

    // MTLS-T9 — capture break-glass env-var state at boot.
    // Boot-only by design (a runtime override would defeat the
    // purpose). Subsequent calls to `is_active()` read the
    // cached AtomicBool — hot-path safe.
    let break_glass = aegis_core::break_glass::init_from_env();
    if break_glass {
        tracing::warn!(
            "MTLS BREAK-GLASS ACTIVE — `AEGIS_ZERO_TRUST_BREAK_GLASS=1` set; \
             `client_auth.mode: required` is downgraded to `optional` \
             on every TLS listener for the duration of this process. \
             Unset the env var and restart to return to enforced mode."
        );
        // One-shot audit event at boot. The 60s heartbeat below
        // re-emits while the process lives.
        bus.emit(aegis_core::audit::AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: String::new(),
            class: aegis_core::audit::AuditClass::System,
            tenant_id: None,
            tier: None,
            action: "zero_trust_break_glass_active".into(),
            reason: "AEGIS_ZERO_TRUST_BREAK_GLASS=1 captured at boot".into(),
            client_ip: String::new(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            method: None,
            path: None,
            mode: None,
            fields: serde_json::json!({"effective_mode_override": "required→optional"}),
        });
        // Heartbeat task — re-warns every 60s + re-emits the
        // audit event so the trail can't be missed in long-
        // running sessions.
        let bus_hb = bus.clone();
        handles.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Skip the first immediate tick (we already logged at boot).
            ticker.tick().await;
            loop {
                ticker.tick().await;
                tracing::warn!("MTLS BREAK-GLASS still active (60s heartbeat)");
                bus_hb.emit(aegis_core::audit::AuditEvent {
                    schema_version: 1,
                    ts: chrono::Utc::now(),
                    request_id: String::new(),
                    class: aegis_core::audit::AuditClass::System,
                    tenant_id: None,
                    tier: None,
                    action: "zero_trust_break_glass_heartbeat".into(),
                    reason: "AEGIS_ZERO_TRUST_BREAK_GLASS still active".into(),
                    client_ip: String::new(),
                    route_id: None,
                    rule_id: None,
                    risk_score: None,
                    method: None,
                    path: None,
                    mode: None,
                    fields: serde_json::Value::Null,
                });
            }
        }));
    }

    // Build the detector set once, shared across all data-plane listeners.
    //
    // AI-T5 — feature-gated wiring of the ML detector lives
    // further down (AI metrics need the registry which is built
    // a few sections later).  We hold the vec mutable here and
    // append the AI detector after metrics init.
    //
    // The `not(feature = "ai")` branch fails boot loudly when
    // `cfg.ai.enabled = true` on a binary built without the
    // feature so the misconfiguration is visible.
    // 2026-05-18 F-CRITICAL-012 (security audit, Phase F): wire the
    // canary detector. 2026-05-20 — the honeypot path set now lives
    // in a shared, hot-swappable `CanaryPaths` handle so it can be
    // edited live from the Settings page via PUT
    // /api/risk/canary-paths. We seed it from `cfg.risk.canary_paths`
    // and clone the handle into `DashboardServices` further down so
    // the admin mutation and the data-plane detector share state.
    let canary_paths = aegis_security::detectors::canary::CanaryPaths::new(&cfg.risk.canary_paths);
    // AC-P2-b (2026-07-04) — build the brute-force detector as a shared
    // handle so (a) the fleet backend can be installed AFTER the state
    // backend exists (the chain is built before `state`), and (b) the
    // config watchers can hot-apply `count_scope` via
    // `apply_cfg_change_to_brute_force`. The chain slot runs this same
    // instance through the delegating `Detector for Arc<…>` impl.
    let brute_force = std::sync::Arc::new(
        aegis_security::detectors::brute_force::BruteForceDetector::default(),
    );
    brute_force.set_count_scope(cfg.detectors.brute_force.count_scope);
    #[allow(unused_mut)]
    let mut detector_vec = aegis_security::detectors::default_detectors_with_canary(
        &cfg.detectors,
        &canary_paths,
        Some(brute_force.clone()),
    );
    #[cfg(not(feature = "ai"))]
    {
        if cfg.ai.enabled {
            return Err(aegis_core::WafError::Config(
                "ai.enabled = true but the binary was built without `--features ai` \
                 (rebuild with `FEATURES=\"redis geoip ai\" make build`)"
                    .into(),
            ));
        }
    }

    // Hot-reloadable detector class mask. Initial state mirrors
    // `cfg.detectors`; the control plane swaps it via PUT
    // `/api/detectors` (folded through the cluster config plane in
    // Phase B), and the config watchers re-derive it on reload.
    //
    // 2026-05-27 (Phase B detectors fold) — seed the full effective
    // state (base + `Ai` bit from the sibling `cfg.ai.enabled` block +
    // `cfg.detectors.per_tier` overrides) through the same
    // `MaskState::from_detectors_config` constructor the watchers use,
    // so a per-tier overlay authored in YAML applies at boot, not just
    // after the first reload. The existing `Arc<AtomicBool>` (set
    // further down) stays as the global AI kill-switch.
    let mask = aegis_security::detectors::SharedDetectorMask::from_state(
        aegis_security::detectors::MaskState::from_detectors_config(&cfg.detectors, cfg.ai.enabled),
    );

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
                let outcome = aegis_control::api::detectors_persist::apply_snapshot_with_compliance(
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
    let ip_rate_limiter = Arc::new(aegis_security::rate_limit::IpRateLimiter::new(
        crate::config_source::reload::derive_ip_rate_cfg(&cfg),
    ));

    // F-T10 — per-stage latency histogram. Build the metrics
    // registry once here so both the data plane (which now
    // emits `waf_request_duration_ms`) and the admin plane
    // (which exposes `/metrics`) share the same series.
    let metrics = aegis_control::metrics::MetricsRegistry::init();
    let request_stage_hist = std::sync::Arc::new(
        aegis_control::metrics::request_duration::RequestStageHistogram::register(&metrics)
            .expect("histogram registration failed"),
    );

    // AI-T5 / AI-T6 — push the ML detector onto the chain now
    // that the metrics registry exists.  Boot fails loudly on
    // a missing model file or an unreadable .onnx; the
    // metrics-disabled binary already errored above.
    #[cfg(feature = "ai")]
    let ai_runtime_toggle: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>;
    #[cfg(not(feature = "ai"))]
    let ai_runtime_toggle: Option<std::sync::Arc<std::sync::atomic::AtomicBool>> = None;
    // 2026-05-29 — parallel handle for `cfg.ai.confidence_threshold`.
    // Captured inside the Ok arms of the AI-detector branches below
    // (same shape as `toggle` capture) into this `mut` Option so the
    // existing `ai_runtime_toggle = match {...}` structure stays
    // surgical. Audit-mutated `PUT /api/ai/confidence` reads the
    // shared atomic from `services.ai_threshold` and updates the same
    // backing store the data plane reads per inference.
    // Mutated only in the `#[cfg(feature = "ai")]` branches below; without
    // the feature it stays `None` (same gate as `ai_model_reloader_inner`).
    #[cfg_attr(not(feature = "ai"), allow(unused_mut))]
    let mut ai_runtime_threshold_inner: Option<std::sync::Arc<std::sync::atomic::AtomicU32>> = None;
    // Model hot-reload bridge — captured in the sync AI-detector branch below
    // (the batch path doesn't expose a swappable handle yet). Drives
    // `POST /api/ai/reload`; `None` leaves the endpoint reporting "unavailable".
    #[cfg_attr(not(feature = "ai"), allow(unused_mut))]
    let mut ai_model_reloader_inner: Option<
        std::sync::Arc<dyn aegis_control::api::ai_reload::AiReloadWriter>,
    > = None;
    #[cfg(feature = "ai")]
    {
        if cfg.ai.batch_enabled {
            // 2026-05-23 — in-process dynamic batching. Spin up the batch
            // accumulator (N parallel sessions + collector) and install
            // the BatchAiDetector. Same verdict/toggle semantics as the
            // single detector; just amortises ORT cost across a [N,27]
            // pass instead of serialising [1,27] behind one session.
            ai_runtime_toggle = match cfg.ai.model_path.as_ref() {
                Some(model_path) if model_path.exists() => {
                    let normal_idx = aegis_security::detectors::ai::DEFAULT_NORMAL_CLASS_IDX;
                    let ai_metrics = std::sync::Arc::new(
                        aegis_control::metrics::ai::AiMetrics::register(&metrics).map_err(|e| {
                            aegis_core::WafError::Config(format!(
                                "ai metrics registration failed: {e}"
                            ))
                        })?,
                    );
                    match aegis_security::detectors::ai::batch_spawn(
                        model_path,
                        normal_idx,
                        cfg.ai.workers,
                        cfg.ai.max_batch,
                        cfg.ai.delay_ms,
                    ) {
                        Ok(svc) => {
                            let detector = aegis_security::detectors::ai::BatchAiDetector::new(
                                svc,
                                cfg.ai.confidence_threshold,
                                aegis_security::detectors::scores::ai::AI,
                            )
                            .with_metrics(ai_metrics);
                            let toggle = detector.runtime_toggle();
                            toggle.store(cfg.ai.enabled, std::sync::atomic::Ordering::Relaxed);
                            // 2026-05-29 — stash the runtime-threshold handle
                            // BEFORE boxing the detector. The dashboard's
                            // `PUT /api/ai/confidence` updates this same
                            // AtomicU32; per-inference reads happen via
                            // `BatchAiDetector::threshold()`.
                            ai_runtime_threshold_inner = Some(detector.runtime_threshold());
                            tracing::info!(
                                model_path = %model_path.display(),
                                threshold = cfg.ai.confidence_threshold,
                                workers = cfg.ai.workers,
                                max_batch = cfg.ai.max_batch,
                                delay_ms = cfg.ai.delay_ms,
                                initial_enabled = cfg.ai.enabled,
                                "AI batch detector loaded; runtime toggle wired",
                            );
                            detector_vec.push(Box::new(detector));
                            Some(toggle)
                        }
                        Err(e) => {
                            if cfg.ai.enabled {
                                return Err(aegis_core::WafError::Config(format!(
                                    "ai.enabled = true but batch model load from {} failed: {e}",
                                    model_path.display(),
                                )));
                            }
                            tracing::warn!(
                                model_path = %model_path.display(),
                                error = %e,
                                "ai.enabled = false and batch model load failed — \
                                 AI detector skipped",
                            );
                            None
                        }
                    }
                }
                Some(model_path) => {
                    if cfg.ai.enabled {
                        return Err(aegis_core::WafError::Config(format!(
                            "ai.enabled = true but model file does not exist at {}",
                            model_path.display(),
                        )));
                    }
                    tracing::warn!(
                        model_path = %model_path.display(),
                        "ai.model_path set but file missing — AI batch detector skipped",
                    );
                    None
                }
                None => {
                    tracing::warn!(
                        "ai.batch_enabled = true but no model_path configured — \
                         AI detector skipped",
                    );
                    None
                }
            };
        } else {
            // 2026-05-10 — AI detector now loads whenever
            // `cfg.ai.model_path` points at an existing file, regardless
            // of `cfg.ai.enabled`. The detector's runtime toggle
            // controls request-time evaluation; the YAML `enabled` flag
            // only seeds the *initial* toggle state. This lets operators
            // flip AI on from Detectors & Tiers → AI row → Enable
            // without a restart (previously the dashboard's Enable
            // button was inert in the common dev case where
            // `enabled: false` left the runtime un-installed).
            ai_runtime_toggle = match cfg.ai.model_path.as_ref() {
                Some(model_path) if model_path.exists() => {
                    let normal_idx = aegis_security::detectors::ai::DEFAULT_NORMAL_CLASS_IDX;
                    let ai_metrics = std::sync::Arc::new(
                        aegis_control::metrics::ai::AiMetrics::register(&metrics).map_err(|e| {
                            aegis_core::WafError::Config(format!(
                                "ai metrics registration failed: {e}"
                            ))
                        })?,
                    );
                    // 2026-05-23 — load a session pool of `cfg.ai.sessions`
                    // (1 = single session, the default). N > 1 parallelises
                    // inference across N sessions via the synchronous
                    // round-robin path — no batching, no async bridge.
                    match aegis_security::detectors::ai::Model::load_pool(
                        model_path,
                        normal_idx,
                        cfg.ai.sessions,
                    ) {
                        Ok(model) => {
                            let sessions = model.session_count();
                            let detector = aegis_security::detectors::ai::AiDetector::from_model(
                                std::sync::Arc::new(model),
                                cfg.ai.confidence_threshold,
                            )
                            .with_metrics(ai_metrics);
                            // AI-T10 — grab the runtime-toggle handle BEFORE
                            // we box the detector. Both the data plane and
                            // the control plane read the same `AtomicBool`.
                            let toggle = detector.runtime_toggle();
                            // 2026-05-29 — same idea for `confidence_threshold`:
                            // stash the shared AtomicU32 the dashboard's
                            // `PUT /api/ai/confidence` will flip and the data
                            // plane reads via `AiDetector::threshold()`.
                            ai_runtime_threshold_inner = Some(detector.runtime_threshold());
                            // Model hot-reload — capture the swappable handle so
                            // `POST /api/ai/reload` can load a new model from this
                            // same path and atomically swap it into the live
                            // detector (the data plane reads the same ArcSwap).
                            let reloader: std::sync::Arc<
                                dyn aegis_control::api::ai_reload::AiReloadWriter,
                            > = std::sync::Arc::new(crate::ai_reload::AiModelReloader::new(
                                detector.model_handle(),
                                model_path.clone(),
                                normal_idx,
                                sessions,
                            ));
                            ai_model_reloader_inner = Some(reloader);
                            // Seed the toggle from `cfg.ai.enabled`. The
                            // detector's default is `true`; we override here
                            // so `enabled: false` in YAML still boots with
                            // AI off (operator opts in via dashboard).
                            toggle.store(cfg.ai.enabled, std::sync::atomic::Ordering::Relaxed);
                            tracing::info!(
                                model_path = %model_path.display(),
                                threshold = cfg.ai.confidence_threshold,
                                sessions,
                                initial_enabled = cfg.ai.enabled,
                                "AI detector loaded; runtime toggle wired",
                            );
                            detector_vec.push(Box::new(detector));
                            Some(toggle)
                        }
                        Err(e) => {
                            // Fail-soft when the model is malformed:
                            // log + leave AI un-installed so the boot
                            // path doesn't trip on a corrupt artifact.
                            // Dashboard will show "feature off" until
                            // the operator fixes the model and restarts.
                            // 2026-05-10 — operator-confirmed: a broken
                            // model shouldn't block boot in dev / CI.
                            if cfg.ai.enabled {
                                // If the YAML asked for AI explicitly,
                                // surface the failure as a hard config
                                // error so prod doesn't silently drop AI.
                                return Err(aegis_core::WafError::Config(format!(
                                    "ai.enabled = true but model load from {} failed: {e}",
                                    model_path.display(),
                                )));
                            }
                            tracing::warn!(
                                model_path = %model_path.display(),
                                error = %e,
                                "ai.enabled = false and model load failed — \
                                 AI detector skipped (operator can't enable from dashboard \
                                 until the model loads cleanly)",
                            );
                            None
                        }
                    }
                }
                Some(model_path) => {
                    // model_path set but file missing.
                    if cfg.ai.enabled {
                        return Err(aegis_core::WafError::Config(format!(
                            "ai.enabled = true but model file does not exist at {}",
                            model_path.display(),
                        )));
                    }
                    tracing::warn!(
                        model_path = %model_path.display(),
                        "ai.model_path set but file missing — AI detector skipped \
                         (run `make ai-link MODEL=<path>` or set a valid path)",
                    );
                    None
                }
                None => {
                    // No model_path configured. Dashboard will show
                    // "feature off" with the rebuild-and-configure hint.
                    None
                }
            };
        }
    }
    // 2026-05-29 — surface the threshold handle captured inside the AI
    // branches above (or `None` when the binary lacks `--features ai` /
    // the detector wasn't installed). From here it travels alongside
    // `ai_runtime_toggle` into the ProxyContext / DashboardServices.
    let ai_runtime_threshold = ai_runtime_threshold_inner;
    // Travels alongside `ai_runtime_toggle` into `admin_accept_loop`, which
    // stashes it on `services.ai_reload` for the `POST /api/ai/reload` handler.
    let ai_model_reloader = ai_model_reloader_inner;
    let detectors: std::sync::Arc<Vec<Box<dyn aegis_security::detectors::Detector>>> =
        std::sync::Arc::new(detector_vec);
    // Phase-3 per-route latency. Cardinality bounded by the
    // route_id key space (configured `routes:`); each request
    // records one sample after the route resolves.
    let route_latency_hist = std::sync::Arc::new(
        aegis_control::metrics::route_latency::RouteLatencyHistogram::register(&metrics)
            .expect("route latency histogram registration failed"),
    );
    // P5 (2026-05-11) — sliding-window per-route activity counter.
    // Built once at boot; the same handle reaches the data plane
    // (for `record`) and the admin endpoint (`GET /api/analytics/
    // route-activity`). Cheap to clone — the inner `DashMap` is
    // `Arc`-shared.
    let route_activity = aegis_control::metrics::route_activity::RouteActivityWindow::new();
    // Per-detector evaluation-duration histogram. Same wiring
    // pattern as `route_latency_hist`; data plane records around
    // each `Detector::inspect` call.
    let detector_latency_hist = std::sync::Arc::new(
        aegis_control::metrics::detector_latency::DetectorLatencyHistogram::register(&metrics)
            .expect("detector latency histogram registration failed"),
    );
    // PROM-T1 — per-decision counter `waf_requests_total{action}`.
    // Lights up the WAF Overview "Decision mix" panel.
    let decision_metrics = std::sync::Arc::new(
        aegis_control::metrics::decisions::DecisionMetrics::register(&metrics)
            .expect("decision metrics registration failed"),
    );
    // WS-T6 — WebSocket bridge metrics (open / close totals,
    // active gauge).  Stashed onto ProxyContext below so the
    // bridge code can call `record_open` / `record_close`
    // without threading through every parameter.
    let websocket_metrics = std::sync::Arc::new(
        aegis_control::metrics::websocket::WebSocketMetrics::register(&metrics)
            .expect("websocket metrics registration failed"),
    );
    // SSE streaming metrics (active gauge / streamed counter / duration +
    // bytes histograms). Shared into the ProxyContext below.
    let stream_metrics = std::sync::Arc::new(
        aegis_control::metrics::streaming::StreamingMetrics::register(&metrics)
            .expect("streaming metrics registration failed"),
    );
    // Zone-aware LB P3 — served-local-vs-cross-zone routing counter. Stashed
    // onto ProxyContext below; the pick sites increment it per request.
    let zone_metrics = std::sync::Arc::new(
        aegis_control::metrics::zone_routing::ZoneRoutingMetrics::register(&metrics)
            .expect("zone routing metrics registration failed"),
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
    // PROXY-T3 — PROXY-protocol event counter
    // `waf_proxy_protocol_events_total{result}`. Recorded once per
    // connection on an `accept_proxy` listener. The label set is owned
    // by `listener::proxy_protocol` so the hot path and registration
    // share one source of truth. Always registered (zero-valued series)
    // so the panel exists even on fleets that never enable PROXY.
    let proxy_protocol_metrics = std::sync::Arc::new(
        aegis_control::metrics::proxy_protocol::ProxyProtocolMetrics::register(
            &metrics,
            &crate::listener::proxy_protocol::METRIC_LABELS,
        )
        .expect("proxy-protocol metrics registration failed"),
    );
    // SC-T4 — tokio runtime metrics. Always registered so the
    // /metrics surface is stable; the gauges read 0 unless the
    // build was made with RUSTFLAGS="--cfg tokio_unstable", in
    // which case `sample_now` populates real numbers from
    // `tokio::runtime::Handle::current().metrics()`. The
    // background sampler ticks every 5 s — same cadence as the
    // upstream-pool sync — so the cost is negligible (one
    // atomic-loads-and-set every 5 s).
    let runtime_metrics = aegis_control::metrics::runtime::RuntimeMetrics::register(&metrics)
        .expect("runtime metrics registration failed");
    runtime_metrics.spawn_sampler(std::time::Duration::from_secs(5));
    // PROM-T3 — per-op state-backend counter
    // `waf_state_backend_ops_total{op,outcome}`. Wraps the
    // resolved state backend with a delegating impl that
    // records every dispatch — every downstream consumer of
    // `state` is automatically instrumented.
    let state_op_metrics = aegis_control::metrics::state_ops::StateOpMetrics::register(&metrics)
        .expect("state op metrics registration failed");
    let state: Arc<dyn aegis_core::state::StateBackend> = Arc::new(
        aegis_control::metrics::state_ops::MeteredStateBackend::new(state, state_op_metrics),
    );
    // 2026-06-24 (redis-interim-durability A0/A2) — attach the resolved
    // state backend to the risk tracker so the P2 durability flush/hydrate
    // can persist lifetime strikes to `control:waf:risk`. The tracker was
    // built above (before the backend existed), so this is a
    // post-construction setter — it propagates to every clone via the
    // shared inner. Gated on `redis`.
    #[cfg(feature = "redis")]
    {
        risk.attach_backend(state.clone());
        // A2 — spawn the background hydrate (boot, non-blocking) + the
        // periodic dirty-set flush. Hot path stays DashMap-only; persistence
        // runs entirely off the request path.
        risk.spawn_persistence();
    }
    // PROM-T3 — audit event counter `waf_audit_events_total{class}`.
    // Recorded by a metrics-only AuditBus subscriber spawned
    // alongside the existing dashboard SSE drain. Cost = one
    // bounded broadcast Receiver + one tokio task; no per-emit
    // call-site changes.
    let audit_event_metrics = std::sync::Arc::new(
        aegis_control::metrics::audit_events::AuditEventMetrics::register(&metrics)
            .expect("audit event metrics registration failed"),
    );
    // AU-2 — waf_audit_events_dropped_total{consumer}. Installed
    // globally so the consumer tasks (dashboard drain, jsonl persist,
    // syslog forward, this metrics subscriber) can record their
    // Lagged drops without threading the handle everywhere.
    aegis_control::metrics::audit_events::AuditDropMetrics::register(&metrics)
        .expect("audit drop metrics registration failed")
        .install_global();
    // AU-3B — risk-tracker saturation gauges, sampled off the hot
    // path. `saturation_rejects` is monotonic (cumulative at-cap
    // requests scored-but-not-stored); `saturated` is 0/1.
    {
        let g_rejects = metrics
            .register_gauge(
                "waf_risk_tracker_saturation_rejects",
                "Cumulative requests scored but NOT stored because the risk tracker hit MAX_TRACKED_KEYS (fail-open, AU-3B).",
            )
            .expect("risk saturation gauge registration failed");
        let g_saturated = metrics
            .register_gauge(
                "waf_risk_tracker_saturated",
                "1 while the risk tracker is at its cardinality cap (new keys never accumulate), else 0.",
            )
            .expect("risk saturated gauge registration failed");
        let tracker = risk.clone();
        tokio::spawn(async move {
            let mut tick =
                tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                tick.tick().await;
                g_rejects.set(tracker.saturation_rejects() as f64);
                g_saturated.set(if tracker.is_saturated() { 1.0 } else { 0.0 });
            }
        });
    }
    {
        let bus_sub = bus.clone();
        let m = audit_event_metrics.clone();
        tokio::spawn(async move {
            let mut rx = bus_sub.subscribe();
            loop {
                match rx.recv().await {
                    Ok(ev) => m.record(ev.class),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        aegis_control::metrics::audit_events::record_dropped(
                            aegis_control::metrics::audit_events::consumer_label::METRICS,
                            n,
                        );
                        tracing::warn!(dropped = n, "audit event metrics subscriber lagged",);
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
    // 2026-05-11 PR #7 follow-up — hand the live `Pipeline` to
    // `ProxyContext` so the data plane's `on_body_frame` call
    // (response-filter rung) reaches the real filter chain. Prior
    // to this commit the boot path constructed a fresh
    // `NoopPipeline` here, silently dropping the response-filter
    // wire-up that landed in `data_plane.rs` two commits ago.
    let upstream_ctx = Arc::new({
        let mut ctx = crate::proxy::ProxyContext::build(&cfg, pipeline.clone())?;
        // WS-T6 — share the registered metrics with the data-
        // plane bridge code.  Done before Arc-wrap so the field
        // can stay non-OnceLock (it never changes after boot).
        ctx.websocket_metrics = Some(websocket_metrics.clone());
        ctx.stream_metrics = Some(stream_metrics.clone());
        ctx.zone_metrics = Some(zone_metrics.clone());
        // WS-MSG3 — hand the detector chain + mask to the WS
        // message-inspection bridge (it runs on a spawned task and needs
        // owned handles). Same Arcs the accept loop / HTTP path use.
        ctx.ws_detectors = Some(detectors.clone());
        ctx.ws_detector_mask = Some(mask.clone());
        ctx
    });

    // PR-DNS-2 spawn (2026-05-11) — one background DNS refresh
    // task per pool that has hostname-addressed members. Each
    // task re-resolves on TTL via `hickory-resolver`, diffs
    // against the last-applied IP set, and atomic-swaps the
    // pool's member list through `PoolRegistry::apply` when the
    // rotation produces a change. Soft-failure: a resolver outage
    // keeps the last-known IPs in place and retries on the next
    // tick.
    //
    // The handles are dropped intentionally — these tasks live
    // for the process lifetime and tokio keeps them alive on the
    // runtime regardless of handle ownership. Mirrors the
    // `config-watcher` pattern below.
    // Build the DNS-refresh manager and reconcile the initial per-pool
    // task set from the boot config. The manager is threaded into both
    // config watchers (below), so a later upstream apply (dashboard PUT /
    // cluster convergence) reconciles tasks too — a hostname pool added
    // after boot now gets a refresh task instead of staying pinned to its
    // PUT-time IPs until the next process restart
    // (BUG-dns-refresh-not-spawned-for-live-added-hostnames). The handles
    // live for the process lifetime inside the manager; tokio keeps the
    // tasks alive regardless of handle ownership.
    let dns_refresh_manager: Option<Arc<crate::upstream::dns_refresh::DnsRefreshManager>> =
        match hickory_resolver::TokioResolver::builder_tokio().and_then(|b| b.build()) {
            Ok(resolver) => {
                let manager = crate::upstream::dns_refresh::DnsRefreshManager::new(
                    // PoolRegistry is internally Arc-cloneable, so a fresh
                    // `Arc` of the same registry keeps the manager's store
                    // in lock-step with everything else.
                    Arc::new(upstream_ctx.pools.clone()),
                    Arc::new(resolver),
                    bus.clone(),
                );
                manager.reconcile(&boot_authored_upstreams);
                Some(manager)
            }
            Err(e) => {
                // Builder failure means we couldn't parse
                // /etc/resolv.conf (or registry on Windows). Phase 1 boot
                // resolution used the system stub anyway, so the pools
                // still have live members — we just can't refresh in the
                // background. Loud-warn so operators see this in the log.
                tracing::warn!(
                    error = %e,
                    "dns_refresh: failed to build hickory resolver; hostname members will not refresh in the background",
                );
                None
            }
        };

    // 2026-05-09 BUG-DDOS-STUB Phase 1 — DDoS observe-only wire-up.
    // Build the runtime if `cfg.ddos.enabled = true` and install
    // it into `ProxyContext`. Default config has `enabled: true,
    // observe_only: true` so the detector runs in shadow mode out
    // of the box. The Phase 2 follow-up flips `observe_only`
    // through to enforcement (503 short-circuit) once operators
    // have validated the signal in their env.
    //
    // The ticker is spawned once here so cluster-wide spike mode
    // (EWMA over `current_rps`) advances every second regardless
    // of request load. Without it, the spike-detection signal
    // would only update on requests, defeating the whole point
    // of "alert before traffic crashes the upstream".
    // F-CRITICAL-006 (2026-05-17): wire the adaptive load shedder
    // into ProxyContext. The data plane consults it after tier
    // classification — Critical-tier requests pass unconditionally,
    // lower tiers shed in priority order when the in-flight count
    // exceeds the Gradient2-adapted limit. Boot log surfaces the
    // initial knobs so operators see the gate is active.
    // 2026-07-07 — the shedder runtime is installed UNCONDITIONALLY so
    // `enabled` can be hot-flipped from the dashboard (PUT /api/gates/shed)
    // without a restart. Enforcement is gated at the data plane by the
    // `upstream_ctx.load_shed_enabled` atomic (initialised from
    // `cfg.load_shedder.enabled`); when off, every request is admitted and
    // the Gradient2 machinery simply idles.
    {
        let shedder = Arc::new(crate::shed::LoadShedder::new(
            cfg.load_shedder.initial_limit,
            cfg.load_shedder.min_limit,
        ));
        if upstream_ctx.load_shedder.set(shedder.clone()).is_err() {
            tracing::warn!("load_shedder: already installed; skipping");
        } else {
            tracing::info!(
                enabled = cfg.load_shedder.enabled,
                initial_limit = cfg.load_shedder.initial_limit,
                min_limit = cfg.load_shedder.min_limit,
                "load_shedder: runtime installed; enabled is hot-flippable via PUT /api/gates/shed",
            );
        }
    }

    // 2026-05-19 — DDoS runtime is now installed unconditionally so
    // operators can hot-flip `enabled` from the dashboard
    // (PUT /api/gates/ddos) without restarting. Enforcement is
    // gated inside `DdosDetector::check_with_tier`, which reads
    // the ArcSwap'd `cfg.enabled` on every request. Boot log
    // distinguishes the initial state so operators see whether
    // the gate is active out of the gate.
    //
    // 2026-05-18 (QC Sprint 1.2 — F-CRITICAL-005, §5.8): wire
    // the WafConfig-level `fail_mode_by_tier` map into the
    // runtime DdosConfig. Schema for this field landed in
    // Phase G (`678baa2`) but no runtime read it until now.
    // Spec §5.8 mandates fail-close on Critical, fail-open on
    // Medium/CatchAll — `Tier::default_failure_mode()`
    // already encodes that, so an empty map preserves the
    // mandate; the per-tier YAML override lets operators
    // tune posture per-deployment.
    // Shared with the hot-reload helper (`apply_cfg_change_to_ddos`) so the
    // boot install and a config-plane re-derive produce identical runtime
    // config (2026-06-18, runtime_gate_toggles_not_durable).
    let ddos_runtime_cfg = crate::config_source::reload::derive_ddos_runtime_cfg(&cfg);
    let runtime = Arc::new(aegis_security::ddos::DdosRuntime::new(
        ddos_runtime_cfg,
        state.clone(),
    ));
    if upstream_ctx.ddos.set(runtime.clone()).is_err() {
        tracing::warn!("ddos: runtime already installed; skipping");
    } else {
        tracing::info!(
            initial_enabled = cfg.ddos.enabled,
            observe_only = runtime.observe_only(),
            per_ip_limit = cfg.ddos.per_ip_limit,
            spike_multiplier = cfg.ddos.spike_multiplier,
            "ddos: runtime installed; enabled is hot-flippable via PUT /api/gates/ddos",
        );
        // Spawn the spike-detection ticker. Drop guard not
        // needed — handle leaks at shutdown the same way the
        // health-check handles do; the proxy supervisor owns
        // the process lifetime. The ticker itself short-circuits
        // when `cfg.enabled = false` so the EWMA freezes during
        // disabled windows.
        let runtime_for_tick = runtime.clone();
        handles.push(tokio::spawn(async move {
            let mut iv = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                iv.tick().await;
                // Fleet RPS aggregation — `tick_rps_fleet` aggregates the
                // spike signal across the fleet when `ddos.spike_scope: fleet`
                // (and a shared backend is present), else behaves exactly like
                // the per-node `tick_rps`. Fail-safe to per-node on any backend
                // error; never blocks the tick.
                runtime_for_tick.tick_rps_fleet().await;
            }
        }));
    }

    // SLO-P5 — alert-event channel: producers scattered across the
    // proxy (pool health monitors, hot-reload failure paths) send
    // AlertEvents here; the SLO dispatch loop in `accept.rs` drains
    // it through the shared dedup/receivers/outcome-ring path.
    let (alert_tx, alert_rx) =
        tokio::sync::mpsc::unbounded_channel::<aegis_control::slo::AlertEvent>();

    // Spawn live health-check tasks for every pool that carries
    // a `health:` block. Without this, configured probes never
    // ran and the dashboard's "members up" stayed at the
    // boot-time default forever.
    let _health_handles =
        upstream_ctx.spawn_health_checks(&cfg, &bus, Some(alert_tx.clone()));

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
                    (
                        c.cert_path.clone(),
                        std::path::PathBuf::from(&c.key_ref),
                        hosts,
                    )
                })
                .collect();
            let store = crate::listener::tls::CertStore::load(&entries).map_err(|e| {
                aegis_core::WafError::Config(format!(
                    "tls.certificates: failed to load cert/key pairs: {e}"
                ))
            })?;
            let resolver = Arc::new(crate::listener::tls::DynamicResolver::new(Arc::new(
                arc_swap::ArcSwap::from_pointee(store),
            )));

            // MTLS-T2 — when `cfg.zero_trust.downstream` is set and
            // its `apply_to` includes `Data`, build a
            // `WebPkiClientVerifier` from the configured CA bundle
            // and wire it into the server config. Otherwise fall
            // through to the existing no-client-auth path.
            //
            // Boot-time CA-bundle parse failures fail the boot
            // (operator opted in; silently downgrading to
            // no-client-auth would be a security regression).
            let client_auth_for_data = cfg
                .zero_trust
                .as_ref()
                .and_then(|z| z.downstream.as_ref())
                .filter(|ca| {
                    ca.mode != aegis_core::config::DownstreamMtlsMode::Disabled
                        && ca
                            .apply_to
                            .contains(&aegis_core::config::DownstreamMtlsScope::Data)
                });

            // MTLS-T5 — keep the parsed `ClientTrustStore`
            // around so the cfg-reload watcher can swap it on
            // future cfg changes. `None` when client auth is
            // disabled or scoped to admin only.
            let mut client_trust_for_reload: Option<
                crate::listener::client_trust::ClientTrustStore,
            > = None;
            let mut server_cfg = if let Some(ca) = client_auth_for_data {
                let bundle = ca.ca_bundle.as_ref().ok_or_else(|| {
                    aegis_core::WafError::Config(
                        "zero_trust.downstream.ca_bundle is required when mode != disabled".into(),
                    )
                })?;
                let trust =
                    crate::listener::client_trust::ClientTrustStore::load_from_pem_file(bundle)?;
                tracing::info!(
                    mode = ?ca.mode,
                    apply_to = ?ca.apply_to,
                    ca_bundle = %bundle.display(),
                    "mtls inbound client auth enabled (data plane)",
                );
                let server_cfg =
                    crate::listener::tls_policy::build_hardened_server_config_with_client_auth(
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
                    aegis_core::WafError::Config(format!("tls: rustls config build failed: {e}"))
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
            server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
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
    //
    // 2026-05-19 — capture the source-of-truth YAML path before
    // the match consumes `reload_source`. The admin plane stashes
    // it on `services.config_yaml_path` so the dashboard's
    // Configuration Backup download can serve the file.
    let config_yaml_path: Option<std::path::PathBuf> = match &reload_source {
        ConfigReloadSource::File(p) => Some(p.clone()),
        _ => None,
    };
    // H2b P2c — select the durable config-plane store from `config_plane.store`
    // BEFORE the file watcher, so the file *publisher* activates onto the SAME
    // store everything else reads (etcd under `store: etcd`), not Redis. Moved
    // above the watcher to fix the etcd file-publisher asymmetry; `shared_state`
    // is byte-identical (the backend is `SharedStateConfigBackend::arc(state)`,
    // exactly what `ConfigStore::new(state)` wraps). A loud boot error fires
    // here if `store: etcd` is set on a binary built without `etcd_config`.
    let config_plane =
        crate::config_source::plane_select::select(&cfg, state.clone()).await?;
    tracing::info!(store = %config_plane.summary, "config plane store selected");
    let config_backend = config_plane.backend.clone();
    // config-single-source-of-truth H1·P1 — the file watcher is now a
    // *publisher* into `config:waf:doc`, not a second applier. It validates a
    // file change and activates it as a new version; the shared-store watcher
    // below is the single applier that swaps it into the live data plane. This
    // removes the old file-vs-doc dual authority. Gated on
    // `config_plane.file_watch`: `publish` (default) spawns it; `off` is
    // bootstrap-only (boot is seeded into the doc, no watcher).
    match reload_source {
        ConfigReloadSource::None => {
            tracing::info!("config reload watcher: disabled (ConfigReloadSource::None)");
        }
        ConfigReloadSource::File(path) => match cfg_swap.load().config_plane.file_watch {
            aegis_core::config::FileWatchMode::Off => {
                tracing::info!(
                    path = %path.display(),
                    "config reload watcher: file bootstrap-only (config_plane.file_watch = off)",
                );
            }
            aegis_core::config::FileWatchMode::Publish => {
                tracing::info!(
                    path = %path.display(),
                    "config reload watcher: file publisher → config:waf:doc",
                );
                // Publish onto the selected config plane (etcd under
                // `store: etcd`), NOT unconditionally Redis — else file edits
                // land in a store nobody reads under etcd.
                let file_store =
                    crate::config_source::config_store::ConfigStore::with_config_backend(
                        config_backend.clone(),
                    );
                // Drop the JoinHandle; the watcher runs for the lifetime of the
                // proxy and tokio::spawn keeps the task alive regardless of
                // handle ownership.
                std::mem::drop(supervisor::spawn_config_watcher(
                    path,
                    file_store,
                    bus.clone(),
                    Some(alert_tx.clone()),
                ));
            }
        },
    }

    // N2 (2026-06-11) — config-plane pub/sub nudge. A dedicated Redis
    // FleetBus (separate from the control-plane nudge below) shared by the
    // watcher (subscribe side) and the audit-mutated config write handlers
    // via `services.config_nudge` (publish side). A successful activate
    // publishes `config:waf:bump`, waking every node's watcher — incl. the
    // writer's own — so the new version applies in ~ms instead of on the
    // next poll tick. Gated on `cluster.pubsub_nudge` + Redis; `None`
    // degrades to pure interval polling (the prior behaviour).
    let config_nudge_bus: Option<std::sync::Arc<dyn aegis_core::fleet::FleetBus>> = {
        #[cfg(feature = "redis")]
        {
            if cfg.cluster.pubsub_nudge
                && matches!(cfg.state.backend, aegis_core::config::StateBackendKind::Redis)
            {
                cfg.state
                    .redis
                    .as_ref()
                    .and_then(|r| r.urls.first())
                    .and_then(|url| match crate::state::RedisFleetBus::connect(url) {
                        Ok(bus) => {
                            tracing::info!(
                                "config plane: pub/sub nudge enabled \
                                 (config:waf:bump → immediate re-poll)"
                            );
                            Some(std::sync::Arc::new(bus)
                                as std::sync::Arc<dyn aegis_core::fleet::FleetBus>)
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "config nudge: redis connect failed; interval polling only"
                            );
                            None
                        }
                    })
            } else {
                None
            }
        }
        #[cfg(not(feature = "redis"))]
        {
            None
        }
    };

    // H2b (2026-06-24) — wrap the config-nudge `FleetBus` in the narrow
    // [`ConfigWatch`] seam (the `config:waf:bump` channel baked in) so both
    // the watcher (subscribe side) and the write handlers via
    // `services.config_nudge` (notify side) talk to the abstraction the etcd
    // config plane will supply natively (P2), not Redis pub/sub directly.
    let fleet_config_nudge: Option<std::sync::Arc<dyn aegis_core::config_backend::ConfigWatch>> =
        config_nudge_bus.map(|bus| {
            aegis_core::config_backend::FleetBusConfigWatch::arc(
                bus,
                crate::config_source::config_store::CONFIG_BUMP_CHANNEL,
            )
        });

    // etcd supplies its own native watch (notify_change is then a no-op — the
    // KV put IS the notification); shared_state reuses the pub/sub nudge.
    let config_nudge: Option<std::sync::Arc<dyn aegis_core::config_backend::ConfigWatch>> =
        config_plane.config_watch.clone().or(fleet_config_nudge);

    // 2026-05-27 — shared-store config watcher (multi-node config
    // plane). INDEPENDENT of the boot config source above: it watches
    // the versioned `config:waf:doc` in the runtime `StateBackend` so a
    // console edit on any node converges on every node and survives
    // leader failover (the config lives in the store, not the leader's
    // process). On `in_memory` single-node the doc is never written, so
    // the watcher is a harmless no-op — we always spawn it. ACKs the
    // applied version per node (`config:waf:applied:<node>`) for the
    // dashboard drift view; NACKs (keeps last-good) on a bad version.
    //
    // N1 (2026-06-11) — shared alert-receiver list. Seed from
    // `cfg.alerting.receivers` when the operator has put receivers under
    // config management; otherwise fall back to the env/boot defaults
    // (`slo::default_receivers`). The config-plane watcher re-derives this
    // on every swap (via `ApplyTargets.receiver_writer`) so a dashboard
    // receiver edit — folded into `cfg.alerting` and activated — propagates
    // to every node instead of staying node-local. Shared with
    // `admin_accept_loop` (GET/PUT/DELETE/test + the SLO dispatch task).
    let shared_receivers: Arc<arc_swap::ArcSwap<Vec<aegis_control::slo::AlertReceiver>>> = {
        let initial: Vec<aegis_control::slo::AlertReceiver> = match cfg.alerting.as_ref() {
            Some(a) => a
                .receivers
                .iter()
                .map(crate::config_source::reload::receiver_from_config)
                .collect(),
            None => aegis_control::slo::default_receivers(),
        };
        Arc::new(arc_swap::ArcSwap::from_pointee(initial))
    };
    // SLO-P4 — the SLO engine is built HERE (was accept.rs) so the
    // config watcher can hot-swap objectives on doc convergence,
    // mirroring shared_receivers. Boot objectives come from
    // `cfg.slo` (invalid → compiled defaults + error log; the
    // alerting engine is report-only and must never fail boot).
    let slo_engine = Arc::new(aegis_control::slo::SloEngine::new(
        crate::config_source::reload::slo_objectives_from_cfg(&cfg),
    ));
    let slo_absent_after_secs = Arc::new(std::sync::atomic::AtomicU64::new(
        cfg.slo
            .as_ref()
            .and_then(|s| s.telemetry_absent_after_secs)
            .unwrap_or(aegis_control::slo::DEFAULT_TELEMETRY_ABSENT_AFTER_SECS),
    ));
    {
        let node_id = lease_store.self_id().to_string();
        // H2b — the watcher reads/seeds the SELECTED config backend (etcd when
        // `config_plane.store: etcd`, else the shared state backend).
        let store = crate::config_source::config_store::ConfigStore::with_config_backend(
            config_backend.clone(),
        );
        let targets = crate::config_source::redis_source::ApplyTargets {
            detector_mask: Some(mask.clone()),
            proxy_ctx: Some(upstream_ctx.clone()),
            ip_rate_limiter: Some(ip_rate_limiter.clone()),
            tls_resolver: tls_resolver.clone(),
            ai_toggle: ai_runtime_toggle.clone(),
            // 2026-05-30 (NT-07 fix) — closes the live-propagate gap.
            ai_threshold: ai_runtime_threshold.clone(),
            response_filter_writer: Some(pipeline.clone()
                as Arc<dyn aegis_control::api::response_filter::ResponseFilterWriter>),
            tiers: Some(tier_store.clone()),
            rules: Some(rule_store.clone()),
            active_ruleset: Some(pipeline.rules_arc()),
            upstream_writer: Some(Arc::new(upstream_ctx.pools.clone())
                as Arc<dyn aegis_control::api::upstreams_config::UpstreamWriter>),
            // BUG-dns-refresh-not-spawned-for-live-added-hostnames —
            // reconcile DNS-refresh tasks on each config-plane swap so a
            // hostname pool added/changed after boot gets a refresh task
            // fleet-wide instead of staying node-local-until-restart.
            dns_refresh: dns_refresh_manager.clone(),
            // N1 — re-derive the alert-receiver list on each swap.
            receiver_writer: Some(Arc::clone(&shared_receivers)),
            // SLO-P4 — re-derive SLO objectives + watchdog knob on
            // each swap.
            slo_engine: Some(Arc::clone(&slo_engine)),
            slo_absent_after_secs: Some(Arc::clone(&slo_absent_after_secs)),
            // SLO-P5 — HotReloadFailed alerts on shared-config NACK.
            alert_tx: Some(alert_tx.clone()),
            // A2 — re-derive the inbound mTLS trust store on each swap so a
            // Zero Trust CA rotation converges fleet-wide (was file-watcher
            // only).
            client_auth: client_trust.clone(),
            // 2026-06-18 (runtime_gate_toggles_not_durable) — re-derive the
            // gate runtimes from the converged doc so an operator's ddos /
            // risk-threshold / strike / bots / canary PUT survives restart
            // (the PUT publishes the doc; this re-installs it into the live
            // runtime). rate-limit already converges via ip_rate_limiter.
            ddos: upstream_ctx.ddos.get().cloned(),
            risk: Some(risk.clone()),
            canary_paths: Some(canary_paths.clone()),
            bots_enabled: Some(upstream_ctx.bots_enabled.clone()),
            // 2026-07-07 — converge the load-shed on/off toggle fleet-wide.
            load_shed_enabled: Some(upstream_ctx.load_shed_enabled.clone()),
            // AC-P2-b — converge `count_scope` fleet-wide on doc swap.
            brute_force: Some(brute_force.clone()),
        };
        tracing::info!(
            node_id = %node_id,
            "config reload watcher: shared-store (config:waf:doc)",
        );
        // 2026-06-18 (runtime-config-lost-on-redis-data-loss report) —
        // persist the last-applied shared-config version next to the boot
        // config so a cold boot after a Redis data-loss can still detect the
        // revert. `None` when there's no on-disk config path (marker disabled;
        // in-memory detection still covers a live Redis bounce).
        let config_marker_path = config_yaml_path
            .as_ref()
            .map(|p| p.with_file_name(".aegis_last_applied_config.json"));
        // FEAT-config-boot-seed-doc-v0 — eagerly publish the boot config as
        // `config:waf:doc` v1 (genesis only) BEFORE the watcher spawns, so the
        // versioned config plane is populated from the first moment instead of
        // lazily on the first mutation. Genesis-gated on the absent marker so a
        // cold boot after a store wipe is left to the revert detection below,
        // not masked. Borrow now; `store` moves into `spawn_watcher` next.
        let _ = crate::config_source::redis_source::seed_boot_config_if_genesis(
            &store,
            config_yaml_path.as_deref(),
            config_marker_path.as_ref(),
        )
        .await;
        // H2a — one-shot migration of a pre-split doc: strip the stored active
        // doc down to its dynamic projection (in place, same version) so the
        // config plane holds no bootstrap keys. Idempotent + CAS-safe; a
        // dynamic-only doc (fresh deploy or already-migrated) is a no-op.
        match store.canonicalize_active_doc().await {
            Ok(true) => {
                tracing::info!("config plane: migrated active doc to dynamic-only (H2a)")
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(error = %e, "config plane: H2a doc canonicalization skipped")
            }
        }
        // H2a — capture the immutable bootstrap half from the boot config.
        // The watcher reconstructs the merged runtime config from each new
        // DYNAMIC doc using this, so a doc can never change how the node came
        // up (`WafConfig::from_parts`).
        let boot = std::sync::Arc::new(aegis_core::BootstrapConfig::from(
            cfg_swap.load().as_ref(),
        ));
        std::mem::drop(crate::config_source::redis_source::spawn_watcher(
            store,
            node_id,
            cfg_swap.clone(),
            boot,
            bus.clone(),
            targets,
            crate::config_source::redis_source::DEFAULT_POLL,
            config_nudge.clone(),
            readiness.config_store_degraded.clone(),
            config_marker_path,
        ));
    }

    // 2026-06-09 (P5) — Zero Trust upstream-mTLS hot rotation. A
    // console/API store of a new shared identity or backend-CA trust
    // bundle (config plane, `cas_set`) is picked up here and applied to
    // live pools with no restart and no dropped connections (the
    // re-applied pool's `PoolKey` fingerprint changes, so the next dial
    // builds a fresh client). No-op every tick when no pool has upstream
    // mTLS enabled. Essential for a fleet — rotation no longer means a
    // rolling restart of every node.
    std::mem::drop(crate::upstream::rotation::spawn(
        state.clone(),
        upstream_ctx.pools.clone(),
        cfg_swap.clone(),
        crate::upstream::rotation::DEFAULT_INTERVAL,
    ));

    // MTLS-T3 — create the per-identity sliding-window tracker
    // here, ahead of both accept loops, so the data-plane
    // (`accept_loop`) can record requests against it AND the
    // admin-plane (`admin_accept_loop`) can stash it on
    // `services.identity_tracker` for `/api/mtls/*` to read.
    // CA-bundle summary loading stays inside `admin_accept_loop`
    // (it knows when boot is "settled").
    let identity_tracker =
        std::sync::Arc::new(aegis_control::identity_tracker::IdentityTracker::new());

    // external interop contract surface . Built
    // here so it's available to the data-plane accept_loop and
    // later threaded into `DashboardServices` for the admin
    // control plane. Opted in via `cfg.interop.enabled`.
    let interop_runtime = build_interop_runtime(&cfg, &risk, &ip_rate_limiter);
    // AC-P2-b — fleet-count capability gate (owner constraint: cluster
    // mode only). The shared backend is installed whenever this node is
    // capable — cluster propagation wired AND a Redis state backend — so
    // a later hot-reload flip to `count_scope: fleet` works without a
    // restart. When fleet is *requested* but the node isn't capable, warn
    // loudly and run per-node: no silent "fleet == this node" (the DDoS
    // `spike_scope` gap this deliberately closes).
    {
        let fleet_capable = interop_runtime
            .as_ref()
            .is_some_and(|rt| rt.control.cluster_enabled())
            && matches!(
                cfg.state.backend,
                aegis_core::config::StateBackendKind::Redis
            );
        if fleet_capable {
            brute_force.install_fleet_backend(state.clone());
        } else if cfg.detectors.brute_force.count_scope
            == aegis_core::config::BruteForceCountScope::Fleet
        {
            tracing::warn!(
                "detectors.brute_force.count_scope = fleet requires cluster mode \
                 + a Redis state backend; counting per-node on this node"
            );
        }
    }
    if let Some(rt) = interop_runtime.as_ref() {
        if let Some(sink) = rt.audit.as_ref() {
            tracing::info!(
                audit_path = %sink.path().display(),
                "external interop contract enabled — control plane on /__waf_control",
            );
        } else {
            tracing::info!("external interop contract enabled (audit log path not configured)",);
        }
        // v2.3 §2.5 — install the ModeStore back into the
        // already-constructed ProxyContext so the data-plane
        // block paths can consult it for log_only enforcement
        // skip. `set` is one-shot: subsequent boots can't
        // accidentally swap modes mid-run.
        let _ = upstream_ctx.interop_modes.set(rt.modes.clone());
        // F-HIGH-005 — install the reset-in-progress flag the data
        // plane consults at request entry to short-circuit with 503
        // during a reset_state window. Same one-shot semantics as
        // interop_modes.
        let _ = upstream_ctx
            .reset_in_progress
            .set(rt.reset_in_progress.clone());

        // v2.3 §3 + NEW-2 (2026-05-08) — install the PoW issuer
        // so the data-plane challenge body carries
        // `{nonce, difficulty, expires_at_ms, mac, submit_to}`
        // instead of just `challenge_type`. SEC-01 (2026-06-19):
        // the HMAC key is derived from `interop.challenge_secret`
        // (NOT the contract-public control secret); when unset we
        // use a random per-process key.
        let challenge_secret = cfg.interop.challenge_secret.as_deref();
        if challenge_secret.map(str::trim).filter(|s| !s.is_empty()).is_none() {
            tracing::info!(
                "challenge/PoW MAC key: using a random per-process key \
                 (interop.challenge_secret unset). Multi-node clusters MUST set \
                 a shared interop.challenge_secret so a challenge-pass minted on \
                 one node verifies on another.",
            );
        }
        let pow_key = resolve_challenge_key(challenge_secret);
        let pow_issuer = std::sync::Arc::new(aegis_security::challenge::PowIssuer::new(
            pow_key,
            // v2.6 §4 Format B counts leading-zero HEX CHARS, so
            // difficulty 4 = 16 zero bits ≈ 65k SHA-256 hashes to
            // solve. (Under the old bit-counting semantics this field
            // was 16; 16 hex chars would be 64 bits — unsolvable.)
            4,
            std::time::Duration::from_secs(60), // 60s validity window
        ));
        let _ = upstream_ctx.pow_issuer.set(pow_issuer);

        // 2026-05-20 reset_state full-clear — late-register the
        // cleaners that need `state` + `upstream_ctx` (not in
        // scope inside build_interop_runtime). Mirrors the
        // AttacksAggregator late-registration in accept.rs.
        //   item 6: DDoS spike-state atomics (config preserved)
        if let Some(ddos_rt) = upstream_ctx.ddos.get() {
            let ddos_for_reset = ddos_rt.clone();
            rt.control
                .register_reset_callback(std::sync::Arc::new(move || {
                    ddos_for_reset.reset();
                }));
        }
        //   item 5: device→IP fingerprint tracker metadata
        let device_tracker_for_reset = upstream_ctx.device_ip_tracker.clone();
        rt.control
            .register_reset_callback(std::sync::Arc::new(move || {
                device_tracker_for_reset.clear();
            }));
        // AC-P2-d — enumeration detector per-IP path/404 counters are
        // §2.4 "temporary client metadata": clear on reset_state so a
        // bench phase boundary doesn't inherit the prior phase's scan
        // history. Only registered when the detector is enabled.
        if let Some(enumeration) = upstream_ctx.enumeration.clone() {
            rt.control
                .register_reset_callback(std::sync::Arc::new(move || {
                    enumeration.clear();
                }));
        }
        // EG-2 T4 / T2/T3 are stateless (per-response scan, no risk feed) —
        // nothing to clear on reset_state. Only T5's egress-volume window
        // carries per-IP state, so it clears so a bench phase boundary doesn't
        // inherit the prior phase's byte counts.
        if let Some(egress_volume) = upstream_ctx.egress_volume.clone() {
            rt.control
                .register_reset_callback(std::sync::Arc::new(move || {
                    egress_volume.clear();
                }));
        }
        // SC-1 — wire `POST /__waf_control/flush_cache` to actually evict the
        // data-plane response cache (all pools), and fan the purge out to the
        // rest of the fleet over Redis pub/sub (control-plane Redis, not the
        // request hot path). Each node evicts its own L1 immediately; the
        // publish lets every other node do the same. Local-only when the redis
        // state backend isn't configured (or the binary lacks `--features redis`).
        let cache_for_flush = upstream_ctx.cache.clone();
        // Purge fan-out URLs — only populated for the redis state backend.
        let purge_urls: Option<Vec<String>> = {
            #[cfg(feature = "redis")]
            {
                if matches!(cfg.state.backend, aegis_core::config::StateBackendKind::Redis) {
                    cfg.state.redis.as_ref().map(|r| r.urls.clone())
                } else {
                    None
                }
            }
            #[cfg(not(feature = "redis"))]
            {
                None
            }
        };
        // Subscriber: evict this node's L1 whenever any node publishes a purge.
        #[cfg(feature = "redis")]
        if let Some(urls) = purge_urls.clone() {
            crate::cache::purge::spawn_subscriber(urls, upstream_ctx.cache.clone());
        }
        let purge_urls_for_cb = purge_urls.clone();
        rt.control
            .register_flush_callback(std::sync::Arc::new(move || {
                // Local L1 eviction first — the flush_cache response is honest
                // even if the fan-out publish later fails.
                cache_for_flush.invalidate(None);
                #[cfg(feature = "redis")]
                {
                    // Clear the shared L2 ONCE from this node (other nodes only
                    // clear their L1 via the pub/sub fan-out below).
                    if cache_for_flush.any_l2() {
                        let cache = cache_for_flush.clone();
                        tokio::spawn(async move { cache.invalidate_l2_all().await });
                    }
                    if let Some(urls) = purge_urls_for_cb.clone() {
                        tokio::spawn(async move {
                            crate::cache::purge::publish(&urls, "all").await;
                        });
                    }
                }
                #[cfg(not(feature = "redis"))]
                let _ = &purge_urls_for_cb;
            }));
        // CTL-NEW-01 (v2.6 §2.4) — `reset_state` MUST clear cache
        // state too. The flush_callback above only fires for
        // `POST /__waf_control/flush_cache`; without this, a cached
        // upstream response from a prior benchmark phase survives a
        // `reset_state` and can be replayed in the next phase,
        // bypassing detection and making results phase-order
        // dependent. Evict this node's L1 (Redis L2 fan-out stays a
        // flush_cache concern — reset isolation only needs local).
        let cache_for_reset = upstream_ctx.cache.clone();
        rt.control
            .register_reset_callback(std::sync::Arc::new(move || {
                cache_for_reset.invalidate(None);
            }));
        //   items 2/4/6 (StateBackend half): async ephemeral wipe of
        //   rate-limit windows + nonces + auto-block + backend risk
        //   keys, scoped to the `g:*` prefixes (leader lease survives).
        let state_for_reset = std::sync::Arc::clone(&state);
        rt.control
            .register_async_reset_callback(std::sync::Arc::new(move || {
                let backend = std::sync::Arc::clone(&state_for_reset);
                Box::pin(async move {
                    match backend.reset_ephemeral().await {
                        Ok(n) => {
                            tracing::info!(cleared = n, "reset_state: StateBackend ephemeral wipe",)
                        }
                        Err(e) => tracing::warn!(
                            error = %e,
                            "reset_state: StateBackend ephemeral wipe failed",
                        ),
                    }
                })
            }));
        // 2026-06-24 (redis-interim-durability P2, A2) — durable risk strikes
        // are now persisted, so `reset_state` must also UNLINK the
        // `control:waf:risk` hash, or struck IPs resurrect on the next boot
        // (durability plan §4). reset_all() (sync, above) already clears the
        // in-memory map + dirty set; this is the async durable half. O(1) —
        // a single-hash UNLINK, so it doesn't stall the bench reset (§9
        // invariant 3). No-op without a backend.
        #[cfg(feature = "redis")]
        {
            let risk_for_durable_reset = risk.clone();
            rt.control
                .register_async_reset_callback(std::sync::Arc::new(move || {
                    let risk = risk_for_durable_reset.clone();
                    Box::pin(async move {
                        risk.unlink_durable().await;
                    })
                }));
        }

        // C-1 (multi-node consistency) — cluster-native control plane.
        // On a shared backend (Redis), install the state handle so
        // `set_profile` / `reset_state` publish to the config plane, and
        // spawn a poller that converges THIS node's ModeStore + local
        // reset state from peers' publishes. Single-node / in-memory
        // deployments skip this entirely — `cluster_state` stays empty,
        // so publish + poll are no-ops and the legacy node-local
        // behaviour is preserved.
        if matches!(cfg.state.backend, aegis_core::config::StateBackendKind::Redis) {
            // H2b — the control plane rides the SELECTED config backend (etcd
            // when `config_plane.store: etcd`, else the shared state backend),
            // so config + control converge on the same store.
            rt.control.set_cluster_state(config_backend.clone());
            // Phase 5 (§3) — control-plane change-notification nudge. Built
            // BEFORE spawn_poller so the poller picks it up via
            // `rt.control.cluster_nudge()`. Prefer the etcd native
            // control-prefix watch; otherwise the Redis pub/sub bus
            // (`control:waf:bump`) when `cluster.pubsub_nudge` + the `redis`
            // feature. Degrades to interval-only polling when neither is set.
            if let Some(control_watch) = config_plane.control_watch.clone() {
                rt.control.set_cluster_nudge(control_watch);
                tracing::info!(
                    "interop: etcd native control-plane watch enabled \
                     (control:waf: prefix → immediate re-poll)"
                );
            } else if cfg.cluster.pubsub_nudge {
                #[cfg(feature = "redis")]
                {
                    if let Some(url) =
                        cfg.state.redis.as_ref().and_then(|r| r.urls.first())
                    {
                        match crate::state::RedisFleetBus::connect(url) {
                            Ok(bus) => {
                                // Wrap the Redis pub/sub bus as the narrow
                                // ConfigWatch on the control bump channel.
                                let watch = aegis_core::config_backend::FleetBusConfigWatch::arc(
                                    std::sync::Arc::new(bus),
                                    aegis_control::interop::cluster_sync::CONTROL_BUMP_CHANNEL,
                                );
                                rt.control.set_cluster_nudge(watch);
                                tracing::info!(
                                    "interop: pub/sub state nudge enabled \
                                     (control:waf:bump → immediate re-poll)"
                                );
                            }
                            Err(e) => tracing::warn!(
                                error = %e,
                                "cluster.pubsub_nudge: redis connect failed; \
                                 falling back to interval polling"
                            ),
                        }
                    }
                }
                #[cfg(not(feature = "redis"))]
                tracing::warn!(
                    "cluster.pubsub_nudge enabled but binary built without the \
                     `redis` feature; falling back to interval polling"
                );
            }
            crate::cluster_control::spawn_poller(
                std::sync::Arc::clone(rt),
                config_backend.clone(),
                vec![
                    crate::cluster_control::AccessListTarget {
                        label: "blacklist",
                        store: upstream_ctx.blacklist.clone(),
                    },
                    crate::cluster_control::AccessListTarget {
                        label: "whitelist",
                        store: upstream_ctx.whitelist.clone(),
                    },
                ],
            );
            tracing::info!(
                "interop: cluster-native control plane enabled (set_profile / \
                 reset_state + operator access-lists converge fleet-wide via \
                 the config plane)"
            );
        }
    }

    // Data-plane listeners.
    for (data_idx, listener_cfg) in cfg.listeners.data.iter().enumerate() {
        let addr = listener_cfg.bind;
        // FDP-T2 — adopt-or-bind. Inherited names use a stable
        // `data-N` suffix matching `cfg.listeners.data` index
        // order so a hot-restart with the same config reuses
        // the same FDs deterministically.
        let name = format!("data-{data_idx}");
        let tcp = crate::hotbin::adopt_or_bind(&mut inherited_listeners, &name, addr).await?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            listener_fd_registry.push((name.clone(), tcp.as_raw_fd()));
        }
        let listener_tls = listener_cfg.tls;
        tracing::info!("data-plane listening on {addr} (tls={})", listener_tls);
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
        let route_activity_l = route_activity.clone();
        let detector_latency_hist_l = detector_latency_hist.clone();
        let bus = bus.clone();
        let upstream_ctx_l = upstream_ctx.clone();
        let acceptor = if listener_tls {
            tls_acceptor.clone()
        } else {
            None
        };
        // B5 — Alt-Svc auto-stamp only on TLS listeners. Plain
        // HTTP listeners never advertise h3 (UA may follow it
        // and downgrade-misroute).
        let advertise_h3_port = if listener_tls {
            cfg.tls.as_ref().and_then(|t| t.advertise_h3)
        } else {
            None
        };
        let interop_l = interop_runtime.clone();
        let decision_metrics_l = decision_metrics.clone();
        let detector_hit_metrics_l = detector_hit_metrics.clone();
        let identity_tracker_l = identity_tracker.clone();
        let state_l = state.clone();
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
            route_activity_l,
            detector_latency_hist_l,
            bus,
            upstream_ctx_l,
            acceptor,
            advertise_h3_port,
            interop_l,
            decision_metrics_l,
            detector_hit_metrics_l,
            // MTLS-T3 — wires per-connection identities into
            // the per-identity sliding-window counter that
            // `/api/mtls/connections` reads.
            Some(identity_tracker_l),
            // 2026-05-08 NEW-2 — state for /__waf_control/challenge_verify
            state_l,
            // PROXY-T1 — per-listener PROXY-protocol mode (default off).
            listener_cfg.accept_proxy,
            // PROXY-T3 — shared PROXY-protocol event counter.
            proxy_protocol_metrics.clone(),
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
    if let Some(acme_yaml) = cfg.tls.as_ref().and_then(|t| t.acme.as_ref()).filter(|a| {
        // `tls.acme.auto_renew: false` disables the in-WAF renewal loop —
        // for deployments where TLS/ACME is owned by an L7 load balancer or
        // an out-of-band issuer that distributes the cert to the fleet (the
        // recommended posture behind a round-robin LB, where the in-WAF
        // HTTP-01 flow can't reliably reach the leader). The WAF then only
        // serves provisioned `tls.certificates` and never calls the ACME CA.
        if !a.auto_renew {
            tracing::info!(
                "acme: auto_renew disabled by config — TLS/ACME owned externally \
                 (LB-terminated or out-of-band issuance); WAF will not contact the ACME directory",
            );
        }
        a.auto_renew
    }) {
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
        let tcp =
            crate::hotbin::adopt_or_bind(&mut inherited_listeners, "force-https", addr).await?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            listener_fd_registry.push(("force-https".to_string(), tcp.as_raw_fd()));
        }
        tracing::info!("force-https redirect listening on {addr}");
        let challenges = challenges.clone();
        handles.push(tokio::spawn(force_https_loop(tcp, status, challenges)));
    }

    // Admin (control-plane) listener.
    let admin_addr = cfg.listeners.admin.bind;
    // F-HIGH-002 follow-up (2026-05-17 Phase 3 step 6): warn loudly
    // when the admin listener is exposed AND no IP allowlist is
    // configured. The Phase-3 decision was that empty allowlist
    // means allow-all (matches current behaviour); this warn turns
    // the gotcha into a visible setup-time signal. Loopback binds
    // are exempt — `127.0.0.0/8` + `::1/128` are inherently
    // already restricted by the OS.
    {
        let is_loopback = admin_addr.ip().is_loopback();
        let allowlist_empty = cfg.admin.dashboard_auth.ip_allowlist.is_empty();
        if !is_loopback && allowlist_empty {
            tracing::warn!(
                admin_bind = %admin_addr,
                "admin: listener not bound to loopback AND ip_allowlist is empty — \
                 every network-reachable client can attempt the auth chain. \
                 Set `admin.dashboard_auth.ip_allowlist: [10.0.0.0/8, ...]` to \
                 restrict, or bind admin to 127.0.0.1 / ::1.",
            );
        }
    }
    let admin_tcp =
        crate::hotbin::adopt_or_bind(&mut inherited_listeners, "admin", admin_addr).await?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        listener_fd_registry.push(("admin".to_string(), admin_tcp.as_raw_fd()));
    }

    // FIX 2026-05-03 — optional admin TLS. `cfg.admin.tls` was
    // always present in the schema but never wired; before this
    // commit the admin port was always plain HTTP, regardless
    // of cert config. Now: when `admin.tls.certificates` is
    // configured, we build a rustls ServerConfig the same way
    // the data-plane does and hand the acceptor to the admin
    // accept loop. Operators wanting plain HTTP in dev leave
    // `admin.tls` unset → None → existing behaviour.
    let admin_tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>> = match cfg.admin.tls.as_ref() {
        None => None,
        Some(tls_cfg) if tls_cfg.certificates.is_empty() => None,
        Some(tls_cfg) => {
            let entries: Vec<(_, _, &[String])> = tls_cfg
                .certificates
                .iter()
                .map(|c| {
                    let hosts: &[String] = &c.hosts;
                    (
                        c.cert_path.clone(),
                        std::path::PathBuf::from(&c.key_ref),
                        hosts,
                    )
                })
                .collect();
            let store = crate::listener::tls::CertStore::load(&entries).map_err(|e| {
                aegis_core::WafError::Config(format!(
                    "admin.tls.certificates: failed to load cert/key pairs: {e}"
                ))
            })?;
            let resolver = Arc::new(crate::listener::tls::DynamicResolver::new(Arc::new(
                arc_swap::ArcSwap::from_pointee(store),
            )));
            let mut server_cfg = crate::listener::tls_policy::build_hardened_server_config(
                resolver,
                tls_cfg.min_version.as_deref(),
            )
            .map_err(|e| {
                aegis_core::WafError::Config(format!(
                    "admin.tls: rustls server config build failed: {e}"
                ))
            })?;
            // Admin is HTTP/1.1 only — dashboard SPA is
            // h1-served. Force ALPN to skip h2.
            server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            Some(Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(
                server_cfg,
            ))))
        }
    };
    let admin_scheme = if admin_tls_acceptor.is_some() {
        "https"
    } else {
        "http"
    };
    tracing::info!("admin-plane listening on {admin_addr} ({admin_scheme})");

    // Boot-time visibility into cookie hardening — a missed-cookie
    // CSRF rejection without this line takes hours to debug.
    if aegis_control::admin_auth::csrf::insecure_cookies_enabled() {
        tracing::warn!(
            "AEGIS_INSECURE_COOKIES=1 — session + CSRF cookies issued WITHOUT Secure flag. \
             Use only on plain-HTTP dev admin listeners; never in production."
        );
    } else {
        tracing::info!("session + CSRF cookies issued with HttpOnly + Secure + SameSite=Strict");
    }

    let admin_cfg = cfg.clone();
    let admin_readiness = readiness.clone();
    let admin_bus = bus.clone();
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
    // RT-T5 — share the live route table with the admin listener so the
    // audit-mutated PUT/DELETE /api/routes/{id} handlers can hot-swap
    // routes through the same atomic ArcSwap the data plane resolves
    // against.
    let admin_route_writer: Arc<dyn aegis_control::api::routes_config::RouteWriter> =
        Arc::new(upstream_ctx.route_table.clone());
    let admin_state_backend = state.clone();
    let admin_identity_tracker = identity_tracker.clone();
    let admin_detectors = detectors.clone();
    // 2026-05-20 — share the live canary handle with the admin
    // listener so PUT /api/risk/canary-paths edits the same set the
    // data-plane CanaryDetector reads.
    let admin_canary_paths = canary_paths.clone();
    let admin_request_stage_hist = request_stage_hist.clone();
    let admin_route_latency_hist = route_latency_hist.clone();
    let admin_route_activity = route_activity.clone();
    let admin_detector_latency_hist = detector_latency_hist.clone();
    // MTLS-T10 Phase 2 — share the live trust store with the admin
    // listener so the audit-mutated PUT /api/mtls/ca-bundle?apply=true
    // path can hot-swap roots without bouncing the proxy.
    let admin_client_trust = client_trust.clone();
    // FDP-T4 — share the data-plane's inflight counter so admin
    // connections also count toward the drain. SIGUSR2 handover
    // exits when BOTH planes are quiet.
    let admin_inflight = upstream_ctx.inflight.clone();
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
        admin_route_writer,
        ai_runtime_toggle.clone(),
        // 2026-05-29 — new positional args for the AI confidence-
        // threshold fold (matches `admin_accept_loop`'s `ai_threshold`
        // + `ai_threshold_default` parameters added below).
        ai_runtime_threshold.clone(),
        cfg.ai.confidence_threshold,
        // Model hot-reload bridge for `POST /api/ai/reload` (None in
        // non-ai builds / batch mode).
        ai_model_reloader.clone(),
        pipeline.clone(),
        admin_state_backend,
        admin_identity_tracker,
        admin_detectors,
        admin_canary_paths,
        admin_request_stage_hist,
        admin_route_latency_hist,
        admin_route_activity,
        admin_detector_latency_hist,
        admin_client_trust,
        admin_inflight,
        admin_tls_acceptor,
        upstream_ctx.clone(),
        config_yaml_path.clone(),
        tier_store,
        rule_store,
        config_nudge,
        // H2b — the selected config backend (etcd or shared_state) so the
        // audit-mutated write handlers activate versions on the SAME store the
        // watcher reads, never splitting reads and writes across stores.
        config_backend,
        shared_receivers,
        slo_engine,
        slo_absent_after_secs,
        alert_rx,
    )));

    readiness.config_loaded.store(true, Ordering::Relaxed);
    readiness.certs_loaded.store(true, Ordering::Relaxed);
    readiness.pool_has_healthy.store(true, Ordering::Relaxed);

    // FDP-T6 — install the SIGUSR2 listener now that the
    // accept loops are running. The HotReloader's `signal()`
    // is the only thing the handler does; the actual handover
    // (perform_handover + drain + exit) runs in the polling
    // task spawned below.
    let hot_reloader = std::sync::Arc::new(crate::hotbin::HotReloader::new(
        std::time::Duration::from_secs(30),
    ));
    let _sigusr2_handle = crate::hotbin::spawn_sigusr2_listener(hot_reloader.clone());

    // FDP drain refactor — polling task that watches
    // `hot_reloader.take_signal()` and orchestrates the actual
    // handover when it fires. Lives for the proxy lifetime.
    // Both procs accept until the parent exits — the kernel's
    // accept-queue hashing distributes new conns across both
    // listeners during the drain window. perform_handover
    // returns when in-flight reaches zero OR drain_grace
    // expires; either way the parent emits the audit completion
    // event then process::exit(0)s so the inherited FDs become
    // child-only.
    #[cfg(unix)]
    {
        let reloader_for_poll = hot_reloader.clone();
        let inflight_for_poll = upstream_ctx.inflight.clone();
        let bus_for_poll = bus.clone();
        let fd_registry = listener_fd_registry.clone();
        handles.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                if !reloader_for_poll.take_signal() {
                    continue;
                }
                run_handover(&fd_registry, inflight_for_poll.clone(), &bus_for_poll).await;
                // run_handover() either calls process::exit on
                // Drained / DrainTimeout or logs the rollback
                // and returns. On rollback we resume polling so
                // a follow-up SIGUSR2 (after the operator
                // diagnoses the bad child) can try again.
            }
        }));
    }

    // FDP-T5 — child-side: signal readiness to a parent that
    // exec'd us. No-op for first-boot. Done as the last step
    // of the boot path so the parent only sees us as ready
    // when the listeners are committed.
    if let Err(e) = crate::hotbin::signal_readiness_to_parent() {
        tracing::warn!(
            error = %e,
            "FDP-T5: signal_readiness_to_parent failed — \
             parent's hot-handover will time out and roll back",
        );
    }

    // B1-T5 — readiness warm-up gate. Hold `state_warmup_done` at
    // false until the rehydrate probe round-trips through the
    // `StateBackend`. While that flag is false, the existing
    // `ReadinessSignal::is_ready()` returns false, so
    // `/healthz/ready` continues to return 503 — exactly the
    // behaviour we want for a fresh node booted against a
    // shared Redis. The deadline comes from
    // `cfg.state.reconcile.readiness_warm_ms` (default 5 s).
    //
    // Even if rehydrate fails (e.g. unreachable Redis, bad
    // password) we flip the warm-up gate to true at the deadline —
    // a mis-configured backend must never permanently 503 the
    // node; the operator gets a `tracing::warn` line + a
    // detailed error in the result.
    //
    // 2026-06-18 (healthz-ready-misreports-redis-down report): seed
    // `state_backend_connected` from the rehydrate result so the very
    // first `/healthz/ready` poll reports the truthful connectivity
    // (avoids a spurious `degraded` flicker before the poller's first
    // tick). The poller below keeps it current thereafter.
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
                .state_backend_connected
                .store(result.completed, Ordering::Relaxed);
            readiness_for_warmup
                .state_warmup_done
                .store(true, Ordering::Relaxed);
        });
    }

    // 2026-06-18 (healthz-ready-misreports-redis-down report): keep
    // `state_backend_connected` live so `/healthz/ready` reports a real
    // backend outage (status `degraded`, HTTP 200) instead of the stale
    // boot value. `StateBackend::health()` caches aggressively (≈5 s on
    // the Redis impl), so a short poll never hammers the backend. This is
    // a *reported* signal only — it does NOT gate `is_ready()`, so a Redis
    // blip never pulls the node from the LB while the data plane serves on
    // in-memory fallback.
    {
        let store = std::sync::Arc::clone(&state);
        let readiness_for_health = readiness.clone();
        tokio::spawn(async move {
            // R-1b (2026-06-19): a read-only Redis replica (the REPLICAOF-hijack
            // scenario) still answers `health()`/PING (`connected: true`) but
            // rejects WRITES — which silently broke admin-session persistence.
            // A tiny set-probe surfaces writability so `/healthz/ready` reports
            // `degraded` instead of looking healthy. Single self-expiring key;
            // one write per tick is negligible. Reported, never gating.
            const WRITE_PROBE_KEY: &str = "__waf:health:writeprobe";
            let probe_ttl = std::time::Duration::from_secs(15);
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let connected = store.health().await.connected;
                readiness_for_health
                    .state_backend_connected
                    .store(connected, Ordering::Relaxed);
                let writable = store.set(WRITE_PROBE_KEY, b"1", probe_ttl).await.is_ok();
                readiness_for_health
                    .state_backend_writable
                    .store(writable, Ordering::Relaxed);
            }
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
            let mut term =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
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
    tracing::info!(
        grace_ms = grace.as_millis() as u64,
        "draining; awaiting grace"
    );
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
                async move { Ok::<_, Infallible>(handle_force_https_request(req, status, &challenges)) }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!("force-https connection from {peer} closed: {e}");
            }
        });
    }
}

/// SEC-01 (LT-RUN-11, 2026-06-19) — resolve the 32-byte HMAC key for the PoW /
/// `waf_challenge_pass` issuer.
///
/// Previously this was derived from `interop.control_secret`. That secret is
/// **contract-public** (v2.6 mandates a fixed `X-Benchmark-Secret:
/// waf-hackathon-2026-ctrl`), so anyone could reconstruct the key and mint a
/// valid challenge-pass, bypassing the entire bot-mitigation ladder on the
/// public data plane. The key is now decoupled:
///
/// - `Some(non-empty)` → derive deterministically from the operator-set
///   `interop.challenge_secret`, domain-separated. Identical on every node, so
///   a cluster produces compatible MACs (set a shared `${secret:...}` value).
/// - `None`/blank → a random per-process key (CSPRNG via `uuid::Uuid::new_v4`,
///   the same source already used for request IDs). Secure by default and
///   needs zero config for the common single-node case; not portable across a
///   restart or across nodes (challenge passes have a 60s validity window, so a
///   restart merely forces a re-solve).
fn resolve_challenge_key(challenge_secret: Option<&str>) -> [u8; 32] {
    match challenge_secret.map(str::trim).filter(|s| !s.is_empty()) {
        Some(secret) => {
            let h = blake3::hash(format!("aegis-pow-key-v1:{secret}").as_bytes());
            *h.as_bytes()
        }
        None => {
            let mut key = [0u8; 32];
            key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
            key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
            key
        }
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod challenge_key_tests {
    use super::resolve_challenge_key;

    /// The legacy derivation that SEC-01 flagged: key == fn(control_secret).
    /// The contract-public control secret. The new key MUST NOT equal this.
    fn legacy_key_from_public_secret() -> [u8; 32] {
        *blake3::hash(b"aegis-pow-key-v1:waf-hackathon-2026-ctrl").as_bytes()
    }

    #[test]
    fn operator_secret_is_deterministic_and_cluster_shareable() {
        let a = resolve_challenge_key(Some("a-shared-cluster-secret"));
        let b = resolve_challenge_key(Some("a-shared-cluster-secret"));
        assert_eq!(a, b, "same challenge_secret must yield the same key on every node");
    }

    #[test]
    fn distinct_secrets_yield_distinct_keys() {
        assert_ne!(
            resolve_challenge_key(Some("secret-one")),
            resolve_challenge_key(Some("secret-two")),
        );
    }

    #[test]
    fn unset_secret_is_not_derived_from_public_control_secret() {
        // SEC-01: the core bypass was a key derivable from the public secret.
        // With no challenge_secret we use a random key — never the public one.
        assert_ne!(resolve_challenge_key(None), legacy_key_from_public_secret());
    }

    #[test]
    fn operator_secret_is_independent_of_public_control_secret() {
        // Even if an operator reuses the control secret value verbatim, the
        // domain-separated derivation differs from the legacy raw derivation…
        // and more importantly, operators are told to use a DIFFERENT secret.
        assert_ne!(
            resolve_challenge_key(Some("operator-chosen-high-entropy")),
            legacy_key_from_public_secret(),
        );
    }

    #[test]
    fn unset_secret_generates_fresh_random_keys() {
        // Random per-process: two resolutions differ with overwhelming prob.
        assert_ne!(resolve_challenge_key(None), resolve_challenge_key(None));
    }

    #[test]
    fn blank_secret_is_treated_as_unset() {
        // Whitespace/empty must not collapse to a deterministic blank key;
        // it falls through to the random path (so != a fixed derivation).
        let blank = resolve_challenge_key(Some("   "));
        let deterministic_empty = *blake3::hash(b"aegis-pow-key-v1:").as_bytes();
        assert_ne!(blank, deterministic_empty);
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
    // v2.3 §2.5 — AI is exposed as a toggleable policy under
    // rules_engine so the OC harness can put it into log_only via
    // set_profile { scope: "policies", feature: "rules_engine",
    // policies: ["ai"], mode: "log_only" } without a YAML edit or
    // restart. Mirror in `aegis_control::interop::control::tests::
    // ctx_v23` — keep the policy list in sync.
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
                "ai".into(),
                "command_injection".into(),
                "template_injection".into(),
                "nosql_injection".into(),
                // 2026-05-17 F-CRITICAL-010 (control audit): the
                // `open_redirect` detector emits live signals
                // (see `detectors/open_redirect.rs`) but was
                // missing from this capability list — set_profile
                // for `open_redirect` mode would return
                // "unsupported" while the rule still fired.
                "open_redirect".into(),
                // 2026-05-20 (committee interop fix): these Phase-F
                // detectors fire AND block but were missing here, so
                // the BTC could neither audit them via `capabilities`
                // nor flip them enforce↔log_only via `set_profile`
                // (they were hard-pinned to Enforce in
                // `rule_to_feature`). canary + velocity emit dynamic
                // per-rule tags but map to these single policy names
                // via prefix in `rule_to_feature`.
                "canary".into(),
                "velocity".into(),
                // 2026-06-17 (v2.6 audit MED-01): `behavior_signals`
                // was advertised here, but `BehavioralAnalyzer` is NOT
                // wired into the live request path (see the NOTE in
                // `build_interop_runtime` below) — no `behavior_*` rule
                // ever fires, so flipping its mode had no observable
                // effect. Advertising an inert toggle is a false
                // promise to the OC (§2.5), so it is intentionally
                // omitted until the analyzer lands in `data_plane.rs`.
                // 2026-06-17 (v2.6 contract audit HIGH-01): both
                // detectors fire AND block and are mapped in
                // `rule_to_feature` (`cookie_injection`,
                // `jwt_*`→`jwt_inspection`), but were missing here —
                // so `capabilities` hid them and `set_profile
                // {scope:policies, feature:rules_engine}` could never
                // flip them enforce↔log_only (they stayed hard-pinned
                // to Enforce). §2.5 requires hardcoded features appear.
                "cookie_injection".into(),
                "jwt_inspection".into(),
                // Tier-1A — GraphQL query guard. Fires AND blocks (depth/
                // complexity/introspection caps) and is mapped in
                // `rule_to_feature` ("graphql"→rules_engine/graphql), so it
                // must appear here for `capabilities` to surface it and for
                // `set_profile {scope:policies, feature:rules_engine}` to
                // flip it enforce↔log_only.
                "graphql".into(),
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
    // 2026-05-22 — DDoS per-IP burst gate exposed as a set_profile
    // feature so `log_only` covers it like the others. It also keeps
    // its own `ddos.observe_only` config flag (shadow at the config
    // level); the interop mode is checked in the data-plane DDoS branch.
    features.insert(
        "ddos".into(),
        CapabilityFeature {
            supported: true,
            toggleable: true,
            policies: vec!["per_ip".into()],
        },
    );

    // v2.5 §2.4 + 2026-05-20 committee clarification —
    // `reset_state` MUST clear ALL of:
    //   1. risk state                  ✓ risk.reset_all() (sync)
    //   2. rate-limit counters         ✓ ip_rate_limiter.reset_all()
    //                                    (in-process) + StateBackend
    //                                    sliding-window/token-bucket
    //                                    keys via reset_ephemeral (async)
    //   3. cache state                 — no content cache (TierCache
    //                                    removed); flush_cache is a
    //                                    graceful no-op
    //   4. challenge/session state     ✓ StateBackend nonces (g:nonce:*)
    //                                    via reset_ephemeral (async)
    //   5. temporary client metadata   ✓ AttacksAggregator (late-reg in
    //                                    accept.rs) + DeviceIpTracker.clear()
    //   6. temporary enforcement state ✓ DdosRuntime.reset() (spike/
    //                                    baseline atomics) + StateBackend
    //                                    auto-block (g:block:*) + backend
    //                                    risk keys (g:risk:*) via
    //                                    reset_ephemeral (async)
    //
    // `ModeStore` (operator-set enforce/log_only) is durable config,
    // NOT temporary — preserved per §2.4. Audit log: append-only,
    // NOT touched by reset.
    let mut reset_callbacks: Vec<aegis_control::interop::control::ResetCallback> = Vec::new();
    let risk_for_reset = risk.clone();
    reset_callbacks.push(Arc::new(move || {
        risk_for_reset.reset_all();
    }));
    let limiter_for_reset = Arc::clone(ip_rate_limiter);
    reset_callbacks.push(Arc::new(move || {
        limiter_for_reset.reset_all();
    }));
    // 2026-05-20 — DDoS spike-state reset (item 6), DeviceIpTracker
    // clear (item 5), and the async StateBackend ephemeral wipe
    // (items 2/4/6 backend half) are LATE-REGISTERED from the
    // caller in `run()` once `state` + `upstream_ctx` exist — same
    // pattern as the AttacksAggregator below. See
    // `register_reset_callback` / `register_async_reset_callback`
    // call sites in `run.rs`.
    // 2026-05-05 — AttacksAggregator's rolling window (Top
    // Attackers / By-Detector / Bot Mix) is built later, inside
    // `DashboardServices`. accept.rs late-registers its reset
    // callback via `rt.control.register_reset_callback(...)`
    // once that aggregator exists — see accept.rs around the
    // `DashboardServices::spawn_with_mask_and_roster` call.
    // NOTE: `aegis_security::behavior::BehavioralAnalyzer` exists
    // and exposes `.clear()`, but it isn't wired into the live
    // request path yet. Because of that, `behavior_signals` is also
    // intentionally omitted from the `rules_engine` capabilities
    // policy list above (v2.6 audit MED-01) — we don't advertise an
    // inert toggle. When the analyzer lands in the data plane,
    // re-add `behavior_signals` to capabilities AND register its
    // `.clear()` here too. Today it's a documented gap —
    // log_only-style false-positive verification doesn't depend on
    // it, so the contract stays satisfied.

    // F-CRITICAL-003 (2026-05-17 s-tester audit): pre-fix this was a
    // `warn!` + `None` swallow that left the gateway running with no
    // contract audit log. v2.3 §6 makes the contract audit mandatory
    // when interop is enabled; running without it silently fails
    // every Phase-2 scoring clause that correlates a decision back
    // to an audit row. Now: best-effort mkdir-p on the parent dir,
    // retry once, then `panic!` with an operator-actionable message
    // on a second failure. The doc-comment on `MinimalJsonlSink::open`
    // already specified this behaviour ("caller should fail-fast at
    // boot in that case"); the run.rs caller was the bug.
    let audit_sink = match MinimalJsonlSink::open(&cfg.interop.audit_path) {
        Ok(s) => Some(Arc::new(s)),
        Err(first_err) => {
            if let Some(parent) = cfg.interop.audit_path.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            match MinimalJsonlSink::open(&cfg.interop.audit_path) {
                Ok(s) => Some(Arc::new(s)),
                Err(retry_err) => {
                    tracing::error!(
                        path = %cfg.interop.audit_path.display(),
                        first_error = %first_err,
                        retry_error = %retry_err,
                        "interop audit sink failed to open; v2.3 §6 mandates an audit log when interop is enabled",
                    );
                    panic!(
                        "interop audit sink open failed for {}: {retry_err}. \
                         Fix the path's permissions, mount a writable volume, or \
                         set `cfg.interop.enabled = false` to disable the contract \
                         audit log altogether.",
                        cfg.interop.audit_path.display(),
                    );
                }
            }
        }
    };

    let control = ControlContext {
        modes: Arc::clone(&modes),
        features,
        reset_callbacks: std::sync::Mutex::new(reset_callbacks),
        async_reset_callbacks: std::sync::Mutex::new(Vec::new()),
        // SC-1 — late-registered in run.rs once the data-plane cache exists.
        flush_callback: std::sync::Mutex::new(None),
        secret: cfg
            .interop
            .control_secret
            .clone()
            .unwrap_or_else(|| aegis_control::interop::DEFAULT_CONTROL_SECRET.to_string()),
        // C-1 — installed post-construction in `run` for Redis
        // deployments (see `set_cluster_state`); empty single-node.
        cluster_state: std::sync::OnceLock::new(),
        // Phase 5 — installed post-construction when cluster.pubsub_nudge
        // is on (see `set_cluster_nudge`); empty otherwise.
        cluster_nudge: std::sync::OnceLock::new(),
        // AU-1 — installed post-construction in `accept` where the
        // AuditBus lives (see `set_audit_bus`); empty in tests.
        audit_bus: std::sync::OnceLock::new(),
    };

    Some(Arc::new(InteropRuntime {
        audit: audit_sink,
        modes,
        control,
        reset_in_progress: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }))
}

/// FDP drain refactor — orchestrate one SIGUSR2-triggered
/// hot-restart attempt. Called from the polling task spawned
/// by `run()` once `HotReloader::take_signal()` returns true.
///
/// On `HandoverOutcome::Drained` / `DrainTimeout` we
/// `process::exit(0)` so the inherited listener FDs become
/// child-only — both procs were accepting briefly during the
/// drain window; once the parent exits, the kernel routes all
/// new conns to the child.
///
/// On `RolledBack` we log + return so the polling loop resumes
/// and a follow-up SIGUSR2 (after the operator diagnoses the
/// bad child) can try again.
#[cfg(unix)]
async fn run_handover(
    listener_fd_registry: &[(String, std::os::fd::RawFd)],
    inflight: crate::hotbin::InFlightCounter,
    bus: &aegis_core::AuditBus,
) {
    let handover_id = blake3::hash(
        chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or(0)
            .to_le_bytes()
            .as_slice(),
    )
    .to_hex()
    .to_string();
    let inflight_at_signal = inflight.current();
    let our_pid = std::process::id();
    let binary_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(
                error = %e,
                "FDP drain: current_exe() failed; cannot hot-restart",
            );
            return;
        }
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let pipe = match crate::hotbin::ReadinessPipe::new() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(
                error = %e,
                "FDP drain: ReadinessPipe::new() failed; cannot hot-restart",
            );
            return;
        }
    };
    let plan = crate::hotbin::SuccessorPlan {
        binary_path: binary_path.clone(),
        listeners: listener_fd_registry.to_vec(),
        extra_env: Vec::new(),
        args,
        readiness_write_fd: Some(pipe.write_fd()),
    };

    bus.emit(aegis_core::audit::AuditEvent {
        schema_version: 1,
        ts: chrono::Utc::now(),
        request_id: handover_id.clone(),
        class: aegis_core::audit::AuditClass::Access,
        tenant_id: None,
        tier: None,
        action: "binary_handover_started".into(),
        reason: "handover_initiated".to_string(),
        client_ip: String::new(),
        route_id: None,
        rule_id: Some("handover_initiated".to_string()),
        risk_score: None,
        method: None,
        path: None,
        mode: None,
        fields: serde_json::json!({
            "handover_id": handover_id,
            "old_pid": our_pid,
            "fd_count": listener_fd_registry.len(),
            "fd_names": listener_fd_registry
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>(),
        }),
    });

    let pipe = std::sync::Arc::new(pipe);
    let pipe_for_poll = pipe.clone();
    let outcome = crate::hotbin::perform_handover(
        plan,
        inflight,
        crate::hotbin::HandoverConfig::default(),
        move || {
            let p = pipe_for_poll.clone();
            async move { p.try_read_signal().unwrap_or(false) }
        },
    )
    .await;

    let outcome_label = match &outcome {
        crate::hotbin::HandoverOutcome::Drained { .. } => "drained",
        crate::hotbin::HandoverOutcome::DrainTimeout { .. } => "drain_timeout",
        crate::hotbin::HandoverOutcome::RolledBack { .. } => "rolled_back",
    };
    bus.emit(aegis_core::audit::AuditEvent {
        schema_version: 1,
        ts: chrono::Utc::now(),
        request_id: handover_id.clone(),
        class: aegis_core::audit::AuditClass::Access,
        tenant_id: None,
        tier: None,
        action: "binary_handover_completed".into(),
        reason: outcome.rule_id().to_string(),
        client_ip: String::new(),
        route_id: None,
        rule_id: Some(outcome.rule_id().to_string()),
        risk_score: None,
        method: None,
        path: None,
        mode: None,
        fields: serde_json::json!({
            "handover_id": handover_id,
            "outcome": outcome_label,
            "inflight_at_signal": inflight_at_signal,
            "details": format!("{outcome:?}"),
        }),
    });

    tracing::info!(
        handover_id = %handover_id,
        outcome = outcome_label,
        ?outcome,
        "FDP handover completed",
    );

    // On a successful drain (or drain-timeout — operator policy
    // is to still hand over rather than leak in-flight requests
    // forever) exit so the child takes over the listener FDs
    // exclusively. RolledBack is the only branch where we keep
    // running.
    match outcome {
        crate::hotbin::HandoverOutcome::Drained { .. }
        | crate::hotbin::HandoverOutcome::DrainTimeout { .. } => {
            // Give the bus subscribers a few ms to flush the
            // completion event before exit. Audit JSONL sinks
            // batch every 1s by default; missing the boundary
            // would lose the completion event.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            std::process::exit(0);
        }
        crate::hotbin::HandoverOutcome::RolledBack { ref reason, .. } => {
            tracing::warn!(
                handover_id = %handover_id,
                reason = %reason,
                "FDP handover rolled back; parent resumes serving",
            );
        }
    }
}
