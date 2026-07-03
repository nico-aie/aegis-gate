//! Shared on-reload helpers used by both the file-watcher
//! (`supervisor::watch_loop`) and the redis config-plane watcher
//! (`redis_source::watch_loop`).
//!
//! A "config reload" lands a new [`WafConfig`] into the data
//! plane. Two side effects must happen atomically with the swap:
//!
//! 1. **Detector-mask base re-derivation.** `cfg.detectors`'s
//!    enable flags drive the *initial* mask state. A hot-reload
//!    that flipped `cfg.detectors.sqli.enabled: false` would be
//!    silently ignored without re-deriving the base. Per-tier
//!    overrides set by `PUT /api/detectors` are intentionally
//!    preserved — they're explicit operator intent, separate
//!    from cfg defaults.
//!
//! 2. **Compliance clamp.** Re-deriving the base from cfg might
//!    have just disabled a class that `cfg.compliance.modes`
//!    pins to ON (PCI / HIPAA / SOC2 / GDPR / FIPS). The clamp
//!    forces those classes back on; the helper returns the
//!    `forced` list so callers can emit a
//!    `compliance_clamp_applied` audit event.
//!
//! Both effects fire on every successful reload, regardless of
//! source — file, etcd, future raft. Putting the logic here
//! keeps the supervisor + etcd watchers in lockstep on the
//! correctness contract.

use std::sync::Arc;

use aegis_core::config::WafConfig;
use aegis_security::detectors::{MaskState, SharedDetectorMask};
use aegis_security::rate_limit::{IpRateLimitConfig, IpRateLimiter};

use crate::listener::client_trust::ClientTrustStore;
use crate::listener::tls::{CertStore, DynamicResolver};
use crate::proxy::ProxyContext;

/// Outcome of [`apply_cfg_change_to_mask`]. Mirrors
/// `detectors_persist::ApplyOutcome` but is local to this module
/// so callers don't drag in the persistence types when they
/// only care about the reload path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// Mask re-derived from `new_cfg.detectors`. No compliance
    /// clamp was needed.
    Applied,
    /// Mask re-derived AND clamped — `forced` lists the classes
    /// the clamp had to flip back on (`"sqli"` for base,
    /// `"override[medium]:sqli"` for per-tier).
    AppliedWithCompliance { forced: Vec<String> },
    /// Caller passed `mask: None` — no work to do. Returned so
    /// callers can log a single info event uniformly.
    NoMask,
}

/// Re-derive the full detector mask state (base **and** per-tier
/// overrides) from `new_cfg` and run the compliance clamp against
/// the result.
///
/// 2026-05-27 (Phase B detectors fold) — contract change. The
/// config document is now the single source of truth for per-tier
/// overrides: the whole [`MaskState`] is rebuilt from
/// `new_cfg.detectors` (base `enabled` flags + the `Ai` bit from
/// `new_cfg.ai.enabled` + `cfg.detectors.per_tier`) and
/// `store_state`'d, so an override authored in YAML — or activated
/// through the cluster config plane via the folded
/// `PUT /api/detectors` — re-derives identically on every node.
/// A live override absent from `cfg.detectors.per_tier` is cleared
/// (it used to be preserved). The compliance clamp then re-runs on
/// both base and overrides so a freshly-disabled compliance-pinned
/// class gets forced back on no matter where it lives.
pub fn apply_cfg_change_to_mask(
    new_cfg: &WafConfig,
    mask: Option<&SharedDetectorMask>,
) -> ReloadOutcome {
    let Some(mask) = mask else {
        return ReloadOutcome::NoMask;
    };

    let new_state =
        MaskState::from_detectors_config(&new_cfg.detectors, new_cfg.ai.enabled);
    mask.store_state(new_state);

    let modes = new_cfg
        .compliance
        .as_ref()
        .map(|c| c.modes.clone())
        .unwrap_or_default();
    if modes.is_empty() {
        return ReloadOutcome::Applied;
    }

    use aegis_control::api::detectors_persist::{
        apply_live_mask_with_compliance, ApplyOutcome,
    };
    match apply_live_mask_with_compliance(mask, &modes) {
        ApplyOutcome::Applied => ReloadOutcome::Applied,
        ApplyOutcome::AppliedWithCompliance { forced } => {
            ReloadOutcome::AppliedWithCompliance { forced }
        }
    }
}

/// Outcome of [`apply_cfg_change_to_routes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteReloadOutcome {
    /// Caller passed `ctx: None` — no work to do.
    NoCtx,
    /// New route table built and atomic-swapped into the live
    /// `ProxyContext`. In-flight requests that already loaded a
    /// snapshot finish on the old table.
    Applied,
    /// Route table validation failed (e.g. missing catch-all,
    /// invalid host pattern). The live table is unchanged.
    Failed { reason: String },
}

/// Outcome of [`apply_cfg_change_to_tls`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsReloadOutcome {
    /// Caller passed `resolver: None` — the proxy boot path
    /// didn't have any TLS certs configured, so there's nothing
    /// to swap into. Callers can still attempt to enable TLS
    /// after restart.
    NoResolver,
    /// New cert store built from `new_cfg.tls.certificates` and
    /// atomic-swapped into the resolver. `cert_count` reflects
    /// the number of `(cert, key, hosts)` triples loaded.
    Applied { cert_count: usize },
    /// `cfg.tls` is `None` or `cfg.tls.certificates` is empty in
    /// the new cfg. Keeping the previous cert store live is
    /// safer than swapping to nothing — listeners with
    /// `tls: true` would handshake-fail otherwise. Operators
    /// disabling TLS need a restart.
    SkippedEmpty,
    /// Cert load / key parse / chain validation failed. The
    /// previous cert store stays live; operators see
    /// `tls_reload_failed` in the audit chain. The most common
    /// causes: missing cert files, mismatched cert/key, or a
    /// PEM with no private key.
    Failed { reason: String },
}

/// Re-derive a [`CertStore`] from `new_cfg.tls.certificates`
/// and atomic-swap it into the live `DynamicResolver`. Triggered
/// by both file + etcd watchers on every successful reload.
///
/// **Empty / missing TLS cfg** is treated as "skip" rather than
/// "remove" — clearing the cert store would crash every
/// `tls: true` listener's next handshake. Operators who want to
/// disable TLS at runtime need to restart.
///
/// **Disk read errors** (missing cert path, unreadable key) and
/// **chain validation errors** (empty PEM, bad signature
/// algorithm) keep the previous store live. The
/// [`TlsReloadOutcome::Failed`] variant carries the reason so
/// the dashboard can surface it.
pub fn apply_cfg_change_to_tls(
    new_cfg: &WafConfig,
    resolver: Option<&Arc<DynamicResolver>>,
) -> TlsReloadOutcome {
    let Some(resolver) = resolver else {
        return TlsReloadOutcome::NoResolver;
    };
    let Some(tls_cfg) = new_cfg.tls.as_ref() else {
        return TlsReloadOutcome::SkippedEmpty;
    };
    if tls_cfg.certificates.is_empty() {
        return TlsReloadOutcome::SkippedEmpty;
    }

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
    let cert_count = entries.len();

    match CertStore::load(&entries) {
        Ok(store) => {
            resolver.swap(store);
            TlsReloadOutcome::Applied { cert_count }
        }
        Err(e) => TlsReloadOutcome::Failed {
            reason: e.to_string(),
        },
    }
}

/// Outcome of [`apply_cfg_change_to_rate_limit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitReloadOutcome {
    /// Caller passed `limiter: None` — no work to do.
    NoLimiter,
    /// New `IpRateLimitConfig` derived from `new_cfg.rate_limit`
    /// and stored. Old per-IP timestamp state is preserved.
    Applied { limit: u32, window_secs: u64 },
    /// New cfg matched the live cfg byte-for-byte; the
    /// `ArcSwap` store was skipped to keep hot reads
    /// uncontended on the no-op path.
    Unchanged,
}

/// Derive an [`IpRateLimitConfig`] from
/// `new_cfg.rate_limit.buckets` and hot-swap it into the live
/// limiter. Same selection rule as the boot path: the FIRST
/// bucket with `scope: Global` + `key: Ip` wins; if none is
/// configured we fall back to the library default. The per-IP
/// timestamp map stays intact across the swap — operators
/// editing the bucket don't accidentally reset every
/// flooding-source IP back to zero counts.
pub fn apply_cfg_change_to_rate_limit(
    new_cfg: &WafConfig,
    limiter: Option<&Arc<IpRateLimiter>>,
) -> RateLimitReloadOutcome {
    let Some(limiter) = limiter else {
        return RateLimitReloadOutcome::NoLimiter;
    };

    let new_rl_cfg = derive_ip_rate_cfg(new_cfg);
    if limiter.config() == new_rl_cfg {
        return RateLimitReloadOutcome::Unchanged;
    }
    limiter.set_config(new_rl_cfg);
    RateLimitReloadOutcome::Applied {
        limit: new_rl_cfg.limit,
        window_secs: new_rl_cfg.window.as_secs(),
    }
}

/// Outcome of re-deriving the AI runtime gate from a config swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiReloadOutcome {
    /// No AI toggle handle wired — binary built without `ai`, or
    /// `cfg.ai.enabled` was false at boot so no detector (and no
    /// runtime toggle) exists. Nothing to re-derive.
    NoToggle,
    /// The runtime toggle (+ the mask `Ai` bit) were set from
    /// `cfg.ai.enabled`.
    Applied { enabled: bool },
}

/// 2026-05-27 (config-plane fold-toggles, Phase B) — re-derive the AI
/// detector's runtime gate from `new_cfg.ai.enabled` on a config swap, so
/// a cluster-wide config activation that flips `ai.enabled` takes effect
/// on every node (eventual — applied on the watcher's next poll). Sets
/// BOTH the runtime `AtomicBool` (the live dispatcher gate the data plane
/// reads per request) and the detector mask's `Ai` bit (so
/// `GET /api/detectors` stays consistent), mirroring the in-process
/// `PUT /api/ai/enabled` handler.
pub fn apply_cfg_change_to_ai(
    new_cfg: &WafConfig,
    ai_toggle: Option<&Arc<std::sync::atomic::AtomicBool>>,
    mask: Option<&SharedDetectorMask>,
    ai_threshold: Option<&Arc<std::sync::atomic::AtomicU32>>,
) -> AiReloadOutcome {
    // 2026-05-30 — write the threshold FIRST so that even when no
    // toggle is wired (e.g. a binary without `--features ai` that
    // still surfaces the config-plane), a cluster-pushed threshold
    // change still reaches whatever does read the atomic later
    // (e.g. a future reader). Independent of `enabled`.
    if let Some(t) = ai_threshold {
        t.store(
            new_cfg.ai.confidence_threshold.to_bits(),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    let Some(toggle) = ai_toggle else {
        return AiReloadOutcome::NoToggle;
    };
    let enabled = new_cfg.ai.enabled;
    toggle.store(enabled, std::sync::atomic::Ordering::Relaxed);
    if let Some(mask) = mask {
        use aegis_security::detectors::mask::DetectorClass;
        let base = mask.load_state().base.with(DetectorClass::Ai, enabled);
        mask.store(base);
    }
    AiReloadOutcome::Applied { enabled }
}

/// Outcome of re-deriving the response-filter rungs from a config swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseFilterReloadOutcome {
    /// No writer handle wired (no-pipeline build / test bundle).
    NoWriter,
    /// The three rungs were set from `cfg.response_filter`.
    Applied {
        scrub_stack_traces: bool,
        mask_internal_ips: bool,
        redact_dlp: bool,
    },
}

/// 2026-05-27 (config-plane fold-toggles, Phase B) — re-derive the
/// response-body filter rungs from `new_cfg.response_filter` on a config
/// swap, so a cluster-wide activation that flips a rung takes effect on
/// every node (eventual). Mirrors the in-process `PUT /api/response-filter`
/// handler by pushing a `ResponseFilterPatch` through the same writer.
pub fn apply_cfg_change_to_response_filter(
    new_cfg: &WafConfig,
    writer: Option<&Arc<dyn aegis_control::api::response_filter::ResponseFilterWriter>>,
) -> ResponseFilterReloadOutcome {
    let Some(writer) = writer else {
        return ResponseFilterReloadOutcome::NoWriter;
    };
    let rf = &new_cfg.response_filter;
    writer.set(aegis_control::api::response_filter::ResponseFilterPatch {
        scrub_stack_traces: rf.scrub_stack_traces,
        mask_internal_ips: rf.mask_internal_ips,
        redact_dlp: rf.redact_dlp,
    });
    ResponseFilterReloadOutcome::Applied {
        scrub_stack_traces: rf.scrub_stack_traces,
        mask_internal_ips: rf.mask_internal_ips,
        redact_dlp: rf.redact_dlp,
    }
}

/// Outcome of re-deriving per-tier settings from a config swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TiersReloadOutcome {
    /// No `TierStore` handle wired.
    NoStore,
    /// Per-tier settings were re-applied from `cfg.tiers`:
    /// `risk_threshold` + `challenges_enabled` for every tier, plus the
    /// richer `block_threshold` / `cumulative_*` / `pipeline` fields for
    /// any tier whose `cfg.tiers.<name>` entry carries them.
    Applied,
}

/// 2026-05-27 (config-plane fold-toggles, Phase B) — re-derive the
/// per-tier settings carried by `cfg.tiers` (`risk_threshold` +
/// `challenges_enabled`) onto the live `TierStore` on a config swap, so a
/// cluster-wide activation propagates them to every node (eventual).
/// Reuses the same `apply_*` methods the boot path uses
/// (`accept.rs` seeds the store identically at startup). Tiers omitted
/// from `cfg.tiers` keep their current value (the methods only touch
/// listed tiers). A3 (2026-06-14) — the richer per-tier fields
/// (`block_threshold` / `cumulative_*` / `pipeline`) are now carried by
/// `cfg.tiers.<name>` (`TierThresholdConfig`) and applied below via
/// `apply_optional_overrides`, so the dedicated `PUT /api/tiers/<name>`
/// folds fully into the converged config.
pub fn apply_cfg_change_to_tiers(
    new_cfg: &WafConfig,
    tiers: Option<&Arc<aegis_control::api::tiers::TierStore>>,
) -> TiersReloadOutcome {
    let Some(tiers) = tiers else {
        return TiersReloadOutcome::NoStore;
    };
    tiers.apply_risk_thresholds(new_cfg.tiers.risk_threshold_overrides());
    tiers.apply_challenges_enabled(new_cfg.tiers.challenges_enabled_overrides());
    // A3 — the richer per-tier fields (block_threshold / cumulative_* /
    // pipeline), applied for each tier whose cfg entry carries them.
    let optional = [
        ("critical", &new_cfg.tiers.critical),
        ("high", &new_cfg.tiers.high),
        ("medium", &new_cfg.tiers.medium),
        ("low", &new_cfg.tiers.low),
    ]
    .into_iter()
    .filter_map(|(name, opt)| {
        opt.as_ref().map(|t| {
            (
                name,
                aegis_control::api::tiers::OptionalTierFields {
                    block_threshold: t.block_threshold,
                    cumulative_challenge_at: t.cumulative_challenge_at,
                    cumulative_block_at: t.cumulative_block_at,
                    pipeline: t.pipeline.clone(),
                },
            )
        })
    });
    tiers.apply_optional_overrides(optional);
    TiersReloadOutcome::Applied
}

/// Outcome of re-deriving the rule set from a config swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulesReloadOutcome {
    /// No `RuleStore` handle wired.
    NoStore,
    /// The `RuleStore` was replaced from `cfg.rules.inline` and the
    /// active engine ruleset rebuilt. `live_rules` is the number of
    /// enabled rules that compiled; `rejected` lists inline rule ids
    /// that failed id/body validation (skipped, not stored).
    Applied {
        live_rules: usize,
        rejected: Vec<String>,
    },
}

/// 2026-05-27 (Phase B rules fold) — re-derive the live `RuleStore`
/// from `new_cfg.rules.inline` (the source of truth) and rebuild the
/// active engine ruleset on a config swap, so a cluster-wide
/// activation propagates rule CRUD to every node (eventual). Reuses
/// the same `RuleStore::replace_all` + `rebuild_active_ruleset` the
/// boot path uses, so seeding and hot-reload stay identical.
///
/// Rules absent from `cfg.rules.inline` are dropped (cfg is
/// authoritative). Inline rules that fail validation are skipped and
/// returned in `rejected`. A parse failure during the engine rebuild
/// leaves the previous live ruleset intact (the `RuleStore` swap still
/// lands) — the same non-rollback contract the CRUD handlers use.
pub fn apply_cfg_change_to_rules(
    new_cfg: &WafConfig,
    rules: Option<&Arc<aegis_control::api::rules::RuleStore>>,
    active_ruleset: Option<&Arc<aegis_security::RuleSet>>,
) -> RulesReloadOutcome {
    let Some(store) = rules else {
        return RulesReloadOutcome::NoStore;
    };
    let rejected: Vec<String> = store
        .replace_all(&new_cfg.rules.inline)
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    let live_rules = match active_ruleset {
        Some(rs) => match aegis_control::api::rules::rebuild_active_ruleset(store, rs) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "rule rebuild after config swap failed to parse; live ruleset unchanged",
                );
                rs.len()
            }
        },
        None => 0,
    };
    RulesReloadOutcome::Applied {
        live_rules,
        rejected,
    }
}

/// Outcome of rebuilding the upstream pool registry from a config swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamsReloadOutcome {
    /// No `UpstreamWriter` handle wired.
    NoWriter,
    /// `cfg.upstreams` was resolved + applied to the live `PoolRegistry`.
    /// `pools` is the pool count after the swap.
    Applied { pools: usize },
    /// DNS resolution or pool validation failed; the live pools are
    /// unchanged.
    Failed { reason: String },
}

/// 2026-05-27 (Phase B upstreams fold) — rebuild the live upstream
/// `PoolRegistry` from `new_cfg.upstreams` on a config swap, so a
/// cluster-wide activation rebuilds pools on every node (eventual).
///
/// Hostnames are resolved **per node** at apply time (the shared doc
/// keeps operator-authored hostnames; each node uses its own resolver
/// view) via `expand_hostname_members`. `SoftSkip` mirrors the boot
/// path: a transient resolver blip drops the failing hostname's members
/// rather than wiping the whole table. The resolved pools then go
/// through the same `PoolRegistry::apply` the audit-mutated PUT uses
/// (atomic pool + circuit-breaker + connection-pool rebuild).
///
/// This closes the gap the file/etcd watchers warn about ("pools are
/// NOT rebuilt from reload") for the config-plane path: folded upstream
/// PUTs now patch `cfg.upstreams` + activate, and this re-derives.
pub async fn apply_cfg_change_to_upstreams(
    new_cfg: &WafConfig,
    writer: Option<&Arc<dyn aegis_control::api::upstreams_config::UpstreamWriter>>,
    dns_refresh: Option<&Arc<crate::upstream::dns_refresh::DnsRefreshManager>>,
) -> UpstreamsReloadOutcome {
    let Some(writer) = writer else {
        return UpstreamsReloadOutcome::NoWriter;
    };
    let resolved = match crate::upstream::dns_resolve::expand_hostname_members_with_policy(
        new_cfg.upstreams.clone(),
        crate::upstream::dns_resolve::ResolveFailurePolicy::SoftSkip,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return UpstreamsReloadOutcome::Failed {
                reason: e.to_string(),
            }
        }
    };
    let pools = resolved.len();
    match writer.apply(&resolved) {
        Ok(()) => {
            // BUG-dns-refresh-not-spawned-for-live-added-hostnames —
            // bring the background DNS-refresh tasks up to date with the
            // operator-authored upstreams (pre-expansion `new_cfg.upstreams`,
            // not the resolved IP literals). Spawns a task for a hostname
            // pool added after boot, restarts one whose hostnames changed,
            // stops one whose pool was removed. Runs *after* the registry
            // apply so the new task's first-tick seed reflects the IPs we
            // just installed. No-op when no manager is wired (resolver
            // failed to build at boot) — same degraded mode as before.
            if let Some(mgr) = dns_refresh {
                mgr.reconcile(&new_cfg.upstreams);
            }
            UpstreamsReloadOutcome::Applied { pools }
        }
        Err(e) => UpstreamsReloadOutcome::Failed {
            reason: e.to_string(),
        },
    }
}

/// 2026-05-28 (Phase B fold parity) — handles for the folded stores
/// (AI gate, response-filter rungs, tiers, rules, upstream pools) that
/// the **file + etcd** watchers re-derive on reload. The redis
/// config-plane watcher does this inline via its `ApplyTargets`; this
/// bundle lets the other config sources reach
/// [`apply_folded_stores`] with one parameter instead of six. All
/// fields default to `None` (the helper short-circuits each).
#[derive(Clone, Default)]
pub struct FoldedReloadTargets {
    /// The live detector mask — passed only so the AI helper can OR its
    /// bit onto the base. The base itself is re-derived separately by
    /// [`apply_cfg_change_to_mask`], which each watcher calls first.
    pub detector_mask: Option<SharedDetectorMask>,
    pub ai_toggle: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// 2026-05-30 (NT-07 / R2-006) — closes the live-propagate gap for
    /// the AI `confidence_threshold` fold. Same shape as `ai_toggle`:
    /// the watcher pushes `new_cfg.ai.confidence_threshold` into this
    /// shared `AtomicU32` (storing `f32::to_bits`) so every node's
    /// AiDetector reads the updated gate on its next inference. Until
    /// this was wired the threshold value persisted in the cluster doc
    /// but only the *originating* node's atomic updated (the PUT
    /// handler writes locally); restarts and other nodes regressed to
    /// `cfg.ai.confidence_threshold` from waf.yaml.
    pub ai_threshold: Option<Arc<std::sync::atomic::AtomicU32>>,
    pub response_filter_writer:
        Option<Arc<dyn aegis_control::api::response_filter::ResponseFilterWriter>>,
    pub tiers: Option<Arc<aegis_control::api::tiers::TierStore>>,
    pub rules: Option<Arc<aegis_control::api::rules::RuleStore>>,
    pub active_ruleset: Option<Arc<aegis_security::RuleSet>>,
    pub upstream_writer:
        Option<Arc<dyn aegis_control::api::upstreams_config::UpstreamWriter>>,
    /// BUG-dns-refresh-not-spawned-for-live-added-hostnames — the live
    /// DNS-refresh task manager, so a file/etcd reload reconciles
    /// per-pool refresh tasks for hostname members added/changed after
    /// boot. `None` when the resolver failed to build at boot.
    pub dns_refresh: Option<Arc<crate::upstream::dns_refresh::DnsRefreshManager>>,
    /// 2026-06-18 (runtime_gate_toggles_not_durable) — gate runtimes so a
    /// file/etcd reload re-derives them too (the shared-store watcher does
    /// via `ApplyTargets`). The DDoS runtime is `OnceCell`-installed at boot.
    pub ddos: Option<Arc<aegis_security::ddos::DdosRuntime>>,
    /// Live risk tracker — re-derives cumulative thresholds + Strike-Block.
    pub risk: Option<aegis_security::risk::RiskTracker>,
    /// Canary honeypot path set.
    pub canary_paths: Option<aegis_security::detectors::canary::CanaryPaths>,
    /// Bot-classifier gate toggle (shared `AtomicBool`).
    pub bots_enabled: Option<Arc<std::sync::atomic::AtomicBool>>,
}

/// 2026-05-28 (Phase B fold parity) — re-derive the folded stores from
/// `new_cfg` on a config swap. Closes the gap where a config delivered
/// via **file** or **etcd** reload only re-derived routes / mask /
/// rate-limit / TLS, leaving rules / upstreams / tiers / AI /
/// response-filter to need a restart (the redis config-plane watcher
/// already re-derived them). Call this AFTER
/// [`apply_cfg_change_to_mask`] (so the AI helper ORs onto a fresh base)
/// and before the `ArcSwap` swap. Each helper is a no-op when its handle
/// is `None`.
pub async fn apply_folded_stores(new_cfg: &WafConfig, t: &FoldedReloadTargets) {
    let _ = apply_cfg_change_to_ai(
        new_cfg,
        t.ai_toggle.as_ref(),
        t.detector_mask.as_ref(),
        t.ai_threshold.as_ref(),
    );
    let _ = apply_cfg_change_to_response_filter(new_cfg, t.response_filter_writer.as_ref());
    let _ = apply_cfg_change_to_tiers(new_cfg, t.tiers.as_ref());
    let _ = apply_cfg_change_to_rules(new_cfg, t.rules.as_ref(), t.active_ruleset.as_ref());
    let _ =
        apply_cfg_change_to_upstreams(new_cfg, t.upstream_writer.as_ref(), t.dns_refresh.as_ref())
            .await;
    let _ = apply_cfg_change_to_copilot(new_cfg).await;
    // 2026-06-18 — gate runtimes (ddos / risk thresholds + strikes + canary /
    // bots). File/etcd reload parity with the shared-store watcher.
    let _ = apply_cfg_change_to_ddos(new_cfg, t.ddos.as_ref());
    let _ = apply_cfg_change_to_risk(new_cfg, t.risk.as_ref(), t.canary_paths.as_ref());
    let _ = apply_cfg_change_to_bots(new_cfg, t.bots_enabled.as_ref());
}

/// 2026-06-03 (config-plane fold) — rebuild the AI Operator Copilot from
/// `new_cfg.observability.copilot` and hot-swap the live service on a
/// config activation, so a cluster-wide change (enable/disable, model,
/// base_url, timeout, or a key rotation behind the secret ref) takes
/// effect on every node without a restart (eventual — applied on the
/// watcher's next poll). The `api_key_ref` is resolved per-node here
/// (env / file / vault / cloud); the secret never transits the stored
/// config doc. Mirrors the boot wiring in `run()`: an enabled block
/// builds from config; a disabled/absent block falls back to the legacy
/// `LLM_*` env build so pure-env deployments survive unrelated config
/// pushes. Returns the copilot's enabled state after the swap.
pub async fn apply_cfg_change_to_copilot(new_cfg: &WafConfig) -> bool {
    let cc = &new_cfg.observability.copilot;
    let svc = if cc.enabled {
        let api_key = crate::run::resolve_copilot_api_key(cc).await;
        aegis_control::copilot::service::CopilotService::from_config(cc, api_key)
    } else {
        aegis_control::copilot::service::CopilotService::from_env()
    };
    let enabled = svc.enabled();
    aegis_control::copilot::service::set_global(svc);
    enabled
}

/// Pure: derive the IP rate-limit config the boot path uses
/// from a `WafConfig`. Shared between `aegis-proxy::run` (boot)
/// and the watchers (hot-reload) so the selection rule stays
/// in one place.
pub fn derive_ip_rate_cfg(cfg: &WafConfig) -> IpRateLimitConfig {
    // 2026-06-22 — `enabled` is a feature-level flag on `rate_limit`, applied
    // regardless of whether a `global/ip` bucket is configured: an operator can
    // disable the gate while leaving the bucket definition in place (or with no
    // bucket at all, where limit/window fall back to the library default).
    let mut derived = cfg
        .rate_limit
        .buckets
        .iter()
        .find(|b| {
            matches!(b.scope, aegis_core::config::RlScope::Global)
                && matches!(b.key, aegis_core::config::RlKey::Ip)
        })
        .map(|b| IpRateLimitConfig {
            limit: b.limit.min(u32::MAX as u64) as u32,
            window: b.window,
            enabled: cfg.rate_limit.enabled,
        })
        .unwrap_or_default();
    derived.enabled = cfg.rate_limit.enabled;
    derived
}

/// Derive the live `DdosRuntime` config from a `WafConfig`, mirroring the
/// boot path in `run()`: start from `cfg.ddos`, then overlay the per-tier
/// failure-mode policy from `cfg.fail_mode_by_tier`. Shared between boot and
/// the hot-reload helper so the two never drift.
pub fn derive_ddos_runtime_cfg(cfg: &WafConfig) -> aegis_security::ddos::DdosConfig {
    let mut ddos_cfg: aegis_security::ddos::DdosConfig = cfg.ddos.clone().into();
    for (tier, mode) in &cfg.fail_mode_by_tier {
        let runtime_mode = match mode {
            aegis_core::config::FailureModeConfig::FailClose => {
                aegis_core::tier::FailureMode::FailClose
            }
            aegis_core::config::FailureModeConfig::FailOpen => {
                aegis_core::tier::FailureMode::FailOpen
            }
        };
        ddos_cfg.failure_mode.insert(*tier, runtime_mode);
    }
    ddos_cfg
}

/// Outcome of a gate-style reload (ddos / risk / bots) — whether a live
/// runtime handle was wired to receive the re-derived config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateReloadOutcome {
    NoHandle,
    Applied,
}

/// 2026-06-18 (runtime_gate_toggles_not_durable) — re-derive the DDoS gate
/// runtime from `new_cfg`. Without this the shared-config watcher published
/// the operator's `ddos` change to `config:waf:doc` but never re-installed
/// it into the live `DdosRuntime`, so a restart reverted to the waf.yaml
/// value. The per-IP sliding-window state in the StateBackend is untouched —
/// `set_config` swaps only the thresholds.
pub fn apply_cfg_change_to_ddos(
    new_cfg: &WafConfig,
    ddos: Option<&Arc<aegis_security::ddos::DdosRuntime>>,
) -> GateReloadOutcome {
    let Some(rt) = ddos else {
        return GateReloadOutcome::NoHandle;
    };
    rt.set_config(derive_ddos_runtime_cfg(new_cfg));
    GateReloadOutcome::Applied
}

/// 2026-06-18 — re-derive the bot-classifier gate toggle from
/// `new_cfg.bots.enabled` (shared `AtomicBool` read by the data plane).
pub fn apply_cfg_change_to_bots(
    new_cfg: &WafConfig,
    bots_enabled: Option<&Arc<std::sync::atomic::AtomicBool>>,
) -> GateReloadOutcome {
    let Some(toggle) = bots_enabled else {
        return GateReloadOutcome::NoHandle;
    };
    toggle.store(new_cfg.bots.enabled, std::sync::atomic::Ordering::Relaxed);
    GateReloadOutcome::Applied
}

/// 2026-06-18 — re-derive the risk-based gates from `new_cfg.risk`:
/// cumulative-risk thresholds, the Strike-Block gate, and the canary
/// honeypot path set. Per-IP risk/strike state in the tracker is preserved
/// (only the config snapshots swap). Each handle is independent; a `None`
/// handle is skipped, and a `risk.strikes` left unset preserves the live
/// strike config (the dashboard PUT always writes it once configured).
pub fn apply_cfg_change_to_risk(
    new_cfg: &WafConfig,
    risk: Option<&aegis_security::risk::RiskTracker>,
    canary: Option<&aegis_security::detectors::canary::CanaryPaths>,
) -> GateReloadOutcome {
    let mut applied = false;
    if let Some(tracker) = risk {
        tracker.set_thresholds(new_cfg.risk.thresholds.clone());
        // 2026-06-21 — sync the cumulative-risk decay rate across nodes. A
        // converged doc that tuned `trust_recovery.per_hour` must hot-apply
        // here, not just on the node that handled the PUT.
        tracker.set_trust_per_hour(
            new_cfg.risk.trust_recovery.clone().unwrap_or_default().per_hour,
        );
        if let Some(sc) = &new_cfg.risk.strikes {
            tracker.set_strike_config(sc.clone());
        }
        applied = true;
    }
    if let Some(c) = canary {
        c.set(&new_cfg.risk.canary_paths);
        applied = true;
    }
    if applied {
        GateReloadOutcome::Applied
    } else {
        GateReloadOutcome::NoHandle
    }
}

/// Rebuild the live `ProxyContext.route_table` from
/// `new_cfg.routes` and atomic-swap it. Validation runs first
/// (`RouteTable::build`) so an invalid new cfg leaves the live
/// table intact.
///
/// Note: `ctx.pools` (the upstream pool registry) is *not*
/// rebuilt here. Pools have their own audit-mutated PUT path
/// (CC-T1.1.b) which provides the same hot-swap semantics —
/// applying both from a single cfg-reload would race the
/// audit-mutated state against itself. Operators who edit
/// `cfg.upstreams` and want it live should either restart or
/// PUT through the dashboard.
pub fn apply_cfg_change_to_routes(
    new_cfg: &WafConfig,
    ctx: Option<&Arc<ProxyContext>>,
) -> RouteReloadOutcome {
    let Some(ctx) = ctx else {
        return RouteReloadOutcome::NoCtx;
    };
    match ctx.route_table.apply(new_cfg) {
        Ok(()) => RouteReloadOutcome::Applied,
        Err(e) => RouteReloadOutcome::Failed {
            reason: e.to_string(),
        },
    }
}

/// 2026-06-21 — config-plane hot-reload for the per-pool response (smart)
/// cache. Reconciles `ctx.cache` against the activated config's `upstreams`
/// so a dashboard pool edit that enables / adds / changes / removes a
/// `cache:` block takes effect WITHOUT a restart. Before this, the response
/// cache was absent from BOTH reload paths (file watcher + shared-store
/// watcher), so a UI "Response cache" toggle was silently
/// node-local-until-restart (and even a restart only helped if the boot
/// config file itself carried the block). Cached entries on pools whose
/// cache config is unchanged are preserved (see [`ResponseCache::apply`]).
pub fn apply_cfg_change_to_cache(
    new_cfg: &WafConfig,
    ctx: Option<&Arc<ProxyContext>>,
) -> GateReloadOutcome {
    let Some(ctx) = ctx else {
        return GateReloadOutcome::NoHandle;
    };
    ctx.cache.apply(&new_cfg.upstreams);
    GateReloadOutcome::Applied
}

/// Tier-1A — re-derive the GraphQL query guard from `new_cfg.graphql` and
/// atomic-swap it into the live `ProxyContext.graphql_guard`. A converged
/// doc that flipped `graphql.enabled` or tuned a limit then applies on
/// every node, not just the one that handled the PUT — the same
/// node-local-until-restart trap the structural guard test prevents.
pub fn apply_cfg_change_to_graphql(
    new_cfg: &WafConfig,
    ctx: Option<&Arc<ProxyContext>>,
) -> GateReloadOutcome {
    let Some(ctx) = ctx else {
        return GateReloadOutcome::NoHandle;
    };
    ctx.graphql_guard.store(Arc::new(
        crate::graphql_guard::GraphqlGuard::from_config(&new_cfg.graphql),
    ));
    GateReloadOutcome::Applied
}

/// Outcome of [`apply_cfg_change_to_client_auth`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuthReloadOutcome {
    /// Caller passed `trust_store: None` — proxy boot didn't
    /// configure inbound mTLS, so there's nothing to swap into.
    /// Operators who flip from "no client_auth" to client_auth
    /// at runtime need to restart (the verifier is wired into
    /// the rustls config at boot, and we don't rebuild that
    /// here).
    NoStore,
    /// New CA bundle parsed and atomic-swapped into the live
    /// store. `cert_count` is the number of trust anchors in
    /// the new bundle (operators see this in the
    /// `zero_trust_reloaded` audit event).
    Applied {
        cert_count: usize,
        mode: aegis_core::config::DownstreamMtlsMode,
    },
    /// `cfg.tls.client_auth` is `None` or its mode is
    /// `Disabled` in the new cfg. Skip-not-clear: keeping the
    /// previous trust store live is safer than swapping to
    /// nothing — `Required`-mode listeners would reject every
    /// handshake otherwise. Operators disabling client-auth
    /// at runtime need a restart.
    SkippedDisabled,
    /// New cfg has no `ca_bundle` path even though
    /// `mode != Disabled`. Validation should have caught this
    /// at the `WafConfig::validate` step; we still defend in
    /// depth and surface a `Failed` so the audit log records
    /// the bad reload attempt.
    MissingCaBundle,
    /// PEM parse / chain validation of the new bundle failed.
    /// The previous trust store stays live; operators see
    /// `zero_trust_reload_failed` in the audit chain. Common
    /// causes: missing file, no `BEGIN CERTIFICATE` blocks,
    /// or an unsupported CA encoding.
    Failed { reason: String },
}

/// MTLS-T5 — re-parse the configured CA bundle and atomic-
/// swap it into the live [`ClientTrustStore`]. Triggered by
/// both file + etcd watchers after `tls_reloaded`.
///
/// **Empty / disabled cfg** is treated as "skip" rather than
/// "remove" — clearing the trust store would crash every
/// `Required`-mode handshake. Operators disabling client-
/// auth at runtime need a restart.
///
/// **Disk read errors** + **PEM parse failures** keep the
/// previous store live and return [`ClientAuthReloadOutcome::Failed`]
/// so the watcher can emit `zero_trust_reload_failed` for audit.
pub fn apply_cfg_change_to_client_auth(
    new_cfg: &WafConfig,
    trust_store: Option<&ClientTrustStore>,
) -> ClientAuthReloadOutcome {
    let Some(trust_store) = trust_store else {
        return ClientAuthReloadOutcome::NoStore;
    };
    let Some(zt) = new_cfg.zero_trust.as_ref() else {
        return ClientAuthReloadOutcome::SkippedDisabled;
    };
    let Some(ca_cfg) = zt.downstream.as_ref() else {
        return ClientAuthReloadOutcome::SkippedDisabled;
    };
    if ca_cfg.mode == aegis_core::config::DownstreamMtlsMode::Disabled {
        return ClientAuthReloadOutcome::SkippedDisabled;
    }

    let Some(bundle_path) = ca_cfg.ca_bundle.as_ref() else {
        return ClientAuthReloadOutcome::MissingCaBundle;
    };

    match ClientTrustStore::load_from_pem_file(bundle_path) {
        Ok(parsed) => {
            // Move the parsed RootCertStore into the live
            // handle. We can't expose `Arc<RootCertStore>`
            // directly through `swap`, so re-clone the trust
            // anchors into a fresh owned store and swap that.
            let cur = parsed.current();
            let mut owned = rustls::RootCertStore::empty();
            for ta in cur.roots.iter() {
                owned.roots.push(ta.clone());
            }
            let cert_count = owned.len();
            trust_store.swap(owned);
            ClientAuthReloadOutcome::Applied {
                cert_count,
                mode: ca_cfg.mode,
            }
        }
        Err(e) => ClientAuthReloadOutcome::Failed {
            reason: e.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// N1 (2026-06-11) — alert-receiver fold
// ---------------------------------------------------------------------------

/// Outcome of re-deriving the live alert-receiver list from config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiversReloadOutcome {
    /// No shared receiver store wired (single-node / test bundle).
    NoStore,
    /// `cfg.alerting` is `None` — receivers are not config-managed on this
    /// node, so the boot/env-seeded list is left untouched (legacy path).
    NotManaged,
    /// Re-derived `count` receivers from `cfg.alerting.receivers`.
    Applied { count: usize },
}

/// N1 — re-derive the live `slo::AlertReceiver` list from
/// `cfg.alerting.receivers` and swap it into the shared store, so a
/// receiver configured on any node propagates to the whole fleet via the
/// shared config doc (like detectors/rules/tiers). A `None` `cfg.alerting`
/// means "not config-managed" → leave the current list alone (preserves an
/// env/boot-seeded list); `Some` (even empty) is authoritative, so a
/// delete-all propagates.
pub fn apply_cfg_change_to_receivers(
    new_cfg: &WafConfig,
    receiver_writer: Option<
        &Arc<arc_swap::ArcSwap<Vec<aegis_control::slo::AlertReceiver>>>,
    >,
) -> ReceiversReloadOutcome {
    let Some(store) = receiver_writer else {
        return ReceiversReloadOutcome::NoStore;
    };
    let Some(alerting) = new_cfg.alerting.as_ref() else {
        return ReceiversReloadOutcome::NotManaged;
    };
    let receivers: Vec<aegis_control::slo::AlertReceiver> =
        alerting.receivers.iter().map(receiver_from_config).collect();
    let count = receivers.len();
    store.store(Arc::new(receivers));
    ReceiversReloadOutcome::Applied { count }
}

/// Map a config-side [`aegis_core::config::ReceiverConfig`] to the live
/// [`aegis_control::slo::AlertReceiver`]. Explicit field map (not serde) so
/// the two crates' enums stay independent.
pub(crate) fn receiver_from_config(
    rc: &aegis_core::config::ReceiverConfig,
) -> aegis_control::slo::AlertReceiver {
    use aegis_core::config::{AlertSeverityConfig as SC, ReceiverKindConfig as KC};
    use aegis_control::slo::{AlertReceiver, AlertSeverity, ReceiverKind};
    let kind = match &rc.kind {
        KC::AlertmanagerWebhook { url } => ReceiverKind::AlertmanagerWebhook { url: url.clone() },
        KC::Slack { webhook_url } => ReceiverKind::Slack { webhook_url: webhook_url.clone() },
        KC::PagerDuty { routing_key } => ReceiverKind::PagerDuty { routing_key: routing_key.clone() },
        KC::ServiceNow { instance, table } => ReceiverKind::ServiceNow {
            instance: instance.clone(),
            table: table.clone(),
        },
        KC::Jira { base_url, project } => ReceiverKind::Jira {
            base_url: base_url.clone(),
            project: project.clone(),
        },
        KC::VipTalk { bot_token, room_ids } => ReceiverKind::VipTalk {
            bot_token: bot_token.clone(),
            room_ids: room_ids.clone(),
        },
    };
    let severities = rc
        .severities
        .iter()
        .map(|s| match s {
            SC::Page => AlertSeverity::Page,
            SC::Ticket => AlertSeverity::Ticket,
            SC::Info => AlertSeverity::Info,
        })
        .collect();
    AlertReceiver {
        name: rc.name.clone(),
        kind,
        severities,
    }
}

/// Inverse of [`receiver_from_config`] — used by the fold write handlers
/// to serialize the operator's receiver list into the config blob.
pub(crate) fn receiver_to_config(
    r: &aegis_control::slo::AlertReceiver,
) -> aegis_core::config::ReceiverConfig {
    use aegis_core::config::{
        AlertSeverityConfig as SC, ReceiverConfig, ReceiverKindConfig as KC,
    };
    use aegis_control::slo::{AlertSeverity, ReceiverKind};
    let kind = match &r.kind {
        ReceiverKind::AlertmanagerWebhook { url } => KC::AlertmanagerWebhook { url: url.clone() },
        ReceiverKind::Slack { webhook_url } => KC::Slack { webhook_url: webhook_url.clone() },
        ReceiverKind::PagerDuty { routing_key } => KC::PagerDuty { routing_key: routing_key.clone() },
        ReceiverKind::ServiceNow { instance, table } => KC::ServiceNow {
            instance: instance.clone(),
            table: table.clone(),
        },
        ReceiverKind::Jira { base_url, project } => KC::Jira {
            base_url: base_url.clone(),
            project: project.clone(),
        },
        ReceiverKind::VipTalk { bot_token, room_ids } => KC::VipTalk {
            bot_token: bot_token.clone(),
            room_ids: room_ids.clone(),
        },
    };
    let severities = r
        .severities
        .iter()
        .map(|s| match s {
            AlertSeverity::Page => SC::Page,
            AlertSeverity::Ticket => SC::Ticket,
            AlertSeverity::Info => SC::Info,
        })
        .collect();
    ReceiverConfig {
        name: r.name.clone(),
        kind,
        severities,
    }
}

// ---------------------------------------------------------------------------
// SLO-P4 — SLO objective fold
// ---------------------------------------------------------------------------

/// Outcome of re-deriving the SLO objectives from config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SloReloadOutcome {
    /// No engine handle wired (test bundle).
    NoEngine,
    /// `cfg.slo` is `None` — objectives are not config-managed on
    /// this node; the compiled defaults stay live.
    NotManaged,
    /// Swapped `objectives` thresholds into the live engine
    /// (SLI history untouched).
    Applied { objectives: usize },
    /// The section failed [`SloEngine::validate_objectives`]; the
    /// previous objectives stay live. Carries the reason for the
    /// log/audit trail.
    Rejected { reason: String },
}

/// SLO-P4 — re-derive the live SLO objective set (and the
/// telemetry-absent watchdog knob) from `cfg.slo`, mirroring
/// [`apply_cfg_change_to_receivers`]'s managed/not-managed
/// semantics. Invalid sections are REJECTED (previous objectives
/// stay live) rather than partially applied — alerting must never
/// be left half-configured by a bad doc.
pub fn apply_cfg_change_to_slo(
    new_cfg: &WafConfig,
    slo_engine: Option<&Arc<aegis_control::slo::SloEngine>>,
    absent_after_secs: Option<&Arc<std::sync::atomic::AtomicU64>>,
) -> SloReloadOutcome {
    let Some(engine) = slo_engine else {
        return SloReloadOutcome::NoEngine;
    };
    let Some(slo) = new_cfg.slo.as_ref() else {
        return SloReloadOutcome::NotManaged;
    };
    // Watchdog knob: a managed section is authoritative — absent
    // key means "the compiled default", not "keep whatever".
    if let Some(store) = absent_after_secs {
        store.store(
            slo.telemetry_absent_after_secs
                .unwrap_or(aegis_control::slo::DEFAULT_TELEMETRY_ABSENT_AFTER_SECS),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    let objectives: Vec<aegis_control::slo::SloObjective> = if slo.objectives.is_empty() {
        aegis_control::slo::default_objectives()
    } else {
        slo.objectives.iter().map(objective_from_config).collect()
    };
    let count = objectives.len();
    match engine.set_objectives(objectives) {
        Ok(()) => SloReloadOutcome::Applied { objectives: count },
        Err(reason) => {
            tracing::warn!(
                %reason,
                "slo config section rejected — keeping previous objectives",
            );
            SloReloadOutcome::Rejected { reason }
        }
    }
}

/// Boot-time helper: the objective set a fresh engine should be
/// constructed with. Invalid config falls back to the compiled
/// defaults WITH a loud error — boot must not panic on a bad
/// `slo:` section (the alerting engine is report-only,
/// never fail-closed).
pub fn slo_objectives_from_cfg(cfg: &WafConfig) -> Vec<aegis_control::slo::SloObjective> {
    let configured: Vec<aegis_control::slo::SloObjective> = match cfg.slo.as_ref() {
        Some(slo) if !slo.objectives.is_empty() => {
            slo.objectives.iter().map(objective_from_config).collect()
        }
        _ => return aegis_control::slo::default_objectives(),
    };
    match aegis_control::slo::SloEngine::validate_objectives(&configured) {
        Ok(()) => configured,
        Err(reason) => {
            tracing::error!(
                %reason,
                "invalid `slo:` config section at boot — using compiled default objectives",
            );
            aegis_control::slo::default_objectives()
        }
    }
}

/// Map a config-side [`aegis_core::config::SloObjectiveConfig`] to the
/// live [`aegis_control::slo::SloObjective`]. Explicit field map (not
/// serde) so the two crates' types stay independent.
pub(crate) fn objective_from_config(
    oc: &aegis_core::config::SloObjectiveConfig,
) -> aegis_control::slo::SloObjective {
    use aegis_control::slo::{BurnRateWindow, SliKind, SloObjective};
    use aegis_core::config::SliKindConfig as KC;
    SloObjective {
        sli: match oc.sli {
            KC::DataPlaneAvailability => SliKind::DataPlaneAvailability,
        },
        target: oc.target,
        window_days: oc.window_days,
        min_events: oc
            .min_events
            .unwrap_or_else(aegis_control::slo::default_min_events),
        burn_rates: oc
            .burn_rates
            .iter()
            .map(|b| BurnRateWindow {
                window_hours: b.window_hours,
                short_window_minutes: b.short_window_minutes,
                burn_threshold: b.burn_threshold,
                severity: severity_from_config(b.severity),
            })
            .collect(),
    }
}

pub(crate) fn severity_from_config(
    s: aegis_core::config::AlertSeverityConfig,
) -> aegis_control::slo::AlertSeverity {
    use aegis_control::slo::AlertSeverity;
    use aegis_core::config::AlertSeverityConfig as SC;
    match s {
        SC::Page => AlertSeverity::Page,
        SC::Ticket => AlertSeverity::Ticket,
        SC::Info => AlertSeverity::Info,
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use aegis_core::config::ComplianceMode;
    use aegis_security::detectors::{DetectorClass, DetectorMask};

    fn yaml_with_sqli(enabled: bool, modes: &[&str]) -> String {
        let modes_yaml = if modes.is_empty() {
            String::new()
        } else {
            format!("compliance:\n  modes: [{}]\n", modes.join(", "))
        };
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
detectors:
  sqli:
    enabled: {enabled}
{modes_yaml}"#
        )
    }

    fn parse(yaml: &str) -> WafConfig {
        aegis_core::load_config_str(yaml).unwrap()
    }

    // 2026-05-27 (Phase B detectors fold) — config carrying a per-tier
    // override so the watcher re-derive can be exercised.
    fn yaml_with_per_tier() -> String {
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
    enabled: true
  per_tier:
    medium:
      recon: false
"#
        .to_string()
    }

    // 2026-05-27 (Phase B) — config with an explicit `ai.enabled`.
    fn yaml_with_ai(enabled: bool) -> String {
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
ai:
  enabled: {enabled}
"#
        )
    }

    #[test]
    fn ai_reload_no_toggle_handle_is_noop() {
        let cfg = parse(&yaml_with_ai(true));
        assert_eq!(
            apply_cfg_change_to_ai(&cfg, None, None, None),
            AiReloadOutcome::NoToggle,
        );
    }

    #[test]
    fn ai_reload_sets_toggle_and_mask_from_cfg() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let toggle = Arc::new(AtomicBool::new(false));
        let mask = SharedDetectorMask::default();

        // cfg.ai.enabled = true → atomic on + mask Ai bit on.
        let cfg_on = parse(&yaml_with_ai(true));
        assert_eq!(
            apply_cfg_change_to_ai(&cfg_on, Some(&toggle), Some(&mask), None),
            AiReloadOutcome::Applied { enabled: true },
        );
        assert!(toggle.load(Ordering::Relaxed));
        assert!(mask.load().is_enabled(DetectorClass::Ai));

        // cfg.ai.enabled = false → atomic off + mask Ai bit off.
        let cfg_off = parse(&yaml_with_ai(false));
        assert_eq!(
            apply_cfg_change_to_ai(&cfg_off, Some(&toggle), Some(&mask), None),
            AiReloadOutcome::Applied { enabled: false },
        );
        assert!(!toggle.load(Ordering::Relaxed));
        assert!(!mask.load().is_enabled(DetectorClass::Ai));
    }

    #[test]
    fn response_filter_defaults_all_true_when_block_omitted() {
        // Behaviour-preservation: a config with no `response_filter:`
        // block must default every rung ON (matches the runtime default).
        let cfg = parse(&yaml_with_ai(false)); // no response_filter block
        assert!(cfg.response_filter.scrub_stack_traces);
        assert!(cfg.response_filter.mask_internal_ips);
        assert!(cfg.response_filter.redact_dlp);
    }

    #[test]
    fn response_filter_reload_no_writer_is_noop() {
        let cfg = parse(&yaml_with_ai(false));
        assert_eq!(
            apply_cfg_change_to_response_filter(&cfg, None),
            ResponseFilterReloadOutcome::NoWriter,
        );
    }

    #[test]
    fn response_filter_reload_sets_rungs_from_cfg() {
        use aegis_control::api::response_filter::{ResponseFilterPatch, ResponseFilterWriter};
        struct MockRf(std::sync::Mutex<ResponseFilterPatch>);
        impl ResponseFilterWriter for MockRf {
            fn set(&self, p: ResponseFilterPatch) {
                *self.0.lock().unwrap() = p;
            }
            fn get(&self) -> ResponseFilterPatch {
                self.0.lock().unwrap().clone()
            }
        }
        let writer: Arc<dyn ResponseFilterWriter> = Arc::new(MockRf(std::sync::Mutex::new(
            ResponseFilterPatch {
                scrub_stack_traces: true,
                mask_internal_ips: true,
                redact_dlp: true,
            },
        )));
        let yaml = r#"
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
response_filter:
  scrub_stack_traces: false
  redact_dlp: false
"#;
        let cfg = parse(yaml);
        let out = apply_cfg_change_to_response_filter(&cfg, Some(&writer));
        assert_eq!(
            out,
            ResponseFilterReloadOutcome::Applied {
                scrub_stack_traces: false,
                mask_internal_ips: true, // omitted → default true
                redact_dlp: false,
            },
        );
        let got = writer.get();
        assert!(!got.scrub_stack_traces);
        assert!(got.mask_internal_ips);
        assert!(!got.redact_dlp);
    }

    #[test]
    fn tiers_reload_no_store_is_noop() {
        let cfg = parse(&yaml_with_ai(false));
        assert_eq!(
            apply_cfg_change_to_tiers(&cfg, None),
            TiersReloadOutcome::NoStore,
        );
    }

    #[test]
    fn tiers_reload_applies_risk_threshold_and_challenges_from_cfg() {
        let tiers = Arc::new(aegis_control::api::tiers::TierStore::new());
        let yaml = r#"
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
tiers:
  high: { risk_threshold: 55, challenges_enabled: true }
"#;
        let cfg = parse(yaml);
        assert_eq!(
            apply_cfg_change_to_tiers(&cfg, Some(&tiers)),
            TiersReloadOutcome::Applied,
        );
        let high = tiers.get("high").expect("high tier exists");
        assert_eq!(high.risk_threshold, 55);
        assert!(high.challenges_enabled);
    }

    // A3 — the richer per-tier fields (block_threshold + cumulative_*)
    // must converge too, not just risk_threshold / challenges_enabled.
    // Guards the config-plane fold so a `PUT /api/tiers/<name>` that edits
    // them is fleet-wide, not node-local-until-restart.
    #[test]
    fn tiers_reload_applies_block_threshold_and_cumulative_from_cfg() {
        let tiers = Arc::new(aegis_control::api::tiers::TierStore::new());
        let yaml = r#"
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
tiers:
  critical:
    risk_threshold: 40
    block_threshold: 80
    cumulative_challenge_at: 30
    cumulative_block_at: 60
"#;
        let cfg = parse(yaml);
        assert_eq!(
            apply_cfg_change_to_tiers(&cfg, Some(&tiers)),
            TiersReloadOutcome::Applied,
        );
        let critical = tiers.get("critical").expect("critical tier exists");
        assert_eq!(critical.block_threshold, 80, "block_threshold must converge");
        assert_eq!(
            critical.cumulative_challenge_at,
            Some(30),
            "cumulative_challenge_at must converge",
        );
        assert_eq!(
            critical.cumulative_block_at,
            Some(60),
            "cumulative_block_at must converge",
        );
    }

    #[test]
    fn no_mask_returns_no_mask_outcome() {
        let cfg = parse(&yaml_with_sqli(true, &[]));
        let outcome = apply_cfg_change_to_mask(&cfg, None);
        assert_eq!(outcome, ReloadOutcome::NoMask);
    }

    #[test]
    fn applied_when_no_compliance_modes_and_no_violations() {
        let cfg = parse(&yaml_with_sqli(true, &[]));
        let mask = SharedDetectorMask::default();
        let outcome = apply_cfg_change_to_mask(&cfg, Some(&mask));
        assert_eq!(outcome, ReloadOutcome::Applied);
        assert!(mask.load().is_enabled(DetectorClass::Sqli));
    }

    #[test]
    fn rederives_base_from_new_cfg() {
        // Boot mask had sqli ON; new cfg flips it OFF. With no
        // compliance modes, the mask should reflect the new cfg.
        let cfg = parse(&yaml_with_sqli(false, &[]));
        let mask = SharedDetectorMask::default();
        // Pre-seed mask with sqli ON to simulate boot.
        mask.store(DetectorMask::all_enabled());

        let outcome = apply_cfg_change_to_mask(&cfg, Some(&mask));
        assert_eq!(outcome, ReloadOutcome::Applied);
        assert!(!mask.load().is_enabled(DetectorClass::Sqli));
    }

    #[test]
    fn pci_does_not_force_classes_on_while_lock_is_deferred() {
        // 2026-05-10 — compliance lock is deferred. New cfg disables
        // sqli with PCI mode declared; the clamp is a no-op so the
        // mask reload applies sqli=false verbatim.
        let cfg = parse(&yaml_with_sqli(false, &["pci"]));
        assert_eq!(
            cfg.compliance.as_ref().unwrap().modes,
            vec![ComplianceMode::Pci],
        );
        let mask = SharedDetectorMask::default();
        mask.store(DetectorMask::all_enabled());

        let outcome = apply_cfg_change_to_mask(&cfg, Some(&mask));
        assert_eq!(outcome, ReloadOutcome::Applied);
        assert!(
            !mask.load().is_enabled(DetectorClass::Sqli),
            "lock is deferred — sqli stays off as the YAML requested"
        );
    }

    #[test]
    fn clears_live_per_tier_override_absent_from_cfg() {
        // 2026-05-27 (Phase B detectors fold) — contract change. The
        // shared config doc is now the single source of truth for
        // per-tier overrides: a live override NOT present in
        // `cfg.detectors.per_tier` is cleared on reload (it used to be
        // preserved). Operators set per-tier policy through the folded
        // `PUT /api/detectors`, which patches `cfg.detectors.per_tier`
        // + activates, so the watcher re-derive reproduces it.
        use aegis_core::tier::Tier;
        let cfg = parse(&yaml_with_sqli(true, &[])); // no per_tier
        let mask = SharedDetectorMask::default();
        let custom_override = DetectorMask::all_enabled()
            .with(DetectorClass::Recon, false);
        mask.store_state(
            mask.load_state().with_override(Tier::Medium, Some(custom_override)),
        );

        let outcome = apply_cfg_change_to_mask(&cfg, Some(&mask));
        assert_eq!(outcome, ReloadOutcome::Applied);
        assert_eq!(
            mask.load_state().override_for(Tier::Medium),
            None,
            "live override absent from cfg is cleared — cfg is source of truth",
        );
    }

    #[test]
    fn rederives_per_tier_override_from_cfg() {
        // The watcher reproduces an override carried by
        // `cfg.detectors.per_tier` so a folded PUT propagates to every
        // node. Tiers omitted from cfg carry no override.
        use aegis_core::tier::Tier;
        let cfg = parse(&yaml_with_per_tier());
        let mask = SharedDetectorMask::default();

        let outcome = apply_cfg_change_to_mask(&cfg, Some(&mask));
        assert_eq!(outcome, ReloadOutcome::Applied);
        let state = mask.load_state();
        let medium = state.resolve(Some(Tier::Medium));
        assert!(
            !medium.is_enabled(DetectorClass::Recon),
            "cfg per_tier.medium.recon=false re-derived onto the live mask",
        );
        assert!(
            medium.is_enabled(DetectorClass::Sqli),
            "unset per_tier classes inherit the base (sqli stays on)",
        );
        assert!(
            state.override_for(Tier::High).is_none(),
            "tiers omitted from cfg.per_tier carry no override",
        );
    }

    // ---- 2026-05-27 (Phase B rules fold) — apply_cfg_change_to_rules ----

    fn yaml_with_inline_rules() -> String {
        // Real rule DSL (list format) so `rebuild_active_ruleset` parses it.
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
rules:
  inline:
    - id: r1
      body: "- id: r1\n  priority: 100\n  when: true\n  then: allow\n"
      enabled: true
    - id: r2
      body: "- id: r2\n  priority: 90\n  when: true\n  then: log_only\n"
      enabled: false
"#
        .to_string()
    }

    // ---- 2026-05-27 (Phase B upstreams fold) — apply_cfg_change_to_upstreams ----

    #[tokio::test]
    async fn upstreams_reload_no_writer_is_noop() {
        let cfg = parse(&yaml_with_sqli(true, &[]));
        assert_eq!(
            apply_cfg_change_to_upstreams(&cfg, None, None).await,
            UpstreamsReloadOutcome::NoWriter,
        );
    }

    #[tokio::test]
    async fn upstreams_reload_applies_pools_from_cfg() {
        use aegis_core::config::PoolConfig;
        use std::collections::HashMap;
        use std::sync::Mutex;

        struct RecordingWriter(Mutex<HashMap<String, PoolConfig>>);
        impl aegis_control::api::upstreams_config::UpstreamWriter for RecordingWriter {
            fn apply(
                &self,
                new_pools: &HashMap<String, PoolConfig>,
            ) -> Result<(), aegis_control::api::upstreams_config::PoolValidationError> {
                *self.0.lock().unwrap() = new_pools.clone();
                Ok(())
            }
        }

        // `yaml_with_sqli` carries one IP-literal pool (`default` →
        // 127.0.0.1:3000); IP members pass through DNS untouched so the
        // apply re-derive needs no network.
        let cfg = parse(&yaml_with_sqli(true, &[]));
        let recorder = Arc::new(RecordingWriter(Mutex::new(HashMap::new())));
        let writer: Arc<dyn aegis_control::api::upstreams_config::UpstreamWriter> =
            recorder.clone();

        let outcome = apply_cfg_change_to_upstreams(&cfg, Some(&writer), None).await;
        assert_eq!(outcome, UpstreamsReloadOutcome::Applied { pools: 1 });
        let applied = recorder.0.lock().unwrap();
        assert!(applied.contains_key("default"), "cfg.upstreams.default rebuilt");
    }

    #[test]
    fn rules_reload_no_store_is_noop() {
        let cfg = parse(&yaml_with_sqli(true, &[]));
        assert_eq!(
            apply_cfg_change_to_rules(&cfg, None, None),
            RulesReloadOutcome::NoStore,
        );
    }

    #[test]
    fn rules_reload_seeds_store_and_rebuilds_engine() {
        let cfg = parse(&yaml_with_inline_rules());
        let store = Arc::new(aegis_control::api::rules::RuleStore::new());
        let ruleset = Arc::new(aegis_security::RuleSet::new());
        // Pre-seed a stale rule absent from cfg — it must be dropped.
        store.upsert("stale", "- id: stale\n  priority: 1\n  when: true\n  then: allow\n", true);

        let outcome = apply_cfg_change_to_rules(&cfg, Some(&store), Some(&ruleset));
        assert_eq!(
            outcome,
            RulesReloadOutcome::Applied { live_rules: 1, rejected: vec![] },
            "2 rules in store, only the enabled one live in the engine",
        );
        assert_eq!(store.list().len(), 2, "both inline rules in the store");
        assert!(store.get("stale").is_none(), "stale rule dropped — cfg is source of truth");
        assert_eq!(ruleset.len(), 1, "only the enabled rule compiled into the engine");
    }

    #[tokio::test]
    async fn apply_folded_stores_threads_handles_to_helpers() {
        // 2026-05-28 (fold parity) — the orchestration the file/etcd
        // watchers call. Prove it threads through to the helpers: rules
        // seed into the store + engine, and the AI toggle is re-derived
        // from cfg.ai.enabled.
        let cfg = parse(&yaml_with_inline_rules()); // 2 inline rules (1 enabled), no `ai:` block
        let rules = Arc::new(aegis_control::api::rules::RuleStore::new());
        let ruleset = Arc::new(aegis_security::RuleSet::new());
        let ai = Arc::new(std::sync::atomic::AtomicBool::new(true)); // starts true → must flip to false
        let targets = FoldedReloadTargets {
            detector_mask: Some(SharedDetectorMask::default()),
            ai_toggle: Some(ai.clone()),
            rules: Some(rules.clone()),
            active_ruleset: Some(ruleset.clone()),
            ..Default::default()
        };
        apply_folded_stores(&cfg, &targets).await;
        assert_eq!(rules.list().len(), 2, "both inline rules seeded into the store");
        assert_eq!(ruleset.len(), 1, "only the enabled rule compiled");
        assert!(
            !ai.load(std::sync::atomic::Ordering::Relaxed),
            "AI toggle re-derived from cfg.ai.enabled (false here)",
        );
    }

    // ---- 2026-06-18 gate-toggle read-back helpers ----
    // (runtime_gate_toggles_not_durable) — prove a converged config doc
    // re-installs into the live gate runtimes, the read-back side the PUT
    // handlers' publish side depends on for restart durability.

    fn gate_yaml(ddos_enabled: bool, risk_enabled: bool, bots_enabled: bool) -> String {
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
ddos:
  enabled: {ddos_enabled}
  per_ip_limit: 100
  per_ip_window_s: 10
  block_ttl_s: 60
  spike_multiplier: 3.0
  tightened_per_ip_rps: 20
risk:
  thresholds: {{ enabled: {risk_enabled}, challenge_at: 40, block_at: 70, max: 100 }}
  strikes: {{ enabled: true, block_at: 25 }}
  canary_paths: ["/wp-admin", "/.env"]
bots:
  enabled: {bots_enabled}
"#
        )
    }

    #[test]
    fn ddos_readback_reinstalls_runtime_config() {
        use crate::state::in_memory::InMemoryBackend;
        // Runtime installed ENABLED at boot; converged doc says disabled.
        let boot = parse(&gate_yaml(true, true, true));
        let backend: Arc<dyn aegis_core::state::StateBackend> = Arc::new(InMemoryBackend::new());
        let rt = Arc::new(aegis_security::ddos::DdosRuntime::new(
            derive_ddos_runtime_cfg(&boot),
            backend,
        ));
        assert!(rt.config_snapshot().enabled, "precondition: ddos enabled at boot");

        let doc = parse(&gate_yaml(false, true, true));
        assert_eq!(
            apply_cfg_change_to_ddos(&doc, Some(&rt)),
            GateReloadOutcome::Applied,
        );
        assert!(
            !rt.config_snapshot().enabled,
            "ddos runtime re-derived from doc → disabled (the read-back fix)",
        );
    }

    #[test]
    fn ddos_readback_no_handle_is_noop() {
        let doc = parse(&gate_yaml(false, true, true));
        assert_eq!(
            apply_cfg_change_to_ddos(&doc, None),
            GateReloadOutcome::NoHandle,
        );
    }

    #[test]
    fn risk_readback_swaps_thresholds_and_canary() {
        let boot = parse(&gate_yaml(true, true, true));
        let tracker = aegis_security::risk::RiskTracker::new(&boot.risk);
        assert!(tracker.thresholds().enabled, "precondition: thresholds enabled");
        let canary = aegis_security::detectors::canary::CanaryPaths::new(&boot.risk.canary_paths);

        let mut doc = parse(&gate_yaml(true, false, true));
        doc.risk.canary_paths = vec!["/only-this".to_string()];
        assert_eq!(
            apply_cfg_change_to_risk(&doc, Some(&tracker), Some(&canary)),
            GateReloadOutcome::Applied,
        );
        assert!(
            !tracker.thresholds().enabled,
            "thresholds re-derived from doc → disabled",
        );
        assert_eq!(
            canary.raw(),
            vec!["/only-this".to_string()],
            "canary set re-derived from doc",
        );
    }

    #[test]
    fn risk_readback_syncs_trust_per_hour_to_peers() {
        // "sync node" — a converged config doc that changes the cumulative
        // decay rate must hot-apply on every node via the reload helper, not
        // just the node that handled the PUT.
        let boot = parse(&gate_yaml(true, true, true));
        let tracker = aegis_security::risk::RiskTracker::new(&boot.risk);
        assert_eq!(tracker.trust_per_hour(), 30, "boot default per_hour");

        let mut doc = parse(&gate_yaml(true, true, true));
        doc.risk.trust_recovery =
            Some(aegis_core::config::TrustRecoveryConfig { per_hour: 90 });
        assert_eq!(
            apply_cfg_change_to_risk(&doc, Some(&tracker), None),
            GateReloadOutcome::Applied,
        );
        assert_eq!(
            tracker.trust_per_hour(),
            90,
            "decay rate re-derived from the converged doc",
        );
    }

    #[test]
    fn bots_readback_flips_toggle() {
        let doc = parse(&gate_yaml(true, true, false));
        let toggle = Arc::new(std::sync::atomic::AtomicBool::new(true));
        assert_eq!(
            apply_cfg_change_to_bots(&doc, Some(&toggle)),
            GateReloadOutcome::Applied,
        );
        assert!(
            !toggle.load(std::sync::atomic::Ordering::Relaxed),
            "bots toggle re-derived from doc → off",
        );
    }

    // ---- apply_cfg_change_to_routes ----

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

    fn boot_ctx(yaml: &str) -> Arc<ProxyContext> {
        let cfg = parse(yaml);
        Arc::new(
            ProxyContext::build(
                &cfg,
                Arc::new(aegis_security::NoopPipeline),
            )
            .unwrap(),
        )
    }

    #[test]
    fn route_reload_no_ctx_returns_no_ctx_outcome() {
        let cfg = parse(&yaml_with_route("v1", "/api/v1"));
        let outcome = apply_cfg_change_to_routes(&cfg, None);
        assert_eq!(outcome, RouteReloadOutcome::NoCtx);
    }

    #[test]
    fn route_reload_swaps_route_table_atomically() {
        let ctx = boot_ctx(&yaml_with_route("v1", "/api/v1"));
        // Boot snapshot resolves /api/v1 → v1.
        let r = ctx
            .route_table
            .resolve("any", "/api/v1", &http::Method::GET)
            .unwrap();
        assert_eq!(r.route_id, "v1");

        // Hot-reload to a v2 route table.
        let new_cfg = parse(&yaml_with_route("v2", "/api/v2"));
        let outcome = apply_cfg_change_to_routes(&new_cfg, Some(&ctx));
        assert_eq!(outcome, RouteReloadOutcome::Applied);

        // /api/v1 now falls through to catch-all.
        let r = ctx
            .route_table
            .resolve("any", "/api/v1", &http::Method::GET)
            .unwrap();
        assert_eq!(r.route_id, "catch-all");

        // /api/v2 resolves to v2.
        let r = ctx
            .route_table
            .resolve("any", "/api/v2", &http::Method::GET)
            .unwrap();
        assert_eq!(r.route_id, "v2");
    }

    // ---- apply_cfg_change_to_graphql ----

    fn yaml_with_graphql(enabled: bool, max_depth: u32) -> String {
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
graphql:
  enabled: {enabled}
  max_depth: {max_depth}
"#
        )
    }

    #[test]
    fn graphql_reload_no_ctx_returns_no_handle() {
        let cfg = parse(&yaml_with_graphql(true, 10));
        assert_eq!(
            apply_cfg_change_to_graphql(&cfg, None),
            GateReloadOutcome::NoHandle,
        );
    }

    #[test]
    fn graphql_reload_swaps_guard_atomically() {
        use crate::graphql_guard::GraphqlGuardOutcome;
        // A 13-deep query (over the default/cap of 10).
        let deep = serde_json::json!({
            "query": "{ a { b { c { d { e { f { g { h { i { j { k { l { m } } } } } } } } } } } } }"
        })
        .to_string();

        // Boot with the guard OFF — a deep query is skipped (forwarded).
        let ctx = boot_ctx(&yaml_with_graphql(false, 10));
        assert_eq!(
            ctx.graphql_guard
                .load()
                .check(&http::Method::POST, "/graphql", deep.as_bytes()),
            GraphqlGuardOutcome::Skipped,
        );

        // Hot-reload to ON with a depth cap of 10 — now the same query is
        // rejected on the live (un-rebuilt) context, proving the atomic swap.
        let new_cfg = parse(&yaml_with_graphql(true, 10));
        assert_eq!(
            apply_cfg_change_to_graphql(&new_cfg, Some(&ctx)),
            GateReloadOutcome::Applied,
        );
        assert!(matches!(
            ctx.graphql_guard
                .load()
                .check(&http::Method::POST, "/graphql", deep.as_bytes()),
            GraphqlGuardOutcome::Rejected { .. },
        ));
    }

    // ---- apply_cfg_change_to_rate_limit ----

    fn yaml_with_rate_limit(limit: u64, window_secs: u64) -> String {
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

    fn yaml_no_rate_limit() -> String {
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

    #[test]
    fn rate_limit_no_limiter_returns_no_limiter_outcome() {
        let cfg = parse(&yaml_with_rate_limit(500, 60));
        let outcome = apply_cfg_change_to_rate_limit(&cfg, None);
        assert_eq!(outcome, RateLimitReloadOutcome::NoLimiter);
    }

    #[test]
    fn rate_limit_applies_when_changed() {
        let initial = parse(&yaml_with_rate_limit(100, 60));
        let limiter = Arc::new(IpRateLimiter::new(derive_ip_rate_cfg(&initial)));
        assert_eq!(limiter.config().limit, 100);

        let new_cfg = parse(&yaml_with_rate_limit(500, 30));
        let outcome = apply_cfg_change_to_rate_limit(&new_cfg, Some(&limiter));
        assert_eq!(
            outcome,
            RateLimitReloadOutcome::Applied {
                limit: 500,
                window_secs: 30,
            },
        );
        assert_eq!(limiter.config().limit, 500);
        assert_eq!(limiter.config().window.as_secs(), 30);
    }

    #[test]
    fn rate_limit_unchanged_when_cfg_identical() {
        let cfg = parse(&yaml_with_rate_limit(100, 60));
        let limiter = Arc::new(IpRateLimiter::new(derive_ip_rate_cfg(&cfg)));
        let outcome = apply_cfg_change_to_rate_limit(&cfg, Some(&limiter));
        assert_eq!(outcome, RateLimitReloadOutcome::Unchanged);
    }

    #[test]
    fn rate_limit_falls_back_to_default_when_no_global_ip_bucket() {
        // Boot from a YAML with a bucket; reload to a YAML
        // without one → limiter falls back to library default.
        let initial = parse(&yaml_with_rate_limit(100, 60));
        let limiter = Arc::new(IpRateLimiter::new(derive_ip_rate_cfg(&initial)));
        assert_eq!(limiter.config().limit, 100);

        let no_rl = parse(&yaml_no_rate_limit());
        let outcome = apply_cfg_change_to_rate_limit(&no_rl, Some(&limiter));
        assert!(matches!(
            outcome,
            RateLimitReloadOutcome::Applied { .. },
        ));
        // Default IpRateLimitConfig (1000 / 60s).
        assert_eq!(limiter.config(), IpRateLimitConfig::default());
    }

    #[test]
    fn rate_limit_preserves_per_ip_state_across_reload() {
        use std::net::IpAddr;
        let initial = parse(&yaml_with_rate_limit(100, 60));
        let limiter = Arc::new(IpRateLimiter::new(derive_ip_rate_cfg(&initial)));
        // Pre-seed counts.
        let ip: IpAddr = "203.0.113.42".parse().unwrap();
        for _ in 0..50 {
            limiter.consume(ip);
        }
        let tracked_before = limiter.tracked();
        assert_eq!(tracked_before, 1);

        let new_cfg = parse(&yaml_with_rate_limit(500, 60));
        apply_cfg_change_to_rate_limit(&new_cfg, Some(&limiter));
        // Per-IP state intact.
        assert_eq!(limiter.tracked(), tracked_before);
    }

    // ---- rate-limit enable toggle (2026-06-22) ----

    fn yaml_rate_limit_enabled(enabled: bool, limit: u64, window_secs: u64) -> String {
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
  enabled: {enabled}
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

    #[test]
    fn derive_ip_rate_cfg_defaults_enabled_true_when_omitted() {
        // The stock builder omits `rate_limit.enabled` → serde default `true`.
        let cfg = parse(&yaml_with_rate_limit(100, 60));
        assert!(derive_ip_rate_cfg(&cfg).enabled);
    }

    #[test]
    fn derive_ip_rate_cfg_reads_disabled_flag() {
        let cfg = parse(&yaml_rate_limit_enabled(false, 100, 60));
        let derived = derive_ip_rate_cfg(&cfg);
        assert!(!derived.enabled);
        // Disabling does not erase the configured limit/window.
        assert_eq!(derived.limit, 100);
        assert_eq!(derived.window.as_secs(), 60);
    }

    #[test]
    fn rate_limit_reload_applies_enabled_only_flip() {
        // Same limit/window, only `enabled` changes — must still re-apply (the
        // flag is part of the `Eq` identity), not short-circuit to Unchanged.
        let initial = parse(&yaml_rate_limit_enabled(true, 100, 60));
        let limiter = Arc::new(IpRateLimiter::new(derive_ip_rate_cfg(&initial)));
        assert!(limiter.config().enabled);

        let disabled = parse(&yaml_rate_limit_enabled(false, 100, 60));
        let outcome = apply_cfg_change_to_rate_limit(&disabled, Some(&limiter));
        assert!(matches!(outcome, RateLimitReloadOutcome::Applied { .. }));
        assert!(!limiter.config().enabled, "limiter must observe the disable");
    }

    // ---- apply_cfg_change_to_tls ----

    fn write_pem(dir: &tempfile::TempDir, name: &str, content: &str) -> std::path::PathBuf {
        use std::io::Write;
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    fn generate_cert(domains: &[&str]) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(
            domains.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        params.is_ca = rcgen::IsCa::NoCa;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
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

    fn yaml_no_tls() -> String {
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

    fn boot_resolver(
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
        host: &str,
    ) -> Arc<DynamicResolver> {
        use arc_swap::ArcSwap;
        let entries = vec![(cert_path.to_path_buf(), key_path.to_path_buf(), vec![host.to_string()])];
        let entries_ref: Vec<(_, _, &[String])> = entries
            .iter()
            .map(|(c, k, h)| (c.clone(), k.clone(), &h[..]))
            .collect();
        let store = CertStore::load(&entries_ref).unwrap();
        Arc::new(DynamicResolver::new(Arc::new(ArcSwap::from_pointee(store))))
    }

    #[test]
    fn tls_reload_no_resolver_returns_no_resolver_outcome() {
        let cfg = parse(&yaml_no_tls());
        let outcome = apply_cfg_change_to_tls(&cfg, None);
        assert_eq!(outcome, TlsReloadOutcome::NoResolver);
    }

    #[test]
    fn tls_reload_swaps_cert_store_atomically() {
        let dir = tempfile::TempDir::new().unwrap();
        let (cert_a, key_a) = generate_cert(&["a.example.com"]);
        let cert_a_path = write_pem(&dir, "a.crt", &cert_a);
        let key_a_path = write_pem(&dir, "a.key", &key_a);
        let resolver = boot_resolver(&cert_a_path, &key_a_path, "a.example.com");

        // Hot-reload swaps in cert B for a different host.
        let (cert_b, key_b) = generate_cert(&["b.example.com"]);
        let cert_b_path = write_pem(&dir, "b.crt", &cert_b);
        let key_b_path = write_pem(&dir, "b.key", &key_b);
        let new_cfg = parse(&yaml_with_tls_certs(
            cert_b_path.to_str().unwrap(),
            key_b_path.to_str().unwrap(),
            "b.example.com",
        ));

        let outcome = apply_cfg_change_to_tls(&new_cfg, Some(&resolver));
        assert_eq!(outcome, TlsReloadOutcome::Applied { cert_count: 1 });
    }

    #[test]
    fn tls_reload_skips_when_new_cfg_has_no_tls() {
        let dir = tempfile::TempDir::new().unwrap();
        let (cert, key) = generate_cert(&["a.example.com"]);
        let cert_path = write_pem(&dir, "a.crt", &cert);
        let key_path = write_pem(&dir, "a.key", &key);
        let resolver = boot_resolver(&cert_path, &key_path, "a.example.com");

        // New cfg drops `tls:` section entirely.
        let new_cfg = parse(&yaml_no_tls());
        let outcome = apply_cfg_change_to_tls(&new_cfg, Some(&resolver));
        assert_eq!(outcome, TlsReloadOutcome::SkippedEmpty);
    }

    #[test]
    fn tls_reload_fails_on_missing_cert_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let (cert, key) = generate_cert(&["a.example.com"]);
        let cert_path = write_pem(&dir, "a.crt", &cert);
        let key_path = write_pem(&dir, "a.key", &key);
        let resolver = boot_resolver(&cert_path, &key_path, "a.example.com");

        // New cfg points at a path that doesn't exist.
        let new_cfg = parse(&yaml_with_tls_certs(
            "/nonexistent/path/cert.pem",
            "/nonexistent/path/key.pem",
            "a.example.com",
        ));
        let outcome = apply_cfg_change_to_tls(&new_cfg, Some(&resolver));
        match outcome {
            TlsReloadOutcome::Failed { reason } => {
                assert!(!reason.is_empty(), "failure reason should be populated");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn tls_reload_failed_keeps_old_resolver_responsive() {
        let dir = tempfile::TempDir::new().unwrap();
        let (cert, key) = generate_cert(&["original.example.com"]);
        let cert_path = write_pem(&dir, "a.crt", &cert);
        let key_path = write_pem(&dir, "a.key", &key);
        let resolver = boot_resolver(&cert_path, &key_path, "original.example.com");
        let store_handle = resolver.store_handle();
        let original_default = store_handle.load().resolve(None);
        assert!(original_default.is_some(), "boot store has a default cert");

        // Trigger a reload with a bogus path.
        let bad_cfg = parse(&yaml_with_tls_certs(
            "/nonexistent/path/cert.pem",
            "/nonexistent/path/key.pem",
            "x.example.com",
        ));
        let _ = apply_cfg_change_to_tls(&bad_cfg, Some(&resolver));

        // Original cert is still resolvable (live store unchanged).
        let after = store_handle.load().resolve(None);
        assert!(after.is_some(), "old cert store still live after failed reload");
    }

    #[test]
    fn route_reload_keeps_old_table_on_validation_error() {
        let ctx = boot_ctx(&yaml_with_route("v1", "/api/v1"));

        // PR2: "no catch-all" no longer fails — deny-by-default
        // covers it. To exercise the validation-error path use the
        // new invariant: two `default: true` routes in the same
        // host scope is rejected.
        let bad_yaml = r#"
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
"#;
        let bad_cfg = parse(bad_yaml);
        let outcome = apply_cfg_change_to_routes(&bad_cfg, Some(&ctx));
        match outcome {
            RouteReloadOutcome::Failed { reason } => {
                assert!(
                    reason.contains("default") && reason.contains("at most one"),
                    "expected double-default error, got: {reason}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }

        // Old route table unchanged.
        let r = ctx
            .route_table
            .resolve("any", "/api/v1", &http::Method::GET)
            .unwrap();
        assert_eq!(r.route_id, "v1");
    }

    // ---------------- MTLS-T5 — apply_cfg_change_to_client_auth ----------------

    /// Issue a self-signed CA in PEM form. Returns the bytes
    /// + the path it was written to.
    fn write_test_ca(name: &str) -> (Vec<u8>, std::path::PathBuf) {
        use std::io::Write;
        let mut params =
            rcgen::CertificateParams::new(vec![name.into()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem().into_bytes();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{name}.pem"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&pem).unwrap();
        f.sync_all().unwrap();
        // Leak the tempdir so the path stays valid for the test.
        std::mem::forget(dir);
        (pem, path)
    }

    fn yaml_with_client_auth(ca_path: &std::path::Path, mode: &str) -> String {
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
    upstream: pool
upstreams:
  pool:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
tls:
  certificates: []
zero_trust:
  downstream:
    mode: {mode}
    ca_bundle: {ca_path}
    apply_to: [data]
"#,
            ca_path = ca_path.display(),
        )
    }

    #[test]
    fn client_auth_no_store_when_caller_passes_none() {
        let (_pem, path) = write_test_ca("ca-a");
        let cfg = parse(&yaml_with_client_auth(&path, "required"));
        let outcome = apply_cfg_change_to_client_auth(&cfg, None);
        assert_eq!(outcome, ClientAuthReloadOutcome::NoStore);
    }

    #[test]
    fn client_auth_skipped_when_disabled_in_new_cfg() {
        let (pem_a, path_a) = write_test_ca("ca-a");
        let trust = ClientTrustStore::load_from_pem_bytes(&pem_a).unwrap();

        // Build a cfg with client_auth.mode = disabled. The
        // helper must short-circuit; the live store stays.
        let cfg_yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: pool
upstreams:
  pool:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#;
        let cfg = parse(cfg_yaml);
        let outcome = apply_cfg_change_to_client_auth(&cfg, Some(&trust));
        assert_eq!(outcome, ClientAuthReloadOutcome::SkippedDisabled);
        // Live store still has the original CA.
        assert!(trust.current().len() >= 1);
        // Path used as a fixture, no swap performed.
        let _ = path_a;
    }

    #[test]
    fn client_auth_applied_swaps_to_new_ca() {
        // Live trust starts with CA-A.
        let (pem_a, _path_a) = write_test_ca("ca-a-1");
        let trust = ClientTrustStore::load_from_pem_bytes(&pem_a).unwrap();
        let len_before = trust.current().len();

        // New cfg points at CA-B. After reload, the live store
        // is swapped to CA-B's roots.
        let (_pem_b, path_b) = write_test_ca("ca-b-1");
        let cfg = parse(&yaml_with_client_auth(&path_b, "required"));

        let outcome = apply_cfg_change_to_client_auth(&cfg, Some(&trust));
        match outcome {
            ClientAuthReloadOutcome::Applied { cert_count, mode } => {
                assert!(cert_count >= 1);
                assert_eq!(mode, aegis_core::config::DownstreamMtlsMode::Required);
            }
            other => panic!("expected Applied, got {other:?}"),
        }
        // Live store is non-empty after swap.
        assert!(trust.current().len() >= len_before.min(1));
    }

    #[test]
    fn client_auth_failed_keeps_live_store_when_path_does_not_exist() {
        // Live trust starts populated.
        let (pem_a, _path_a) = write_test_ca("ca-a-2");
        let trust = ClientTrustStore::load_from_pem_bytes(&pem_a).unwrap();

        // New cfg points at a non-existent path. Helper must
        // return Failed and the live store must stay populated.
        let bogus = std::path::PathBuf::from("/does-not-exist/ca.pem");
        let cfg = parse(&yaml_with_client_auth(&bogus, "required"));

        let outcome = apply_cfg_change_to_client_auth(&cfg, Some(&trust));
        match outcome {
            ClientAuthReloadOutcome::Failed { reason } => {
                assert!(
                    reason.contains("does-not-exist")
                        || reason.to_lowercase().contains("ca_bundle"),
                    "expected path or label in error: {reason}",
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        // Live store stays — operators don't lose trust on a
        // bad reload.
        assert!(trust.current().len() >= 1);
    }

    // 2026-06-03 (copilot config-plane fold) — minimal config carrying an
    // `observability.copilot` block. Only the `llm`-feature tests below use it.
    #[cfg(feature = "llm")]
    fn yaml_with_copilot(
        enabled: bool,
        key_ref: Option<&str>,
        base_url: Option<&str>,
        model: Option<&str>,
    ) -> String {
        let mut block = format!("\nobservability:\n  copilot:\n    enabled: {enabled}\n");
        if let Some(k) = key_ref {
            block.push_str(&format!("    api_key_ref: \"{k}\"\n"));
        }
        if let Some(b) = base_url {
            block.push_str(&format!("    base_url: \"{b}\"\n"));
        }
        if let Some(m) = model {
            block.push_str(&format!("    model: \"{m}\"\n"));
        }
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
{block}"#
        )
    }

    // The fold is deterministic from config (it ignores `LLM_*` env on the
    // enabled path), so we assert on the returned enabled state — not the
    // process global, which other tests in this binary may also swap.
    #[cfg(feature = "llm")]
    #[tokio::test]
    async fn copilot_fold_enables_from_full_block() {
        let cfg = yaml_with_copilot(true, Some("sk-test"), Some("https://h/v1"), Some("m"));
        let cfg = parse(&cfg);
        assert!(apply_cfg_change_to_copilot(&cfg).await);
    }

    #[cfg(feature = "llm")]
    #[tokio::test]
    async fn copilot_fold_disabled_without_resolved_key() {
        // enabled, but no api_key_ref → no key resolves → disabled.
        let cfg = yaml_with_copilot(true, None, Some("https://h/v1"), Some("m"));
        let cfg = parse(&cfg);
        assert!(!apply_cfg_change_to_copilot(&cfg).await);
    }

    #[cfg(feature = "llm")]
    #[tokio::test]
    async fn copilot_fold_resolves_secret_ref_via_env() {
        // api_key_ref is a ${secret:env:...} reference — the fold resolves
        // it per-node through the secrets resolver.
        std::env::set_var("AEGIS_TEST_COPILOT_KEY", "sk-from-env");
        let cfg = yaml_with_copilot(
            true,
            Some("${secret:env:AEGIS_TEST_COPILOT_KEY}"),
            Some("https://h/v1"),
            Some("m"),
        );
        let cfg = parse(&cfg);
        assert!(apply_cfg_change_to_copilot(&cfg).await);
        std::env::remove_var("AEGIS_TEST_COPILOT_KEY");
    }

    // N1 (2026-06-11) — alert-receiver fold.

    fn yaml_with_alerting() -> String {
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
alerting:
  receivers:
    - name: oncall
      kind:
        VipTalk:
          bot_token: "tok-1234"
          room_ids: ["!room:srv"]
      severities: [Page]
"#
        .to_string()
    }

    #[test]
    fn receivers_reload_no_store_when_writer_absent() {
        let cfg = parse(&yaml_with_alerting());
        assert_eq!(
            apply_cfg_change_to_receivers(&cfg, None),
            ReceiversReloadOutcome::NoStore
        );
    }

    #[test]
    fn receivers_reload_not_managed_leaves_store_untouched() {
        // The per-tier fixture has no `alerting:` block → None → the
        // env/boot-seeded store must be left alone (no wipe on an
        // unrelated config change).
        let cfg = parse(&yaml_with_per_tier());
        let store = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
        assert_eq!(
            apply_cfg_change_to_receivers(&cfg, Some(&store)),
            ReceiversReloadOutcome::NotManaged
        );
    }

    #[test]
    fn receivers_reload_applies_config_managed_list() {
        let cfg = parse(&yaml_with_alerting());
        let store = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
        let out = apply_cfg_change_to_receivers(&cfg, Some(&store));
        assert_eq!(out, ReceiversReloadOutcome::Applied { count: 1 });
        let live = store.load();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].name, "oncall");
        match &live[0].kind {
            aegis_control::slo::ReceiverKind::VipTalk {
                bot_token,
                room_ids,
            } => {
                assert_eq!(bot_token, "tok-1234");
                assert_eq!(room_ids, &vec!["!room:srv".to_string()]);
            }
            other => panic!("wrong kind: {other:?}"),
        }
        assert_eq!(
            live[0].severities,
            vec![aegis_control::slo::AlertSeverity::Page]
        );
    }

    // ---- SLO-P4: slo objective fold ------------------------------------

    fn yaml_with_slo() -> String {
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
slo:
  telemetry_absent_after_secs: 300
  objectives:
    - sli: data_plane_availability
      target: 0.995
      window_days: 30
      min_events: 100
      burn_rates:
        - window_hours: 1
          short_window_minutes: 5
          burn_threshold: 14.4
          severity: Page
"#
        .to_string()
    }

    fn test_engine() -> std::sync::Arc<aegis_control::slo::SloEngine> {
        std::sync::Arc::new(aegis_control::slo::SloEngine::new(
            aegis_control::slo::default_objectives(),
        ))
    }

    #[test]
    fn slo_reload_no_engine_when_handle_absent() {
        let cfg = parse(&yaml_with_slo());
        assert_eq!(
            apply_cfg_change_to_slo(&cfg, None, None),
            SloReloadOutcome::NoEngine
        );
    }

    #[test]
    fn slo_reload_not_managed_leaves_defaults() {
        // No `slo:` block → compiled defaults stay live.
        let cfg = parse(&yaml_with_per_tier());
        let engine = test_engine();
        assert_eq!(
            apply_cfg_change_to_slo(&cfg, Some(&engine), None),
            SloReloadOutcome::NotManaged
        );
        let status = engine.budget_status();
        assert!((status[0].target - 0.999).abs() < 1e-9, "defaults live");
    }

    #[test]
    fn slo_reload_applies_config_objectives_and_watchdog_knob() {
        let cfg = parse(&yaml_with_slo());
        let engine = test_engine();
        let absent = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
            aegis_control::slo::DEFAULT_TELEMETRY_ABSENT_AFTER_SECS,
        ));
        let out = apply_cfg_change_to_slo(&cfg, Some(&engine), Some(&absent));
        assert_eq!(out, SloReloadOutcome::Applied { objectives: 1 });
        let status = engine.budget_status();
        assert!((status[0].target - 0.995).abs() < 1e-9, "config target live");
        assert_eq!(
            absent.load(std::sync::atomic::Ordering::Relaxed),
            300,
            "watchdog knob applied",
        );
    }

    #[test]
    fn slo_reload_rejects_invalid_and_keeps_previous() {
        let mut yaml = yaml_with_slo();
        yaml = yaml.replace("window_days: 30", "window_days: 90");
        let cfg = parse(&yaml);
        let engine = test_engine();
        let out = apply_cfg_change_to_slo(&cfg, Some(&engine), None);
        assert!(
            matches!(out, SloReloadOutcome::Rejected { .. }),
            "got: {out:?}",
        );
        let status = engine.budget_status();
        assert!((status[0].target - 0.999).abs() < 1e-9, "previous set live");
    }

    #[test]
    fn slo_boot_helper_falls_back_to_defaults_on_invalid() {
        // Valid section → configured objectives.
        let cfg = parse(&yaml_with_slo());
        let objs = slo_objectives_from_cfg(&cfg);
        assert!((objs[0].target - 0.995).abs() < 1e-9);
        assert_eq!(objs[0].min_events, 100);

        // Invalid section → compiled defaults, no panic.
        let cfg = parse(&yaml_with_slo().replace("target: 0.995", "target: 1.5"));
        let objs = slo_objectives_from_cfg(&cfg);
        assert!((objs[0].target - 0.999).abs() < 1e-9);

        // No section → compiled defaults.
        let cfg = parse(&yaml_with_per_tier());
        let objs = slo_objectives_from_cfg(&cfg);
        assert!((objs[0].target - 0.999).abs() < 1e-9);
    }

    #[test]
    fn stale_budget_pct_key_fails_config_parse() {
        // The pre-P3 threshold key must be a loud parse error,
        // never a silently-defaulted threshold.
        let yaml = yaml_with_slo().replace(
            "burn_threshold: 14.4",
            "budget_pct: 2.0\n          burn_threshold: 14.4",
        );
        assert!(
            aegis_core::load_config_str(&yaml).is_err(),
            "stale budget_pct must be rejected by deny_unknown_fields",
        );
    }

    #[test]
    fn receiver_config_round_trips_through_slo() {
        let cfg = parse(&yaml_with_alerting());
        let alerting = cfg.alerting.as_ref().expect("alerting present");
        let slo = receiver_from_config(&alerting.receivers[0]);
        let back = receiver_to_config(&slo);
        assert_eq!(back.name, "oncall");
        match back.kind {
            aegis_core::config::ReceiverKindConfig::VipTalk {
                bot_token,
                room_ids,
            } => {
                assert_eq!(bot_token, "tok-1234");
                assert_eq!(room_ids, vec!["!room:srv".to_string()]);
            }
            other => panic!("wrong kind: {other:?}"),
        }
        assert_eq!(
            back.severities,
            vec![aegis_core::config::AlertSeverityConfig::Page]
        );
    }
}
