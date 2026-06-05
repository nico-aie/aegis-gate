use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::tier::Tier;

// ---------------------------------------------------------------------------
// ConfigEvent (broadcast)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum ConfigEvent {
    Reloaded { version: u64 },
    Failed { error: String },
}

pub type ConfigBroadcast = tokio::sync::broadcast::Sender<ConfigEvent>;

// ---------------------------------------------------------------------------
// Config loader
// ---------------------------------------------------------------------------

/// Load configuration from a YAML file with environment variable overlay.
///
/// Layers (lowest → highest priority):
/// 1. YAML file at `path`
/// 2. Environment variables prefixed with `WAF_` (nested via `__`, e.g. `WAF_STATE__BACKEND`)
///
/// After extraction the config is validated via [`WafConfig::validate`].
pub fn load_config(path: &std::path::Path) -> crate::Result<WafConfig> {
    use figment::providers::{Env, Format, Yaml};
    use figment::Figment;

    let cfg: WafConfig = Figment::new()
        .merge(Yaml::file(path))
        .merge(Env::prefixed("WAF_").split("__"))
        .extract()
        .map_err(|e| crate::error::WafError::Config(format!("{e}")))?;

    cfg.validate()?;
    Ok(cfg)
}

/// Load configuration from a YAML string (useful for tests and embedded configs).
pub fn load_config_str(yaml: &str) -> crate::Result<WafConfig> {
    let cfg: WafConfig = serde_yaml::from_str(yaml)
        .map_err(|e| crate::error::WafError::Config(format!("invalid config: {e}")))?;
    cfg.validate()?;
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Top-level WafConfig
// ---------------------------------------------------------------------------

// 2026-05-17 F-CRITICAL-013 (core audit): `#[serde(
// deny_unknown_fields)]` on the top-level config catches typos
// like `routs:` / `upstrems:` / `risk_threshols:` that serde would
// otherwise silently drop. Pre-fix the entire 4024-LoC config
// module had ZERO uses of this attribute — every "ghost feature"
// report by operators traced back to a typo that vanished into
// the void. Applied at the top level here; nested structs can opt
// in over time as we verify they're closed-set.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WafConfig {
    pub listeners: Listeners,
    pub routes: Vec<RouteConfig>,
    pub upstreams: HashMap<String, PoolConfig>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    pub state: StateConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub risk: RiskConfig,
    #[serde(default)]
    pub detectors: DetectorsConfig,
    #[serde(default)]
    pub bots: BotConfig,
    #[serde(default)]
    pub dlp: DlpConfig,
    /// 2026-05-27 — response-body filter rungs (stack-trace scrub /
    /// RFC-1918 mask / DLP redact). Added so the config plane can carry
    /// these toggles (they previously lived only in the runtime
    /// `aegis-security::pipeline::ResponseFilterConfig`). Defaults match
    /// the runtime default (all on) so configs that omit the block are
    /// byte-identical at boot.
    #[serde(default)]
    pub response_filter: ResponseFilterConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub compliance: Option<ComplianceProfile>,
    #[serde(default)]
    pub load_mode: crate::load_mode::LoadModeConfig,
    #[serde(default)]
    pub logging: crate::verbosity::LoggingConfig,
    /// Node identity for cluster mode (HA-T3).
    ///
    /// When set, this is the value the lease layer + admin
    /// observability use for "who am I". When unset, it is derived
    /// from hostname + PID + nanos at boot, which is sufficient for
    /// single-node and short-lived test rigs but unstable across
    /// restarts. For long-running production clusters, set this to
    /// a stable per-pod identifier (k8s `${POD_NAME}`, hostname).
    #[serde(default)]
    pub node: NodeConfig,
    /// Tokio runtime tuning (Layer-1 worker scaling, post-HA).
    /// Surfaces the in-process knobs operators need to size the
    /// gateway against host CPU. Restart-only — tokio runtimes
    /// can't resize once built.
    #[serde(default)]
    pub runtime: RuntimeConfig,
    /// 2026-05-23 — per-tier per-request block scores. Seeds the
    /// `TierStore` `risk_threshold` at boot so operators can pin tier
    /// posture declaratively per profile instead of editing code or
    /// relying on (non-durable) dashboard edits. Any tier omitted
    /// falls back to the code default (`Tier::defaults_for`). The
    /// dashboard `PUT /api/tiers/<name>` still applies live runtime
    /// overrides; a restart re-applies this block.
    #[serde(default)]
    pub tiers: TiersConfig,
    /// CI-T8 — MaxMind GeoIP databases. When set, the
    /// `aegis-security/geoip` reader loads them at boot and the
    /// AttacksHandler enriches `/api/attacks/top` rows with
    /// country + ASN. Both fields are optional (set only the DB
    /// you have); both unset = no enrichment.
    #[serde(default)]
    pub geoip: GeoIpConfig,
    /// External interop surface. Always-on by default — exposes
    /// `/__waf_control/*` (capability discovery, runtime-state
    /// reset, mode toggle, cache flush), the always-on `X-WAF-*`
    /// response headers, and the minimal-schema JSONL audit log.
    /// Set `interop.enabled: false` to disable the surface
    /// entirely (e.g. in test fixtures).
    #[serde(default)]
    pub interop: InteropConfig,
    /// AI-T1 — ML-based detector. Off by default. With
    /// `ai.enabled: true` AND a binary built `--features ai`,
    /// the [`crate::config::AiConfig::model_path`] ONNX is
    /// loaded at boot and `AiDetector` joins the detector
    /// chain. `enabled: true` against a binary built without
    /// the feature is a boot-time error so misconfiguration
    /// is loud, not silent.
    #[serde(default)]
    pub ai: AiConfig,
    /// Data-plane request-handling knobs. Today this only carries
    /// `max_body_bytes` (the global request-body cap, previously a
    /// hard-coded 1 MiB in `data_plane.rs`). Per-route quotas
    /// (`routes[].quota.client_max_body_size`) take precedence when
    /// set; this is the global ceiling that applies to every route.
    /// Default 10 MiB — matches `QuotaConfig::default()`.
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// 2026-05-17 F-CRITICAL-006 — adaptive load shedder. When
    /// enabled, the data plane consults `LoadShedder::should_admit`
    /// after tier classification and returns 503 + `Retry-After: 1`
    /// when the current in-flight count exceeds the adaptive limit.
    /// Critical-tier requests are never shed; Low / Medium / High
    /// shed in that order. The limit auto-tunes via Gradient2 from
    /// the WAF's own inspection latency only (2026-05-22 — upstream
    /// RTT is excluded so a slow backend can't make a healthy WAF
    /// shed). See `crates/aegis-proxy/src/shed.rs` for the algorithm
    /// and `docs/data-plane/adaptive-load-shedding.md` for the
    /// operator guide. Default `enabled: true` so Round-3 resilience
    /// scoring works out of the box.
    #[serde(default)]
    pub load_shedder: LoadShedderConfig,
    /// DDoS protection — per-IP burst detection + EWMA spike
    /// mode + cluster-wide auto-block via the state backend.
    ///
    /// **2026-05-11 CORE-01 fix.** Defaults are now documented
    /// truthfully: `enabled: true, observe_only: false` —
    /// **enforce by default**. The previous doc claimed shadow
    /// mode by default, but `DdosConfig::default()` has always
    /// set `observe_only: false` (the code is the source of
    /// truth). Production posture is to enforce immediately;
    /// operators who want a baking period can set
    /// `observe_only: true` in YAML for the first deploy and
    /// flip it off after metrics confirm the thresholds are
    /// well-calibrated.
    ///
    /// See `docs/security/ddos-protection.md` for the operator
    /// guide and
    /// `plans/issue-fix/internal-audit-2026-05-09-ddos/` for
    /// the original wire-up plan.
    #[serde(default)]
    pub ddos: DdosConfig,
    /// 2026-05-17 F-CRITICAL-010 (core audit): tier-keyed failure
    /// mode override. By default each tier derives its failure
    /// mode from `Tier::default_failure_mode` (Critical →
    /// FailClose, all others → FailOpen). Operators who need to
    /// override that policy globally (without setting
    /// `failure_mode` on every individual route) can wire it here.
    ///
    /// YAML shape:
    /// ```yaml
    /// fail_mode_by_tier:
    ///   high: fail_close      # treat High like Critical
    ///   medium: fail_close
    /// ```
    ///
    /// Per-route `routes[].failure_mode` still wins when set;
    /// this is the tier-level default for routes that don't pin
    /// their own. Schema only — consumer wiring lands in Phase E.
    #[serde(default)]
    pub fail_mode_by_tier: HashMap<Tier, FailureModeConfig>,
}

/// External interop surface configuration. Always-on by default.
#[derive(Clone, Debug, Deserialize)]
pub struct InteropConfig {
    /// Master toggle. Default `true`. Set `false` to disable the
    /// `/__waf_control/*` endpoints, the always-on `X-WAF-*`
    /// response headers, and the minimal-schema audit sink.
    #[serde(default = "default_interop_enabled")]
    pub enabled: bool,
    /// Path the minimal-schema audit log writes to. Default
    /// `./waf_audit.log` (cwd at boot).
    #[serde(default = "default_interop_audit_path")]
    pub audit_path: std::path::PathBuf,
    /// Secret expected on the `X-Benchmark-Secret` header for
    /// every `/__waf_control/*` request. `None` falls back to
    /// the documented default; production deployments SHOULD
    /// override via secret-ref.
    #[serde(default)]
    pub control_secret: Option<String>,
}

impl Default for InteropConfig {
    fn default() -> Self {
        Self {
            enabled: default_interop_enabled(),
            audit_path: default_interop_audit_path(),
            control_secret: None,
        }
    }
}

fn default_interop_enabled() -> bool {
    true
}

fn default_interop_audit_path() -> std::path::PathBuf {
    // ./waf_audit.log — the v2.3 §6 CONTRACT-shape audit sink.
    // Schema: request_id, ts_ms, ip (TCP peer), method, path,
    // action, risk_score, mode (+ optional rule_id, tier).
    //
    // This is the file the OC benchmark harness parses for
    // contract validation. It is intentionally distinct from
    // the OPERATOR audit at `cfg.audit.sinks` (rich AuditEvent
    // schema with XFF-resolved client_ip, ISO 8601 ts, class,
    // tenant_id, fields.*). See deploy/STAGING-BENCHMARK.md
    // §"Audit log files" for the dual-sink rationale.
    std::path::PathBuf::from("./waf_audit.log")
}

/// Node identity for cluster mode. Optional — `id: None` means
/// "derive at boot". See [`crate::cluster::NodeId`] for what
/// the lease layer does with the value.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct NodeConfig {
    /// Stable node ID. Surfaces in `/api/cluster.our_node`,
    /// audit log entries, lease holder strings.
    #[serde(default)]
    pub id: Option<String>,
}

/// MaxMind GeoIP databases (CI-T8). Path-only — the actual
/// readers live in `aegis-security` behind the `geoip` feature.
/// Both fields optional — set only the DB you have; both unset
/// is the same as omitting the `geoip:` block entirely.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct GeoIpConfig {
    /// Path to a MaxMind `GeoLite2-Country.mmdb` (or compatible).
    #[serde(default)]
    pub country_db: Option<PathBuf>,
    /// Path to a MaxMind `GeoLite2-ASN.mmdb` (or compatible).
    #[serde(default)]
    pub asn_db: Option<PathBuf>,
}

/// AI-T1 — ML-based detector configuration. Path-only model
/// reference (the operator builds + ships their own ONNX from
/// their training pipeline). Mirrors [`GeoIpConfig`]: the
/// reader/runtime lives in `aegis-security` behind the `ai`
/// Cargo feature; without the feature, `enabled: true` is a
/// boot-time error so the misconfiguration is loud.
///
/// Default: disabled. The detector joins the chain only when
/// the operator opts in AND the binary carries the feature.
///
/// Simplified 2026-05-04 — AI is treated like any other
/// detector now, with just `enabled` + the model knobs that
/// actually do something. The earlier `mode: observe | enforce`,
/// `tiers:`, `timeout:`, and `explain:` fields were dead in
/// the implementation (only `mode` was logged at boot, the rest
/// were declared but never read) — they're gone.
#[derive(Clone, Debug, Deserialize)]
pub struct AiConfig {
    /// Master toggle. Default `false` — opt-in. With `true`
    /// against a feature-disabled binary, boot fails with a
    /// `WafError::Config` containing the build-feature hint.
    /// Hot-flippable at runtime via `PUT /api/ai/enabled`.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the operator-supplied `.onnx` model artifact.
    /// Required when `enabled: true`; ignored otherwise.
    /// Mirrors `geoip.country_db` (path-only, never embedded
    /// in git). The training pipeline + license belongs to
    /// the operator's ML repo.
    #[serde(default)]
    pub model_path: Option<PathBuf>,
    /// Softmax-confidence threshold above which a non-Normal
    /// class is treated as a verdict. Default `0.85` — high
    /// enough to keep false-positive rate low, low enough to
    /// catch the SQLi/XSS classes the dataset report shows
    /// resolving > 0.95 in practice.
    #[serde(default = "default_ai_confidence_threshold")]
    pub confidence_threshold: f32,
    /// 2026-05-23 — synchronous session pool. `N > 1` loads N independent
    /// ONNX sessions; each request grabs a free one and runs `[1,27]`
    /// directly (no batching, no async bridge), giving ~`N ×` the
    /// single-session throughput while keeping the clean low-tail
    /// synchronous path. The scaling lever for a fast CPU model when one
    /// session can't keep up with the AI-invocation rate. Each pooled
    /// session is capped to 1 intra-op thread (parallelism from the pool,
    /// not per-session threads). Default 1 (single session). Ignored when
    /// `batch_enabled` is set.
    #[serde(default = "default_ai_sessions")]
    pub sessions: usize,
    /// 2026-05-23 — in-process dynamic batching. When `true`, inference
    /// runs through a batch accumulator (Triton-style): requests within
    /// a `delay_ms` window share one `[N, 27]` ONNX pass across `workers`
    /// parallel sessions, instead of the per-request `[1, 27]` path that
    /// serialises behind a single session. Big throughput win at high
    /// RPS only when inference is the bottleneck (slow/large model). For
    /// a fast model prefer `sessions` (a synchronous pool) — batching's
    /// coordination overhead can hurt at high request rates. Requires the
    /// `ai` build feature + `model_path`. Falls back to single-inference
    /// `AiDetector` when `false`.
    #[serde(default)]
    pub batch_enabled: bool,
    /// Number of parallel ONNX sessions (= inference workers) for batch
    /// mode. Each owns one session; keep ≤ physical cores. Default = CPU
    /// count clamped to [1, 8].
    #[serde(default = "default_ai_workers")]
    pub workers: usize,
    /// Max requests accumulated before a batch is forced. Larger = better
    /// throughput, higher worst-case latency. Default 32.
    #[serde(default = "default_ai_max_batch")]
    pub max_batch: usize,
    /// Max time (ms) the collector waits to fill a batch before flushing.
    /// Lower = lower latency; higher = bigger batches at low RPS.
    /// Default 2.
    #[serde(default = "default_ai_delay_ms")]
    pub delay_ms: u64,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model_path: None,
            confidence_threshold: default_ai_confidence_threshold(),
            sessions: default_ai_sessions(),
            batch_enabled: false,
            workers: default_ai_workers(),
            max_batch: default_ai_max_batch(),
            delay_ms: default_ai_delay_ms(),
        }
    }
}

fn default_ai_confidence_threshold() -> f32 {
    0.85
}

fn default_ai_sessions() -> usize {
    1
}

fn default_ai_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 8)
}

fn default_ai_max_batch() -> usize {
    32
}

fn default_ai_delay_ms() -> u64 {
    2
}

/// Data-plane request-handling knobs.
///
/// 2026-05-17 F-CRITICAL-004: surfaces `max_body_bytes` (previously a
/// hard-coded 1 MiB const in `data_plane.rs`) so operators can admit
/// legitimate large payloads (file upload routes, multipart batches,
/// PDF/CSV ingest) without an inline rebuild. The per-route knob
/// `routes[].quota.client_max_body_size` (in `QuotaConfig`) takes
/// precedence when populated; this field is the global ceiling.
#[derive(Clone, Debug, Deserialize)]
pub struct ProxyConfig {
    /// Maximum request body size buffered for detector inspection.
    /// Requests above this cap return 413. Default 10 MiB — matches
    /// `QuotaConfig::default().client_max_body_size`. Increase for
    /// upload-heavy workloads; decrease to tighten the DoS surface.
    /// **Beware**: detectors buffer up to this size before running,
    /// so a high cap costs more memory per concurrent request.
    #[serde(default = "default_proxy_max_body_bytes")]
    pub max_body_bytes: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self { max_body_bytes: default_proxy_max_body_bytes() }
    }
}

fn default_proxy_max_body_bytes() -> u64 {
    10 * 1024 * 1024 // 10 MiB — matches QuotaConfig::default()
}

/// Adaptive load-shedder knobs. See
/// `crates/aegis-proxy/src/shed.rs` for the algorithm.
#[derive(Clone, Debug, Deserialize)]
pub struct LoadShedderConfig {
    /// Master toggle. Default `true` so Round-3 resilience scoring
    /// engages without explicit opt-in.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Initial concurrency limit before Gradient2 adapts.
    /// Operator-tunable based on host capacity — default 1000 is
    /// fine for most workloads; lower it on memory-constrained
    /// hosts.
    #[serde(default = "default_shed_initial_limit")]
    pub initial_limit: u64,
    /// Floor the adaptive limit cannot go below. Protects against
    /// pathological RTT spikes shedding all traffic.
    #[serde(default = "default_shed_min_limit")]
    pub min_limit: u64,
}

impl Default for LoadShedderConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            initial_limit: default_shed_initial_limit(),
            min_limit: default_shed_min_limit(),
        }
    }
}

fn default_shed_initial_limit() -> u64 {
    1000
}
fn default_shed_min_limit() -> u64 {
    100
}

/// In-process runtime sizing — Layer-1 of the three-layer scaling
/// model (Layer-2 is the HA cluster, Layer-3 is Redis state).
///
/// Maps onto `tokio::runtime::Builder` knobs at boot. Restart-only:
/// tokio runtimes can't resize once built. Hot-reload requests
/// against these fields are rejected by the admin surface.
#[derive(Clone, Debug, Deserialize)]
pub struct RuntimeConfig {
    /// Async worker threads. `Workers::Auto` (the default) resolves
    /// to `num_cpus::get()` at boot. An explicit count must be
    /// `>= 2` to leave headroom for the cluster heartbeat + roster
    /// poller (validation enforces this).
    #[serde(default)]
    pub workers: Workers,
    /// Blocking-thread pool size. Tokio default is 512; lower it
    /// on memory-constrained hosts.
    #[serde(default = "default_blocking_threads")]
    pub blocking_threads: usize,
    /// Pin worker threads to distinct CPU cores when feasible.
    /// Requires the `affinity` Cargo feature on `aegis-bin`; on
    /// hosts/OSes without support, the request is logged and
    /// ignored (no failure).
    #[serde(default)]
    pub cpu_affinity: bool,
    /// Per-thread stack size in KiB. Tokio default is 2 MiB.
    /// Most workloads never touch this; deep recursive evaluators
    /// or large stack-allocated buffers may need it.
    #[serde(default = "default_stack_size_kb")]
    pub stack_size_kb: usize,
}

/// `runtime.workers` — auto-detect or fixed.
#[derive(Clone, Debug, Default)]
pub enum Workers {
    /// `num_cpus::get()` resolved at boot.
    #[default]
    Auto,
    /// Explicit thread count. Must be `>= 2` (validated at boot).
    Fixed(usize),
}

impl Workers {
    /// Resolve to a concrete worker count. `Auto` calls
    /// `num_cpus::get()`, which is at minimum 1 — we lift it to 2
    /// so the heartbeat and roster pollers have a thread of
    /// headroom on tiny VMs.
    pub fn resolve(&self) -> usize {
        match self {
            Workers::Auto => std::cmp::max(num_cpus::get(), 2),
            Workers::Fixed(n) => *n,
        }
    }
}

impl<'de> serde::Deserialize<'de> for Workers {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Accept either `"auto"` (string) or a positive integer.
        // `serde_yaml::Value` lets us branch without two passes.
        use serde::de::Error;
        let v = serde_yaml::Value::deserialize(deserializer)?;
        match v {
            serde_yaml::Value::String(s) if s.eq_ignore_ascii_case("auto") => {
                Ok(Workers::Auto)
            }
            serde_yaml::Value::Number(n) => {
                let raw = n
                    .as_u64()
                    .ok_or_else(|| D::Error::custom("workers must be a positive integer"))?;
                if raw == 0 {
                    return Err(D::Error::custom("workers must be >= 1"));
                }
                Ok(Workers::Fixed(raw as usize))
            }
            other => Err(D::Error::custom(format!(
                "expected \"auto\" or a positive integer, got {other:?}"
            ))),
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            workers: Workers::default(),
            blocking_threads: default_blocking_threads(),
            cpu_affinity: false,
            stack_size_kb: default_stack_size_kb(),
        }
    }
}

fn default_blocking_threads() -> usize {
    512
}

/// 2026-05-23 — per-tier seeds from the `tiers:` config block. Each
/// canonical tier is optional; omitted tiers use the code default from
/// `Tier::defaults_for`. The per-request block score (`risk_threshold`)
/// and the cumulative-challenge toggle (`challenges_enabled`, added
/// 2026-05-25) are settable here; per-tier cumulative threshold overrides
/// stay on the dashboard `PUT /api/tiers/<name>` surface.
///
/// ```yaml
/// tiers:
///   critical: { risk_threshold: 50, challenges_enabled: true }
///   high:     { risk_threshold: 60, challenges_enabled: true }
///   medium:   { risk_threshold: 70, challenges_enabled: true }
///   low:      { risk_threshold: 80, challenges_enabled: true }
/// ```
#[derive(Clone, Debug, Default, Deserialize)]
pub struct TiersConfig {
    #[serde(default)]
    pub critical: Option<TierThresholdConfig>,
    #[serde(default)]
    pub high: Option<TierThresholdConfig>,
    #[serde(default)]
    pub medium: Option<TierThresholdConfig>,
    #[serde(default)]
    pub low: Option<TierThresholdConfig>,
}

/// One tier's configurable seeds.
///
/// 2026-05-27 — extended with the richer per-tier fields the dashboard
/// `PUT /api/tiers/<name>` sets (`block_threshold`, `cumulative_*`,
/// `pipeline`) so the config plane can carry the full per-tier state and
/// fold that handler. All the new fields are optional — omitted → the
/// `TierStore` keeps its code default / current value. (No longer `Copy`:
/// `pipeline` is a `Vec`.)
#[derive(Clone, Debug, Deserialize)]
pub struct TierThresholdConfig {
    /// Per-request block score (0–100). A request blocks when its
    /// summed detector score reaches this value on the matched tier.
    pub risk_threshold: u32,
    /// Cumulative-IP-risk hard-block score for this tier. `None` →
    /// inherit the global `risk.thresholds.block_at`.
    #[serde(default)]
    pub block_threshold: Option<u32>,
    /// Per-tier cumulative challenge-band start. `None` → inherit global.
    #[serde(default)]
    pub cumulative_challenge_at: Option<u32>,
    /// Per-tier cumulative block point. `None` → inherit global.
    #[serde(default)]
    pub cumulative_block_at: Option<u32>,
    /// Descriptive detector-pipeline names for this tier. `None` → keep
    /// the code default (`Tier::defaults_for`).
    #[serde(default)]
    pub pipeline: Option<Vec<String>>,
    /// 2026-05-25 — opt-in cumulative-IP-risk challenge rung for this
    /// tier. `Some(true)` makes a cumulative score in the challenge band
    /// (`challenge_at..block_at`) issue a 429 PoW challenge; absent or
    /// `Some(false)` leaves the band passing through as allow (only
    /// `block_at` blocks). Seeded into the TierStore at boot; the
    /// dashboard `PUT /api/tiers/<name>` can still override it live.
    #[serde(default)]
    pub challenges_enabled: Option<bool>,
}

impl TiersConfig {
    /// Flatten to `(tier_name, risk_threshold)` pairs for the
    /// configured tiers only. Drives `TierStore` seeding at boot.
    pub fn risk_threshold_overrides(&self) -> Vec<(&'static str, u32)> {
        let mut out = Vec::new();
        if let Some(t) = &self.critical {
            out.push(("critical", t.risk_threshold));
        }
        if let Some(t) = &self.high {
            out.push(("high", t.risk_threshold));
        }
        if let Some(t) = &self.medium {
            out.push(("medium", t.risk_threshold));
        }
        if let Some(t) = &self.low {
            out.push(("low", t.risk_threshold));
        }
        out
    }

    /// 2026-05-25 — flatten to `(tier_name, challenges_enabled)` for the
    /// tiers that set the toggle explicitly. Drives `TierStore`
    /// challenge-rung seeding at boot. Tiers that omit `challenges_enabled`
    /// are not returned (they keep the store default, `false`).
    pub fn challenges_enabled_overrides(&self) -> Vec<(&'static str, bool)> {
        let mut out = Vec::new();
        for (name, tier) in [
            ("critical", &self.critical),
            ("high", &self.high),
            ("medium", &self.medium),
            ("low", &self.low),
        ] {
            if let Some(t) = tier {
                if let Some(enabled) = t.challenges_enabled {
                    out.push((name, enabled));
                }
            }
        }
        out
    }

    /// Reject out-of-range scores (the gate compares against a value
    /// capped at 100, so anything above that can never block).
    pub fn validate(&self) -> crate::Result<()> {
        for (name, rt) in self.risk_threshold_overrides() {
            if rt > 100 {
                return Err(crate::error::WafError::Config(format!(
                    "tiers.{name}.risk_threshold must be <= 100 (got {rt})"
                )));
            }
        }
        Ok(())
    }
}

fn default_stack_size_kb() -> usize {
    2048
}

impl WafConfig {
    /// Validate semantic invariants that serde alone cannot enforce.
    pub fn validate(&self) -> crate::Result<()> {
        if self.listeners.data.is_empty() {
            return Err(crate::error::WafError::Config(
                "listeners.data must contain at least one entry".into(),
            ));
        }
        if self.routes.is_empty() {
            return Err(crate::error::WafError::Config(
                "routes must contain at least one route".into(),
            ));
        }
        if self.upstreams.is_empty() {
            return Err(crate::error::WafError::Config(
                "upstreams must contain at least one pool".into(),
            ));
        }
        // Every route must reference a declared upstream.
        for route in &self.routes {
            if !self.upstreams.contains_key(&route.upstream) {
                return Err(crate::error::WafError::Config(format!(
                    "route '{}' references unknown upstream '{}'",
                    route.id, route.upstream,
                )));
            }
        }
        // 2026-05-11 PROXY-02 — reject `match_type: regex|glob` at
        // lint time. The resolver only supports prefix lookup via
        // `PathTrie::find_all_prefixes` today; regex / glob routes
        // get inserted into the trie as literal strings and never
        // match real traffic. Pre-fix this was a silent
        // mis-configuration trap (verified 2026-05-11 against
        // `aegis-proxy/src/route/mod.rs::resolve_inner`). Loud-fail
        // at boot instead of letting operators ship routes that
        // never fire. When regex / glob lands, drop this guard.
        for route in &self.routes {
            match route.match_type {
                MatchType::Exact | MatchType::Prefix => {}
                MatchType::Regex => {
                    return Err(crate::error::WafError::Config(format!(
                        "route '{}' uses match_type: regex which is not implemented. \
                         The resolver only supports prefix matching today; regex routes \
                         would never fire. Switch to match_type: prefix or split into \
                         multiple exact / prefix routes.",
                        route.id,
                    )));
                }
                MatchType::Glob => {
                    return Err(crate::error::WafError::Config(format!(
                        "route '{}' uses match_type: glob which is not implemented. \
                         The resolver only supports prefix matching today; glob routes \
                         would never fire. Switch to match_type: prefix or split into \
                         multiple exact / prefix routes.",
                        route.id,
                    )));
                }
            }
        }
        // TCP-T1 — every route resolving to a `scheme: tcp` pool
        // must carry a non-empty `tcp_destination_allowlist`, and
        // every entry must parse cleanly. Validation here
        // (rather than at first request) gives operators a fast
        // failure at boot rather than a 500 on first CONNECT.
        for route in &self.routes {
            let pool = self.upstreams.get(&route.upstream).expect("checked above");
            if pool.connection.scheme != UpstreamScheme::Tcp {
                continue;
            }
            if route.tcp_destination_allowlist.is_empty() {
                return Err(crate::error::WafError::Config(format!(
                    "route '{}' targets tcp pool '{}' but has empty tcp_destination_allowlist — \
                     CONNECT tunnels would be rejected on every request. \
                     Add at least one '<cidr>:<port-spec>' entry.",
                    route.id, route.upstream,
                )));
            }
            for entry in &route.tcp_destination_allowlist {
                if let Err(e) = crate::tcp_destination::parse_rule(entry) {
                    return Err(crate::error::WafError::Config(format!(
                        "route '{}': {}",
                        route.id, e,
                    )));
                }
            }
        }
        // Every pool must have at least one member.
        for (name, pool) in &self.upstreams {
            if pool.members.is_empty() {
                return Err(crate::error::WafError::Config(format!(
                    "upstream '{}' must have at least one member",
                    name,
                )));
            }
        }
        // P4 TLS hardening: validate min_version + redirect status.
        if let Some(tls) = self.tls.as_ref() {
            validate_tls_hardening(tls)?;
        }
        // 2026-05-19 committee bind contract: `/__waf_control/*`
        // MUST be local-only on the team's server. The control
        // surface is now peer-IP-gated to loopback at both mounts
        // (admin_dispatch + data-plane accept short-circuit), so a
        // non-loopback admin bind is safe — the surface is invisible
        // to anyone outside the host. But a loopback bind is still
        // the documented committee shape, so emit a one-line boot
        // notice on stderr when interop is enabled AND the admin
        // listener is not loopback. Operators see the reminder;
        // deploys do not hard-fail (which would break the dev
        // Prometheus / docker scrape path that pins 0.0.0.0:9443).
        if self.interop.enabled && !self.listeners.admin.bind.ip().is_loopback() {
            eprintln!(
                "aegis: NOTICE interop enabled but admin bind {} is non-loopback. \
                 /__waf_control/* is peer-IP-gated to loopback regardless; \
                 committee deploys SHOULD bind admin to 127.0.0.1:<port> \
                 (see config/profiles/prod-balanced.yaml).",
                self.listeners.admin.bind
            );
        }
        if let Some(redirect) = self.listeners.force_https.as_ref() {
            if redirect.status != 301 && redirect.status != 308 {
                return Err(crate::error::WafError::Config(format!(
                    "listeners.force_https.status must be 301 or 308, got {}",
                    redirect.status,
                )));
            }
        }
        // P7: load_mode thresholds + hysteresis must be coherent.
        self.load_mode.validate()?;
        // Layer-1: runtime sizing constraints (workers >= 2, sane
        // blocking-pool size, sane stack).
        self.runtime.validate()?;
        // 2026-05-23 — per-tier block-score bounds (<= 100).
        self.tiers.validate()?;
        // 2026-05-11 CORE-09 / CTL-08 — reject not-implemented
        // state-backend + reconcile-mode values at lint time
        // instead of letting them pass `validate()` and then
        // crash at boot in `aegis-bin/state_select.rs`. Tools
        // that run `load_config_str()` + `validate()` as a lint
        // step now catch these gaps.
        if matches!(self.state.backend, StateBackendKind::Raft) {
            return Err(crate::error::WafError::Config(
                "state.backend = raft is not implemented (Phase B candidate). \
                 Use `in_memory` or `redis`."
                    .into(),
            ));
        }
        if self.state.backend == StateBackendKind::Redis
            && self.state.redis.as_ref().is_some_and(|r| r.cluster)
        {
            return Err(crate::error::WafError::Config(
                "state.redis.cluster = true requires the redis_cluster backend, \
                 which is not yet implemented (Phase B candidate). \
                 Set `state.redis.cluster: false` or switch to single-node Redis."
                    .into(),
            ));
        }
        match self.state.reconcile.mode {
            ReconcileMode::Max => {}
            ReconcileMode::Latest => {
                return Err(crate::error::WafError::Config(
                    "state.reconcile.mode = latest is not implemented; \
                     use `max` until a Phase B follow-up lands the latest-wins merge."
                        .into(),
                ));
            }
            ReconcileMode::FailSafe => {
                return Err(crate::error::WafError::Config(
                    "state.reconcile.mode = fail_safe is not implemented; \
                     use `max` until a Phase B follow-up lands the fail-safe merge."
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

impl RuntimeConfig {
    /// Reject configs that would starve the runtime.
    pub fn validate(&self) -> crate::Result<()> {
        if let Workers::Fixed(n) = &self.workers {
            if *n < 2 {
                return Err(crate::error::WafError::Config(format!(
                    "runtime.workers must be >= 2 (got {n}); the cluster heartbeat \
                     + roster pollers reserve a thread of headroom",
                )));
            }
            if *n > 512 {
                return Err(crate::error::WafError::Config(format!(
                    "runtime.workers must be <= 512 (got {n}); higher values \
                     waste memory without measurable throughput gain",
                )));
            }
        }
        if self.blocking_threads == 0 {
            return Err(crate::error::WafError::Config(
                "runtime.blocking_threads must be > 0".into(),
            ));
        }
        if self.blocking_threads > 4096 {
            return Err(crate::error::WafError::Config(format!(
                "runtime.blocking_threads must be <= 4096 (got {})",
                self.blocking_threads,
            )));
        }
        if self.stack_size_kb < 64 {
            return Err(crate::error::WafError::Config(format!(
                "runtime.stack_size_kb must be >= 64 (got {})",
                self.stack_size_kb,
            )));
        }
        Ok(())
    }
}

fn validate_tls_hardening(tls: &TlsConfig) -> crate::Result<()> {
    if let Some(v) = tls.min_version.as_ref() {
        if v != "1.2" && v != "1.3" {
            return Err(crate::error::WafError::Config(format!(
                "tls.min_version must be \"1.2\" or \"1.3\", got {v:?}"
            )));
        }
    }
    if let Some(acme) = tls.acme.as_ref() {
        if !acme.directory_url.starts_with("https://") {
            return Err(crate::error::WafError::Config(
                "tls.acme.directory_url must use https://".into(),
            ));
        }
        if acme.contacts.is_empty() {
            return Err(crate::error::WafError::Config(
                "tls.acme.contacts must contain at least one email".into(),
            ));
        }
        if acme.domains.is_empty() {
            return Err(crate::error::WafError::Config(
                "tls.acme.domains must contain at least one host".into(),
            ));
        }
        if acme.renew_before < Duration::from_secs(24 * 3600) {
            return Err(crate::error::WafError::Config(
                "tls.acme.renew_before must be >= 1 day".into(),
            ));
        }
        if !acme.terms_of_service_agreed {
            return Err(crate::error::WafError::Config(
                "tls.acme.terms_of_service_agreed must be true to register an account".into(),
            ));
        }
    }
    if let Some(hsts) = tls.hsts.as_ref() {
        if hsts.max_age == 0 {
            return Err(crate::error::WafError::Config(
                "tls.hsts.max_age must be > 0 (RFC 6797 §6.1.1)".into(),
            ));
        }
        // Preload list submission requirements (hstspreload.org).
        if hsts.preload {
            if hsts.max_age < 31_536_000 {
                return Err(crate::error::WafError::Config(
                    "tls.hsts.preload requires max_age >= 31536000 (1 year)".into(),
                ));
            }
            if !hsts.include_subdomains {
                return Err(crate::error::WafError::Config(
                    "tls.hsts.preload requires include_subdomains: true".into(),
                ));
            }
        }
    }
    if let Some(ca) = tls.client_auth.as_ref() {
        // Disabled mode is a no-op so we don't require a
        // ca_bundle — operators can stage a future enable by
        // populating fields with mode: disabled.
        if ca.mode != ClientAuthMode::Disabled {
            if ca.ca_bundle.is_none() {
                return Err(crate::error::WafError::Config(format!(
                    "tls.client_auth.ca_bundle is required when mode is {:?} \
                     (cannot verify client certs without a trust anchor)",
                    ca.mode,
                )));
            }
            if ca.apply_to.is_empty() {
                return Err(crate::error::WafError::Config(
                    "tls.client_auth.apply_to must list at least one listener \
                     plane (admin / data) when mode is non-disabled — \
                     otherwise no listener would enforce the policy"
                        .into(),
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Listeners
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct Listeners {
    pub data: Vec<ListenerConfig>,
    pub admin: ListenerConfig,
    /// Optional plain-HTTP listener whose only job is to
    /// 301-redirect every request to the HTTPS equivalent. Pair
    /// with `tls.force_https = true` (see [`TlsConfig`]).
    #[serde(default)]
    pub force_https: Option<ForceHttpsListener>,
}

/// Listener that returns 301 to `https://{host}{path}` for every
/// request. Bind to `:80` in production deployments where you
/// already terminate TLS in the WAF on `:443`.
#[derive(Clone, Debug, Deserialize)]
pub struct ForceHttpsListener {
    pub bind: SocketAddr,
    /// Status code to return. Defaults to `301 Moved Permanently`.
    /// Use `308` if downstream caches need preserved methods.
    #[serde(default = "default_redirect_status")]
    pub status: u16,
}

fn default_redirect_status() -> u16 {
    301
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListenerConfig {
    pub bind: SocketAddr,
    #[serde(default)]
    pub tls: bool,
}

// ---------------------------------------------------------------------------
// Route
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct RouteConfig {
    pub id: String,
    #[serde(default)]
    pub host: Option<String>,
    pub path: String,
    #[serde(default = "default_match_type")]
    pub match_type: MatchType,
    /// 2026-05-12 — when `true` (the default) the route's `path`
    /// prefix is removed from the request URI before the upstream
    /// sees it. Example: route `path: "/news"` + request
    /// `/news/article.html` → upstream gets `/article.html`. This
    /// is the common "mount point" semantics most reverse proxies
    /// adopt (nginx `proxy_pass` with trailing slash, traefik's
    /// `StripPrefix`, envoy's `prefix_rewrite`).
    ///
    /// Set to `false` for path-preserving forwarding (the legacy
    /// behaviour) when the upstream expects to see the full path
    /// (e.g. API gateways behind an `/api/` mount).
    ///
    /// Only applies to `match_type: prefix` and `match_type: exact`.
    /// For `regex` / `glob` matches the field is ignored (there's
    /// no single literal prefix to strip).  Also a no-op for the
    /// catch-all `path: "/"` route — stripping a single slash
    /// would leave the request without a path at all.
    #[serde(default = "default_strip_prefix")]
    pub strip_prefix: bool,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    pub upstream: String,
    #[serde(default)]
    pub tier_override: Option<Tier>,
    #[serde(default)]
    pub failure_mode: Option<FailureModeConfig>,
    #[serde(default)]
    pub quota: Option<QuotaConfig>,
    /// MTLS-T4 — required client-identity kinds. Empty (default)
    /// means "any identity admitted" — including `Anonymous`,
    /// preserving the current open-route behaviour.
    /// Non-empty acts as an allow-list against
    /// [`crate::ClientIdentity::kind()`]:
    /// - `["mtls"]` — only mTLS-authenticated clients.
    /// - `["spiffe"]` — only SPIFFE-id clients.
    /// - `["mtls", "spiffe"]` — either authenticated kind.
    /// - Including `"anonymous"` is equivalent to leaving the
    ///   list empty; validation flags it as a likely typo.
    ///
    ///   Mismatches return 403 with an audit reason; the contract
    ///   `action` is `block`, `rule_id = mtls_required`.
    #[serde(default)]
    pub auth_required: Vec<String>,
    /// TCP-T1 — destination allowlist for CONNECT-method tunnels.
    /// Only consulted when this route's pool has
    /// `scheme: tcp`. Empty (default) = closed: every CONNECT
    /// attempt is rejected. Each entry parses as
    /// `<cidr>:<port-spec>` (see
    /// [`crate::tcp_destination::parse_rule`]). Hardcoded reject
    /// of loopback / link-local / unspecified address space —
    /// bypass via `AEGIS_TCP_TUNNEL_ALLOW_INTERNAL=1`.
    #[serde(default)]
    pub tcp_destination_allowlist: Vec<String>,
    /// TCP-T2 — per-source-IP cap on concurrent open tunnels.
    /// 0 = use the boot default (16). Tunnels are heavy (one
    /// socket each direction + a copy task); a misbehaving
    /// client otherwise drains FDs.
    #[serde(default)]
    pub max_concurrent_tunnels_per_ip: u32,
    /// PR2 — marks this route as the **default fallback** for its
    /// host scope. Exactly one default route is allowed per host
    /// scope. Auto-migration on boot tags any `path: "/"` no-host
    /// route as `default: true` if no explicit default exists yet
    /// (idempotent — only fills the gap). When no default exists
    /// at all, unmatched requests get a 404 through the security
    /// pipeline (PR3 — deny-by-default).
    ///
    /// Replaces the rigid pre-PR2 invariant *"the route table must
    /// contain a route with `path: "/"` and no host"* — which broke
    /// edits to the catch-all because the validator rebuilt with
    /// the new path **before** the operator could swap which route
    /// holds the default role.
    #[serde(default)]
    pub default: bool,
    /// PR2 — `false` skips this route from trie registration so
    /// the operator can pull a misbehaving route without deleting
    /// it. Defaults to `true` (enabled). Disabled routes still
    /// appear in `/api/routes` (dimmed in the UI) so config
    /// integrity is preserved across the toggle.
    #[serde(default = "default_route_enabled")]
    pub enabled: bool,
}

fn default_route_enabled() -> bool {
    true
}

/// Per-route request/response quotas.
#[derive(Clone, Debug, Deserialize)]
pub struct QuotaConfig {
    /// Maximum request body size in bytes (→ 413).
    #[serde(default = "default_max_body_size")]
    pub client_max_body_size: u64,
    /// Maximum total header size in bytes (→ 431).
    #[serde(default = "default_max_header_size")]
    pub max_header_size: usize,
    /// Maximum URI length in bytes (→ 414).
    #[serde(default = "default_max_uri_length")]
    pub max_uri_length: usize,
    /// Read timeout for the request (→ 408).
    #[serde(default = "default_read_timeout", with = "humantime_serde")]
    pub read_timeout: Duration,
    /// Write / upstream timeout (→ 504).
    #[serde(default = "default_write_timeout", with = "humantime_serde")]
    pub write_timeout: Duration,
    /// Total request deadline (→ 504).
    #[serde(default = "default_total_deadline", with = "humantime_serde")]
    pub total_deadline: Duration,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            client_max_body_size: default_max_body_size(),
            max_header_size: default_max_header_size(),
            max_uri_length: default_max_uri_length(),
            read_timeout: default_read_timeout(),
            write_timeout: default_write_timeout(),
            total_deadline: default_total_deadline(),
        }
    }
}

fn default_max_body_size() -> u64 {
    10 * 1024 * 1024 // 10 MB
}
fn default_max_header_size() -> usize {
    64 * 1024 // 64 KB
}
fn default_max_uri_length() -> usize {
    8192
}
fn default_read_timeout() -> Duration {
    Duration::from_secs(30)
}
fn default_write_timeout() -> Duration {
    Duration::from_secs(60)
}
fn default_total_deadline() -> Duration {
    Duration::from_secs(120)
}

fn default_match_type() -> MatchType {
    MatchType::Prefix
}

fn default_strip_prefix() -> bool {
    true
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    Exact,
    Prefix,
    Regex,
    Glob,
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FailureModeConfig {
    FailClose,
    FailOpen,
}

// ---------------------------------------------------------------------------
// Upstream Pool
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct PoolConfig {
    pub members: Vec<MemberConfig>,
    #[serde(default = "default_lb")]
    pub lb: LbStrategy,
    #[serde(default)]
    pub health: Option<HealthCheckConfig>,
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    /// UP-T1 — per-upstream connection pooling. Closed run-06's
    /// "WAF can't saturate cores" gap by keeping idle TCP +
    /// HTTP/1.1 keep-alive connections to each member around
    /// instead of opening a new TCP per request.
    #[serde(default)]
    pub connection: ConnectionPoolConfig,
}

/// Per-pool keep-alive / idle-pool tuning. All optional;
/// defaults match hyper-util's defaults closely.
#[derive(Clone, Debug, Deserialize)]
pub struct ConnectionPoolConfig {
    /// Maximum idle connections kept per host:port. `0` disables
    /// pooling (every request gets a fresh connection — restores
    /// pre-UP-T1 behaviour, useful for debugging).
    #[serde(default = "default_pool_max_idle_per_host")]
    pub max_idle_per_host: usize,
    /// How long an idle connection may stay in the pool before
    /// it's closed proactively. Should be shorter than the
    /// upstream's keep-alive timeout to avoid racing the
    /// remote close.
    #[serde(default = "default_pool_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// HTTP/1.1 keep-alive on the request side. Off = always
    /// `Connection: close`, no pooling regardless of
    /// `max_idle_per_host`. Defaults to true.
    #[serde(default = "default_keep_alive")]
    pub keep_alive: bool,
    /// HP-T1 — when `true`, requests are forwarded over
    /// rustls + HTTP/1.1 (`https://<addr>`) using the host's
    /// webpki root certificates. Default `false` (plain HTTP).
    /// The TLS session pool is shared by every member of a
    /// pool that has the same connection signature.
    ///
    /// **Back-compat note:** when `scheme` is `Auto` (the default),
    /// `tls: true` ⇒ Https, `tls: false` ⇒ Auto-Http. When `scheme`
    /// is set explicitly (Https/H2c/Grpc/etc.), `tls` is ignored.
    #[serde(default)]
    pub tls: bool,
    /// Explicit upstream protocol selector. `Auto` (default)
    /// preserves the pre-Phase-3 behaviour: ALPN negotiates
    /// HTTP/1.1 vs HTTP/2 between the connector and upstream.
    /// Operators force a specific protocol by setting this.
    #[serde(default)]
    pub scheme: UpstreamScheme,
    /// 2026-05-17 F-HIGH-003 — cap on the response body the WAF
    /// buffers from the upstream. Pre-fix the response was fully
    /// collected with `into_body().collect()` and no `Limited<_>`
    /// wrapper, exposing the WAF to OOM under a hostile or runaway
    /// upstream (gzipped XML bomb, infinite-stream bug). Default
    /// 10 MiB — matches `ProxyConfig.max_body_bytes` for the
    /// request side. Operators with legitimate large downloads
    /// raise this per-pool.
    #[serde(default = "default_max_response_body_bytes")]
    pub max_response_body_bytes: u64,
    /// 2026-05-17 F-HIGH-stateful — wall-clock deadline on the
    /// upstream response-body read. Without it, a slowloris-style
    /// upstream that trickles bytes below the per-byte cap can
    /// pin the WAF's connection slot indefinitely (`Limited<_>`
    /// only enforces the SIZE budget, not the TIME budget).
    /// Default 30 s — generous enough for legitimate slow APIs;
    /// drop to 5-10 s for typical request/response workloads.
    /// Exceeded deadline surfaces as `ForwardError::Timeout`
    /// which the data plane maps onto v2.3 §3 `timeout` action.
    #[serde(default = "default_response_body_read_timeout", with = "humantime_serde")]
    pub response_body_read_timeout: Duration,
}

/// Upstream protocol selector for `ConnectionPoolConfig.scheme`.
/// See `aegis-proxy/src/upstream/forward.rs::build_client` for
/// how each variant maps to the hyper connector.
///
/// HIGH-RU-02 (2026-05-12) — `Hash` is needed so the per-process
/// upstream-client cache in `forward.rs::PoolKey` can include the
/// scheme as part of its key.  Without that, a hot-reload that
/// flips scheme (e.g. `auto → https`) hit the stale cache entry
/// built for the prior scheme, and `build_client`'s scheme-
/// dependent ALPN / `http2_only` flags didn't take effect until
/// the WAF process restarted.
#[derive(Copy, Clone, Debug, Default, serde::Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamScheme {
    /// ALPN auto-negotiation. The TLS toggle (`tls: bool`)
    /// decides plaintext vs encrypted. Either H1 or H2 may
    /// land depending on what the upstream advertises.
    #[default]
    Auto,
    /// Plain HTTP/1.1 over TCP. Equivalent to `tls: false` on
    /// the legacy schema. No TLS handshake.
    Http,
    /// HTTPS — TLS with ALPN preference for both h1 and h2.
    /// Equivalent to `tls: true` on the legacy schema.
    Https,
    /// HTTP/2 cleartext (h2c). Forces HTTP/2 over plain TCP —
    /// no TLS handshake. Useful for service-mesh sidecars and
    /// gRPC over loopback.
    H2c,
    /// gRPC over HTTPS. Identical wire shape to `Https` but
    /// forces ALPN to `h2` only (no HTTP/1.1 fallback) — gRPC
    /// strictly requires HTTP/2.
    Grpc,
    /// Raw TCP byte forwarding (no HTTP framing). Phase 4 work —
    /// when set today the forwarder logs an error and returns
    /// 502 Bad Gateway with `x-waf-rule-id: tcp-not-implemented`.
    Tcp,
}

impl UpstreamScheme {
    /// Human-readable label used by `/api/upstreams/config`
    /// and the dashboard's PoolEditModal.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Http => "http",
            Self::Https => "https",
            Self::H2c => "h2c",
            Self::Grpc => "grpc",
            Self::Tcp => "tcp",
        }
    }

    /// True when this scheme should drive the TLS handshake
    /// path. Used by `build_client` to decide between
    /// `HttpsConnector` and the plain `HttpConnector`.
    pub fn uses_tls(self, tls_legacy: bool) -> bool {
        match self {
            Self::Auto => tls_legacy,
            Self::Http | Self::H2c | Self::Tcp => false,
            Self::Https | Self::Grpc => true,
        }
    }

    /// True when this scheme requires HTTP/2 wire framing
    /// (used to flip `http2_only` on the hyper Client builder).
    pub fn forces_http2(self) -> bool {
        matches!(self, Self::H2c | Self::Grpc)
    }
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: default_pool_max_idle_per_host(),
            idle_timeout: default_pool_idle_timeout(),
            keep_alive: default_keep_alive(),
            tls: false,
            scheme: UpstreamScheme::Auto,
            max_response_body_bytes: default_max_response_body_bytes(),
            response_body_read_timeout: default_response_body_read_timeout(),
        }
    }
}

#[cfg(test)]
mod upstream_scheme_tests {
    use super::*;

    #[test]
    fn auto_scheme_inherits_tls_flag() {
        let mut c = ConnectionPoolConfig::default();
        c.tls = true;
        assert!(c.scheme.uses_tls(c.tls));
        c.tls = false;
        assert!(!c.scheme.uses_tls(c.tls));
    }

    #[test]
    fn explicit_https_uses_tls_regardless_of_legacy_flag() {
        let mut c = ConnectionPoolConfig::default();
        c.scheme = UpstreamScheme::Https;
        c.tls = false;
        assert!(c.scheme.uses_tls(c.tls));
    }

    #[test]
    fn explicit_http_skips_tls_regardless_of_legacy_flag() {
        let mut c = ConnectionPoolConfig::default();
        c.scheme = UpstreamScheme::Http;
        c.tls = true;
        assert!(!c.scheme.uses_tls(c.tls));
    }

    #[test]
    fn h2c_is_plaintext_with_http2_only() {
        assert!(!UpstreamScheme::H2c.uses_tls(true));
        assert!(UpstreamScheme::H2c.forces_http2());
    }

    #[test]
    fn grpc_is_tls_with_http2_only() {
        assert!(UpstreamScheme::Grpc.uses_tls(false));
        assert!(UpstreamScheme::Grpc.forces_http2());
    }

    #[test]
    fn http_and_https_do_not_force_http2() {
        assert!(!UpstreamScheme::Http.forces_http2());
        assert!(!UpstreamScheme::Https.forces_http2());
        assert!(!UpstreamScheme::Auto.forces_http2());
    }

    #[test]
    fn as_str_renders_snake_case() {
        assert_eq!(UpstreamScheme::Auto.as_str(),  "auto");
        assert_eq!(UpstreamScheme::Http.as_str(),  "http");
        assert_eq!(UpstreamScheme::Https.as_str(), "https");
        assert_eq!(UpstreamScheme::H2c.as_str(),   "h2c");
        assert_eq!(UpstreamScheme::Grpc.as_str(),  "grpc");
        assert_eq!(UpstreamScheme::Tcp.as_str(),   "tcp");
    }

    #[test]
    fn scheme_round_trips_via_yaml() {
        let yaml = "scheme: grpc\n";
        let c: ConnectionPoolConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(c.scheme, UpstreamScheme::Grpc);
    }

    #[test]
    fn missing_scheme_defaults_to_auto() {
        let yaml = "tls: false\n";
        let c: ConnectionPoolConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(c.scheme, UpstreamScheme::Auto);
    }
}

#[cfg(test)]
mod member_addr_spec_tests {
    use super::*;

    #[test]
    fn ip_string_round_trips() {
        // Bare IP:port — the legacy shape every config that
        // predates PR-DNS-1 uses.
        let raw = "\"127.0.0.1:8080\"";
        let parsed: MemberAddrSpec = serde_json::from_str(raw).unwrap();
        let MemberAddrSpec::Ip(sa) = parsed else { panic!("expected Ip variant") };
        assert_eq!(sa.to_string(), "127.0.0.1:8080");
        assert_eq!(serde_json::to_string(&MemberAddrSpec::Ip(sa)).unwrap(), raw);
    }

    #[test]
    fn ipv6_string_round_trips_through_ip_variant() {
        // RFC 3986 bracket notation — `[host]:port`. Must hit the
        // `SocketAddr::from_str` branch first; the host:port split
        // would otherwise fold the `:` characters into the port.
        let raw = "\"[::1]:8443\"";
        let parsed: MemberAddrSpec = serde_json::from_str(raw).unwrap();
        assert!(matches!(parsed, MemberAddrSpec::Ip(_)));
    }

    #[test]
    fn hostname_string_falls_back_to_hostname_variant() {
        let raw = "\"api.example.com:443\"";
        let parsed: MemberAddrSpec = serde_json::from_str(raw).unwrap();
        let MemberAddrSpec::Hostname { host, port, refresh_seconds } = parsed else {
            panic!("expected Hostname variant");
        };
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
        assert!(refresh_seconds.is_none(), "string form should leave refresh_seconds unset");
    }

    #[test]
    fn map_shape_parses_with_refresh_override() {
        let yaml = "\
host: api.example.com
port: 443
refresh_seconds: 120
";
        let parsed: MemberAddrSpec = serde_yaml::from_str(yaml).unwrap();
        let MemberAddrSpec::Hostname { host, port, refresh_seconds } = parsed else {
            panic!("expected Hostname variant");
        };
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
        assert_eq!(refresh_seconds, Some(120));
    }

    #[test]
    fn serialize_always_uses_string_form() {
        // Stable wire shape — Hostname members serialise as
        // `host:port` so dashboard PUT round-trips don't churn YAML.
        let v = MemberAddrSpec::Hostname {
            host: "api.example.com".into(),
            port: 443,
            refresh_seconds: Some(60),
        };
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, "\"api.example.com:443\"");
    }

    #[test]
    fn rejects_empty_hostname() {
        let raw = "\":443\"";
        let err = serde_json::from_str::<MemberAddrSpec>(raw).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn rejects_hostname_with_slash() {
        let raw = "\"api/example.com:443\"";
        let err = serde_json::from_str::<MemberAddrSpec>(raw).unwrap_err();
        assert!(
            err.to_string().contains("must not contain `/`"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn rejects_bad_port() {
        let raw = "\"api.example.com:not-a-port\"";
        let err = serde_json::from_str::<MemberAddrSpec>(raw).unwrap_err();
        assert!(
            err.to_string().contains("invalid port"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn member_config_parses_mixed_yaml_with_both_shapes() {
        // The real operator surface — a YAML pool with one IP
        // member and one hostname member side by side.
        let yaml = "\
addr: 10.0.1.10:8080
";
        let m: MemberConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(m.addr, MemberAddrSpec::Ip(_)));
        assert_eq!(m.addr.port(), 8080);

        let yaml = "\
addr: api.example.com:443
";
        let m: MemberConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(m.addr, MemberAddrSpec::Hostname { .. }));
        assert_eq!(m.addr.hostname(), Some("api.example.com"));
        assert_eq!(m.addr.port(), 443);
    }

    #[test]
    fn display_matches_operator_authored_shape() {
        let ip: MemberAddrSpec = serde_json::from_str("\"10.0.0.1:8080\"").unwrap();
        assert_eq!(ip.display(), "10.0.0.1:8080");
        let host: MemberAddrSpec = serde_json::from_str("\"api.example.com:443\"").unwrap();
        assert_eq!(host.display(), "api.example.com:443");
    }
}

fn default_pool_max_idle_per_host() -> usize {
    32
}

fn default_pool_idle_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_keep_alive() -> bool {
    true
}

fn default_max_response_body_bytes() -> u64 {
    10 * 1024 * 1024 // 10 MiB — matches `ProxyConfig::default()`.
}

fn default_response_body_read_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_lb() -> LbStrategy {
    LbStrategy::RoundRobin
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LbStrategy {
    RoundRobin,
    WeightedRoundRobin,
    LeastConn,
    ConsistentHash,
    P2c,
}

/// 2026-05-11 (PR-DNS-1) — wire shape for `MemberConfig.addr`.
/// Operators can address a backend by either an IP literal or a
/// hostname; YAML keeps the single-string form for both, while the
/// internal enum gives the boot path enough structure to resolve
/// hostnames and pick a sensible SNI default.
///
/// **Serde shape.** `#[serde(untagged)]` against a single string —
/// we first try `SocketAddr::from_str` for the strict "IP:port"
/// case, falling back to a `host:port` hostname split. This means
/// the YAML stays:
///
/// ```yaml
/// members:
///   - addr: 10.0.1.10:8080         # parses as Ip
///   - addr: api.example.com:443    # parses as Hostname
/// ```
///
/// without operators having to opt into a different tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemberAddrSpec {
    /// IP:port literal — exactly the original behaviour.
    Ip(SocketAddr),
    /// Hostname + port. Resolved via DNS at boot/config-load time;
    /// multi-A records expand into N synthetic members (Phase 1).
    /// Phase 2 (not in this commit) adds background refresh on TTL.
    Hostname {
        host: String,
        port: u16,
        /// Override the DNS-honored TTL refresh cadence (seconds).
        /// `None` honours the record's TTL (Phase 2 honours this;
        /// Phase 1 ignores the field, kept on the wire so YAML
        /// authored against the spec doesn't break later).
        refresh_seconds: Option<u32>,
    },
}

impl MemberAddrSpec {
    /// Port number the operator configured.
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(sa) => sa.port(),
            Self::Hostname { port, .. } => *port,
        }
    }

    /// Hostname for SNI / outbound `Host:` header. `None` for IP
    /// literals (the existing path picks `addr.to_string()` or
    /// `host_header` in that case); `Some(host)` for hostnames so
    /// the forwarder can default SNI to the configured name
    /// without operators having to repeat themselves in
    /// `host_header`.
    pub fn hostname(&self) -> Option<&str> {
        match self {
            Self::Ip(_) => None,
            Self::Hostname { host, .. } => Some(host.as_str()),
        }
    }

    /// Display form for operator-facing surfaces (audit log,
    /// dashboard, error messages). Hostname members render as
    /// `host:port`; IP members render as `ip:port`.
    pub fn display(&self) -> String {
        match self {
            Self::Ip(sa) => sa.to_string(),
            Self::Hostname { host, port, .. } => format!("{host}:{port}"),
        }
    }
}

impl std::fmt::Display for MemberAddrSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display())
    }
}

impl<'de> Deserialize<'de> for MemberAddrSpec {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        // Two accepted shapes:
        //   - bare string:  `addr: api.example.com:443`
        //   - tagged map:   `addr: { host: api.example.com, port: 443, refresh_seconds: 60 }`
        //
        // We delegate to `serde_yaml::Value` (via `serde_json::Value` —
        // serde-compatible across both formats) so the same code
        // works for YAML config + JSON dashboard PUTs.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Str(String),
            Map {
                host: String,
                port: u16,
                #[serde(default)]
                refresh_seconds: Option<u32>,
            },
        }

        match Raw::deserialize(deserializer)? {
            Raw::Str(s) => parse_addr_string(&s).map_err(D::Error::custom),
            Raw::Map { host, port, refresh_seconds } => {
                validate_hostname(&host).map_err(D::Error::custom)?;
                Ok(MemberAddrSpec::Hostname { host, port, refresh_seconds })
            }
        }
    }
}

impl Serialize for MemberAddrSpec {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        // Stable wire shape — always the single-string form so
        // round-trips through the dashboard PUT path stay tidy.
        ser.serialize_str(&self.display())
    }
}

/// Parse `addr: <string>` into a `MemberAddrSpec`. Tries the strict
/// `SocketAddr` form first (so `127.0.0.1:8080` always wins);
/// falls back to `host:port` split if that fails.
fn parse_addr_string(s: &str) -> Result<MemberAddrSpec, String> {
    use std::str::FromStr;
    if let Ok(sa) = SocketAddr::from_str(s) {
        return Ok(MemberAddrSpec::Ip(sa));
    }
    // `host:port` split — port is everything after the last `:`,
    // which keeps IPv6 strings (`[::1]:8080`) routed through the
    // earlier `SocketAddr` branch.
    let (host, port_str) = s.rsplit_once(':').ok_or_else(|| {
        format!("invalid address `{s}` — expected `IP:port` or `host:port`")
    })?;
    let port: u16 = port_str.parse().map_err(|_| {
        format!("invalid port `{port_str}` in `{s}`")
    })?;
    validate_hostname(host)?;
    Ok(MemberAddrSpec::Hostname {
        host: host.to_string(),
        port,
        refresh_seconds: None,
    })
}

/// Surface-level hostname sanity. We're not running RFC 1035 — we
/// just want to reject obviously-broken input (empty host, host
/// containing `/`, host starting with `-`) so the resolver gets a
/// fair chance. Wider validation is the resolver's job.
fn validate_hostname(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("hostname must not be empty".into());
    }
    if host.contains('/') || host.contains(' ') {
        return Err(format!("invalid hostname `{host}` — must not contain `/` or whitespace"));
    }
    if host.starts_with('-') || host.ends_with('-') {
        return Err(format!("invalid hostname `{host}` — must not start or end with `-`"));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
pub struct MemberConfig {
    /// Backend address — either an IP literal (`10.0.1.10:8080`) or
    /// a hostname (`api.example.com:443`). Hostnames are resolved
    /// at boot/config-load and expanded into one `Member` per
    /// resolved IP, so the LB strategies (round-robin, p2c,
    /// consistent-hash) distribute across all A/AAAA results.
    pub addr: MemberAddrSpec,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub zone: Option<String>,
    /// FIX 2026-05-03 — explicit `Host:` header override.
    /// Without this the forwarder rewrites `Host` to the
    /// member's `addr` (IP:port) which works for IP-addressed
    /// upstreams but breaks vhost-routed backends — putting the
    /// WAF in front of `nginx` / Cloudflare / GitHub Pages /
    /// any service that dispatches on Host returns 404 / wrong
    /// vhost.  Set this to the hostname the upstream expects.
    ///
    /// **TLS note** — for HTTPS upstreams the SNI + cert-
    /// validation hostname still come from the connection URL
    /// (the member's `addr` IP).  That works for internal CAs
    /// that issue certs to IPs; for public TLS upstreams you'll
    /// either need a sidecar that does the vhost dance OR a
    /// future `host_header_override` extension that pins SNI to
    /// the override (queued as a follow-up; today's v1 covers
    /// the plain-HTTP and IP-cert HTTPS cases which are the
    /// most common operator surface).
    #[serde(default)]
    pub host_header: Option<String>,
}

fn default_weight() -> u32 {
    1
}

#[derive(Clone, Debug, Deserialize)]
pub struct HealthCheckConfig {
    pub path: String,
    #[serde(default = "default_health_interval", with = "humantime_serde")]
    pub interval: Duration,
    #[serde(default = "default_health_timeout", with = "humantime_serde")]
    pub timeout: Duration,
}

fn default_health_interval() -> Duration {
    Duration::from_secs(10)
}
fn default_health_timeout() -> Duration {
    Duration::from_secs(3)
}

#[derive(Clone, Debug, Deserialize)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_cb_threshold")]
    pub error_rate_threshold: f64,
    #[serde(default = "default_cb_window", with = "humantime_serde")]
    pub open_duration: Duration,
}

fn default_cb_threshold() -> f64 {
    0.5
}
fn default_cb_window() -> Duration {
    Duration::from_secs(30)
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub certificates: Vec<CertConfig>,
    /// Minimum TLS protocol version. Accepted: `"1.2"` or `"1.3"`.
    /// `None` falls back to the rustls default (1.2 + 1.3 both
    /// allowed). Validated at config load — typos like `"1.1"` or
    /// `"v1.2"` fail fast.
    #[serde(default)]
    pub min_version: Option<String>,
    /// When `true`, the proxy can be paired with a plain-HTTP
    /// listener that 301-redirects every request to its HTTPS
    /// equivalent. The redirect listener itself is added to
    /// [`Listeners`] separately (see [`Listeners::force_https`]).
    #[serde(default)]
    pub force_https: bool,
    /// HSTS policy emitted on TLS-served responses. `None` =
    /// don't send the header.
    #[serde(default)]
    pub hsts: Option<HstsConfig>,
    /// ACME / Let's Encrypt automatic cert issuance. `None`
    /// disables the manager — operators stay on the static
    /// `certificates: [...]` flow.
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
    /// MTLS-T1 — server-side mutual-TLS client cert verification.
    /// `None` (default) keeps the legacy `with_no_client_auth()`
    /// behaviour — listeners present their server cert and never
    /// ask the client to authenticate. Setting this opts the
    /// listeners listed in `apply_to` into the rustls
    /// `WebPkiClientVerifier` path; see [`ClientAuthConfig`].
    #[serde(default)]
    pub client_auth: Option<ClientAuthConfig>,
    /// B5 carry-over — when set, every TLS-served data-plane
    /// response is stamped with an `Alt-Svc:` header
    /// advertising the supplied UDP port for HTTP/3. Capable
    /// browsers will switch to QUIC for subsequent requests
    /// (cached for 24h by default). `None` (default) emits
    /// nothing — clients keep the original protocol.
    ///
    /// Only meaningful when an HTTP/3 listener is also
    /// configured (cargo `http3` feature). Set to `Some(443)`
    /// in front-door deployments where the QUIC listener
    /// is bound to the public 443/UDP.
    #[serde(default)]
    pub advertise_h3: Option<u16>,
}

/// MTLS-T1 — server-side mTLS client-cert verification settings.
///
/// The presence of this struct means "request client certs from
/// the listener planes named in [`Self::apply_to`]". The exact
/// enforcement strictness comes from [`Self::mode`]; the trust
/// anchors come from [`Self::ca_bundle`]. An empty
/// [`Self::allowed_sans`] means "any SAN signed by `ca_bundle`
/// is admitted" — non-empty adds a SAN allowlist gate on top.
#[derive(Clone, Debug, Deserialize)]
pub struct ClientAuthConfig {
    /// Strictness of the client-cert check. See
    /// [`ClientAuthMode`]. Defaults to `Disabled` so a
    /// half-typed cfg (`client_auth: {}`) is a no-op rather than
    /// a footgun.
    #[serde(default)]
    pub mode: ClientAuthMode,
    /// PEM bundle of trust anchors for verifying client certs.
    /// **Required** when `mode != Disabled` — validation rejects
    /// a non-disabled mode with no `ca_bundle` populated.
    #[serde(default)]
    pub ca_bundle: Option<PathBuf>,
    /// Optional SAN allowlist — when non-empty, a client cert
    /// must (a) chain to `ca_bundle` AND (b) carry at least one
    /// SAN that matches an entry in this list. Empty list means
    /// "any SAN signed by the trust anchor is admitted".
    /// Wildcard syntax: `*.example.com` matches single-label
    /// subdomains.
    #[serde(default)]
    pub allowed_sans: Vec<String>,
    /// Which listener planes enforce client-cert verification.
    /// Default `[admin]` — safe default that doesn't break
    /// existing data-plane clients on a config that opts in
    /// without specifying `apply_to`. Operators wanting full
    /// zero-trust ingress set `apply_to: [admin, data]`.
    #[serde(default = "default_client_auth_apply_to")]
    pub apply_to: Vec<ClientAuthScope>,
}

/// Strictness of [`ClientAuthConfig`] enforcement.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMode {
    /// Listener does not request a client cert. Equivalent to
    /// `client_auth: None`.
    #[default]
    Disabled,
    /// Listener requests a client cert but does not fail the
    /// handshake when none is presented. Useful for staging a
    /// rollout — operators flip to `Optional`, watch the
    /// identity tracker, then flip to `Required` once every
    /// expected client has been issued a cert.
    Optional,
    /// Listener requests a client cert and fails the handshake
    /// without one. Cert must chain to `ca_bundle`; if
    /// `allowed_sans` is non-empty the leaf SAN must also match.
    Required,
}

/// Listener plane(s) that enforce [`ClientAuthConfig`]. Mirrors
/// the existing `cfg.listeners.{data, admin}` split.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthScope {
    /// Admin / dashboard / `/__waf_control` listener.
    Admin,
    /// Data-plane listeners (per `cfg.listeners.data[*]`).
    Data,
}

fn default_client_auth_apply_to() -> Vec<ClientAuthScope> {
    vec![ClientAuthScope::Admin]
}

/// ACME / Let's Encrypt configuration (P5 of the security-toggle
/// plan). Issuance and renewal flow through `aegis_proxy::acme`.
#[derive(Clone, Debug, Deserialize)]
pub struct AcmeConfig {
    /// Directory URL. Defaults to Let's Encrypt production. Use
    /// `https://acme-staging-v02.api.letsencrypt.org/directory`
    /// during integration testing.
    #[serde(default = "default_acme_directory")]
    pub directory_url: String,
    /// Contact emails for the ACME account. At least one entry.
    pub contacts: Vec<String>,
    /// Domains to issue certs for.
    pub domains: Vec<String>,
    /// Path where the ACME account private key is persisted.
    pub account_key_path: PathBuf,
    /// Directory where issued certs are persisted (one file per
    /// domain or SAN bundle).
    pub cert_dir: PathBuf,
    /// How early before expiry to trigger renewal. Defaults to
    /// 30 days (per Let's Encrypt guidance).
    #[serde(default = "default_renew_before", with = "humantime_serde")]
    pub renew_before: Duration,
    /// Acknowledge the directory's Terms of Service. Required
    /// for first-time account registration.
    #[serde(default)]
    pub terms_of_service_agreed: bool,
    /// Challenge mechanism. Defaults to `http_01` (the proxy
    /// already runs a plain-HTTP listener for force-https).
    #[serde(default)]
    pub challenge: AcmeChallenge,
    /// Run the leader-gated auto-renewal loop. **Default `true`** (single-
    /// node / edge deployments auto-renew). **Set `false` when TLS/ACME is
    /// owned elsewhere** — an L7 load balancer that terminates TLS, or
    /// out-of-band issuance (certbot/cert-manager) that distributes the
    /// cert to the fleet. Behind a round-robin L4 LB the in-WAF HTTP-01
    /// flow can't reliably complete (the CA's challenge request isn't
    /// guaranteed to reach the leader, and the issued cert isn't shared),
    /// so a load-balanced fleet should set this `false` and provision certs
    /// externally. When `false` the WAF never contacts the ACME directory;
    /// it only serves certs you provision via `tls.certificates`.
    #[serde(default = "default_true")]
    pub auto_renew: bool,
}

fn default_acme_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".into()
}

fn default_renew_before() -> Duration {
    Duration::from_secs(30 * 24 * 3600)
}

/// Which ACME challenge mechanism the manager uses.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AcmeChallenge {
    /// HTTP-01 — server proves control by responding on `:80`
    /// at `/.well-known/acme-challenge/{token}`. Pairs with
    /// the existing force-https listener.
    #[default]
    Http01,
    /// TLS-ALPN-01 — same proof but over TLS on `:443` using
    /// the `acme-tls/1` ALPN. Use when port 80 is unavailable.
    TlsAlpn01,
    /// DNS-01 — server publishes a TXT record. Required for
    /// wildcard certificates.
    Dns01,
}

/// `Strict-Transport-Security` policy. Browsers honour this only
/// when received over HTTPS, so the proxy emits it on TLS responses
/// and skips it on plain HTTP.
#[derive(Clone, Debug, Deserialize)]
pub struct HstsConfig {
    /// Lifetime in seconds. RFC 6797 §6.1.1 requires a positive
    /// value; defaults to 1 year per the OWASP HSTS guidance.
    #[serde(default = "default_hsts_max_age")]
    pub max_age: u64,
    #[serde(default = "default_true")]
    pub include_subdomains: bool,
    /// Set to `true` to opt into the browser HSTS preload list.
    /// Submitting requires `max_age >= 31_536_000` and
    /// `include_subdomains: true` per hstspreload.org.
    #[serde(default)]
    pub preload: bool,
}

fn default_hsts_max_age() -> u64 {
    31_536_000
}

impl Default for HstsConfig {
    fn default() -> Self {
        Self {
            max_age: default_hsts_max_age(),
            include_subdomains: true,
            preload: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct CertConfig {
    pub cert_path: PathBuf,
    pub key_ref: String,
    #[serde(default)]
    pub hosts: Vec<String>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct StateConfig {
    #[serde(default = "default_state_backend")]
    pub backend: StateBackendKind,
    #[serde(default)]
    pub redis: Option<RedisConfig>,
    #[serde(default)]
    pub reconcile: ReconcileConfig,
}

fn default_state_backend() -> StateBackendKind {
    StateBackendKind::InMemory
}

/// State-backend reconciliation policy.
///
/// **B1-T5 — Phase B.** Today only `readiness_warm_ms` is honored
/// (the maximum time a fresh node will wait for its state backend
/// to round-trip before it flips `/healthz/ready` to 200). The
/// `mode` field is reserved for B1-T6 partition-safe merge.
#[derive(Clone, Debug, Deserialize)]
pub struct ReconcileConfig {
    /// How long the gateway holds `/healthz/ready` at 503 while
    /// warming the state backend on boot. After this elapses
    /// readiness flips to ready regardless of warm-up outcome
    /// (we never want a permanently-503 node).
    #[serde(default = "default_readiness_warm", with = "humantime_serde")]
    pub readiness_warm_ms: Duration,

    /// Reserved for B1-T6.
    #[serde(default = "default_reconcile_mode")]
    pub mode: ReconcileMode,
}

impl Default for ReconcileConfig {
    fn default() -> Self {
        Self {
            readiness_warm_ms: default_readiness_warm(),
            mode: default_reconcile_mode(),
        }
    }
}

fn default_readiness_warm() -> Duration {
    Duration::from_secs(5)
}

fn default_reconcile_mode() -> ReconcileMode {
    ReconcileMode::Max
}

/// Partition-recovery merge mode. **Reserved** — only `Max` is
/// implemented (and that only by B1-T6).
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileMode {
    Max,
    Latest,
    FailSafe,
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StateBackendKind {
    InMemory,
    Redis,
    Raft,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RedisConfig {
    pub urls: Vec<String>,
    #[serde(default)]
    pub cluster: bool,
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
    #[serde(default = "default_redis_timeout", with = "humantime_serde")]
    pub timeout: Duration,
}

fn default_pool_size() -> u32 {
    16
}
fn default_redis_timeout() -> Duration {
    Duration::from_secs(5)
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Default)]
pub struct RulesConfig {
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    #[serde(default = "default_max_rule_count")]
    pub max_rule_count: u32,
    #[serde(default)]
    pub strict_compile: bool,
    /// 2026-05-27 (Phase B rules fold) — inline, operator-authored rule
    /// list. This is the persistent + cluster-propagated source for the
    /// dashboard `RuleStore`: the boot path seeds the store from it and
    /// every config watcher re-derives the store + active ruleset via
    /// `reload::apply_cfg_change_to_rules`. The dashboard rule CRUD
    /// (`POST/PUT/DELETE /api/rules`, `/toggle`) patches this list and
    /// activates through the config plane. `paths` above stays for the
    /// backup/snapshot tooling and is not loaded into the live engine.
    #[serde(default)]
    pub inline: Vec<RuleDef>,
}

/// 2026-05-27 (Phase B rules fold) — one inline rule. Mirrors the live
/// `aegis_control::api::rules::Rule` minus its runtime `updated_at`
/// (regenerated by `RuleStore::upsert`). `body` is the rule DSL text.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDef {
    pub id: String,
    pub body: String,
    #[serde(default)]
    pub enabled: bool,
}

fn default_max_rule_count() -> u32 {
    10_000
}

// ---------------------------------------------------------------------------
// Rate limit
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Default)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub buckets: Vec<RateLimitRule>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RateLimitRule {
    pub id: String,
    pub scope: RlScope,
    pub key: RlKey,
    pub algo: RlAlgo,
    pub limit: u64,
    #[serde(with = "humantime_serde")]
    pub window: Duration,
    #[serde(default)]
    pub burst: Option<u32>,
}

/// 2026-05-17 F-CRITICAL-009 (core audit): rule scope, per §5.4 of
/// the official rules. Six base scopes; each binds a rate-limit
/// bucket (or rule) to a different dimension. Schema only —
/// evaluator wiring lands in Phase E/F. Externally-tagged so
/// existing YAML configs with `scope: global` keep working
/// unchanged.
///
/// YAML shape (rate-limit bucket example):
/// ```yaml
/// rate_limit:
///   buckets:
///     - id: per-tenant-login
///       scope:
///         tier: critical
///       rps: 10
///     - id: per-fp
///       scope: device_fingerprint
///       rps: 5
/// ```
#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RlScope {
    /// Global — applies to every request.
    Global,
    /// Bind to one specific named route (matches `route.id`).
    Route,
    /// §5.4 — bind to one of the 4 tiers.
    Tier(crate::tier::Tier),
    /// §5.4 — glob/regex route pattern (e.g. `/api/users/*`).
    RoutePattern(String),
    /// §5.4 — single IP or CIDR.
    Ip(String),
    /// §5.4 — bind by authenticated user session ID.
    UserSession,
    /// §5.4 — bind by device fingerprint hash (JA4 + UA + H2).
    DeviceFingerprint,
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RlKey {
    Ip,
    Session,
    Header(String),
    JwtSub,
    /// 2026-05-17 F-CRITICAL-009 (core audit): device fingerprint
    /// key — composite of JA4 + User-Agent + H2 settings.
    DeviceFp,
    /// 2026-05-17 F-CRITICAL-009 (core audit): authenticated user
    /// ID (e.g. from JWT claim or session lookup).
    UserId,
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RlAlgo {
    SlidingWindow,
    TokenBucket,
}

// ---------------------------------------------------------------------------
// Risk
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct RiskConfig {
    #[serde(default)]
    pub weights: RiskWeights,
    #[serde(default = "default_risk_decay", with = "humantime_serde")]
    pub decay_half_life: Duration,
    #[serde(default)]
    pub thresholds: RiskThresholds,
    /// P6: trust recovery policy. Per-hour decay cap when a client
    /// behaves cleanly. `None` keeps the legacy "decay only via
    /// half-life" behaviour.
    #[serde(default)]
    pub trust_recovery: Option<TrustRecoveryConfig>,
    /// P6: strike accounting. Tracks lifetime malicious-event count
    /// per client; once `block_at` strikes are reached, the client
    /// is permanently blocked even if their score has decayed.
    #[serde(default)]
    pub strikes: Option<StrikeConfig>,
    /// 2026-05-17 F-CRITICAL-012 (core audit): canary path list.
    /// Any request that touches one of these paths is treated as
    /// high-signal malicious (no legitimate caller should hit a
    /// honeypot URL). Each entry matches as an exact path or a
    /// `*` suffix glob (`/admin/*` matches `/admin/foo` and
    /// `/admin/foo/bar`). Schema only — consumer wiring lands in
    /// Phase F (`aegis-security/src/canary/`).
    ///
    /// YAML shape:
    /// ```yaml
    /// risk:
    ///   canary_paths:
    ///     - "/wp-admin"
    ///     - "/.env"
    ///     - "/phpmyadmin/*"
    /// ```
    #[serde(default)]
    pub canary_paths: Vec<String>,
}

fn default_risk_decay() -> Duration {
    Duration::from_secs(300)
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            weights: RiskWeights::default(),
            decay_half_life: default_risk_decay(),
            thresholds: RiskThresholds::default(),
            trust_recovery: None,
            strikes: None,
            canary_paths: Vec::new(),
        }
    }
}

/// Trust-recovery policy. Per the user-confirmed default, score
/// decay is capped at `-30 per hour` so a client can claw back
/// reputation but a single benign request can't reset a high
/// score instantly.
#[derive(Clone, Debug, Deserialize)]
pub struct TrustRecoveryConfig {
    /// Maximum points the score can decay by in one hour of clean
    /// requests. Negative is an error (validated at config load).
    #[serde(default = "default_trust_per_hour")]
    pub per_hour: u32,
}

fn default_trust_per_hour() -> u32 {
    30
}

impl Default for TrustRecoveryConfig {
    fn default() -> Self {
        Self {
            per_hour: default_trust_per_hour(),
        }
    }
}

/// Strike accounting. Each malicious detection bumps a lifetime
/// counter (never decays); once `block_at` is reached, the IP is
/// blocked at the data plane until an operator runs
/// `PUT /api/risk/{ip}/reset`.
///
/// 2026-05-10 — `enabled` defaults to `false`. Strike-Block is
/// now opt-in because (a) the contract's `X-WAF-Risk-Score`
/// requires accumulation+decay semantics that can be tested in
/// isolation, and Strike-Block's never-decay counter can keep
/// an IP locked even after the cumulative score has decayed
/// below threshold; and (b) operators caught off-guard by a
/// permanent block found the YAML knob hard to discover.
/// Enable from Dashboard → Traffic Gates → Strike-Block card →
/// Edit, audit-mutated PUT /api/gates/strikes.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StrikeConfig {
    /// Master enable/disable for the Strike-Block gate. When
    /// `false`, `is_strike_blocked()` always returns `false` —
    /// detector hits still increment the lifetime counter
    /// (operators see it climb in `/api/risk`), but the data
    /// plane does not 403 on threshold cross. Defaults to
    /// `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Number of strikes that triggers the gate. Only honored
    /// when `enabled = true`.
    #[serde(default = "default_strike_block_at")]
    pub block_at: u32,
}

fn default_strike_block_at() -> u32 {
    50
}

impl Default for StrikeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            block_at: default_strike_block_at(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct RiskWeights {
    #[serde(default = "default_risk_weight")]
    pub bad_asn: u32,
    #[serde(default = "default_risk_weight")]
    pub bad_ja4: u32,
    #[serde(default = "default_risk_weight")]
    pub failed_auth: u32,
    #[serde(default = "default_risk_weight")]
    pub detector_hit: u32,
    #[serde(default = "default_risk_weight")]
    pub bot_unknown: u32,
    #[serde(default = "default_risk_weight")]
    pub repeat_offender: u32,
}

fn default_risk_weight() -> u32 {
    10
}

impl Default for RiskWeights {
    fn default() -> Self {
        Self {
            bad_asn: 10,
            bad_ja4: 10,
            failed_auth: 10,
            detector_hit: 10,
            bot_unknown: 10,
            repeat_offender: 10,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct RiskThresholds {
    /// 2026-05-21 — master on/off for the cumulative IP-risk gate.
    /// When `false`, accumulated per-key score never produces a
    /// challenge or block (the data plane + `/api/risk` LEVEL treat
    /// every bucket as Allow); detector signals are still RECORDED so
    /// Top Attackers / forensics keep climbing, and strike-block (its
    /// own gate) is unaffected. Replaces the old "set block_at to a
    /// huge number" hack — a real toggle disables BOTH the challenge
    /// and block paths and is self-documenting. Default `true`.
    #[serde(default = "default_risk_gate_enabled")]
    pub enabled: bool,
    #[serde(default = "default_challenge_at")]
    pub challenge_at: u32,
    #[serde(default = "default_block_at")]
    pub block_at: u32,
    #[serde(default = "default_risk_max")]
    pub max: u32,
}

fn default_risk_gate_enabled() -> bool {
    true
}

fn default_challenge_at() -> u32 {
    // 2026-05-17 F-CRITICAL-007: 40 → 30 to match the v2.3 spec.
    // Companion to `RiskThresholds::default()` so a YAML config
    // that sets only `block_at` (not `challenge_at`) still picks
    // up the spec value via this serde default.
    30
}
fn default_block_at() -> u32 {
    // 2026-05-17 F-CRITICAL-007: 80 → 70 to match the v2.3 spec.
    70
}
fn default_risk_max() -> u32 {
    100
}

impl Default for RiskThresholds {
    fn default() -> Self {
        // 2026-05-17 (core F-CRITICAL-007 + security F-CRITICAL-006):
        // bumped from 40/80 → 30/70 to match the spec. Pre-fix two
        // sources disagreed out of the box: `RiskEngine::classify`
        // hardcoded 30/70 (per spec) while this default was 40/80,
        // so a `RiskTracker` built from default config silently
        // disagreed with the spec'd thresholds. Now both agree.
        Self {
            enabled: true,
            challenge_at: 30,
            block_at: 70,
            max: 100,
        }
    }
}

// ---------------------------------------------------------------------------
// Bot classification gate
// ---------------------------------------------------------------------------

/// 2026-05-21 — gate-style on/off for the bot classifier. The
/// classifier (UA + ASN based, `aegis-security/src/bots.rs`) labels
/// requests and feeds the dashboard "Bot classification mix". It's
/// modelled as a GATE (like DDoS / rate-limit / strike-block), not a
/// detector, because its inputs are ambient (ASN via GeoIP, etc.).
/// When disabled, no classification runs and `bot_category` is left
/// unset. Hot-flippable via `PUT /api/gates/bots`.
///
/// **Default OFF** — the classifier is observational today (it labels
/// + feeds the mix; it does not block/challenge by class) and only
/// produces useful (non-`unknown`) output once the GeoIP ASN DB is
/// loaded. Operators opt in via `cfg.bots.enabled: true` or the
/// Traffic Gates toggle, so a default deployment doesn't spend the
/// per-request classification cost for a surface it isn't using.
#[derive(Clone, Debug, Deserialize)]
pub struct BotConfig {
    #[serde(default = "default_bot_enabled")]
    pub enabled: bool,
}

fn default_bot_enabled() -> bool {
    false
}

impl Default for BotConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct DetectorsConfig {
    #[serde(default = "default_detector_toggle")]
    pub sqli: DetectorToggle,
    #[serde(default = "default_detector_toggle")]
    pub xss: DetectorToggle,
    #[serde(default = "default_detector_toggle")]
    pub path_traversal: DetectorToggle,
    #[serde(default = "default_detector_toggle")]
    pub ssrf: DetectorToggle,
    #[serde(default = "default_detector_toggle")]
    pub header_injection: DetectorToggle,
    #[serde(default = "default_detector_toggle")]
    pub body_abuse: DetectorToggle,
    #[serde(default = "default_detector_toggle")]
    pub recon: DetectorToggle,
    #[serde(default = "default_detector_toggle")]
    pub brute_force: DetectorToggle,
    /// 2026-05-08 SEC-M002 — dedicated command-injection detector
    /// (`$()`, backticks, `${}`, `| cmd`, `; cmd`, etc.). Default
    /// enabled — closes a gap that AI was previously covering.
    #[serde(default = "default_detector_toggle")]
    pub command_injection: DetectorToggle,
    /// 2026-05-08 Run-5 GAP-006 — server-side template injection
    /// (Jinja2 `{{...}}`, Spring SpEL `${...}`, Freemarker `<#...>`,
    /// Velocity `#set(...)`, etc.). Default enabled.
    #[serde(default = "default_detector_toggle")]
    pub template_injection: DetectorToggle,
    /// 2026-05-08 Run-5 GAP-007 — NoSQL (MongoDB) operator
    /// injection (`?param[$ne]=foo`, `{"$where":"..."}`).
    /// Default enabled — closes a gap previously covered only
    /// by AI; closed Mongo operator vocabulary keeps FP near zero.
    #[serde(default = "default_detector_toggle")]
    pub nosql_injection: DetectorToggle,
    /// 2026-05-09 Run-5 GAP-009 — open-redirect detector.
    /// Flags suspicious external URLs (`http(s)://`,
    /// protocol-relative `//`, `javascript:`, `data:`) in known
    /// redirect-style query parameters (`?next=`, `?redirect_uri=`,
    /// etc.). Score 30 — phishing / OAuth-token-theft /
    /// CSRF-bypass tier. `allowed_domains` is an operator
    /// allowlist of safe redirect targets (literal hostnames
    /// or `*.example.com` wildcards); empty = strict mode
    /// (every external URL flags).
    #[serde(default)]
    pub open_redirect: OpenRedirectConfig,
    /// 2026-05-19 — Phase F behaviour-signals detector. Stateful
    /// per-IP signals: burst (<50 ms), missing UA, missing Referer
    /// on mutations, zero-depth first-touch. **Default OFF** because
    /// single-IP smoke tests / NAT'd egress trip it heavily. Turn
    /// on once you have real-IP traffic to score.
    #[serde(default = "default_detector_toggle_off")]
    pub behavior_signals: DetectorToggle,
    /// 2026-05-19 — Phase F cross-endpoint velocity engine.
    /// Detects login→deposit / login→withdrawal sequences tighter
    /// than 5 s. **Default ON** — zero cost when the upstream has
    /// no matching routes (it just doesn't fire).
    #[serde(default = "default_detector_toggle")]
    pub velocity: DetectorToggle,
    /// 2026-05-19 — Phase F canary recon tripwire. Fires on
    /// hits against operator-supplied honeypot paths
    /// (`cfg.risk.canary_paths`). **Default OFF**; also gated by
    /// `canary_paths` being non-empty so flipping this on alone
    /// is a no-op until you also populate the path list.
    #[serde(default = "default_detector_toggle_off")]
    pub canary: DetectorToggle,
    /// DURABLE-T2 — optional file-backed persistence for the live
    /// detector mask. When set, the proxy writes the mask state to
    /// `path` after every audit-mutated PUT and reloads from it at
    /// boot so operator toggles survive a restart. Compliance
    /// clamps re-run on load: any class the snapshot disabled but
    /// compliance now requires is forced back on with a warn log.
    /// Absent → in-memory only (legacy behaviour).
    #[serde(default)]
    pub persistence: Option<DetectorMaskPersistenceConfig>,
    /// 2026-05-17 F-CRITICAL-011 (core audit): §4 tier-policy
    /// per-tier override mask. The global toggles above are the
    /// baseline; any tier listed here overrides them for requests
    /// classified to that tier. Empty (default) means "single
    /// global policy applies to every tier".
    ///
    /// `TierDetectorMask` fields are `Option<bool>`: `Some(true)`
    /// forces the class enabled on that tier, `Some(false)` forces
    /// it disabled, and `None` inherits the global toggle.
    ///
    /// YAML shape:
    /// ```yaml
    /// detectors:
    ///   sqli: { enabled: true }
    ///   per_tier:
    ///     critical:
    ///       command_injection: true   # force on for CRITICAL
    ///       brute_force: true
    ///     low:
    ///       recon: false              # disable recon on baseline
    /// ```
    ///
    /// 2026-05-27 (Phase B detectors fold) — now **consumed**: the boot
    /// path and every config watcher build the live `MaskState` via
    /// `MaskState::from_detectors_config`, which resolves each entry here
    /// into a per-tier override (`Some(true)`/`Some(false)` force on/off,
    /// `None` inherits the base). This is the source of truth — a live
    /// override absent from this map is cleared on the next reload.
    #[serde(default)]
    pub per_tier: HashMap<Tier, TierDetectorMask>,
}

/// 2026-05-17 F-CRITICAL-011 (core audit): per-tier detector
/// override mask. Each field tri-states the corresponding detector
/// class on the bound tier: `Some(true)` = force enabled,
/// `Some(false)` = force disabled, `None` = inherit global.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierDetectorMask {
    #[serde(default)]
    pub sqli: Option<bool>,
    #[serde(default)]
    pub xss: Option<bool>,
    #[serde(default)]
    pub path_traversal: Option<bool>,
    #[serde(default)]
    pub ssrf: Option<bool>,
    #[serde(default)]
    pub header_injection: Option<bool>,
    #[serde(default)]
    pub body_abuse: Option<bool>,
    #[serde(default)]
    pub recon: Option<bool>,
    #[serde(default)]
    pub brute_force: Option<bool>,
    #[serde(default)]
    pub command_injection: Option<bool>,
    #[serde(default)]
    pub template_injection: Option<bool>,
    #[serde(default)]
    pub nosql_injection: Option<bool>,
    #[serde(default)]
    pub open_redirect: Option<bool>,
    /// 2026-05-19 — per-tier override for the Phase F
    /// behaviour-signals detector. `None` = inherit global; the
    /// global default is OFF (cf. `DetectorsConfig::default`).
    #[serde(default)]
    pub behavior_signals: Option<bool>,
    /// 2026-05-19 — per-tier override for the cross-endpoint
    /// velocity sequence engine. `None` = inherit global.
    #[serde(default)]
    pub velocity: Option<bool>,
    /// 2026-05-19 — per-tier override for the canary tripwire.
    /// `None` = inherit global. Inert without `canary_paths`.
    #[serde(default)]
    pub canary: Option<bool>,
    /// 2026-05-19 — per-tier override for the AI (ONNX) detector.
    /// Common use case: `low: { ai: false }` to skip ML inference
    /// on static-asset traffic, `critical: { ai: true }` to force
    /// it on regardless of the global toggle.
    #[serde(default)]
    pub ai: Option<bool>,
}

/// File-backed persistence config for the live detector mask.
#[derive(Clone, Debug, Deserialize)]
pub struct DetectorMaskPersistenceConfig {
    /// Snapshot file path. Atomic-replace via a sibling `.tmp`
    /// file + rename, so a crash mid-write leaves the previous
    /// snapshot intact.
    pub path: PathBuf,
}

fn default_detector_toggle() -> DetectorToggle {
    DetectorToggle {
        enabled: true,
    }
}

/// 2026-05-19 — opt-in default for detectors that are too noisy or
/// too narrowly scoped to ship on by default (`behavior_signals`,
/// `canary`). Operators turn them on explicitly per-deployment.
fn default_detector_toggle_off() -> DetectorToggle {
    DetectorToggle {
        enabled: false,
    }
}

impl Default for DetectorsConfig {
    fn default() -> Self {
        Self {
            sqli: default_detector_toggle(),
            xss: default_detector_toggle(),
            path_traversal: default_detector_toggle(),
            ssrf: default_detector_toggle(),
            header_injection: default_detector_toggle(),
            body_abuse: default_detector_toggle(),
            recon: default_detector_toggle(),
            brute_force: default_detector_toggle(),
            command_injection: default_detector_toggle(),
            template_injection: default_detector_toggle(),
            nosql_injection: default_detector_toggle(),
            open_redirect: OpenRedirectConfig::default(),
            behavior_signals: default_detector_toggle_off(),
            velocity: default_detector_toggle(),
            canary: default_detector_toggle_off(),
            persistence: None,
            per_tier: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct DetectorToggle {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// 2026-05-09 — DDoS request-flow gate config.
///
/// DDoS is **not a `Detector` trait impl** — it does not produce
/// risk-score signals via the detector chain. It's a request-flow
/// gate that sits alongside the access-list / strike-block /
/// rate-limit gates in the data plane, reading the shared
/// `StateBackend` cluster-wide auto-block list and writing TTL'd
/// blocks on per-IP burst-exceed.
///
/// `enabled` toggles the gate wholesale (default `true` — secure
/// by default, matching every other security primitive in this
/// codebase).
///
/// `observe_only` runs the gate + emits audit events but **does
/// not short-circuit the request**. Default `false` — the gate
/// enforces by default. Operators with edge cases (CDN-fronted
/// where high RPS-per-IP is normal, internal-API workloads with
/// trusted high-volume callers) can opt into shadow mode by
/// setting `observe_only: true` in YAML. Audit-event tag changes
/// from `ddos_blocked` (enforce) to `ddos_observed` (observe-only)
/// so operators can grep either way.
///
/// The threshold knobs (`per_ip_limit`, `per_ip_window_s`,
/// `block_ttl_s`, `spike_multiplier`) defaults are deliberately
/// generous (1000 req/s per IP for a 10s window, 5-minute block
/// TTL) so legitimate users never hit them. A real DDoS attacker
/// burning a single IP at >100 req/s sustained will trip in <10s
/// and earn the auto-block.
///
/// `tightened_per_ip_rps` is the per-IP cap that kicks in cluster-
/// wide once spike-mode is active (current_rps > spike_multiplier
/// × baseline_rps).
///
/// **Contract compliance** (`Hackathon_Doc/EN_waf_interop_contract_v2.3.md` §3.1):
/// volumetric abuse from a single source maps to acceptable
/// actions `rate_limit` or `block`. This gate emits
/// `X-WAF-Action: block` + HTTP 403 (the `block` action's
/// recommended response per §4). The token-bucket rate-limiter
/// at `aegis-security/src/rate_limit/` covers the `rate_limit`
/// + 429 path independently.
///
/// YAML shape:
///
/// ```yaml
/// ddos:
///   enabled: true        # default — secure by default
///   observe_only: false  # default — enforce by default
///   per_ip_limit: 1000
///   per_ip_window_s: 10
///   block_ttl_s: 300
///   spike_multiplier: 3.0
///   tightened_per_ip_rps: 20
/// ```
#[derive(Clone, Debug, Deserialize)]
pub struct DdosConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Default `false` — enforce by default. Operators opt into
    /// shadow mode explicitly via `observe_only: true`.
    #[serde(default)]
    pub observe_only: bool,
    #[serde(default = "default_ddos_per_ip_limit")]
    pub per_ip_limit: u64,
    #[serde(default = "default_ddos_per_ip_window_s")]
    pub per_ip_window_s: u32,
    #[serde(default = "default_ddos_block_ttl_s")]
    pub block_ttl_s: u64,
    #[serde(default = "default_ddos_spike_multiplier")]
    pub spike_multiplier: f64,
    #[serde(default = "default_ddos_tightened_rps")]
    pub tightened_per_ip_rps: u64,
    /// 2026-05-17 F-CRITICAL-008 (core audit): per-tier overrides
    /// for the global DDoS knobs. Any field not specified in the
    /// override falls back to the top-level value. Empty (default)
    /// means "single global policy applies to every tier".
    ///
    /// YAML shape:
    /// ```yaml
    /// ddos:
    ///   per_ip_limit: 1000
    ///   tier_overrides:
    ///     critical:
    ///       per_ip_limit: 200      # tighter for critical paths
    ///       block_ttl_s: 1800
    ///     low:
    ///       per_ip_limit: 5000     # looser for static asset paths
    /// ```
    ///
    /// Schema only — consumer wiring lands in Phase E/F.
    #[serde(default)]
    pub tier_overrides: HashMap<Tier, DdosTierConfig>,
}

/// 2026-05-17 F-CRITICAL-008 (core audit): per-tier DDoS override.
/// All fields optional — only the knobs the operator wants to
/// override against the global `DdosConfig` baseline.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DdosTierConfig {
    #[serde(default)]
    pub per_ip_limit: Option<u64>,
    #[serde(default)]
    pub per_ip_window_s: Option<u32>,
    #[serde(default)]
    pub block_ttl_s: Option<u64>,
    #[serde(default)]
    pub spike_multiplier: Option<f64>,
    #[serde(default)]
    pub tightened_per_ip_rps: Option<u64>,
}

fn default_ddos_per_ip_limit() -> u64 { 1000 }
fn default_ddos_per_ip_window_s() -> u32 { 10 }
fn default_ddos_block_ttl_s() -> u64 { 300 }
fn default_ddos_spike_multiplier() -> f64 { 3.0 }
fn default_ddos_tightened_rps() -> u64 { 20 }

impl Default for DdosConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            observe_only: false,
            per_ip_limit: default_ddos_per_ip_limit(),
            per_ip_window_s: default_ddos_per_ip_window_s(),
            block_ttl_s: default_ddos_block_ttl_s(),
            spike_multiplier: default_ddos_spike_multiplier(),
            tightened_per_ip_rps: default_ddos_tightened_rps(),
            tier_overrides: HashMap::new(),
        }
    }
}

/// 2026-05-09 Run-5 GAP-009 — open-redirect detector config.
/// `enabled` mirrors the standard `DetectorToggle.enabled` knob
/// (default `true`); `allowed_domains` is the operator allowlist
/// of safe redirect targets. Each entry is either a literal
/// hostname (`example.com`) or a `*.example.com` glob (matches
/// `foo.example.com` and `a.b.example.com`, but not bare
/// `example.com`). Empty list = strict mode (every external URL
/// in a redirect-style param flags). YAML shape:
///
/// ```yaml
/// detectors:
///   open_redirect:
///     enabled: true
///     allowed_domains:
///       - "example.com"
///       - "*.example.com"
/// ```
#[derive(Clone, Debug, Deserialize)]
pub struct OpenRedirectConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

impl Default for OpenRedirectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_domains: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Response filter (2026-05-27)
// ---------------------------------------------------------------------------

/// Response-body filter rungs. Mirrors
/// `aegis-security::pipeline::ResponseFilterConfig` so the config plane
/// can carry these toggles cluster-wide. Each field defaults to `true`
/// (safe-by-default scrubbing — matches the runtime default), so a config
/// that omits the `response_filter:` block behaves exactly as before.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseFilterConfig {
    #[serde(default = "default_true")]
    pub scrub_stack_traces: bool,
    #[serde(default = "default_true")]
    pub mask_internal_ips: bool,
    #[serde(default = "default_true")]
    pub redact_dlp: bool,
}

impl Default for ResponseFilterConfig {
    fn default() -> Self {
        Self {
            scrub_stack_traces: true,
            mask_internal_ips: true,
            redact_dlp: true,
        }
    }
}

// ---------------------------------------------------------------------------
// DLP
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Default)]
pub struct DlpConfig {
    #[serde(default)]
    pub patterns: Vec<DlpPattern>,
    #[serde(default)]
    pub fpe: Option<FpeConfig>,
    #[serde(default = "default_max_scan_bytes")]
    pub max_scan_bytes: usize,
}

fn default_max_scan_bytes() -> usize {
    2_097_152
}

#[derive(Clone, Debug, Deserialize)]
pub struct DlpPattern {
    pub id: String,
    pub regex: String,
    pub direction: DlpDir,
    pub action: DlpAction,
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DlpDir {
    Inbound,
    Outbound,
    Both,
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DlpAction {
    Redact,
    Tokenize,
    Block,
    Log,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FpeConfig {
    pub key_ref: String,
    pub version: u32,
}

// ---------------------------------------------------------------------------
// Observability
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub prometheus: PromConfig,
    #[serde(default)]
    pub otel: Option<OtelConfig>,
    #[serde(default)]
    pub access_log: AccessLogConfig,
    /// AI Operator Copilot (advisory LLM layer). Off by default; the
    /// API key is a `${secret:...}` reference resolved at boot/apply,
    /// never inline. Hot-reloadable via the config plane.
    #[serde(default)]
    pub copilot: CopilotConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PromConfig {
    #[serde(default = "default_prom_path")]
    pub path: String,
}

fn default_prom_path() -> String {
    "/metrics".into()
}

impl Default for PromConfig {
    fn default() -> Self {
        Self {
            path: default_prom_path(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct OtelConfig {
    pub endpoint: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default = "default_sample_ratio")]
    pub sample_ratio: f32,
}

fn default_sample_ratio() -> f32 {
    1.0
}

/// AI Operator Copilot provider config (advisory LLM layer).
///
/// Centralized here so the copilot is configured like every other
/// subsystem (YAML + the config plane) instead of raw `LLM_*` env. The
/// API key is **never** inline: `api_key_ref` is a `${secret:...}`
/// reference the node resolves at boot/apply (env / file / vault / cloud).
/// The config plane stores the ref un-resolved and each node resolves it
/// locally — the secret never transits the cluster doc.
#[derive(Clone, Debug, Deserialize)]
pub struct CopilotConfig {
    /// Master switch. When false the copilot is disabled regardless of
    /// the other fields (and never calls the provider).
    #[serde(default)]
    pub enabled: bool,
    /// Which adapter to build. `openai_compatible` (vLLM/Ollama/OpenAI)
    /// or `anthropic`.
    #[serde(default)]
    pub provider: CopilotProvider,
    /// Base URL for the OpenAI-compatible endpoint (`/chat/completions`
    /// is appended). Ignored by the Anthropic adapter.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Model name the endpoint serves.
    #[serde(default)]
    pub model: Option<String>,
    /// Per-request timeout in milliseconds.
    #[serde(default = "default_copilot_timeout_ms")]
    pub timeout_ms: u64,
    /// Scheduled-briefing cadence in seconds. `0` disables; the runtime
    /// floors any positive value at 60s (briefings are billable calls).
    #[serde(default)]
    pub briefing_interval_secs: u64,
    /// Secret reference for the API key, e.g.
    /// `${secret:env:LLM_API_KEY}`. Resolved at boot/apply; never stored
    /// or logged in the clear.
    #[serde(default)]
    pub api_key_ref: Option<String>,
}

fn default_copilot_timeout_ms() -> u64 {
    20_000
}

impl Default for CopilotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: CopilotProvider::default(),
            base_url: None,
            model: None,
            timeout_ms: default_copilot_timeout_ms(),
            briefing_interval_secs: 0,
            api_key_ref: None,
        }
    }
}

/// Copilot LLM adapter selector.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CopilotProvider {
    /// OpenAI-compatible `/v1/chat/completions` (vLLM, Ollama, LiteLLM,
    /// OpenAI). The default.
    #[default]
    #[serde(rename = "openai_compatible", alias = "open_ai_compatible", alias = "openai")]
    OpenAiCompatible,
    /// Anthropic Messages API.
    Anthropic,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AccessLogConfig {
    #[serde(default = "default_access_log_format")]
    pub format: AccessLogFormat,
    #[serde(default = "default_access_log_sink")]
    pub sink: AccessLogSink,
}

fn default_access_log_format() -> AccessLogFormat {
    AccessLogFormat::Json
}
fn default_access_log_sink() -> AccessLogSink {
    AccessLogSink::Stdout
}

impl Default for AccessLogConfig {
    fn default() -> Self {
        Self {
            format: default_access_log_format(),
            sink: default_access_log_sink(),
        }
    }
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AccessLogFormat {
    Combined,
    Json,
    Template(String),
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AccessLogSink {
    Stdout,
    File(PathBuf),
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct AuditConfig {
    #[serde(default)]
    pub sinks: Vec<AuditSinkConfig>,
    #[serde(default)]
    pub chain: AuditChainConfig,
    #[serde(default = "default_audit_retention", with = "humantime_serde")]
    pub retention: Duration,
    #[serde(default)]
    pub pseudonymize_ip: bool,
    /// 2026-05-17 Phase 7a — broadcast-channel capacity for the
    /// in-process `AuditBus`. Pre-fix this was a hard-coded `4096`
    /// at the boot site, which produced `Lagged(n)` drops at burst
    /// loads above ~2-3k audit events/sec (observed: 60k-RPS stress
    /// run on 2026-05-14 dropped hundreds of events per burst).
    /// Default 100_000 — ~30 seconds of headroom at 3k events/sec
    /// before any subscriber lags out. Increase for sustained
    /// high-RPS workloads with slow subscribers; decrease only on
    /// memory-constrained hosts (each slot holds one `AuditEvent`
    /// clone, ~512 bytes typical, so 100k ≈ 50 MiB).
    #[serde(default = "default_audit_bus_capacity")]
    pub bus_capacity: usize,
}

fn default_audit_retention() -> Duration {
    Duration::from_secs(90 * 24 * 3600) // 90 days
}

fn default_audit_bus_capacity() -> usize {
    100_000
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            sinks: Vec::new(),
            chain: AuditChainConfig::default(),
            retention: default_audit_retention(),
            pseudonymize_ip: false,
            bus_capacity: default_audit_bus_capacity(),
        }
    }
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditSinkConfig {
    /// File-backed NDJSON sink with daily rotation + TTL pruning.
    /// `path` is the *directory* the writer rotates into — files are
    /// named `audit-YYYY-MM-DD.ndjson`. Backwards-compatible: when the
    /// configured `path` is a regular file path, the parent directory
    /// is used and the writer rotates inside it (DURABLE-T1).
    Jsonl {
        path: PathBuf,
        /// Days to retain rotated files. Older files are pruned by a
        /// periodic background task. Default 30.
        #[serde(default = "default_audit_jsonl_retention_days")]
        retention_days: u32,
        /// Max events buffered before forcing a flush. Default 100.
        #[serde(default = "default_audit_jsonl_max_batch")]
        max_batch: usize,
        /// Max time between forced flushes, even if the batch isn't
        /// full. Default 1 s. Keeps disk writes shaped — never on
        /// the data-plane hot path.
        #[serde(default = "default_audit_jsonl_flush_interval", with = "humantime_serde")]
        flush_interval: Duration,
    },
    /// HACK-T5 — RFC 5424 / CEF audit forwarder. Streams every
    /// `AuditEvent` from the broadcast bus to a remote syslog or
    /// CEF receiver in a fire-and-forget fashion (data-plane
    /// hot path never blocks on network I/O — the background task
    /// is a dedicated subscriber).
    ///
    /// `address` is `host:port` — UDP datagram endpoint or TCP
    /// stream. `transport` defaults to `udp`. `format` defaults
    /// to `rfc5424`; `cef` emits ArcSight Common Event Format
    /// for SIEMs that prefer that envelope.
    Syslog {
        address: String,
        #[serde(default)]
        transport: SyslogTransport,
        #[serde(default)]
        format: SyslogFormat,
        /// Syslog facility (RFC 5424). Defaults to 10 (security/auth).
        #[serde(default = "default_syslog_facility")]
        facility: u8,
        /// Application name reported in the RFC 5424 header.
        #[serde(default = "default_syslog_app_name")]
        app_name: String,
        /// HACK-T5 TLS — optional CA bundle for the syslog
        /// receiver's server certificate. PEM file containing
        /// one or more trust anchors. `None` falls back to
        /// the webpki system roots — appropriate when the
        /// receiver is behind a public CA (Let's Encrypt
        /// etc.). Required when the receiver presents a
        /// private CA. Ignored when `transport != tls`.
        #[serde(default)]
        ca_bundle: Option<PathBuf>,
        /// HACK-T5 TLS — SNI / cert-validation hostname.
        /// Defaults to the host part of `address` (typical
        /// for endpoints accessed via DNS); set explicitly
        /// when the receiver's cert CN/SAN doesn't match
        /// the connect address (e.g. routing through a
        /// load balancer). Ignored when `transport != tls`.
        #[serde(default)]
        server_name: Option<String>,
    },
    Splunk { endpoint: String, token_ref: String },
    Kafka { brokers: Vec<String>, topic: String },
}

fn default_audit_jsonl_retention_days() -> u32 {
    30
}

fn default_audit_jsonl_max_batch() -> usize {
    100
}

fn default_audit_jsonl_flush_interval() -> Duration {
    Duration::from_secs(1)
}

/// HACK-T5 — supported syslog transport. UDP is the default
/// (RFC 5426 datagram); TCP is RFC 6587 octet-counting framing
/// (no octet-counting prefix in this slice — newline-terminated
/// is widely supported and simpler). TLS wraps TCP in
/// `tokio_rustls` so syslog payloads cross untrusted networks
/// (cloud → on-prem SIEM, multi-region → central log lake)
/// without exposing the audit stream.
#[derive(Copy, Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyslogTransport {
    #[default]
    Udp,
    Tcp,
    Tls,
}

/// HACK-T5 — supported syslog message format.
#[derive(Copy, Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyslogFormat {
    /// RFC 5424 `<PRI>1 TS HOST APP PROCID MSGID STRUCTURED MSG`
    /// with the audit event JSON in the MSG slot.
    #[default]
    Rfc5424,
    /// ArcSight Common Event Format —
    /// `CEF:0|Vendor|Product|Version|EventClassID|Name|Severity|<extension>`.
    Cef,
}

fn default_syslog_facility() -> u8 {
    10 // security/auth
}

fn default_syslog_app_name() -> String {
    "aegis-waf".into()
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuditChainConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub witness: Option<WitnessConfig>,
}

impl Default for AuditChainConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            witness: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct WitnessConfig {
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    pub destination: PathBuf,
    #[serde(default)]
    pub signer_ref: Option<String>,
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct AdminConfig {
    #[serde(default = "default_admin_bind")]
    pub bind: SocketAddr,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub dashboard_auth: DashboardAuthConfig,
    #[serde(default)]
    pub dashboard: DashboardConfig,
    /// Deployment environment label rendered on the dashboard topbar
    /// (e.g. `prod`, `staging`, `dev`). Optional — when absent the
    /// topbar shows an em-dash placeholder.
    #[serde(default)]
    pub environment: Option<String>,
}

fn default_admin_bind() -> SocketAddr {
    "127.0.0.1:9443".parse().unwrap()
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            bind: default_admin_bind(),
            tls: None,
            dashboard_auth: DashboardAuthConfig::default(),
            dashboard: DashboardConfig::default(),
            environment: None,
        }
    }
}

/// Dashboard-shell configuration (D-M1-T1.6).
///
/// Dashboard-level admin config. The legacy-shell flag was removed
/// in D-M6-T6.9; the struct is retained so existing `dashboard:`
/// blocks in `waf.yaml` still parse cleanly (back-compat). The
/// `legacy_shell` field is now `#[serde(default)]` and unused —
/// operators previously running with `legacy_shell: true` should
/// drop the field on their next config edit.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct DashboardConfig {
    /// Deprecated as of D-M6-T6.9. Ignored.
    #[serde(default, alias = "legacy_shell")]
    pub legacy_shell: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DashboardAuthConfig {
    #[serde(default)]
    pub password_hash_ref: String,
    #[serde(default)]
    pub csrf_secret_ref: String,
    #[serde(default = "default_session_idle", with = "humantime_serde")]
    pub session_ttl_idle: Duration,
    #[serde(default = "default_session_absolute", with = "humantime_serde")]
    pub session_ttl_absolute: Duration,
    #[serde(default = "default_ip_allowlist")]
    pub ip_allowlist: Vec<ipnet::IpNet>,
    #[serde(default)]
    pub totp_enabled: bool,
    /// 2026-05-17 F-CRITICAL-003 — base32-encoded TOTP shared secret
    /// for the configured admin user. Required when `totp_enabled =
    /// true`; ignored otherwise. The b32 encoding matches what
    /// authenticator apps consume from the `otpauth://` provisioning
    /// URI returned by `crate::admin_auth::totp::provisioning_uri`.
    /// Empty string when unset. See `docs/operator/admin-auth-setup.md`
    /// for the enrollment flow (YAML-only in v1).
    #[serde(default)]
    pub totp_secret_b32: String,
    /// 2026-05-17 F-CRITICAL-002 (Phase 3 step 4) — service-account
    /// bearer tokens. Used by CI / cron / Nagios-shaped automation
    /// that can't login interactively. Each account has:
    /// - `name`: human-readable identifier, becomes `actor` on
    ///   audit-mutated changes.
    /// - `token_hash`: argon2id hash of the bearer token (mint via
    ///   `waf admin service-account mint` — follow-up CLI).
    /// - `scopes`: `["read"]` allows GET only; `["read", "write"]`
    ///   allows mutations.
    /// Bearer requests send `Authorization: Bearer <plaintext>`;
    /// middleware argon2-verifies and synthesises a per-request
    /// session. See `docs/operator/admin-auth-setup.md`.
    #[serde(default)]
    pub service_accounts: Vec<ServiceAccountConfig>,
    #[serde(default)]
    pub login_rate_limit: LoginRateLimitConfig,
    #[serde(default)]
    pub lockout: LockoutConfig,
    /// MTLS-T10 — when `true`, the dashboard exposes a card on
    /// the Settings page that lets operators validate-and-preview
    /// (and, in a future phase, hot-swap) a CA bundle without
    /// editing YAML. **Default `false`** — many operators run
    /// trust anchors through GitOps and don't want them mutable
    /// from a browser. Flip to `true` only when the dashboard
    /// is the canonical source of truth for the bundle.
    #[serde(default)]
    pub allow_ca_upload: bool,
    /// 2026-05-17 F-HIGH-admin sub-finding: pre-fix every admin
    /// mutation handler did `req.into_body().collect()` without
    /// any cap, so a single oversized `Content-Length: 1GB`
    /// payload from a (typo-ed allowlist or stolen-credential)
    /// client would buffer the whole gigabyte into RAM before
    /// the JSON parser rejected it. Admin payloads are small
    /// JSON (config blobs, rule definitions, allowlist entries);
    /// 1 MiB is a generous cap. Enforced as a `Content-Length`
    /// pre-check inside `admin_auth_middleware::admit` so the
    /// 30+ existing `into_body().collect()` call sites don't
    /// need surgery. Streaming / chunked-without-length bodies
    /// bypass the Content-Length gate; that gap is documented
    /// in `plans/future/unwired-stubs-catalog.md` (admin body
    /// streaming cap) and tracked as a follow-up.
    #[serde(default = "default_admin_max_body_bytes")]
    pub max_request_body_bytes: u64,
}

fn default_session_idle() -> Duration {
    Duration::from_secs(1800)
}
fn default_session_absolute() -> Duration {
    Duration::from_secs(28800)
}
fn default_ip_allowlist() -> Vec<ipnet::IpNet> {
    vec![
        "127.0.0.1/32".parse().unwrap(),
        "::1/128".parse().unwrap(),
    ]
}

fn default_admin_max_body_bytes() -> u64 {
    1024 * 1024 // 1 MiB — admin payloads are small JSON.
}

impl Default for DashboardAuthConfig {
    fn default() -> Self {
        Self {
            password_hash_ref: String::new(),
            csrf_secret_ref: String::new(),
            session_ttl_idle: default_session_idle(),
            session_ttl_absolute: default_session_absolute(),
            ip_allowlist: default_ip_allowlist(),
            totp_enabled: false,
            totp_secret_b32: String::new(),
            service_accounts: Vec::new(),
            login_rate_limit: LoginRateLimitConfig::default(),
            lockout: LockoutConfig::default(),
            allow_ca_upload: false,
            max_request_body_bytes: default_admin_max_body_bytes(),
        }
    }
}

/// 2026-05-17 F-CRITICAL-002 (Phase 3 step 4) — see
/// `DashboardAuthConfig.service_accounts` for the full doc.
#[derive(Clone, Debug, Deserialize)]
pub struct ServiceAccountConfig {
    pub name: String,
    pub token_hash: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LoginRateLimitConfig {
    #[serde(default)]
    pub per_ip: RateCap,
    #[serde(default)]
    pub per_user: RateCap,
}

impl Default for LoginRateLimitConfig {
    fn default() -> Self {
        Self {
            per_ip: RateCap {
                limit: 5,
                window: Duration::from_secs(60),
            },
            per_user: RateCap {
                limit: 10,
                window: Duration::from_secs(900),
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct RateCap {
    #[serde(default = "default_rate_cap_limit")]
    pub limit: u32,
    #[serde(default = "default_rate_cap_window", with = "humantime_serde")]
    pub window: Duration,
}

fn default_rate_cap_limit() -> u32 {
    5
}
fn default_rate_cap_window() -> Duration {
    Duration::from_secs(60)
}

impl Default for RateCap {
    fn default() -> Self {
        Self {
            limit: default_rate_cap_limit(),
            window: default_rate_cap_window(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct LockoutConfig {
    #[serde(default = "default_lockout_threshold")]
    pub threshold: u32,
    #[serde(default = "default_lockout_window", with = "humantime_serde")]
    pub window: Duration,
    #[serde(default = "default_lockout_duration", with = "humantime_serde")]
    pub duration: Duration,
}

fn default_lockout_threshold() -> u32 {
    10
}
fn default_lockout_window() -> Duration {
    Duration::from_secs(900)
}
fn default_lockout_duration() -> Duration {
    Duration::from_secs(900)
}

impl Default for LockoutConfig {
    fn default() -> Self {
        Self {
            threshold: default_lockout_threshold(),
            window: default_lockout_window(),
            duration: default_lockout_duration(),
        }
    }
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct ComplianceProfile {
    #[serde(default)]
    pub modes: Vec<ComplianceMode>,
    #[serde(default)]
    pub min_tls_version: Option<String>,
    #[serde(default)]
    pub disallow_algorithms: Vec<String>,
    #[serde(default)]
    pub pii_pseudonymize: bool,
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceMode {
    Fips,
    Pci,
    Soc2,
    Gdpr,
    Hipaa,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_config_parses_challenges_enabled_and_flattens_overrides() {
        // 2026-05-25 — `challenges_enabled` must be a recognized config key
        // (previously absent → silently ignored) and flow into the boot-time
        // TierStore seed via `challenges_enabled_overrides()`.
        let yaml = r#"
critical: { risk_threshold: 50, challenges_enabled: true }
high:     { risk_threshold: 60, challenges_enabled: true }
medium:   { risk_threshold: 70 }
low:      { risk_threshold: 80, challenges_enabled: false }
"#;
        let tiers: TiersConfig = serde_yaml::from_str(yaml).unwrap();
        let mut ce = tiers.challenges_enabled_overrides();
        ce.sort();
        // `medium` omitted the toggle → not present (keeps store default).
        assert_eq!(ce, vec![("critical", true), ("high", true), ("low", false)]);
        // The existing risk_threshold seeding is unaffected.
        assert_eq!(tiers.high.unwrap().risk_threshold, 60);
    }

    #[tokio::test]
    async fn config_broadcast_sends_and_receives() {
        let (tx, mut rx) = tokio::sync::broadcast::channel::<ConfigEvent>(16);
        tx.send(ConfigEvent::Reloaded { version: 1 }).unwrap();
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, ConfigEvent::Reloaded { version: 1 }));
    }

    #[tokio::test]
    async fn config_broadcast_failure_event() {
        let (tx, mut rx) = tokio::sync::broadcast::channel::<ConfigEvent>(16);
        tx.send(ConfigEvent::Failed {
            error: "bad yaml".into(),
        })
        .unwrap();
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, ConfigEvent::Failed { .. }));
    }

    #[test]
    fn minimal_waf_config_deserializes() {
        let yaml = r#"
listeners:
  data:
    - bind: "0.0.0.0:443"
  admin:
    bind: "127.0.0.1:9443"

routes:
  - id: catch-all
    path: "/"
    upstream: default

upstreams:
  default:
    members:
      - addr: "127.0.0.1:8080"

state:
  backend: in_memory
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.routes[0].id, "catch-all");
        assert!(cfg.upstreams.contains_key("default"));
        assert_eq!(cfg.state.backend, StateBackendKind::InMemory);
    }

    #[test]
    fn route_defaults() {
        let yaml = r#"
id: api
path: "/api"
upstream: backend
"#;
        let route: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(route.match_type, MatchType::Prefix);
        assert!(route.methods.is_none());
        assert!(route.tier_override.is_none());
    }

    #[test]
    fn route_with_tier_override() {
        let yaml = r#"
id: login
path: "/login"
upstream: auth
tier_override: critical
methods: [POST]
"#;
        let route: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(route.tier_override, Some(Tier::Critical));
        assert_eq!(route.methods.as_ref().unwrap(), &["POST"]);
    }

    #[test]
    fn pool_config_defaults() {
        let yaml = r#"
members:
  - addr: "10.0.0.1:80"
"#;
        let pool: PoolConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(pool.lb, LbStrategy::RoundRobin);
        assert_eq!(pool.members[0].weight, 1);
        assert!(pool.health.is_none());
    }

    #[test]
    fn state_config_redis() {
        let yaml = r#"
backend: redis
redis:
  urls: ["redis://127.0.0.1:6379"]
  cluster: false
"#;
        let state: StateConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(state.backend, StateBackendKind::Redis);
        let redis = state.redis.unwrap();
        assert_eq!(redis.urls.len(), 1);
        assert!(!redis.cluster);
        assert_eq!(redis.pool_size, 16);
    }

    #[test]
    fn risk_config_defaults() {
        // 2026-05-17 (F-CRITICAL-007): bumped 40/80 → 30/70 to
        // match the v2.3 spec defaults that `RiskEngine::classify`
        // already hardcoded. Pre-fix the two sources disagreed
        // out of the box.
        let cfg = RiskConfig::default();
        assert_eq!(cfg.thresholds.challenge_at, 30);
        assert_eq!(cfg.thresholds.block_at, 70);
        assert_eq!(cfg.thresholds.max, 100);
        assert_eq!(cfg.decay_half_life, Duration::from_secs(300));
    }

    #[test]
    fn detectors_config_defaults_all_enabled() {
        let cfg = DetectorsConfig::default();
        assert!(cfg.sqli.enabled);
        assert!(cfg.xss.enabled);
        assert!(cfg.path_traversal.enabled);
        assert!(cfg.ssrf.enabled);
    }

    #[test]
    fn admin_config_defaults() {
        let cfg = AdminConfig::default();
        assert_eq!(cfg.bind, "127.0.0.1:9443".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.dashboard_auth.session_ttl_idle, Duration::from_secs(1800));
        assert_eq!(cfg.dashboard_auth.session_ttl_absolute, Duration::from_secs(28800));
        assert_eq!(cfg.dashboard_auth.ip_allowlist.len(), 2);
        assert!(!cfg.dashboard_auth.totp_enabled);
        // D-M1-T1.6: legacy_shell is opt-in, default false.
        assert!(!cfg.dashboard.legacy_shell);
    }

    #[test]
    fn admin_config_accepts_dashboard_block() {
        // serde(default) keeps existing waf.yaml files working when
        // the new key is absent; explicit values override.
        let yaml = r#"
bind: "127.0.0.1:9443"
dashboard:
  legacy_shell: true
"#;
        let cfg: AdminConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.dashboard.legacy_shell);
    }

    #[test]
    fn admin_config_works_without_dashboard_block() {
        // Backward compatibility: existing configs that don't mention
        // `dashboard:` must still parse and pick up the default.
        let yaml = r#"bind: "127.0.0.1:9443""#;
        let cfg: AdminConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!cfg.dashboard.legacy_shell);
    }

    #[test]
    fn admin_config_environment_defaults_to_none() {
        let cfg = AdminConfig::default();
        assert!(cfg.environment.is_none());
    }

    #[test]
    fn admin_config_accepts_environment() {
        let yaml = r#"
bind: "127.0.0.1:9443"
environment: "prod"
"#;
        let cfg: AdminConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.environment.as_deref(), Some("prod"));
    }

    #[test]
    fn lockout_config_defaults() {
        let cfg = LockoutConfig::default();
        assert_eq!(cfg.threshold, 10);
        assert_eq!(cfg.window, Duration::from_secs(900));
        assert_eq!(cfg.duration, Duration::from_secs(900));
    }

    #[test]
    fn compliance_mode_deserialize() {
        let yaml = r#"
modes: [fips, pci, hipaa]
pii_pseudonymize: true
"#;
        let cp: ComplianceProfile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cp.modes.len(), 3);
        assert_eq!(cp.modes[0], ComplianceMode::Fips);
        assert!(cp.pii_pseudonymize);
    }

    #[test]
    fn dlp_pattern_deserializes() {
        let yaml = r#"
id: credit-card
regex: '\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'
direction: outbound
action: redact
"#;
        let p: DlpPattern = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(p.id, "credit-card");
        assert_eq!(p.direction, DlpDir::Outbound);
        assert_eq!(p.action, DlpAction::Redact);
    }

    #[test]
    fn rate_limit_rule_deserializes() {
        let yaml = r#"
id: global-ip
scope: global
key: ip
algo: sliding_window
limit: 100
window: "1m"
"#;
        let rule: RateLimitRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.id, "global-ip");
        assert_eq!(rule.scope, RlScope::Global);
        assert_eq!(rule.key, RlKey::Ip);
        assert_eq!(rule.algo, RlAlgo::SlidingWindow);
        assert_eq!(rule.limit, 100);
        assert_eq!(rule.window, Duration::from_secs(60));
    }

    #[test]
    fn audit_sink_config_jsonl() {
        let yaml = r#"
!jsonl
path: /var/log/waf/audit.jsonl
"#;
        let sink: AuditSinkConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(sink, AuditSinkConfig::Jsonl { .. }));
    }

    #[test]
    fn access_log_format_defaults_to_json() {
        let cfg = AccessLogConfig::default();
        assert_eq!(cfg.format, AccessLogFormat::Json);
        assert_eq!(cfg.sink, AccessLogSink::Stdout);
    }

    // -----------------------------------------------------------------------
    // load_config (figment) tests
    // -----------------------------------------------------------------------

    #[test]
    fn load_config_round_trip_waf_yaml() {
        let path = std::path::Path::new("../../config/prod.yaml");
        if path.exists() {
            let cfg = super::load_config(path).unwrap();
            assert!(!cfg.routes.is_empty());
            assert!(cfg.upstreams.contains_key("backend-pool"));
            assert!(!cfg.listeners.data.is_empty());
            cfg.validate().unwrap();
        }
    }

    #[test]
    fn load_config_round_trip_dev_yaml() {
        // The dev config covers both day-to-day development AND the
        // k6 load-test layer (tests/load/*.js). Schema drift here
        // breaks the whole test harness.
        let path = std::path::Path::new("../../config/dev.yaml");
        if path.exists() {
            let cfg = super::load_config(path)
                .unwrap_or_else(|e| panic!("dev.yaml must parse: {e}"));
            cfg.validate()
                .unwrap_or_else(|e| panic!("dev.yaml must validate: {e}"));

            // k6 load-test invariants — `loadmode-degradation.js`
            // stages assert these exact values.
            assert_eq!(
                cfg.load_mode.elevated_rps, 500,
                "loadmode-degradation.js stage B expects elevated_rps=500",
            );
            assert_eq!(
                cfg.load_mode.critical_rps, 2_000,
                "loadmode-degradation.js stage C expects critical_rps=2000",
            );
            // Post-2026-05 refactor: dev.yaml uses Redis state by
            // default (matches prod profiles) so the dev experience
            // mirrors production. Test harness configs that need
            // self-contained state live under
            // `tests/hackathon/configs/*` and override there.
            assert_eq!(
                cfg.state.backend,
                StateBackendKind::Redis,
                "dev config uses Redis state — matches the 3 prod profiles",
            );
            assert!(
                cfg.compliance.is_none(),
                "dev config must not pin compliance modes — \
                 detector toggle tests would be clamped",
            );
            let strikes = cfg.risk.strikes.as_ref().expect(
                "dev config must declare risk.strikes for risk-strikes.js",
            );
            // Strike threshold raised to 1M for shared-IP synthetic
            // load (`make mock-load`). Real attackers fan out across
            // many IPs in production; the threshold is per-IP.
            assert_eq!(
                strikes.block_at, 1_000_000,
                "shared-IP-friendly tweak — `make mock-load` puts \
                 legit + attacker traffic on 127.0.0.1",
            );
            assert!(
                cfg.risk.trust_recovery.is_some(),
                "dev config must enable trust recovery (P6)",
            );
            assert!(
                cfg.admin.dashboard_auth.password_hash_ref
                    .starts_with("$argon2id$"),
                "admin password must be a real argon2id hash, \
                 not a `${{secret:env:…}}` reference",
            );
        }
    }

    #[test]
    fn load_config_missing_file_returns_error() {
        let result = super::load_config(std::path::Path::new("/nonexistent/waf.yaml"));
        assert!(result.is_err());
    }

    #[test]
    fn load_config_invalid_yaml_returns_error() {
        let dir = std::env::temp_dir();
        let path = dir.join("aegis_test_bad_config.yaml");
        std::fs::write(&path, "not: [valid: yaml: config").unwrap();
        let result = super::load_config(&path);
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }

    // -----------------------------------------------------------------------
    // load_config_str tests
    // -----------------------------------------------------------------------

    fn minimal_yaml() -> &'static str {
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
    }

    #[test]
    fn load_config_str_valid() {
        let cfg = super::load_config_str(minimal_yaml()).unwrap();
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.routes[0].id, "catch-all");
        assert!(cfg.upstreams.contains_key("default"));
    }

    // 2026-05-27 (Phase B rules fold) — cfg.rules.inline carries the
    // persistent dashboard rule list ({id, body, enabled}).
    #[test]
    fn load_config_str_parses_inline_rules() {
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
      - addr: "127.0.0.1:9000"
state:
  backend: in_memory
rules:
  inline:
    - id: custom-1
      body: "rule custom-1 { allow }"
      enabled: true
    - id: custom-2
      body: "rule custom-2 { allow }"
      enabled: false
"#;
        let cfg = super::load_config_str(yaml).unwrap();
        assert_eq!(cfg.rules.inline.len(), 2);
        assert_eq!(cfg.rules.inline[0].id, "custom-1");
        assert_eq!(cfg.rules.inline[0].body, "rule custom-1 { allow }");
        assert!(cfg.rules.inline[0].enabled);
        assert!(!cfg.rules.inline[1].enabled);
    }

    #[test]
    fn rules_inline_defaults_empty() {
        let cfg = super::load_config_str(minimal_yaml()).unwrap();
        assert!(cfg.rules.inline.is_empty());
    }

    // -----------------------------------------------------------------------
    // validate() tests
    // -----------------------------------------------------------------------

    // 2026-05-11 PROXY-02 — regex / glob routes must be rejected
    // at validate() time because the resolver only supports
    // prefix lookup today; without this guard, operators ship
    // routes that never fire.
    #[test]
    fn validate_rejects_match_type_regex() {
        let yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: api-v1
    path: "/api/v[0-9]+"
    match_type: regex
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:9000"
state:
  backend: in_memory
"#;
        let err = super::load_config_str(yaml).expect_err("regex routes must fail validate");
        let msg = format!("{err:?}");
        assert!(msg.contains("regex"), "got: {msg}");
        assert!(msg.contains("not implemented"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_match_type_glob() {
        let yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: api-glob
    path: "/api/*"
    match_type: glob
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:9000"
state:
  backend: in_memory
"#;
        let err = super::load_config_str(yaml).expect_err("glob routes must fail validate");
        let msg = format!("{err:?}");
        assert!(msg.contains("glob"), "got: {msg}");
        assert!(msg.contains("not implemented"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_empty_listeners() {
        let yaml = r#"
listeners:
  data: []
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
"#;
        let result = super::load_config_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("listeners.data must contain at least one entry"));
    }

    #[test]
    fn validate_rejects_empty_routes() {
        let yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes: []
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#;
        let result = super::load_config_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("routes must contain at least one route"));
    }

    #[test]
    fn validate_rejects_empty_upstreams() {
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
upstreams: {}
state:
  backend: in_memory
"#;
        let result = super::load_config_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("upstreams must contain at least one pool"));
    }

    #[test]
    fn validate_rejects_unknown_upstream_ref() {
        let yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: nonexistent
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#;
        let result = super::load_config_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown upstream 'nonexistent'"));
    }

    #[test]
    fn validate_rejects_empty_pool_members() {
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
    members: []
state:
  backend: in_memory
"#;
        let result = super::load_config_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("must have at least one member"));
    }

    // ---------- Connection pool config (UP-T1) -------------------------

    #[test]
    fn connection_pool_default_pools_idle_conns() {
        let c = ConnectionPoolConfig::default();
        assert_eq!(c.max_idle_per_host, 32);
        assert_eq!(c.idle_timeout.as_secs(), 30);
        assert!(c.keep_alive);
    }

    #[test]
    fn pool_config_yaml_defaults_present() {
        // No `connection:` block → defaults populated.
        let yaml = r#"
listeners:
  data: [{ bind: "127.0.0.1:8080" }]
  admin: { bind: "127.0.0.1:9443" }
routes:
  - { id: catch-all, path: "/", upstream: default }
upstreams:
  default:
    members: [{ addr: "127.0.0.1:8081" }]
state: { backend: in_memory }
"#;
        let cfg = load_config_str(yaml).unwrap();
        let pool = cfg.upstreams.get("default").unwrap();
        assert_eq!(pool.connection.max_idle_per_host, 32);
        assert!(pool.connection.keep_alive);
    }

    #[test]
    fn pool_config_yaml_accepts_explicit_block() {
        let yaml = r#"
listeners:
  data: [{ bind: "127.0.0.1:8080" }]
  admin: { bind: "127.0.0.1:9443" }
routes:
  - { id: catch-all, path: "/", upstream: default }
upstreams:
  default:
    members: [{ addr: "127.0.0.1:8081" }]
    connection:
      max_idle_per_host: 64
      idle_timeout: 90s
      keep_alive: false
state: { backend: in_memory }
"#;
        let cfg = load_config_str(yaml).unwrap();
        let pool = cfg.upstreams.get("default").unwrap();
        assert_eq!(pool.connection.max_idle_per_host, 64);
        assert_eq!(pool.connection.idle_timeout.as_secs(), 90);
        assert!(!pool.connection.keep_alive);
    }

    #[test]
    fn pool_config_zero_max_idle_disables_pooling() {
        // 0 = pre-UP-T1 behaviour, useful for debugging perf.
        let yaml = r#"
listeners:
  data: [{ bind: "127.0.0.1:8080" }]
  admin: { bind: "127.0.0.1:9443" }
routes:
  - { id: catch-all, path: "/", upstream: default }
upstreams:
  default:
    members: [{ addr: "127.0.0.1:8081" }]
    connection:
      max_idle_per_host: 0
state: { backend: in_memory }
"#;
        let cfg = load_config_str(yaml).unwrap();
        let pool = cfg.upstreams.get("default").unwrap();
        assert_eq!(pool.connection.max_idle_per_host, 0);
    }

    // ---------- Runtime / workers config (Layer-1 scaling) -------------

    fn good_cfg_with_runtime(runtime_yaml: &str) -> String {
        format!(
            r#"
listeners:
  data: [{{ bind: "0.0.0.0:8080" }}]
  admin: {{ bind: "127.0.0.1:9443" }}
routes:
  - {{ id: catch-all, path: "/", upstream: default }}
upstreams:
  default: {{ members: [{{ addr: "127.0.0.1:8081" }}] }}
state: {{ backend: in_memory }}
runtime:
{runtime_yaml}
"#
        )
    }

    #[test]
    fn runtime_default_is_auto_workers() {
        let cfg = RuntimeConfig::default();
        assert!(matches!(cfg.workers, Workers::Auto));
        assert_eq!(cfg.blocking_threads, 512);
        assert_eq!(cfg.stack_size_kb, 2048);
        assert!(!cfg.cpu_affinity);
    }

    #[test]
    fn workers_auto_resolves_to_at_least_two() {
        let n = Workers::Auto.resolve();
        assert!(n >= 2, "Auto must lift to >= 2 even on single-core hosts");
    }

    #[test]
    fn workers_fixed_resolves_to_value() {
        assert_eq!(Workers::Fixed(8).resolve(), 8);
    }

    #[test]
    fn runtime_yaml_accepts_auto_string() {
        let yaml = "  workers: auto";
        let cfg = load_config_str(&good_cfg_with_runtime(yaml)).unwrap();
        assert!(matches!(cfg.runtime.workers, Workers::Auto));
    }

    #[test]
    fn runtime_yaml_accepts_integer() {
        let yaml = "  workers: 4";
        let cfg = load_config_str(&good_cfg_with_runtime(yaml)).unwrap();
        match cfg.runtime.workers {
            Workers::Fixed(n) => assert_eq!(n, 4),
            other => panic!("expected Fixed(4), got {other:?}"),
        }
    }

    #[test]
    fn runtime_yaml_rejects_zero() {
        let yaml = "  workers: 0";
        let err = load_config_str(&good_cfg_with_runtime(yaml)).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("workers"), "got {msg}");
    }

    #[test]
    fn runtime_validate_rejects_workers_below_two() {
        let cfg = RuntimeConfig {
            workers: Workers::Fixed(1),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("workers must be >= 2"));
    }

    #[test]
    fn runtime_validate_rejects_huge_workers() {
        let cfg = RuntimeConfig {
            workers: Workers::Fixed(513),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("<= 512"));
    }

    #[test]
    fn runtime_validate_rejects_zero_blocking() {
        let cfg = RuntimeConfig {
            blocking_threads: 0,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("blocking_threads must be > 0"));
    }

    #[test]
    fn runtime_validate_rejects_huge_blocking() {
        let cfg = RuntimeConfig {
            blocking_threads: 5000,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("<= 4096"));
    }

    #[test]
    fn runtime_validate_rejects_tiny_stack() {
        let cfg = RuntimeConfig {
            stack_size_kb: 32,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("stack_size_kb"));
    }

    #[test]
    fn runtime_validate_accepts_default() {
        RuntimeConfig::default().validate().unwrap();
    }

    #[test]
    fn runtime_full_yaml_round_trip() {
        let yaml = r#"  workers: 16
  blocking_threads: 256
  cpu_affinity: true
  stack_size_kb: 4096"#;
        let cfg = load_config_str(&good_cfg_with_runtime(yaml)).unwrap();
        match cfg.runtime.workers {
            Workers::Fixed(16) => {}
            other => panic!("expected Fixed(16), got {other:?}"),
        }
        assert_eq!(cfg.runtime.blocking_threads, 256);
        assert!(cfg.runtime.cpu_affinity);
        assert_eq!(cfg.runtime.stack_size_kb, 4096);
    }

    // ---------- P4 TLS hardening + force-https + HSTS validation -------

    fn good_cfg_with_tls(tls_yaml: &str) -> String {
        format!(
            r#"
listeners:
  data: [{{ bind: "0.0.0.0:443" }}]
  admin: {{ bind: "127.0.0.1:9443" }}
routes:
  - {{ id: catch-all, path: "/", upstream: default }}
upstreams:
  default: {{ members: [{{ addr: "127.0.0.1:8080" }}] }}
state: {{ backend: in_memory }}
tls:
{tls_yaml}
"#
        )
    }

    #[test]
    fn tls_min_version_accepts_supported_versions() {
        for v in ["1.2", "1.3"] {
            let yaml = good_cfg_with_tls(&format!("  min_version: \"{v}\"\n"));
            let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
            cfg.validate().unwrap_or_else(|e| panic!("expected ok for {v}: {e}"));
        }
    }

    #[test]
    fn tls_min_version_rejects_legacy_versions() {
        for v in ["1.0", "1.1", "ssl3", ""] {
            let yaml = good_cfg_with_tls(&format!("  min_version: \"{v}\"\n"));
            let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
            let err = cfg.validate().unwrap_err().to_string();
            assert!(
                err.contains("tls.min_version"),
                "expected validation error for {v}, got: {err}"
            );
        }
    }

    #[test]
    fn tls_hsts_max_age_zero_rejected() {
        let yaml = good_cfg_with_tls("  hsts: { max_age: 0 }\n");
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("max_age must be > 0"));
    }

    #[test]
    fn tls_hsts_preload_requires_one_year_max_age() {
        let yaml = good_cfg_with_tls(
            "  hsts: { max_age: 86400, include_subdomains: true, preload: true }\n",
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("preload requires max_age >= 31536000"));
    }

    #[test]
    fn tls_hsts_preload_requires_include_subdomains() {
        let yaml = good_cfg_with_tls(
            "  hsts: { max_age: 31536000, include_subdomains: false, preload: true }\n",
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("preload requires include_subdomains"));
    }

    #[test]
    fn tls_hsts_default_passes_validation() {
        let yaml = good_cfg_with_tls("  hsts: {}\n");
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let hsts = cfg.tls.unwrap().hsts.unwrap();
        assert_eq!(hsts.max_age, 31_536_000);
        assert!(hsts.include_subdomains);
        assert!(!hsts.preload);
    }

    // ---------- MTLS-T1 client_auth schema --------------------------------

    #[test]
    fn client_auth_absent_keeps_default_disabled_behaviour() {
        let yaml = good_cfg_with_tls("  certificates: []\n");
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.tls.unwrap().client_auth.is_none());
    }

    #[test]
    fn client_auth_disabled_mode_does_not_require_ca_bundle() {
        // Operators staging a future enable can populate
        // allowed_sans / apply_to with mode: disabled to
        // pre-build the cfg without yet requesting client certs.
        let yaml = good_cfg_with_tls(
            "  client_auth:\n    mode: disabled\n    allowed_sans: [admin@aegis.local]\n",
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let ca = cfg.tls.unwrap().client_auth.unwrap();
        assert_eq!(ca.mode, ClientAuthMode::Disabled);
        assert_eq!(ca.allowed_sans, vec!["admin@aegis.local".to_string()]);
        // apply_to default kicks in even when populated by the
        // serde default function.
        assert_eq!(ca.apply_to, vec![ClientAuthScope::Admin]);
    }

    #[test]
    fn client_auth_optional_mode_round_trips() {
        let yaml = good_cfg_with_tls(
            "  client_auth:\n    mode: optional\n    ca_bundle: /etc/aegis/admin-ca.pem\n",
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let ca = cfg.tls.unwrap().client_auth.unwrap();
        assert_eq!(ca.mode, ClientAuthMode::Optional);
        assert_eq!(
            ca.ca_bundle.as_ref().unwrap().to_string_lossy(),
            "/etc/aegis/admin-ca.pem",
        );
    }

    #[test]
    fn client_auth_required_mode_round_trips() {
        let yaml = good_cfg_with_tls(
            "  client_auth:\n    mode: required\n    ca_bundle: /etc/aegis/admin-ca.pem\n    allowed_sans:\n      - admin@aegis.local\n      - ops@aegis.local\n",
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let ca = cfg.tls.unwrap().client_auth.unwrap();
        assert_eq!(ca.mode, ClientAuthMode::Required);
        assert_eq!(ca.allowed_sans.len(), 2);
    }

    #[test]
    fn client_auth_apply_to_defaults_to_admin_only() {
        let yaml = good_cfg_with_tls(
            "  client_auth:\n    mode: required\n    ca_bundle: /etc/aegis/ca.pem\n",
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let ca = cfg.tls.unwrap().client_auth.unwrap();
        assert_eq!(ca.apply_to, vec![ClientAuthScope::Admin]);
    }

    #[test]
    fn client_auth_apply_to_admin_and_data() {
        let yaml = good_cfg_with_tls(
            "  client_auth:\n    mode: required\n    ca_bundle: /etc/aegis/ca.pem\n    apply_to: [admin, data]\n",
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let ca = cfg.tls.unwrap().client_auth.unwrap();
        assert_eq!(
            ca.apply_to,
            vec![ClientAuthScope::Admin, ClientAuthScope::Data],
        );
    }

    #[test]
    fn client_auth_required_without_ca_bundle_rejected() {
        let yaml = good_cfg_with_tls("  client_auth:\n    mode: required\n");
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("ca_bundle is required"),
            "expected ca_bundle error, got: {err}",
        );
    }

    #[test]
    fn client_auth_optional_without_ca_bundle_rejected() {
        let yaml = good_cfg_with_tls("  client_auth:\n    mode: optional\n");
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("ca_bundle is required"));
    }

    #[test]
    fn client_auth_required_with_empty_apply_to_rejected() {
        let yaml = good_cfg_with_tls(
            "  client_auth:\n    mode: required\n    ca_bundle: /etc/aegis/ca.pem\n    apply_to: []\n",
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("apply_to"),
            "expected apply_to error, got: {err}",
        );
    }

    #[test]
    fn client_auth_unknown_mode_rejected_at_deserialise() {
        let yaml = good_cfg_with_tls(
            "  client_auth:\n    mode: paranoid\n    ca_bundle: /etc/aegis/ca.pem\n",
        );
        let err = serde_yaml::from_str::<WafConfig>(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("paranoid")
                || err.to_string().contains("variant"),
            "expected serde unknown-variant error, got: {err}",
        );
    }

    #[test]
    fn client_auth_unknown_scope_rejected_at_deserialise() {
        let yaml = good_cfg_with_tls(
            "  client_auth:\n    mode: required\n    ca_bundle: /etc/aegis/ca.pem\n    apply_to: [moon]\n",
        );
        let err = serde_yaml::from_str::<WafConfig>(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("moon")
                || err.to_string().contains("variant"),
            "expected serde unknown-variant error, got: {err}",
        );
    }

    #[test]
    fn force_https_listener_status_must_be_redirect_code() {
        let yaml = r#"
listeners:
  data: [{ bind: "0.0.0.0:443" }]
  admin: { bind: "127.0.0.1:9443" }
  force_https: { bind: "0.0.0.0:80", status: 200 }
routes: [{ id: catch-all, path: "/", upstream: default }]
upstreams: { default: { members: [{ addr: "127.0.0.1:8080" }] } }
state: { backend: in_memory }
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("must be 301 or 308"));
    }

    #[test]
    fn force_https_listener_accepts_301_and_308() {
        for code in [301u16, 308u16] {
            let yaml = format!(
                r#"
listeners:
  data: [{{ bind: "0.0.0.0:443" }}]
  admin: {{ bind: "127.0.0.1:9443" }}
  force_https: {{ bind: "0.0.0.0:80", status: {code} }}
routes: [{{ id: catch-all, path: "/", upstream: default }}]
upstreams: {{ default: {{ members: [{{ addr: "127.0.0.1:8080" }}] }} }}
state: {{ backend: in_memory }}
"#
            );
            let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
            cfg.validate().unwrap_or_else(|e| panic!("status {code} should be ok: {e}"));
        }
    }

    // ---------- P5 ACME validation -------------------------------------

    fn acme_yaml_block(extra: &str) -> String {
        format!(
            r#"
listeners:
  data: [{{ bind: "0.0.0.0:443" }}]
  admin: {{ bind: "127.0.0.1:9443" }}
routes: [{{ id: catch-all, path: "/", upstream: default }}]
upstreams: {{ default: {{ members: [{{ addr: "127.0.0.1:8080" }}] }} }}
state: {{ backend: in_memory }}
tls:
  acme:
    contacts: ["ops@example.com"]
    domains: ["example.com"]
    account_key_path: "/var/lib/aegis/acme.key"
    cert_dir: "/var/lib/aegis/certs"
    terms_of_service_agreed: true
{extra}
"#
        )
    }

    #[test]
    fn acme_minimal_passes_validation() {
        let yaml = acme_yaml_block("");
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let acme = cfg.tls.unwrap().acme.unwrap();
        assert!(acme.directory_url.starts_with("https://"));
        assert_eq!(acme.challenge, AcmeChallenge::Http01);
        assert_eq!(acme.renew_before.as_secs(), 30 * 24 * 3600);
        // auto_renew defaults on (single-node / edge keeps renewing).
        assert!(acme.auto_renew);
    }

    #[test]
    fn acme_auto_renew_can_be_disabled() {
        // Fleet-behind-LB posture: keep the acme block but disable the
        // in-WAF renewal loop (TLS/ACME owned by the LB or out-of-band).
        let yaml = acme_yaml_block("    auto_renew: false\n");
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        assert!(!cfg.tls.unwrap().acme.unwrap().auto_renew);
    }

    #[test]
    fn acme_rejects_non_https_directory_url() {
        let yaml = acme_yaml_block(
            "    directory_url: \"http://acme-v02.api.letsencrypt.org/directory\"\n",
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("directory_url must use https"));
    }

    #[test]
    fn acme_rejects_empty_contacts() {
        let yaml = r#"
listeners:
  data: [{ bind: "0.0.0.0:443" }]
  admin: { bind: "127.0.0.1:9443" }
routes: [{ id: catch-all, path: "/", upstream: default }]
upstreams: { default: { members: [{ addr: "127.0.0.1:8080" }] } }
state: { backend: in_memory }
tls:
  acme:
    contacts: []
    domains: ["example.com"]
    account_key_path: "/var/lib/aegis/acme.key"
    cert_dir: "/var/lib/aegis/certs"
    terms_of_service_agreed: true
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("contacts must contain at least one"));
    }

    #[test]
    fn acme_rejects_empty_domains() {
        let yaml = r#"
listeners:
  data: [{ bind: "0.0.0.0:443" }]
  admin: { bind: "127.0.0.1:9443" }
routes: [{ id: catch-all, path: "/", upstream: default }]
upstreams: { default: { members: [{ addr: "127.0.0.1:8080" }] } }
state: { backend: in_memory }
tls:
  acme:
    contacts: ["ops@example.com"]
    domains: []
    account_key_path: "/var/lib/aegis/acme.key"
    cert_dir: "/var/lib/aegis/certs"
    terms_of_service_agreed: true
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("domains must contain at least one"));
    }

    #[test]
    fn acme_rejects_renew_before_under_one_day() {
        let yaml = acme_yaml_block("    renew_before: 1h\n");
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("renew_before must be >= 1 day"));
    }

    #[test]
    fn acme_rejects_missing_tos_agreement() {
        let yaml = r#"
listeners:
  data: [{ bind: "0.0.0.0:443" }]
  admin: { bind: "127.0.0.1:9443" }
routes: [{ id: catch-all, path: "/", upstream: default }]
upstreams: { default: { members: [{ addr: "127.0.0.1:8080" }] } }
state: { backend: in_memory }
tls:
  acme:
    contacts: ["ops@example.com"]
    domains: ["example.com"]
    account_key_path: "/var/lib/aegis/acme.key"
    cert_dir: "/var/lib/aegis/certs"
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("terms_of_service_agreed must be true"));
    }

    #[test]
    fn acme_challenge_modes_round_trip() {
        for (yaml_val, expected) in [
            ("http01", AcmeChallenge::Http01),
            ("tls_alpn01", AcmeChallenge::TlsAlpn01),
            ("dns01", AcmeChallenge::Dns01),
        ] {
            let yaml = acme_yaml_block(&format!("    challenge: {yaml_val}\n"));
            let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
            cfg.validate().unwrap();
            assert_eq!(cfg.tls.unwrap().acme.unwrap().challenge, expected);
        }
    }

    #[test]
    fn force_https_listener_default_status_is_301() {
        let yaml = r#"
listeners:
  data: [{ bind: "0.0.0.0:443" }]
  admin: { bind: "127.0.0.1:9443" }
  force_https: { bind: "0.0.0.0:80" }
routes: [{ id: catch-all, path: "/", upstream: default }]
upstreams: { default: { members: [{ addr: "127.0.0.1:8080" }] } }
state: { backend: in_memory }
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.listeners.force_https.unwrap().status, 301);
    }

    // -----------------------------------------------------------
    // TCP-T1 — `tcp_destination_allowlist` validation
    // -----------------------------------------------------------

    fn cfg_with_tcp_route(allowlist_yaml: &str) -> String {
        // YAML fragment: a route → tcp pool, with the allowlist
        // injected verbatim so each test can shape the field
        // however it needs.
        format!(
            r#"
listeners:
  data: [{{ bind: "0.0.0.0:8080" }}]
  admin: {{ bind: "127.0.0.1:9443" }}
routes:
  - id: tcp-tunnel
    path: "/"
    upstream: tcp-mesh
{allowlist_yaml}
upstreams:
  tcp-mesh:
    members: [{{ addr: "127.0.0.1:6379" }}]
    connection: {{ scheme: tcp }}
state: {{ backend: in_memory }}
"#
        )
    }

    #[test]
    fn tcp_route_with_no_allowlist_is_rejected() {
        let yaml = cfg_with_tcp_route("");
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = cfg.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("empty tcp_destination_allowlist"),
            "expected empty-allowlist message, got: {msg}",
        );
    }

    #[test]
    fn tcp_route_with_valid_allowlist_validates_ok() {
        let yaml = cfg_with_tcp_route(
            r#"    tcp_destination_allowlist:
      - "10.0.0.0/8:6379"
      - "192.168.1.0/24:443"
"#,
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().expect("valid config");
    }

    #[test]
    fn tcp_route_with_garbage_allowlist_entry_is_rejected() {
        let yaml = cfg_with_tcp_route(
            r#"    tcp_destination_allowlist:
      - "10.0.0.0/8:6379"
      - "not a real entry"
"#,
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = cfg.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("route 'tcp-tunnel'"), "got {msg}");
        assert!(
            msg.contains("missing ':<port-spec>'") || msg.contains("bad cidr"),
            "expected parse-error message, got: {msg}",
        );
    }

    #[test]
    fn tcp_route_with_loopback_entry_is_rejected_via_internal_gate() {
        let yaml = cfg_with_tcp_route(
            r#"    tcp_destination_allowlist:
      - "127.0.0.0/8:*"
"#,
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = cfg.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("internal-only"),
            "expected internal-only reject, got: {msg}",
        );
    }

    #[test]
    fn non_tcp_route_skips_allowlist_validation() {
        // HTTP route (default scheme=auto) without an allowlist
        // — fine, the validation only fires on tcp pools.
        let yaml = r#"
listeners:
  data: [{ bind: "0.0.0.0:8080" }]
  admin: { bind: "127.0.0.1:9443" }
routes:
  - { id: catch-all, path: "/", upstream: default }
upstreams:
  default: { members: [{ addr: "127.0.0.1:8081" }] }
state: { backend: in_memory }
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        cfg.validate().expect("non-tcp route should validate without allowlist");
    }

    /// 2026-05-17 F-CRITICAL-008 (core audit): per-tier DDoS
    /// overrides parse from YAML. Existing configs without
    /// `tier_overrides` keep working (`#[serde(default)]` →
    /// empty map).
    #[test]
    fn ddos_tier_overrides_parse_and_default_empty() {
        let yaml = r#"
enabled: true
per_ip_limit: 1000
tier_overrides:
  critical:
    per_ip_limit: 200
    block_ttl_s: 1800
  low:
    per_ip_limit: 5000
"#;
        let cfg: DdosConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.tier_overrides.len(), 2);
        let crit = cfg.tier_overrides.get(&Tier::Critical).unwrap();
        assert_eq!(crit.per_ip_limit, Some(200));
        assert_eq!(crit.block_ttl_s, Some(1800));
        assert!(crit.per_ip_window_s.is_none()); // not overridden → None
        let low = cfg.tier_overrides.get(&Tier::Low).unwrap();
        assert_eq!(low.per_ip_limit, Some(5000));

        // Default (no tier_overrides key) is an empty map, not an error.
        let default_yaml = "enabled: true\n";
        let cfg: DdosConfig = serde_yaml::from_str(default_yaml).unwrap();
        assert!(cfg.tier_overrides.is_empty());
    }

    /// 2026-05-17 F-CRITICAL-010 (core audit): `fail_mode_by_tier`
    /// parses from YAML; existing configs default to empty.
    #[test]
    fn fail_mode_by_tier_parses_and_default_empty() {
        let yaml = r#"
listeners:
  data: [{ bind: "0.0.0.0:8080" }]
  admin: { bind: "127.0.0.1:9443" }
routes:
  - { id: catch-all, path: "/", upstream: default }
upstreams:
  default: { members: [{ addr: "127.0.0.1:8081" }] }
state: { backend: in_memory }
fail_mode_by_tier:
  high: fail_close
  medium: fail_close
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.fail_mode_by_tier.len(), 2);
        assert_eq!(
            cfg.fail_mode_by_tier.get(&Tier::High),
            Some(&FailureModeConfig::FailClose),
        );
        assert_eq!(
            cfg.fail_mode_by_tier.get(&Tier::Medium),
            Some(&FailureModeConfig::FailClose),
        );
        assert!(cfg.fail_mode_by_tier.get(&Tier::Low).is_none());
    }

    /// 2026-05-17 F-CRITICAL-009 (core audit): the four new
    /// `RlScope` variants parse from YAML, externally-tagged. Old
    /// configs with `scope: global` and `scope: route` keep
    /// parsing unchanged.
    #[test]
    fn rl_scope_new_variants_parse() {
        // Existing: unit variants — no change.
        let s: RlScope = serde_yaml::from_str("global").unwrap();
        assert_eq!(s, RlScope::Global);
        let s: RlScope = serde_yaml::from_str("route").unwrap();
        assert_eq!(s, RlScope::Route);
        let s: RlScope = serde_yaml::from_str("user_session").unwrap();
        assert_eq!(s, RlScope::UserSession);
        let s: RlScope = serde_yaml::from_str("device_fingerprint").unwrap();
        assert_eq!(s, RlScope::DeviceFingerprint);

        // Newly added: tuple variants — externally tagged YAML uses
        // the `!variant value` form. JSON-style `{variant: value}`
        // also works through serde_json round-trip.
        let s: RlScope = serde_yaml::from_str("!tier critical").unwrap();
        assert_eq!(s, RlScope::Tier(Tier::Critical));

        let s: RlScope = serde_yaml::from_str("!route_pattern \"/api/users/*\"").unwrap();
        assert_eq!(s, RlScope::RoutePattern("/api/users/*".into()));

        let s: RlScope = serde_yaml::from_str("!ip \"10.0.0.0/8\"").unwrap();
        assert_eq!(s, RlScope::Ip("10.0.0.0/8".into()));

        // JSON-style also parses (used by REST API request bodies).
        let s: RlScope = serde_json::from_str(r#"{"tier":"critical"}"#).unwrap();
        assert_eq!(s, RlScope::Tier(Tier::Critical));
    }

    /// 2026-05-17 F-CRITICAL-009 (core audit): new RlKey variants.
    #[test]
    fn rl_key_new_variants_parse() {
        let k: RlKey = serde_yaml::from_str("ip").unwrap();
        assert_eq!(k, RlKey::Ip);
        let k: RlKey = serde_yaml::from_str("device_fp").unwrap();
        assert_eq!(k, RlKey::DeviceFp);
        let k: RlKey = serde_yaml::from_str("user_id").unwrap();
        assert_eq!(k, RlKey::UserId);
    }

    /// 2026-05-17 F-CRITICAL-011 (core audit): per-tier detector
    /// override mask parses from YAML; existing configs without
    /// `per_tier` default to empty (single global policy).
    #[test]
    fn detectors_per_tier_mask_parses_and_default_empty() {
        let yaml = r#"
sqli: { enabled: true }
per_tier:
  critical:
    command_injection: true
    brute_force: true
  low:
    recon: false
"#;
        let cfg: DetectorsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.per_tier.len(), 2);
        let crit = cfg.per_tier.get(&Tier::Critical).unwrap();
        assert_eq!(crit.command_injection, Some(true));
        assert_eq!(crit.brute_force, Some(true));
        assert!(crit.sqli.is_none()); // not overridden → inherit global
        let low = cfg.per_tier.get(&Tier::Low).unwrap();
        assert_eq!(low.recon, Some(false));

        // Default (no per_tier key) is an empty map, not an error.
        let cfg: DetectorsConfig = serde_yaml::from_str("{}").unwrap();
        assert!(cfg.per_tier.is_empty());
    }

    /// 2026-05-17 F-CRITICAL-012 (core audit): `canary_paths`
    /// parses from YAML; existing configs default to empty.
    #[test]
    fn risk_canary_paths_parse_and_default_empty() {
        let yaml = r#"
canary_paths:
  - "/wp-admin"
  - "/.env"
  - "/phpmyadmin/*"
"#;
        let cfg: RiskConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.canary_paths.len(), 3);
        assert_eq!(cfg.canary_paths[0], "/wp-admin");
        assert_eq!(cfg.canary_paths[2], "/phpmyadmin/*");

        // Default (no canary_paths key) is an empty vec, not an error.
        let cfg: RiskConfig = serde_yaml::from_str("{}").unwrap();
        assert!(cfg.canary_paths.is_empty());
    }
}

#[cfg(test)]
mod copilot_config_tests {
    use super::*;

    #[test]
    fn defaults_are_disabled_and_safe() {
        let cfg = CopilotConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.provider, CopilotProvider::OpenAiCompatible);
        assert_eq!(cfg.timeout_ms, 20_000);
        assert_eq!(cfg.briefing_interval_secs, 0);
        assert!(cfg.api_key_ref.is_none());
        assert!(cfg.base_url.is_none());
        assert!(cfg.model.is_none());
    }

    #[test]
    fn observability_copilot_defaults_when_absent() {
        // No `copilot:` key → default (disabled) sub-config, not an error.
        let obs: ObservabilityConfig = serde_yaml::from_str("{}").unwrap();
        assert!(!obs.copilot.enabled);
    }

    #[test]
    fn deserializes_full_copilot_block_with_secret_ref() {
        let yaml = r#"
copilot:
  enabled: true
  provider: openai_compatible
  base_url: "https://host/v1"
  model: "Qwen3.6-35B-A3B"
  timeout_ms: 4000
  briefing_interval_secs: 900
  api_key_ref: "${secret:env:LLM_API_KEY}"
"#;
        let obs: ObservabilityConfig = serde_yaml::from_str(yaml).unwrap();
        let c = &obs.copilot;
        assert!(c.enabled);
        assert_eq!(c.provider, CopilotProvider::OpenAiCompatible);
        assert_eq!(c.base_url.as_deref(), Some("https://host/v1"));
        assert_eq!(c.model.as_deref(), Some("Qwen3.6-35B-A3B"));
        assert_eq!(c.timeout_ms, 4000);
        assert_eq!(c.briefing_interval_secs, 900);
        // The key is preserved as a ref — NOT resolved at parse time.
        assert_eq!(c.api_key_ref.as_deref(), Some("${secret:env:LLM_API_KEY}"));
    }

    #[test]
    fn provider_anthropic_parses() {
        let obs: ObservabilityConfig =
            serde_yaml::from_str("copilot:\n  provider: anthropic\n").unwrap();
        assert_eq!(obs.copilot.provider, CopilotProvider::Anthropic);
    }
}
