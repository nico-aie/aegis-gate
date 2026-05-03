use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

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

#[derive(Clone, Debug, Deserialize)]
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
    pub dlp: DlpConfig,
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
}

/// Upstream protocol selector for `ConnectionPoolConfig.scheme`.
/// See `aegis-proxy/src/upstream/forward.rs::build_client` for
/// how each variant maps to the hyper connector.
#[derive(Copy, Clone, Debug, Default, serde::Serialize, Deserialize, PartialEq, Eq)]
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

fn default_pool_max_idle_per_host() -> usize {
    32
}

fn default_pool_idle_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_keep_alive() -> bool {
    true
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

#[derive(Clone, Debug, Deserialize)]
pub struct MemberConfig {
    pub addr: SocketAddr,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub zone: Option<String>,
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

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RlScope {
    Global,
    Route,
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RlKey {
    Ip,
    Session,
    Header(String),
    JwtSub,
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
#[derive(Clone, Debug, Deserialize)]
pub struct StrikeConfig {
    /// Number of strikes that triggers a permanent block. Per the
    /// user-confirmed default, strikes never decay — the operator
    /// must reset them via the audit-mutation pipeline.
    #[serde(default = "default_strike_block_at")]
    pub block_at: u32,
}

fn default_strike_block_at() -> u32 {
    50
}

impl Default for StrikeConfig {
    fn default() -> Self {
        Self {
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

#[derive(Clone, Debug, Deserialize)]
pub struct RiskThresholds {
    #[serde(default = "default_challenge_at")]
    pub challenge_at: u32,
    #[serde(default = "default_block_at")]
    pub block_at: u32,
    #[serde(default = "default_risk_max")]
    pub max: u32,
}

fn default_challenge_at() -> u32 {
    40
}
fn default_block_at() -> u32 {
    80
}
fn default_risk_max() -> u32 {
    100
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            challenge_at: 40,
            block_at: 80,
            max: 100,
        }
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
    /// DURABLE-T2 — optional file-backed persistence for the live
    /// detector mask. When set, the proxy writes the mask state to
    /// `path` after every audit-mutated PUT and reloads from it at
    /// boot so operator toggles survive a restart. Compliance
    /// clamps re-run on load: any class the snapshot disabled but
    /// compliance now requires is forced back on with a warn log.
    /// Absent → in-memory only (legacy behaviour).
    #[serde(default)]
    pub persistence: Option<DetectorMaskPersistenceConfig>,
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
            persistence: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct DetectorToggle {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
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
}

fn default_audit_retention() -> Duration {
    Duration::from_secs(90 * 24 * 3600) // 90 days
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            sinks: Vec::new(),
            chain: AuditChainConfig::default(),
            retention: default_audit_retention(),
            pseudonymize_ip: false,
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

impl Default for DashboardAuthConfig {
    fn default() -> Self {
        Self {
            password_hash_ref: String::new(),
            csrf_secret_ref: String::new(),
            session_ttl_idle: default_session_idle(),
            session_ttl_absolute: default_session_absolute(),
            ip_allowlist: default_ip_allowlist(),
            totp_enabled: false,
            login_rate_limit: LoginRateLimitConfig::default(),
            lockout: LockoutConfig::default(),
            allow_ca_upload: false,
        }
    }
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
        let cfg = RiskConfig::default();
        assert_eq!(cfg.thresholds.challenge_at, 40);
        assert_eq!(cfg.thresholds.block_at, 80);
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

    // -----------------------------------------------------------------------
    // validate() tests
    // -----------------------------------------------------------------------

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
}
