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
        // Every pool must have at least one member.
        for (name, pool) in &self.upstreams {
            if pool.members.is_empty() {
                return Err(crate::error::WafError::Config(format!(
                    "upstream '{}' must have at least one member",
                    name,
                )));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Listeners
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct Listeners {
    pub data: Vec<ListenerConfig>,
    pub admin: ListenerConfig,
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
    #[serde(default)]
    pub min_version: Option<String>,
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
}

fn default_state_backend() -> StateBackendKind {
    StateBackendKind::InMemory
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
    Jsonl { path: PathBuf },
    Syslog { address: String },
    Splunk { endpoint: String, token_ref: String },
    Kafka { brokers: Vec<String>, topic: String },
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
        }
    }
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
        let path = std::path::Path::new("../../config/waf.yaml");
        if path.exists() {
            let cfg = super::load_config(path).unwrap();
            assert!(!cfg.routes.is_empty());
            assert!(cfg.upstreams.contains_key("backend-pool"));
            assert!(!cfg.listeners.data.is_empty());
            cfg.validate().unwrap();
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
}
