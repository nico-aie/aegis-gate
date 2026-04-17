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
// Top-level WafConfig
// ---------------------------------------------------------------------------

#[derive(Clone, Deserialize)]
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

// ---------------------------------------------------------------------------
// Listeners
// ---------------------------------------------------------------------------

#[derive(Clone, Deserialize)]
pub struct Listeners {
    pub data: Vec<ListenerConfig>,
    pub admin: ListenerConfig,
}

#[derive(Clone, Deserialize)]
pub struct ListenerConfig {
    pub bind: SocketAddr,
    #[serde(default)]
    pub tls: bool,
}

// ---------------------------------------------------------------------------
// Route
// ---------------------------------------------------------------------------

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub certificates: Vec<CertConfig>,
    #[serde(default)]
    pub min_version: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct CertConfig {
    pub cert_path: PathBuf,
    pub key_ref: String,
    #[serde(default)]
    pub hosts: Vec<String>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize, Default)]
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

#[derive(Clone, Deserialize, Default)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub buckets: Vec<RateLimitRule>,
}

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize, Default)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
pub struct FpeConfig {
    pub key_ref: String,
    pub version: u32,
}

// ---------------------------------------------------------------------------
// Observability
// ---------------------------------------------------------------------------

#[derive(Clone, Deserialize)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub prometheus: PromConfig,
    #[serde(default)]
    pub otel: Option<OtelConfig>,
    #[serde(default)]
    pub access_log: AccessLogConfig,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            prometheus: PromConfig::default(),
            otel: None,
            access_log: AccessLogConfig::default(),
        }
    }
}

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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
}
