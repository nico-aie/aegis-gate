# Aegis-Gate — Shared Contract (read first)

This file is the single source of truth for types, module layout, and
inter-member interfaces. **All three member plans (M1/M2/M3) depend on
it.** Any change here must be agreed by all three members.

---

## 1. Workspace Layout

```
aegis-gate/
├── Cargo.toml                  # workspace
├── crates/
│   ├── aegis-core/             # shared types (owned by all, PR-reviewed)
│   ├── aegis-proxy/            # M1
│   ├── aegis-security/         # M2
│   ├── aegis-control/          # M3
│   └── aegis-bin/              # ./waf binary, wires the three crates
└── config/
    ├── waf.yaml                # example config
    └── rules/                  # example rule files
```

Top-level `Cargo.toml`:

```toml
[workspace]
members = ["crates/aegis-core", "crates/aegis-proxy",
           "crates/aegis-security", "crates/aegis-control",
           "crates/aegis-bin"]
resolver = "2"
```

---

## 2. `aegis-core` — Shared Types

All three crates depend on `aegis-core`. Nothing else is shared.

```rust
// crates/aegis-core/src/lib.rs
pub mod config;
pub mod context;
pub mod decision;
pub mod audit;
pub mod tier;
pub mod risk;
pub mod error;

pub use config::WafConfig;
pub use context::{RequestCtx, RouteCtx, ClientInfo};
pub use decision::{Decision, Action};
pub use audit::{AuditEvent, AuditClass};
pub use tier::{Tier, FailureMode};
pub use risk::RiskKey;
pub use error::{WafError, Result};
```

### 2.1 Tier

```rust
#[derive(Copy, Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier { Critical, High, Medium, CatchAll }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FailureMode { FailClose, FailOpen }

impl Tier {
    pub fn default_failure_mode(self) -> FailureMode {
        match self {
            Tier::Critical => FailureMode::FailClose,
            _ => FailureMode::FailOpen,
        }
    }
}
```

### 2.2 Decision

```rust
#[derive(Clone, Debug)]
pub struct Decision {
    pub action: Action,
    pub reason: String,          // human-readable
    pub rule_id: Option<String>,
    pub risk_score: u32,         // 0..=100
}

#[derive(Clone, Debug)]
pub enum Action {
    Allow,
    Block { status: u16 },
    Challenge { level: ChallengeLevel },
    RateLimited { retry_after_s: u32 },
}

#[derive(Copy, Clone, Debug)]
pub enum ChallengeLevel { Js, Pow, Captcha }
```

### 2.3 RequestCtx / RouteCtx / ClientInfo

```rust
pub struct RequestCtx {
    pub request_id: String,        // ulid
    pub received_at: std::time::Instant,
    pub client: ClientInfo,
    // tenant_id reserved for future multi-tenancy (deferred) — always None in v1
    pub tenant_id: Option<String>,
    pub trace_id: Option<String>,  // W3C traceparent
    /// Free-form bag populated by the pipeline. Keys used by the
    /// rule engine expression language:
    ///   "jwt.sub", "jwt.role", "jwt.claims.<name>"  (M2 T5.6)
    ///   "risk.score"       u32 0..=100              (M2 T3.4)
    ///   "risk.human_conf"  u32 0..=100              (M2 T3.5)
    ///   "bot.label"        "good"|"bad"|"unknown"   (M2 T4.3)
    ///   "device.fp"        String (blake3 digest)   (M2 T3.1)
    /// Expression references write `user.role` ⇒ `jwt.role`.
    pub fields: std::collections::BTreeMap<String, FieldValue>,
}

#[derive(Clone, Debug)]
pub enum FieldValue {
    Str(String),
    Int(i64),
    U32(u32),
    Bool(bool),
    List(Vec<FieldValue>),
}

pub struct ClientInfo {
    pub ip: std::net::IpAddr,
    pub tls_fingerprint: Option<TlsFingerprint>, // JA4/JA3 from M1
    pub h2_fingerprint: Option<String>,
    pub user_agent: Option<String>,
}

pub struct TlsFingerprint {
    pub ja3: String,
    pub ja4: String,
}

pub struct RouteCtx {
    pub route_id: String,
    pub tier: Tier,
    pub failure_mode: FailureMode,
    pub upstream: String,          // pool name
    // tenant_id reserved for future multi-tenancy (deferred) — always None in v1
    pub tenant_id: Option<String>,
}
```

### 2.4 RiskKey

```rust
#[derive(Clone, Hash, Eq, PartialEq)]
pub struct RiskKey {
    pub ip: std::net::IpAddr,
    pub device_fp: Option<String>,
    pub session: Option<String>,
    // tenant_id reserved for future multi-tenancy (deferred) — always None in v1
    pub tenant_id: Option<String>,
}
```

### 2.5 AuditEvent

```rust
#[derive(Clone, Debug, serde::Serialize)]
pub struct AuditEvent {
    pub schema_version: u32,       // start at 1
    pub ts: chrono::DateTime<chrono::Utc>,
    pub request_id: String,
    pub class: AuditClass,
    // tenant_id reserved for future multi-tenancy (deferred) — always None in v1
    pub tenant_id: Option<String>,
    pub tier: Option<Tier>,
    pub action: String,
    pub reason: String,
    pub client_ip: String,         // pseudonymized per compliance mode
    pub route_id: Option<String>,
    pub rule_id: Option<String>,
    pub risk_score: Option<u32>,
    pub fields: serde_json::Value, // free-form
}

#[derive(Copy, Clone, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditClass { Detection, Admin, Access, System }
```

### 2.6 WafConfig (top-level skeleton)

```rust
#[derive(Clone, serde::Deserialize)]
pub struct WafConfig {
    pub listeners: Listeners,            // M1, §2.6.1
    pub routes: Vec<RouteConfig>,         // M1, §2.6.2
    pub upstreams: std::collections::HashMap<String, PoolConfig>, // M1
    pub tls: Option<TlsConfig>,           // M1
    pub state: StateConfig,               // M1, §2.6.3
    pub rules: RulesConfig,               // M2, §2.6.4
    pub rate_limit: RateLimitConfig,      // M2, §2.6.5
    pub risk: RiskConfig,                 // M2, §2.6.6
    pub detectors: DetectorsConfig,       // M2, §2.6.7
    pub dlp: DlpConfig,                   // M2, §2.6.8
    pub observability: ObservabilityConfig, // M3, §2.6.9
    pub audit: AuditConfig,               // M3, §2.6.10
    pub admin: AdminConfig,               // M3, §2.6.11
    // §2.6.12 multi-tenancy is DEFERRED (see deferred/multi-tenancy.md)
    pub compliance: Option<ComplianceProfile>, // M3, §2.6.13
}
```
Each sub-config struct lives in its owning crate but is re-exported
through `aegis-core::config` via a feature-flag–free public type, so
`aegis-core` only holds the outer `WafConfig` and the owning crate
provides the inner struct. **Rule:** if a struct has logic, it lives
in the owning crate; if it's pure data that everyone reads, it lives
in `aegis-core`.

The shapes below are the **authoritative serde schema** for week-1
parsing (M1 T1.2). Adding fields requires a contract PR. All numeric
fields are `u32` unless noted; durations are humantime strings (`"30s"`).

#### 2.6.1 `StateConfig` (M1)
```rust
pub struct StateConfig {
    pub backend: StateBackendKind,   // in_memory | redis | raft
    pub redis: Option<RedisConfig>,
    pub raft:  Option<RaftConfig>,
}
pub enum StateBackendKind { InMemory, Redis, Raft }
pub struct RedisConfig {
    pub urls: Vec<String>, pub cluster: bool,
    pub pool_size: u32, pub timeout: Duration,
    pub tls: bool, pub password_ref: Option<String>,
}
pub struct RaftConfig {
    pub data_dir: std::path::PathBuf,
    pub peers: Vec<String>, pub heartbeat_ms: u32,
}
```

#### 2.6.4 `RulesConfig` (M2)
```rust
pub struct RulesConfig {
    pub paths: Vec<std::path::PathBuf>,  // YAML files / dirs
    pub default_action: Action,
    pub max_rule_count: u32,             // safety cap, default 10_000
    pub strict_compile: bool,            // fail load on warnings
}
```
Per-rule YAML schema (one rule):
```yaml
id: "sqli-strict-1"        # unique
priority: 100              # higher = earlier
scope: { tier: critical, route: "api.*" }   # all keys optional
when: "method == 'POST' && path matches '^/api/' && body contains_any sqli_signatures"
then: { action: block, status: 403, reason: "sqli" }
tags: ["owasp:a03"]
```
Operators: `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `contains`,
`contains_any`, `matches` (regex), `cidr_in`, `&&`, `||`, `!`.
Identifiers: `method`, `path`, `host`, `header.<name>`,
`query.<name>`, `body`, `client.ip`, `client.asn`, `user.role`,
`risk.score`, `bot.label`, `device.fp`.

#### 2.6.5 `RateLimitConfig` (M2)
```rust
pub struct RateLimitConfig {
    pub buckets: Vec<RateLimitRule>,
}
pub struct RateLimitRule {
    pub id: String,
    pub scope: RlScope,                  // global | route
    pub key:   RlKey,                    // ip | session | header(name) | jwt_sub
    pub algo:  RlAlgo,                   // sliding_window | token_bucket
    pub limit: u64, pub window: Duration,
    pub burst: Option<u32>,              // token_bucket only
    pub on_exceed: Action,               // default RateLimited
}
```

#### 2.6.6 `RiskConfig` (M2)
```rust
pub struct RiskConfig {
    pub weights: RiskWeights,
    pub decay_half_life: Duration,       // default "5m"
    pub thresholds: RiskThresholds,
    pub challenge_ladder: Vec<ChallengeStep>,
}
pub struct RiskWeights {
    pub bad_asn: u32, pub bad_ja4: u32,
    pub failed_auth: u32, pub detector_hit: u32,
    pub bot_unknown: u32, pub repeat_offender: u32,
}
pub struct RiskThresholds {
    pub challenge_at: u32,    // default 40
    pub block_at: u32,        // default 80
    pub max: u32,             // default 100
}
pub struct ChallengeStep { pub at_score: u32, pub level: ChallengeLevel }
```

#### 2.6.7 `DetectorsConfig` (M2)
```rust
pub struct DetectorsConfig {
    pub sqli:             DetectorToggle,
    pub xss:              DetectorToggle,
    pub path_traversal:   DetectorToggle,
    pub ssrf:             DetectorToggle,
    pub header_injection: DetectorToggle,
    pub body_abuse:       DetectorToggle,
    pub recon:            DetectorToggle,
    pub brute_force:      DetectorToggle,
    pub limits: DetectorLimits,          // see §3.1
}
pub struct DetectorToggle {
    pub enabled: bool,
    pub action: Action,                  // default Block { status: 403 }
    pub fp_corpus: Option<std::path::PathBuf>, // benign FP regression set
}
```

#### 2.6.8 `DlpConfig` (M2)
```rust
pub struct DlpConfig {
    pub patterns: Vec<DlpPattern>,
    pub fpe: Option<FpeConfig>,
    pub max_scan_bytes: usize,           // default 2 MiB, see §3.1
}
pub struct DlpPattern {
    pub id: String, pub regex: String,
    pub direction: DlpDir,               // inbound | outbound | both
    pub action: DlpAction,               // redact | tokenize | block | log
}
pub struct FpeConfig { pub key_ref: String, pub version: u32 }
```

#### 2.6.9 `ObservabilityConfig` (M3)
```rust
pub struct ObservabilityConfig {
    pub prometheus: PromConfig,
    pub otel: Option<OtelConfig>,
    pub access_log: AccessLogConfig,
}
pub struct PromConfig {
    pub bind: std::net::SocketAddr, pub path: String, // "/metrics"
}
pub struct OtelConfig {
    pub endpoint: String, pub headers: std::collections::BTreeMap<String, String>,
    pub sample_ratio: f32,
}
pub struct AccessLogConfig {
    pub format: AccessLogFormat,         // combined | json | template(String)
    pub path: AccessLogSink,             // stdout | file(PathBuf)
}
```

#### 2.6.10 `AuditConfig` (M3)
```rust
pub struct AuditConfig {
    pub sinks: Vec<AuditSinkConfig>,     // jsonl, syslog, splunk, kafka, ...
    pub chain: AuditChainConfig,
    pub retention: Duration,
    pub pseudonymize_ip: bool,
}
pub struct AuditChainConfig {
    pub enabled: bool,
    pub witness: Option<WitnessConfig>,  // periodic merkle root export
}
pub struct WitnessConfig {
    pub interval: Duration,
    pub destination: std::path::PathBuf,
    pub signer_ref: Option<String>,      // ${secret:...}
}
```

#### 2.6.11 `AdminConfig` (M3)
```rust
pub struct AdminConfig {
    pub bind: std::net::SocketAddr,      // default 127.0.0.1:9443
    pub tls: Option<TlsConfig>,          // server TLS for admin listener
    pub dashboard_auth: DashboardAuthConfig,
}

pub struct DashboardAuthConfig {
    /// argon2id PHC hash of the admin password, in the form
    /// `$argon2id$v=19$m=65536,t=2,p=1$<salt>$<hash>`. Resolved via
    /// `${secret:etcd:/aegis/secrets/admin_password}`.
    pub password_hash_ref: String,
    /// 32-byte HMAC key for session + CSRF tokens.
    pub csrf_secret_ref: String,
    pub session_ttl_idle: Duration,       // default 30m
    pub session_ttl_absolute: Duration,   // default 8h
    pub ip_allowlist: Vec<ipnet::IpNet>,  // default [127.0.0.1/32, ::1/128]
    pub totp_enabled: bool,               // default false
    pub login_rate_limit: LoginRateLimitConfig,
    pub lockout: LockoutConfig,
    pub mtls: MtlsAdminConfig,
}

pub struct LoginRateLimitConfig {
    pub per_ip:   RateCap,                // default { limit: 5,  window: 1m }
    pub per_user: RateCap,                // default { limit: 10, window: 15m }
}
pub struct RateCap { pub limit: u32, pub window: Duration }

pub struct LockoutConfig {
    pub threshold: u32,                   // default 10
    pub window: Duration,                 // default 15m
    pub duration: Duration,               // default 15m
}

pub struct MtlsAdminConfig {
    pub enabled: bool,                    // default false
    pub ca_ref: Option<String>,           // PEM bundle via secret provider
    pub required_san: Option<String>,     // e.g. "CN=aegis-admin"
}
```

**No OIDC, RBAC, API-token, or 4-eyes approval in v1.** See
`docs/deferred/rbac-sso.md` for the deferred enterprise design.

#### 2.6.12 Multi-tenancy — **DEFERRED**

`TenantConfig`, `TenantQuotas`, `TenantPressure`, and the tenant
governor are out of scope for v1. The v1 WAF is single-tenant:
one config, one dashboard, one audit stream. See
`docs/deferred/multi-tenancy.md` for the original design.

#### 2.6.13 `ComplianceProfile` (M3)
```rust
pub struct ComplianceProfile {
    pub modes: Vec<ComplianceMode>,       // fips | pci | soc2 | gdpr | hipaa
    pub min_tls_version: TlsVersion,      // "1.2" | "1.3"
    pub disallow_algorithms: Vec<String>,
    pub log_retention: Duration,
    pub pii_pseudonymize: bool,
}
pub enum ComplianceMode { Fips, Pci, Soc2, Gdpr, Hipaa }
```

---

## 3. Cross-Crate Traits

### 3.1 SecurityPipeline (M1 ↔ M2)

`aegis-core/src/pipeline.rs`:

```rust
/// Read-only view of the request passed to every detector.
/// M1 constructs this once per request; detectors borrow it.
/// The body is exposed as a framed, peekable handle so streaming
/// detectors never buffer more than `DetectorLimits::max_body_peek`.
pub struct RequestView<'a> {
    pub method: &'a http::Method,
    pub uri: &'a http::Uri,
    pub version: http::Version,
    pub headers: &'a http::HeaderMap,
    pub peer: std::net::SocketAddr,
    pub tls: Option<&'a TlsFingerprint>,
    /// Lazily-read body frames. Calling `peek` returns up to
    /// `max_body_peek` bytes without consuming them from the
    /// upstream stream. Detectors must not call `take`.
    pub body: &'a BodyPeek,
}

pub struct BodyPeek { /* opaque, M1-owned */ }

impl BodyPeek {
    pub async fn peek(&self, max: usize) -> Result<&[u8]>;
    pub fn content_length(&self) -> Option<u64>;
    pub fn is_chunked(&self) -> bool;
}

#[async_trait::async_trait]
pub trait SecurityPipeline: Send + Sync + 'static {
    /// Inspect inbound request before upstream selection.
    /// Return `Allow` to continue, anything else short-circuits.
    /// Detectors may write arbitrary key/value pairs into
    /// `RequestCtx::fields` (e.g. JWT claims, risk score).
    async fn inbound(
        &self,
        view: RequestView<'_>,
        rctx: &mut RequestCtx,
        route: &RouteCtx,
    ) -> Decision;

    /// Inspect outbound response frames one at a time.
    /// M1 calls `on_response_start` once with headers, then
    /// `on_body_frame` for each body chunk as it is streamed to
    /// the client. The pipeline MUST NOT buffer more than
    /// `DetectorLimits::max_body_scan` bytes — it returns
    /// `OutboundAction::PassThrough` once the budget is exceeded.
    /// This preserves the "1 GB body, constant memory" invariant.
    async fn on_response_start(
        &self,
        head: &http::response::Parts,
        rctx: &RequestCtx,
        route: &RouteCtx,
    ) -> OutboundAction;

    async fn on_body_frame(
        &self,
        frame: &[u8],
        rctx: &RequestCtx,
        route: &RouteCtx,
    ) -> OutboundAction;
}

#[derive(Clone, Debug)]
pub enum OutboundAction {
    /// Forward the frame unmodified.
    PassThrough,
    /// Replace the frame bytes (DLP redaction, body scrub).
    Rewrite(bytes::Bytes),
    /// Abort the response — M1 truncates the stream and emits
    /// a trailer with `x-aegis-blocked: <reason>`.
    Abort { reason: String },
}

pub struct DetectorLimits {
    pub max_body_peek: usize,  // inbound scan budget (default 1 MiB)
    pub max_body_scan: usize,  // outbound scan budget (default 2 MiB)
}
```

M1 calls these at the fixed points in its proxy loop. M2 provides
the implementation. For week 1, M1 ships a `NoopPipeline` (in
`aegis-security` as a test helper, re-exported from `aegis-core`)
so the proxy can run standalone.

### 3.2 StateBackend (M1 provides, M2 consumes)

`aegis-core/src/state.rs`:

```rust
use std::time::Duration;
use std::net::IpAddr;

#[async_trait::async_trait]
pub trait StateBackend: Send + Sync + 'static {
    // ---- generic byte K/V (used by M1 cache, snapshots, M3 GitOps state)
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn set(&self, key: &str, val: &[u8], ttl: Duration) -> Result<()>;
    async fn del(&self, key: &str) -> Result<()>;

    // ---- rate limiting primitives (M2 T2.1, T2.2)
    /// Atomic sliding-window counter. Returns the post-increment count
    /// and whether the request is within `limit`.
    async fn incr_window(
        &self,
        key: &str,
        window: Duration,
        limit: u64,
    ) -> Result<SlidingWindowResult>;

    /// Token-bucket admission. Returns true if a token was consumed.
    async fn token_bucket(
        &self,
        key: &str,
        rate_per_s: u32,
        burst: u32,
    ) -> Result<bool>;

    // ---- risk engine (M2 T3.4)
    async fn get_risk(&self, key: &RiskKey) -> Result<u32>;
    /// Atomically add `delta` (signed), clamped to `[0, max]`.
    /// Returns the new value.
    async fn add_risk(&self, key: &RiskKey, delta: i32, max: u32) -> Result<u32>;

    // ---- DDoS auto-block list (M2 T2.3)
    async fn auto_block(&self, ip: IpAddr, ttl: Duration) -> Result<()>;
    async fn is_auto_blocked(&self, ip: IpAddr) -> Result<bool>;

    // ---- challenge nonces (M2 T3.6)
    async fn put_nonce(&self, nonce: &str, ttl: Duration) -> Result<bool>;
    /// Returns true if the nonce existed and was atomically removed.
    async fn consume_nonce(&self, nonce: &str) -> Result<bool>;
}

pub struct SlidingWindowResult {
    pub count: u64,
    pub allowed: bool,
    pub retry_after: Option<Duration>,
}
```

**Key namespace.** All keys use the `g:{subsystem}:{key}` prefix
(e.g. `g:rl:sw:1.2.3.4`). The prefix is applied inside each
`StateBackend` impl; callers pass the unprefixed key. A `t:{id}:`
prefix is reserved for future multi-tenancy.

**Lease ownership.** Distributed leases (leader-only tasks) live on
`ClusterMembership::acquire_lease` (§3.8), not on `StateBackend`.

M1 ships `InMemoryBackend` (week 1, `dashmap` + `moka`) and
`RedisBackend` (week 5, `deadpool-redis` with Lua sliding window).
A `RaftBackend` is feature-gated for air-gapped deployments. M2
depends only on the trait — not on any concrete impl.

### 3.3 AuditSink (M2/M1 emit, M3 consumes)

`aegis-core/src/audit.rs` also defines:

```rust
#[derive(Clone)]
pub struct AuditBus(tokio::sync::broadcast::Sender<AuditEvent>);

impl AuditBus {
    pub fn new(cap: usize) -> Self { /* ... */ }
    pub fn emit(&self, ev: AuditEvent) { let _ = self.0.send(ev); }
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<AuditEvent> {
        self.0.subscribe()
    }
}
```

A single `AuditBus` is created in `aegis-bin::main` and passed to all
three crates. M3 subscribes and fans out to sinks (JSONL, Syslog,
Splunk, Kafka, ...). M1 and M2 emit via `bus.emit(...)`.

### 3.4 MetricsRegistry (M3 provides)

```rust
pub struct MetricsRegistry(pub Arc<prometheus::Registry>);
```
M3 creates the registry in `aegis-control::metrics::init()` and
passes it into M1/M2 during boot so they can register their own
families.

### 3.5 SecretProvider (M1 provides, M2+M3 consume)

`aegis-core/src/secrets.rs`:

```rust
#[async_trait::async_trait]
pub trait SecretProvider: Send + Sync + 'static {
    async fn resolve(&self, reference: &str) -> Result<Secret>;
    fn watch(&self, reference: &str)
        -> futures::stream::BoxStream<'static, Secret>;
}

pub struct Secret(pub zeroize::Zeroizing<Vec<u8>>);
```

**Reference grammar (ABNF).** Authoritative — every parser must
accept exactly this shape:
```
secret-ref = "${secret:" provider ":" path [ "#" field ] "}"
provider   = 1*( ALPHA / DIGIT / "-" / "_" )
path       = 1*( %x21-22 / %x24-7B / %x7D ) ; any printable except ':' '#' '}'
field      = 1*( ALPHA / DIGIT / "-" / "_" / "." )
```
Examples: `${secret:env:DB_PASSWORD}`,
`${secret:vault:kv/data/waf#api_key}`,
`${secret:file:/etc/waf/jwt.pem}`.

Providers shipped by M1: `env`, `file`. **M3 owns the cloud providers**
`vault`, `aws-sm`, `gcp-sm`, `azure-kv` (behind feature flags
`vault`, `aws-sm`, `gcp-sm`, `azure-kv`) — see M3 plan §T5.6a–d.
Secrets are resolved at config load and streamed on rotation;
consumers re-derive keys on the `ConfigReloaded` broadcast.

### 3.6 ServiceDiscovery (M1 provides)

`aegis-core/src/sd.rs`:

```rust
#[async_trait::async_trait]
pub trait ServiceDiscovery: Send + Sync + 'static {
    /// Subscribe to a named pool's membership changes.
    async fn subscribe(&self, pool: &str)
        -> Result<tokio::sync::watch::Receiver<Vec<MemberAddr>>>;
}

pub struct MemberAddr {
    pub addr: std::net::SocketAddr,
    pub zone: Option<String>,
    pub weight: u32,
}
```

Impls in M1: `file`, `dns_srv`, `consul`, `etcd`, `k8s` (feature-gated).
The pool manager adds new members in `probing` state until the active
health checker confirms them; removed members enter the drain path.

### 3.7 CacheProvider (M1 provides, policy from config)

`aegis-core/src/cache.rs`:

```rust
#[async_trait::async_trait]
pub trait CacheProvider: Send + Sync + 'static {
    async fn get(&self, key: &CacheKey) -> Option<CachedResponse>;
    async fn put(&self, key: CacheKey, resp: CachedResponse, ttl: std::time::Duration);
    async fn invalidate(&self, key: &CacheKey);
}
```

Tier-aware smart cache: MEDIUM tier is aggressive, HIGH is conservative,
CRITICAL never cached. Used by M1 `proxy.rs` immediately before upstream
selection. Keys include `(method, host, path, vary_headers, tenant_id)`.

### 3.8 ClusterMembership (M3 provides view, M1 provides gossip)

`aegis-core/src/cluster.rs`:

```rust
pub struct NodeInfo {
    pub id: String,          // stable node id
    pub zone: Option<String>,
    pub version: String,     // binary version
    pub load: u32,           // 0..=100
    pub started_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait::async_trait]
pub trait ClusterMembership: Send + Sync + 'static {
    fn self_node(&self) -> &NodeInfo;
    async fn peers(&self) -> Vec<NodeInfo>;
    async fn acquire_lease(&self, key: &str, ttl: std::time::Duration)
        -> Result<Option<Lease>>;
}

pub struct Lease { pub key: String, pub expires_at: std::time::Instant }
```

M1 implements with `foca` (gossip) or a Redis-backed registry behind the
same trait. Leader-only tasks (threat-intel fetch, ACME issue, GitOps
pull, audit witness export) use `acquire_lease`. M3 surfaces `peers()` on
the dashboard and `/api/cluster`.

### 3.9 TenantPressure — **DEFERRED**

Multi-tenancy is out of scope for v1 (see
`docs/deferred/multi-tenancy.md`). The adaptive shedder (M1 T5.3)
operates on **global** and **per-route** signals only; there is no
`TenantPressure` shared state. When multi-tenancy is picked up, a
tenant-pressure trait will land here without touching §3.1–§3.8.

### 3.10 ReadinessSignal (M1 ↔ M3)

`aegis-core/src/health.rs`:

```rust
#[derive(Clone)]
pub struct ReadinessSignal {
    pub config_loaded: Arc<AtomicBool>,
    pub state_backend_up: Arc<AtomicBool>,
    pub certs_loaded: Arc<AtomicBool>,
    pub pool_has_healthy: Arc<AtomicBool>,
    pub draining: Arc<AtomicBool>,
}
```

Created in `aegis-bin::main`, passed to both M1 and M3. M3's
`/healthz/ready` ANDs these. M1 flips `draining` on SIGTERM so M3 starts
returning 503 immediately.

### 3.11 ConfigBroadcast

`aegis-core/src/config.rs`:

```rust
#[derive(Clone, Debug)]
pub enum ConfigEvent { Reloaded { version: u64 }, Failed { error: String } }

pub type ConfigBroadcast = tokio::sync::broadcast::Sender<ConfigEvent>;
```

Any subsystem caching compiled state (rule tree, cert store, DLP
patterns, threat-intel store, OpenAPI index) subscribes and rebuilds on
`Reloaded`. The data-plane hot path does not see the rebuild — ArcSwap
already holds the new compiled value by the time the event fires.

---

## 4. Boot Sequence (owned by `aegis-bin`)

```rust
// crates/aegis-bin/src/main.rs
#[tokio::main]
async fn main() -> aegis_core::Result<()> {
    let cfg_path = parse_args();
    let secrets = aegis_proxy::secrets::build_providers();
    let cfg = Arc::new(ArcSwap::from_pointee(
        aegis_core::config::load(&cfg_path, &secrets).await?
    ));

    // Shared plumbing
    let metrics      = aegis_control::metrics::init();
    let audit_bus    = aegis_core::AuditBus::new(4096);
    let cfg_bcast    = tokio::sync::broadcast::channel(64).0;
    let readiness    = aegis_core::ReadinessSignal::default();
    let state: Arc<dyn StateBackend> =
        aegis_proxy::state::build(&cfg.load().state).await?;
    let cluster: Arc<dyn ClusterMembership> =
        aegis_proxy::cluster::build(&cfg.load(), state.clone()).await?;
    let cache: Arc<dyn CacheProvider> = aegis_proxy::cache::build(&cfg.load());
    let sd: Arc<dyn ServiceDiscovery> = aegis_proxy::sd::build(&cfg.load());

    // M2 builds the pipeline impl
    let pipeline = aegis_security::build(
        cfg.clone(), state.clone(), cache.clone(),
        audit_bus.clone(), metrics.clone(), cfg_bcast.clone(),
    ).await?;

    // M3 control plane starts first so /healthz/startup is observable
    aegis_control::start(
        cfg.clone(), audit_bus.clone(), metrics.clone(),
        readiness.clone(),
        cluster.clone(), cfg_bcast.clone(),
    ).await?;

    // M1 data plane owns the hot path
    aegis_proxy::run(
        cfg.clone(), pipeline, state, sd, cache, cluster,
        audit_bus.clone(), metrics,
        readiness, cfg_bcast,
    ).await
}
```

---

## 5. Error Type

```rust
// aegis-core/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum WafError {
    #[error("config: {0}")] Config(String),
    #[error("io: {0}")] Io(#[from] std::io::Error),
    #[error("state backend: {0}")] State(String),
    #[error("rule: {0}")] Rule(String),
    #[error("other: {0}")] Other(String),
}
pub type Result<T> = std::result::Result<T, WafError>;
```

---

## 6. Integration Checkpoints

| Day | Checkpoint | Owners |
|---|---|---|
| End W1 | `./waf run` boots, `NoopPipeline` returns Allow, `/healthz/live` green | M1+M3 |
| End W2 | One SQLi rule blocks; block appears on dashboard SSE | M1+M2+M3 |
| End W3 | TLS listener + JWT auth + Prometheus scrape green | all |
| End W4 | Dashboard auth green: login + session + CSRF + lockout + IP allowlist | all |
| End W5 | 2-node Redis cluster, red-team suite green, 5k RPS load test | all |

---

## 7. Conventions

- **Formatting:** `cargo fmt` enforced in CI.
- **Lints:** `cargo clippy -- -D warnings`.
- **Tests:** `cargo test --workspace` must be green on `main`.
- **Commit prefix:** `m1:`, `m2:`, `m3:`, or `core:` for shared.
- **PR review:** changes to `aegis-core` require approval from the
  other two members.
- **Feature flags:** `tls`, `redis`, `otel`, `acme`, `http3`, `fips`,
  `consul`, `etcd`, `k8s`, `kafka`, `hsm`, `opa`, `bot_ml`.
- **MSRV:** Rust 1.82.

---

## 8. Requirement → Plan Coverage Matrix

One row per `Requirement.md` section. This is the authoritative
"does the implementation cover everything" checklist. Anything not
owned below is a plan bug — file an issue against `shared-contract.md`.

| Req § | Topic | Owner | Tasks |
|---|---|---|---|
| 3 | Core (binary, dual listener, hot reload) | M1 | T1.1–1.4 |
| 4 | Routing & multi-host | M1 | T2.1–2.3 |
| 5 | Upstream pools + LB + health + CB | M1 | T2.4–2.7 |
| 6 | Traffic mgmt (canary, steering, retry, shadow) | M1 | T4.3–4.5 |
| 7 | TLS, ACME, OCSP, mTLS upstream, FIPS, HSM | M1 | T3.1, 3.5–3.7 |
| 8 | Protocols (h1, h2, WS, gRPC, h3) | M1 | T3.2–3.4, 3.8 |
| 9 | Tiered protection policy | M2 | T1.5 (classifier) |
| 10.1 | Rule engine | M2 | T1.1–1.4 |
| 10.2 | Rate limiting | M2 | T2.1–2.2 |
| 10.3 | DDoS | M2 | T2.3 |
| 10.4 | Attack detectors (OWASP) | M2 | T2.4 |
| 10.5 | Risk + challenge + CAPTCHA | M2 | T3.4–3.7 |
| 10.6 | Device fingerprinting | M2 | T3.1–3.3 |
| 10.7 | IP reputation + ASN + XFF | M2 | T4.1–4.2 |
| 10.8 | Response filtering | M2 | T5.1 |
| 11 | External auth (FA/JWT/OIDC/Basic/CIDR/OPA) | M2 | T5.5–5.6, 5.12–5.14 |
| 12 | Transforms + CORS + rewrite | M1 | T4.2 |
| 13 | Per-route quotas + buffering | M1 | T4.1 |
| 14 | Session affinity | M1 | T4.6 |
| 15 | Observability (Prom/OTel/access logs/health) | M3 | T1.1–1.3, T2.1–2.4 |
| 16 | Audit logging + hash chain + SIEM sinks | M3 | T3.1–3.5 |
| 17 | Zero-downtime (drain, hot binary reload) | M1 | T4.7–4.8 |
| 18 | Service discovery | M1 | T5.6 |
| 19 | HA & clustering (state, gossip, leases) | M1 | T5.1–5.2, T5.7 |
| 20 | Compliance profiles (FIPS/PCI/SOC2/GDPR/HIPAA) | M3 | T5.1 |
| 21 | Dashboard auth (argon2 + session + CSRF + rate-limit + allowlist + optional TOTP + optional mTLS) | M3 | T4.1–4.4 |
| 21 | SSO / OIDC / RBAC / API tokens / 4-eyes approval | — | **DEFERRED** (see `docs/deferred/rbac-sso.md`) |
| 22 | Secrets management (env/file/etcd) | M1 | T5.4 |
| 22 | Secrets management (vault/aws-sm/gcp-sm/azure-kv) | — | **DEFERRED** |
| 23 | Multi-tenancy + tenant governor | — | **DEFERRED** (see `docs/deferred/multi-tenancy.md`) |
| 24 | Threat intelligence | M2 | T4.4 |
| 25 | DLP + FPE | M2 | T5.2–5.3 |
| 26 | API security (OpenAPI/GraphQL/HMAC/keys) | M2 | T5.4, 5.9–5.11 |
| 27 | Bot management | M2 | T4.3 |
| 28 | Content & upload (ICAP + bombs + magic) | M2 | T5.7–5.8 |
| 29 | Adaptive load shedding (global + per-route) | M1 | T5.3 |
| 30 | DR & backup (config + state snapshot) | M1+M3 | M1 T5.5 + M3 T3.6 |
| 31 | Data residency + retention + GDPR erase | M3 | T5.2 |
| 32 | Change mgmt / GitOps + signed commits | M3 | T5.3–5.4 |
| 33 | SLO / SLI / multi-burn alerts | M3 | T5.5 |
| 34 | Deliverables checklist | — | see each DoD |

Behavioral + transaction velocity (Req §10 risk signals) are covered by
M2 T3.8–3.9. Smart caching is M1 T4.9. Cluster membership view is M3
T1.4b (Cluster page). If a row has no tasks, it's a gap — fix the plan,
don't silently skip it.
