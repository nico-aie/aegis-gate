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
    pub tenant_id: Option<String>,
    pub trace_id: Option<String>,  // W3C traceparent
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
    pub listeners: Listeners,           // M1
    pub routes: Vec<RouteConfig>,        // M1
    pub upstreams: std::collections::HashMap<String, PoolConfig>, // M1
    pub tls: Option<TlsConfig>,          // M1
    pub rules: RulesConfig,              // M2
    pub rate_limit: RateLimitConfig,     // M2
    pub risk: RiskConfig,                // M2
    pub detectors: DetectorsConfig,      // M2
    pub dlp: DlpConfig,                  // M2
    pub observability: ObservabilityConfig, // M3
    pub audit: AuditConfig,              // M3
    pub admin: AdminConfig,              // M3
    pub tenants: Vec<TenantConfig>,      // M3
    pub compliance: Option<ComplianceProfile>, // M3
}
```
Each sub-config struct lives in its owning crate but is re-exported
through `aegis-core::config` via a feature-flag–free public type, so
`aegis-core` only holds the outer `WafConfig` and the owning crate
provides the inner struct. **Rule:** if a struct has logic, it lives
in the owning crate; if it's pure data that everyone reads, it lives
in `aegis-core`.

---

## 3. Cross-Crate Traits

### 3.1 SecurityPipeline (M1 ↔ M2)

`aegis-core/src/pipeline.rs`:

```rust
#[async_trait::async_trait]
pub trait SecurityPipeline: Send + Sync + 'static {
    /// Inspect inbound request before upstream selection.
    /// Return `Allow` to continue, anything else short-circuits.
    async fn inbound(
        &self,
        req: &mut http::Request<hyper::body::Incoming>,
        rctx: &RequestCtx,
        route: &RouteCtx,
    ) -> Decision;

    /// Inspect outbound response body frames (streaming).
    async fn outbound(
        &self,
        resp: &mut http::Response<hyper::body::Incoming>,
        rctx: &RequestCtx,
        route: &RouteCtx,
    );
}
```

M1 calls these at the fixed points in its proxy loop. M2 provides
the implementation. For week 1, M1 ships a `NoopPipeline` so the
proxy can run standalone.

### 3.2 StateBackend (M1 provides, M2 consumes)

`aegis-core/src/state.rs`:

```rust
#[async_trait::async_trait]
pub trait StateBackend: Send + Sync + 'static {
    async fn incr(&self, key: &str, ttl_s: u32) -> Result<u64>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn set(&self, key: &str, val: &[u8], ttl_s: u32) -> Result<()>;
    async fn del(&self, key: &str) -> Result<()>;
    async fn sliding_window(&self, key: &str, window_s: u32, limit: u64)
        -> Result<SlidingWindowResult>;
}

pub struct SlidingWindowResult { pub count: u64, pub allowed: bool }
```

M1 ships `InMemoryBackend` (week 1) and `RedisBackend` (week 5).
M2 depends only on the trait.

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

Reference syntax: `${secret:<provider>:<path>[#field]}`. Providers shipped
by M1: `env`, `file`. M3 adds `vault`, `aws-sm`, `gcp-sm`, `azure-kv`
behind feature flags. Secrets are resolved at config load and streamed on
rotation; consumers re-derive keys on the `ConfigReloaded` broadcast.

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

### 3.9 TenantPressure (M3 writes, M1 reads)

`aegis-core/src/tenancy.rs`:

```rust
#[derive(Clone, Default)]
pub struct TenantPressure {
    inner: Arc<dashmap::DashMap<String, PressureState>>,
}

pub struct PressureState {
    pub inflight: AtomicU32,
    pub rps_ewma: AtomicU32,
    pub over_quota: AtomicBool,  // set by M3 governor
}
```

M3 flips `over_quota` when a tenant exceeds its quota; M1's adaptive
shedder reads it and rejects that tenant with 503 before touching the
pipeline. Shared Arc, no channel needed.

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
    let tenant_press = aegis_core::TenantPressure::default();
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
        readiness.clone(), tenant_press.clone(),
        cluster.clone(), cfg_bcast.clone(),
    ).await?;

    // M1 data plane owns the hot path
    aegis_proxy::run(
        cfg.clone(), pipeline, state, sd, cache, cluster,
        audit_bus.clone(), metrics,
        readiness, tenant_press, cfg_bcast,
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
| End W4 | OIDC admin login + multi-tenant isolation test green | all |
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
| 21 | RBAC + SSO + admin mTLS + approval | M3 | T4.1–4.4, T5.4 |
| 22 | Secrets management | M1 | T5.4 (+M3 providers) |
| 23 | Multi-tenancy + tenant governor | M3 | T4.5–4.6 |
| 24 | Threat intelligence | M2 | T4.4 |
| 25 | DLP + FPE | M2 | T5.2–5.3 |
| 26 | API security (OpenAPI/GraphQL/HMAC/keys) | M2 | T5.4, 5.9–5.11 |
| 27 | Bot management | M2 | T4.3 |
| 28 | Content & upload (ICAP + bombs + magic) | M2 | T5.7–5.8 |
| 29 | Adaptive load shedding + tenant pressure | M1+M3 | M1 T5.3 + M3 T4.6 |
| 30 | DR & backup (config + state snapshot) | M1+M3 | M1 T5.5 + M3 T3.6 |
| 31 | Data residency + retention + GDPR erase | M3 | T5.2 |
| 32 | Change mgmt / GitOps + signed commits | M3 | T5.3–5.4 |
| 33 | SLO / SLI / multi-burn alerts | M3 | T5.5 |
| 34 | Deliverables checklist | — | see each DoD |

Behavioral + transaction velocity (Req §10 risk signals) are covered by
M2 T3.8–3.9. Smart caching is M1 T4.9. Cluster membership view is M3
T1.4b (Cluster page). If a row has no tasks, it's a gap — fix the plan,
don't silently skip it.
