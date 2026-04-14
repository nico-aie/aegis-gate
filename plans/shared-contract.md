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

---

## 4. Boot Sequence (owned by `aegis-bin`)

```rust
// crates/aegis-bin/src/main.rs
#[tokio::main]
async fn main() -> aegis_core::Result<()> {
    let cfg_path = parse_args();
    let cfg = Arc::new(ArcSwap::from_pointee(
        aegis_core::config::load(&cfg_path)?
    ));

    let metrics = aegis_control::metrics::init();
    let audit_bus = aegis_core::AuditBus::new(4096);
    let state: Arc<dyn StateBackend> = aegis_proxy::state::in_memory();

    // M2 builds the pipeline impl
    let pipeline = aegis_security::build(cfg.clone(), state.clone(),
                                         audit_bus.clone(), metrics.clone())?;

    // M3 control plane starts first so /healthz/startup is observable
    aegis_control::start(cfg.clone(), audit_bus.clone(),
                         metrics.clone()).await?;

    // M1 data plane owns the hot path
    aegis_proxy::run(cfg.clone(), pipeline, state,
                     audit_bus.clone(), metrics).await
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
- **Feature flags:** `tls`, `redis`, `otel`, `acme`, `http3`, `fips`.
- **MSRV:** Rust 1.82.
