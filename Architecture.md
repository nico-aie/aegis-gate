# WAF Mini Hackathon 2026 – Architecture & Implementation Guide

## 2.1 Overall Architecture (Rust Single Binary)

```
Rust
┌─────────────────────────────┐
│        Config Loader        │  (hot-reload YAML/TOML)
├─────────────────────────────┤
│        Rule Engine          │  (priority-based matching)
├─────────────────────────────┤
│     Risk & Challenge Engine │  (per {IP+FP+Session})
├─────────────────────────────┤
│   Request/Response Pipeline │  (inbound → tier policy → outbound)
├─────────────────────────────┤
│   Caching Layer             │  (tier-aware)
├─────────────────────────────┤
│   Rate Limiter + DDoS       │  (sliding window + token bucket)
├─────────────────────────────┤
│   Device Fingerprint +      │
│   Behavioral Analyzer       │
├─────────────────────────────┤
│   Proxy Core (Hyper + Tokio)│  ← Single binary entry point
└─────────────────────────────┘
          ↓
     Backend (transparent)
```

Entry point: `cargo build --release → ./waf run`

---

## 2.2 Recommended Rust Crates (2026-ready)

### HTTP Proxy Layer
- hyper
- http
- tokio
- tower

### TLS Termination
- rustls
- tokio-rustls
- rustls-platform-verifier

### Async Runtime
- tokio (full)
- mimalloc / jemallocator

### Config (Hot Reload)
- figment
- notify
- serde_yaml / toml

### Rule Engine
- serde
- custom AST or rhai (optional scripting)

### Rate Limiting
- governor OR custom sliding window
- dashmap

### Caching
- moka (async)
- quick-cache

### Device Fingerprinting
- custom JA3/JA4 parser
- HTTP header analysis

### ASN / IP Reputation
- maxminddb
- ipnet

### Dashboard / Metrics
- axum
- tracing
- opentelemetry (optional)

### Logging
- tracing
- tracing-subscriber (JSON logs)

### Performance
- mimalloc
- parking_lot
- crossbeam

---

## 2.3 Implementation Guidelines

### Phase 1 – Foundation

- Build reverse proxy using hyper + tower
- Enable full request/response streaming
- Add route tier classification
- Add config hot reload (notify)

---

### Phase 2 – Core Security Pipeline

```rust
async fn handle_request(req: Request<Body>) -> Response<Body> {
    let tier = classify_tier(req.uri());
    let mut risk = RiskEngine::new(ip, device_fp, session);

    // 1. Global checks (blacklist, proxy detection)
    // 2. Tier-specific policy
    // 3. Rule engine (priority order)
    // 4. Rate limiting + behavioral analysis
    // 5. Challenge decision
    // 6. Forward to backend
    // 7. Response filtering
}
```

---

### Phase 3 – Mandatory Features

1. Rule Engine + Risk Scoring (core brain)
2. Rate Limiting + DDoS protection
3. Device Fingerprinting + Behavior analysis
4. Attack detection (SQLi, XSS, Path Traversal, SSRF)
5. Response filtering (PII + sensitive data)
6. Dashboard (Axum + SSE live feed)

---

### Phase 4 – Performance & Reliability

- Zero-copy optimization (Bytes, Arc)
- Connection pooling
- Circuit breaker (tower + custom logic)
- Fail-open / fail-close per tier (YAML configurable)

---

### Phase 5 – Bonus Features

- TLS termination (rustls)
- GeoIP filtering (MaxMind)
- Multi-region config sync (etcd / file versioning)

---

## 2.4 Testing & Validation Strategy

- Red team attack simulation (SQLi/XSS/SSRF/bruteforce)
- Load testing (wrk / hey ≥ 5000 RPS)
- Chaos testing (backend failure, DDoS simulation)
- Dashboard verification (real-time logs + alerts)

---

## 2.5 Deliverables Checklist

- `./waf run` starts immediately
- Hot reload config (YAML/TOML)
- All tier policies enforced
- OWASP Top 5 mitigated
- Dashboard available at `/dashboard`
- Single static binary output

---

## 2.6 Revised Binary Layout

v1 is a single-upstream proxy wrapped in a security pipeline. v2 inserts a
**route table + upstream pool manager** in front of the pipeline and adds
**TLS**, **observability**, and a **worker supervisor** on the sides.

```
                ┌──────────────────────────────────────────────┐
  TCP listen ─► │  Worker Supervisor (SO_REUSEPORT, N workers) │
                └────────────────────┬─────────────────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │  TLS / SNI / ACME       │  (rustls ResolvesServerCert)
                        └────────────┬────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │  Protocol Adapters      │  (h1 / h2 / ws / grpc)
                        └────────────┬────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │  Route Table            │  (host + path → Route)
                        └────────────┬────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │  v1 Security Pipeline   │  (rules, detectors, risk,
                        │  (unchanged)            │   rate limit, challenge)
                        └────────────┬────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │  Transformations / CORS │
                        │  ForwardAuth / JWT      │
                        └────────────┬────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │  Upstream Pool Manager  │  (LB + health + CB)
                        └────────────┬────────────┘
                                     │
                                     ▼
                               Backend pools

         Side channels:
          ├── Prometheus /metrics exporter
          ├── OpenTelemetry OTLP exporter (optional)
          ├── Access-log writer
          └── Dashboard (v1, extended with routes + pools views)
```

Key invariant: the v1 security pipeline is **unchanged** and runs after the
route has been resolved but before the upstream is selected. Per-route tier
overrides are applied by the route table and then fed into the existing
`classify_tier` fallback.

---

## 2.7 Route Table & Host Matching

*Implements §1.7.*

```rust
pub struct RouteTable {
    hosts: Vec<HostEntry>,      // sorted: exact > wildcard > default
}

pub struct HostEntry {
    matcher: HostMatcher,        // Exact | Wildcard("*.example.com") | Default
    path_index: PathTrie<Route>, // longest-prefix lookup
}

pub struct Route {
    id: String,
    methods: Option<Vec<Method>>,
    path_matcher: PathMatcher,   // Exact | Prefix | Regex | Glob
    tier_override: Option<Tier>,
    upstream_ref: String,        // name of a Pool
    transforms: Transforms,      // add/set/remove headers, rewrites
    quotas: RouteQuotas,
    auth: Option<AuthConfig>,
    policies: RoutePolicies,     // per-route rate limit, challenge, cache
}
```

**Matching algorithm:**

1. Resolve Host by exact → wildcard → default.
2. Within the host, walk the path trie for longest-prefix match; regex and
   glob entries are evaluated in declaration order after the trie miss.
3. If method filter fails, continue to next candidate.
4. On miss, fall through to the v1 catch-all tier.

The route table lives inside `ArcSwap<WafConfig>` so it reloads atomically
with the rest of the config.

---

## 2.8 Upstream Pool Manager

*Implements §1.8.*

```rust
pub struct Pool {
    name: String,
    members: Vec<Member>,
    lb: LbStrategy,              // RoundRobin | LeastConn | ConsistentHash(Key)
    health: HealthState,
    circuit: CircuitState,
    keepalive: hyper_util::client::legacy::Client<_, _>,
}

pub struct Member {
    addr: SocketAddr,
    weight: u32,
    zone: Option<String>,
    healthy: AtomicBool,
    inflight: AtomicU32,
    ewma_latency_ms: AtomicU32,
    consecutive_failures: AtomicU32,
}
```

- **Round-robin**: atomic counter modulo live-member count.
- **Least-connections**: scan members, pick lowest `inflight`.
- **Consistent-hash**: `hashring` crate keyed by client IP / cookie / header,
  with virtual nodes for balanced distribution.
- **Active health checker**: one `tokio::spawn` per pool, periodic probe with
  configurable method/path/expected-status.
- **Passive ejection**: pipeline increments `consecutive_failures` on 5xx /
  connect error; threshold trips the circuit breaker.
- **Circuit breaker** states:
  - `Closed` (normal)
  - `Open` (reject immediately, return 503 to pipeline)
  - `HalfOpen` (allow a probe request; success → Closed, failure → Open)

Each pool owns its own `hyper` client so keepalive connections are scoped
per pool (avoids head-of-line blocking across unrelated backends).

---

## 2.9 TLS / SNI / ACME Subsystem

*Implements §1.10.*

```rust
pub struct CertStore {
    by_host: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
}

pub struct DynamicResolver {
    store: Arc<ArcSwap<CertStore>>,
}

impl rustls::server::ResolvesServerCert for DynamicResolver { … }
```

- File watcher (`notify`) reloads PEM cert + key pairs on disk changes;
  swap is atomic via `ArcSwap<CertStore>`.
- Optional **ACME** client (`instant-acme` or `rustls-acme`) for Let's
  Encrypt. HTTP-01 challenge responses are served via a dedicated route
  under `/.well-known/acme-challenge/` injected into the route table.
  TLS-ALPN-01 is handled at the rustls layer.
- **OCSP stapling**: background task fetches OCSP responses per cert and
  populates `CertifiedKey::ocsp`.
- **mTLS to upstream** is a per-pool option: the pool's `hyper` client is
  built with a `rustls::ClientConfig` carrying a client cert + CA roots.

---

## 2.10 Protocol Adapters

*Implements §1.11.*

- **HTTP/1.1 and HTTP/2**: served by `hyper::server::conn::auto::Builder`
  (auto-detect based on ALPN).
- **WebSocket**: when the inbound request carries `Upgrade: websocket`, the
  security pipeline runs as normal against the handshake; after the pipeline
  approves, the handler uses `hyper::upgrade::on(req)` to obtain the raw
  stream and splices it to an upstream-side upgraded connection with
  `tokio::io::copy_bidirectional`.
- **gRPC**: no special handling beyond HTTP/2 — the pipeline must preserve
  trailers. The response forwarding code is updated to stream frames + trailers
  instead of collecting the whole body.
- **HTTP/3 (bonus)**: `quinn` + `h3` feature-gated behind `--features http3`.

---

## 2.11 Auth Subsystem

*Implements §1.12.*

```rust
pub enum AuthConfig {
    ForwardAuth {
        address: String,
        copy_request_headers: Vec<String>,
        copy_response_headers: Vec<String>,
        timeout: Duration,
    },
    Jwt {
        jwks_url: String,
        issuer: String,
        audience: Vec<String>,
        required_claims: Vec<String>,
    },
    Basic { htpasswd_path: String },
    CidrAllow(Vec<IpNet>),
}
```

- **ForwardAuth** uses a dedicated `hyper` client; the subrequest path is
  `GET <address><original path>` by default, configurable. Selected response
  headers (e.g. `X-Auth-User`, `X-Auth-Groups`) are copied into the
  upstream-bound request and into `RequestContext` for the rule engine.
- **JWT** uses `jsonwebtoken` with a JWKS cache keyed by `kid`. The JWKS
  fetcher is a `moka::future::Cache` with TTL + stale-while-revalidate.
- Validated claims are attached to `RequestContext` so rules can reference
  `user.role`, `user.id`, etc.

---

## 2.12 Observability Exporter

*Implements §1.16.*

- `prometheus` crate registry shared across the binary; the existing
  dashboard Axum router mounts `/metrics` alongside `/api/*`.
- Histograms: upstream latency, pipeline latency, detector latency, TLS
  handshake time. Counters: requests by `(tier, decision)`, detector hits,
  circuit-breaker trips, pool health transitions.
- **Trace propagation**: a small middleware reads incoming `traceparent`, or
  generates a fresh one, and writes it into `RequestContext`; the header is
  forwarded upstream and included in access logs.
- **OpenTelemetry OTLP** (feature-gated): `opentelemetry-otlp` + batch
  exporter. Traces capture the pipeline stages as child spans.
- **Access log writer**: a background `tokio` task drains a bounded channel
  of `AccessLogRecord`s, formatting via one of:
  - `combined` (nginx-default)
  - `json` (one-line JSON per request)
  - Custom template string with `%{var}` placeholders
  Output target: stdout or a rotating file (`tracing-appender`).

---

## 2.13 Worker Supervisor & Graceful Reload

*Implements §1.17.*

- Main process sets up the tokio runtime, loads config, then creates N
  worker tasks that each `bind()` the listener with `SO_REUSEPORT` so the
  kernel distributes accepts across workers.
- `InFlightTracker` is an `Arc<AtomicUsize>` incremented on `handle_request`
  entry and decremented in a guard's `Drop`.
- **Drain sequence** on `SIGTERM`:
  1. Close the listener (no more accepts).
  2. Start a drain deadline timer (e.g. 30s).
  3. Wait for `InFlightTracker` to hit zero or the deadline to expire.
  4. Exit with code 0.
- **Hot binary reload (bonus)** on `SIGUSR2`: the running process spawns the
  new binary with the listener FD inherited via `CommandExt::fd_mappings`
  (or via `systemd` socket activation). The new process begins accepting
  on the same port thanks to `SO_REUSEPORT`; the old process drains as
  above and exits.
- **Dry-run validator**: the config watcher first parses the candidate
  config into a fully-resolved `WafConfig` (including compiling regexes and
  building the route table). Only if construction succeeds is the
  `ArcSwap` updated. Failures are logged and reported to the dashboard.

---

## 2.14 Config Schema Additions

New top-level keys added to `src/config/schema.rs`. All are optional with
sensible defaults, so existing v1 configs remain valid.

```yaml
routes:
  - host: "api.example.com"
    path: "/v1/"
    match_type: prefix
    upstream: api_v1_pool
    tier_override: high
    transforms:
      request_headers:
        set:
          X-Real-IP: "${client_ip}"
        remove: [Cookie]
    auth:
      type: jwt
      jwks_url: "https://issuer.example.com/.well-known/jwks.json"
      audience: ["api.example.com"]
    quotas:
      client_max_body_size: 1048576
      read_timeout_ms: 15000

upstreams:
  api_v1_pool:
    lb: least_conn
    members:
      - addr: "10.0.0.1:8080"
        weight: 1
      - addr: "10.0.0.2:8080"
        weight: 1
    health_check:
      path: "/healthz"
      interval_s: 5
      timeout_ms: 2000
      unhealthy_after: 3
    circuit_breaker:
      error_threshold_pct: 50
      min_requests: 20
      open_duration_s: 30

tls:
  listen: "0.0.0.0:443"
  certificates:
    - host: "api.example.com"
      cert_file: "/etc/waf/certs/api.pem"
      key_file:  "/etc/waf/certs/api.key"
  acme:
    enabled: false
    email: "ops@example.com"
    hosts: ["api.example.com"]

observability:
  prometheus_path: "/metrics"
  access_log:
    format: json
    target: stdout
  otel:
    enabled: false
    endpoint: "http://otel-collector:4317"

workers:
  count: 4
  drain_timeout_s: 30
```

All of these flow through the existing `ArcSwap<WafConfig>` reload path —
nothing about hot reload changes.

---

## 2.15 New Crate Dependencies

Added to `Cargo.toml` for v2:

```toml
# Routing + LB
hashring = "0.3"

# TLS / ACME
rustls-pemfile = "2"        # (already in v1)
instant-acme = "0.7"        # optional, feature = "acme"
rcgen = "0.13"              # test cert generation

# HTTP/2 + WebSocket
hyper = { version = "1", features = [..., "http2"] }
tokio-tungstenite = "0.24"  # for WS framing (bonus: direct WS server)

# Auth
jsonwebtoken = "9"

# Observability
prometheus = "0.13"
opentelemetry = { version = "0.27", optional = true }
opentelemetry-otlp = { version = "0.27", optional = true }
tracing-opentelemetry = { version = "0.28", optional = true }
tracing-appender = "0.2"

# DNS service discovery (bonus)
hickory-resolver = "0.24"

# Signals
nix = { version = "0.29", features = ["signal"] }
```

Feature flags in `Cargo.toml`:

```toml
[features]
default = ["tls"]
tls  = []
acme = ["dep:instant-acme"]
otel = ["dep:opentelemetry", "dep:opentelemetry-otlp", "dep:tracing-opentelemetry"]
http3 = []   # bonus
```

---

## 2.16 Revised Implementation Phases (v2)

These phases run **after** the v1 implementation (Phases 1 – 12) is complete.

| Phase | Subsystem | Dependencies |
|-------|-----------|--------------|
| A | Route table + host/path matching | v1 complete |
| B | Upstream pool manager + LB + health checks | A |
| C | Per-route transformations + CORS + quotas | A |
| D | TLS termination with SNI + file-reload certs | B |
| E | HTTP/2 + WebSocket passthrough | D |
| F | External auth (ForwardAuth + JWT) | A |
| G | Observability (Prometheus + access logs) | A |
| H | Worker supervisor + graceful drain | All above |
| I | ACME + OCSP (bonus) | D |
| J | gRPC passthrough + trailers (bonus) | E |
| K | OpenTelemetry + traceparent propagation (bonus) | G |
| L | Service discovery (bonus) | B |
| M | Hot binary reload via SO_REUSEPORT + FD passing (bonus) | H |

---

## 2.17 Migration Notes

v2 must stay backwards compatible with v1 configs. Migration rules:

- If a config has no `upstreams` / `routes` blocks, the v1 `upstream.address`
  is auto-wrapped into a synthetic single-member pool named `default`, and
  a single catch-all route `{host: _, path: /, upstream: default}` is
  inserted at table build time.
- v1 tier classification remains the fallback when no route matches.
- v1 security pipeline stages are unchanged and run between the route
  match and the upstream selection.
- v1 dashboard pages continue to work; new pages (`/dashboard/routes`,
  `/dashboard/upstreams`) are added alongside them.
- v1 `config/waf.yaml` continues to parse. New fields are additive.

---

## 2.18 Testing & Validation Strategy (v2 additions)

On top of the v1 test strategy (§2.4):

- **Host-routing conformance**: table-driven tests covering exact, wildcard,
  and default host matching with overlapping paths.
- **Health-check flap**: unit test that brings a member down and back up and
  verifies LB rotation + circuit-breaker state transitions.
- **TLS/SNI handshake matrix**: openssl s_client against multiple SNI names
  with different cert profiles.
- **WebSocket echo**: end-to-end test with `tokio-tungstenite` client through
  the WAF to an echo backend.
- **HTTP/2 + gRPC**: `tonic` echo service behind the WAF, verify trailers
  are preserved.
- **ForwardAuth**: spin up a mock auth service that returns 200 / 401
  based on a header; verify the WAF enforces the decision and copies
  response headers.
- **JWT**: validate a signed token against a local JWKS and verify claims
  are surfaced to the rule engine.
- **Graceful drain**: `wrk` under load while `SIGTERM` is sent; count
  dropped in-flight requests — must be zero.
- **Prometheus scrape**: start the WAF, send traffic, scrape `/metrics`,
  assert expected metric families and labels exist.
- **Dry-run validator**: feed an intentionally broken rule file; assert
  the running config is untouched and the dashboard shows the error.

---

---

# Enterprise Readiness Addendum (§2.20 – §2.35)

The following sections design the subsystems required by the enterprise
addendum of the requirements doc (§1.20 – §1.35). They slot into the v2
binary alongside the edge-proxy subsystems described above.

---

## 2.20 Control Plane vs Data Plane Separation

*Implements §1.23 Admin Access Control and underpins §1.20 HA.*

The binary logically splits into two planes that bind different listeners:

```
┌──────────────────────────┐     ┌──────────────────────────┐
│   Data Plane (public)    │     │   Control Plane (admin)  │
│   :80, :443              │     │   :9443 (mTLS)           │
│                          │     │                          │
│   TLS → Routing →        │     │   Dashboard (Axum)       │
│   Pipeline → Upstream    │     │   Admin API (REST+gRPC)  │
│                          │     │   /metrics /healthz      │
└──────────┬───────────────┘     └─────────┬────────────────┘
           │                               │
           └─────────┬─────────────────────┘
                     ▼
         ┌──────────────────────────┐
         │   Shared State Backend   │
         │  (Redis / Raft / memory) │
         └──────────────────────────┘
```

- Data-plane hot path never queries the admin listener.
- Control-plane mutations publish notifications over an internal channel
  that the data plane consumes (`tokio::sync::broadcast`) so `ArcSwap`
  updates propagate without polling.
- Per-listener feature flags allow running control plane on a
  bastion-only interface.

---

## 2.21 Clustered / Distributed State

*Implements §1.20 HA & Clustering.*

State access is abstracted behind a trait so the rest of the code is
backend-agnostic:

```rust
#[async_trait]
pub trait StateBackend: Send + Sync {
    async fn incr_window(&self, key: &str, window: Duration) -> u32;
    async fn get_risk(&self, key: &RiskKey) -> u32;
    async fn add_risk(&self, key: &RiskKey, delta: u32, max: u32) -> u32;
    async fn auto_block(&self, ip: IpAddr, ttl: Duration);
    async fn is_auto_blocked(&self, ip: IpAddr) -> bool;
    async fn revoke_token(&self, jti: &str, ttl: Duration);
    async fn is_revoked(&self, jti: &str) -> bool;
}
```

Implementations:

- `InMemoryBackend` — v1/v2 behavior (DashMap).
- `RedisBackend` — Redis Cluster with Lua scripts for atomic sliding
  windows and INCRBY + EXPIRE fused. Connection pool via `deadpool-redis`.
- `RaftBackend` (bonus) — embedded Raft (`openraft`) for air-gapped
  deployments, strong consistency for critical counters.

**Cluster membership** uses `foca` (Rust SWIM implementation) or a
shared config registry. Each node publishes `(id, zone, load, version)`;
the dashboard and admin API surface the view.

**Split-brain safety**: sliding-window counters use `max(local, remote)`
semantics on reconciliation so a partition can only be more restrictive,
never less.

---

## 2.22 Compliance Architecture

*Implements §1.21 Compliance.*

- **FIPS mode** is a runtime flag wired through a Rust feature gate on
  `rustls` (`rustls` + `aws-lc-rs` with FIPS provider). A config-load
  hook walks all configured ciphers, HMAC algorithms, and signing keys
  and refuses any that are not in the FIPS allowlist.
- **Tamper-evident audit log** — each admin-change and security event
  carries `prev_hash = SHA-256(prev_record || fields)`. A nightly job
  exports the Merkle root to an external witness (file, S3 Object Lock,
  or blockchain anchor) for post-incident verification.
- **PCI mode** binds listeners with TLS 1.2+ only, enables Luhn-based PAN
  redaction in the DLP engine, and sets the default log retention to 90
  days.
- **GDPR data-residency tags** are on every log sink; the exporter
  refuses cross-region delivery when tags don't match.
- **Right-to-erasure**: an admin endpoint walks the state backend and
  local spool files purging by identifier, with an attested report.

---

## 2.23 Secrets Management Subsystem

*Implements §1.22.*

```rust
#[async_trait]
pub trait SecretProvider: Send + Sync {
    async fn resolve(&self, reference: &str) -> Result<Secret>;
    async fn watch(&self, reference: &str) -> BoxStream<'static, Secret>;
}

pub struct Secret(Zeroizing<Vec<u8>>);
```

- `${secret:vault:kv/data/waf#tls_key}` style references are parsed at
  config load; unresolved references block load.
- Providers shipped: `env`, `file`, `vault` (`vaultrs`), `aws-sm`,
  `gcp-sm`, `azure-kv`.
- Watcher streams feed the existing `ArcSwap<WafConfig>` pipeline so
  rotation is transparent to the data plane.
- `Zeroize` + `Zeroizing<T>` hold all secret bytes; the compiler plugin
  `secrecy` is used at struct level for compile-time enforcement.
- **HSM** support via `cryptoki` (PKCS#11) behind a feature flag.

---

## 2.24 RBAC & SSO Subsystem

*Implements §1.23.*

- The admin router (Axum) wraps every mutating handler in a
  `require_role!(Operator)` macro; reads use `require_role!(Viewer)`.
- **OIDC** via `openidconnect` crate; tokens are verified against the
  IdP's JWKS (cached via `moka`). User → role mapping is driven by
  claims (`groups`, `roles`) with a config-defined matrix.
- **Local users** stored in `htpasswd`-style file behind `argon2`
  hashing; only available when `admin.local_users.enabled = true`.
- **API tokens**: `PASETO v4.local` tokens issued via the admin API,
  scoped (`tenant_id`, `permissions`, `expires_at`), revocable.
- **Change audit**: every mutating handler emits an `AdminChangeEvent`
  to the hash-chained audit log (§2.22).
- **MFA** is delegated to the IdP (the WAF verifies `amr` / `acr`
  claims).

---

## 2.25 Multi-Tenancy Data Model

*Implements §1.24.*

- `Tenant` is a new top-level config struct. Routes, upstreams, rules,
  quotas, and policies are all `Option<TenantId>`-tagged.
- State-backend keys are prefixed with `tenant:{id}:…` so Redis / Raft
  partitioning is automatic.
- **Per-tenant quotas** are enforced by a `TenantGovernor` sitting in
  front of the pipeline: it tracks current in-flight + rate per tenant
  and load-sheds offenders with 503 (§2.32) without touching other
  tenants.
- **Dashboard scoping**: every admin API handler projects results
  through the caller's tenant set. Viewer tokens are single-tenant by
  default.

---

## 2.26 SIEM & Log Forwarding Subsystem

*Implements §1.25.*

```rust
pub enum SinkKind {
    Stdout,
    File(RotatingFileSink),
    SyslogTcpTls { endpoint: Url, format: EventFormat },
    Kafka { brokers: Vec<String>, topic: String },
    Http { endpoint: Url, format: EventFormat },
}

pub enum EventFormat { Combined, Json, Cef, Leef, Ocsf }
```

- A single `EventBus` (`tokio::sync::broadcast`) decouples emitters
  from sinks. Sinks each run a dedicated task with a bounded channel.
- **Backpressure**: on bounded-channel full, the sink spools to disk
  (`sled` ring or a bounded file); on overflow it drops
  lowest-severity first and increments a drop counter.
- **Formatters** are trait objects; CEF/LEEF use fixed field maps with
  escape rules. OCSF reuses the internal event schema with a JSON
  projection.
- **Kafka** via `rdkafka` with SASL/TLS; partitions keyed by
  `(tenant_id, client_ip)` for ordering guarantees.

---

## 2.27 Threat Intelligence Subsystem

*Implements §1.26.*

```rust
pub struct ThreatIntelStore {
    ips: IpRangeSet,              // aggregated CIDR set
    domains: aho_corasick::AhoCorasick,
    urls: aho_corasick::AhoCorasick,
    hashes: HashSet<[u8; 32]>,
    provenance: DashMap<Indicator, FeedId>,
}
```

- Feed fetchers run as periodic tokio tasks with `reqwest` + `ETag`
  handling. **STIX/TAXII** via a dedicated client (custom or `stix`
  crate when available).
- Incremental updates: feeds publish additions and removals; the store
  is rebuilt incrementally and swapped via `ArcSwap`.
- The IP-reputation check in the v1 pipeline is rewired to consult the
  `ThreatIntelStore` in addition to the static config lists.
- **Provenance**: when an indicator fires a block, the `FeedId` is
  included in the audit event so analysts can trace back.

---

## 2.28 Advanced Bot Management

*Implements §1.27.*

- **Classification pipeline**: UA → ASN + rDNS verification → TLS JA3/JA4
  lookup in a known-bot database → behavioral signals. The classifier
  emits a `BotClass` (`Verified`, `Unknown`, `Likely`, `Known`) that
  feeds the risk engine.
- **CAPTCHA provider** is a trait:
  ```rust
  #[async_trait]
  pub trait CaptchaProvider {
      async fn verify(&self, response: &str, client_ip: IpAddr) -> Result<bool>;
      fn widget_html(&self, site_key: &str) -> String;
  }
  ```
  Implementations: Turnstile, hCaptcha, reCAPTCHA v3.
- **Escalation state machine** lives inside the challenge engine:
  `None → JS → PoW → CAPTCHA → Block`, indexed on the challenge nonce
  so replay of an old level on the new page fails.
- **Human-confidence score** persists in the state backend keyed by
  device fingerprint and decays like risk score.

---

## 2.29 API Security Guard (OpenAPI + GraphQL)

*Implements §1.28.*

- **OpenAPI loader** compiles a loaded OpenAPI 3.x document into a
  `RouteSchemaIndex` keyed by `(method, path)`. Path templates are
  converted to a radix tree for O(log n) lookup.
- **Validator** (`jsonschema-rs`) checks body + query + headers against
  the operation schema. A violation raises a `DetectionResult` with
  `attack_type = "schema_violation"` so it flows through the existing
  risk engine and actions.
- **GraphQL guard**: a lightweight parser (`async-graphql-parser`)
  computes depth + field count before forwarding. Introspection
  queries are rejected when disabled.
- **HMAC signing**: per-route config specifies algorithm, header, and
  secret reference; mismatched signatures are blocked.

---

## 2.30 DLP Engine

*Implements §1.29.*

```rust
pub struct DlpEngine {
    patterns: Vec<CompiledPattern>,
    ac: aho_corasick::AhoCorasick,  // anchors for literal-heavy patterns
}

pub struct CompiledPattern {
    name: String,
    category: DlpCategory,
    regex: Regex,
    validator: Option<fn(&str) -> bool>,  // e.g. Luhn for PAN
    action: DlpAction,                     // Mask | Block | Alert
    masker: MaskStrategy,
}
```

- Runs inbound (request bodies) and outbound (response bodies). Bodies
  are processed in chunks to avoid buffering large payloads.
- **PAN detection** uses aho-corasick prefilter then a per-candidate
  Luhn check. **API keys** use provider-specific prefixes
  (`AKIA`, `ghp_`, `sk-`).
- **Masking strategies**: full, last-N, hash, or FPE (format-preserving
  encryption) via `orion`.
- Pattern library is hot-reloadable via the existing watcher.

---

## 2.31 Content Scanning (ICAP Client)

*Implements §1.30.*

- `IcapClient` implements RFC 3507 `REQMOD` / `RESPMOD`. Connections
  are pooled per target.
- Upload routes buffer the body up to a configured cap, then stream it
  into the ICAP client. The verdict (`allow`, `modify`, `block`) maps
  to pipeline decisions.
- **Magic-byte detection** via `infer` crate.
- **Archive bomb** protection: depth counter in the `zip`/`tar` walker
  aborts on ratio breach.

---

## 2.32 Adaptive Load Shedding

*Implements §1.31.*

- A per-listener `AdmissionController` tracks concurrent in-flight and
  a rolling p99 latency EWMA.
- Algorithm: **Gradient2** (Netflix concurrency-limits) — expands the
  limit while latency is stable, contracts on latency rise.
- A global `PriorityScheduler` orders the admission queue by tier so
  CRITICAL is always admitted ahead of CATCH-ALL.
- **Self-health** samples: process CPU from `/proc/self/stat`, RSS from
  `/proc/self/status`, tokio metrics. Crossing thresholds triggers
  aggressive shedding (reject CATCH-ALL entirely) until pressure
  subsides.

---

## 2.33 DR / Backup Subsystem

*Implements §1.32.*

- `waf config export --out snapshot.tar.zst` serializes the effective
  `WafConfig` + rules + tenant definitions into a deterministic archive
  signed with the cluster key.
- `waf config import snapshot.tar.zst --dry-run` runs the existing
  dry-run validator; `--apply` activates.
- Periodic backup is a tokio task with a pluggable target (`s3`, `gcs`,
  `file`, `sftp`). Retention policy is age + count.
- **State snapshot** (bonus) serializes the state backend via its
  native export (Redis `BGSAVE`, Raft snapshot).

---

## 2.34 Change Management / GitOps

*Implements §1.34.*

- A `GitSyncer` task clones or pulls a configured repo on interval,
  validates the effective config, and stages it for activation.
- **Signed commits**: commits are verified with a configured set of
  allowed GPG / SSH keys before they are considered.
- **Dashboard edits in Git-sync mode** produce a PR to the target repo
  via the Git host's API (GitHub / GitLab) rather than mutating
  locally. In "break-glass" mode, mutations apply locally and are
  tracked for later reconciliation.
- CLI: `waf config diff` shows pending changes against the live
  configuration; `waf config apply` triggers the dry-run + swap.

---

## 2.35 SLO / Health Endpoints

*Implements §1.35.*

- `/healthz/live` — always OK while the process is running.
- `/healthz/ready` — OK when: config loaded, state backend reachable,
  at least one upstream pool has a healthy member for each critical
  route, listeners bound.
- `/healthz/startup` — OK after the first successful config load and
  ACME / cert resolution.
- **SLI recorder** wraps the pipeline with histograms for availability
  and latency; `slo_burn_rate` is exported as a metric so Alertmanager
  rules can reference it.
- **Alert sinks**: Alertmanager-compatible webhook receiver and
  direct PagerDuty / Slack sinks.

---

## 2.36 Revised Stack Diagram (v2 + Enterprise)

```
                  ┌────────────────────────────────────────────┐
   SIGTERM/USR2 ─►│  Worker Supervisor (SO_REUSEPORT, N workers)│
                  └──────────────────┬──────────────────────────┘
                                     │
                         ┌───────────▼────────────┐
                         │  Admission / Load Shed │ ◄── self-health
                         └───────────┬────────────┘
                                     │
                         ┌───────────▼────────────┐
                         │  TLS / SNI / ACME      │
                         │  (FIPS-mode gated)     │
                         └───────────┬────────────┘
                                     │
                         ┌───────────▼────────────┐
                         │  Protocol Adapters     │  (h1/h2/ws/grpc)
                         └───────────┬────────────┘
                                     │
                         ┌───────────▼────────────┐
                         │  Tenant Governor       │ ◄── per-tenant quotas
                         └───────────┬────────────┘
                                     │
                         ┌───────────▼────────────┐
                         │  Route Table           │
                         └───────────┬────────────┘
                                     │
                         ┌───────────▼─────────────┐
                         │  Threat Intel + IP rep  │
                         │  Bot Classifier         │
                         └───────────┬─────────────┘
                                     │
                         ┌───────────▼────────────┐
                         │  v1 Security Pipeline  │
                         │  (rules/detect/risk)   │ ◄── State Backend
                         └───────────┬────────────┘      (Redis / Raft)
                                     │
                         ┌───────────▼────────────┐
                         │  OpenAPI/GraphQL Guard │
                         │  HMAC / JWT / ForwardAuth│
                         └───────────┬────────────┘
                                     │
                         ┌───────────▼────────────┐
                         │  DLP + ICAP scan       │
                         └───────────┬────────────┘
                                     │
                         ┌───────────▼────────────┐
                         │  Transforms / CORS     │
                         └───────────┬────────────┘
                                     │
                         ┌───────────▼────────────┐
                         │  Upstream Pool Manager │
                         └───────────┬────────────┘
                                     │
                                     ▼
                               Backend pools

   Control plane (separate listener, mTLS + OIDC + RBAC):
     ├── Dashboard (multi-tenant)
     ├── Admin API (REST + gRPC, audit-logged)
     ├── /metrics  /healthz/{live,ready,startup}
     └── GitSync / Secret provider watchers

   Side exporters:
     ├── SIEM sinks (syslog/CEF/LEEF/Kafka/OCSF)
     ├── OTel traces + metrics
     ├── Access log writer
     └── Hash-chained audit log + witness anchor
```

---

## 2.37 Additional Crate Dependencies (Enterprise)

```toml
# Clustering / state
deadpool-redis = "0.18"
foca = "0.17"              # SWIM membership
openraft = "0.9"           # bonus

# Compliance / crypto
aws-lc-rs = "1"            # FIPS-capable rustls provider
zeroize = "1"
secrecy = "0.8"
cryptoki = "0.7"           # PKCS#11 / HSM (bonus)

# Secrets
vaultrs = "0.7"
aws-sdk-secretsmanager = "1"
aws-sdk-ssm = "1"

# Auth / RBAC
openidconnect = "4"
argon2 = "0.5"
rusty_paseto = "0.7"
jsonwebtoken = "9"         # shared w/ §2.11

# SIEM / logging
rdkafka = "0.37"
syslog = "7"
# (CEF/LEEF/OCSF formatters are written inline)

# Threat intel
reqwest = { version = "0.12", features = ["json", "gzip", "stream"] }

# API security
jsonschema = "0.28"
openapiv3 = "2"
async-graphql-parser = "7"

# DLP
regex = "1"                # shared
infer = "0.16"             # magic-byte

# Scanning
# (custom ICAP client; no ready crate)

# Load shedding
# (custom; can borrow concurrency-limits patterns)

# Git sync
gix = "0.66"               # pure-Rust git

# Health / alerting
prometheus = "0.13"        # shared w/ §2.15
```

All new dependencies are behind feature flags so the minimal build does
not pay for unused subsystems.

---

## 2.38 Enterprise Testing Strategy

In addition to the v1 + v2 test strategies (§2.4, §2.18):

- **Cluster consistency**: two-node test with Redis, generate load,
  verify rate-limit counters converge and no more than 2× burst slips.
- **FIPS boot**: start the WAF with `compliance.fips: true`; assert
  refusal to load non-FIPS cipher suite.
- **Audit log tamper detection**: mutate a line in the audit log file;
  verifier CLI reports break at expected offset.
- **Secret rotation**: rotate a Vault entry while traffic is flowing;
  assert TLS handshake continues using the new cert within N seconds
  with zero dropped connections.
- **RBAC enforcement**: as `viewer`, attempt every mutating endpoint;
  expect 403.
- **Multi-tenant isolation**: tenant A's viewer token attempts to read
  tenant B's audit log → 404.
- **SIEM round-trip**: fire a synthetic attack, assert CEF record
  arrives at the test SIEM with correct fields.
- **STIX/TAXII**: import a fixture feed, send a request from a listed
  IP, assert block with correct feed provenance.
- **CAPTCHA escalation**: scripted client passes JS but fails CAPTCHA;
  assert final decision is block.
- **OpenAPI enforcement**: send a request violating the schema (extra
  field, wrong type); assert block.
- **DLP masking**: synthetic credit-card number in response body is
  masked before reaching the client.
- **ICAP AV**: upload EICAR test file; assert block.
- **Load shedding**: overload a CATCH-ALL path while keeping a CRITICAL
  path healthy; assert CRITICAL availability ≥ SLO.
- **DR round-trip**: snapshot → wipe state → restore → pipeline works.
- **GitOps**: commit a rule change; assert it becomes active within
  poll interval without manual intervention.
- **Healthz semantics**: kill state backend; `/healthz/live` still OK,
  `/healthz/ready` goes NOT-OK.

---

## 2.19 v2 Deliverables Checklist

- [ ] Single binary with all features compiled in
- [ ] YAML config exercising `routes`, `upstreams`, `tls`, `observability`
- [ ] Two-pool canary demo with weighted split
- [ ] Active + passive health checks verified in integration test
- [ ] HTTPS listener with SNI serving two different hostnames
- [ ] WebSocket echo through the WAF
- [ ] ForwardAuth + JWT routes in the demo config
- [ ] `/metrics` scraped by a local Prometheus
- [ ] `SIGTERM` graceful drain verified under load
- [ ] Dry-run validator rejects malformed config on hot reload
