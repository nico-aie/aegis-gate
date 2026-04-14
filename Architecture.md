# WAF / Security Gateway — Architecture

This document describes the implementation architecture of the WAF defined
in `Requirement.md`. It is a **from-scratch** design: there is no legacy
pipeline to preserve, no migration layer, and no "v1/v2" split. Every
subsystem below is built directly against the requirements.

Language: **Rust**, single static binary (`./waf run`). Runtime: **tokio**.
HTTP: **hyper 1.x**. TLS: **rustls** (optionally `aws-lc-rs` FIPS).

---

## 1. Binary Topology

```
                         ┌────────────────────────────────────────┐
  Internet ── TCP ──►    │  Worker Supervisor                     │
                         │  (SO_REUSEPORT, N workers, graceful    │
                         │   drain, hot binary reload via FD pass)│
                         └──────────────────┬─────────────────────┘
                                            │
                         ┌──────────────────▼─────────────────────┐
                         │  TLS / SNI / ACME / OCSP               │
                         │  rustls ResolvesServerCert + hot swap  │
                         └──────────────────┬─────────────────────┘
                                            │
                         ┌──────────────────▼─────────────────────┐
                         │  Protocol Layer                        │
                         │  h1 / h2 (auto) · WS upgrade · gRPC    │
                         │  h3/QUIC (feature-gated)               │
                         └──────────────────┬─────────────────────┘
                                            │
                         ┌──────────────────▼─────────────────────┐
                         │  Admission Controller                  │
                         │  adaptive concurrency + priority queue │
                         │  (CRITICAL never shed)                 │
                         └──────────────────┬─────────────────────┘
                                            │
                         ┌──────────────────▼─────────────────────┐
                         │  Route Table                           │
                         │  host(exact/wildcard/regex) →          │
                         │  path(trie + regex) → Route            │
                         └──────────────────┬─────────────────────┘
                                            │
                         ┌──────────────────▼─────────────────────┐
                         │  Tenant Governor                       │
                         │  per-tenant quotas + load shedding     │
                         └──────────────────┬─────────────────────┘
                                            │
                         ┌──────────────────▼─────────────────────┐
                         │  Security Pipeline (tiered)            │
                         │  ─ IP reputation / threat intel        │
                         │  ─ Device fingerprint (JA3/JA4/h2)     │
                         │  ─ Rule engine (priority)              │
                         │  ─ Rate limiter (cluster-backed)       │
                         │  ─ DDoS mode                           │
                         │  ─ Attack detectors (OWASP)            │
                         │  ─ API guard (OpenAPI/GraphQL)         │
                         │  ─ Bot classifier                      │
                         │  ─ DLP inbound                         │
                         │  ─ Content scan (ICAP)                 │
                         │  ─ Risk engine → Challenge ladder      │
                         └──────────────────┬─────────────────────┘
                                            │
                         ┌──────────────────▼─────────────────────┐
                         │  External Auth                         │
                         │  ForwardAuth · JWT · OIDC · Basic · IP │
                         └──────────────────┬─────────────────────┘
                                            │
                         ┌──────────────────▼─────────────────────┐
                         │  Transforms · CORS · Rewrite · Quotas  │
                         └──────────────────┬─────────────────────┘
                                            │
                         ┌──────────────────▼─────────────────────┐
                         │  Upstream Pool Manager                 │
                         │  LB · health · circuit · retry ·       │
                         │  shadow · sticky · mTLS upstream       │
                         └──────────────────┬─────────────────────┘
                                            │
                         ┌──────────────────▼─────────────────────┐
                         │  Response Filter                       │
                         │  header hardening · stack scrub ·      │
                         │  DLP outbound · ICAP RESPMOD           │
                         └──────────────────┬─────────────────────┘
                                            ▼
                                     Backend pools

Side channels:
  ├─ Control Plane listener (mTLS + OIDC): dashboard, admin API, /metrics, /healthz
  ├─ State Backend client (Redis / Raft / in-mem)
  ├─ Event Bus → SIEM sinks (JSON/Syslog/CEF/LEEF/OCSF/Kafka/HEC)
  ├─ Audit chain writer → witness exporter
  ├─ Secret providers (env/file/Vault/AWS/GCP/Azure/HSM)
  ├─ Config source (local file + GitOps puller)
  └─ Tracing exporter (OTLP, feature-gated)
```

**Invariant.** The data plane (public listeners) and the control plane
(admin listeners) bind distinct addresses and share nothing on the hot path
other than the `ArcSwap<WafConfig>` and the state-backend handle. A
compromise of one plane does not trivially reach the other.

---

## 2. Module Layout

> **SUPERSEDED.** The single-crate layout below is a conceptual map
> only. The authoritative workspace structure is the 5-crate split
> defined in [`plans/shared-contract.md` §1](plans/shared-contract.md):
> `aegis-core`, `aegis-proxy` (M1), `aegis-security` (M2),
> `aegis-control` (M3), `aegis-bin`. The module names below map onto
> those crates as: `tls/proto/route/upstream/state/sd/secrets/shed/dr`
> → `aegis-proxy`; `security/* + auth/transform/threat_intel`
> → `aegis-security`; `observability/audit/siem/admin/gitops/compliance/tenancy`
> → `aegis-control`; `pipeline + config schema + shared traits`
> → `aegis-core`. Use this section for *what lives where*, not for
> Cargo manifests.

```
crates/waf/
├── src/
│   ├── main.rs                 // CLI: run / validate / audit / config
│   ├── bin/waf.rs
│   ├── supervisor/             // workers, signals, drain, FD passing
│   ├── config/
│   │   ├── schema.rs           // serde types
│   │   ├── loader.rs           // file + Git + secret resolution
│   │   ├── validator.rs        // dry-run compile + lint
│   │   └── watcher.rs          // notify + debounce + ArcSwap
│   ├── tls/                    // rustls resolver, ACME, OCSP, FIPS gate
│   ├── proto/                  // h1/h2/ws/grpc/h3 adapters
│   ├── route/                  // host matcher + path trie/regex
│   ├── upstream/               // pool, lb, health, circuit, retry, shadow
│   ├── pipeline/               // orchestration, tier policy, fail modes
│   ├── security/
│   │   ├── rules/              // AST, compiler, evaluator
│   │   ├── ratelimit/          // sliding window + token bucket
│   │   ├── ddos/               // per-IP burst + global spike
│   │   ├── detect/             // sqli, xss, traversal, ssrf, hdr inj, ...
│   │   ├── fingerprint/        // JA3, JA4, h2, UA entropy
│   │   ├── reputation/         // blacklists, ASN, XFF walk
│   │   ├── risk/               // scoring + decay + decisions
│   │   ├── challenge/          // JS/PoW/CAPTCHA, HMAC tokens, nonce
│   │   ├── bot/                // classifier + verified-bot rDNS
│   │   ├── apiguard/           // OpenAPI + GraphQL + HMAC signing
│   │   ├── dlp/                // inbound+outbound, patterns, FPE
│   │   └── scan/               // ICAP REQMOD/RESPMOD
│   ├── auth/                   // ForwardAuth, JWT, OIDC, Basic, CIDR
│   ├── transform/              // req/resp headers, rewrite, CORS
│   ├── tenancy/                // tenant model + governor + quotas
│   ├── state/                  // StateBackend trait + impls
│   ├── observability/
│   │   ├── metrics.rs          // prometheus registry
│   │   ├── tracing.rs          // W3C Trace Context + OTLP
│   │   ├── access_log.rs       // combined/json/template
│   │   └── health.rs           // /healthz/*
│   ├── audit/                  // hash chain + sinks + witness
│   ├── siem/                   // sink kinds + formatters + spool
│   ├── threat_intel/           // feeds (text/STIX/TAXII/MISP) + store
│   ├── secrets/                // providers + zeroize + rotation
│   ├── admin/                  // Axum router, RBAC, OIDC, API tokens
│   ├── gitops/                 // pull, verify signatures, stage, PR
│   ├── compliance/             // FIPS/PCI/SOC2/GDPR/HIPAA gates
│   ├── dr/                     // config export/import, snapshots
│   ├── sd/                     // service discovery (file/DNS/Consul/etcd/K8s)
│   ├── shed/                   // admission controller (Gradient2)
│   └── util/
└── Cargo.toml
```

---

## 3. Configuration Model

Source of truth: a declarative config tree loaded from a **local file** or
a **Git repository** (GitOps mode), resolved through secret providers, then
compiled into an immutable `WafConfig` held in `ArcSwap<WafConfig>`.

Top-level keys:

```yaml
listeners: { data: [...], admin: {...} }
tls:       { certificates: [...], acme: {...}, fips: false }
tenants:   [ {id, name, quotas, residency, compliance, ...} ]
routes:    [ {host, path, match_type, methods, upstream, tier_override,
              transforms, auth, quotas, tenant_id, policies} ]
upstreams: { pool_name: { lb, members, health, circuit_breaker, tls,
                          retry, shadow, keepalive } }
rules:     [ {id, priority, scope, when, then} ]
ratelimits:[ {scope, algo, key, limit, window} ]
risk:      { weights, decay, thresholds, challenge_ladder }
detectors: { sqli, xss, traversal, ssrf, header_injection, ... }
bot:       { classifier, verified_bots, captcha: {provider, site_key, secret_ref} }
dlp:       { patterns, actions, fpe: {key_ref, version} }
apiguard:  { openapi_specs, graphql: {...} }
threat_intel: { feeds: [...] }
reputation: { blacklist, whitelist, trusted_proxies, asn_deltas }
state:     { backend: redis|raft|in_memory, ... }
audit:     { sinks, chain: {witness}, retention }
secrets:   { providers: {...} }
admin:     { oidc, rbac, api_tokens, ip_allowlist, approvals }
workers:   { count, drain_timeout_s }
observability: { prometheus, otel, access_log }
compliance: { modes: [fips, pci, soc2, gdpr, hipaa] }
gitops:    { repo, branch, allowed_signers, interval }
```

All values support `${secret:<provider>:<path>#<field>}` references,
resolved at load time through the secret subsystem.

### Hot reload pipeline

```
  file/git event ─► loader ─► resolve secrets ─► compile → validate → lint
                                                         │
                                                       fail ──► keep old config,
                                                         │      dashboard banner,
                                                         │      audit event
                                                         ▼
                                              ArcSwap<WafConfig> swap
                                                         │
                                              broadcast(ConfigReloaded)
                                                         │
                       subsystems re-derive indexes (route trie, rule tree,
                       DLP patterns, cert store, …); data plane unaffected
```

Any subsystem that caches compiled state subscribes to `ConfigReloaded` and
rebuilds its indices without touching the hot path.

---

## 4. Request Lifecycle

One pass through the data plane for a single HTTP request:

```
 accept ─► TLS handshake (JA3/JA4 captured)
        ─► h1/h2 decode (h2 fingerprint captured)
        ─► Admission controller (priority by tier, may 503)
        ─► Build RequestContext { client_ip (XFF-walked), device_fp,
                                   session_id, tenant_id, trace_ctx, tier? }
        ─► Route lookup (host → path → Route); tier_override applied
        ─► Tenant governor (per-tenant quotas)
        ─► Security pipeline (see §5), tier-policy-driven fail mode
        ─► External auth (ForwardAuth / JWT / OIDC / Basic / IP)
        ─► Transforms (headers, rewrite, CORS preflight shortcut)
        ─► Upstream selection (LB + sticky + retry + shadow mirror)
        ─► Stream response frames + trailers
        ─► Response filter (headers, stack scrub, DLP, ICAP RESPMOD)
        ─► Emit access log + audit event + metrics + span end
```

Every stage is fallible; the **failure mode** of a stage is tier-resolved:

- CRITICAL routes: any failure → 503, audit, alert.
- Other tiers: failures are logged, the stage is skipped, request continues.
- Per-route `failure_mode` override allowed for non-CRITICAL routes.

The pipeline is expressed as a typed state machine (`PipelineState`) that
threads the `RequestContext` and a growing `Decisions` struct through each
stage. The orchestrator enforces the fail-mode contract centrally so
individual stages need not know their tier.

---

## 5. Security Pipeline

Stages run in this order. Earlier stages can short-circuit later ones.

1. **IP reputation + threat intel.** XFF is walked only when the TCP peer
   is in `trusted_proxies`. ASN classification applies a reputation delta.
   Threat-intel store (CIDR set + Aho-Corasick for domains / URLs + hash
   set for file hashes) contributes matches with `FeedId` provenance.

2. **Device fingerprint.** JA4 primary, JA3 legacy, HTTP/2 SETTINGS +
   pseudo-header order, UA-entropy + header-order for plaintext. Composite
   id = `blake3(salt || ja4 || h2 || ua_bits)`. Stored in the state
   backend with per-deployment salt.

3. **Rule engine.** Priority-ordered, scope-filtered (global → tier →
   route → tenant → session). Rules compile into an `ArcSwap<Vec<CompiledRule>>`
   with an AST evaluator. Match types: exact, regex, wildcard, CIDR,
   AND/OR/NOT. Actions: `Allow`, `Block`, `Challenge(level)`, `RateLimit`,
   `RaiseRisk(delta)`, `Transform`, `LogOnly`. First terminal action wins.

4. **Rate limiter.** Sliding window and token bucket. Scope ∈ {IP, session,
   device, tenant, route, global}. Backed by `StateBackend::incr_window`;
   Redis path uses a Lua script for atomic window increment + TTL.
   **Local fallback** on backend outage reconciles with
   `max(local, remote)` on recovery.

5. **DDoS mode.** Per-IP burst detector (short sliding window → auto-block
   with TTL → cluster-wide set). Global detector compares cluster RPS
   against its rolling average; exceeding `spike_multiplier` enters DDoS
   mode (tighter thresholds, mandatory challenges on new sessions).

6. **Attack detectors.** SQLi, XSS, path traversal, SSRF, HTTP header
   injection, body abuse (size + nesting), brute force, reconnaissance.
   Each detector is a pure function over `RequestContext`; results feed
   both the rule engine and the risk engine.

7. **API guard.** If the route has an OpenAPI spec, validate path +
   method + headers + query + body with `jsonschema`. Modes: `enforce`
   (block on violation), `monitor` (log), `learn` (record into a
   synthesized spec). GraphQL guard applies depth + node + complexity
   limits and (optionally) persisted-query allowlist.

8. **Bot classifier.** Combines JA4/h2 fingerprint, header order, UA
   entropy, rDNS verification (for `Verified` good-bot class), threat-intel
   labels, and failed-challenge history into a `BotClass ∈ {Human, Verified,
   Likely, KnownBad, Unknown}`. Maps to an action via route config.

9. **DLP inbound.** Pattern library + custom regex scan request bodies
   for secrets, PII, credentials. Streaming chunked scan so large uploads
   are not buffered. Actions: redact / mask / hash / FPE / block.

10. **Content scan.** For upload routes, stream the body into an ICAP
    client (REQMOD). Verdict mapped to pipeline decision. Clean-hash cache
    short-circuits repeated identical uploads.

11. **Risk engine + challenge.** `RiskKey = (ip, device_fp, session,
    tenant_id)`. Contributions from detectors, reputation, bot class,
    behavior, transaction velocity, threat intel. Score decays over time.
    Decision:
    - `< 30` allow · `30–70` challenge · `> 70` block.
    - Challenge escalation `None → JS → PoW → CAPTCHA → Block`, driven by
      `(risk, human_confidence, bot_class, tier)`.
    - Tokens: HMAC-signed (`challenge_secret` from secret provider),
      single-use via nonce stored in the state backend, non-downgradable.
    - CAPTCHA providers behind a `CaptchaProvider` trait: Turnstile,
      hCaptcha, reCAPTCHA v3.

12. **Response filter** (runs after the upstream responds). Security header
    injection, stack-trace scrub, internal IP mask, information-leak header
    strip, DLP outbound, ICAP RESPMOD. Streaming chunk processor so large
    responses never balloon memory.

---

## 6. Route Table

```rust
pub struct RouteTable {
    exact_hosts: HashMap<String, HostNode>,
    wildcard_hosts: Vec<(WildcardMatcher, HostNode)>, // "*.example.com"
    regex_hosts: Vec<(Regex, HostNode)>,              // opt-in
    default: HostNode,                                 // mandatory catch-all
}

pub struct HostNode {
    path_trie: PathTrie<Route>,      // longest-prefix wins
    regex_paths: Vec<(Regex, Route>, // evaluated in declaration order
    glob_paths: Vec<(Glob,  Route)>, // ditto
}

pub struct Route {
    id: String,
    methods: Option<Vec<Method>>,
    path_matcher: PathMatcher,
    tier_override: Option<Tier>,
    upstream_ref: UpstreamRef,        // pool or weighted split
    transforms: Transforms,
    auth: Option<AuthConfig>,
    quotas: RouteQuotas,
    tenant_id: Option<TenantId>,
    policies: RoutePolicies,          // rate, challenge, cache
    failure_mode: Option<FailureMode>,
}
```

Lookup: host → trie prefix → regex/glob fallback → method filter → match.
Ties broken by declaration order. Loader refuses configs that fail to cover
every request (the default catch-all is synthesized if absent).

---

## 7. Upstream Pool Manager

```rust
pub struct Pool {
    name: String,
    members: ArcSwap<Vec<Arc<Member>>>,
    lb: LbStrategy,        // RR | WRR | LeastConn | ConsistentHash | P2C
    health: HealthConfig,
    circuit_breaker: CbConfig,
    retry: RetryPolicy,    // attempts, per_try_timeout, statuses, budget
    shadow: Option<ShadowConfig>,
    client: hyper_util::client::legacy::Client<Connector, BoxBody>,
    mtls: Option<ClientTlsConfig>,
}

pub struct Member {
    addr: SocketAddr,
    zone: Option<String>,
    weight: u32,
    healthy: AtomicBool,
    inflight: AtomicU32,
    ewma_rtt: AtomicU64,
    consecutive_failures: AtomicU32,
    cb_state: Atomic<CbState>,       // Closed | Open(since) | HalfOpen
    slow_start_until: AtomicU64,
}
```

- **Active health check** per pool: periodic probe task.
- **Passive ejection** on N consecutive 5xx / connect errors.
- **Circuit breaker** per member with error-rate threshold + open duration.
- **Retry** budget is cluster-wide via a token bucket on the state backend
  so retry storms cannot cascade.
- **Shadow mirroring** spawns a fire-and-forget request to a second pool;
  its response is dropped and never charged to user latency.
- **Sticky session**: HMAC-signed cookie naming the chosen member.
  Consistent-hash is the fallback key space when the cookie is absent.
- **Graceful drain**: removed members finish in-flight before being dropped.
- **Outlier detection** (bonus): ejects members whose p99 diverges beyond
  threshold.

Each pool owns its own `hyper` client so keepalive pools are scoped —
unrelated backends cannot cause head-of-line blocking.

---

## 8. TLS Subsystem

```rust
pub struct CertStore {
    by_host: HashMap<String, Arc<CertifiedKey>>,
    wildcard: Vec<(WildcardMatcher, Arc<CertifiedKey>)>,
    default: Option<Arc<CertifiedKey>>,
}
pub struct DynamicResolver { store: Arc<ArcSwap<CertStore>> }
impl rustls::server::ResolvesServerCert for DynamicResolver { ... }
```

- Certs loaded from disk (PEM), hot-reloaded via `notify`; swap is atomic.
- **ACME** via `instant-acme` for HTTP-01 (a dedicated route under
  `/.well-known/acme-challenge/` is injected) and TLS-ALPN-01 (handled at
  the rustls layer).
- **OCSP stapling**: background task fetches responses per cert and
  populates `CertifiedKey::ocsp`.
- **mTLS upstream** per pool: pool client built with a `rustls::ClientConfig`
  carrying client cert + CA bundle.
- **FIPS mode**: `rustls` + `aws-lc-rs` FIPS provider; cipher / HMAC /
  signing allowlist enforced at load time. Non-FIPS primitives refused.
- **HSM / PKCS#11** (bonus): private keys live behind a `cryptoki`
  provider; signing happens in the HSM.
- **SNI cross-check**: the resolved host must match the request's `Host`
  header when TLS is terminated.

---

## 9. Protocol Adapters

- **HTTP/1.1** and **HTTP/2** served by `hyper::server::conn::auto::Builder`
  (ALPN auto-detect). Header / body / URI limits are enforced at the
  adapter. HPACK dynamic table capped; **rapid-reset (CVE-2023-44487)**
  mitigator counts `RST_STREAM` rate per connection and drops offenders.
- **WebSocket**: the security pipeline inspects the upgrade request; on
  approval the handler uses `hyper::upgrade::on` and splices client ↔
  upstream via `tokio::io::copy_bidirectional` with idle + lifetime timeouts.
- **gRPC**: HTTP/2 with trailers preserved end-to-end. The forwarder
  streams frames + trailers rather than collecting bodies. Per-method
  routing uses the `:path` pseudo-header.
- **HTTP/3** (bonus): `quinn` + `h3`, feature-gated behind `--features http3`.
- **gRPC-Web** (bonus): bridging to plain gRPC.

---

## 10. Auth Subsystem

```rust
pub enum AuthConfig {
    ForwardAuth { address, copy_req_headers, copy_resp_headers, timeout },
    Jwt         { jwks_url, issuer, audience, required_claims },
    Oidc        { issuer, client_id, client_secret_ref, scopes, session_cookie },
    Basic       { htpasswd_ref },
    CidrAllow(Vec<IpNet>),
}
```

- **ForwardAuth**: subrequest through a dedicated `hyper` client; whitelisted
  response headers copied onto the forwarded request and into
  `RequestContext` for rule evaluation. Failure mode honors route tier.
- **JWT**: `jsonwebtoken` with a `moka`-backed JWKS cache keyed by `kid`,
  stale-while-revalidate. Validated claims projected into rules as
  `user.role`, `user.id`, etc., and optionally as headers.
- **OIDC** relying party for browser traffic: session cookie encoded as
  **PASETO v4.local** with the signing key from the secret provider.
- **Basic** against an htpasswd file loaded via secret provider.
- **OPA / Rego callout** (bonus).

---

## 11. Transforms, CORS, Quotas

- **Headers**: add / set / remove on request and response, with variable
  expansion (`$host`, `$client_ip`, `$request_id`, `$jwt.sub`,
  `$cookie.<name>`, `$header.<name>`).
- **Rewrite**: regex rewrite, prefix strip, prefix add, redirect (301/302/
  307/308) with target templating.
- **CORS**: preflight answered directly by the WAF unless the route opts
  out. Origin allowlist supports wildcard subdomains.
- **Quotas**: `client_max_body_size`, header total size, URI length, read /
  write / upstream / absolute timeouts. **Buffering vs streaming** per
  route — streaming disables body-dependent detectors (used for large
  uploads). Distinct HTTP status per quota (`413`, `431`, `408`, `504`,
  `503`) and an audit event naming the specific quota.

---

## 12. State Backend

The authoritative trait definition lives in
[`plans/shared-contract.md` §3.2](plans/shared-contract.md). The
sketch below is illustrative; **do not implement against this snippet**
— follow the contract.

> **Lease ownership note.** `acquire_lease` is **not** on
> `StateBackend`. Distributed leases live on
> `ClusterMembership::acquire_lease` (contract §3.8); the underlying
> impl may delegate to Redis/Raft, but data-plane code calls the
> cluster trait, never the state backend.

```rust
// ILLUSTRATIVE — see plans/shared-contract.md §3.2 for canonical signatures
#[async_trait]
pub trait StateBackend: Send + Sync {
    async fn incr_window(&self, key: &str, window: Duration, limit: u64)
        -> Result<SlidingWindowResult>;
    async fn token_bucket(&self, key: &str, rate: u32, burst: u32) -> Result<bool>;
    async fn get_risk(&self, key: &RiskKey) -> Result<u32>;
    async fn add_risk(&self, key: &RiskKey, delta: i32, max: u32) -> Result<u32>;
    async fn auto_block(&self, ip: IpAddr, ttl: Duration) -> Result<()>;
    async fn is_auto_blocked(&self, ip: IpAddr) -> Result<bool>;
    async fn put_nonce(&self, nonce: &str, ttl: Duration) -> Result<bool>;
    async fn consume_nonce(&self, nonce: &str) -> Result<bool>;
    // generic K/V: get/set/del — see contract
}
```

Implementations:

- **InMemory** — `dashmap` + `moka`, single-node dev.
- **Redis / Redis Cluster** — `deadpool-redis`; atomic sliding windows via
  Lua; keys tenant-prefixed; pipeline fused `INCRBY` + `EXPIRE`.
- **Raft** — embedded `openraft` for air-gapped deployments with strong
  consistency on critical counters.
- **Gossip advisory soft state** — `foca` SWIM for membership + soft
  hints, separate from the authoritative backend.

Cluster membership is surfaced on the dashboard: `(node_id, zone, version,
load, uptime)`. Leader-only tasks (threat-intel fetch, ACME issuance,
GitOps pull, audit witness export) acquire a lease key in the backend.

---

## 13. Multi-Tenancy

`Tenant` is a first-class config entity with: id, name, owner, allowed
hosts, quotas, tier overrides, rule namespace, audit sinks, data residency,
compliance profile, secret mount.

- **Isolation boundaries**: routing (allowed hosts), state keyspace
  (`tenant:{id}:…`), audit + metrics labels, rules (namespaced), secrets
  (tenant-scoped providers).
- **Tenant Governor** sits in front of the pipeline, tracks in-flight +
  RPS per tenant, and 503-sheds offenders so one noisy tenant cannot starve
  others.
- **Security floors** defined by cluster admins set minimum CRITICAL
  controls, TLS versions, retention, and required detectors that tenants
  cannot weaken.
- **Per-tenant dashboards**: admin API handlers project results through the
  caller's tenant set; viewer tokens default to a single tenant.

---

## 14. Secrets Management

```rust
#[async_trait]
pub trait SecretProvider: Send + Sync {
    async fn resolve(&self, reference: &str) -> Result<Secret>;
    fn watch(&self, reference: &str) -> BoxStream<'static, Secret>;
}
pub struct Secret(Zeroizing<Vec<u8>>);
```

- References like `${secret:vault:kv/data/waf#tls_key}` are parsed at
  config load; unresolved references block the swap.
- Providers: env, file (with mode enforcement), HashiCorp Vault
  (`vaultrs`, KV v2 + dynamic creds), AWS Secrets Manager, GCP Secret
  Manager, Azure Key Vault, PKCS#11 HSM.
- **Rotation without restart**: watcher streams feed the reload pipeline;
  TLS / HMAC / upstream mTLS reload atomically.
- **Memory hygiene**: `Zeroize` + `Zeroizing<T>` for all secret bytes.
- **Never in logs**: `/api/config` returns the reference string, never the
  resolved value.

---

## 15. Admin Plane

- **Listener**: separate address, mTLS **and** OIDC required; per-endpoint
  role check via `require_role!(Role)` on every handler.
- **Axum router**: `/dashboard`, `/api/*`, `/metrics`, `/healthz/*`.
- **Roles**: `viewer`, `operator`, `admin`, `auditor`, `break_glass`.
- **OIDC SSO** via `openidconnect` (Okta / Azure AD / Google / Keycloak).
  `groups` / `roles` claims map to local roles via a configured matrix.
  MFA is delegated to the IdP and verified via `amr` / `acr`.
- **API tokens**: PASETO v4.local, scoped, IP-allowlisted, TTL'd; hashes
  stored via `argon2`.
- **Change approval**: mutations to CRITICAL-scope config require a second
  admin approver before activation.
- **Admin IP allowlist** in addition to auth.
- **Admin change audit log**: hash-chained separately from the detection
  log; records actor, target, diff, reason, approver.
- **Break-glass edits** in GitOps mode are applied locally and
  automatically round-tripped as a PR to the source repo; a banner warns
  until the PR is merged.

---

## 16. Observability

- **Metrics** (`prometheus` crate): counters and histograms for requests
  (tenant / route / tier / decision / status), detector hits, rule hits,
  risk-score buckets, upstream latency + circuit state, challenge
  issue/pass/fail, state-backend op latency, audit throughput + drops,
  config reload outcomes, retry / shadow counts, TLS handshake time, SLO
  burn rate. `/metrics` lives on the control-plane listener only.
- **Tracing**: W3C Trace Context; generate a root span if absent.
  Server span `waf.request` with child spans for rule engine, each
  detector, upstream, and challenge. **OTLP** exporter over gRPC or HTTP,
  feature-gated.
- **Access logs**: nginx `combined`, JSON (ECS), or user template with
  `$var` placeholders. Targets: stdout, rotating file (`tracing-appender`),
  or an audit sink. A bounded channel + dedicated writer task decouples
  request latency from log I/O.
- **Health**: `/healthz/live`, `/healthz/ready` (state backend reachable,
  certs loaded, ≥ 1 healthy upstream member per pool), `/healthz/startup`.

---

## 17. Audit Logging

- **Stable JSON schema** with `schema_version`.
- **Tamper-evident hash chain**: `hash = SHA-256(prev_hash || canonical_json)`
  over detection and admin classes. A leader task periodically signs the
  Merkle root and exports it to an external **witness** (S3 Object Lock,
  append-only log service, or blockchain anchor). `waf audit verify`
  walks the chain and reports breaks.
- **Admin change log** has its own hash chain (actor, target, diff, reason,
  approver).
- **Sinks**: JSONL, Syslog RFC 5424, CEF, LEEF, OCSF, Splunk HEC, Elastic
  ECS, Kafka (`rdkafka` with SASL/TLS). Each sink is a tokio task with a
  bounded channel, on-disk spool, and priority drop policy (lowest severity
  first; admin + critical never dropped without paging).
- **Retention** per event class with compliance floors (e.g. PCI ≥ 90d).

---

## 18. Threat Intelligence

```rust
pub struct ThreatIntelStore {
    ips: IpRangeSet,
    domains: aho_corasick::AhoCorasick,
    urls: aho_corasick::AhoCorasick,
    ja_fps: HashSet<String>,
    asns: HashMap<u32, AsnClass>,
    hashes: HashSet<[u8; 32]>,
    provenance: DashMap<Indicator, FeedId>,
}
```

- Feeds fetched on interval (`reqwest` + ETag). Formats: plain text, CSV,
  JSON, **STIX 2.1** over **TAXII 2.1**, MISP.
- Incremental add/remove → rebuild → `ArcSwap` swap.
- Per-feed confidence + severity; confidence → action mapping
  (`block` / `raise_risk` / `watch`) is configurable.
- **Local override list** wins over imported feeds.
- Every decision carries `feed_id + confidence` so analysts can trace
  `block → rule → indicator → feed → source`.

---

## 19. DLP Engine

```rust
pub struct DlpEngine {
    anchors: aho_corasick::AhoCorasick,     // cheap prefilter
    patterns: Vec<CompiledPattern>,
}
pub struct CompiledPattern {
    name: String,
    category: DlpCategory,
    regex: Regex,
    validator: Option<fn(&str) -> bool>,    // Luhn, mod-97, ...
    action: DlpAction,                      // Redact | Mask | Hash | Fpe | Block
    masker: MaskStrategy,
}
```

- Pattern library covers PAN (Luhn), SSN, IBAN, phone, email, DOB, cloud
  keys (AWS / GCP / Azure / Stripe / GitHub / Slack / Twilio), PEM headers,
  JWTs, HIPAA identifiers (opt-in). Custom regex patterns with a named
  `value` capture.
- Runs both inbound and outbound, streaming in chunks so large bodies are
  not buffered.
- **FPE** (format-preserving encryption, AES-FF1) via an internal
  implementation or `orion`; keys are versioned so old tokens stay
  decryptable until retired.
- **Audit redaction**: every audit event passes through DLP before
  emission so secrets never leak into logs.
- Per-tenant, per-route policies; shared pipeline with response filtering.

---

## 20. API Security Guard

- **OpenAPI 3** documents compile into a `RouteSchemaIndex` keyed by
  `(method, path)`; path templates become a radix tree for O(log n) lookup.
  Body + query + headers validated with `jsonschema`. Modes: `enforce`,
  `monitor`, `learn`.
- Validation errors carry a JSON-pointer for precise audit; client-facing
  error detail is minimized to prevent enumeration.
- **GraphQL**: `async-graphql-parser` computes depth, node count,
  complexity; introspection togglable; persisted-query allowlist
  supported. Mass-assignment protection rejects unknown fields on strict
  schemas.
- **Request signing**: HMAC verification (SigV4-style or custom) per route.
- **API-key management**: per-consumer keys with rate limits and scopes.
- **Learn mode** records observed traffic into a synthesized spec for
  operator review and promotion.

---

## 21. Advanced Bot Management

- **Good-bot verification** via forward-confirmed reverse DNS for Googlebot,
  Bingbot, LinkedInBot, etc., with cached rDNS results.
- **Signals**: JA3/JA4, h2 fingerprint, header order, UA entropy, rDNS,
  threat-intel labels, failed-challenge history, ASN + IP reputation,
  behavioral patterns.
- **Classifier**: shipped rule-based classifier plus optional model-backed
  classifier (feature-gated).
- **Behavioral biometrics / device attestation** (bonus): mouse / keystroke
  rhythm, iOS App Attest, Android Play Integrity.
- Output `BotClass` feeds the risk engine and is mappable to actions via
  route config.

---

## 22. Content & Upload Security (ICAP)

- `IcapClient` implements RFC 3507 `REQMOD` and `RESPMOD` with a connection
  pool per target. Upload routes stream body frames into the ICAP client
  and use the verdict as a pipeline decision.
- **Magic-byte** type detection (`infer`), not `Content-Type`.
- **Allowlist** of file types per route.
- **Archive-bomb** protection: depth + ratio limits in the `zip` / `tar`
  walker.
- **Clean-hash cache** skips re-scanning known-good payloads.
- Scan timeout applies the route's failure mode (fail-closed for CRITICAL
  by default).
- **Sandbox detonation** and **EXIF / steganography scrubbing** (bonus).

---

## 23. Adaptive Load Shedding

- Per-listener `AdmissionController` with adaptive concurrency —
  **Gradient2** (`L(t+1) = L(t) * (RTT_min / RTT_now)`). No static ceiling.
- **Priority queue**: CATCH-ALL dropped first, then MEDIUM, then HIGH;
  CRITICAL is never shed by admission (only by actual security decisions).
- **CPU-aware backstop** from `/proc/stat` or cgroups `cpu.stat`.
- **Per-tenant `concurrency_soft` / `concurrency_hard`** so a burst from
  one tenant cannot starve another.
- Coordinates with DDoS mode: thresholds tighten further when global DDoS
  mode is active.
- Load-shed response: immediate `503` with `Retry-After` + request id, no
  pipeline cost, no upstream contact.

---

## 24. Compliance Profiles

Modes **stack**; the strictest wins; conflicting config is refused at load
time.

- **FIPS 140-2/3**: only `aws-lc-rs` FIPS primitives; TLS / HMAC / PRNG on
  FIPS allowlist.
- **PCI-DSS v4.0**: PAN masking in logs + responses; TLS 1.2+ only on
  PCI-scope listeners; ≥ 90-day audit retention; no CVV / CVC stored.
- **SOC 2**: hash-chained audit log, admin change trail, access review
  exports, SLI/SLO monitoring.
- **GDPR**: PII redaction before logs leave the node, residency pinning,
  right-to-erasure endpoint, retention ceilings.
- **HIPAA**: PHI-safe log mode suppressing bodies + flagged headers on PHI
  routes; BAA dedication flags.

A **compliance-mode profile** flips all of the above into the strictest
setting with a single config switch.

---

## 25. Zero-Downtime Operations

- **Graceful drain** on `SIGTERM`: stop accepting new connections, finish
  in-flight within a bounded TTL, then exit. `/healthz/ready` goes
  not-ready immediately so L4 LBs bleed traffic away.
- **Worker model** via `SO_REUSEPORT`: N workers share the listener with
  kernel-level load balancing. `InFlightTracker = Arc<AtomicUsize>` guards
  the drain.
- **Hot binary reload** on `SIGUSR2`: new process inherits the listening FD
  via `SCM_RIGHTS` (or systemd socket activation); old process drains; new
  process accepts; rollback on readiness-probe failure.
- **Dry-run validator** on every config change: full compile + lint +
  compliance check before the `ArcSwap` swap. Malformed updates refused;
  running config preserved.
- **TLS cert hot reload** via `ArcSwap<CertStore>`: in-flight handshakes
  finish on the old cert; new ones pick up the new cert.

---

## 26. Service Discovery (optional)

Pool membership may populate dynamically from external sources:

- File watcher (JSON / YAML list)
- DNS SRV (`hickory-resolver`)
- Consul (`/v1/health/service` long poll)
- etcd v3 (prefix watch)
- Kubernetes Endpoints API (informer, feature-gated)

Safety limits: minimum-member floor, maximum churn-per-interval cap. Added
members enter `probing` before joining the LB ring; removed members drain.

---

## 27. Disaster Recovery & Backup

- `waf config export --out snapshot.tar.zst` serializes effective config +
  rules + tenants into a deterministic archive, signed with the cluster
  key.
- `waf config import snapshot.tar.zst --dry-run` runs the dry-run validator;
  `--apply` activates after the swap.
- **State snapshots**: Redis RDB + AOF / Raft log + snapshot, replicated
  across AZs and archived hourly (S3 Object Lock).
- **Audit backup**: at-least-once delivery to SIEM + S3 Object Lock +
  witness anchor.
- **RPO** ≤ 5 minutes for security state; 0 for config (Git).
- **RTO** ≤ 30 min region failover; ≤ 4 h cold-start rebuild.
- **Quarterly restore drills** with audit evidence.

---

## 28. Change Management / GitOps

- Declarative config is the single source of truth in a Git repo.
- **Signed commits only**: GPG / SSH signatures verified against
  `allowed_signers` at every pull.
- **CI lint** pipeline runs the same validator as the runtime.
- **Approval floors**: merges to `rules/core/` or `tenants/` require ≥ 2
  approvers, one `admin`.
- **GitSyncer** (leader-only task) polls / receives a webhook; new commits
  run the dry-run validator before the swap.
- **Break-glass** dashboard edits apply locally **and** round-trip as a PR
  against the source repo. A banner warns until the PR is merged; the next
  Git pull will revert an unmerged emergency change.
- `waf config diff` shows pending changes; `waf config apply` triggers the
  dry-run + swap.

---

## 29. SLO / SLI & Alerting

- **SLIs**: availability (non-5xx / total), **WAF-overhead** latency
  (p50/p95/p99, not end-to-end), upstream availability, admin API
  availability, audit delivery rate, config freshness, cert freshness.
- **SLOs**: data-plane availability 99.99% / 30d, p99 overhead ≤ 5 ms in
  99% of 1-min windows, audit delivery 99.999%, cert freshness ≥ 7 days
  remaining.
- **Multi-window, multi-burn-rate** alerts (fast 1h/2%, slow 6h/5%,
  trickle 3d/10%).
- **Alert routing**: Alertmanager-compatible plus direct webhook (Slack,
  PagerDuty, ServiceNow, Jira).
- **Runbooks** referenced on every alert with symptom, mitigation,
  root-cause probes, and escalation path.

---

## 30. Crate Dependencies (indicative)

```toml
# Runtime & HTTP
tokio          = { version = "1",  features = ["full"] }
hyper          = { version = "1",  features = ["http1", "http2", "server", "client"] }
hyper-util     = "0.1"
tower          = "0.5"
http           = "1"
bytes          = "1"
mimalloc       = "0.1"

# TLS / ACME / crypto
rustls         = "0.23"
tokio-rustls   = "0.26"
rustls-pemfile = "2"
aws-lc-rs      = { version = "1", features = ["fips"], optional = true }
instant-acme   = { version = "0.7", optional = true }
rcgen          = "0.13"
blake3         = "1"
sha2           = "0.10"
hmac           = "0.12"
zeroize        = { version = "1", features = ["zeroize_derive"] }
secrecy        = "0.10"

# Routing / matching
regex          = "1"
globset        = "0.4"
ipnet          = "2"
hashring       = "0.3"
aho-corasick   = "1"

# Config / serde
serde          = { version = "1", features = ["derive"] }
serde_yaml     = "0.9"
toml           = "0.8"
figment        = "0.10"
notify         = "6"
arc-swap       = "1"

# Concurrency
dashmap        = "6"
parking_lot    = "0.12"
moka           = { version = "0.12", features = ["future"] }
crossbeam      = "0.8"

# Auth
jsonwebtoken   = "9"
openidconnect  = "3"
argon2         = "0.5"
rusty_paseto   = "0.7"

# State backends
deadpool-redis = "0.18"
redis          = "0.27"
openraft       = { version = "0.9", optional = true }
foca           = { version = "0.17", optional = true }

# Observability
prometheus     = "0.13"
tracing        = "0.1"
tracing-subscriber = { version = "0.3", features = ["json"] }
tracing-appender = "0.2"
opentelemetry  = { version = "0.27", optional = true }
opentelemetry-otlp = { version = "0.27", optional = true }

# Threat intel / content / SIEM
reqwest        = { version = "0.12", features = ["rustls-tls", "stream"] }
rdkafka        = { version = "0.36", optional = true }
infer          = "0.16"

# Secrets
vaultrs        = "0.7"

# Service discovery
hickory-resolver = "0.24"

# Signals / OS
nix            = { version = "0.29", features = ["signal", "fs"] }
```

Feature flags (`Cargo.toml`):

```toml
[features]
default   = ["tls", "redis"]
tls       = []
fips      = ["dep:aws-lc-rs"]
acme      = ["dep:instant-acme"]
redis     = []
raft      = ["dep:openraft"]
gossip    = ["dep:foca"]
otel      = ["dep:opentelemetry", "dep:opentelemetry-otlp"]
kafka     = ["dep:rdkafka"]
http3     = []     # quinn + h3
hsm       = []     # cryptoki / PKCS#11
bot_ml    = []     # model-backed bot classifier
```

---

## 31. Implementation Phases

Implementation is sequenced so that each phase produces a runnable binary
with a meaningful subset of the requirements.

| Phase | Milestone | Key subsystems |
|---|---|---|
| **0** | Skeleton | CLI, config schema + loader + ArcSwap, validator, logging, `/healthz/live` |
| **1** | Proxy core | h1/h2 adapters, route table, upstream pool (RR + health + CB), transforms, quotas |
| **2** | Security baseline | rule engine, rate limiter (in-mem), IP reputation, attack detectors, risk + challenge (JS/PoW), response filter |
| **3** | TLS | rustls resolver, SNI, hot cert reload, TLS 1.3 defaults |
| **4** | Observability | Prometheus, access logs, W3C trace propagation, `/healthz/ready` + `/healthz/startup` |
| **5** | Admin plane | Axum dashboard + admin API, mTLS + OIDC + RBAC, change approval, admin audit chain |
| **6** | Clustered state | Redis backend, cluster-wide counters / auto-block / nonces, local fallback + reconcile |
| **7** | Tenancy | tenant config, key prefixing, tenant governor, security floors, per-tenant dashboards |
| **8** | Audit + SIEM | hash-chained audit, JSONL/Syslog/CEF/LEEF/OCSF/HEC/Kafka sinks, witness exporter |
| **9** | Secrets | provider trait + env/file/Vault/AWS/GCP/Azure, rotation, zeroize |
| **10** | Threat intel | feed fetchers (text/CSV/JSON/STIX/TAXII), store, provenance in audit |
| **11** | API guard | OpenAPI enforcement, GraphQL guard, HMAC request signing |
| **12** | DLP | patterns, Luhn/mod-97 validators, mask/hash/FPE, audit redaction |
| **13** | Bot management | JA4/h2 fingerprints, rDNS verification, CAPTCHA providers, escalation ladder |
| **14** | Content scan | ICAP REQMOD/RESPMOD, magic-byte, archive-bomb |
| **15** | Adaptive shed | Gradient2, priority queue, per-tenant soft/hard |
| **16** | Compliance profiles | FIPS gate, PCI, SOC 2, GDPR, HIPAA, stacking logic |
| **17** | HA + clustering | gossip membership, leader lease, rolling restart story |
| **18** | GitOps | signed-commit verification, GitSyncer, dashboard→PR round-trip |
| **19** | DR / backup | config export/import, state snapshots, restore validation |
| **20** | Zero-downtime | `SO_REUSEPORT` worker supervisor, graceful drain, hot binary reload (FD passing) |
| **21** | SLO / alerting | SLI recorders, burn-rate metrics, Alertmanager-compatible webhook |
| **22** | Bonus | ACME + OCSP stapling, HTTP/3, HSM, service discovery, OTLP exporter, gRPC-Web, behavioral bot ML |

---

## 32. Testing & Validation

- **Unit**: every detector, every LB strategy, rule AST evaluator, hash
  chain writer/verifier, DLP pattern matrix, FPE round-trips, CB state
  machine.
- **Integration**:
  - Host routing conformance (exact / wildcard / regex / default).
  - Health-check flap + CB transitions under induced failures.
  - TLS/SNI handshake matrix with `openssl s_client`.
  - WebSocket echo through the WAF.
  - gRPC echo (`tonic`) with trailers preserved.
  - ForwardAuth with a mock service.
  - JWT + JWKS cache behavior.
  - Redis-backed rate limit across two nodes.
  - Hash-chain tamper detection by `waf audit verify`.
  - Secrets rotation via Vault without restart.
  - Two-tenant isolation (tenant A cannot see tenant B data).
  - OIDC-gated admin API; viewer cannot mutate.
- **End-to-end red team**: SQLi / XSS / path traversal / SSRF / brute
  force / recon scanner must all be blocked.
- **Load**: `wrk` / `hey` ≥ 5 000 RPS with p99 overhead ≤ 5 ms. Latency
  measured as WAF overhead only.
- **Chaos**: backend failures, Redis partition, TLS cert rotation under
  load, DDoS simulation.
- **Drain**: `wrk` under load + `SIGTERM` → zero dropped in-flight
  requests.
- **Dry-run**: malformed rule file refused; running config untouched;
  dashboard shows the error.
- **Compliance**: FIPS profile boots; PCI profile refuses TLS 1.1; GDPR
  residency exporter refuses cross-region delivery.
- **SLO**: burn-rate alert fires via Alertmanager on a synthetic regression.

---

## 33. Deliverables (maps to Requirement §34)

- `./waf run` single static binary.
- Hot reload of config, rules, secrets, and certificates.
- Multi-host routing with SNI-checked host matching.
- ≥ 2 upstream pools demonstrating LB + health checks.
- Canary split between pools with sticky assignment.
- TLS termination with hot-reloaded certificates.
- HTTP/2, WebSocket upgrade, gRPC passthrough verified.
- ForwardAuth + JWT integration tests passing.
- Prometheus `/metrics` scraped successfully.
- `traceparent` propagation verified.
- Graceful drain under load with zero drops.
- Hot binary reload keeps connections alive.
- Dry-run validator blocks a malformed rule.
- Two-node cluster sharing rate-limit + risk state via Redis.
- FIPS-mode config profile boots.
- Audit-log hash chain verified tamper-evident.
- Secrets resolved from Vault; rotation without restart.
- Admin listener gated by OIDC + RBAC.
- Two tenants isolated end-to-end.
- Syslog / CEF / OCSF forwarder delivering to a test SIEM.
- STIX / TAXII feed imported with feed provenance in blocks.
- Turnstile CAPTCHA fallback in the challenge ladder.
- OpenAPI schema enforcement blocking malformed requests.
- DLP masking a synthetic credit card in a response.
- ICAP antivirus integration on an upload route.
- Load shedding engaged under overload; CRITICAL traffic unaffected.
- Config snapshot → restore round-trip.
- `/healthz/*` correct at each lifecycle phase.
- SLO burn alert via Alertmanager on synthetic regression.
- Red-team attack simulation fully blocked.
- ≥ 5 000 RPS sustained with p99 overhead ≤ 5 ms.
