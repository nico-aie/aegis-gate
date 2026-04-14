# Member 1 — Proxy Core & Platform

**Read [`shared-contract.md`](./shared-contract.md) first.** Every type
name, trait, and boot sequence referenced here is defined there.

**Mission:** make `./waf run` boot, route traffic, terminate TLS, load
balance upstreams, hot-reload config, and stay up under load. You own
the hot path from accept-socket to upstream write.

**Crate:** `crates/aegis-proxy/`
**Binary wiring:** `crates/aegis-bin/src/main.rs`

---

## 1. Crate Layout

```
crates/aegis-proxy/
├── Cargo.toml
└── src/
    ├── lib.rs              # pub fn run(cfg, pipeline, state, bus, metrics)
    ├── config.rs           # listeners, routes, upstreams, tls sub-schemas
    ├── listener/
    │   ├── mod.rs
    │   ├── acceptor.rs     # TCP accept + SO_REUSEPORT
    │   └── tls.rs          # rustls + DynamicResolver
    ├── proto/
    │   ├── mod.rs
    │   ├── h1.rs           # hyper http1
    │   ├── h2.rs           # hyper http2
    │   ├── ws.rs           # WebSocket upgrade passthrough
    │   └── grpc.rs         # gRPC trailer preservation
    ├── route/
    │   ├── mod.rs          # RouteTable + build()
    │   ├── host.rs         # HostMatcher (Exact/Wildcard/Regex/Default)
    │   └── path.rs         # PathTrie longest-prefix match
    ├── upstream/
    │   ├── mod.rs          # Pool, Member
    │   ├── lb.rs           # RR, WRR, LeastConn, P2C, ConsistentHash
    │   ├── health.rs       # active + passive
    │   └── circuit.rs      # CB state machine
    ├── transform/
    │   ├── mod.rs          # header add/set/remove, var expansion
    │   └── rewrite.rs      # path rewrite/strip/add, redirects
    ├── quota.rs            # body/header/URI size + timeouts
    ├── session.rs          # sticky-cookie + consistent-hash fallback
    ├── traffic.rs          # canary split, header steering, retries, shadow
    ├── state/
    │   ├── mod.rs          # StateBackend impls (in_memory, redis)
    │   ├── in_memory.rs
    │   └── redis.rs        # feature = "redis"
    ├── shed.rs             # Gradient2 adaptive concurrency
    ├── supervisor.rs       # worker tasks, SIGTERM drain, hot reload
    ├── hotbin.rs           # SIGUSR2 FD passing exec
    ├── secrets.rs          # ${secret:provider:path} resolver + providers
    ├── cache/              # tier-aware smart cache (CacheProvider impl)
    │   ├── mod.rs
    │   └── key.rs
    ├── sd/                 # service discovery (ServiceDiscovery impl)
    │   ├── mod.rs
    │   ├── file.rs
    │   ├── dns.rs
    │   ├── consul.rs       # feature = "consul"
    │   ├── etcd.rs         # feature = "etcd"
    │   └── k8s.rs          # feature = "k8s"
    ├── cluster.rs          # ClusterMembership (foca / redis-registry)
    ├── acme.rs             # ACME HTTP-01 + TLS-ALPN-01 (feature = "acme")
    ├── ocsp.rs             # stapling background refresh
    ├── dr.rs               # snapshot/restore CLI + state snapshot hook
    └── proxy.rs            # handle_request: the main loop
```

---

## 2. Weekly Task Breakdown

Each task lists: **file**, **signature**, **behavior**, **tests**.
Feed an AI assistant one task at a time.

### Week 1 — Foundation

**T1.1** — Workspace + `./waf run` skeleton
- Files: `Cargo.toml`, `crates/aegis-bin/src/main.rs`, `crates/aegis-proxy/src/lib.rs`
- Signature: `pub async fn run(cfg: Arc<ArcSwap<WafConfig>>, pipeline: Arc<dyn SecurityPipeline>, state: Arc<dyn StateBackend>, bus: AuditBus, metrics: MetricsRegistry) -> Result<()>`
- Behavior: parse `--config <path>`, load YAML, bind `listeners.http` on `:8080`, serve a 200 OK.
- Test: `cargo run -- --config config/waf.yaml` responds to `curl localhost:8080`.

**T1.2** — Config loader + schema types
- Files: `aegis-proxy/src/config.rs`, `aegis-core/src/config.rs`
- Types: `Listeners { http: SocketAddr, https: Option<SocketAddr> }`, `RouteConfig`, `PoolConfig`, `TlsConfig` (see §2.14 of `Architecture.md`).
- Loader: `pub fn load(path: &Path) -> Result<WafConfig>` using `figment` + `serde_yaml`.
- Test: round-trip parse `config/waf.yaml` fixture; reject missing required fields.

**T1.3** — Hot reload (`notify` + `ArcSwap`)
- File: `aegis-proxy/src/supervisor.rs`
- Signature: `pub fn spawn_config_watcher(path: PathBuf, cfg: Arc<ArcSwap<WafConfig>>, bus: AuditBus)`
- Behavior: watch file, on change re-parse + full validate, swap atomically, emit `AuditClass::Admin` event. On parse failure keep old config + emit audit event with error.
- Test: integration test mutates file, asserts new value observed in `cfg.load()` within 2s, asserts malformed update is rejected.

**T1.4** — Dual listener model
- File: `aegis-proxy/src/listener/acceptor.rs`
- Behavior: data plane on `listeners.https`/`http`, admin plane address handed to M3. M1 never binds the admin address.
- Test: unit — `build_listeners(&cfg)` returns exactly the configured data-plane sockets.

**T1.5** — `NoopPipeline` + audit bus wiring (unblocks M2/M3)
- File: `aegis-core/src/pipeline.rs`
- Provide: `pub struct NoopPipeline; impl SecurityPipeline for NoopPipeline { always Allow }`
- Test: boot uses `NoopPipeline` if `--no-security` flag set.

**Week 1 exit:** `./waf run` serves, reloads, emits an admin audit event on reload.

---

### Week 2 — Route Table & Upstream Pools

**T2.1** — Host matcher
- File: `aegis-proxy/src/route/host.rs`
- Types: `enum HostMatcher { Exact(String), Wildcard(String), Regex(regex::Regex), Default }`
- `pub fn matches(&self, host: &str) -> bool`
- Test: table-driven — exact beats wildcard beats default; case-insensitive; SNI mismatch rejected.

**T2.2** — Path trie
- File: `aegis-proxy/src/route/path.rs`
- Type: `PathTrie<V>` with `insert(&mut self, pattern: &str, v: V)` and `find<'a>(&'a self, path: &str) -> Option<&'a V>` — longest-prefix wins.
- Test: `/api/v1/users` matches `/api/v1/` over `/api/`.

**T2.3** — `RouteTable::build(&WafConfig)` + `resolve`
- File: `aegis-proxy/src/route/mod.rs`
- Signature: `pub fn resolve(&self, host: &str, path: &str, method: &Method) -> Option<RouteCtx>`
- Behavior: host lookup → path trie → method filter → fall through to catch-all. Loader rejects configs with no catch-all.
- Test: integration — 5-route fixture, assert each request lands on expected route.

**T2.4** — Upstream `Pool` + LB strategies
- File: `aegis-proxy/src/upstream/lb.rs`
- Types per `Architecture.md` §2.8.
- Strategies: `RoundRobin`, `WeightedRoundRobin`, `LeastConn`, `P2C`, `ConsistentHash(KeyFn)`.
- Interface: `pub fn pick<'a>(&self, members: &'a [Member], ctx: &RequestCtx) -> Option<&'a Member>`
- Test: unit per strategy; consistent-hash stability under member churn.

**T2.5** — Active health checks
- File: `aegis-proxy/src/upstream/health.rs`
- Spawn one `tokio::task` per pool that probes `health_check.path` every `interval_s`, updates `Member::healthy`, emits `AuditClass::System` on state transition.
- Test: mock upstream, flap health, assert rotation in/out within one interval.

**T2.6** — Passive health + circuit breaker
- File: `aegis-proxy/src/upstream/circuit.rs`
- State machine: `Closed → Open → HalfOpen → Closed`. Config: `error_threshold_pct`, `min_requests`, `open_duration_s`.
- Test: inject 20 failures → Open; wait → HalfOpen; one success → Closed.

**T2.7** — Wire routing + upstream into `proxy.rs`
- File: `aegis-proxy/src/proxy.rs`
- `handle_request`: accept → parse request → resolve route → call `pipeline.inbound` → pick upstream → forward (`hyper::Client`) → call `pipeline.outbound` → write response.
- Test: end-to-end — 2 pools, one healthy one not, traffic only hits healthy.

---

### Week 3 — TLS & Protocols

**T3.1** — `DynamicResolver` + `CertStore`
- File: `aegis-proxy/src/listener/tls.rs` (Architecture §2.9)
- `rustls::server::ResolvesServerCert` impl reading `ArcSwap<CertStore>`.
- File watcher reloads PEM pairs without dropping in-flight handshakes.
- Test: openssl `s_client` against two SNI names, rotate cert file, assert new cert served without connection drops.

**T3.2** — HTTP/2 on both sides
- File: `aegis-proxy/src/proto/h2.rs`
- Use `hyper::server::conn::auto::Builder` (ALPN). Upstream client built with `http2_only(true)` when pool so configured.
- Include rapid-reset mitigator: cap `MAX_CONCURRENT_STREAMS`, track reset rate per conn, drop connection on abuse.
- Test: h2load stress; assert no runaway memory under reset flood.

**T3.3** — WebSocket upgrade passthrough
- File: `aegis-proxy/src/proto/ws.rs`
- On `Upgrade: websocket`: run pipeline on handshake only; then `hyper::upgrade::on(req)` + `tokio::io::copy_bidirectional` to upstream.
- Test: `tokio-tungstenite` echo client through WAF.

**T3.4** — gRPC trailer-preserving forward
- File: `aegis-proxy/src/proto/grpc.rs`
- Stream frames + trailers; never buffer full body.
- Test: `tonic` hello-world backend, assert trailer `grpc-status: 0` passes through.

**T3.5** — mTLS to upstream
- File: `aegis-proxy/src/upstream/mod.rs`
- Per-pool `tls: { ca_bundle, client_cert_ref, client_key_ref, server_name }`. Build a `rustls::ClientConfig` with client auth; the pool's `hyper` client uses it. Refresh on secret rotation.
- Test: backend requiring client cert — request succeeds only when pool has matching cert.

**T3.6** — ACME issuance (HTTP-01 + TLS-ALPN-01) — feature `acme`
- File: `aegis-proxy/src/acme.rs`
- Use `instant-acme` for order/authz. HTTP-01: expose `/.well-known/acme-challenge/*` via a synthetic route injected into the route table. TLS-ALPN-01: resolver serves the `acme-tls/1` cert when the ClientHello ALPN matches. Leader-only task (`ClusterMembership::acquire_lease("acme")`). New cert goes through the same hot-reload path as file certs.
- Test: against `pebble` test CA, issue and serve a cert, renewal path runs before expiry.

**T3.7** — OCSP stapling
- File: `aegis-proxy/src/ocsp.rs`
- Background task fetches OCSP response per cert, caches to disk, populates `CertifiedKey::ocsp`. Refresh before `nextUpdate`.
- Test: mock responder, assert stapled bytes on TLS handshake.

**T3.8** — HTTP/3 (bonus, feature `http3`)
- File: `aegis-proxy/src/proto/h3.rs` using `quinn` + `h3`. Shares the route table and pipeline contract.
- Test: `curl --http3` end-to-end.

---

### Week 4 — Traffic Mgmt, Quotas, Sessions, Drain

**T4.1** — Per-route quotas
- File: `aegis-proxy/src/quota.rs`
- Enforce `client_max_body_size` (413), header total (431), URI (414), read/write timeouts (408/504), total deadline.
- Audit event names the specific quota breached.
- Test: one fixture per status code.

**T4.2** — Transformations + CORS
- File: `aegis-proxy/src/transform/mod.rs`
- Variable expansion: `$host`, `$client_ip`, `$request_id`, `$jwt.sub`, `$cookie.*`, `$header.*`.
- CORS preflight answered directly unless `cors.passthrough = true`.
- Test: golden-file header snapshots.

**T4.3** — Canary split + header/cookie steering
- File: `aegis-proxy/src/traffic.rs`
- `split: [{pool: v1, weight: 95}, {pool: v2, weight: 5}]` with optional sticky assignment (HMAC cookie).
- Header/cookie steering short-circuits to a specific pool.
- Test: 10k synthetic requests — within 1% of configured weight; sticky clients never split.

**T4.4** — Retries with budget
- File: `aegis-proxy/src/traffic.rs`
- Per-pool `{max_attempts, per_try_timeout, retry_on: [502, 503, 504, connect_err]}` + cluster budget ratio (reject retries if cluster retry ratio > N%).
- Test: failing upstream → retries up to budget then 502; budget exhausted → no retries.

**T4.5** — Shadow mirroring
- File: `aegis-proxy/src/traffic.rs`
- Fire-and-forget clone of the request to a second pool; response discarded; user latency untouched.
- Test: both pools see the request; user path timed, shadow failure does not affect status.

**T4.6** — Session affinity
- File: `aegis-proxy/src/session.rs`
- HMAC-signed `AG_SID` cookie naming the chosen member; consistent-hash fallback; re-issue on member drain.
- Test: 100 requests, first picks member M, next 99 hit M while healthy, re-pick after drain.

**T4.7** — Worker supervisor + graceful drain
- File: `aegis-proxy/src/supervisor.rs`
- `workers.count` tasks bind with `SO_REUSEPORT`. `InFlightTracker = Arc<AtomicUsize>`. On SIGTERM: set `ReadinessSignal.draining = true`, stop accepting, wait up to `drain_timeout_s`, exit.
- Test: `wrk` load + SIGTERM; dropped in-flight count must be 0.

**T4.8** — Hot binary reload (SIGUSR2, FD passing)
- File: `aegis-proxy/src/hotbin.rs`
- On `SIGUSR2`: `fork+exec` the new binary with the listening socket FDs passed via `CommandExt::fd_mappings` (or systemd socket activation). Old process enters drain path. Rollback on readiness probe failure.
- Test: under `wrk` load, send SIGUSR2; connections never drop; new binary serves traffic.

**T4.9** — Tier-aware smart cache (`CacheProvider` impl)
- File: `aegis-proxy/src/cache/mod.rs`
- `moka`-backed async cache keyed by `(method, host, path, tenant_id, vary_headers_hash)`. MEDIUM aggressive (minutes), HIGH conservative (seconds, with `Cache-Control` respect), CRITICAL never. Consulted just before upstream selection; updated from upstream response based on `Cache-Control` headers and route policy.
- Test: repeated GETs on a MEDIUM route hit cache; CRITICAL route never caches; `Cache-Control: no-store` respected.

---

### Week 5 — Clustering, Shedding, Secrets, DR

**T5.1** — `InMemoryBackend` (ready since W1) → polish
- File: `aegis-proxy/src/state/in_memory.rs`
- `DashMap` + TTL wheel. Implements full `StateBackend`.
- Test: sliding-window property test — count never exceeds limit across concurrent writers.

**T5.2** — `RedisBackend` (feature = "redis")
- File: `aegis-proxy/src/state/redis.rs`
- Use `fred` or `redis` crate. Sliding window via Lua script (atomic).
- Fallback: on backend error, fall through to local in-memory and reconcile via `max(local, remote)` on recovery.
- Test: docker-compose Redis, 2-node cluster test asserts shared counter.

**T5.3** — Adaptive load shedder (Gradient2)
- File: `aegis-proxy/src/shed.rs`
- Per-pool concurrency `L(t+1) = L(t) * (RTT_min / RTT_now)`. Priority classes drop CatchAll → Medium → High; Critical never shed.
- Shed response: `503` + `Retry-After` + request id, zero pipeline cost.
- Test: synthetic overload — Critical success rate stays ≥ 99% while CatchAll is shed.

**T5.4** — Secrets resolver
- File: `aegis-proxy/src/secrets.rs`
- Syntax: `${secret:<provider>:<path>[#field]}`. Providers: `env`, `file`. Vault/AWS as stubs returning `NotImplemented`.
- `zeroize`-ing container for resolved material.
- Test: config with `${secret:env:DB_PASS}` resolves, `/api/config` reflects back the reference string not the value.

**T5.5** — DR snapshot/restore CLI
- File: `aegis-proxy/src/dr.rs`
- `./waf snapshot --out /tmp/cfg.tar.zst` writes effective config + rules + tenant defs + version stamp, signed with cluster key; `./waf restore <file>` runs dry-run validator before activating. Periodic backup task with pluggable target (`file`, `s3`, `gcs`, `sftp`) — leader-only.
- Test: round-trip — snapshot, mutate live, restore, assert identical. S3 target mocked.

**T5.6** — Service discovery (`ServiceDiscovery` impl)
- File: `aegis-proxy/src/sd/mod.rs`
- Backends: `file` watcher (JSON/YAML list), `dns_srv` via `hickory-resolver`, `consul` long-poll, `etcd` prefix watch, `k8s` endpoints informer (feature-gated). Emits on `watch::Sender<Vec<MemberAddr>>` consumed by the pool manager. Safety limits: `min_members`, `max_churn_per_interval`. New members enter `probing` until active health passes.
- Test: file SD fixture — add/remove a member, pool rotation updates within 1s, churn cap enforced.

**T5.7** — Cluster membership (`ClusterMembership` impl)
- File: `aegis-proxy/src/cluster.rs`
- Default: `foca` SWIM gossip for peer discovery + soft load hints. Alternate: Redis-backed registry (`nodes:*` keys with TTL heartbeat). `acquire_lease(key, ttl)` used by ACME, GitOps, witness export, threat-intel fetch so only one node runs them.
- Test: 3-node in-process cluster; assert `peers()` stabilizes; assert only one node holds a given lease at a time.

---

## 3. Integration Contracts (must not change without M2/M3 sign-off)

- `SecurityPipeline` trait (`aegis-core::pipeline`) — M1 calls, M2 implements.
- `StateBackend` trait (`aegis-core::state`) — M1 provides impls, M2 consumes.
- `AuditBus` — M1 emits on: config reload, pool health transition, CB state change, quota breach, load shed.
- Metrics — M1 registers the families listed in §4 into the `MetricsRegistry` from M3.

## 4. Metrics You Own (Prometheus families)

```
waf_requests_total{tier,route,tenant,decision,status}
waf_upstream_latency_seconds{pool,member}    (histogram)
waf_upstream_inflight{pool,member}           (gauge)
waf_circuit_state{pool,member}                (gauge 0/1/2)
waf_pool_health_transitions_total{pool,member,to}
waf_load_shed_total{tier,reason}
waf_config_reload_total{outcome}
waf_retry_total{pool,outcome}
waf_shadow_total{pool,outcome}
```

## 5. Tests Required per Phase

Every week you must ship:
1. Unit tests for every public function in new files.
2. One integration test under `crates/aegis-proxy/tests/` for the week's feature.
3. A short fixture under `config/fixtures/week-N/waf.yaml`.

CI gate: `cargo test -p aegis-proxy`, `cargo clippy -p aegis-proxy -- -D warnings`.

## 6. Definition of Done (M1 exit criteria)

- [ ] Deliverables checklist items from `Requirement.md` §34: 1–7, 10–13, 26, 27, 30.
- [ ] Load test: ≥ 5 000 RPS sustained, p99 WAF overhead ≤ 5 ms (measured excluding upstream time).
- [ ] Graceful drain: 0 dropped in-flight under SIGTERM during `wrk` load.
- [ ] 2-node cluster demo sharing rate-limit counter via Redis.
- [ ] All W1–W5 tests green in CI.

## 7. Working with an AI Assistant

When asking an AI to implement a task, copy this template:

```
Read: plans/shared-contract.md and plans/member-1-proxy-core.md

Task: <copy T-number and title>
File: <path>
Signature: <copy from plan>
Behavior: <copy from plan>

Constraints:
- Use only dependencies already in crates/aegis-proxy/Cargo.toml;
  if a new one is needed, list it and wait for confirmation.
- Do not touch files outside aegis-proxy except aegis-core (and flag it).
- Write the unit tests listed under "Test:" in the same PR.
- Run `cargo test -p aegis-proxy` before finishing.
```
