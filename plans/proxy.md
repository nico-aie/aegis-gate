# Proxy Core — `aegis-proxy` Task Plan

> **Before reading this:** Read `README.md`, then `Implement-Progress.md`,
> then `plans/plan.md` (shared types §2, traits §3, boot §4, conventions §5).
> This file contains only the per-task implementation breakdown for `aegis-proxy`.

**Crate mission:** make `./waf run` boot, route traffic, terminate TLS,
load-balance upstreams, hot-reload config, and stay up under load.
Owns the hot path from accept-socket to upstream write.

**Entry point:** `pub async fn run(cfg, pipeline, state, sd, cache, cluster, bus, metrics, readiness, cfg_bcast) -> Result<()>`

**Verification command:** `cargo test -p aegis-proxy && cargo clippy -p aegis-proxy -- -D warnings`

---

## Crate Layout

```
crates/aegis-proxy/src/
  lib.rs              # pub fn run(...)
  config.rs           # listeners, routes, upstreams, tls sub-schemas
  proxy.rs            # handle_request: the main loop
  listener/
    acceptor.rs       # TCP accept + SO_REUSEPORT
    tls.rs            # rustls + DynamicResolver + CertStore
  proto/
    h1.rs             # hyper http1
    h2.rs             # hyper http2 + rapid-reset mitigator
    ws.rs             # WebSocket upgrade passthrough
    grpc.rs           # gRPC trailer preservation
  route/
    mod.rs            # RouteTable + build()
    host.rs           # HostMatcher (Exact/Wildcard/Regex/Default)
    path.rs           # PathTrie longest-prefix match
  upstream/
    mod.rs            # Pool, Member, mTLS client config
    lb.rs             # RR, WRR, LeastConn, P2C, ConsistentHash
    health.rs         # active + passive health checks
    circuit.rs        # CB state machine
  transform/
    mod.rs            # header add/set/remove, var expansion
    rewrite.rs        # path rewrite/strip/add, redirects
  state/
    mod.rs            # StateBackend impls
    in_memory.rs      # DashMap + TTL wheel
    redis.rs          # feature = "redis", deadpool + Lua scripts
  cache/
    mod.rs            # CacheProvider impl (moka)
    key.rs            # CacheKey construction
  sd/
    mod.rs            # ServiceDiscovery impl
    file.rs           # JSON/YAML list watcher
    dns.rs            # dns_srv via hickory-resolver
    consul.rs         # feature = "consul"
    etcd.rs           # feature = "etcd"
    k8s.rs            # feature = "k8s"
  quota.rs            # body/header/URI size + timeouts
  session.rs          # sticky-cookie + consistent-hash fallback
  traffic.rs          # canary split, header steering, retries, shadow
  shed.rs             # Gradient2 adaptive concurrency
  supervisor.rs       # worker tasks, SIGTERM drain, config watcher
  hotbin.rs           # SIGUSR2 FD passing exec
  secrets.rs          # ${secret:provider:path} resolver + env/file providers
  cluster.rs          # ClusterMembership (foca / redis-registry)
  acme.rs             # ACME HTTP-01 + TLS-ALPN-01 (feature = "acme")
  ocsp.rs             # OCSP stapling background refresh
  dr.rs               # snapshot/restore CLI + periodic backup
```

---

## Prometheus Metrics (register into MetricsRegistry from aegis-control)

```
waf_requests_total{tier,route,decision,status}
waf_upstream_latency_seconds{pool,member}   (histogram)
waf_upstream_inflight{pool,member}          (gauge)
waf_circuit_state{pool,member}              (gauge: 0=Closed,1=Open,2=HalfOpen)
waf_pool_health_transitions_total{pool,member,to}
waf_load_shed_total{tier,reason}
waf_config_reload_total{outcome}
waf_retry_total{pool,outcome}
waf_shadow_total{pool,outcome}
```

---

## Integration Contracts (changes require sign-off)

- Calls `SecurityPipeline::inbound` + `on_response_start` + `on_body_frame` (implemented by `aegis-security`).
- Provides `StateBackend` impls — consumed by `aegis-security` for rate-limiting, risk, nonces.
- Provides `ClusterMembership` — surfaced by `aegis-control` on the cluster dashboard page.
- Provides `SecretProvider` (`env`, `file`) — consumed by `aegis-security` and `aegis-control`.
- Emits `AuditBus` events on: config reload, pool health transition, CB state change, quota breach, load shed.

---

## W1 — Foundation

**M1-T1.1** Workspace + `./waf run` skeleton
- Files: `Cargo.toml` (workspace), `crates/aegis-bin/src/main.rs`, `crates/aegis-proxy/src/lib.rs`
- `pub async fn run(cfg, pipeline, state, bus, metrics) -> Result<()>` — parse `--config <path>`, load YAML, bind `listeners.http :8080`, serve 200 OK.
- Test: `cargo run -- --config config/waf.yaml` responds to `curl localhost:8080`.

**M1-T1.2** Config loader
- Files: `aegis-proxy/src/config.rs`, `aegis-core/src/config.rs`
- `pub fn load(path: &Path) -> Result<WafConfig>` via `figment` + `serde_yaml`.
- Test: round-trip parse `config/waf.yaml`; reject missing required fields.

**M1-T1.3** Hot reload (`notify` + `ArcSwap`)
- File: `aegis-proxy/src/supervisor.rs`
- `pub fn spawn_config_watcher(path: PathBuf, cfg: Arc<ArcSwap<WafConfig>>, bus: AuditBus)`
- Re-parse + validate on change, atomic swap, emit `AuditClass::Admin`. Keep old config on parse failure.
- Test: mutate file → new value in `cfg.load()` within 2s; malformed update rejected, old config untouched.

**M1-T1.4** Dual listener model
- File: `aegis-proxy/src/listener/acceptor.rs`
- Proxy binds data-plane sockets only; admin address (`cfg.admin.bind`) goes to `aegis-control`.
- Test: `build_listeners(&cfg)` returns exactly the configured data-plane sockets.

**M1-T1.5** `NoopPipeline` + audit bus wiring
- File: `aegis-core/src/pipeline.rs`
- `pub struct NoopPipeline; impl SecurityPipeline for NoopPipeline { always returns Allow }`
- Test: binary boots with `--no-security` flag using `NoopPipeline`.

**W1 exit gate:** `./waf run` serves traffic, hot-reloads on file change, emits admin audit event.

---

## W2 — Route Table & Upstreams

**M1-T2.1** Host matcher
- File: `aegis-proxy/src/route/host.rs`
- `enum HostMatcher { Exact(String), Wildcard(String), Regex(regex::Regex), Default }`
- `pub fn matches(&self, host: &str) -> bool`
- Test: exact beats wildcard beats default; case-insensitive; SNI mismatch rejected.

**M1-T2.2** Path trie
- File: `aegis-proxy/src/route/path.rs`
- `PathTrie<V>` with `insert(&mut self, pattern: &str, v: V)` and `find<'a>(&'a self, path: &str) -> Option<&'a V>` (longest-prefix wins).
- Test: `/api/v1/users` matches `/api/v1/` over `/api/`.

**M1-T2.3** `RouteTable::build` + `resolve`
- File: `aegis-proxy/src/route/mod.rs`
- `pub fn resolve(&self, host: &str, path: &str, method: &Method) -> Option<RouteCtx>`
- Host lookup → path trie → method filter → catch-all. Loader rejects configs with no catch-all.
- Test: 5-route fixture; each of the 5 request shapes lands on the expected route.

**M1-T2.4** Upstream Pool + LB strategies
- File: `aegis-proxy/src/upstream/lb.rs`
- Strategies: `RoundRobin`, `WeightedRoundRobin`, `LeastConn`, `P2C`, `ConsistentHash(KeyFn)`.
- `pub fn pick<'a>(&self, members: &'a [Member], ctx: &RequestCtx) -> Option<&'a Member>`
- Test: unit per strategy; consistent-hash stable under member churn.

**M1-T2.5** Active health checks
- File: `aegis-proxy/src/upstream/health.rs`
- One `tokio::task` per pool probes `health_check.path` every `interval_s`, updates `Member::healthy`, emits `AuditClass::System` on state transition.
- Test: mock upstream, flap health, assert member rotates in/out within one interval.

**M1-T2.6** Circuit breaker
- File: `aegis-proxy/src/upstream/circuit.rs`
- State machine: `Closed → Open → HalfOpen → Closed`. Config: `error_threshold_pct`, `min_requests`, `open_duration_s`.
- Test: inject 20 failures → Open; wait → HalfOpen; one success → Closed.

**M1-T2.7** Wire routing + upstream into `proxy.rs`
- File: `aegis-proxy/src/proxy.rs`
- `handle_request`: accept → parse → resolve route → call `pipeline.inbound` → pick upstream → forward (hyper Client) → call `pipeline.on_response_start` + `on_body_frame` → write response.
- Test: 2 pools, one healthy, one not; all traffic hits the healthy pool.

**W2 exit gate:** traffic routed correctly through 5-route fixture; circuit breaker trips on simulated failures.

---

## W3 — TLS & Protocols

**M1-T3.1** `DynamicResolver` + `CertStore`
- File: `aegis-proxy/src/listener/tls.rs`
- `rustls::server::ResolvesServerCert` impl reading `ArcSwap<CertStore>`. File watcher reloads PEM pairs without dropping in-flight TLS handshakes.
- Test: two SNI names, rotate cert file, assert new cert served; no connection drops.

**M1-T3.2** HTTP/2 on both sides
- File: `aegis-proxy/src/proto/h2.rs`
- `hyper::server::conn::auto::Builder` with ALPN. Upstream client `http2_only(true)` when pool configured. Rapid-reset mitigator: cap `MAX_CONCURRENT_STREAMS`, track reset rate per conn, drop conn on abuse.
- Test: h2load stress; assert no runaway memory under rapid-reset flood.

**M1-T3.3** WebSocket upgrade passthrough
- File: `aegis-proxy/src/proto/ws.rs`
- Run pipeline on HTTP handshake only. On `Upgrade: websocket`: `hyper::upgrade::on(req)` + `tokio::io::copy_bidirectional` to upstream.
- Test: `tokio-tungstenite` echo client through WAF; messages round-trip.

**M1-T3.4** gRPC trailer-preserving forward
- File: `aegis-proxy/src/proto/grpc.rs`
- Stream frames + trailers; never buffer the full body.
- Test: `tonic` hello-world backend, assert trailer `grpc-status: 0` passes through.

**M1-T3.5** mTLS to upstream
- File: `aegis-proxy/src/upstream/mod.rs`
- Per-pool `tls: { ca_bundle, client_cert_ref, client_key_ref, server_name }`. Build a `rustls::ClientConfig` with client auth; refresh on secret rotation.
- Test: backend that requires client cert — request succeeds only when pool has matching cert.

**M1-T3.6** ACME (feature `acme`)
- File: `aegis-proxy/src/acme.rs`
- `instant-acme` for HTTP-01 and TLS-ALPN-01. Leader-only via `acquire_lease("acme")`. New cert goes through the same hot-reload path as file certs.
- Test: against `pebble` test CA; issue and serve a cert; renewal runs before expiry.

**M1-T3.7** OCSP stapling
- File: `aegis-proxy/src/ocsp.rs`
- Background task fetches OCSP response per cert, caches to disk, populates `CertifiedKey::ocsp`. Refresh before `nextUpdate`.
- Test: mock OCSP responder; assert stapled bytes present on TLS handshake.

**M1-T3.8** HTTP/3 (bonus, feature `http3`)
- File: `aegis-proxy/src/proto/h3.rs` using `quinn` + `h3`. Shares the route table and pipeline contract.
- Test: `curl --http3` end-to-end.

**W3 exit gate:** TLS listener green; two SNI names served; h2load passes; gRPC trailers preserved.

---

## W4 — Traffic Mgmt, Quotas, Sessions, Drain

**M1-T4.1** Per-route quotas
- File: `aegis-proxy/src/quota.rs`
- Enforce `client_max_body_size` (413), total header size (431), URI length (414), read/write timeouts (408/504), total deadline. Audit event names the specific quota breached.
- Test: one fixture per status code.

**M1-T4.2** Transformations + CORS
- File: `aegis-proxy/src/transform/mod.rs`
- Variable expansion: `$host`, `$client_ip`, `$request_id`, `$jwt.sub`, `$cookie.<name>`, `$header.<name>`.
- CORS preflight answered directly unless `cors.passthrough = true`.
- Test: golden-file header snapshots for each variable and CORS case.

**M1-T4.3** Canary split + header/cookie steering
- File: `aegis-proxy/src/traffic.rs`
- `split: [{pool: v1, weight: 95}, {pool: v2, weight: 5}]` with optional sticky HMAC cookie. Header/cookie steering short-circuits to a specific pool.
- Test: 10k synthetic requests within 1% of configured weight; sticky clients never split.

**M1-T4.4** Retries with budget
- File: `aegis-proxy/src/traffic.rs`
- Per-pool `{max_attempts, per_try_timeout, retry_on: [502,503,504,connect_err]}` + cluster-level budget ratio (reject retries if cluster retry ratio > N%).
- Test: failing upstream → retries up to budget then 502; budget exhausted → no further retries.

**M1-T4.5** Shadow mirroring
- File: `aegis-proxy/src/traffic.rs`
- Fire-and-forget clone of request to a second pool; response discarded; user latency unaffected.
- Test: both pools receive the request; shadow pool failure does not change the response status.

**M1-T4.6** Session affinity
- File: `aegis-proxy/src/session.rs`
- HMAC-signed `AG_SID` cookie naming the chosen member; consistent-hash fallback; re-issue on member drain.
- Test: 100 requests, first picks member M, next 99 hit M while healthy, re-pick after drain.

**M1-T4.7** Worker supervisor + graceful drain
- File: `aegis-proxy/src/supervisor.rs`
- Workers bind with `SO_REUSEPORT`. `InFlightTracker = Arc<AtomicUsize>`. On SIGTERM: set `ReadinessSignal.draining = true`, stop accepting, wait up to `drain_timeout_s`, exit.
- Test: `wrk` load + SIGTERM; dropped in-flight count must be 0.

**M1-T4.8** Hot binary reload (SIGUSR2, FD passing)
- File: `aegis-proxy/src/hotbin.rs`
- On SIGUSR2: `fork+exec` new binary with listening socket FDs passed via `CommandExt::fd_mappings`. Old process enters drain path. Rollback on readiness probe failure.
- Test: under `wrk` load, send SIGUSR2; no connections drop; new binary serves traffic.

**M1-T4.9** Tier-aware smart cache (`CacheProvider` impl)
- File: `aegis-proxy/src/cache/mod.rs`
- `moka`-backed async cache keyed by `(method, host, path, vary_headers_hash)`. MEDIUM aggressive (minutes), HIGH conservative (seconds, respects `Cache-Control`), CRITICAL never cached.
- Test: repeated GETs on MEDIUM route hit cache; CRITICAL route never caches; `Cache-Control: no-store` respected.

**W4 exit gate:** canary within 1%; graceful drain with 0 drops; hot reload under load.

---

## W5 — Clustering, Shedding, Secrets, DR

**M1-T5.1** `InMemoryBackend` polish
- File: `aegis-proxy/src/state/in_memory.rs`
- `DashMap` + TTL wheel. Implements full `StateBackend` trait (including `incr_window`, `token_bucket`, `get_risk`, `add_risk`, nonces, auto-block).
- Test: sliding-window property test — count never exceeds limit across concurrent writers.

**M1-T5.2** `RedisBackend` (feature `redis`)
- File: `aegis-proxy/src/state/redis.rs`
- `deadpool-redis` + Lua script for atomic sliding window. Fallback to local in-memory on backend error; reconcile via `max(local, remote)` on recovery.
- Test: docker-compose Redis; 2-node cluster shares rate-limit counter.

**M1-T5.3** Adaptive load shedder (Gradient2)
- File: `aegis-proxy/src/shed.rs`
- Per-pool: `L(t+1) = L(t) * (RTT_min / RTT_now)`. Priority drop order: CatchAll → Medium → High; Critical never shed. Shed response: 503 + `Retry-After` + request id, zero pipeline cost.
- Test: synthetic overload; Critical success rate ≥ 99% while CatchAll is shed.

**M1-T5.4** Secrets resolver
- File: `aegis-proxy/src/secrets.rs`
- Syntax: `${secret:<provider>:<path>[#field]}`. Providers: `env`, `file`. Vault/AWS return `NotImplemented` stubs. `zeroize::Zeroizing` container for resolved material.
- Test: config with `${secret:env:DB_PASS}` resolves; `/api/config` response never contains the resolved value.

**M1-T5.5** DR snapshot/restore CLI
- File: `aegis-proxy/src/dr.rs`
- `./waf snapshot --out /tmp/cfg.tar.zst` — effective config + rules + version stamp, signed with cluster key. `./waf restore <file>` — dry-run validator before activating. Periodic backup task, leader-only.
- Test: round-trip — snapshot, mutate live state, restore, assert identical.

**M1-T5.6** Service discovery
- File: `aegis-proxy/src/sd/mod.rs`
- Backends: `file` watcher, `dns_srv` (hickory-resolver), `consul` long-poll, `etcd` prefix watch, `k8s` endpoints informer (feature-gated). Safety limits: `min_members`, `max_churn_per_interval`. New members enter `probing` until active health confirms them.
- Test: file SD — add/remove a member, pool rotation within 1s, churn cap enforced.

**M1-T5.7** Cluster membership
- File: `aegis-proxy/src/cluster.rs`
- Default: `foca` SWIM gossip. Alternate: Redis-backed registry (`nodes:*` keys with TTL heartbeat). `acquire_lease(key, ttl)` used by ACME, GitOps, witness export, threat-intel fetch — only one node runs them.
- Test: 3-node in-process cluster; `peers()` stabilizes; only one node holds any given lease at a time.

**W5 exit gate:** 2-node Redis cluster sharing rate-limit + risk counters; Gradient2 load shedder keeps Critical at ≥ 99%.

---

## Definition of Done (`aegis-proxy`)

- [ ] `cargo test -p aegis-proxy` green; `cargo clippy -p aegis-proxy -- -D warnings` clean.
- [ ] Load test: ≥ 5 000 RPS sustained; p99 WAF overhead ≤ 5 ms (excluding upstream time).
- [ ] Graceful drain: 0 dropped in-flight under SIGTERM during `wrk` load.
- [ ] Hot binary reload: 0 connection drops under `wrk` load.
- [ ] 2-node Redis cluster demo sharing rate-limit counter.
- [ ] Fixtures under `config/fixtures/week-N/waf.yaml` for W1–W5.
