# Aegis-Gate Implementation Progress

## Last Completed
- Task: **D-M2-T2.7 Overview page module + proxy wire-up**
- Crates: aegis-control (services bundle + page module + tests),
  aegis-proxy (admin router wiring)
- Files changed:
  - `crates/aegis-control/src/api/stats.rs` — `StatsHandler`
    refactored to always carry an upstream-summary provider closure.
    `StatsHandler::new(agg)` defaults to `UpstreamSummary::placeholder`
    (back-compat); new `with_upstream(agg, F)` and
    `with_ttl_and_upstream(agg, ttl, F)` constructors take a real
    closure. `render()` overlays the provider output onto the
    aggregator snapshot at every cache miss so stats and upstream
    summaries agree numerically. +2 unit tests.
  - `crates/aegis-control/src/dashboard_services.rs` — new module:
    `DashboardServices { stats, stats_agg, attacks, attacks_agg,
    upstreams, environment }` bundle. `spawn(bus, pool_provider,
    env)` builds every aggregator/handler, **subscribes to the
    audit bus synchronously before spawning the drain task** (the
    one bug surfaced during this task: `broadcast::Receiver` only
    sees post-subscribe messages, so doing `bus.subscribe()` inside
    the spawned task lost any event emitted before it scheduled —
    fixed by hoisting subscribe outside `tokio::spawn`). Drain task
    feeds both aggregators from one subscriber. `pool_snapshot_provider(cfg)`
    helper builds a config-derived snapshot (pool names + member
    counts; healthy = 0 until the cluster runtime lands real per-
    member health). +5 tests.
  - `crates/aegis-control/src/lib.rs` — `+pub mod dashboard_services;`.
  - `crates/aegis-proxy/src/lib.rs` — `admin_accept_loop` now
    builds `Arc<DashboardServices>` once at boot (passing
    `cfg.admin.environment` and the config-derived pool provider)
    and shares it with every connection handler. `admin_router`
    gained a `&DashboardServices` parameter and 6 new dispatch
    arms: `/api/about`, `/api/stats`, `/api/stats/timeseries`,
    `/api/upstreams/summary`, `/api/attacks/distribution`,
    `/api/attacks/top`. Each emits `Cache-Control` per
    `docs/dashboard-enterprise/api.md` §"Caching"
    (`max-age=1` for stats, `max-age=2` for upstreams,
    `max-age=10` for attacks + about). New helpers:
    `parse_query_u32(query, key, default)` (tolerates the spec's
    `15m`/`5s` suffix by trim_end_matches('s')) and
    `json_body_response(status, body, cache_control)`.
  - `crates/aegis-control/assets/dashboard/pages/overview.js` —
    placeholder → real page (~210 lines). Renders 4 stat tiles
    (request rate, blocks total, block rate, active threats), a
    traffic chart slot, an attack-distribution slot, and a top-
    attackers table slot. Polls each endpoint at the documented
    cadence (1 s / 5 s / 10 s / 10 s); first fetch fires
    immediately on mount. Pauses polling while
    `document.visibilityState !== "visible"`; refreshes everything
    on `visibilitychange` returning to visible. Aborts in-flight
    fetches on `destroy()` via `AbortController`. Reads
    `/api/about` once on mount to fill the topbar version + env
    slots. Component swap targets (`[data-slot="traffic-chart"]`
    etc.) keep T2.9 a drop-in.
  - `crates/aegis-control/tests/api_smoke.rs` — new integration
    smoke test (6 cases): about shape; stats shape with real
    aggregator (asserts `blocks_total`, upstream rollup);
    timeseries shape (window=60, step=5, 12 buckets, sum matches
    recorded events); attacks distribution percentages sum to ~100
    (the milestone's required test); attacks top groups by
    attacker (sorted by hits desc); upstreams summary reflects
    pool provider.
- Tests added: 13 net new (2 stats + 5 dashboard_services + 6
  api_smoke).
- Status: DONE — 1,645 workspace tests pass (was 1,632, +13 new).
- Date: 2026-04-27

## Next Task
- Track: **Enterprise Dashboard (D)** — D-M2 in flight.
- **Next task: D-M2-T2.8 Wire SSE status pill**.
  Update `crates/aegis-control/assets/dashboard/app.js` (the
  status-bar bit from D-M1-T1.4 — currently shows "Disconnected"
  hardcoded) to open an `EventSource` to `/dashboard/sse` once on
  page boot and toggle the status-bar pill between
  `Connected` / `Reconnecting` / `Disconnected` based on the SSE
  connection state. The SSE handler at `/dashboard/sse` is
  already present (legacy from M1, returns one event then closes
  per the existing stub). For now the pill will flap because the
  stream auto-reconnects on close; that's intentional behaviour
  until full streaming SSE lands later.
  Plan note: the milestone says "not strictly Rust-testable;
  covered by an axe-driven smoke" — no new Rust tests are
  required, but verify the asset structure tests still pass.
  See [`plans/dashboard-enterprise/milestone-2-overview.md`](plans/dashboard-enterprise/milestone-2-overview.md).
- Milestone progress (D-M2):
  - [x] D-M2-T2.1 `/api/stats`
  - [x] D-M2-T2.2 `/api/stats/timeseries`
  - [x] D-M2-T2.3 `/api/upstreams/summary`
  - [x] D-M2-T2.4 `/api/attacks/distribution`
  - [x] D-M2-T2.5 `/api/attacks/top`
  - [x] D-M2-T2.6 `/api/about`
  - [x] D-M2-T2.7 Overview page module + proxy wire-up
  - [ ] D-M2-T2.8 SSE status pill
  - [ ] D-M2-T2.9 Stat-card / chart components + Chart.js vendor
- Remaining milestones: D-M3..D-M6 — see plan README.

### Known limitations / carry-overs
- Pool health: per-member `healthy` is hardcoded to 0 in
  `pool_snapshot_provider` because the cluster runtime that owns
  per-member health is itself stubbed. Pool *names* and *total*
  surface correctly. Real per-member readings land when the
  cluster runtime ships (likely M3 or later) — at that point
  swap the closure for one that reads from `cluster::Pool`
  state.
- `/dashboard/sse`: still returns one event then closes (the
  M1-era stub). T2.8 just wires the pill; full SSE streaming is
  in the existing deferred list.
- Components: stat-card, line-chart, donut, table are still
  M1-era stubs. T2.9 fills them and vendors `chart.umd.min.js`.

### Parallel track — Benchmark mode (B-)
- Plan: [`plans/benchmark-mode.md`](plans/benchmark-mode.md)
- Spec: [`docs/benchmark-mode.md`](docs/benchmark-mode.md)
- Status: planning complete, no code yet. B-T1..B-T3 (data plane)
  unblocked; B-T4.5 / B-T4.6 (dashboard panels) gated on D-M3.
  May land in any order alongside the dashboard track.
- Touches: aegis-core, aegis-proxy, aegis-security, aegis-control,
  aegis-bin. No new top-level deps.

### Deferred (post-dashboard track)
- [ ] Full upstream proxying (currently stub "OK" for clean requests — needs real TCP connect + proxy to upstream members)
- [ ] Full SSE streaming on `/dashboard/sse` (currently returns one event then closes — needs streaming body with AuditBus subscription)
- [ ] Production Dockerfile + Helm chart
- [ ] End-to-end integration tests (k6 load + nuclei security)
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] D-M2: vendor `chart.umd.min.js` and replace the SRI placeholder
  in `index.html` with the real digest; add `tests/dashboard/sri.rs`.

## Verification
- `cargo test -p aegis-core` → 82 passed.
- `cargo test -p aegis-control` → 526 passed (499 lib + 15 dod + 6 router_smoke + 6 api_smoke).
- `cargo test -p aegis-proxy` → 224 passed.
- `cargo test --workspace` → 1,645 passed (82 core + 499+15+6+6 control + 224 proxy + 780+1+32 security).
- `cargo clippy -p aegis-control -p aegis-proxy -- -D warnings` → clean.

## Completed Tasks Log
| Task | Crate | Date |
|------|-------|------|
| M1-T1.1 Workspace + `./waf run` skeleton | aegis-bin, aegis-proxy, aegis-core | 2026-04-22 |
| M1-T1.5 NoopPipeline + bus wiring | aegis-security (pre-existing), aegis-bin | 2026-04-22 |
| M1-T1.2 Config loader (figment + validation) | aegis-core | 2026-04-22 |
| M1-T1.3 Hot reload (notify + ArcSwap) | aegis-proxy | 2026-04-22 |
| M1-T1.4 Dual listener model | aegis-proxy | 2026-04-22 |
| M1-T2.1 Host matcher | aegis-proxy | 2026-04-22 |
| M1-T2.2 Path trie | aegis-proxy | 2026-04-22 |
| M1-T2.3 RouteTable::build + resolve | aegis-proxy | 2026-04-22 |
| M1-T2.4 Upstream Pool + LB strategies | aegis-proxy | 2026-04-22 |
| M1-T2.5 Active health checks | aegis-proxy | 2026-04-22 |
| M1-T2.6 Circuit breaker | aegis-proxy | 2026-04-22 |
| M1-T2.7 Wire routing + upstream into proxy.rs | aegis-proxy | 2026-04-22 |
| M1-T3.1 DynamicResolver + CertStore | aegis-proxy | 2026-04-24 |
| M1-T3.2 HTTP/2 on both sides | aegis-proxy | 2026-04-24 |
| M1-T3.3 WebSocket upgrade passthrough | aegis-proxy | 2026-04-24 |
| M1-T3.4 gRPC trailer-preserving forward | aegis-proxy | 2026-04-24 |
| M1-T3.5 mTLS to upstream | aegis-proxy | 2026-04-24 |
| M1-T3.6 ACME (feature acme) | aegis-proxy | 2026-04-24 |
| M1-T3.7 OCSP stapling | aegis-proxy | 2026-04-24 |
| M1-T4.1 Per-route quotas | aegis-proxy, aegis-core | 2026-04-24 |
| M1-T4.2 Transformations + CORS | aegis-proxy | 2026-04-24 |
| M1-T4.3 Canary split + header/cookie steering | aegis-proxy | 2026-04-24 |
| M1-T4.4 Retries with budget | aegis-proxy | 2026-04-24 |
| M1-T4.5 Shadow mirroring | aegis-proxy | 2026-04-24 |
| M1-T4.6 Session affinity | aegis-proxy | 2026-04-24 |
| M1-T4.7 Worker supervisor + graceful drain | aegis-proxy | 2026-04-24 |
| M1-T4.8 Hot binary reload (SIGUSR2) | aegis-proxy | 2026-04-24 |
| M1-T4.9 Tier-aware smart cache | aegis-proxy | 2026-04-24 |
| M1-T5.1 InMemoryBackend polish | aegis-proxy | 2026-04-24 |
| M1-T5.2 RedisBackend (feature redis) | aegis-proxy | 2026-04-24 |
| M1-T5.3 Adaptive load shedder (Gradient2) | aegis-proxy | 2026-04-24 |
| M1-T5.4 Secrets resolver | aegis-proxy | 2026-04-24 |
| M1-T5.5 DR snapshot/restore | aegis-proxy | 2026-04-24 |
| M1-T5.6 Service discovery | aegis-proxy | 2026-04-24 |
| M1-T5.7 Cluster membership | aegis-proxy | 2026-04-24 |
| M2-T1.1 Rule AST + parser | aegis-security | 2026-04-24 |
| M2-T1.2 Linter | aegis-security | 2026-04-24 |
| M2-T1.3 Evaluator | aegis-security | 2026-04-24 |
| M2-T1.4 RuleSet hot reload | aegis-security | 2026-04-24 |
| M2-T1.5 Tier classifier | aegis-security | 2026-04-24 |
| M2-T2.1 Sliding window rate limit | aegis-security | 2026-04-26 |
| M2-T2.2 Token bucket | aegis-security | 2026-04-26 |
| M2-T2.3 DDoS per-IP burst + cluster spike | aegis-security | 2026-04-26 |
| M2-T2.4 OWASP detectors (SQLi, XSS, PathTraversal, SSRF, HeaderInjection, BodyAbuse, Recon) | aegis-security | 2026-04-26 |
| M2-T3.1 JA4/JA3 parser | aegis-security | 2026-04-26 |
| M2-T3.2 HTTP/2 fingerprint | aegis-security | 2026-04-26 |
| M2-T3.3 Composite device id | aegis-security | 2026-04-26 |
| M2-T3.4 RiskEngine (scoring + decay) | aegis-security | 2026-04-26 |
| M2-T3.5 Challenge ladder | aegis-security | 2026-04-26 |
| M2-T3.6 Challenge tokens (HMAC + nonce) | aegis-security | 2026-04-26 |
| M2-T3.7 CAPTCHA providers (Turnstile, hCaptcha, reCAPTCHA) | aegis-security | 2026-04-26 |
| M2-T3.8 Behavioral analyzer | aegis-security | 2026-04-26 |
| M2-T3.9 Transaction velocity | aegis-security | 2026-04-26 |
| M2-T4.1 CIDR lists + XFF walker | aegis-security | 2026-04-26 |
| M2-T4.2 MaxMind ASN classifier | aegis-security | 2026-04-26 |
| M2-T4.3 Bot classifier | aegis-security | 2026-04-26 |
| M2-T4.4 Threat intel feeds | aegis-security | 2026-04-26 |
| M2-T5.1 Streaming response filter | aegis-security | 2026-04-26 |
| M2-T5.2 DLP patterns + actions | aegis-security | 2026-04-26 |
| M2-T5.3 FPE (AES-FF1) | aegis-security | 2026-04-26 |
| M2-T5.4 OpenAPI schema enforcement | aegis-security | 2026-04-26 |
| M2-T5.5 ForwardAuth | aegis-security | 2026-04-26 |
| M2-T5.6 JWT validation | aegis-security | 2026-04-26 |
| M2-T5.7 ICAP antivirus | aegis-security | 2026-04-26 |
| M2-T5.8 Magic-byte + archive-bomb | aegis-security | 2026-04-26 |
| M2-T5.9 GraphQL guard | aegis-security | 2026-04-26 |
| M2-T5.10 HMAC request signing | aegis-security | 2026-04-26 |
| M2-T5.11 API-key management | aegis-security | 2026-04-26 |
| M2-T5.12 Basic Auth | aegis-security | 2026-04-26 |
| M2-T5.14 OPA callout | aegis-security | 2026-04-26 |
| M2-DoD Red-team suite + benign corpus + fixture expansion | aegis-security | 2026-04-26 |
| M3-T1.1 MetricsRegistry init | aegis-control | 2026-04-26 |
| M3-T1.2 Prometheus exporter | aegis-control | 2026-04-26 |
| M3-T1.3 Health endpoints (live/ready/startup) | aegis-control | 2026-04-26 |
| M3-T1.4 Dashboard shell + SSE | aegis-control | 2026-04-26 |
| M3-T1.4b Dashboard overview page | aegis-control | 2026-04-26 |
| M3-T1.5 GET /api/config | aegis-control | 2026-04-26 |
| M3-T2.2 Tracing init + W3C Trace Context | aegis-control | 2026-04-26 |
| M3-T2.4 Access log writer (combined/JSON/template) | aegis-control | 2026-04-26 |
| M3-T3.1 Audit chain writer (SHA-256 hash chain) | aegis-control | 2026-04-26 |
| M3-T3.2 Audit verify (chain walk + recompute) | aegis-control | 2026-04-26 |
| M3-T3.3 Audit sinks (JSONL, syslog, CEF, LEEF, OCSF, Splunk HEC, ECS, Kafka) | aegis-control | 2026-04-26 |
| M3-T3.4 Admin change log | aegis-control | 2026-04-26 |
| M3-T3.5 Witness export (blake3 signing) | aegis-control | 2026-04-26 |
| M3-T3.6 State snapshot tracker | aegis-control | 2026-04-26 |
| M3-T4.1 Password verify + PHC (argon2id) | aegis-control | 2026-04-26 |
| M3-T4.2 HMAC session cookie + SessionRecord | aegis-control | 2026-04-26 |
| M3-T4.3 CSRF double-submit | aegis-control | 2026-04-26 |
| M3-T4.4 Login rate limit + lockout | aegis-control | 2026-04-26 |
| M3-T4.5 IP allowlist (in mtls module) | aegis-control | 2026-04-26 |
| M3-T4.6 TOTP (RFC 6238) + recovery codes | aegis-control | 2026-04-26 |
| M3-T4.7 Admin mTLS | aegis-control | 2026-04-26 |
| M3-T5.1 Compliance profiles (FIPS, PCI, SOC2, GDPR, HIPAA) + conflict detection | aegis-control | 2026-04-26 |
| M3-T5.2 Residency / retention sweep / right-to-erasure | aegis-control | 2026-04-26 |
| M3-T5.3 GitOps loader (poll, sig verify, dry-run, break-glass) | aegis-control | 2026-04-27 |
| M3-T5.5 SLO / SLI + multi-burn alerts (5 SLIs, 3 windows, 5 receivers) | aegis-control | 2026-04-27 |
| M3-DoD Integration tests (login flow, audit verify, SIEM ≥3 sinks, FIPS, SLO) | aegis-control | 2026-04-27 |
| Cross-crate wiring (audit verify, admin set-password, admin enroll-totp, validate + compliance) | aegis-bin | 2026-04-27 |
| README.md full rewrite (status, architecture, features, security, CLI) | project-wide | 2026-04-27 |
| deploy/GUIDE.md deployment guide (dev, staging, production) | project-wide | 2026-04-27 |
| docs/USAGE.md operations & usage guide | project-wide | 2026-04-27 |
| Data-plane detector wiring (7 OWASP detectors run on every request, block+audit on detection) | aegis-proxy | 2026-04-27 |
| Admin listener wiring (dashboard, SSE stub, health, metrics, config API on :9443) | aegis-proxy | 2026-04-27 |
| deploy/etcd/bootstrap.sh fix (self-shadowing function) | deploy | 2026-04-27 |
| config/README.md configuration guide (12 sections) | project-wide | 2026-04-27 |
| D-M1-T1.1 Asset embedder (31 assets, blake3 ETag, OnceLock table) | aegis-control | 2026-04-27 |
| D-M1-T1.2 SPA shell HTML (full chrome + 17-symbol inlined sprite) | aegis-control | 2026-04-27 |
| D-M1-T1.3 Router (dispatch + vanilla app.js + aegis-proxy delegation) | aegis-control, aegis-proxy | 2026-04-27 |
| D-M1-T1.4 Chrome (aegis.css design tokens + theme.js bootstrap + toggle wiring) | aegis-control | 2026-04-27 |
| D-M1-T1.5 Security headers (CSP + 8 others, single-source const + proxy wiring) | aegis-control, aegis-proxy | 2026-04-27 |
| D-M1-T1.6 Legacy shell carve-out (legacy.rs + DashboardConfig + flag wiring) | aegis-core, aegis-control, aegis-proxy | 2026-04-27 |
| D-M1-T1.7 Hot-reload (cfg-gated disk read of assets in debug builds) | aegis-control | 2026-04-27 |
| D-M1-T1.8 i18n loader (en.json bundle + t()/applyI18n in app.js) | aegis-control | 2026-04-27 |
| **D-M1 milestone complete** (SPA shell + assets + router + chrome + security headers + legacy carve-out + dev hot-reload + i18n) | aegis-core, aegis-control, aegis-proxy | 2026-04-27 |
| D-M2-T2.1 `/api/stats` data layer (StatsAggregator + Handler + 1s cache) | aegis-control | 2026-04-27 |
| D-M2-T2.2 `/api/stats/timeseries` (per-second BTreeMap + step-aligned downsampling) | aegis-control | 2026-04-27 |
| D-M2-T2.3 `/api/upstreams/summary` (compute_summary + UpstreamHandler with provider closure) | aegis-control | 2026-04-27 |
| D-M2-T2.4 `/api/attacks/distribution` (sliding-window per-detector counters + percentages) | aegis-control | 2026-04-27 |
| D-M2-T2.5 `/api/attacks/top` (per-attacker rollup + IP/JA4 identifier resolution) | aegis-control | 2026-04-27 |
| D-M2-T2.6 `/api/about` (AboutResponse + AdminConfig.environment) | aegis-core, aegis-control | 2026-04-27 |
| D-M2-T2.7 Overview page + proxy wire-up (DashboardServices + 6 endpoints + real overview.js) | aegis-control, aegis-proxy | 2026-04-27 |
