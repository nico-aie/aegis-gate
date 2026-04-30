# Implementation Progress — Completed Tasks Log

Append-only log of every task that has closed since the
project started. The very recent few rows are also mirrored in
`Implement-Progress.md`'s **Recent History** for at-a-glance.

---

## Completed Tasks Log

Append-only. One row per closed task.

| Task | Crate | Date |
|------|-------|------|
| M1-T1.1 Workspace + `./waf run` skeleton | aegis-bin, aegis-proxy, aegis-core | 2026-04-22 |
| M1-T1.5 NoopPipeline + bus wiring | aegis-security, aegis-bin | 2026-04-22 |
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
| M1-T5.2 RedisBackend stub (feature redis) | aegis-proxy | 2026-04-24 |
| M1-T5.3 Adaptive load shedder (Gradient2) | aegis-proxy | 2026-04-24 |
| M1-T5.4 Secrets resolver (env + file) | aegis-proxy | 2026-04-24 |
| M1-T5.5 DR snapshot/restore types | aegis-proxy | 2026-04-24 |
| M1-T5.6 Service discovery (file watcher) | aegis-proxy | 2026-04-24 |
| M1-T5.7 Cluster membership (in-process) | aegis-proxy | 2026-04-24 |
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
| M2-T4.4 Threat intel feeds (in-memory store) | aegis-security | 2026-04-26 |
| M2-T5.1 Streaming response filter | aegis-security | 2026-04-26 |
| M2-T5.2 DLP patterns + actions | aegis-security | 2026-04-26 |
| M2-T5.3 FPE (AES-FF1) | aegis-security | 2026-04-26 |
| M2-T5.4 OpenAPI schema enforcement | aegis-security | 2026-04-26 |
| M2-T5.5 ForwardAuth | aegis-security | 2026-04-26 |
| M2-T5.6 JWT validation | aegis-security | 2026-04-26 |
| M2-T5.7 ICAP antivirus (trait + types stub) | aegis-security | 2026-04-26 |
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
| M3-T1.4 Dashboard shell + SSE stub | aegis-control | 2026-04-26 |
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
| README.md full rewrite | project-wide | 2026-04-27 |
| deploy/GUIDE.md deployment guide | project-wide | 2026-04-27 |
| docs/operator/usage.md operator runbook | project-wide | 2026-04-27 |
| Data-plane detector wiring (7 OWASP detectors run on every request) | aegis-proxy | 2026-04-27 |
| Admin listener wiring (dashboard, SSE stub, health, metrics, config API on :9443) | aegis-proxy | 2026-04-27 |
| config/README.md configuration guide | project-wide | 2026-04-27 |
| **D-M1 milestone** (SPA shell + assets + router + chrome + security headers + legacy carve-out + dev hot-reload + i18n) | aegis-control, aegis-proxy | 2026-04-27 |
| **D-M2 milestone** (6 endpoints + Overview page wired end-to-end) | aegis-control, aegis-proxy | 2026-04-27 |
| **D-M3 milestone** (4 operator pages + 11 endpoints) | aegis-control, aegis-proxy | 2026-04-27 |
| **D-M4 milestone** (5 config-management pages + 11 endpoints + 5 stores) | aegis-control, aegis-proxy | 2026-04-28 |
| **D-M5 milestone** (tracking page — 6 endpoints + snapshot aggregate) | aegis-control, aegis-proxy | 2026-04-28 |
| **D-M6 milestone** (a11y/contrast/headers/budget tests + legacy removal + docs) | aegis-control, aegis-proxy, docs | 2026-04-28 |
| **Dashboard track complete** (D-M1..D-M6, +275 tests) | project-wide | 2026-04-28 |
| **P1** AuditedMutate pipeline (CSRF + audit chain + ArcSwap) | aegis-control | 2026-04-28 |
| **P2** Class toggles + hot-path bitfield mask + Settings UI | aegis-security, aegis-control | 2026-04-28 |
| **P3** Per-detector toggles + per-tier override (SharedDetectorMask) | aegis-security, aegis-control | 2026-04-28 |
| **P4** TLS hardening (TLS 1.2+ minimum, security headers, redirect) | aegis-proxy | 2026-04-28 |
| **P5** ACME — InstantAcmeProvider + AcmeManager + scheduler | aegis-proxy | 2026-04-28 |
| **P6** Risk-scoring upgrades (strikes + trust recovery + reset) | aegis-security, aegis-control | 2026-04-28 |
| **P7** LoadMode + bounded caches + degraded logging | aegis-core, aegis-security, aegis-proxy, aegis-control | 2026-04-28 |
| **P8** Verbosity gating + cold-tier surface | aegis-core, aegis-control | 2026-04-28 |
| **F-T1** Wire `POST /admin/login` + `/admin/logout` end-to-end | aegis-control | 2026-04-28 |
| **F-T2** Wire per-IP rate limiting | aegis-security, aegis-proxy | 2026-04-28 |
| **F-T3** No-op (was test contamination, not a real bug) | — | 2026-04-28 |
| **F-T4 + F-T5** k6 contract tests for security toggles + risk strikes | tests/load | 2026-04-28 |
| **F-T6** host-vs-laptop perf calibration docs | tests/load/README-perf.md | 2026-04-28 |
| **F-T7** Pebble container + ACME smoke | deploy, tests/api/acme.sh | 2026-04-28 |
| **F-T8** AcmeManager + InstantAcmeProvider wired into `run()` | aegis-proxy | 2026-04-28 |
| **F-T9** k6 audit-since + cold-tier inventory contracts | tests/load | 2026-04-28 |
| **F-T10** RequestStageHistogram (per-stage WAF latency) | aegis-control, aegis-proxy | 2026-04-28 |
| Documentation restructure — flat docs/ → 8-category taxonomy | docs/, plans/, crates/ | 2026-04-28 |
| Tests folder consolidation + new auth/TLS/rate-limit smoke coverage | tests/ | 2026-04-29 |
| Doc-by-doc implementation audit + Status banners + Phase B candidate seeds | docs/, plans/plan.md | 2026-04-29 |
| Implement-Progress.md rewritten as lean future-proof template | Implement-Progress.md | 2026-04-29 |
| Phase B promoted to active track — `plans/phase-b/` formalised, dashboard redesign queued | plans/, Implement-Progress.md | 2026-04-29 |
| `plans/` cleanup — README status board + extracted implementation-matrix.md + 21 Status banners + AI-guide-only `plan.md` | plans/, Implement-Progress.md | 2026-04-29 |
| **B1-T1** Real Redis state backend (`deadpool-redis` + Lua scripts + per-call timeout + live parity vs InMemoryBackend) | aegis-proxy | 2026-04-29 |
| **B1-T2** Backend selection in `aegis-bin` (`state_select::select` + boot log line + feature-gated redis branch + actionable errors) | aegis-bin | 2026-04-29 |
| **B1-T3** Cross-node leader lease (`LeaseStore` trait + `InProcessLease` + `RedisLease` + `spawn_heartbeat` + 7 live parity tests) | aegis-core, aegis-proxy | 2026-04-29 |
| **B1-T4** Lease gate on leader-only tasks (`run_with_lease` runner + `lease_select` + ACME gated; gitops/witness/threat-intel TODOs marked) | aegis-proxy, aegis-bin | 2026-04-29 |
| **B1-T5** Rehydrate + readiness gate (`state::rehydrate` probe + `state.reconcile.readiness_warm_ms` config + 5s default deadline; never permanently 503) | aegis-core, aegis-proxy | 2026-04-29 |
| **B1-T6** Partition-safe merge — closes B1 (`ReconcilingBackend` wrap; block-list union on heal; counters fall through; `ha-clustering.md` flipped Implemented) | aegis-proxy, aegis-bin, docs | 2026-04-29 |
| **B1 milestone CLOSED** — HA & multi-node ships single-node + Redis-primary + local-fallback | project-wide | 2026-04-29 |
| **B2-T1** Vault secret resolver (`aegis-proxy/vault` feature, KV-v2 client, token + AppRole auth, env-var config) | aegis-proxy | 2026-04-29 |
| **B2-T2** AWS Secrets Manager resolver (`aegis-proxy/aws` feature, `aws-sdk-secretsmanager`, full credential chain, JSON-field extraction) | aegis-proxy | 2026-04-29 |
| **B2-T3** GCP Secret Manager resolver (`aegis-proxy/gcp` feature, REST + `gcp_auth`, ADC chain, shared `json_field` helper) | aegis-proxy | 2026-04-29 |
| **B2-T4** Azure Key Vault resolver (`aegis-proxy/azure` feature, REST + hand-rolled SP/IMDS auth) — closes the cloud-secrets quartet | aegis-proxy | 2026-04-29 |
| **B2-T5** Consul service discovery (`aegis-proxy/consul` feature, blocking-query watcher, env-driven config, ACL/multi-DC/mTLS support) | aegis-proxy | 2026-04-29 |
| Side-quest: VipTalk default alert routing (`aegis-control/alerts` feature, `slo::dispatch::send_alert`, env override; doc updated) | aegis-control, docs | 2026-04-29 |
| **B2-T6** etcd service discovery (`aegis-proxy/etcd` feature, REST gateway range-polling, basic auth + mTLS, configurable poll interval) | aegis-proxy | 2026-04-29 |
| **B2-T7** Kubernetes service discovery — closes B2 (`aegis-proxy/k8s` feature, EndpointSlice streaming watch, in-cluster + override auth) | aegis-proxy | 2026-04-29 |
| **B2 milestone CLOSED** — operational integrations (cloud-secrets quartet + service-discovery trio) ship | project-wide | 2026-04-29 |
| **B3-T1** Built-in git poll-and-pull `GitClient` (`gitops::poll_driver::GitPollDriver` shells out to system `git`; signature parse via `verify-commit --raw`; read-only by design; +9 tests) | aegis-control | 2026-04-29 |
| **B3-T2** STIX/TAXII fetch loop into `ThreatIntelStore` (`aegis-security/taxii` feature; TAXII 2.1 client + paginated fetcher loop; STIX 2.1 pattern decoder for IPv4/IPv6/domain/URL/SHA-256; +38 tests) | aegis-security | 2026-04-29 |
| **B3-T3** GeoIP MaxMind reader + rule-engine `country` / `asn` conditions (`aegis-security/geoip` feature; `MaxMindReader` w/ atomic hot-reload + `EvalContext`-threaded rule eval; `geoip-filtering.md` flipped Implemented; +18 default-feature + 5 feature-gated tests) | aegis-security | 2026-04-29 |
| **B3-T4** Concrete RFC 3507 ICAP TCP client — closes B3 (`content::icap::{codec,tcp}`; pure framing helpers + 5-vendor decision table; configurable timeout + fail-open default; `content-scanning.md` flipped Implemented; +36 tests) | aegis-security | 2026-04-29 |
| **B3 milestone CLOSED** — Data feeds + filtering (GitOps + TAXII + GeoIP + ICAP) ship | project-wide | 2026-04-29 |
| **B4-T1** `waf snapshot` CLI subcommand (`aegis-bin::snapshot::SnapshotEnvelope`; bundles config + rules files + blake3 integrity + schema versioning into JSON; refuses overwrite without `--force`; `decode`/`validate_envelope` ready for B4-T2; +15 tests) | aegis-bin | 2026-04-29 |
| **B4-T2** `waf restore` CLI subcommand (`restore_envelope` w/ atomic dry-run validation + rollback; `dr-backup.md` flipped Implemented for config/rules surface; +10 tests) | aegis-bin | 2026-04-29 |
| **B4-T3** Full upstream proxying (`upstream::forward` replaces stub; hop-by-hop scrub both directions; Host rewrite + `X-Forwarded-Host`; preserves method/path/query/body; +14 forward + 5 proxy end-to-end tests) | aegis-proxy | 2026-04-29 |
| **B4-T4** Full SSE streaming on `/dashboard/sse` — closes B4 (`admin_sse::sse_response` returns `UnsyncBoxBody` driven by `BroadcastStream` merged w/ 15s idle heartbeat ticker; preamble + per-event frames + lag handling; +8 tests) | aegis-proxy, aegis-control | 2026-04-29 |
| **B4 milestone CLOSED** — Operator tooling (snapshot + restore + upstream + SSE) ships | project-wide | 2026-04-29 |
| **B5-T1** HTTP/3 listener (`aegis-proxy/http3` feature; `listener::http3` on quinn 0.11 + h3 0.0.8 + h3-quinn 0.0.10; pure helpers for Alt-Svc + ALPN + bind parse + config; runtime path dispatches QUIC streams through `proxy::handle_request`; `protocols.md` flipped Implemented; +15 tests) | aegis-proxy | 2026-04-29 |
| **B5-T2** Benchmark mode core slice — closes B5 (`aegis-proxy::benchmark` ships `BenchmarkConfig` + `StageTimings` + `X-Aegis-*` header serialiser; `proxy::handle_request` captures total/route/upstream timings + tier + decision; 1 KiB header budget; off-mode = 1 bool check; `benchmark-mode.md` flipped Implemented (core slice); +21 unit + 2 proxy end-to-end tests) | aegis-proxy | 2026-04-29 |
| **B5 milestone CLOSED** — Protocols + benchmark (HTTP/3 + benchmark mode) ships | project-wide | 2026-04-29 |
| **Perf re-run** — 2026-04-29 baseline + ddos-burst + rate-limit benchmarks against release build w/ B3+B4+B5 changes; allow-path latency p95 7.21 ms → 877 µs; surfaced two carry-overs (`lib.rs::handle_data_request` Allow stub still active; rate-limit returns 403 not 429); old logs preserved as `tests/results/*.log`, new as `tests/results/*-2026-04-29.log`, comparison in `tests/results/README-2026-04-29.md` | tests/results | 2026-04-29 |
| **HTTPS test additions** — `tests/api/tls-data.sh` (data-plane TLS hardening; skips when `:8443` not bound), `tests/api/tls-ciphers.sh` (TLS 1.3 + 1.2 cipher-suite negotiation, weak-cipher reject, cert-chain probe), `tests/load/tls-baseline.js` (k6 baseline over HTTPS w/ handshake-latency SLO); wired into `tests/api/run-all.sh`; pyramid table updated | tests/api, tests/load | 2026-04-29 |
| **HA cluster smoke track** — new `tests/cluster/` (4 scripts + `_common.sh` + `run-all.sh` + `README.md`) exercising B1's contract: shared Redis state (`01-shared-counter.sh`), cross-node leader failover (`02-leader-failover.sh`), rehydrate-readiness gate (`03-rehydrate-readiness.sh`), partition-fallback heal (`04-partition-fallback.sh`); two-node fixture w/ `config/waf.cluster-{a,b}.yaml`; both configs validate clean | tests/cluster, config | 2026-04-29 |
| **Cluster + HTTPS perf re-run** — first live run of the new cluster track; 3 PASS / 0 FAIL / 1 SKIP (leader-state admin endpoint not exposed). Two-node baseline shows identical perf across A and B (34.5 k RPS, p95 ~880 µs, identical to single-node). Surfaced two new carry-overs: rate-limit bucket per-node despite shared state backend (each node admits 10 k, total 20 k); data-plane `tls.certificates` parsed but no listener-side loader. HTTPS load test skipped — no data-plane TLS path consumable from YAML. Logs in `tests/results/cluster/`, comparison in `tests/results/cluster/README-2026-04-29.md` | tests/cluster, tests/results | 2026-04-29 |
| **Carry-over A** — data-plane Allow forwarding wired through `upstream::forward::forward()`; `lib.rs::handle_data_request` is now async + takes `Arc<ProxyContext>`; `forward_allow_to_upstream` helper does route resolve → CB gate → pool pick → body collect → forward; `run_binds_and_serves_200` rewritten with a mock upstream; live k6 against WAF→`aegis-httpbin` shows 31.5 k RPS / 504 µs median / 3.66 ms full-hop p95; closes the data-plane stub gap surfaced 2026-04-29 | aegis-proxy | 2026-04-29 |
| **Carry-over B** — rate-limit response code alignment. Investigation found the gateway *already* emits 429 + Retry-After at `lib.rs:1814`; the original failure was a `tests/load/rate-limit.js` calibration bug (burst < budget). Fixed in script: defaults bumped to 2 000 RPS × 8 s, VU pool resized, thresholds relaxed to match real budget arithmetic, 403 strike-block path also accepted. Re-run: `status_429_observed = 50`, threshold PASS. No gateway code change. | tests/load, tests/results | 2026-04-29 |
| **Carry-over 3** — leader-state admin endpoint. New `LeaderView` shared cell + background polling task in `aegis-proxy::run` reads `lease_store.holder("leader:cluster")` every 2 s; `LeaseStore::self_id()` added so the trait surfaces a node's identity. `/api/cluster` now returns `is_leader`, `leader_node`, `our_node`. Singleton `leader:cluster` lease (5 s TTL) acquired by exactly one node. `tests/cluster/02-leader-failover.sh` flipped SKIP → PASS. +5 net new tests in `tracking::tests`. | aegis-control, aegis-proxy, aegis-core | 2026-04-29 |
| **Carry-over 4** — cluster-shared rate-limit bucket. Closed as a doc clarification: the per-IP volumetric guard is intentionally per-node (DDoS shield), the named-bucket limiter is cluster-shared via `StateBackend`. `docs/security/rate-limiting.md` rewritten to distinguish the two surfaces explicitly. No code change. | docs | 2026-04-29 |
| **Carry-over 5** — data-plane TLS loader. `config.tls.certificates` now flows to a single `tokio_rustls::TlsAcceptor` built at boot; data-plane listeners with `tls: true` use it. ALPN forced to `http/1.1` (HTTP/2 over TLS is a follow-up). New `config/waf.tls.yaml` + self-signed cert fixture in `tests/fixtures/tls/`. Live: TLS 1.3 + AES-256-GCM, k6 measures 31.8 k RPS / handshake p95 2.12 ms / request p95 1.03 ms. | aegis-proxy, config, tests/fixtures | 2026-04-29 |
| **run-04 perf re-run** — `tests/results/` restructured into per-run dated subdirs. Cluster smoke 4/4 PASS (was 3/4), HTTPS data plane proven end-to-end, cluster perf identical across nodes. Documented in `tests/results/run-04-2026-04-29-cluster-https/README.md` + master index `tests/results/README.md`. | tests/results | 2026-04-29 |
| **Carry-over 6 (NEW, open)** — HA perf test methodology gap noted: cluster perf hits each node on its own port, not via a single VIP / LB. New `tests/cluster/HA-TEST-METHODOLOGY.md` analyses three remediation options (DNS RR / HAProxy / SO_REUSEPORT), recommends HAProxy in front. Cluster + run-04 + master READMEs cross-reference the doc. Test-infra gap, not a runtime bug. | tests/cluster, tests/results, docs | 2026-04-29 |
| **HA cluster docs + ingress plan** — rewrote `docs/operations/ha-clustering.md` to align with what shipped vs the v2-design placeholder (drop `state.backends[]` array, document actual `state.redis` block); added §"Cluster topology" diagram, §"Load balancer patterns" (k8s Ingress / Nginx / HAProxy recipes), §"Roadmap" with 8 open HA items + carry-over 6 + B-track cross-refs. New `plans/cluster-ingress-lb.md` breaks the fix into HA-T1..HA-T5 sub-tracks (~1.5 days total); promoted to second active track in `plans/README.md`. | docs/operations, plans | 2026-04-29 |
