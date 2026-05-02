# Aegis-Gate

A production-grade **Web Application Firewall** and security
gateway written in Rust. Aegis-Gate sits in front of arbitrary
HTTP/HTTPS backends as a full reverse proxy, inspecting every
request and response through a tiered security pipeline before
traffic reaches the application.

Targeted at enterprise environments (fintech, healthcare, public
sector) with high availability, multi-tenancy, compliance, and
observability demands comparable to F5 BIG-IP ASM, Imperva,
Akamai Kona, and Cloudflare Enterprise.

> **For AI Assistants** — read `Implement-Progress.md` and
> `plans/plan.md` before writing any code.

## Status (as of 2026-05-02)

**Core M1–M3, Aegis WAF Console redesign, HA cluster, the
external interop contract, the entire Phase B production
packaging track, the Hackathon-readiness track (HACK-T1..T5
+ both follow-ups), and the proxy refactor (lib.rs 5569 →
559 lines) are all shipped.** Active work:

- **Hackathon Round-1 stress-test prep** — 15-min mixed-traffic
  harness scaffolded under `tests/hackathon/` (mock upstream
  matching `Hackathon_Doc/openapi.public.yaml`, k6 mixed-
  traffic script with 15-shape attack corpus, bench config,
  one-shot `run.sh`, post-run `summary.sh`). Awaiting
  benchmark team's source-IP fan-out / latency target /
  attack-labelling source — see
  [`plans/hackathon-stress-test.md`](plans/hackathon-stress-test.md) §8.
- **Console QA — full feature audit** ([`plans/console-qa.md`](plans/console-qa.md)) —
  14-slice manual sweep verifying every screen / button / action
  against live data; no fakes, no dead buttons, every mutation
  round-trips through the audit chain. ~9 h wall-clock.
- **MTLS-T8..T11** queued — break-glass, CA upload, per-route
  editor. T1..T7 ✅ shipped (rustls inbound, identity
  extraction, route gate, hot-reload, console observability,
  SAN allowlist).
- **Detector coverage gap-fills** under consideration to
  raise Round-1 detection rate from 33 % → ~73 %: mass-assignment
  body shape, brute-force on /login, SSRF metadata-IP body scan,
  XXE detector. Each ~half-day.

**Recent verification (2026-05-02, perf-sweep + harness smoke):**

| Check | Result |
|---|---|
| Workspace tests | **~2 500 / 0 fail** across 17 binaries |
| v2.3 contract gate (`tests/contract/v2.3_compliance.sh`) | **40 / 40 PASS** (after curl 8.1+ URL-encode fix) |
| API smoke (auth, detectors, risk, loadmode, logging, cold-tier) | **56 / 56 PASS** |
| Protocol mix | HTTP/1.1 PASS; HTTP/2/3/gRPC graceful SKIP (no TLS data plane in dev cfg); WS info |
| Hackathon harness smoke (30 s, 10/3/10 VUs) | legit p99 **5.81 ms**, legit OK **99.76 %**, attacks detected **33 %** (corpus has app-layer shapes today's detectors don't reach yet — see "detector gap-fills" above) |
| MTLS-T7 SAN allowlist live verification | GET-empty → PUT 3 → test admit matrix (exact / wildcard single-label match / wildcard multi-label rejected / unknown rejected) → DELETE → audit chain captured set + remove |
| HACK-T4 rollback live verification | `POST /api/config/versions/{seq}/rollback` for `mode_set` → mode reverts → audit chain captures `mode_set_rollback` |

Earlier baselines: k6 **37 600 req/s** sustained at median **60 µs** /
p95 **286 µs** (run-12); Nuclei 742 templates / 1 431 requests
**0 vulnerabilities** (run-12).

| Milestone | Crate | Description |
|---|---|---|
| **M1** Data Plane | `aegis-proxy` | TLS (rustls), HTTP/1.1, HTTP/2, HTTP/3 (`http3` feature), WebSocket, gRPC, routing trie, upstream pools (5 LB strategies + pooled keep-alive HTTP/1.1 + rustls connector for HTTPS), circuit breakers, rate-limiting quotas, canary, retries, caching, state backends (in-memory + Redis), service discovery (Consul / etcd / k8s), hot reload, ACME, OCSP stapling |
| **M2** Security Pipeline | `aegis-security` | Rule engine (AST + evaluator + hot reload), OWASP detectors, risk scoring, JA4/JA3 fingerprinting, HTTP/2 fingerprint, bot classification, challenge ladder, DLP + FPE, JWT/OAuth, OpenAPI enforcement, GraphQL guard, STIX/TAXII threat intel (`taxii` feature), GeoIP MaxMind reader (`geoip` feature), ICAP RFC 3507 client |
| **M3** Control Plane | `aegis-control` | Prometheus metrics, health probes, audit hash chain (SHA-256) with **durable NDJSON sink** (DURABLE-T1), 8 SIEM sinks, admin auth (argon2id + HMAC session + CSRF + TOTP + mTLS policy), compliance (FIPS/PCI/SOC2/GDPR/HIPAA), GitOps loader, SLO alerting + multi-burn windows + VipTalk delivery (`alerts` feature), audit-mutation pipeline (rule CRUD lands here), `/api/config/version` for hot-reload visibility, **persistent detector mask** (DURABLE-T2) |
| **HA cluster** (HA-T1..T5) | `aegis-proxy` + `aegis-control` | Redis-backed cluster shared rate-limits + leader lease; `/admin/drain` + `?strict=1` readiness; HAProxy reference deploy. 9.5 k RPS via VIP, 99.93% hard / 100% graceful failover. |
| **Interop contract** (IT-T1..T6) | `aegis-control::interop` + `aegis-proxy` | Always-on `X-WAF-*` headers + `/__waf_control/*` (capabilities, mode, reset_state, rule_id_present), audit-chained mode toggles. 27/27 contract checks green at ~30 µs p95 overhead. |
| **Aegis WAF Console** (DD-T0..T8 + CI-T1..T12 + CC-T\*) | `aegis-control` (assets + api) | Pre-compiled React 18 SPA (`assets/dashboard/app.js`, **178 KB**) + 12 sidebar pages + 17+ real `/api/*` hooks. CSP `script-src 'self'` (no CDN, no `unsafe-eval`). Full **upstreams CRUD** (CC-T1.\*), **alert receivers card** (CC-T2.\*), **risk thresholds** (CI-T12), **audit-mutated** rule + mode + receiver edits with hot-reload visibility ≤ 10 s. |
| **Audit-driven gap closure** (PROM-T1+T2+T3, GRAFANA-T1, OTEL-T1+T2+T3) | `aegis-control` + `aegis-bin` + `deploy/grafana/` | Closes the 4 audit gaps. Live Prometheus instrumentation (`waf_requests_total`, `waf_upstream_members_*`, `waf_detector_hits_total`, `waf_state_backend_ops_total`, `waf_audit_events_total`); 3 file-provisioned Grafana dashboards (overview / redis / runtime); live OTel OTLP exporter with `#[tracing::instrument]` on every hot-path span; **Jaeger** parent-child trace trees per request. |
| **Config from etcd** (ETCD-T1) | `aegis-proxy` | `AEGIS_CONFIG_SOURCE=etcd` boot path under the `etcd` feature. Loads `WafConfig` from `/aegis/config/waf` via etcd v3 `/v3/kv/range`; same YAML blob the file loader accepts; same `WafConfig::validate`. |
| **Server-side mTLS** (MTLS-T1+T6) | `aegis-core` + `aegis-control` | `cfg.tls.client_auth: ClientAuthConfig` schema (mode disabled/optional/required, ca_bundle, allowed_sans, apply_to admin/data) + `ClientIdentity` enum (Anonymous / Mtls / Spiffe). Read-only `/api/mtls`, `/connections`, `/failures`, `/ca-summary` console endpoints. **Rustls inbound wiring (T2) + identity extraction (T3) deferred behind the proxy refactor**; today's `client_auth` is parsed but ignored at the handshake layer. |
| **Hot-reload coverage** | `aegis-proxy` + `aegis-security` | **Six cfg surfaces hot-reload via the file watcher (notify, ~100 ms) or etcd watcher (REST poll, ~5 s)**: `cfg.routes` (RouteTable ArcSwap), `cfg.upstreams` (PoolRegistry — also via audit-mutated PUT), `cfg.detectors` (SharedDetectorMask base + per-tier overrides), `cfg.compliance.modes` (clamp re-runs), `cfg.rate_limit.buckets[0]` (IpRateLimiter ArcSwap), `cfg.tls.certificates` (DynamicResolver swap; in-flight handshakes finish on the old store). Audit chain emits `routes_reload_failed`, `compliance_clamp_applied`, `rate_limit_reloaded`, `tls_reloaded`, `tls_reload_failed` so the dashboard surfaces every reload event. |
| **Phase B** (B1..B6) | project-wide | All closed. B1 HA + multi-node (Redis primary + InProcessLease + ReconcilingBackend), B2 cloud secrets (Vault, AWS, GCP, Azure) + Consul SD, B3 GitOps + Kafka audit + WASM rules, B4 caching + reflection (with Allow forwarding), B5 protocols (HTTP/3 + benchmark mode), B6 packaging (production Dockerfile + Helm chart). |
| **Proxy refactor** (PRE-T1..T6) | `aegis-proxy` | Structural extraction. `aegis-proxy/src/lib.rs`: 5569 → **2650 lines (−52%)**. Six new submodules: `responses.rs` (231), `data_plane.rs` (616), `admin_login.rs` (151), `admin_get.rs` (519), `admin_mutate.rs` (1714), plus pre-existing `admin_sse.rs` (385). PRE-T7 (`run.rs`) + PRE-T8 (verify) close the track. |

## Quick Start

```sh
# 1. One-shot setup — generates self-signed dev cert + release build
make setup

# 2. Boot the WAF
make run                    # uses config/prod.yaml by default

# 3. Smoke test (in another terminal)
make smoke
```

Run `make help` to see every target. Common overrides:

```sh
CONFIG=config/dev.yaml make run                          # boot dev config
FEATURES="redis alerts geoip taxii http3 etcd otel" make build
make test                                                # cargo test --workspace
```

Step-by-step setup + tuning + admin auth:
[`QUICKSTART.md`](QUICKSTART.md). Production deployment:
[`deploy/GUIDE.md`](deploy/GUIDE.md). YAML reference:
[`config/README.md`](config/README.md).

### Three-layer scaling

| Layer | Knob | Doc |
|---|---|---|
| 1 — In-node | `runtime.workers`, `cpu_affinity` (tokio worker threads, `affinity` feature) | [`docs/operations/runtime-tuning.md`](docs/operations/runtime-tuning.md) |
| 2 — Across nodes | `node.id` + an LB in front of N peers | [`docs/operations/ha-clustering.md`](docs/operations/ha-clustering.md) |
| 3 — State | `state.backend: redis` (counters, leases, block lists) | [`Architecture.md` §12](Architecture.md) |

### Config sources (boot-time selection)

```sh
# Default — load from a local YAML file
./target/release/waf run --config config/prod.yaml

# etcd v3 (--features etcd) — load from a key, watch for changes
AEGIS_CONFIG_SOURCE=etcd \
AEGIS_ETCD_ENDPOINTS=http://etcd-cluster:2379 \
  ./target/release/waf run
```

Both sources flow through the same `WafConfig::validate` and
the same hot-reload watcher path. See
[`deploy/etcd/README.md`](deploy/etcd/README.md) for the etcd
key layout + bootstrap.

## CLI Overview

```
waf run       --config <path>         Start the WAF gateway
waf validate  --config <path>         Dry-run validation + compliance check
waf audit     verify --from <path>    Verify audit chain integrity
waf admin     set-password            Hash admin password (argon2id)
waf admin     enroll-totp             Generate TOTP secret + recovery codes
waf snapshot  --output <path>         Bundle effective config + rules into a JSON snapshot
waf restore   --from <path>           Restore config + rules from a snapshot (validates first)
waf version                           Show version
waf help                              Show help
```

## Repository Layout

```text
aegis-gate/
├── README.md                      # This file
├── Requirement.md                 # Functional + non-functional requirements
├── Architecture.md                # System architecture + design decisions
├── Implement-Progress.md          # Living implementation snapshot (Last Completed + Status)
├── plans/                         # Implementation plans per track
│   ├── README.md                  # Status board for every track
│   ├── plan.md                    # AI assistant guide + protocol
│   ├── implementation-matrix.md   # doc-by-doc Implemented/Partial/Designed
│   ├── hackathon-stress-test.md   # ACTIVE — Round-1 15-min stress-test prep
│   ├── followups-rollback-and-sans.md # CLOSED — HACK-T4 rollback + MTLS-T7 SANs
│   ├── hackathon-readiness.md     # CLOSED — HACK-T1..T5 + follow-ups
│   ├── proxy.md                   # M1 (closed)
│   ├── security.md                # M2 (closed)
│   ├── control.md                 # M3 (closed)
│   ├── dashboard-redesign.md      # DD-T0..T8 (closed)
│   ├── cluster-ingress-lb.md      # HA-T1..T5 (closed)
│   ├── interop-contract.md        # IT-T1..T6 (closed)
│   ├── interop-dry-run.md         # DR-T1..T7 (closed)
│   ├── console-config-pages.md    # CC-T1..T2 (closed)
│   ├── console-api-integration.md # CI-T1..T12 (closed)
│   ├── post-run-08.md             # AF-T1, HP-T1, TLS-T1 (closed)
│   ├── post-k6-followup.md        # P1..P8 + F-T1..F-T10 (closed)
│   ├── benchmark-mode.md          # folded into B5-T2
│   ├── phase-b/                   # B1..B6 (closed)
│   ├── mtls.md                    # MTLS-T1..T11 (T1..T7 closed; T8..T11 queued)
│   ├── proxy-refactor.md          # PRE-T1..T8 (closed)
│   ├── scaling-config.md          # SC-T* (T1..T3 + T5 closed; T4 deferred)
│   └── archive/                   # superseded plans, kept for history
├── docs/                          # Per-feature specifications (~60 files, foldered)
│   ├── README.md                  # Taxonomy index + ownership map
│   ├── operator/                  # usage.md, cli.md, soc-runbook.md, benchmark-mode.md
│   ├── architecture/              # protocols
│   ├── data-plane/                # M1 — proxy, routing, TLS, traffic mgmt
│   ├── security/                  # M2 — rules, detectors, risk, challenge, mtls
│   │   └── detectors/             #   per-attack-class detector specs
│   ├── control-plane/             # M3 — dashboard, admin API, hot-reload
│   │   └── enterprise/            #   enterprise dashboard SPA spec
│   ├── observability/             # metrics, audit, SIEM, SLO
│   ├── operations/                # HA, compliance, residency, DR
│   ├── progress/                  # completed-tasks-log.md (append-only)
│   └── future/                    # Phase B intake + deferred designs
├── deploy/                        # Docker Compose + deployment + Grafana
│   ├── GUIDE.md                   # Deployment guide (dev → staging → production)
│   ├── README.md                  # Dev infrastructure quick start
│   ├── docker-compose.dev.yml     # Full dev stack (etcd, prometheus, grafana, jaeger, redis, httpbin)
│   ├── docker-compose.test.yml    # Test pyramid (attacker, k6, nuclei, etcdctl)
│   ├── grafana/                   # File-provisioned datasources + 3 dashboards
│   │   └── dashboards/            #   aegis-waf-overview, aegis-redis, aegis-runtime
│   ├── etcd/                      # bootstrap.sh + key-layout README
│   ├── helm/aegis-gate/           # Production Helm chart (B6-T2)
│   ├── Dockerfile                 # Multi-arch distroless production image (B6-T1)
│   └── docker-build.sh            # buildx wrapper for amd64 + arm64
├── tests/                         # Out-of-process load + security + dashboard tests
│   ├── api/                       # curl + jq smoke tests (16 scripts)
│   │   ├── openapi-shape.sh       # 32-check OpenAPI contract
│   │   └── upstreams-crud.sh      # CC-T1.audit end-to-end CRUD
│   ├── contract/                  # v2.3 contract regression gate (40 numbered §X.Y checks)
│   ├── hackathon/                 # Round-1 15-min stress-test harness
│   │   ├── upstream/server.py     #   mock app matching openapi.public.yaml
│   │   ├── k6/mixed-15min.js      #   legit + crawler + attacker scenarios
│   │   ├── configs/bench.yaml     #   loose-thresholds WAF config for shared-IP load
│   │   ├── run.sh                 #   orchestrator (boot → 15-min k6 → summary)
│   │   └── summary.sh             #   post-run Markdown report
│   ├── load/                      # k6 scripts (baseline, rate-limit, ddos-burst, …)
│   ├── security/                  # corpus + nuclei + zap runners
│   ├── dashboard/                 # round1-acceptance.sh + capture-screenshots.mjs
│   ├── cluster/                   # HA smoke (5 scripts + fixtures)
│   ├── interop/                   # 27-check interop contract
│   ├── protocols/                 # h1 / h2 / WS / gRPC / h3
│   └── results/                   # dated run reports with logs + screenshots
└── crates/
    ├── aegis-core/                # Shared types, traits, config schema, ClientIdentity
    ├── aegis-proxy/               # Data plane (TLS, routing, upstreams, state)
    │   └── src/
    │       ├── lib.rs             # 2650 lines — boot + admin dispatch + watchers
    │       ├── responses.rs       # JSON / cache-control / dashboard-shell helpers
    │       ├── data_plane.rs      # handle_data_request + forward_allow_to_upstream
    │       ├── admin_login.rs     # /admin/login + /admin/logout
    │       ├── admin_get.rs       # admin_router (every GET dispatch arm)
    │       ├── admin_mutate.rs    # 18 audit-mutated PUT/POST/DELETE handlers
    │       ├── admin_sse.rs       # /dashboard/sse streaming body
    │       ├── config_source/     # etcd_source + reload helpers
    │       └── ...                # listener/, upstream/, route/, state/, supervisor/, ...
    ├── aegis-security/            # Security pipeline (rules, detectors, risk)
    ├── aegis-control/             # Control plane (dashboard, auth, audit, compliance)
    └── aegis-bin/                 # `waf` binary — wires all crates together
```

## Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │                aegis-bin (waf)                │
                    │       CLI dispatch + crate wiring             │
                    │ + tokio runtime build (workers, affinity)     │
                    │ + ConfigSource selection (file | etcd)        │
                    │ + OTEL OTLP exporter (--features otel)        │
                    └──────┬──────────┬──────────────┬─────────────┘
                           │          │              │
              ┌────────────▼──┐  ┌────▼──────────┐  ┌▼───────────────┐
              │  aegis-proxy  │  │ aegis-security │  │ aegis-control  │
              │  (data plane) │  │  (sec pipeline)│  │ (control plane)│
              │               │  │                │  │                │
              │ • TLS/HTTP/2  │  │ • Rule engine  │  │ • Dashboard    │
              │ • Routing*    │  │ • OWASP detect │  │ • Auth (argon2)│
              │ • Upstreams*  │  │ • Risk scoring │  │ • Audit chain*│
              │ • Load shed   │  │ • DLP/FPE      │  │ • SIEM sinks   │
              │ • State*      │  │ • Bot classify │  │ • Compliance*  │
              │ • Caching     │  │ • API security │  │ • GitOps       │
              │ • Hot-reload* │  │ • Rate-limit*  │  │ • SLO alerts   │
              └───────┬───────┘  └───────┬────────┘  │ • Identity*    │
                      │                  │           │   tracker      │
                      └──────────┬───────┘           └────────┬───────┘
                            ┌────▼────┐                       │
                            │aegis-core│◄──────────────────────┘
                            │ (types) │
                            │ + ClientIdentity (mTLS-ready)    │
                            └─────────┘

* = surface that hot-reloads from cfg changes (file or etcd watcher).
```

## Hot-reload story (operator-facing)

Editing `waf.yaml` or pushing a new value to
`/aegis/config/waf` in etcd triggers atomic reloads of the
following surfaces **without restarting the proxy**:

| Surface | Reload latency | Audit event |
|---|---|---|
| `cfg.routes` | ~100 ms (file) / ~5 s (etcd) | `config_reload`, `routes_reload_failed` (validation error keeps live table) |
| `cfg.detectors` (base mask + per-tier overrides) | same | `config_reload`, `compliance_clamp_applied` (when `cfg.compliance.modes` forces a class back on) |
| `cfg.rate_limit.buckets[0]` | same | `rate_limit_reloaded` (per-IP timestamps preserved) |
| `cfg.tls.certificates` | same; in-flight handshakes finish on old store | `tls_reloaded`, `tls_reload_failed` |
| `cfg.compliance.modes` | same | `compliance_clamp_applied` |

What's still boot-only by design:

- `cfg.listeners` — tokio binds at boot, no API to unbind
- `cfg.runtime` — tokio worker count is `Builder::new_multi_thread()`-time
- `cfg.upstreams` — hot-swap is via the audit-mutated PUT path (CC-T1.1.b's `PoolRegistry`); cfg-driven hot-reload of upstreams is a small follow-up

## Crate Responsibilities

| Crate | Scope |
|---|---|
| **aegis-proxy** | TLS termination, HTTP/1.1+2+3, WebSocket, gRPC, routing trie (ArcSwap-backed for hot-reload), upstream pools (5 LB strategies + `PoolRegistry`), circuit breakers, per-route quotas, canary/shadow, retries, caching, state backends (in-memory + Redis), service discovery, ACME, OCSP stapling, **etcd config source**, **file + etcd cfg-reload watchers**, OTel hot-path instrumentation |
| **aegis-security** | Rule engine (AST + parser + evaluator + hot reload), rate limiters (sliding window + token bucket, **ArcSwap-backed for hot-reload**), DDoS detection, 7 OWASP detectors with `waf_detector_hits_total{class}` Prometheus counter, JA4/JA3 fingerprinting, HTTP/2 fingerprint, composite device ID, risk scoring with decay, challenge ladder (JS + CAPTCHA + block), bot classifier, threat intel feeds, DLP (patterns + FPE), OpenAPI/GraphQL enforcement, JWT/OAuth validation, HMAC signing, ForwardAuth |
| **aegis-control** | Prometheus metrics (request decisions / detector hits / state-backend ops / audit events / upstream gauges), health probes (live / ready / startup with `?strict=1` leader gate + `/admin/drain`), Aegis WAF Console (12-page React 18 SPA — DD-T0..T8 + CI-T1..T12 + CC-T1..T3) + real `/dashboard/sse`, W3C Trace Context, access logs, **durable audit chain** (NDJSON daily-rotation + retention TTL), 8 SIEM sinks, witness export, admin auth (argon2id / HMAC sessions / CSRF / rate limit / lockout / TOTP / mTLS policy), compliance profiles, data residency + retention + erasure, GitOps loader, SLO/SLI engine + multi-burn alerts + VipTalk delivery, audit-mutation pipeline (rule + mode + receiver + upstream + risk thresholds + detector mask CRUD), `/api/config/version` for hot-reload visibility, **persistent detector mask** (DURABLE-T2 — atomic save + boot rehydrate + compliance re-check), interop contract (`X-WAF-*` headers + `/__waf_control/*`), **mTLS read-only console** (T6 — identity tracker + CA bundle parser + 4 GET endpoints) |
| **aegis-core** | Shared types (`WafConfig`, `AuditEvent`, `ReadinessSignal`, `ClientIdentity`), traits (`SecurityPipeline`, `StateBackend`), config loading + validation, error types, tier classification |
| **aegis-bin** | `waf` binary — CLI dispatch (`run`/`validate`/`audit verify`/`admin set-password`/`admin enroll-totp`/`snapshot`/`restore`), tokio runtime build (workers / blocking / stack / cpu-affinity), **OTel OTLP exporter init** (`--features otel`), **ConfigSource selection** (file vs etcd) |

## Security Features

- **OWASP Top 10**: SQLi, XSS, path traversal, SSRF, header
  injection, body abuse, recon detection — every class
  emits to `waf_detector_hits_total{class}` for Grafana
- **DDoS Protection**: Per-IP burst detection, cluster spike
  correlation, sliding window + token bucket rate limiting,
  hot-reloadable budget via `cfg.rate_limit.buckets[0]`
- **Bot Management**: JA4/JA3 TLS fingerprinting, HTTP/2
  fingerprint, behavioral analysis, challenge ladder
- **API Security**: OpenAPI schema enforcement, GraphQL
  depth/complexity guards, JWT validation, HMAC signing
- **Data Protection**: DLP pattern matching, format-preserving
  encryption (AES-FF1), PII pseudonymization
- **Compliance**: FIPS 140-2, PCI-DSS (TLS ≥ 1.2 + audit
  retention ≥ 90d), SOC 2, GDPR (right to erasure), HIPAA
  (PHI-safe mode). The compliance clamp re-runs on every
  detector-mask change AND on cfg hot-reload — operators
  can't accidentally disable a PCI-pinned class.
- **Audit**: Tamper-evident SHA-256 hash chain with **durable
  NDJSON sink** (daily rotation + retention TTL), 8 SIEM sink
  formats, witness export, chain verification CLI

## Admin Authentication

The admin dashboard uses a defense-in-depth authentication
stack:

1. **IP Allowlist** — reject connections before HTTP parsing
2. **mTLS** — optional client certificate. Schema + identity
   types live (MTLS-T1+T6); rustls inbound wiring (T2) deferred
   behind the proxy refactor.
3. **Password** — argon2id with constant-time unknown-user path
4. **TOTP** — RFC 6238 with recovery codes
5. **HMAC Session Cookie** — `HttpOnly; Secure; SameSite=Strict`
6. **CSRF** — double-submit cookie pattern on every mutation
   endpoint
7. **Rate Limiting** — per-IP + per-user with exponential
   backoff + lockout

## Observability

| Surface | Endpoint / Tool |
|---|---|
| Prometheus metrics | `:9100/metrics` (data) + `:9443/metrics` (admin) |
| OTel traces | `cfg.observability.otel.endpoint` (e.g. `http://jaeger:4317`); enable with `--features otel` |
| Grafana dashboards | 3 file-provisioned: WAF Overview, Redis, Runtime |
| Audit chain | `/api/audit/since?cursor=N&limit=M&ip=…&rule_id=…&from=…&to=…` |
| Live Feed (SSE) | `/dashboard/sse` (real audit-bus events) |
| Identity tracker (mTLS) | `/api/mtls/connections`, `/api/mtls/failures`, `/api/mtls/ca-summary` |
| Status / cluster | `/api/about`, `/api/cluster`, `/api/runtime`, `/api/loadmode`, `/api/slo`, `/api/certs`, `/api/gitops/status` |
| Dashboard | `/dashboard/` (12 pages, React 18 SPA, 178 KB bundle, CSP `script-src 'self'`) |

## Testing

```sh
# Per-crate
cargo test -p aegis-control
cargo test -p aegis-proxy --features etcd

# Full workspace
cargo test --workspace

# Clippy (required: zero warnings on libs)
cargo clippy --workspace --features etcd --lib -- -D warnings

# API smoke (curl + jq)
AEGIS_ADMIN=http://127.0.0.1:9443 \
ADMIN_USER=admin ADMIN_PASS=aegis-test-1234 \
  bash tests/api/openapi-shape.sh

# Round-1 acceptance
bash tests/dashboard/round1-acceptance.sh

# k6 load
WAF_TARGET=http://127.0.0.1:8080 k6 run tests/load/baseline.js

# Nuclei security scan
nuclei -u http://127.0.0.1:8080/ -severity critical,high \
  -tags sqli,xss,traversal -duc

# Per-page screenshots (Playwright)
node tests/dashboard/capture-screenshots.mjs \
  --admin=http://127.0.0.1:9443 \
  --user=admin --pass='aegis-test-1234' \
  --out=./screenshots
```

## Documentation

| Document | Purpose |
|----------|---------|
| [`docs/operator/soc-runbook.md`](docs/operator/soc-runbook.md) | **SOC team operations runbook** — config → build → deploy → login → test → monitor, plus incident playbooks |
| [`docs/operator/cli.md`](docs/operator/cli.md) | Authoritative CLI reference |
| [`docs/operator/usage.md`](docs/operator/usage.md) | Day-1 bring-up + day-2 operations guide |
| [`docs/control-plane/api.openapi.yaml`](docs/control-plane/api.openapi.yaml) | **OpenAPI 3.0.3 contract** for the admin API (37 paths, 52 schemas) — generate clients with `openapi-generator-cli` |
| [`docs/control-plane/enterprise/`](docs/control-plane/enterprise/) | Aegis WAF Console design spec |
| [`docs/security/mtls.md`](docs/security/mtls.md) | mTLS deployment story (queued — lands with MTLS-T2) |
| [`docs/operator/benchmark-mode.md`](docs/operator/benchmark-mode.md) | Benchmark mode (gated, opt-in `X-Aegis-*` diagnostics) |
| [`deploy/GUIDE.md`](deploy/GUIDE.md) | Deployment guide (dev → staging → production) |
| [`deploy/README.md`](deploy/README.md) | Dev infrastructure quick start (docker-compose dev stack + observability stack) |
| [`deploy/etcd/README.md`](deploy/etcd/README.md) | etcd key layout + bootstrap + ETCD-T1 config-from-etcd guide |
| [`Architecture.md`](Architecture.md) | System design and decisions |
| [`Requirement.md`](Requirement.md) | Functional and non-functional requirements |
| [`Implement-Progress.md`](Implement-Progress.md) | Living implementation snapshot — Last Completed + Status + Recent History + Next Task |
| [`docs/progress/completed-tasks-log.md`](docs/progress/completed-tasks-log.md) | Append-only ledger of every closed task |

## License

TBD.
