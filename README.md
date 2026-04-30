# Aegis-Gate

A production-grade **Web Application Firewall** and security gateway written in Rust. Aegis-Gate sits in front of arbitrary HTTP/HTTPS backends as a full reverse proxy, inspecting every request and response through a tiered security pipeline before traffic reaches the application.

Targeted at enterprise environments (fintech, healthcare, public sector) with high availability, multi-tenancy, compliance, and observability demands comparable to F5 BIG-IP ASM, Imperva, Akamai Kona, and Cloudflare Enterprise.

> **For AI Assistants** — read `Implement-Progress.md` and `plans/plan.md` before writing any code.

## Status

**Core M1–M3, the Aegis WAF Console redesign, HA cluster, and the
external interop contract are all shipped.** Phase B is the only
active track, and within Phase B only **B6 (production packaging)**
remains — `B6-T1` (production Dockerfile) is the in-flight task.

**Workspace test count: 2,197.** Workspace `cargo clippy -- -D warnings`
clean (modulo two pre-existing rust 1.94 lints in untouched files).

| Milestone | Crate | Description |
|-----------|-------|-------------|
| **M1** Data Plane | `aegis-proxy` | TLS (rustls), HTTP/1.1, HTTP/2, HTTP/3 (`http3` feature), WebSocket, gRPC, routing trie, upstream pools (5 LB strategies + pooled keep-alive HTTP/1.1 + rustls connector for HTTPS), circuit breakers, rate-limiting quotas, canary, retries, caching, state backends (in-memory + Redis), service discovery (Consul / etcd / k8s), hot reload, ACME, OCSP stapling |
| **M2** Security Pipeline | `aegis-security` | Rule engine (AST + evaluator + hot reload), OWASP detectors, risk scoring, JA4/JA3 fingerprinting, HTTP/2 fingerprint, bot classification, challenge ladder, DLP + FPE, JWT/OAuth, OpenAPI enforcement, GraphQL guard, STIX/TAXII threat intel (`taxii` feature), GeoIP MaxMind reader (`geoip` feature), ICAP RFC 3507 client |
| **M3** Control Plane | `aegis-control` | Prometheus metrics, health probes, audit hash chain (SHA-256), 8 SIEM sinks, admin auth (argon2id + HMAC session + CSRF + TOTP + mTLS), compliance (FIPS/PCI/SOC2/GDPR/HIPAA), GitOps loader (built-in `git` poll-and-pull), SLO alerting + multi-burn windows + VipTalk delivery (`alerts` feature), audit-mutation pipeline (rule CRUD lands here), `/api/config/version` for hot-reload visibility |
| **HA cluster** | `aegis-proxy` + `aegis-control` | Redis-backed cluster shared rate-limits + leader lease; `/admin/drain` + `?strict=1` readiness; HAProxy reference deploy in `deploy/haproxy/`. Run-05 measured 9.5 k RPS via VIP and 99.93 % hard / 100 % graceful failover. (Plan: [`plans/cluster-ingress-lb.md`](plans/cluster-ingress-lb.md), `HA-T<n>`.) |
| **Interop contract** | `aegis-control::interop` + `aegis-proxy` | Always-on `X-WAF-*` response headers + `/__waf_control/*` (capabilities, mode, reset_state, rule_id_present), audit-chained mode toggles, JSONL audit sink. Run-08 self-gate: 27/27 contract checks green at ~30 µs p95 overhead. (Plan: [`plans/interop-contract.md`](plans/interop-contract.md), `IT-T<n>`.) |
| **Aegis WAF Console (DD-T0..T8)** | `aegis-control` (assets + api) | Pre-compiled React 18 SPA (`crates/aegis-control/assets/dashboard/app.js`, ~170 KB) + 12 sidebar pages + 17 real `/api/*` hooks + Rule CRUD with hot-reload toast. CSP `script-src 'self'` (no CDN, no `unsafe-eval`). Closes the Hackathon WAF-FE §2 contract — real-time monitor ≤ 5 s, hot-reload ≤ 10 s, ≤ 5 clicks for create-rule, audit search ≤ 30 s. See [`plans/dashboard-redesign.md`](plans/dashboard-redesign.md). |

**Open carry-overs** (tracked in `Implement-Progress.md`):

- `B6-T1` production Dockerfile (multi-stage distroless, signed image).
- `B6-T2..T5` Helm chart, GitHub Actions CI, HSM resolver, fd-pass binary handover.
- Auto-stamping `Alt-Svc` on every TLS response (helper exists, listener wire-up pending).
- Full benchmark-mode plan (B-T1..B-T6) — IP allowlist, HMAC tokens, per-detector timing, dashboard panel — beyond the core slice that landed as B5-T2.

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
FEATURES="redis alerts geoip taxii http3" make build     # custom feature set
make test                                                # cargo test --workspace
```

Full step-by-step + tuning + admin auth: [`QUICKSTART.md`](QUICKSTART.md).
Production deployment: [`deploy/GUIDE.md`](deploy/GUIDE.md).
YAML reference: [`config/README.md`](config/README.md).

### Three-layer scaling

| Layer | Knob | Doc |
|---|---|---|
| 1 — In-node | `runtime.workers`, `cpu_affinity` (tokio worker threads) | [`docs/operations/runtime-tuning.md`](docs/operations/runtime-tuning.md) |
| 2 — Across nodes | `node.id` + an LB in front of N peers | [`docs/operations/ha-clustering.md`](docs/operations/ha-clustering.md) |
| 3 — State | `state.backend: redis` (counters, leases, block lists) | [`Architecture.md` §12](Architecture.md) |

## CLI Overview

```
waf run       --config <path>         Start the WAF gateway
waf validate  --config <path>         Dry-run validation + compliance check
waf audit     verify --from <path>    Verify audit chain integrity
waf admin     set-password            Hash admin password (argon2id)
waf admin     enroll-totp             Generate TOTP secret + recovery codes
waf version                           Show version
waf help                              Show help
```

## Repository Layout

```
aegis-gate/
├── README.md                # This file
├── Requirement.md           # Functional + non-functional requirements
├── Architecture.md          # System architecture and design decisions
├── Implement-Progress.md    # Implementation progress log
├── plans/                   # Implementation plans per track
│   ├── README.md            # Status board for every track
│   ├── plan.md              # AI assistant guide + protocol
│   ├── implementation-matrix.md  # doc-by-doc Implemented/Partial/Designed
│   ├── phase-b/             # ACTIVE — B1..B6 (B6 only remains)
│   ├── proxy.md             # M1 (closed)
│   ├── security.md          # M2 (closed)
│   ├── control.md           # M3 (closed)
│   ├── dashboard-redesign.md       # DD-T0..T8 (closed) — Aegis WAF Console
│   ├── cluster-ingress-lb.md       # HA-T1..T5 (closed)
│   ├── interop-contract.md         # IT-T1..T6 (closed)
│   ├── interop-dry-run.md          # DR-T1..T7 (closed)
│   ├── post-run-08.md              # AF-T1, HP-T1, TLS-T1 (closed)
│   ├── post-k6-followup.md         # P1..P8 + F-T1..F-T10 (closed)
│   ├── benchmark-mode.md           # folded into B5-T2
│   └── archive/            # superseded plans, kept for history
│       ├── dashboard-enterprise/        # D-M1..D-M6 superseded by DD
│       └── dashboard-redesign-early-brief/  # M0..M10 brief superseded by DD
├── docs/                    # Per-feature specifications (~60 files, foldered)
│   ├── README.md            # Taxonomy index + ownership map
│   ├── operator/            # usage.md, cli.md, benchmark-mode.md
│   ├── architecture/        # protocols
│   ├── data-plane/          # M1 — proxy, routing, TLS, traffic mgmt
│   ├── security/            # M2 — rules, detectors, risk, challenge
│   │   └── detectors/       #   per-attack-class detector specs
│   ├── control-plane/       # M3 — dashboard, admin API, hot-reload
│   │   └── enterprise/      #   enterprise dashboard SPA spec
│   ├── observability/       # metrics, audit, SIEM, SLO
│   ├── operations/          # HA, compliance, residency, DR
│   └── future/              # Phase B intake + deferred designs
├── deploy/                  # Docker Compose + deployment guide
│   ├── GUIDE.md             # Deployment guide (dev, staging, production)
│   ├── docker-compose.dev.yml
│   ├── docker-compose.test.yml
│   └── ...
├── tests/                   # Out-of-process load and security tests
│   ├── load/                # k6 scripts
│   └── security/            # Attack corpora + runners
└── crates/
    ├── aegis-core/          # Shared types, traits, config schema
    ├── aegis-proxy/         # Data plane (TLS, routing, upstreams, state)
    ├── aegis-security/      # Security pipeline (rules, detectors, risk)
    ├── aegis-control/       # Control plane (dashboard, auth, audit, compliance)
    └── aegis-bin/           # `waf` binary — wires all crates together
```

## Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │                aegis-bin (waf)                │
                    │       CLI dispatch + crate wiring             │
                    └──────┬──────────┬──────────────┬─────────────┘
                           │          │              │
              ┌────────────▼──┐  ┌────▼──────────┐  ┌▼───────────────┐
              │  aegis-proxy  │  │ aegis-security │  │ aegis-control  │
              │  (data plane) │  │  (sec pipeline)│  │ (control plane)│
              │               │  │                │  │                │
              │ • TLS/HTTP/2  │  │ • Rule engine  │  │ • Dashboard    │
              │ • Routing     │  │ • OWASP detect │  │ • Auth (argon2)│
              │ • Upstreams   │  │ • Risk scoring │  │ • Audit chain  │
              │ • Load shed   │  │ • DLP/FPE      │  │ • SIEM sinks   │
              │ • State       │  │ • Bot classify │  │ • Compliance   │
              │ • Caching     │  │ • API security │  │ • GitOps       │
              └───────┬───────┘  └───────┬────────┘  │ • SLO alerts   │
                      │                  │           └────────┬───────┘
                      └──────────┬───────┘                    │
                            ┌────▼────┐                       │
                            │aegis-core│◄──────────────────────┘
                            │ (types) │
                            └─────────┘
```

## Crate Responsibilities

| Crate | Scope |
|-------|-------|
| **aegis-proxy** | TLS termination, HTTP/2, WebSocket, gRPC, routing trie, upstream pools (5 LB strategies), circuit breakers, per-route quotas, canary/shadow, retries, caching, state backends (in-memory + Redis), service discovery, hot reload, ACME, OCSP stapling |
| **aegis-security** | Rule engine (AST + parser + evaluator + hot reload), rate limiters (sliding window + token bucket), DDoS detection, 7 OWASP detectors, JA4/JA3 fingerprinting, HTTP/2 fingerprint, composite device ID, risk scoring with decay, challenge ladder (JS + CAPTCHA + block), bot classifier, threat intel feeds, DLP (patterns + FPE), OpenAPI/GraphQL enforcement, JWT/OAuth validation, HMAC signing, ForwardAuth |
| **aegis-control** | Prometheus metrics, health probes (live/ready/startup with `?strict=1` leader gate + `/admin/drain` for graceful failover), Aegis WAF Console (12-page React 18 SPA — DD-T0..T8) + real `/dashboard/sse` streaming, W3C Trace Context, access logs (combined/JSON/template), audit hash chain (SHA-256) with mutation pipeline (rule CRUD), chain verification, 8 SIEM sinks (JSONL/syslog/CEF/LEEF/OCSF/Splunk HEC/ECS/Kafka), witness export, admin auth (argon2id/HMAC sessions/CSRF/rate limit/lockout/TOTP/mTLS), compliance profiles (FIPS/PCI-DSS/SOC2/GDPR/HIPAA), data residency + retention + erasure, GitOps loader (`B3-T1` built-in git driver), SLO/SLI engine with multi-burn alerting + VipTalk delivery, `/api/config/version` for hot-reload visibility, interop contract surface (`X-WAF-*` headers + `/__waf_control/*`), 17 real `/api/*` data hooks consumed by the dashboard (stats / timeseries / upstreams / attacks / audit / about / analytics / rules / tiers / blacklist / whitelist / cluster / slo / certs / alerts / gitops / runtime) |
| **aegis-core** | Shared types (`WafConfig`, `AuditEvent`, `ReadinessSignal`), traits (`SecurityPipeline`, `StateBackend`), config loading, error types, tier classification |
| **aegis-bin** | `waf` binary — CLI dispatch, crate wiring, `run`/`validate`/`audit verify`/`admin set-password`/`admin enroll-totp` |

## Security Features

- **OWASP Top 10**: SQLi, XSS, path traversal, SSRF, header injection, body abuse, recon detection
- **DDoS Protection**: Per-IP burst detection, cluster spike correlation, sliding window + token bucket rate limiting
- **Bot Management**: JA4/JA3 TLS fingerprinting, HTTP/2 fingerprint, behavioral analysis, challenge ladder
- **API Security**: OpenAPI schema enforcement, GraphQL depth/complexity guards, JWT validation, HMAC signing
- **Data Protection**: DLP pattern matching, format-preserving encryption (AES-FF1), PII pseudonymization
- **Compliance**: FIPS 140-2, PCI-DSS, SOC 2, GDPR (right to erasure), HIPAA (PHI-safe mode)
- **Audit**: Tamper-evident SHA-256 hash chain, 8 SIEM sink formats, witness export, chain verification CLI

## Admin Authentication

The admin dashboard uses a defense-in-depth authentication stack:

1. **IP Allowlist** — reject connections before HTTP parsing
2. **mTLS** — optional client certificate (bypasses password)
3. **Password** — argon2id with constant-time unknown-user path
4. **TOTP** — RFC 6238 with recovery codes
5. **HMAC Session Cookie** — `HttpOnly; Secure; SameSite=Strict`
6. **CSRF** — double-submit cookie pattern
7. **Rate Limiting** — per-IP + per-user with exponential backoff + lockout

## Testing

```sh
# Run all tests for a specific crate
cargo test -p aegis-control

# Run all workspace tests
cargo test --workspace

# Clippy (required: zero warnings)
cargo clippy --workspace -- -D warnings
```

## Documentation

| Document | Purpose |
|----------|---------|
| [`docs/operator/soc-runbook.md`](docs/operator/soc-runbook.md) | **SOC team operations runbook** — config → build → deploy → login → test → monitor, plus incident playbooks |
| [`docs/operator/cli.md`](docs/operator/cli.md) | Authoritative CLI reference |
| [`docs/operator/usage.md`](docs/operator/usage.md) | Day-1 bring-up + day-2 operations guide |
| [`docs/control-plane/api.openapi.yaml`](docs/control-plane/api.openapi.yaml) | **OpenAPI 3.0.3 contract** for the admin API — generate clients with `openapi-generator-cli`, render with `swagger-ui` or `redocly preview-docs` |
| [`docs/control-plane/enterprise/`](docs/control-plane/enterprise/) | Aegis WAF Console design spec (layout, pages, API, accessibility, security) |
| [`docs/operator/benchmark-mode.md`](docs/operator/benchmark-mode.md) | Benchmark mode design (gated, opt-in `X-Aegis-*` diagnostics) |
| [`deploy/GUIDE.md`](deploy/GUIDE.md) | Deployment guide (dev → staging → production) |
| [`deploy/README.md`](deploy/README.md) | Dev infrastructure quick start |
| [`Architecture.md`](Architecture.md) | System design and decisions |
| [`Requirement.md`](Requirement.md) | Functional and non-functional requirements |

## License

TBD.
