# Aegis-Gate

A production-grade **Web Application Firewall** and security gateway written in Rust. Aegis-Gate sits in front of arbitrary HTTP/HTTPS backends as a full reverse proxy, inspecting every request and response through a tiered security pipeline before traffic reaches the application.

Targeted at enterprise environments (fintech, healthcare, public sector) with high availability, multi-tenancy, compliance, and observability demands comparable to F5 BIG-IP ASM, Imperva, Akamai Kona, and Cloudflare Enterprise.

> **For AI Assistants** — read `Implement-Progress.md` and `plans/plan.md` before writing any code.

## Status

**All three milestones are complete.**

| Milestone | Crate | Tests | Description |
|-----------|-------|-------|-------------|
| **M1** Data Plane | `aegis-proxy` | ✅ | TLS, HTTP/2, WebSocket, gRPC, routing, upstream pools, circuit breakers, rate-limiting quotas, canary, retries, caching, state backends, service discovery, hot reload |
| **M2** Security Pipeline | `aegis-security` | ✅ | Rule engine (AST + evaluator), OWASP detectors (SQLi, XSS, path traversal, SSRF, etc.), risk scoring, JA4/JA3 fingerprinting, bot classification, challenge ladder, DLP, JWT/OAuth, OpenAPI enforcement, GraphQL guard, FPE |
| **M3** Control Plane | `aegis-control` | ✅ 368 | Prometheus metrics, health probes, dashboard + SSE, tracing, access logs, audit hash chain, 8 SIEM sinks, admin auth (argon2id + HMAC + CSRF + TOTP + mTLS), compliance (FIPS/PCI/SOC2/GDPR/HIPAA), GitOps loader, SLO alerting |

## Quick Start

```sh
# 1. Build
cargo build --workspace --release

# 2. Start infrastructure (etcd, Prometheus, Jaeger, Redis, httpbin)
docker compose -f deploy/docker-compose.dev.yml up -d

# 3. Validate config
./target/release/waf validate --config config/waf.yaml

# 4. Run the gateway
./target/release/waf run --config config/waf.yaml
```

See [`docs/cli.md`](docs/cli.md) for the full CLI reference and [`deploy/GUIDE.md`](deploy/GUIDE.md) for deployment instructions.

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
├── plans/                   # Implementation plans per crate
│   ├── plan.md              # Shared types, traits, boot sequence, AI guide
│   ├── proxy.md             # M1: aegis-proxy tasks
│   ├── security.md          # M2: aegis-security tasks
│   └── control.md           # M3: aegis-control tasks
├── docs/                    # Per-feature specifications (~55 files)
│   ├── README.md            # Feature index + ownership map
│   ├── cli.md               # Authoritative `waf` CLI reference
│   ├── USAGE.md             # Operations & usage guide
│   └── ...
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
| **aegis-control** | Prometheus metrics, health probes (live/ready/startup), dashboard (HTML + SSE), W3C Trace Context, access logs (combined/JSON/template), audit hash chain (SHA-256), chain verification, 8 SIEM sinks (JSONL/syslog/CEF/LEEF/OCSF/Splunk HEC/ECS/Kafka), witness export, admin auth (argon2id/HMAC sessions/CSRF/rate limit/lockout/TOTP/mTLS), compliance profiles (FIPS/PCI-DSS/SOC2/GDPR/HIPAA), data residency + retention + erasure, GitOps loader, SLO/SLI engine with multi-burn alerting |
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
| [`docs/cli.md`](docs/cli.md) | Authoritative CLI reference |
| [`docs/USAGE.md`](docs/USAGE.md) | Operations and usage guide |
| [`deploy/GUIDE.md`](deploy/GUIDE.md) | Deployment guide (dev → staging → production) |
| [`deploy/README.md`](deploy/README.md) | Dev infrastructure quick start |
| [`Architecture.md`](Architecture.md) | System design and decisions |
| [`Requirement.md`](Requirement.md) | Functional and non-functional requirements |

## License

TBD.
