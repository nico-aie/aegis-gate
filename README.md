# Aegis-Gate

A production-grade **Web Application Firewall** and security
gateway written in Rust. Aegis-Gate sits in front of arbitrary
HTTP/HTTPS/WebSocket/gRPC backends as a full reverse proxy,
inspecting every request through a tiered security pipeline
before traffic reaches the application.

Designed for operators that need F5 BIG-IP / Imperva / Akamai
Kona / Cloudflare Enterprise-class capability without the
licensing — fintech, healthcare, public sector. Single-binary,
distroless image, hot-reloadable config, audit-chained mutations,
SOC-first dashboard.

> **For AI assistants** — read `Implement-Progress.md` and
> `plans/plan.md` before writing any code.

---

## What it does

### Data plane
- **Protocols** — HTTP/1.1, HTTP/2, HTTP/3 (`http3` feature),
  WebSocket bridge (auto-detected on http/https/auto schemes),
  gRPC, raw TCP tunneling via `CONNECT`.
- **Routing** — host + path + method matching trie with
  regex / glob / prefix / exact match, hot-swappable from YAML
  or etcd.
- **Upstreams** — pool registry with 5 LB strategies
  (`round_robin`, `weighted_round_robin`, `least_conn`,
  `consistent_hash`, `p2c`), pooled HTTP/1.1 keep-alive,
  rustls connector for HTTPS, **per-member `host_header`
  override + SNI pinning** for multi-vhost backends, active
  health checks + per-member circuit breaker, audit-mutated
  hot-swap (no restart).
- **TLS** — rustls 0.23 inbound, ACME issuance + renewal,
  OCSP stapling, hot-reloadable cert store, optional mTLS
  with SAN allow-list and audit-chained CA bundle hot-swap.
- **Performance** — sustained
  4 891 RPS k6 / 6 392 RPS WAF-internal at p99 1.03 ms on the
  `prod-balanced` profile; baseline 37 600 req/s at median 60 µs.

### Security pipeline
- **OWASP detectors** — SQLi, XSS, path traversal, SSRF,
  header injection, body abuse (oversize / depth / decompression),
  XXE, mass-assignment, recon / scanner detection, auth
  brute-force. Per-tier on/off, compliance-clamped, hot-reloadable.
  Per-detector docs in [`docs/security/detectors/`](docs/security/detectors/).
- **Rule engine** — AST + parser + evaluator with hot-reload,
  custom rule definitions in YAML.
- **AI detector** (`ai` feature) — operator-supplied ONNX model
  loaded via `ort` 2.0-rc.12, 26-feature extractor, binary
  attack-vs-normal verdict, hybrid `mode: observe | enforce`
  for safe rollouts. Mean inference 357 µs, +0.1 ms p95 when
  chained behind the regex detectors. Per-detector doc:
  [`docs/security/detectors/ai-detector.md`](docs/security/detectors/ai-detector.md).
- **Risk scoring** — composite IP + JA4/JA3 + HTTP/2 fingerprint
  + bot classification + threat-intel feed lookup, with
  exponential decay and trust recovery.
- **Bot management** — JA4/JA3 TLS fingerprinting, HTTP/2
  fingerprint, behavioral analysis, challenge ladder
  (JS / CAPTCHA / block).
- **API security** — OpenAPI schema enforcement, GraphQL
  depth/complexity guards, JWT / OAuth validation, HMAC
  signing, ForwardAuth.
- **DLP** — pattern matching + format-preserving encryption
  (AES-FF1) + PII pseudonymisation.
- **Threat intel** — STIX/TAXII auto-fetch (`taxii` feature),
  in-memory + file-loaded indicators, MaxMind GeoIP for
  country / ASN enrichment (`geoip` feature).

### Control plane (admin / dashboard)
- **Aegis WAF Console** — pre-compiled React 18 SPA at
  `/dashboard/`, CSP `script-src 'self'`, no CDN, no
  `unsafe-eval`. 17+ pages — Overview, Live Feed, Investigation,
  Top Attackers, Threat Intel, Rules, Detectors, Access Lists,
  Routing & Upstreams, Compliance, Performance, Health & SLOs,
  Audit Trail, Scaling, Settings, Reports, Help. Error-bounded
  per-page so a single component crash never blanks the shell.
- **Auth** — defense-in-depth: IP allow-list → optional mTLS
  → argon2id password → TOTP (RFC 6238) → HMAC session cookie
  (`HttpOnly; Secure; SameSite=Strict`) → CSRF double-submit
  → per-IP / per-user rate limit + lockout.
- **Audit chain** — SHA-256 hash-chained NDJSON sink with
  daily rotation + retention TTL, 8 SIEM sink formats,
  tamper-evident, witness export, CLI verifier.
- **Hot-reload** — six surfaces reload from disk (notify
  watcher, ~100 ms) or etcd (REST poll, ~5 s) without a
  restart: `cfg.routes`, `cfg.detectors`, `cfg.rate_limit`,
  `cfg.tls.certificates`, `cfg.compliance.modes`,
  `cfg.upstreams` (via the audit-mutated PUT path).
- **Audit-mutated CRUD** — every config change goes through
  the audit chain + CSRF gate + capability check; rule edits,
  mode toggles, alert receivers, upstream pools, risk
  thresholds, detector mask all hot-swap with a visible
  `config_reload` audit entry.
- **Compliance** — FIPS 140-2, PCI-DSS, SOC 2, GDPR, HIPAA
  profiles. The compliance clamp re-runs on every mask change
  and cfg reload — operators can't accidentally disable a
  pinned class.

### Observability
- **Prometheus metrics** — per-decision counters, per-stage
  request-duration histogram, per-route latency, per-detector
  hits, audit-event counter, upstream pool health gauges,
  WebSocket bridge counters, runtime gauges (workers, blocking
  pool, I/O fds).
- **OpenTelemetry** (`otel` feature) — OTLP gRPC exporter,
  `#[tracing::instrument]` on every hot-path span, Jaeger
  parent-child traces per request.
- **Grafana** — three file-provisioned dashboards (WAF
  Overview / Redis / Runtime).
- **Live Feed** — `/dashboard/sse` streams every audit event;
  proto pill on each row distinguishes `http` / `ws-open` /
  `ws-close` / `tcp-open` / `tcp-close` events.

### HA + scaling (three-layer model)
| Layer | Knob | Doc |
|---|---|---|
| 1 — In-node | `runtime.workers`, `cpu_affinity` (tokio worker threads, `affinity` feature) | [`docs/operations/runtime-tuning.md`](docs/operations/runtime-tuning.md) |
| 2 — Across nodes | `node.id` + an LB in front of N peers, Redis-shared rate-limit + leader lease | [`docs/operations/ha-clustering.md`](docs/operations/ha-clustering.md) |
| 3 — State | `state.backend: redis` (counters, leases, block lists) — same shape across dev / prod | [`Architecture.md` §12](Architecture.md) |

### Production deploy
- **Distroless multi-arch image** (amd64 + arm64), non-root,
  ~70 MB release / ~80 MB with all features.
- **Helm chart** at [`deploy/helm/aegis-gate`](deploy/helm/aegis-gate)
  — 3-replica StatefulSet, PodDisruptionBudget, anti-affinity
  per zone.
- **Binary handover via fd-passing** (FDP-T1..T6, drain
  refactor) — `kill -USR2 <pid>` hot-restarts the binary in
  place; in-flight requests finish on the parent, new
  requests land on the child, no dropped connections.
- **Service discovery** — Consul / etcd / Kubernetes
  EndpointSlice watchers for dynamic upstream membership.
- **Secrets** — `${secret:vault:...}` / AWS Secrets Manager /
  GCP Secret Manager / Azure Key Vault resolvers (one Cargo
  feature each).

---

## Quick Start

The operator path has four phases — **Build → Run → Test → Deploy**.

### 1 · Build

```sh
make setup        # one-shot: dev cert + release build
                  # (cold ~2 min, warm ~10 s)
```

Customise the feature set with `FEATURES=`:

```sh
FEATURES="redis geoip alerts taxii http3 etcd otel" make build
```

| Feature flag | Adds |
|---|---|
| `redis` | shared rate-limit + leader-lease state backend |
| `geoip` | MaxMind GeoLite2 reader (country / ASN enrichment + `kind: country` access-list) |
| `alerts` | VipTalk delivery for SLO + audit alerts |
| `taxii` | STIX/TAXII threat-intel auto-fetch |
| `http3` | QUIC listener (quinn + h3) |
| `etcd` | `AEGIS_CONFIG_SOURCE=etcd` boot path |
| `otel` | OpenTelemetry OTLP exporter |
| `ai` | ML-based detector (operator-supplied ONNX) |

Validate any config without booting:

```sh
make validate
make validate-all      # dev + 3 production profiles
```

### 2 · Run

```sh
make run-dev      # config/dev.yaml + Redis + mock upstream
make urls         # print every URL + log path
make logs         # tail audit chain + container logs
```

Listeners after boot: `:8080` (HTTP), `:8443` (HTTPS), `:9443`
(admin / dashboard / `/metrics`).

For real workloads pick a production profile:

| Target | Config | When |
|---|---|---|
| `make run-dev` | `config/dev.yaml` | Local dev (inline creds) |
| `make run` | `config/profiles/prod-balanced.yaml` | **Production default** |
| `make run-strict` | `config/profiles/prod-strict.yaml` | PCI / HIPAA / SOC2 / GDPR |
| `make run-throughput` | `config/profiles/prod-high-throughput.yaml` | CDN front-door, > 5 k RPS |

Decision tree: [`docs/operator/profiles.md`](docs/operator/profiles.md).

### 3 · Configure your upstream

This is the one config you'll always touch. **Recipe-driven
guide** with copy-paste blocks per protocol:
**[`docs/operator/upstream-cookbook.md`](docs/operator/upstream-cookbook.md)**.

Quick decision:

| Backend | Pick `connection.scheme:` | Note |
|---|---|---|
| Plain HTTP/1.1 | `http` | Auto-bridges WebSocket. |
| TLS-terminated HTTPS | `https` | Auto-bridges WSS. |
| Multi-vhost / public TLS | `https` + `host_header:` | Vhost name drives Host header AND TLS SNI. |
| HTTP/2 cleartext (h2c) | `h2c` | Service-mesh sidecars. |
| gRPC | `grpc` | Forces ALPN h2 only. |
| Raw TCP (SSH / custom) | `tcp` | Requires CONNECT method. |

Smallest possible config:

```yaml
# config/dev.yaml — replace the stub-pool block
upstreams:
  api-pool:
    members:
      - addr: "10.0.1.10:3001"
    lb: round_robin
    connection:
      scheme: http
```

Multi-vhost public-TLS backend (e.g. GitHub Pages):

```yaml
upstreams:
  github-pages:
    members:
      - addr: "185.199.108.153:443"
        host_header: "your-org.github.io"
    connection:
      scheme: https
```

Same set of fields is editable from the dashboard's
**Routing & Upstreams** page — including the new Host-header
column for vhost / SNI override and the **Protocol matrix**
card that maps each scheme to which protocols it carries
(HTTP/1.1, HTTP/2, WebSocket, gRPC, raw TCP).

Reference for every field: [`docs/data-plane/upstream-pools.md`](docs/data-plane/upstream-pools.md).

Boot from etcd instead of a file (`--features etcd`):

```sh
AEGIS_CONFIG_SOURCE=etcd \
AEGIS_ETCD_ENDPOINTS=http://etcd-cluster:2379 \
  ./target/release/waf run
```

Same `WafConfig::validate` + same hot-reload watcher path. Key
layout: [`deploy/etcd/README.md`](deploy/etcd/README.md).

### 4 · Test

Three layers — automated, contract, hand-driven.

```sh
# Automated (~1 500 unit tests, zero warnings)
make test
make clippy

# Contract / smoke (assumes `make run-dev` is up)
make smoke              # curl data + admin healthz
make protocols-test     # h1 / h2 / h3 / WS / gRPC
make openapi-test       # OpenAPI shape contract
make ci-local           # everything GitHub Actions runs

# Hand-driven validation of recently-shipped fixes
export ADMIN_USER=admin ADMIN_PASS=admin
export AEGIS_ADMIN=http://127.0.0.1:9443 AEGIS_DATA=http://127.0.0.1:8080
tests/manual/access-list-roundtrip.sh
tests/manual/csrf-cookie-flow.sh
tests/manual/fake-country-ips.sh
tests/manual/websocket-bridge.sh
tests/manual/viptalk-alert-test.sh
```

**Stress + load + security:**

```sh
make mock-load             # ~50 RPS legit + crawler + attacker mix
make mock-load-attacks     # attack-only flood (drives detector hits)
make mock-load-mix         # ~5 k RPS — stress the WAF
bash tests/hackathon/run.sh
k6 run tests/load/baseline.js
nuclei -u http://127.0.0.1:8080/ -tags sqli,xss,traversal -duc
```

**End-to-end QA via Claude Skill** —
[`skills/aegis-waf-tester/`](skills/aegis-waf-tester/) is a
self-contained Claude Skill that drives the WAF as a real QA
engineer (browser via Playwright + curl + structured findings).

```sh
cp -R skills/aegis-waf-tester ~/.claude/skills/
# Then in Claude Desktop:
# "Use the aegis-waf-tester skill in smoke mode"
```

### 5 · Deploy

```sh
# Multi-arch image
bash deploy/docker-build.sh --tag aegis-gate:0.x

# Helm chart (3-replica HA)
helm upgrade --install aegis deploy/helm/aegis-gate \
  --set image.tag=0.x \
  --set redis.url=redis://prod-redis:6379

make helm-lint
make helm-render
```

Full walkthrough: [`deploy/GUIDE.md`](deploy/GUIDE.md).

---

## CLI

```
waf run       --config <path>         Start the WAF gateway
waf validate  --config <path>         Dry-run validation + compliance check
waf audit     verify --from <path>    Verify audit chain integrity
waf admin     set-password            Hash admin password (argon2id)
waf admin     enroll-totp             Generate TOTP secret + recovery codes
waf snapshot  --output <path>         Bundle effective config + rules into a JSON snapshot
waf restore   --from <path>           Restore config + rules from a snapshot (validates first)
waf version
waf help
```

---

## Documentation

| Topic | Doc |
|---|---|
| **Operator quick start** | [`QUICKSTART.md`](QUICKSTART.md) |
| **Upstream cookbook (per-protocol recipes)** | [`docs/operator/upstream-cookbook.md`](docs/operator/upstream-cookbook.md) |
| **Profile picker** | [`docs/operator/profiles.md`](docs/operator/profiles.md) |
| **SOC runbook** | [`docs/operator/soc-runbook.md`](docs/operator/soc-runbook.md) |
| **CLI reference** | [`docs/operator/cli.md`](docs/operator/cli.md) |
| **Detectors** (per-class behaviour + tags) | [`docs/security/detectors/README.md`](docs/security/detectors/README.md) |
| **Upstream pools (full schema)** | [`docs/data-plane/upstream-pools.md`](docs/data-plane/upstream-pools.md) |
| **Reverse proxy + tunneling** | [`docs/data-plane/reverse-proxy.md`](docs/data-plane/reverse-proxy.md) |
| **TLS termination + mTLS** | [`docs/data-plane/tls-termination.md`](docs/data-plane/tls-termination.md) |
| **API contract** (OpenAPI) | [`docs/control-plane/api.openapi.yaml`](docs/control-plane/api.openapi.yaml) |
| **Dashboard reference** (page inventory + REST/SSE) | [`docs/control-plane/enterprise/`](docs/control-plane/enterprise/) |
| **AI Detector** (perf, config, observability) | [`docs/security/detectors/ai-detector.md`](docs/security/detectors/ai-detector.md) |
| **HA clustering** | [`docs/operations/ha-clustering.md`](docs/operations/ha-clustering.md) |
| **Runtime tuning** | [`docs/operations/runtime-tuning.md`](docs/operations/runtime-tuning.md) |
| **Deployment guide** | [`deploy/GUIDE.md`](deploy/GUIDE.md) |
| **Architecture** | [`Architecture.md`](Architecture.md) |
| **Requirements** | [`Requirement.md`](Requirement.md) |
| **Implementation log** | [`Implement-Progress.md`](Implement-Progress.md) |
| **Plans (per track)** | [`plans/README.md`](plans/README.md) |

---

## Repository layout

```text
aegis-gate/
├── README.md / QUICKSTART.md / Architecture.md / Requirement.md
├── Implement-Progress.md          # Living implementation snapshot
├── Makefile
├── config/                        # YAML profiles
│   ├── dev.yaml
│   ├── prod.yaml
│   └── profiles/{prod-balanced,prod-strict,prod-high-throughput}.yaml
├── crates/
│   ├── aegis-core/                # Shared types, config schema, ClientIdentity
│   ├── aegis-proxy/               # Data plane (TLS, routing, upstreams, state)
│   ├── aegis-security/            # Security pipeline (rules, detectors, risk)
│   ├── aegis-control/             # Control plane (dashboard, auth, audit)
│   └── aegis-bin/                 # `waf` binary — CLI dispatch + crate wiring
├── docs/                          # Operator + per-feature documentation
├── deploy/                        # Docker / Helm / Grafana / etcd bootstrap
├── plans/                         # Implementation plans per track
├── skills/aegis-waf-tester/       # Claude Skill for end-to-end QA
└── tests/
    ├── api/        # curl + jq smoke (16 scripts)
    ├── manual/     # Hand-driven validation of shipped fixes
    ├── contract/   # v2.3 contract regression gate
    ├── cluster/    # HA cluster smoke
    ├── dashboard/  # Round-1 acceptance + Playwright screenshots
    ├── protocols/  # h1 / h2 / h3 / WS / gRPC mix
    ├── load/       # k6 scripts
    ├── security/   # corpus + nuclei + zap
    └── hackathon/  # 15-min mixed-traffic stress harness
```

---

## License

TBD.
