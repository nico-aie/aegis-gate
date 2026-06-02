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

> **For AI assistants** — start with [`AGENTS.md`](./AGENTS.md), then
> `Implement-Progress.md` and `plans/plan.md` before writing any code.

---

## What it does

### Data plane
- **Protocols** — HTTP/1.1, HTTP/2, HTTP/3 (`http3` feature),
  WebSocket bridge (auto-detected on http/https/auto schemes),
  gRPC, raw TCP tunneling via `CONNECT`.
- **Routing** — host + path + method matching trie with
  regex / glob / prefix / exact match, hot-swappable from YAML
  (and the cluster config plane).
- **Upstreams** — pool registry with 5 LB strategies
  (`round_robin`, `weighted_round_robin`, `least_conn`,
  `consistent_hash`, `p2c`), pooled HTTP/1.1 keep-alive,
  rustls connector for HTTPS, **per-member `host_header`
  override + SNI pinning** for multi-vhost backends,
  **hostname-addressed members (`addr: api.example.com:443`)
  resolved + multi-A expanded at config-load time, with
  background TTL-aware DNS refresh via `hickory-resolver`** so
  cloud LBs / K8s Services / Consul rotate without a restart,
  active health checks + per-member circuit breaker,
  audit-mutated hot-swap (no restart).
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
  brute-force, command injection (`$()`, `|cmd`, `/bin/sh`, etc.,
  including Log4Shell `${jndi:...}` at higher score), template
  injection (Jinja2 / Twig / SpEL / Freemarker / Velocity /
  Handlebars), NoSQL operator injection (`[$ne]`, `[$where]`,
  `{"$gt":...}`), open redirect (`?next=http://evil.com`,
  `?redirect_uri=javascript:…` with operator allowlist).
  Prototype pollution (`__proto__`, `constructor.prototype`)
  caught under the body-abuse class. Per-tier on/off,
  hot-reloadable.
  Per-detector docs in [`docs/security/detectors/`](docs/security/detectors/).
- **Rule engine** — AST + parser + evaluator with hot-reload,
  custom rule definitions in YAML.
- **AI detector** (`ai` feature) — operator-supplied ONNX model
  loaded via `ort` 2.0-rc.12, 26-feature extractor, binary
  attack-vs-normal verdict, hybrid `mode: observe | enforce`
  for safe rollouts. Mean inference 694 µs, +1.1 ms p95 / +2.3 ms
  p99 when chained behind the regex detectors (laptop hardware).
  Per-detector doc + p99 vs 5 ms target:
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
- **DDoS protection** (✅ **Implemented v1 single-node**)
  — request-flow gate (NOT a `Detector` trait impl) sitting
  alongside access-list / strike-block / rate-limit. Per-IP
  sliding-window burst gate + EWMA spike-mode ticker, wired
  into `aegis-proxy/src/data_plane.rs` from `cfg.ddos`. Secure-
  by-default: `enabled: true, observe_only: false`. Burst-exceed
  → HTTP 403 + `X-WAF-Action: block` per
  [`Hackathon_Doc/EN_waf_interop_contract_v2.3.md`](Hackathon_Doc/EN_waf_interop_contract_v2.3.md)
  §3.1 (volumetric abuse). Cluster-wide spike-mode broadcast
  across nodes deferred behind ha-clustering. Audit + plan:
  [`docs/security/ddos-protection.md`](docs/security/ddos-protection.md)
  and [`plans/archive/issue-fix/internal-audit-2026-05-09-ddos/`](./plans/archive/issue-fix/internal-audit-2026-05-09-ddos).

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
- **Hot-reload** — config reloads from disk (notify watcher,
  ~100 ms) without a restart, or fleet-wide via the cluster
  config plane (`config:waf:doc`): `cfg.routes`, `cfg.detectors`,
  `cfg.rate_limit`, `cfg.tls.certificates`, `cfg.compliance.modes`,
  `cfg.upstreams`, `cfg.rules`, `cfg.tiers`.
- **Audit-mutated CRUD** — every config change goes through
  the audit chain + CSRF gate + capability check; rule edits,
  mode toggles, alert receivers, upstream pools, risk
  thresholds (global + per-tier), detector mask, Strike-Block
  enable, rate-limit, DDoS gate all hot-swap with a visible
  `config_reload` audit entry.
- **Per-tier risk thresholds** — every tier (critical / high /
  medium / low) carries its own per-request block score plus a
  `challenges_enabled` toggle (defaults `false` — challenges
  opt-in). Lets operators flip a tier into hard allow/block
  semantics (no PoW puzzle) without affecting other tiers — useful
  for admin / payment / machine-only API tiers. The wire shape
  also accepts per-tier `cumulative_challenge_at` /
  `cumulative_block_at` overrides for API clients with strong
  per-tier needs; the dashboard surfaces only the toggle since
  most deployments are well-served by the global thresholds.
- **Compliance modes** — `cfg.compliance.modes` accepts
  documentation tags (`fips`, `pci`, `soc2`, `gdpr`, `hipaa`)
  that surface on the dashboard's Compliance page. Lock-by-mode
  (auto-pinning detector classes when a mode is active) is
  deferred — see [`plans/future/compliance-profiles.md`](plans/archive/compliance-profiles.md).
  Operators may freely enable or disable any detector class
  today.

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
  Overview / Redis / Runtime). `make obs-up` brings up the full
  Prometheus + Grafana + Jaeger stack via
  [`deploy/docker-compose.dev.yml`](deploy/docker-compose.dev.yml);
  if dashboards render empty, see the diagnostic checklist in
  [`docs/observability/README.md`](docs/observability/README.md#empty-grafana-panels--diagnostic-checklist).
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

```sh
make setup       # dev cert + release build (cold ~2 min, warm ~10 s)
make run-dev     # boots WAF + Redis + mock upstream
make urls        # prints every URL + log path
```

Open <https://127.0.0.1:9443/> · login `admin` / `aegis-test-1234`.

> **Full happy-path walkthrough** (dashboard tour, traffic
> generation, real-upstream wiring, troubleshooting): →
> [`QUICKSTART.md`](QUICKSTART.md).

### Hackathon submission deploy (v2.5 contract)

The OC contract expects the binary at `./waf` and the config at
`./waf.yaml` in the working directory. **Before judging, run
both steps** — `cargo run` alone will not satisfy the contract.

```sh
make build && make stage   # creates ./waf symlink + ./waf.yaml
./waf run                   # boots against prod-balanced profile
```

Key references:
- [`deploy/STAGING-BENCHMARK.md`](deploy/STAGING-BENCHMARK.md) — three-host benchmarker topology + SSH tunnel for `/__waf_control/*` + `/challenge/verify` smoke tests.
- `config/profiles/prod-balanced.yaml` — staged config; ships
  `interop.audit_path: ./waf_audit.log`,
  `interop.control_secret: waf-hackathon-2026-ctrl`.

### Dashboard JSX workflow

The dashboard is a pre-compiled `app.js` embedded into the
release binary via `include_bytes!`. **`make build` auto-rebundles
the JSX whenever any source under
`crates/aegis-control/assets/dashboard/src/` is newer than the
compiled `app.js`** — no manual step required.

If you bypass make (`cargo build` directly), run
`make dashboard` first or you'll embed the previous bundle.
`make dashboard-force` rebuilds even when mtimes say the bundle
is fresh — useful after toolchain bumps (Node, esbuild) where
the output might shift without any source change.

CI gates on `app.js` drift: a PR that edits JSX without
committing the matching bundle fails the
`dashboard-bundle-fresh` job.

### Feature flags

`make build` defaults to `FEATURES="redis geoip alerts ai"`. Add
more at build time:

| Flag | Adds |
|---|---|
| `redis` | shared rate-limit + leader-lease state backend |
| `geoip` | MaxMind GeoLite2 reader (country / ASN enrichment + `kind: country` access-list) |
| `alerts` | VipTalk delivery for SLO + audit alerts |
| `ai` | ML-based detector (operator-supplied ONNX, `ort` runtime) |
| `taxii` | STIX/TAXII threat-intel auto-fetch |
| `http3` | QUIC listener (quinn + h3) |
| `otel` | OpenTelemetry OTLP exporter |
| `vault` / `aws` / `gcp` / `azure` | cloud-secret resolvers |
| `consul` / `etcd` / `k8s` | service-discovery watchers |

```sh
FEATURES="redis geoip alerts ai taxii http3 otel" make build
```

### Profiles

| Make target | Config | When |
|---|---|---|
| `make run-dev` | `config/dev.yaml` | local dev (inline creds, loose limits) |
| `make run` | `config/profiles/prod-balanced.yaml` | **production default** |
| `make run-strict` | `config/profiles/prod-strict.yaml` | PCI / HIPAA / SOC 2 / GDPR |
| `make run-throughput` | `config/profiles/prod-high-throughput.yaml` | CDN front-door, > 5 k RPS |

Decision tree + measured perf comparison: [`docs/operator/profiles.md`](docs/operator/profiles.md).

### Upstreams (the one config you'll always touch)

Per-protocol recipes (plain HTTP, HTTPS+WSS, multi-vhost,
h2c / gRPC, raw TCP via CONNECT): [`docs/operator/upstream-cookbook.md`](docs/operator/upstream-cookbook.md).
Both routes and pools are editable from the dashboard's
**Routing & Upstreams** page — audit-mutated, hot-swap, no
restart.

### Tests

```sh
make test        # cargo test --workspace (~2 800 tests, zero warnings)
make clippy      # cargo clippy -- -D warnings
make smoke       # curl data + admin healthz (assumes `make run-dev` up)
make ci-local    # everything GitHub Actions runs
```

Full test catalogue (smoke / contract / load / cluster / dashboard /
hackathon stress / security corpus): [`tests/`](tests/) — every
subfolder has its own README.

### Deploy

```sh
bash deploy/docker-build.sh --tag aegis-gate:0.x      # multi-arch image (amd64 + arm64)
helm upgrade --install aegis deploy/helm/aegis-gate \
  --set image.tag=0.x --set redis.url=redis://prod-redis:6379
```

Full walkthrough (image, systemd, Helm, config plane, prod
checklist): [`deploy/GUIDE.md`](deploy/GUIDE.md).

---

## CLI

```
waf run       --config <path>         Start the WAF gateway
waf validate  --config <path>         Dry-run validation
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
| **v2.3 benchmark contract** (control plane + headers + audit shape) | [`Hackathon_Doc/EN_waf_interop_contract_v2.3.md`](Hackathon_Doc/EN_waf_interop_contract_v2.3.md) — drive locally with `make bench-dev` (see [`QUICKSTART.md`](QUICKSTART.md) §8) or on staging via [`deploy/STAGING-BENCHMARK.md`](deploy/STAGING-BENCHMARK.md) §7.5 |
| **Feature playbook** (one row per feature, how to verify each) | [`docs/FEATURES.md`](docs/FEATURES.md) |
| **How the security engine works** (request → decision walkthrough) | [`docs/security/security-engine.md`](docs/security/security-engine.md) |
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
| **Deployment guide** (production multi-node) | [`deploy/GUIDE.md`](deploy/GUIDE.md) |
| **Linux staging deploy** (single host, Docker infra, benchmark-ready, AI-assistant-driven) | [`deploy/STAGING-BENCHMARK.md`](deploy/STAGING-BENCHMARK.md) |
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
