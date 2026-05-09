# Aegis-Gate — Documentation

Per-feature documentation for the WAF / Security Gateway. The
authoritative top-level specs live at the repository root:

- [`../Requirement.md`](../Requirement.md) — requirements (the "what")
- [`../Architecture.md`](../Architecture.md) — architecture (the "how")
- [`../plans/README.md`](../plans/README.md) — index of active and
  recently-shipped tracks (per-feature plans + the implementation
  matrix that flips them between *Implemented* / *Partial* /
  *Designed-only*)

Each doc in this folder is scoped to a single subsystem and is
implementation-agnostic; the owning member plan (M1/M2/M3) points back
to it for background.

---

## Layout

```
docs/
├── README.md                  ← this taxonomy index
├── operator/                  Operator-facing how-to (run, configure, observe)
├── architecture/              Cross-cutting design and protocol references
├── data-plane/                M1 — proxying, routing, TLS, traffic mgmt
├── security/                  M2 — rules, detectors, risk, challenge engine
│   └── detectors/             Per-attack-class detector specs
├── control-plane/             M3 — dashboard, admin API, hot-reload, secrets
│   └── enterprise/            Aegis WAF Console — page inventory + REST/SSE contract
├── observability/             Metrics, tracing, audit, SIEM, SLO/SLI
├── operations/                Day-2: HA, compliance, residency, DR
└── future/                    Phase-B intake + deferred designs
```

A category folder contains a `README.md` that lists its docs and an
ownership note. The rest of this file is a flat index pointing into
each category.

---

## Category indexes

| Category | When to read | Index |
|---|---|---|
| **Operator** | "How do I run / configure / observe Aegis-Gate?" | [`operator/`](./operator/) |
| **Architecture** | Cross-cutting protocol + system contracts | [`architecture/protocols.md`](./architecture/protocols.md) |
| **Data plane** | Proxy, routing, TLS, traffic management | [`data-plane/README.md`](./data-plane/README.md) |
| **Security** | Rule engine, detectors, risk, challenge | [`security/README.md`](./security/README.md) |
| **Control plane** | Dashboard, admin API, hot-reload | [`control-plane/README.md`](./control-plane/README.md) |
| **Observability** | Metrics, audit, SIEM, SLO | [`observability/README.md`](./observability/README.md) |
| **Operations** | HA, compliance, DR, residency | [`operations/README.md`](./operations/README.md) |
| **Future** | Phase-B intake + deferred designs | [`future/README.md`](./future/README.md) |

---

## Operator

| Doc | Summary |
|---|---|
| [usage.md](./operator/usage.md) | End-to-end operator guide — bring-up, config, security toggles, runbooks |
| [cli.md](./operator/cli.md) | Authoritative CLI reference for the `waf` binary |
| [benchmark-mode.md](./operator/benchmark-mode.md) | Gated, opt-in mode that exposes per-request WAF diagnostics on `X-Aegis-*` response headers + dashboard panels + Prometheus series |

## Architecture

| Doc | Summary |
|---|---|
| [protocols.md](./architecture/protocols.md) | HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC |

## Data plane

| Doc | Summary |
|---|---|
| [reverse-proxy.md](./data-plane/reverse-proxy.md) | Data-plane listener, route table, protocol adapters |
| [routing-ingress.md](./data-plane/routing-ingress.md) | Host + path route table, longest-prefix-wins |
| [upstream-pools.md](./data-plane/upstream-pools.md) | Load balancing, health checks, circuit breaker |
| [traffic-management.md](./data-plane/traffic-management.md) | Canary split, steering, shadow mirror, retries |
| [tls-termination.md](./data-plane/tls-termination.md) | SNI, ACME, OCSP, FIPS, mTLS to upstream |
| [session-affinity.md](./data-plane/session-affinity.md) | Sticky cookies + consistent-hash |
| [per-route-quotas.md](./data-plane/per-route-quotas.md) | Body size, header, timeout limits |
| [transformations-cors.md](./data-plane/transformations-cors.md) | Header / URL rewrites, CORS |
| [service-discovery.md](./data-plane/service-discovery.md) | File / DNS / Consul / etcd / k8s |
| [smart-caching.md](./data-plane/smart-caching.md) | Cache with security awareness |
| [adaptive-load-shedding.md](./data-plane/adaptive-load-shedding.md) | Gradient2 + tier priority |
| [graceful-degradation.md](./data-plane/graceful-degradation.md) | Circuit breakers, timeouts, fallback |

## Security

| Doc | Summary |
|---|---|
| [rule-engine.md](./security/rule-engine.md) | AST + matcher + actions |
| [tiered-protection.md](./security/tiered-protection.md) | Tiered policy + fail-close/open |
| [rate-limiting.md](./security/rate-limiting.md) | Sliding window, distributed state |
| [ddos-protection.md](./security/ddos-protection.md) | Burst + global spike + cluster blocks |
| [ip-reputation.md](./security/ip-reputation.md) | Lists, ASN, threat-intel, XFF validation |
| [geoip-filtering.md](./security/geoip-filtering.md) | Geo allow/deny |
| [device-fingerprinting.md](./security/device-fingerprinting.md) | JA4 + h2 fingerprint + composite device id |
| [risk-scoring.md](./security/risk-scoring.md) | Composite RiskKey, decay, actions |
| [challenge-engine.md](./security/challenge-engine.md) | JS / PoW / CAPTCHA escalation |
| [bot-management.md](./security/bot-management.md) | Class, good-bot verify, model backend |
| [behavioral-analysis.md](./security/behavioral-analysis.md) | Session shape + anomaly |
| [transaction-velocity.md](./security/transaction-velocity.md) | Abuse velocity counters |
| [threat-intelligence.md](./security/threat-intelligence.md) | STIX / TAXII / commercial feeds |
| [api-security.md](./security/api-security.md) | OpenAPI / GraphQL positive security |
| [content-scanning.md](./security/content-scanning.md) | ICAP / antivirus |
| [dlp.md](./security/dlp.md) | Data loss prevention patterns + FPE |
| [response-filtering.md](./security/response-filtering.md) | Stack trace scrub, headers, DLP bridge |
| [external-auth.md](./security/external-auth.md) | ForwardAuth, JWT, Basic, IP ACL (origin-facing, data plane) |

### Detectors

| Doc | Summary |
|---|---|
| [sqli.md](./security/detectors/sqli.md) | SQL injection detector |
| [xss.md](./security/detectors/xss.md) | XSS detector |
| [path-traversal.md](./security/detectors/path-traversal.md) | Path traversal detector |
| [ssrf.md](./security/detectors/ssrf.md) | SSRF detector |
| [header-injection.md](./security/detectors/header-injection.md) | Header injection |
| [recon.md](./security/detectors/recon.md) | Scanner / probe detection |
| [brute-force.md](./security/detectors/brute-force.md) | Auth brute-force |
| [ai-detector.md](./security/detectors/ai-detector.md) | ML-based binary attack/normal verdict (operator-supplied ONNX, `ort` runtime, `ai` Cargo feature) |
| [body-abuse.md](./security/detectors/body-abuse.md) | Body size / nesting abuse |

## Control plane

| Doc | Summary |
|---|---|
| [dashboard.md](./control-plane/dashboard.md) | Control-plane UI + admin API |
| [dashboard-auth.md](./control-plane/dashboard-auth.md) | Dashboard + admin API auth: argon2id + HMAC session + CSRF + IP allowlist + optional TOTP/mTLS |
| [config-hot-reload.md](./control-plane/config-hot-reload.md) | Dry-run validator + secret refs + GitOps |
| [gitops-change-management.md](./control-plane/gitops-change-management.md) | Git source of truth, signed commits |
| [secrets-management.md](./control-plane/secrets-management.md) | Vault / AWS SM / GCP SM / Azure KV / HSM |
| [zero-downtime-ops.md](./control-plane/zero-downtime-ops.md) | SO_REUSEPORT, drain, hot reload |
| [enterprise/](./control-plane/enterprise/) | Aegis WAF Console — live page inventory + REST/SSE contract + front-end CSP |

## Observability

| Doc | Summary |
|---|---|
| [prometheus-otel.md](./observability/prometheus-otel.md) | Metrics, tracing, access logs |
| [audit-logging.md](./observability/audit-logging.md) | Hash-chained audit + change log |
| [siem-log-forwarding.md](./observability/siem-log-forwarding.md) | Syslog / CEF / LEEF / OCSF / Kafka |
| [slo-sli-alerting.md](./observability/slo-sli-alerting.md) | SLOs, burn-rate alerts, runbooks |

## Operations

| Doc | Summary |
|---|---|
| [runtime-tuning.md](./operations/runtime-tuning.md) | Layer-1 scaling — tokio worker threads, blocking pool, CPU affinity |
| [ha-clustering.md](./operations/ha-clustering.md) | Layer-2 scaling — etcd (config) + optional Redis (counters), split-brain safety |
| [compliance.md](./operations/compliance.md) | FIPS, PCI, HIPAA, SOC 2, GDPR modes |
| [data-residency-retention.md](./operations/data-residency-retention.md) | Region pin + retention + GDPR erasure |
| [dr-backup.md](./operations/dr-backup.md) | RPO/RTO, snapshots, restore drills |

## Future

| Doc | Status | Summary |
|---|---|---|
| [advanced-features.md](./future/advanced-features.md) | Phase B intake | Template for collecting + scoring future feature requests |
| [rbac-sso.md](./future/rbac-sso.md) | Deferred | OIDC / SAML / RBAC |

---

## Reading order for a new engineer

1. `../Requirement.md` — the "what"
2. `../Architecture.md` — the "how"
3. `../plans/README.md` — the active + recently-shipped track index
4. `data-plane/reverse-proxy.md` → `data-plane/routing-ingress.md` →
   `data-plane/upstream-pools.md` — request flow
5. `security/tiered-protection.md` → `security/rule-engine.md` → any
   detector — the security pipeline
6. `security/risk-scoring.md` → `security/challenge-engine.md` —
   decisioning
7. `control-plane/config-hot-reload.md` →
   `control-plane/gitops-change-management.md` — how changes land
8. `control-plane/dashboard.md` → `control-plane/dashboard-auth.md` →
   `observability/audit-logging.md` — operator surfaces
9. `operations/ha-clustering.md` → `operations/compliance.md` — the
   enterprise story

## Ownership map

| Area | Owner | Plan |
|---|---|---|
| data-plane/* (proxy, routing, upstreams, TLS, traffic-mgmt, quotas, transformations, session-affinity, service-discovery, smart-caching, adaptive-load-shedding, graceful-degradation) | **M1** | `../plans/member-1-proxy-core.md` |
| security/* (rule-engine, rate-limiting, ddos, all detectors, fingerprinting, risk, challenge, bot-mgmt, behavior, velocity, threat-intel, ip-rep, geoip, response-filtering, dlp, content-scanning, api-security, external-auth) | **M2** | `../plans/member-2-security-pipeline.md` |
| control-plane/* + observability/* + operations/* | **M3** | `../plans/member-3-control-plane.md` |
| smart-caching | M1 (cache) + M2 (security-aware bypass) | both |
| tiered-protection, graceful-degradation, per-route-quotas | M1 (enforce) + M2 (policy) | both |

## Future phases

Tracks landing here:

1. **Dashboard redesign** — closed (DD-T0..T8 shipped in run-10).
   The bundled SPA is now the source of truth — see
   [`control-plane/enterprise/`](./control-plane/enterprise/) for
   the live page inventory + REST/SSE contract.
2. **AI Detector** — closed 2026-05-03 (AI-T1..T9). See
   [`security/detectors/ai-detector.md`](./security/detectors/ai-detector.md).
3. **Phase B (advanced features)** — open intake. Use
   [`future/advanced-features.md`](./future/advanced-features.md) to
   propose, score, and triage requests. Once a feature is accepted it
   moves into the appropriate category folder with its own doc.
