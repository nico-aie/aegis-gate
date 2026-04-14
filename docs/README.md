# WAF v2 — Feature Docs

This folder is the per-feature documentation for the **v2** design of
the WAF (k8s-ingress + nginx inspired, enterprise-ready). It replaces
the original `docs/` folder, which documents the v1 design.

The v2 requirements and architecture specs are at the repository root:

- [`../waf_mini_hackathon_2026_v2.md`](../waf_mini_hackathon_2026_v2.md) — requirements
- [`../waf_mini_hackathon_architecture_2026_v2.md`](../waf_mini_hackathon_architecture_2026_v2.md) — architecture

Each doc in this folder starts with a `v1 → v2` delta callout where
applicable.

---

## Core pipeline

| Doc | Summary |
|---|---|
| [reverse-proxy.md](./reverse-proxy.md) | Data-plane listener, route table, protocol adapters |
| [routing-ingress.md](./routing-ingress.md) | Host + path route table, longest-prefix-wins |
| [upstream-pools.md](./upstream-pools.md) | Load balancing, health checks, circuit breaker |
| [traffic-management.md](./traffic-management.md) | Canary split, steering, shadow mirror, retries |
| [protocols.md](./protocols.md) | HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC |
| [tls-termination.md](./tls-termination.md) | SNI, ACME, OCSP, FIPS, mTLS to upstream |
| [session-affinity.md](./session-affinity.md) | Sticky cookies + consistent-hash |
| [per-route-quotas.md](./per-route-quotas.md) | Body size, header, timeout limits |
| [transformations-cors.md](./transformations-cors.md) | Header / URL rewrites, CORS |
| [tiered-protection.md](./tiered-protection.md) | Tiered policy + fail-close/open |
| [graceful-degradation.md](./graceful-degradation.md) | Circuit breakers, timeouts, fallback |

## Security pipeline

| Doc | Summary |
|---|---|
| [rule-engine.md](./rule-engine.md) | AST + matcher + actions |
| [rate-limiting.md](./rate-limiting.md) | Sliding window, distributed state |
| [ddos-protection.md](./ddos-protection.md) | Burst + global spike + cluster blocks |
| [ip-reputation.md](./ip-reputation.md) | Lists, ASN, threat-intel, XFF validation |
| [geoip-filtering.md](./geoip-filtering.md) | Geo allow/deny |
| [device-fingerprinting.md](./device-fingerprinting.md) | JA4 + h2 fingerprint + composite device id |
| [risk-scoring.md](./risk-scoring.md) | Composite RiskKey, decay, actions |
| [challenge-engine.md](./challenge-engine.md) | JS / PoW / CAPTCHA escalation |
| [bot-management.md](./bot-management.md) | Class, good-bot verify, model backend |
| [behavioral-analysis.md](./behavioral-analysis.md) | Session shape + anomaly |
| [transaction-velocity.md](./transaction-velocity.md) | Abuse velocity counters |
| [detection-sqli.md](./detection-sqli.md) | SQL injection detector |
| [detection-xss.md](./detection-xss.md) | XSS detector |
| [detection-path-traversal.md](./detection-path-traversal.md) | Path traversal detector |
| [detection-ssrf.md](./detection-ssrf.md) | SSRF detector |
| [detection-header-injection.md](./detection-header-injection.md) | Header injection |
| [detection-recon.md](./detection-recon.md) | Scanner / probe detection |
| [detection-brute-force.md](./detection-brute-force.md) | Auth brute-force |
| [detection-body-abuse.md](./detection-body-abuse.md) | Body size / nesting abuse |

## Authentication

| Doc | Summary |
|---|---|
| [external-auth.md](./external-auth.md) | ForwardAuth, JWT, OIDC RP, Basic, IP ACL (data plane) |
| [rbac-sso.md](./rbac-sso.md) | Dashboard + admin API auth (control plane) |

## Egress / data protection

| Doc | Summary |
|---|---|
| [response-filtering.md](./response-filtering.md) | Stack trace scrub, headers, DLP bridge |
| [dlp.md](./dlp.md) | Data loss prevention patterns + FPE |
| [content-scanning.md](./content-scanning.md) | ICAP / antivirus |
| [api-security.md](./api-security.md) | OpenAPI / GraphQL positive security |
| [smart-caching.md](./smart-caching.md) | Cache with security awareness |

## Operations

| Doc | Summary |
|---|---|
| [dashboard.md](./dashboard.md) | Control-plane UI + admin API |
| [config-hot-reload.md](./config-hot-reload.md) | Dry-run validator + secret refs + GitOps |
| [gitops-change-management.md](./gitops-change-management.md) | Git source of truth, signed commits |
| [zero-downtime-ops.md](./zero-downtime-ops.md) | SO_REUSEPORT, drain, hot reload |
| [service-discovery.md](./service-discovery.md) | File / DNS / Consul / etcd / k8s |
| [adaptive-load-shedding.md](./adaptive-load-shedding.md) | Gradient2 + tier priority |
| [secrets-management.md](./secrets-management.md) | Vault / AWS SM / GCP SM / Azure KV / HSM |

## Enterprise

| Doc | Summary |
|---|---|
| [ha-clustering.md](./ha-clustering.md) | Redis / Raft / gossip, split-brain safety |
| [multi-tenancy.md](./multi-tenancy.md) | Per-tenant isolation + quotas + residency |
| [compliance.md](./compliance.md) | FIPS, PCI, HIPAA, SOC 2, GDPR modes |
| [audit-logging.md](./audit-logging.md) | Hash-chained audit + change log |
| [siem-log-forwarding.md](./siem-log-forwarding.md) | Syslog / CEF / LEEF / OCSF / Kafka |
| [threat-intelligence.md](./threat-intelligence.md) | STIX / TAXII / commercial feeds |
| [observability-prometheus-otel.md](./observability-prometheus-otel.md) | Metrics, tracing, access logs |
| [slo-sli-alerting.md](./slo-sli-alerting.md) | SLOs, burn-rate alerts, runbooks |
| [data-residency-retention.md](./data-residency-retention.md) | Region pin + retention + GDPR erasure |
| [dr-backup.md](./dr-backup.md) | RPO/RTO, snapshots, restore drills |

---

## Reading order for a new engineer

1. `../waf_mini_hackathon_2026_v2.md` — the "what"
2. `../waf_mini_hackathon_architecture_2026_v2.md` — the "how"
3. `reverse-proxy.md` → `routing-ingress.md` → `upstream-pools.md` —
   request flow
4. `tiered-protection.md` → `rule-engine.md` → any detector — the
   security pipeline
5. `risk-scoring.md` → `challenge-engine.md` — decisioning
6. `config-hot-reload.md` → `gitops-change-management.md` — how
   changes land
7. `dashboard.md` → `rbac-sso.md` → `audit-logging.md` — operator
   surfaces
8. `ha-clustering.md` → `multi-tenancy.md` → `compliance.md` — the
   enterprise story
