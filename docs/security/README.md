# Security pipeline (M2)

The decision pipeline: rule engine, detectors, risk scoring, challenge
engine. Implementation lives in `crates/aegis-security/`; per-feature
plans are tracked in [`../../plans/`](../../plans/).

## Reading order

1. [tiered-protection.md](./tiered-protection.md) — tier policy +
   fail-close/open semantics (read this first; everything else
   layers on top)
2. [rule-engine.md](./rule-engine.md) — AST + matcher + actions
3. Any detector under [detectors/](./detectors/) — per-attack-class
   logic
4. [risk-scoring.md](./risk-scoring.md) → [challenge-engine.md](./challenge-engine.md)
   — decisioning

## Detectors

| Doc | Detector |
|---|---|
| [sqli.md](./detectors/sqli.md) | SQL injection |
| [xss.md](./detectors/xss.md) | Cross-site scripting |
| [path-traversal.md](./detectors/path-traversal.md) | Path traversal |
| [ssrf.md](./detectors/ssrf.md) | SSRF |
| [header-injection.md](./detectors/header-injection.md) | Header / response splitting |
| [recon.md](./detectors/recon.md) | Scanner / probe detection |
| [brute-force.md](./detectors/brute-force.md) | Auth brute-force |
| [body-abuse.md](./detectors/body-abuse.md) | Body size / nesting abuse |

## Cross-cutting

| Doc | Summary |
|---|---|
| [rate-limiting.md](./rate-limiting.md) | Sliding window, distributed state |
| [ddos-protection.md](./ddos-protection.md) | Burst + global spike + cluster blocks |
| [ip-reputation.md](./ip-reputation.md) | Lists, ASN, threat-intel, XFF validation |
| [geoip-filtering.md](./geoip-filtering.md) | Geo allow/deny |
| [device-fingerprinting.md](./device-fingerprinting.md) | JA4 + h2 fingerprint + composite device id |
| [bot-management.md](./bot-management.md) | Class, good-bot verify, model backend |
| [behavioral-analysis.md](./behavioral-analysis.md) | Session shape + anomaly |
| [transaction-velocity.md](./transaction-velocity.md) | Abuse velocity counters |
| [threat-intelligence.md](./threat-intelligence.md) | STIX / TAXII / commercial feeds |
| [api-security.md](./api-security.md) | OpenAPI / GraphQL positive security |
| [content-scanning.md](./content-scanning.md) | ICAP / antivirus |
| [dlp.md](./dlp.md) | Data loss prevention patterns + FPE |
| [response-filtering.md](./response-filtering.md) | Stack trace scrub, headers, DLP bridge |
| [external-auth.md](./external-auth.md) | ForwardAuth, JWT, Basic, IP ACL (origin-facing) |
