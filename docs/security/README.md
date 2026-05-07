# Security pipeline (M2)

The decision pipeline: rule engine, detectors, risk scoring, challenge
engine. Implementation lives in `crates/aegis-security/`; per-feature
plans are tracked in [`../../plans/`](../../plans/).

## Reading order

0. **[security-engine.md](./security-engine.md) — how the engine works
   end-to-end.** Start here. One-page narrative: request flow,
   per-stage decisions, the risk model (per-request score vs
   cumulative IP strike), worked examples. Companion to
   `Architecture.md` §5.
1. [tiered-protection.md](./tiered-protection.md) — tier policy +
   fail-close/open semantics
2. [rule-engine.md](./rule-engine.md) — AST + matcher + actions
3. Any detector under [detectors/](./detectors/) — per-attack-class
   logic
4. [risk-scoring.md](./risk-scoring.md) → [challenge-engine.md](./challenge-engine.md)
   — decisioning

## Detectors

Per-class signal generators. Each fires independently; the engine
sums their `score` into the per-request risk total. Concrete signal
scores per detector are listed in
[risk-scoring.md § Score reference](./risk-scoring.md#score-reference).

| Doc | Detector | Default signal score | Notes |
|---|---|---:|---|
| [sqli.md](./detectors/sqli.md) | SQL injection | 40 | Pattern + AST hybrid |
| [xss.md](./detectors/xss.md) | Cross-site scripting | 35 | Reflected + stored heuristics |
| [path-traversal.md](./detectors/path-traversal.md) | Path traversal | 45 | URL-decoded `..` walk |
| [ssrf.md](./detectors/ssrf.md) | SSRF | 50 | Internal/cloud-meta IP blocklist |
| [header-injection.md](./detectors/header-injection.md) | Header / response splitting | 40 | CRLF + smuggling probes |
| [recon.md](./detectors/recon.md) | Scanner / probe detection | 25–30 | Common 404 fingerprints + canaries |
| [brute-force.md](./detectors/brute-force.md) | Auth brute-force | configurable | Counter-based per `(ip, path)` |
| [body-abuse.md](./detectors/body-abuse.md) | Body size / nesting abuse | 30–60 | Depth + size escalation |
| [ai-detector.md](./detectors/ai-detector.md) | **AI / ML classifier** (`ai` feature) | 60 | ONNX, 26-feature extractor; chains AFTER the regex detectors as a tiebreaker for ambiguous payloads |

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
