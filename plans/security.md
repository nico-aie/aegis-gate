# Security Pipeline — `aegis-security` Task Plan

> **Before reading this:** Read `README.md`, then `Implement-Progress.md`,
> then `plans/plan.md` (shared types §2, traits §3, boot §4, conventions §5).
> This file contains only the per-task breakdown for `aegis-security`.

**Crate mission:** implement `SecurityPipeline` end-to-end — inspect, score, and
decide every request before the proxy forwards it; scrub every response.

**Entry point:** `pub async fn build(cfg, state, cache, bus, metrics, cfg_bcast) -> Result<Arc<dyn SecurityPipeline>>`

**Verification:** `cargo test -p aegis-security && cargo clippy -p aegis-security -- -D warnings`

---

## Crate Layout

```
crates/aegis-security/src/
  lib.rs, pipeline.rs
  rules/:       mod.rs, ast.rs, parser.rs, linter.rs, eval.rs
  rate_limit/:  mod.rs, sliding.rs, bucket.rs
  detectors/:   mod.rs, sqli.rs, xss.rs, path_traversal.rs, ssrf.rs,
                header_injection.rs, body_abuse.rs, recon.rs, brute_force.rs
  fingerprint/: mod.rs, ja4.rs, ja3.rs, h2.rs
  risk/:        mod.rs, store.rs
  challenge/:   mod.rs, token.rs, providers.rs
  ip_rep/:      mod.rs, asn.rs, xff.rs
  dlp/:         mod.rs, fpe.rs
  api_security/:mod.rs, graphql.rs, hmac_sign.rs, api_keys.rs
  auth/:        mod.rs, forward.rs, jwt.rs, basic.rs, cidr.rs, opa.rs
  content/:     mod.rs, archive.rs, icap.rs
  ddos.rs, bots.rs, behavior.rs, velocity.rs, threat_intel.rs, response_filter.rs
```

---

## Pipeline Execution Order

**Inbound (every request, in order):**
```
 1. XFF resolve / trusted-proxy         ip_rep/xff.rs    (W4)
 2. IP blacklist + threat feed          ip_rep, threat_intel (W4)
 3. Rate limit + DDoS burst             rate_limit, ddos  (W2)
 4. Tier classify + failure mode        pipeline.rs       (W1)
 5. Route-level auth (JWT/FA/Basic/CIDR/OPA) auth/       (W5)
 6. API guard (OpenAPI/GraphQL/HMAC/keys) api_security/  (W5)
 7. OWASP detectors → signals           detectors/        (W2)
 8. Content type + archive checks       content/          (W5)
 9. Rule engine (priority order)        rules/            (W1)
10. Bot classify + behavior + velocity  bots, behavior, velocity (W3/W4)
11. Risk engine + challenge             risk/, challenge/ (W3)
12. DLP inbound                         dlp/              (W5)
13. ICAP REQMOD (upload routes)         content/icap.rs   (W5)
14. return Decision
```
**Outbound:** DLP → stack-trace scrub → security header injection.

Every short-circuit emits **exactly one** `AuditClass::Detection` event.

---

## Prometheus Metrics

```
waf_rule_hits_total{rule_id,action}
waf_detector_hits_total{detector,tag}
waf_rate_limit_denied_total{scope}
waf_ddos_blocked_total
waf_risk_score_bucket{bucket}               (histogram)
waf_challenge_total{level,outcome}
waf_threat_feed_hits_total{feed_id}
waf_dlp_matches_total{pattern,action}
waf_schema_violations_total{route}
waf_auth_failures_total{mechanism}
```

---

## W1 — Rule Engine Core

**M2-T1.1** Rule AST + parser
- Files: `src/rules/ast.rs`, `src/rules/parser.rs`
- `Rule { id: String, priority: u32, scope: Scope, when: Condition, then: Action }`
- `Condition` variants: `All(Vec<Condition>)`, `Any`, `Not`, `IpIn(Vec<IpNet>)`, `PathMatches(MatchOp)`, `HostMatches(MatchOp)`, `Method(Vec<Method>)`, `HeaderMatches{name,op}`, `QueryMatches{name,op}`, `BodyMatches(MatchOp)`, `CookieMatches{name,op}`, `JwtClaim{path,op}`, `BotClass(Vec<String>)`, `ThreatFeed{id,min_confidence}`, `SchemaViolation`
- `Action` variants: `Allow`, `Block{status:u16}`, `Challenge{level}`, `RateLimit{key,limit,window_s}`, `RaiseRisk(u32)`, `Transform(TransformSpec)`, `LogOnly`
- `pub fn parse(yaml: &str) -> Result<Vec<Rule>>`
- Test: round-trip 10 rule fixtures; reject duplicate id, unknown field.

**M2-T1.2** Linter
- File: `src/rules/linter.rs`
- Checks: unique ids, max nesting depth 8, priority in [0, 10_000], regex compiles, referenced rule/pool ids exist.
- `pub fn lint(rules: &[Rule], cfg: &WafConfig) -> Result<()>`
- Test: one fixture per failure class.

**M2-T1.3** Evaluator
- File: `src/rules/eval.rs`
- `pub fn evaluate(rules: &[Rule], req: &RequestView, route: &RouteCtx) -> Option<Decision>`
- Priority-ordered; first terminal action wins. Non-terminal (`RaiseRisk`, `LogOnly`, `Transform`) accumulates then continues.
- Test: 20 request/rule combinations with expected decisions.

**M2-T1.4** RuleSet hot reload
- File: `src/rules/mod.rs`
- `pub struct RuleSet(ArcSwap<Arc<Vec<Rule>>>)` with `reload(path) -> Result<()>` — lints before swap.
- Test: reload a broken file; assert running set untouched; audit emits failure event.

**M2-T1.5** Tier classifier
- File: `src/pipeline.rs`
- `fn classify_tier(route: Option<&RouteCtx>, req: &RequestView) -> (Tier, FailureMode)` — route override first, then path heuristic (`/login`, `/payments/*` → Critical).
- Test: 10 paths mapped to expected tier.

**W1 exit gate:** `NoopPipeline` replaced by `Pipeline` stub wired to rules. A rule blocking `/evil` returns 403 visible on dashboard SSE.

---

## W2 — Rate Limit, DDoS, OWASP Detectors

**M2-T2.1** Sliding window rate limit
- File: `src/rate_limit/sliding.rs`
- `pub async fn check(state: &dyn StateBackend, key: &str, limit: u64, window_s: u32) -> Result<RateDecision>`
- Key format: `rl:{scope}:{id}:{bucket}` (the `t:{tenant}:` prefix is reserved for deferred multi-tenancy).
- Test: 1k concurrent callers; count never exceeds limit.

**M2-T2.2** Token bucket
- File: `src/rate_limit/bucket.rs`
- `pub async fn take(state: &dyn StateBackend, key: &str, rate: f64, burst: u64) -> Result<bool>`
- Test: burst consumed instantly; refill linear.

**M2-T2.3** DDoS per-IP burst + cluster spike
- File: `src/ddos.rs`
- Per-IP sliding window → auto-block key `block:{ip}` with TTL. Cluster spike: compare rolling cluster RPS vs `rolling_avg * spike_multiplier`; when active, tighten challenge thresholds.
- Test: 1k req/s from one IP → block within 2s.

**M2-T2.4** OWASP detectors
- Trait: `pub trait Detector: Send + Sync { fn id(&self) -> &'static str; fn inspect(&self, req: &RequestView) -> Vec<Signal>; }`
- `Signal { pub score: u32, pub tag: String, pub field: String }`
- Required: SQLi, XSS, PathTraversal, SSRF, HeaderInjection, BodyAbuse (oversize + deep nesting), Recon (dir scans, known tools), BruteForce (`state:fail:{ip}:{path}` counter).
- Each detector: ≥ 30 positive fixtures + ≥ 30 negative fixtures; FP rate < 1% on benign corpus.
- Test: `cargo test -p aegis-security detectors`.

**W2 exit gate:** red-team script with SQLi, XSS, SSRF payloads → all blocked; decision visible on dashboard with rule id.

---

## W3 — Fingerprint, Risk, Challenge

**M2-T3.1** JA4/JA3 parser
- Files: `src/fingerprint/ja4.rs`, `src/fingerprint/ja3.rs`
- Input: ClientHello bytes from proxy hook. Output: `TlsFingerprint { ja3, ja4 }` blake3-salted with per-deployment salt.
- Test: golden-file captures from curl/chrome/firefox/python-requests.

**M2-T3.2** HTTP/2 fingerprint
- File: `src/fingerprint/h2.rs`
- Input: SETTINGS frame + pseudo-header order. Output: stable string.
- Test: tonic vs chrome H2 hellos produce distinct fingerprints.

**M2-T3.3** Composite device id
- `pub fn device_id(fp: &TlsFingerprint, h2: Option<&str>, ua: Option<&str>, header_order: &[String]) -> String` — blake3 over tuple, salted.

**M2-T3.4** RiskEngine
- File: `src/risk/mod.rs`
- `pub async fn score(&self, key: &RiskKey, signals: &[Signal]) -> u32`
- State in `StateBackend`. Decay: `score = score * exp(-Δt / half_life)`. Canary rules (hit `/admin/.env`) set score to max instantly.
- Thresholds: < 30 allow, 30–70 challenge, > 70 block.
- Test: decay test with mocked clock; canary rule test.

**M2-T3.5** Challenge ladder
- `pub fn next_level(risk: u32, human_conf: u32, bot: BotClass, tier: Tier) -> Option<ChallengeLevel>`
- Escalation: None → JS → PoW → CAPTCHA → Block.

**M2-T3.6** Challenge tokens
- File: `src/challenge/token.rs`
- HMAC-signed (`blake3::Hasher::new_keyed`), single-use nonce via `StateBackend` (TTL `nonce:{hash}`).
- `pub fn issue(&self, key: &RiskKey, level: ChallengeLevel) -> String`
- `pub async fn verify(&self, token: &str) -> Result<ChallengeLevel>`
- Test: replay attack rejected; downgrade attempt rejected.

**M2-T3.7** CAPTCHA providers
- `pub trait CaptchaProvider { async fn verify(&self, client_token: &str, ip: IpAddr) -> Result<bool>; }`
- Implementations: Turnstile, hCaptcha, reCAPTCHA v3 (HTTP POST to each API).
- Test: wiremock for each provider.

**M2-T3.8** Behavioral analyzer
- File: `src/behavior.rs`
- Features: request rate shape, path-diversity, error ratio, inter-arrival jitter, cookie consistency. Tracked per `RiskKey` in state backend with decay. Output: `Signal`.
- Test: replay legitimate browsing vs scripted fuzzing; anomaly score separates them.

**M2-T3.9** Transaction velocity
- File: `src/velocity.rs`
- Config-defined action templates per route (e.g. N deposits/5min). Velocity breach raises risk + optionally blocks.
- Test: 10 deposits/min from one user → block + audit event naming the action.

---

## W4 — IP Reputation, Bots, Threat Intel

**M2-T4.1** CIDR lists + XFF walker
- Files: `src/ip_rep/mod.rs`, `src/ip_rep/xff.rs`
- Blacklist/whitelist/trusted-proxies as `ipnet::IpNet` tries. XFF: walk right-to-left while peer ∈ trusted; first non-trusted = client IP. Ignore XFF entirely if TCP peer is not trusted.
- Test: spoofed XFF through untrusted peer is ignored.

**M2-T4.2** MaxMind ASN classifier
- File: `src/ip_rep/asn.rs`
- Load GeoLite2-ASN mmdb at boot. Categories: `residential`, `hosting`, `vpn`, `tor`, `bogon`. Configurable risk deltas.
- Test: known ASN fixtures produce expected category.

**M2-T4.3** Bot classifier
- File: `src/bots.rs`
- Tiers: `human | good_bot | likely_bot | known_bad | unknown`. Signals: JA4, h2fp, UA entropy, reverse-DNS (moka cached), threat feed, failed-challenge history. Good-bot verification: forward-confirmed reverse-DNS (e.g. Googlebot).
- Test: 10 known bots + 10 human browser captures.

**M2-T4.4** Threat intel feeds
- File: `src/threat_intel.rs`
- Formats: plain text, CSV, JSON, STIX 2.1 over TAXII 2.1. Per-feed confidence + severity; TTL-respected eviction. Local override list wins. Provenance (`feed_id`, `confidence`) in `AuditEvent::fields`.
- Test: mock TAXII server; import feed; block fires with provenance.

---

## W5 — Response Filter, DLP, API Security, Auth, ICAP

**M2-T5.1** Streaming response filter
- File: `src/response_filter.rs`
- Stack-trace scrub (Python/JVM/Node/Rust/PHP/.NET/Rails/Go). Internal-IP mask (RFC 1918, link-local, loopback). Strip `Server`, `X-Powered-By`. Inject `X-Content-Type-Options`, `X-Frame-Options`, HSTS, `Referrer-Policy`, `Permissions-Policy`, CSP. Streaming frame processor — never buffer full body.
- Test: 1 GB body passes with constant memory.

**M2-T5.2** DLP patterns + actions
- File: `src/dlp/mod.rs`
- Patterns (named `value` capture): credit card (Luhn-validated), SSN, IBAN (mod-97), email, phone, DOB, AWS/GCP/Azure/Stripe/GitHub/Slack/Twilio keys, PEM private keys, JWTs.
- Actions: `redact | mask | fpe | hmac | block`. Inbound + outbound. Every audit event also runs through DLP before emission.
- Test: `4111-1111-1111-1111` → `****-****-****-1111`.

**M2-T5.3** FPE (AES-FF1)
- File: `src/dlp/fpe.rs`
- Key versioning so existing tokens remain decryptable until retired.

**M2-T5.4** OpenAPI schema enforcement
- File: `src/api_security/mod.rs`
- Load OAS3 YAML; validate path, method, parameters, headers, body. Modes: `enforce | monitor | learn` (learn records observed traffic to a synthesized spec). Errors carry JSON-pointer path in audit; client-facing detail minimized.
- Test: valid POST accepted; mass-assignment with unknown field rejected.

**M2-T5.5** ForwardAuth
- File: `src/auth/forward.rs`
- `GET <address><original_path>`; copy allowlisted response headers onto forwarded request; failure honors route tier failure mode.
- Test: mock auth svc 401 → request blocked; 200 with headers → headers propagated.

**M2-T5.6** JWT validation
- File: `src/auth/jwt.rs`
- `jsonwebtoken` + JWKS cached in moka (TTL + stale-while-revalidate). Claims attached to `RequestCtx::fields` so rules can reference `user.role`.
- Test: valid/expired/wrong-iss/wrong-aud cases.

**M2-T5.7** ICAP antivirus
- File: `src/content/icap.rs`
- REQMOD (inbound) + RESPMOD (outbound) per RFC 3507. Clean-hash cache. Scan timeout applies route failure mode (fail-close for Critical).
- Test: EICAR test string via clamav in docker → blocked.

**M2-T5.8** Magic-byte + archive-bomb
- Files: `src/content/mod.rs`, `src/content/archive.rs`
- Detect file type via `infer` crate (not `Content-Type`). Per-route allowlist rejects disallowed types with 415. Archive walker enforces depth + compression ratio limits and aborts on breach.
- Test: zip bomb → blocked; `.exe` upload to image-only route → 415.

**M2-T5.9** GraphQL guard
- File: `src/api_security/graphql.rs`
- `async-graphql-parser` computes depth, node count, complexity cost. Reject beyond limits. Toggle introspection. Persisted-query allowlist.
- Test: normal query accepted; 10-deep nested query rejected; unknown persisted-id rejected.

**M2-T5.10** HMAC request signing
- File: `src/api_security/hmac_sign.rs`
- Verify SigV4-style or custom HMAC over `(method, path, canonical headers, body hash)` using per-consumer secret from `SecretProvider`. Clock-skew tolerance configurable. Replay nonce via `StateBackend`.
- Test: valid signature passes; tampered body rejected; replay rejected.

**M2-T5.11** API-key management
- File: `src/api_security/api_keys.rs`
- Per-consumer keys with scopes + rate limits. Stored as argon2id hashes. Extracted from `Authorization: Bearer` or a configured header name.
- Test: revoked key rejected; scope mismatch → 403.

**M2-T5.12** Basic Auth (data plane)
- File: `src/auth/basic.rs`
- Verify against htpasswd-style file loaded via `SecretProvider`. Opt-in per route.
- Test: correct/incorrect password cases.

**M2-T5.13** *(deferred)* OIDC RP — see `docs/deferred/rbac-sso.md`.

**M2-T5.14** OPA callout (feature `opa`)
- File: `src/auth/opa.rs`
- POST decision request to configured OPA endpoint; result mapped to `Decision`. Cached per `(policy, input_hash)` in moka.
- Test: mock OPA allow/deny.

**W5 exit gate:** red-team suite (SQLi/XSS/SSRF/path-traversal/brute-force) fully blocked; FP rate < 1% on benign corpus.

---

## Definition of Done (`aegis-security`)

- [ ] `cargo test -p aegis-security` green; `cargo clippy -p aegis-security -- -D warnings` clean.
- [ ] Red-team suite (SQLi/XSS/SSRF/path-traversal/brute-force) fully blocked.
- [ ] FP rate < 1% on `tests/corpus/benign/`.
- [ ] Each OWASP detector has ≥ 30 positive + ≥ 30 negative fixtures.
- [ ] 2-node cluster shares rate-limit + risk state via Redis (`StateBackend`).
