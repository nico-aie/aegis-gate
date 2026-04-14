# Member 2 — Security Pipeline

**Read [`shared-contract.md`](./shared-contract.md) first.**

**Mission:** implement `SecurityPipeline` end-to-end. Every request is
inspected, scored, and decided (allow / block / challenge / rate-limit)
before M1 forwards upstream; every response is scrubbed before M1
returns it.

**Crate:** `crates/aegis-security/`

---

## 1. Crate Layout

```
crates/aegis-security/
├── Cargo.toml
└── src/
    ├── lib.rs               # pub fn build(cfg, state, bus, metrics) -> Arc<dyn SecurityPipeline>
    ├── pipeline.rs          # impl SecurityPipeline for Pipeline
    ├── rules/
    │   ├── mod.rs           # Rule, RuleSet, hot-reload via ArcSwap
    │   ├── ast.rs           # Condition, Match, Action
    │   ├── parser.rs        # YAML -> AST
    │   ├── linter.rs        # id uniqueness, depth, priority sanity
    │   └── eval.rs          # priority-ordered evaluator
    ├── rate_limit/
    │   ├── mod.rs
    │   ├── sliding.rs       # sliding-window via StateBackend
    │   └── bucket.rs        # token bucket
    ├── ddos.rs              # per-IP burst + cluster spike + auto-block
    ├── detectors/
    │   ├── mod.rs           # trait Detector { fn inspect(&self, req) -> Vec<Signal> }
    │   ├── sqli.rs
    │   ├── xss.rs
    │   ├── path_traversal.rs
    │   ├── ssrf.rs
    │   ├── header_injection.rs
    │   ├── body_abuse.rs
    │   ├── recon.rs
    │   └── brute_force.rs
    ├── fingerprint/
    │   ├── mod.rs
    │   ├── ja4.rs           # parse ClientHello bytes from M1
    │   ├── ja3.rs
    │   └── h2.rs            # SETTINGS + pseudo-header order
    ├── risk/
    │   ├── mod.rs           # RiskEngine, score contributions, decay
    │   └── store.rs         # per-RiskKey state via StateBackend
    ├── challenge/
    │   ├── mod.rs           # ladder None → JS → PoW → CAPTCHA
    │   ├── token.rs         # HMAC-signed, nonce via StateBackend
    │   └── providers.rs     # Turnstile, hCaptcha, reCAPTCHA
    ├── ip_rep/
    │   ├── mod.rs           # blacklist/whitelist/trusted-proxy CIDR
    │   ├── asn.rs           # MaxMind ASN classification
    │   └── xff.rs           # XFF chain walker
    ├── bots.rs              # classifier tiers + good-bot reverse-DNS
    ├── threat_intel.rs      # feed ingestion (JSON/CSV/STIX-TAXII)
    ├── response_filter.rs   # stack trace scrub, IP mask, header harden
    ├── dlp/
    │   ├── mod.rs           # pattern library + actions
    │   └── fpe.rs           # AES-FF1
    ├── api_security.rs      # OpenAPI enforce/monitor/learn
    ├── auth/
    │   ├── mod.rs
    │   ├── forward.rs       # ForwardAuth subrequest
    │   ├── jwt.rs           # JWKS cache
    │   └── oidc.rs          # browser session (PASETO)
    └── icap.rs              # antivirus REQMOD/RESPMOD
```

---

## 2. Weekly Task Breakdown

### Week 1 — Rule Engine Core

**T1.1** — Rule AST + parser
- File: `src/rules/ast.rs`, `src/rules/parser.rs`
- Types:
  ```rust
  pub struct Rule {
      pub id: String,
      pub priority: u32,
      pub scope: Scope,
      pub when: Condition,
      pub then: Action,
      pub description: Option<String>,
  }
  pub enum Condition {
      All(Vec<Condition>), Any(Vec<Condition>), Not(Box<Condition>),
      IpIn(Vec<ipnet::IpNet>),
      PathMatches(MatchOp), HostMatches(MatchOp), Method(Vec<http::Method>),
      HeaderMatches { name: String, op: MatchOp },
      QueryMatches { name: String, op: MatchOp },
      BodyMatches(MatchOp),
      CookieMatches { name: String, op: MatchOp },
      JwtClaim { path: String, op: MatchOp },
      BotClass(Vec<String>),
      ThreatFeed { id: String, min_confidence: u8 },
      SchemaViolation,
      TenantIs(String),
  }
  pub enum MatchOp {
      Exact(String), Regex(regex::Regex),
      Wildcard(String), Contains(String), Prefix(String), Suffix(String),
  }
  pub enum Action {
      Allow, Block { status: u16 },
      Challenge { level: ChallengeLevel },
      RateLimit { key: RateKey, limit: u64, window_s: u32 },
      RaiseRisk(u32), Transform(TransformSpec), LogOnly,
  }
  pub enum Scope { Global, Tier(Tier), Route(String), Tenant(String) }
  ```
- Parser: `pub fn parse(yaml: &str) -> Result<Vec<Rule>>`
- Test: round-trip 10 rule fixtures, reject malformed (duplicate id, unknown field).

**T1.2** — Linter
- File: `src/rules/linter.rs`
- Checks: unique ids, max nesting depth (8), priority in [0, 10_000], regex compiles, referenced rule/pool ids exist.
- Signature: `pub fn lint(rules: &[Rule], cfg: &WafConfig) -> Result<()>`
- Test: one fixture per failure class.

**T1.3** — Evaluator
- File: `src/rules/eval.rs`
- `pub fn evaluate(rules: &[Rule], req: &RequestView, route: &RouteCtx) -> Option<Decision>`
- Priority-ordered, first terminal action wins. Non-terminal (`RaiseRisk`, `LogOnly`, `Transform`) accumulates then continues.
- Test: table-driven — 20 request/rule combinations with expected decisions.

**T1.4** — RuleSet hot reload
- File: `src/rules/mod.rs`
- `pub struct RuleSet(ArcSwap<Arc<Vec<Rule>>>)` with `reload(path) -> Result<()>` that **lints before swap**.
- Test: reload a broken file, assert running set is untouched and audit emits failure.

**T1.5** — Tier classifier
- File: `src/pipeline.rs`
- `fn classify_tier(route: Option<&RouteCtx>, req: &RequestView) -> (Tier, FailureMode)` — uses route override first, then falls back to path heuristic (`/login`, `/payments/*` → Critical, etc.).
- Test: 10 paths mapped to expected tier.

**Week 1 exit:** M1's NoopPipeline replaced by `Pipeline` stub wired to
rules only. A rule blocking `/evil` returns 403 via dashboard SSE.

---

### Week 2 — Rate Limit, DDoS, OWASP Detectors

**T2.1** — Sliding window rate limit
- File: `src/rate_limit/sliding.rs`
- `pub async fn check(state: &dyn StateBackend, key: &str, limit: u64, window_s: u32) -> Result<RateDecision>`
- Key format: `rl:{scope}:{tenant}:{id}:{bucket}`.
- Uses `StateBackend::sliding_window` (Lua on Redis, DashMap on in-memory).
- Test: property test — across 1k concurrent callers, count never exceeds limit.

**T2.2** — Token bucket
- File: `src/rate_limit/bucket.rs`
- `pub async fn take(state: &dyn StateBackend, key: &str, rate: f64, burst: u64) -> Result<bool>`
- Test: burst consumed instantly, refill linear.

**T2.3** — DDoS per-IP burst + cluster spike
- File: `src/ddos.rs`
- Per-IP sliding window → auto-block key `block:{ip}` with TTL.
- Cluster spike: compare rolling cluster RPS (cluster counter) vs `rolling_avg * spike_multiplier`. When DDoS mode active, tighten challenge thresholds.
- Per-tenant scope: flood against tenant A does not affect tenant B.
- Test: simulate 1k req/s from one IP, assert block within 2s, assert tenant isolation.

**T2.4** — OWASP detectors (one file each)
- Trait: `pub trait Detector: Send + Sync { fn id(&self) -> &'static str; fn inspect(&self, req: &RequestView) -> Vec<Signal>; }`
- `Signal { pub score: u32, pub tag: String, pub field: String }`
- Detectors required: SQLi, XSS, Path Traversal, SSRF, Header Injection, Body Abuse (oversize, deep nesting), Recon (dir scans, known tools), Brute Force (`state:fail:{ip}:{path}` counter).
- Each detector has ≥ 30 positive fixtures and ≥ 30 negative; FP rate < 1% on benign corpus.
- Test: `cargo test -p aegis-security detectors` runs the full matrix.

**Week 2 exit:** Red-team script with SQLi, XSS, SSRF payloads → all blocked, visible on dashboard with rule id.

---

### Week 3 — Fingerprint, Risk, Challenge

**T3.1** — JA4/JA3 parser
- File: `src/fingerprint/ja4.rs`, `ja3.rs`
- Input: ClientHello bytes. M1 exposes a hook: `on_client_hello(conn_id, bytes)` and stores the result in `ClientInfo::tls_fingerprint`.
- Output: `TlsFingerprint { ja3, ja4 }` hashed with per-deployment salt (`blake3`).
- Test: golden-file captures from curl/chrome/firefox/python-requests.

**T3.2** — HTTP/2 fingerprint
- File: `src/fingerprint/h2.rs`
- Input: SETTINGS frame + pseudo-header order. Output: stable string.
- Test: tonic vs chrome H2 hellos produce distinct fingerprints.

**T3.3** — Composite device id
- File: `src/fingerprint/mod.rs`
- `pub fn device_id(fp: &TlsFingerprint, h2: Option<&str>, ua: Option<&str>, header_order: &[String]) -> String` — `blake3` over the tuple, salted.

**T3.4** — RiskEngine
- File: `src/risk/mod.rs`
- `pub async fn score(&self, key: &RiskKey, signals: &[Signal]) -> u32`
- State: per-key score + last-update in `StateBackend`. Decay: `score = score * exp(-Δt / half_life)`.
- Canary rules (hit `/admin/.env`) set score to max instantly.
- Thresholds: `< 30` allow, `30..=70` challenge, `> 70` block.
- Test: decay test with mocked clock; canary rule test.

**T3.5** — Challenge ladder
- File: `src/challenge/mod.rs`
- `pub fn next_level(risk: u32, human_conf: u32, bot: BotClass, tier: Tier) -> Option<ChallengeLevel>`
- Returns escalation path None → JS → PoW → CAPTCHA → Block.

**T3.6** — Challenge tokens
- File: `src/challenge/token.rs`
- HMAC-signed (`blake3::Hasher::new_keyed`), single-use via nonce stored in `StateBackend` (`nonce:{hash}` TTL), non-downgradable within TTL.
- `pub fn issue(&self, key: &RiskKey, level: ChallengeLevel) -> String`
- `pub async fn verify(&self, token: &str) -> Result<ChallengeLevel>`
- Test: replay attack rejected; downgrade attempt rejected.

**T3.7** — CAPTCHA providers
- File: `src/challenge/providers.rs`
- Trait `CaptchaProvider { async fn verify(&self, client_token: &str, ip: IpAddr) -> Result<bool> }`
- Implementations: Turnstile, hCaptcha, reCAPTCHA v3 (HTTP POST to each).
- Test: wiremock for each provider.

---

### Week 4 — IP Reputation, Bots, Threat Intel

**T4.1** — CIDR lists + XFF walker
- Files: `src/ip_rep/mod.rs`, `src/ip_rep/xff.rs`
- Per-tenant blacklist/whitelist/trusted-proxies as `ipnet::IpNet` tries.
- XFF: walk right-to-left while peer ∈ trusted, pick first non-trusted as client; ignore XFF entirely if TCP peer not trusted.
- Test: spoofed XFF through untrusted peer is ignored.

**T4.2** — MaxMind ASN classifier
- File: `src/ip_rep/asn.rs`
- Load GeoLite2-ASN mmdb at boot; categorize: `residential`, `hosting`, `vpn`, `tor`, `bogon`. Configurable risk deltas.
- Test: known ASN fixtures.

**T4.3** — Bot classifier
- File: `src/bots.rs`
- Tiers: `human | good_bot | likely_bot | known_bad | unknown`.
- Signals: JA4, h2 fp, header order, UA entropy, reverse-DNS (cached in `moka`), threat feed, failed-challenge history.
- Good-bot verification: forward-confirmed reverse-DNS for Googlebot etc.
- Test: fixture captures for 10 known bots + 10 human browsers.

**T4.4** — Threat intel feeds
- File: `src/threat_intel.rs`
- Formats: plain text, CSV, JSON, STIX 2.1 over TAXII 2.1. Use `reqwest` + `serde_json`.
- Per-feed confidence & severity; TTL-respected eviction.
- Local override list wins.
- Provenance: every decision sourced from a feed carries `feed_id` + `confidence` in `AuditEvent::fields`.
- Test: mock TAXII server, import feed, assert block with provenance.

---

### Week 5 — Response Filter, DLP, API Security, Auth, ICAP

**T5.1** — Streaming response filter
- File: `src/response_filter.rs`
- Stack-trace scrub for Python/JVM/Node/Rust/PHP/.NET/Rails/Go.
- Internal-IP mask (RFC 1918, link-local, loopback, ULA).
- Strip `Server`, `X-Powered-By`, etc.
- Inject `X-Content-Type-Options`, `X-Frame-Options`, `HSTS`, `Referrer-Policy`, `Permissions-Policy`, `CSP`.
- Streaming frame processor — never buffer full body.
- Test: 1 GB body passes with constant memory.

**T5.2** — DLP patterns + actions
- File: `src/dlp/mod.rs`
- Patterns (with named `value` capture): credit card (Luhn-validated), SSN, IBAN (mod-97), email, phone, DOB, AWS/GCP/Azure/Stripe/GitHub/Slack/Twilio keys, PEM private keys, JWTs.
- Actions: `redact | mask | fpe | hmac | block`.
- Inbound and outbound.
- Every audit event also runs through DLP before emission.
- Test: golden synthetic body masks `4111-1111-1111-1111` → `****-****-****-1111`.

**T5.3** — FPE (AES-FF1)
- File: `src/dlp/fpe.rs`
- Use `aes-kw` + FF1 impl (or port known crate). Key versioning so existing tokens stay decryptable until retired.

**T5.4** — OpenAPI schema enforcement
- File: `src/api_security.rs`
- Load OpenAPI 3 YAML; validate path, method, parameters, headers, body against schema.
- Modes: `enforce`, `monitor`, `learn` (`learn` records observed traffic into a synthesized spec file).
- Errors carry JSON-pointer path in audit; client-facing detail minimized.
- Test: accept a matching POST; reject mass-assignment with unknown field.

**T5.5** — ForwardAuth
- File: `src/auth/forward.rs`
- `GET <address><original_path>`, copy whitelisted response headers onto forwarded request; failure honors route tier.
- Test: mock auth svc returns 401 → request blocked; returns 200 with headers → propagated.

**T5.6** — JWT validation
- File: `src/auth/jwt.rs`
- `jsonwebtoken` + JWKS cached in `moka` (TTL + stale-while-revalidate). Claims attached to `RequestCtx::fields` so rules can reference `user.role`.
- Test: valid/expired/wrong-iss/wrong-aud.

**T5.7** — ICAP antivirus
- File: `src/icap.rs`
- REQMOD (inbound) + RESPMOD (outbound) per RFC 3507. Clean-hash cache. Scan timeout applies route failure mode (fail-close for Critical).
- Test: against `clamav` in docker — EICAR test string blocked.

---

## 3. Pipeline Execution Order

In `src/pipeline.rs`, for each request:

```
1. trusted-proxy / XFF resolve  (W4)
2. ip blacklist + threat feed   (W4)
3. rate limit + DDoS burst      (W2)
4. tier classify + failure mode (W1)
5. route-level auth (JWT/FA)    (W5)
6. detectors → signals          (W2)
7. rule engine (priority)       (W1)
8. risk engine + challenge      (W3)
9. DLP inbound + OpenAPI        (W5)
10. return Decision
```

For responses:
```
1. DLP outbound
2. stack-trace scrub + header harden
3. security header injection
```

On any failure, route `failure_mode` decides `block(503)` vs `continue`.
Every short-circuit emits exactly one `AuditClass::Detection` event.

---

## 4. Metrics You Own

```
waf_rule_hits_total{rule_id,action}
waf_detector_hits_total{detector,tag}
waf_rate_limit_denied_total{scope,tenant}
waf_ddos_blocked_total{tenant}
waf_risk_score_bucket{bucket}          (histogram)
waf_challenge_total{level,outcome}
waf_threat_feed_hits_total{feed_id}
waf_dlp_matches_total{pattern,action}
waf_schema_violations_total{route}
waf_auth_failures_total{mechanism}
```

## 5. Audit Events You Emit

Every blocking / challenging / rate-limiting decision emits exactly one
`AuditClass::Detection` event with:
```
action, reason, rule_id, risk_score, tier, tenant_id,
fields: { detector, tag, field, feed_id?, confidence? }
```

## 6. Definition of Done (M2 exit criteria)

- [ ] Deliverables checklist `Requirement.md` §34: 8, 9, 20, 21, 22, 23, 24, 29.
- [ ] Red-team suite (SQLi/XSS/SSRF/path-traversal/brute force) fully blocked.
- [ ] FP rate < 1% on benign corpus (provided as `tests/corpus/benign/`).
- [ ] 2-node cluster shares rate-limit + risk state via Redis.
- [ ] All W1–W5 tests green.
- [ ] `cargo clippy -p aegis-security -- -D warnings` clean.

## 7. Working with an AI Assistant

```
Read: plans/shared-contract.md and plans/member-2-security-pipeline.md

Task: <T-number and title>
File: <path>
Types / signature: <copy>
Behavior: <copy>

Constraints:
- Depend only on aegis-core from the shared contract.
- Use dyn StateBackend — do not hardcode Redis or in-memory.
- Do not import from aegis-proxy or aegis-control.
- New detectors must ship ≥ 30 positive and ≥ 30 negative fixtures.
- Every short-circuit must emit exactly one AuditEvent.
- Run `cargo test -p aegis-security` before finishing.
```
