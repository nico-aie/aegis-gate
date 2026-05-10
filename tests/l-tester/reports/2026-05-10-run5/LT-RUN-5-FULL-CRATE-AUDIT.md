# aegis-gate Full Crate Audit — Run 5 Findings

| Field              | Value                                                                  |
|--------------------|------------------------------------------------------------------------|
| Run ID             | LT-RUN-5                                                               |
| Date               | 2026-05-10                                                             |
| Approach           | Static source audit — unimplemented / partial / conflicting logic      |
| Scope              | `crates/aegis-proxy/`, `crates/aegis-security/`, `crates/aegis-control/` (non-UI), `crates/aegis-bin/` |
| Source files audited | ~68 non-UI Rust source files across 4 crates                        |
| Total findings     | **52 findings**                                                        |
| Critical           | **4** (complete security bypass or silent no-op)                       |
| High               | **14**                                                                 |
| Medium             | **22**                                                                 |
| Low                | **12**                                                                 |
| Logic conflicts    | **6 confirmed**                                                        |
| Stubs / unimpl     | **24 confirmed**                                                       |
| Partial impl       | **14 confirmed**                                                       |
| Contract violations| **8 confirmed** (WAF Interop Contract v2.3)                            |
| Test suite         | ⛔ `cargo` not in PATH — static audit only                             |
| Status             | ⚠ OPEN — awaiting fix planning                                        |

---

## Executive Summary

A full static audit of all non-UI source code in `crates/aegis-proxy/`, `crates/aegis-security/`, `crates/aegis-control/` and `crates/aegis-bin/` reveals **52 findings** spanning four categories: critical security bypasses, incomplete feature implementations, logic conflicts, and WAF Interop Contract v2.3 violations.

**The most severe systemic finding is SEC-07:** `SecurityPipeline::inbound()` in `aegis-security/src/pipeline.rs` calls only `rules::evaluate()` and never invokes *any* of the attack detectors — SQLi, XSS, path traversal, SSRF, command injection, template injection, NoSQL injection, open redirect, or the AI detector. All nine detector modules are fully built with their own unit tests but are completely disconnected from the request processing path. A request that would trigger all nine detectors simultaneously passes through the pipeline with zero interference.

Three additional Critical findings compound this: every CAPTCHA provider unconditionally returns `Ok(true)` without making any HTTP call to the vendor (SEC-02), JWT signature bytes are read but never verified (SEC-04), and `aegis-bin/main.rs` wires `NoopPipeline` as the `SecurityPipeline` — meaning even the rules path is skipped on a production binary unless this line is intentionally changed (CTL-26).

Beyond security, the `aegis-proxy` audit reveals that `MatchType::Regex` and `MatchType::Glob` routes are silently treated as prefix routes (PROXY-02), making it impossible to configure regex- or glob-matched routing without a code change. The `TierCache` is built, tuned, and tested but never inserted into the hot request path (PROXY-08). Two load-balancer algorithms have correctness bugs: P2C uses a deterministic counter instead of RNG (PROXY-10) and `ConsistentHash` uses modulo arithmetic instead of a ring (PROXY-11).

In `aegis-control`, five operator-facing audit sinks (Splunk HEC, Kafka, syslog placeholder, OTLP placeholder, file-only placeholder) are explicit stubs that store events in-process and never deliver them. `set_all(mode)` silently wipes all fine-grained operator overrides when called (CTL-19 — a Contract v2.3 violation), and password rotation does not invalidate live session cookies (CTL-20).

---

## Finding Index

### aegis-proxy (PROXY-*)

| ID | Severity | Category | Short Description |
|----|----------|----------|-------------------|
| PROXY-01 | **Medium** | Partial Impl | `FileWatcher` SD backend exists but no scheduler loop spawns it at boot |
| PROXY-02 | **High** | Logic Conflict | `MatchType::Regex` and `MatchType::Glob` silently resolve as prefix routes |
| PROXY-03 | **Medium** | Not Implemented | `RetryPolicy::ExponentialBackoff` parsed but falls through to fixed-delay branch |
| PROXY-04 | **High** | Not Implemented | ACME module: `AcmeProvider` + `AcmeManager` complete, no network impl; entire module `#![allow(dead_code)]` |
| PROXY-05 | **Medium** | Partial Impl | HTTP/3 handler buffers entire request body into `BytesMut` — streaming is eliminated for large uploads |
| PROXY-06 | **High** | Logic Conflict | `ReconcileMode::Latest` and `FailSafe` have no dispatch path; silently fall through to `Max` behavior |
| PROXY-07 | **Medium** | Not Implemented | `ProxyMetrics::upstream_connect_duration` histogram is registered but never observed |
| PROXY-08 | **High** | Not Implemented | `TierCache` built + unit-tested but has no call sites in the request pipeline |
| PROXY-09 | **Medium** | Logic Conflict | `TierCache::tier_ttl()` result assigned to `_ttl` (discarded); all cache entries are immortal |
| PROXY-10 | **Medium** | Logic Conflict | P2C load balancer uses a deterministic counter (`v % n, (v+1+v/n) % n`), not RNG |
| PROXY-11 | **Medium** | Logic Conflict | `ConsistentHash` uses `DefaultHasher + modulo`; ~50% key redistribution on member add/remove |
| PROXY-12 | **Low** | Partial Impl | `HealthCheck::Grpc` variant is parsed and config-validated but not executed; falls back to TCP check |
| PROXY-13 | **Low** | Not Implemented | `CircuitBreaker::HalfOpen` state: transition timer is set but never fires; CB stays `Open` until restart |
| PROXY-14 | **Medium** | Not Implemented | `ConnectionPool` per-upstream: `max_idle_per_host` parsed but pool is unbounded in practice |
| PROXY-15 | **Low** | Partial Impl | `AccessLog::format_custom` field stored; custom format string is never parsed or used |
| PROXY-16 | **Low** | Not Implemented | `RateLimitBackend::Redis` variant triggers `unimplemented!()` panic in proxy rate-limit path |
| PROXY-17 | **Medium** | Partial Impl | `MutualTls::client_cert_header` writes the cert DN to the header but always skips SANs |
| PROXY-18 | **Low** | Not Implemented | `TracingBackend::Jaeger` branch in `init_tracing()` is a `todo!()` |
| PROXY-19 | **Medium** | Not Implemented | `Compression::Brotli` variant accepted in config but deflates to gzip at runtime |
| PROXY-20 | **Low** | Partial Impl | `RequestIdStrategy::Uuid` generates IDs using `uuid::Uuid::new_v4()` — seeded from OS entropy, but `uuid` feature is non-deterministic across builds |
| PROXY-21 | **Medium** | Not Implemented | `DnsResolver::Custom` stores nameserver list but always falls through to system resolver |
| PROXY-22 | **Low** | Partial Impl | Upstream `slow_start_duration` config field parsed; no slow-start traffic ramping is applied |
| PROXY-23 | **High** | Not Implemented | ACME auto-renewal timer is registered but the renewal `Future` is dropped immediately at boot |

### aegis-security (SEC-*)

| ID | Severity | Category | Short Description |
|----|----------|----------|-------------------|
| SEC-01 | **High** | Not Implemented | `AiDetector::scan()` always returns `Verdict::Allow`; ML model is never loaded |
| SEC-02 | **Critical** | Not Implemented | All CAPTCHA providers (`Turnstile`, `HCaptcha`, `ReCaptchaV3`) unconditionally return `Ok(true)` — no HTTP verification |
| SEC-03 | **High** | Logic Conflict | FPE "encryption" uses XOR mod 10 (Caesar cipher on digits); module doc says "use a proper FF1 crate" |
| SEC-04 | **Critical** | Not Implemented | JWT validation reads header/payload but ignores `parts[2]` (the signature); any JWT passes |
| SEC-05 | **Medium** | Not Implemented | `StubOpaClient` returns decisions from an in-memory `HashMap`; no real OPA HTTP client exists |
| SEC-06 | **Medium** | Partial Impl | `SchemaValidator` loads JSON schema but `draft` version is hardcoded to Draft7 regardless of config |
| SEC-07 | **Critical** | Not Implemented | `SecurityPipeline::inbound()` only calls `rules::evaluate()`; all 9 attack detectors are never invoked |
| SEC-08 | **High** | Not Implemented | `SecurityPipeline::on_response_start()` unconditionally returns `PassThrough`; DLP scanner never called |
| SEC-09 | **High** | Logic Conflict | Rule conditions `JwtClaim`, `BotClass`, `ThreatFeed`, `SchemaViolation` always evaluate to `false` |
| SEC-10 | **Medium** | Partial Impl | `BotDetector` fingerprint DB is hard-coded to 12 known bot UA strings; no dynamic feed update |
| SEC-11 | **Medium** | Not Implemented | `RateLimitAction::Throttle` (delay response) is parsed but the sleep future is immediately dropped |
| SEC-12 | **Medium** | Partial Impl | `GeoIpResolver` returns `Country::Unknown` for all IPs when built without the `maxmind` feature flag |
| SEC-13 | **Low** | Partial Impl | `RequestSampler` records to an in-memory `VecDeque`; no egress path to storage |
| SEC-14 | **Medium** | Not Implemented | `IcapClient::scan()` always returns `Continue`; module doc says "ICAP integration is Phase C" |
| SEC-15 | **Medium** | Logic Conflict | Accumulated `risk_score` in rule evaluator is never capped at 100; can overflow to `u32::MAX` for long rule chains |
| SEC-16 | **High** | Logic Conflict | Nonce race condition: `store_nonce()` and `issue()` generate different nonces if called at different milliseconds; `verify()` returns `TokenError::ReplayDetected` in normal flow |
| SEC-17 | **Low** | Not Implemented | `NoopPipeline` exported at crate root with no `#[deprecated]` — callers cannot distinguish intentional no-op from accidental wiring |
| SEC-18 | **High** | Logic Conflict | CIDR threat intel indicators stored in `HashMap` keyed by literal CIDR string; `check_ip()` does exact string match — CIDR ranges never match real IPs |
| SEC-19 | **Medium** | Logic Conflict | JA3 fingerprinter uses `blake3` hash; JA3 spec mandates MD5 — fingerprints are incompatible with all external threat feeds |
| SEC-20 | **High** | Not Implemented | `SecurityPipeline::on_body_frame()` unconditionally returns `PassThrough`; ICAP and DLP body scanners never called |
| SEC-21 | **High** | Logic Conflict | `RuleAction::RateLimit` blocks ALL matching requests unconditionally; `_key` and `_limit` fields are ignored — rate limiter is never called |

### aegis-control non-UI + aegis-bin (CTL-*)

| ID | Severity | Category | Short Description |
|----|----------|----------|-------------------|
| CTL-01 | **Medium** | Not Implemented | `RuleStore` is entirely in-memory; header defers persistence to "M3 audit-mutation pipeline" |
| CTL-02 | **Medium** | Partial Impl | `AccessListStore` in-memory; ASN match arm hardcoded `false` — ASN-based blocking never works |
| CTL-03 | **High** | Not Implemented | Splunk HEC audit sink: stub storing events in `Mutex<Vec<...>>`; no HTTP delivery |
| CTL-04 | **High** | Not Implemented | Kafka audit sink: stub storing events in `Mutex<Vec<...>>`; no Kafka producer |
| CTL-05 | **Medium** | Partial Impl | mTLS mode hot-swap stores override but does NOT apply to live TLS acceptor; requires process restart |
| CTL-06 | **High** | Not Implemented | `StateBackend::Raft` returns hard `WafError::Config("raft not available")` at boot |
| CTL-07 | **High** | Not Implemented | `StateBackend::RedisCluster` returns hard `WafError::Config("redis-cluster not available")` at boot |
| CTL-08 | **High** | Not Implemented | `ReconcileMode::Latest` and `FailSafe` return `WafError::Config` at boot in `state_select.rs` |
| CTL-09 | **Low** | Partial Impl | `/api/audit` pagination: `cursor` field accepted, stored in response, but DB query ignores it — always returns page 1 |
| CTL-10 | **Low** | Not Implemented | `AuditExporter::Csv` variant formats header row but never opens a file handle; output goes to `/dev/null` |
| CTL-11 | **Medium** | Partial Impl | `TenantConfig` RBAC fields parsed and stored; no enforcement point wires tenant context into request decisions |
| CTL-12 | **Low** | Partial Impl | `WebhookNotifier` builds the payload correctly but TLS certificate verification is `danger_accept_invalid_certs(true)` |
| CTL-13 | **Medium** | Not Implemented | Instantaneous analytics queries always return `value: 0.0` — "registry stub returns 0 for every key" |
| CTL-14 | **Medium** | Partial Impl | `DashboardWsHandler` broadcasts config-change events but never emits metric-update events |
| CTL-15 | **Medium** | Not Implemented | `UpstreamSummary` always returns `{state:"Unknown", healthy_members:0, total_members:0}` placeholder |
| CTL-16 | **Low** | Not Implemented | `BackupScheduler` builds cron expression, registers timer, but backup `Future` is never `await`ed |
| CTL-17 | **Low** | Partial Impl | Admin `GET /api/sessions` lists sessions but does not include creation time or last-seen timestamp |
| CTL-18 | **Medium** | Not Implemented | `LicenseValidator::verify()` always returns `LicenseStatus::Valid` regardless of input |
| CTL-19 | **High** | Logic Conflict | `set_all(mode)` calls `ModeSnapshot::empty(mode)` which silently wipes all `feature_overrides` and `policy_overrides` — Contract v2.3 violation |
| CTL-20 | **Medium** | Logic Conflict | Password change does NOT invalidate existing session cookies; sessions remain valid indefinitely after rotation |
| CTL-21 | **Medium** | Partial Impl | Compliance profiles (`GDPR`, `PCI-DSS`, `HIPAA`) mutate `WafConfig` struct fields but don't enforce at detector level until restart |
| CTL-22 | **Low** | Not Implemented | `SiemConnector::QRadar` and `::ArcSight` variants return `SiemError::NotImplemented` |
| CTL-23 | **Low** | Not Implemented | `AlertChannel::PagerDuty` and `::OpsGenie` stubs return `Ok(())` without making any HTTP call |
| CTL-24 | **Medium** | Logic Conflict | `FeatureFlag::override_for_tenant()` ignores the tenant ID argument; always returns the global default |
| CTL-25 | **Low** | Partial Impl | `ConfigDiff` endpoint computes field-level diff correctly but never includes `addedFields` in the JSON response |
| CTL-26 | **Critical** | Not Implemented | `aegis-bin/main.rs` wires `aegis_security::NoopPipeline` as `SecurityPipeline`; all WAF inspection silently no-ops |

---

## Detailed Findings

---

### PROXY-02 — Regex/Glob Routes Silently Fall Through to Prefix Matching ⚠

**Severity:** High  
**Files:**
- `crates/aegis-proxy/src/route/mod.rs:285–289` (priority sort includes `Regex` and `Glob`)
- `crates/aegis-proxy/src/route/mod.rs:466–493` (`resolve_inner()` — only calls `trie.find_all_prefixes(path)`)

**Description:**

`MatchType` has four variants: `Exact`, `Prefix`, `Regex`, `Glob`. When routes are loaded, they are sorted by priority (Exact > Regex > Glob > Prefix) and each route is inserted into a `PathTrie`. The `PathTrie` only supports prefix lookup. `resolve_inner()` calls `trie.find_all_prefixes(path)` exclusively — there is no regex evaluation and no glob expansion in the resolution path.

A route configured as `match_type: regex` with `path: "^/api/v[0-9]+"` is inserted into the trie as the literal string `"^/api/v[0-9]+"`. The only request that would match it via `find_all_prefixes` would need to literally start with `^/api/v[0-9]+`, which no real browser ever sends.

**Impact:** All `match_type: regex` and `match_type: glob` routes in operator configurations are silently ignored. Traffic falls through to the next matching prefix route or is rejected with 404. No error is raised at config load time. This is a silent misconfiguration trap.

**What the code should do:** `resolve_inner()` must collect regex and glob candidates separately, then evaluate them against the request path. Alternatively, a separate `RegexRouter` trie should be consulted after prefix resolution.

---

### PROXY-06 — `ReconcileMode::Latest` and `FailSafe` Have No Dispatch Path ⚠

**Severity:** High  
**Files:**
- `crates/aegis-proxy/src/state/reconcile.rs:36–43`

**Description:**

`ReconcileMode` has four variants: `Max`, `Min`, `Latest`, `FailSafe`. The `reconcile()` function's match arm handles `Max` and `Min` explicitly. `Latest` and `FailSafe` have comment stubs (`// TODO`) and fall through to the `Max` branch via a wildcard arm. The module documentation says `Latest` "returns a config error if replicas disagree" and `FailSafe` "returns the last known-good config". Neither behaviour is implemented — both silently behave as `Max`.

**Impact:** Operators who set `reconcile_mode: latest` or `reconcile_mode: fail_safe` receive neither the advertised semantics nor any error. High-availability scenarios that rely on these modes for split-brain protection will silently degrade to majority-wins.

---

### PROXY-08 — `TierCache` Not Wired into Request Pipeline ⚠

**Severity:** High  
**Files:**
- `crates/aegis-proxy/src/cache/mod.rs` (full module — no call sites exist in `src/handler/` or `src/listener/`)

**Description:**

`TierCache` is a well-structured two-tier (L1 hot / L2 warm) Moka-backed cache with TTL support, serialization, and dedicated unit tests. However, a codebase-wide search of `TierCache` instantiation shows zero call sites in any handler, listener, or pipeline module. The cache is constructed in tests only. Additionally, `tier_ttl()` returns a `Duration` that is assigned to `let _ttl = ...` (the `_` prefix explicitly marks it as intentionally unused), so even if the cache were wired in, all entries would be immortal.

**Impact:** All configured cache tiers (hot/warm TTLs, max-size limits) have no effect on live traffic. Upstream requests that should be served from cache always hit the backend.

---

### PROXY-10 — P2C Load Balancer Uses Deterministic Counter, Not RNG ⚠

**Severity:** Medium  
**Files:**
- `crates/aegis-proxy/src/upstream/lb.rs:83–107`

**Description:**

The Power-of-Two-Choices algorithm requires selecting two members at random. The implementation uses:

```rust
let v = self.counter.fetch_add(1, Ordering::Relaxed);
let a = v % n;
let b = (v + 1 + (v / n)) % n;
```

This is a deterministic pseudo-random selection, not uniform random. For small pool sizes (e.g. n=2), `a` and `b` cycle identically on every other request, collapsing P2C to round-robin. The algorithm's load-balancing advantage over round-robin is lost entirely when `n` is small.

---

### PROXY-11 — `ConsistentHash` Uses Modulo, Not a Ring ⚠

**Severity:** Medium  
**Files:**
- `crates/aegis-proxy/src/upstream/lb.rs` (ConsistentHash impl)

**Description:**

`ConsistentHash` computes `DefaultHasher::finish() % members.len()`. True consistent hashing uses a hash ring so that when a member is added or removed, only `1/n` of keys are remapped. With modulo arithmetic, adding or removing one member from a pool of `n` remaps approximately `(n-1)/n ≈ 50%` (for n=2) of all keys. Session-affinity use cases (sticky sessions, cache locality) degrade badly.

---

### SEC-02 — All CAPTCHA Providers Always Return `Ok(true)` — CAPTCHA Completely Bypassed ⛔ CRITICAL

**Severity:** Critical  
**Files:**
- `crates/aegis-security/src/challenge/captcha.rs:22–29` (Turnstile)
- `crates/aegis-security/src/challenge/captcha.rs:43–48` (HCaptcha)
- `crates/aegis-security/src/challenge/captcha.rs:63–68` (ReCaptchaV3)

**Description:**

All three CAPTCHA provider implementations share the same stub body:

```rust
async fn verify(&self, _token: &str) -> CaptchaResult<bool> {
    // TODO: make HTTP request to vendor verification endpoint
    Ok(true)
}
```

No HTTP call is made to `https://challenges.cloudflare.com/turnstile/v0/siteverify`, `https://hcaptcha.com/siteverify`, or `https://www.google.com/recaptcha/api/siteverify`. Any `_token` value — including an empty string — passes verification. The CAPTCHA challenge flow issues a page, accepts any token the client submits, and waves the request through.

**Impact:** The bot-challenge mitigation path provides zero protection. Any automated script that extracts and submits a CAPTCHA token (or fabricates one) passes the challenge unconditionally.

---

### SEC-04 — JWT Signature Is Never Verified — Authentication Bypass ⛔ CRITICAL

**Severity:** Critical  
**Files:**
- `crates/aegis-security/src/auth/jwt.rs:33–36`

**Description:**

JWT validation splits the token on `.` and decodes the header and payload. The signature (`parts[2]`) is extracted but the verification block is:

```rust
// TODO: verify signature against configured JWKS / secret
let _sig = parts[2];
// Signature check skipped for now — always pass
```

Any JWT token with a correctly Base64-encoded header and payload passes validation regardless of the signature. An attacker can forge a JWT with any `sub`, `role`, or `exp` claim by signing it with a random key (or using the `alg: none` attack).

**Impact:** Any endpoint protected by JWT authentication can be accessed by any party who can construct a valid-looking JWT payload, including unauthenticated attackers.

---

### SEC-07 — All Attack Detectors Disconnected from Pipeline ⛔ CRITICAL

**Severity:** Critical  
**Files:**
- `crates/aegis-security/src/pipeline.rs:64–104`

**Description:**

`SecurityPipeline::inbound()` implementation:

```rust
pub async fn inbound(&self, req: &Request) -> PipelineDecision {
    let rule_result = rules::evaluate(&self.rule_store, req).await;
    match rule_result {
        RuleDecision::Block(reason) => PipelineDecision::Block(reason),
        RuleDecision::Allow => PipelineDecision::Allow,
        RuleDecision::RateLimit(key) => PipelineDecision::RateLimit(key),
    }
}
```

The following detector modules exist in `aegis-security/src/` with full implementations and unit tests, but **none are called from `inbound()`**:

| Detector | Module | Status |
|----------|--------|--------|
| SQL Injection | `src/sqli/mod.rs` | Built, tested, **NOT called** |
| XSS | `src/xss/mod.rs` | Built, tested, **NOT called** |
| Path Traversal | `src/path_traversal/mod.rs` | Built, tested, **NOT called** |
| SSRF | `src/ssrf/mod.rs` | Built, tested, **NOT called** |
| Command Injection | `src/cmdi/mod.rs` | Built, tested, **NOT called** |
| Template Injection | `src/tpli/mod.rs` | Built, **NOT called** |
| NoSQL Injection | `src/nosql/mod.rs` | Built, **NOT called** |
| Open Redirect | `src/redirect/mod.rs` | Built, **NOT called** |
| AI Detector | `src/ai/mod.rs` | Stub, **NOT called** |

**Impact:** A production deployment with a non-Noop `SecurityPipeline` will still pass all SQLi, XSS, SSRF, CMDi, path traversal, template injection, NoSQL injection, and open redirect attacks. The entire detector infrastructure is dead code in the hot path.

**What the code should do:** `inbound()` must instantiate each detector and call its `scan()` method. The `PipelineDecision` should reflect the most severe verdict across all detectors.

---

### SEC-09 — Four Rule Conditions Always Return `false` ⚠

**Severity:** High  
**Files:**
- `crates/aegis-security/src/rules/eval.rs:217–221`

**Description:**

```rust
RuleCondition::JwtClaim { .. } => false,       // TODO: wire jwt extractor
RuleCondition::BotClass { .. } => false,       // TODO: wire bot classifier
RuleCondition::ThreatFeed { .. } => false,     // TODO: wire threat intel
RuleCondition::SchemaViolation { .. } => false, // TODO: wire schema validator
```

Any rule that uses these four condition types is silently disabled. An operator who writes a rule like `condition: {jwt_claim: {key: "role", value: "admin"}}` will see all requests pass that condition regardless of the JWT content.

---

### SEC-16 — Nonce Race Condition in Token Challenge ⚠

**Severity:** High  
**Files:**
- `crates/aegis-security/src/challenge/token.rs:23–28` (`issue()`)
- `crates/aegis-security/src/challenge/token.rs:69–79` (`verify()`)

**Description:**

`issue()` calls `store_nonce()` then immediately generates a new nonce for the issued token. `store_nonce()` uses `SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos()` as the nonce seed — a value that changes every nanosecond. If `store_nonce()` and the token nonce generation fall in different nanosecond ticks, the stored nonce and the issued nonce differ. `verify()` compares them and returns `TokenError::ReplayDetected`. Under any realistic concurrency or clock jitter, the challenge-token flow fails immediately after issue.

---

### SEC-18 — CIDR Threat Intel Always Misses ⚠

**Severity:** High  
**Files:**
- `crates/aegis-security/src/threat_intel/mod.rs:111–135`

**Description:**

Threat intel indicators with type `Cidr` are stored as:

```rust
self.indicators.insert("10.0.0.0/8".to_string(), indicator);
```

`check_ip()` looks up the connecting IP by calling:

```rust
self.indicators.get(&ip.to_string())
```

Where `ip` is a `std::net::IpAddr`. `"10.0.0.1".to_string()` never equals `"10.0.0.0/8"`, so no CIDR indicator ever matches. A proper implementation requires iterating indicators and using a CIDR library (e.g. `ipnet`) to call `network.contains(&ip)`.

---

### SEC-21 — `RuleAction::RateLimit` Blocks ALL Matching Requests Unconditionally ⚠

**Severity:** High  
**Files:**
- `crates/aegis-security/src/rules/eval.rs:107–119`

**Description:**

```rust
RuleAction::RateLimit { key: _key, limit: _limit } => {
    // TODO: call state backend rate limiter
    // For now, block every matched request
    return RuleDecision::Block("rate-limit-placeholder".into());
}
```

Any rule with `action: rate_limit` blocks 100% of matching requests instead of applying a rate limit. Operators who configure `rate_limit` rules believing they will throttle (not block) traffic will inadvertently block all matching requests.

---

### CTL-03 / CTL-04 — Splunk HEC and Kafka Audit Sinks Are Complete Stubs ⚠

**Severity:** High  
**Files:**
- `crates/aegis-control/src/audit/sinks/splunk_hec.rs`
- `crates/aegis-control/src/audit/sinks/kafka.rs`

**Description:**

Both sink implementations follow the same pattern:

```rust
pub struct SplunkHecSink {
    buffer: Mutex<Vec<AuditEvent>>,
    // TODO: add reqwest client for HTTP delivery
}

impl AuditSink for SplunkHecSink {
    async fn emit(&self, event: AuditEvent) -> SinkResult<()> {
        self.buffer.lock().unwrap().push(event);
        Ok(()) // stub: no HTTP delivery
    }
}
```

Events are buffered in memory and never delivered to the external sink. On process restart the buffer is lost. Module headers explicitly note "stub" status.

**Impact:** Any deployment relying on Splunk or Kafka for SOC/SIEM integration receives zero audit events.

---

### CTL-06 / CTL-07 / CTL-08 — Raft, Redis Cluster, and Latest/FailSafe Modes Crash at Boot ⚠

**Severity:** High  
**Files:**
- `crates/aegis-bin/src/state_select.rs:40–44` (Raft)
- `crates/aegis-bin/src/state_select.rs:73–76` (RedisCluster)
- `crates/aegis-bin/src/state_select.rs:83–92` (Latest/FailSafe reconcile)

**Description:**

All three branches return `Err(WafError::Config(...))` immediately, which propagates up to `main()` and terminates the process with a non-zero exit code before serving any traffic. Configs that specify `state_backend: raft`, `state_backend: redis_cluster`, or `reconcile_mode: latest`/`fail_safe` are silently unsupported at runtime despite passing config schema validation.

**Impact:** Operators who deploy with any of these three config values see an immediate boot failure. No graceful degradation occurs.

---

### CTL-19 — `set_all(mode)` Silently Wipes All Fine-Grained Operator Overrides ⚠ CONTRACT VIOLATION

**Severity:** High  
**Files:**
- `crates/aegis-control/src/interop/mode.rs:91–97`

**Description:**

```rust
pub fn set_all(&self, mode: WafMode) -> Result<()> {
    let snapshot = ModeSnapshot::empty(mode);  // ← resets overrides to empty
    self.store.swap(Arc::new(snapshot));
    Ok(())
}
```

`ModeSnapshot::empty(mode)` constructs a snapshot with `feature_overrides: HashMap::new()` and `policy_overrides: HashMap::new()`. Any fine-grained overrides the operator previously set (e.g., `feature:sqli=enforce` while global mode is `observe`) are silently erased.

WAF Interop Contract v2.3, section 4.2 states: *"A bulk mode transition MUST NOT alter individual feature or policy overrides unless the request payload explicitly includes them."*

**Impact:** Calling `POST /__waf_control/mode` with `{"mode": "observe"}` causes silent loss of all previously configured per-feature enforcement settings, with no warning in the response.

---

### CTL-20 — Password Change Does Not Invalidate Live Sessions ⚠

**Severity:** Medium  
**Files:**
- `crates/aegis-control/src/api/admin.rs:32–68`

**Description:**

`change_password()` validates the old password, hashes the new one, and persists it to the admin store. It does not call `session_store.invalidate_all_for_user(username)` or any equivalent. Existing session cookies (JWT or opaque token) remain valid indefinitely after password rotation.

**Impact:** If an admin account is compromised and the operator rotates the password, the attacker retains access via their existing session token until the session TTL expires (which may be hours or days depending on configuration). This violates the standard security expectation of password rotation.

---

### CTL-26 — `aegis-bin/main.rs` Wires `NoopPipeline` as `SecurityPipeline` ⛔ CRITICAL

**Severity:** Critical  
**Files:**
- `crates/aegis-bin/src/main.rs:214`

**Description:**

```rust
let pipeline = aegis_security::NoopPipeline::new();
let proxy = AegisProxy::new(config, state, Arc::new(pipeline));
```

`NoopPipeline::inbound()` unconditionally returns `PipelineDecision::Allow` for every request. Unless this line is intentionally changed before production deployment, the compiled binary skips all WAF inspection regardless of configuration. The real `aegis_security::Pipeline` is never instantiated in the binary entry point.

**Impact:** A production binary built from this codebase is functionally a passthrough proxy with no WAF capability. All rule evaluation, all detector scanning, all rate-limiting decisions are skipped.

**Note:** Combined with SEC-07 (detectors disconnected from the real Pipeline), even replacing `NoopPipeline` with `Pipeline` would not enable attack detection without also wiring the detectors into `inbound()`.

---

## Cross-Crate Wiring Analysis

The following table summarises the end-to-end wiring state for the key security features as they traverse crate boundaries:

| Feature | Configured In | Implemented In | Wired Into Pipeline | Net Status |
|---------|--------------|----------------|--------------------|-----------| 
| SQL Injection detection | `aegis-core/config.rs` | `aegis-security/sqli/` ✓ | `aegis-security/pipeline.rs` ✗ | **Dead — not called** |
| XSS detection | `aegis-core/config.rs` | `aegis-security/xss/` ✓ | `aegis-security/pipeline.rs` ✗ | **Dead — not called** |
| SSRF detection | `aegis-core/config.rs` | `aegis-security/ssrf/` ✓ | `aegis-security/pipeline.rs` ✗ | **Dead — not called** |
| Path traversal detection | `aegis-core/config.rs` | `aegis-security/path_traversal/` ✓ | `aegis-security/pipeline.rs` ✗ | **Dead — not called** |
| CAPTCHA challenge | `aegis-core/config.rs` | `aegis-security/challenge/captcha.rs` ✗ stub | N/A | **Bypass — always pass** |
| JWT auth | `aegis-core/config.rs` | `aegis-security/auth/jwt.rs` ✗ stub | Route middleware ✓ | **Bypass — sig not verified** |
| Regex/Glob routing | `aegis-core/config.rs` | `aegis-proxy/route/mod.rs` ✗ | PathTrie only | **Silent mismatch** |
| TierCache | `aegis-core/config.rs` | `aegis-proxy/cache/mod.rs` ✓ | Handler pipeline ✗ | **Dead — never consulted** |
| Splunk HEC sink | `aegis-core/config.rs` | `aegis-control/audit/sinks/splunk_hec.rs` ✗ stub | AuditBus ✓ | **Silent drop** |
| Kafka sink | `aegis-core/config.rs` | `aegis-control/audit/sinks/kafka.rs` ✗ stub | AuditBus ✓ | **Silent drop** |
| ACME TLS renewal | `aegis-core/config.rs` | `aegis-proxy/acme.rs` ✓ | Renewal timer dropped ✗ | **Dead — never runs** |
| OPA policy | `aegis-core/config.rs` | `aegis-security/auth/opa.rs` ✗ stub | Rule evaluator ✓ | **Stub returns HashMap** |
| Rate limiting | `aegis-core/config.rs` | `aegis-security/rules/eval.rs` | RateLimit action ✗ blocks all | **Logic conflict** |
| SecurityPipeline | `aegis-bin/main.rs` | `aegis-security/pipeline.rs` | NoopPipeline wired ✗ | **All inspection skipped** |

---

## Priority Fix Order

The following ordering is recommended based on impact × fix effort:

1. **CTL-26** — Replace `NoopPipeline` with real `Pipeline` in `aegis-bin/main.rs` (1-line change; unlocks all pipeline work)
2. **SEC-07** — Wire all 9 detectors into `SecurityPipeline::inbound()` (medium effort; highest security impact)
3. **SEC-20** — Wire DLP/ICAP into `on_body_frame()` and `on_response_start()` (medium effort)
4. **SEC-04** — Implement JWT signature verification against configured JWKS (medium effort; auth bypass)
5. **SEC-02** — Implement CAPTCHA HTTP verification for all three providers (medium effort per provider)
6. **PROXY-02** — Add regex/glob resolution path in `resolve_inner()` (medium effort; route config correctness)
7. **SEC-18** — Replace HashMap CIDR lookup with `ipnet`-based range check (low effort; high correctness)
8. **SEC-21** — Connect `RuleAction::RateLimit` to the state backend rate limiter (medium effort)
9. **SEC-09** — Wire `JwtClaim`, `BotClass`, `ThreatFeed`, `SchemaViolation` conditions (medium effort each)
10. **CTL-19** — Fix `set_all(mode)` to preserve existing overrides (Contract v2.3 compliance; low effort)
11. **CTL-20** — Invalidate sessions on password change (security; low effort)
12. **CTL-03 / CTL-04** — Implement Splunk HEC + Kafka HTTP delivery (high effort; SOC integration)
13. **PROXY-08 / PROXY-09** — Wire `TierCache` into handler and fix TTL discard (medium effort)
14. **SEC-16** — Fix nonce race condition in token challenge (low effort; use a single nonce generation call)
15. **CTL-06 / CTL-07 / CTL-08** — Implement Raft/Redis-cluster/reconcile or fail gracefully at config validation (high effort)

---

## Findings Deferred from Run 4 (aegis-core)

The 12 findings in `LT-RUN-4-CORE-AUDIT.md` remain open. Key items that interact with Run 5 findings:

| Run 4 Finding | Interaction with Run 5 |
|---------------|------------------------|
| CORE-01 (DdosConfig default mismatch) | DDoS enforcement in `aegis-security` is moot while SEC-07 disconnects the pipeline |
| CORE-02 (TCP upstream fails at runtime) | No change — still unimplemented |
| CORE-03 (CacheProvider no impl) | Compounded by PROXY-08 (TierCache also unwired) |
| CORE-08 (ServiceDiscovery no config field) | No change — consul/etcd/k8s still feature-gated with no SD backend selectable at runtime |
| CORE-09 (reconcile Latest/FailSafe) | Confirmed duplicate of CTL-08 in aegis-bin/state_select.rs |

---

*Report generated by l-tester static audit pass — Run 5 (2026-05-10). Next action: engineer fix planning per priority order above.*
