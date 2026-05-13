# aegis-security Full Crate Audit — Run 6 Findings

| Field                | Value                                                                  |
|----------------------|------------------------------------------------------------------------|
| Run ID               | LT-RUN-6                                                               |
| Date                 | 2026-05-13                                                             |
| Approach             | Static source audit — unimplemented / partial / conflicting logic + test-case generation |
| Scope                | `crates/aegis-security` (all non-generated source, 69 files)          |
| Source files audited | 69 `.rs` files, ≈20,398 lines                                         |
| Total findings       | **16**                                                                 |
| Critical             | **2**                                                                  |
| High                 | **4**                                                                  |
| Medium               | **5**                                                                  |
| Low                  | **5**                                                                  |
| Logic conflicts      | **2 confirmed**                                                        |
| Stubs / unimpl       | **4 confirmed** (3 now explicitly documented deferred via PR #9)      |
| Partial impl         | **5 confirmed**                                                        |
| Contract violations  | **1 confirmed**                                                        |
| Test suite           | ⚠ `cargo` not in sandbox PATH — tests written to `tests/lt_run6_audit_tests.rs`, pending `cargo test` |
| Status               | ⚠ OPEN — awaiting fix planning                                        |

---

## Executive Summary

The most impactful finding in this run remains **SEC-07**: `AegisSecurityPipeline::inbound()` still calls only `crate::rules::evaluate()` and never invokes `run_all_filtered_timed()`. All 12 concrete detectors (SQLi, XSS, SSRF, PathTraversal, CommandInjection, TemplateInjection, NoSql, OpenRedirect, HeaderInjection, BodyAbuse, BruteForce, Recon) are fully implemented with comprehensive unit tests — but none of them are reached during live request processing. The detectors are a complete, tested library that is completely bypassed in production. Every malicious payload reaching the data plane passes uninspected.

A new **Critical** finding joins this run: **EVAL-01** in `rules/eval.rs`. The `Condition::IpIn` check uses a string-prefix comparison (`ip_str.starts_with(network_addr_without_mask)`) rather than real CIDR network membership. As a result, a rule like `ip_in: ["10.0.0.0/24"]` only matches the single IP `10.0.0.0` (the network address itself) and fails to match any host within the subnet (10.0.0.1–10.0.0.254). This silently voids all CIDR-based block and rate-limit rules in the deployed rule engine.

Two previously Critical findings have been **reclassified** this run: JWT signature verification (`auth/jwt.rs`) and CAPTCHA stubs (`challenge/captcha.rs`) are now explicitly documented as zero-caller roadmap stubs via PR #9 (`#![allow(dead_code)]` + module doc "zero callers in aegis-proxy/src + aegis-bin/src"). These are tracked in the project's `Implement-Progress.md` and not re-filed here as active security bypasses in production — the proof-of-work path (`challenge/pow.rs`) is the production-shipped challenge.

Three **High** issues persist: ICAP content-scanning is not invoked on `on_response_start()` (SEC-20), the nonce race in `challenge/token.rs` is still present (SEC-16, though the module is deferred/zero callers), and `RuleAction::RateLimit` ignores both the `key` and `limit` fields — every request matching a rate-limit rule is immediately returned as `RateLimited` without consulting the `StateBackend` (EVAL-02).

On the positive side, several issues from Run 5 are confirmed fixed: SEC-18 (CIDR threat intel) now correctly uses `ipnet::IpNet::contains()`, `on_body_frame()` now properly invokes DLP redaction and stack-trace scrubbing (PR #7), and the `accumulated_risk` overflow uses `saturating_add`.

---

## Finding Index

### Pipeline Wiring (SEC-*)

| ID      | Severity     | Category       | Short Description                                                      |
|---------|--------------|----------------|------------------------------------------------------------------------|
| SEC-07  | **Critical** | Not Implemented | `inbound()` never calls detectors — all 12 attack detectors bypassed  |
| SEC-16  | **High**     | Logic Conflict  | Nonce race in `challenge/token.rs`: `store_nonce` and `issue` generate separate nonces |
| SEC-20  | **High**     | Not Implemented | `on_response_start()` always returns `PassThrough` — ICAP never called |

### Rule Evaluation (EVAL-*)

| ID        | Severity     | Category       | Short Description                                                      |
|-----------|--------------|----------------|------------------------------------------------------------------------|
| EVAL-01   | **Critical** | Logic Conflict  | `Condition::IpIn` uses string-prefix not CIDR — subnet rules never fire |
| EVAL-02   | **High**     | Partial Impl    | `RuleAction::RateLimit` ignores `key`/`limit`, always returns RateLimited immediately |

### Infrastructure (RL-*, RISK-*, DDOS-*)

| ID        | Severity     | Category       | Short Description                                                      |
|-----------|--------------|----------------|------------------------------------------------------------------------|
| RL-01     | **Medium**   | Partial Impl    | `IpRateLimiter` complete + tested but `#![allow(dead_code)]` — not wired into hot path |
| RISK-01   | **Medium**   | Partial Impl    | `RiskTracker` complete + tested but `#![allow(dead_code)]` — not wired into hot path |
| DDOS-01   | **Medium**   | Partial Impl    | `DdosRuntime::tick_rps()` never called by any timer — EWMA baseline perpetually stale |

### Threat Intelligence (THREAT-*)

| ID         | Severity     | Category       | Short Description                                                    |
|------------|--------------|----------------|----------------------------------------------------------------------|
| THREAT-01  | **Medium**   | Partial Impl    | `check_domain()` exact-match only — no wildcard subdomain matching   |

### Security Controls (BotClass / Auth)

| ID         | Severity     | Category       | Short Description                                                    |
|------------|--------------|----------------|----------------------------------------------------------------------|
| BOTS-01    | **Medium**   | Logic Conflict  | `BotClassifier` trusts caller-supplied `reverse_dns` without FCrDNS validation |

### Low-Severity / Design Notes

| ID         | Severity  | Category    | Short Description                                                        |
|------------|-----------|-------------|--------------------------------------------------------------------------|
| SEC-19     | **Low**   | Design Note  | JA3 uses blake3 (64-char output), incompatible with external MD5 feeds   |
| NOOP-01    | **Low**   | Partial Impl | `NoopSecurityPipeline` exported without `#[deprecated]` — easy to rewire accidentally |
| DLP-FPE    | **Low**   | Stub         | `dlp/fpe.rs` uses XOR-mod10 (Caesar cipher) instead of AES-FF1 — documented as stub |
| BASIC-01   | **Low**   | Design Note  | `auth/basic.rs` hashes passwords with blake3 (fast hash, not KDF) — deferred/zero callers |
| GQL-01     | **Low**   | Partial Impl | GraphQL complexity uses `depth * word_count` — alias/fragment bypass possible |

---

## Detailed Findings

---

### SEC-07 — All 12 Attack Detectors Disconnected from Inbound Pipeline ⛔

**Severity:** Critical
**Files:**
- `crates/aegis-security/src/pipeline.rs:147–157` (inbound implementation)
- `crates/aegis-security/src/detectors/mod.rs:258–279` (run_all_filtered_timed)

**Description:**

`AegisSecurityPipeline::inbound()` calls `crate::rules::evaluate()` to run rule-engine decisions, but never calls `run_all_filtered_timed()`. The function exists on line 258 and dispatches all 12 registered detectors (SQLi, XSS, SSRF, PathTraversal, CommandInjection, TemplateInjection, NoSqlInjection, OpenRedirect, HeaderInjection, BodyAbuse, BruteForce, Recon). None are reached in the hot path.

```rust
// pipeline.rs:147 — the entire inbound() body
pub async fn inbound(&self, req: &RequestView<'_>) -> Action {
    crate::rules::evaluate(&self.rules.snapshot(), req)
    // ← run_all_filtered_timed() is NEVER called here
}
```

The detectors themselves are complete: SQLi has 30 patterns + URL-decoding; XSS has 3-stage decode (raw → URL → HTML-entity); SSRF covers IPv4-mapped IPv6 forms; Recon covers Docker API, Spring Boot actuators, Kibana 7/8, Jenkins. All have 30–50 unit tests each. None of that work reaches production traffic.

**Impact:** An attacker sending any payload detectable by the 12 detectors — SQL injection, XSS, SSRF to AWS metadata, path traversal, command injection, reconnaissance probes — receives `Action::Allow`. The rule engine fires (if rules are loaded), but the detector layer is dead. This effectively nullifies the crate's primary security function.

**What the code should do:** `inbound()` must call `run_all_filtered_timed(self.detectors, req, ...)`, aggregate the returned `Signal` scores, and produce a `Block` or `Challenge` action when the accumulated score exceeds a configured threshold. The detectors and the scoring machinery already exist — only the call site is missing.

---

### SEC-16 — Nonce Race Condition in `challenge/token.rs` ⚠

**Severity:** High
**Files:**
- `crates/aegis-security/src/challenge/token.rs:23` (issue)
- `crates/aegis-security/src/challenge/token.rs:74` (store_nonce)
- `crates/aegis-security/src/challenge/token.rs:99` (generate_nonce)

**Description:**

`store_nonce()` (line 74) and `issue()` (line 23) each make an independent call to `generate_nonce(key)`. `generate_nonce()` derives its value from `timestamp_ms()` which returns the current Unix millisecond. If the two calls execute in different milliseconds, the nonce stored in the state backend (`N1`) differs from the nonce embedded in the token (`N2`), causing every subsequent `verify()` to return `TokenError::ReplayDetected` for a legitimately issued token.

```rust
// token.rs:74 — stores N1
pub fn store_nonce(&self, key: &str) -> String {
    let nonce = generate_nonce(key);   // ← N1 (timestamp at call T1)
    self.state.put_nonce(&nonce, ...);
    nonce
}

// token.rs:23 — embeds N2 (may differ!)
pub fn issue(&self, key: &str) -> Token {
    let nonce = generate_nonce(key);   // ← N2 (timestamp at call T2, T2 ≠ T1 possible)
    Token { nonce, ... }
}
```

Note: `challenge/token.rs` is marked `#![allow(dead_code)]` (PR #9); `challenge/pow.rs` is the production-deployed challenge. However, if `token.rs` is ever wired, this race would cause intermittent challenge failures at scale.

**Impact:** Challenge tokens issued by a high-throughput issuer fail verification non-deterministically, causing legitimate users to be repeatedly rejected. Under load, nearly all challenges would fail at millisecond boundaries.

**What the code should do:** Call `generate_nonce()` once, pass the result to both `store_nonce()` and `issue()`. Or adopt the same `put_nonce` / `consume_nonce` state-backend pattern that `pow.rs` uses correctly.

---

### SEC-20 — `on_response_start()` Always Returns PassThrough — ICAP Not Called ⚠

**Severity:** High
**Files:**
- `crates/aegis-security/src/pipeline.rs:149–157` (on_response_start stub)
- `crates/aegis-security/src/content/icap/mod.rs` (IcapClient trait + StubIcapClient)
- `crates/aegis-security/src/content/icap/tcp.rs` (real IcapTcpClient)

**Description:**

`on_response_start()` unconditionally returns `OutboundAction::PassThrough` regardless of response headers or status. A real `IcapTcpClient` exists in `content/icap/tcp.rs` with full RFC 3507 framing, timeout handling, EICAR detection tests, and fail-open/fail-closed modes — but it is never called from the pipeline.

```rust
// pipeline.rs:149
async fn on_response_start(&self, _resp: &ResponseStartView<'_>) -> OutboundAction {
    OutboundAction::PassThrough   // ← always, IcapTcpClient never consulted
}
```

**Impact:** Malware/viruses in response bodies, DLP-violating data in API responses (exposed PII, credentials), and server-side data exfiltration pass through without inspection. The ICAP scanning infrastructure is deployed but produces no security effect.

**What the code should do:** `on_response_start()` should call `self.icap_client.scan(IcapMode::Respmod, ...)` on the response body and return `OutboundAction::Block` when the scanner returns `ScanResult::Infected`. At minimum, response headers indicating a large binary body should trigger a scan before passing through.

---

### EVAL-01 — `Condition::IpIn` Uses String-Prefix, Not CIDR Network Match ⛔

**Severity:** Critical
**Files:**
- `crates/aegis-security/src/rules/eval.rs:195–201` (IpIn evaluation)

**Description:**

The `IpIn` condition evaluation extracts the network address from a CIDR string by splitting on `/` and taking the left side, then checks if the request IP string starts with that network address. This is not CIDR matching.

```rust
// eval.rs:195–201
Condition::IpIn { cidrs } => {
    let ip_str = req.peer.ip().to_string();
    cidrs.iter().any(|cidr| {
        ip_str.starts_with(cidr.split('/').next().unwrap_or(cidr))
        //     ^^^^^^^^^^^^ string prefix check — NOT network membership
    })
}
```

For `cidr = "10.0.0.0/24"`: the network address is `"10.0.0.0"`. `"10.0.0.1".starts_with("10.0.0.0")` = `false`. So IPs `10.0.0.1` through `10.0.0.255` all fail the check — the rule fires only for the single network address `10.0.0.0`. Every CIDR-based block/allow/rate-limit rule in the operator's rule file is silently ineffective.

For contrast, `threat_intel/mod.rs` was fixed in Run 5 (PR #8) to use `ipnet::IpNet::contains()`. The same fix is needed here.

**Impact:** All operator-configured `ip_in` conditions using CIDR notation silently fail to match any host IP. Block rules scoped to address ranges provide no protection. Allowlists pass traffic from unauthorized subnets. This is a silent, total bypass of IP-based access control.

**What the code should do:** Parse each CIDR with `ipnet::IpNet::from_str(cidr)` and use `net.contains(&client_ip)`. The `ipnet` crate is already in `Cargo.toml` (used in `threat_intel/mod.rs` and `ip_rep/`).

```rust
// Correct fix:
Condition::IpIn { cidrs } => {
    let ip = req.peer.ip();
    cidrs.iter().any(|cidr| {
        cidr.parse::<ipnet::IpNet>()
            .map(|net| net.contains(&ip))
            .unwrap_or(false)
    })
}
```

---

### EVAL-02 — `RuleAction::RateLimit` Ignores `key` and `limit` Fields ⚠

**Severity:** High
**Files:**
- `crates/aegis-security/src/rules/eval.rs:107–119` (RateLimit arm)

**Description:**

The `RuleAction::RateLimit` arm in `evaluate_with_ctx()` reads `window_s` for the retry-after value but silently ignores the `key` (discriminator string for state-backend lookup) and `limit` (maximum allowed requests). It returns `Action::RateLimited` immediately on every matching request without consulting the `StateBackend`:

```rust
// eval.rs:107–119
RuleAction::RateLimit { key, limit, window_s } => {
    // key:   ← never used
    // limit: ← never used
    Action::RateLimited {
        retry_after_s: *window_s,   // window is used only for retry-after
    }
}
```

This means any request matching a rule whose `then:` is `rate_limit:` is **always** rate-limited, on the very first request, regardless of how many prior requests have been made. A `limit: 1000` rule and a `limit: 1` rule are functionally identical.

**Impact:** Any operator-configured rate-limit rule blocks 100% of matching traffic unconditionally. Operators using rate-limiting to allow high volumes of legitimate traffic (e.g., API calls from trusted consumers) will see total access denial. This is a silent correctness inversion: a rule meant to _allow_ up to N requests _blocks_ all of them.

**What the code should do:** The arm must build a state-backend key, call `crate::rate_limit::sliding::check(state, &key, *limit, *window_s)`, and return `Allow` if the window is not exhausted or `RateLimited` if it is. This requires threading the `StateBackend` reference into `evaluate_with_ctx()`.

---

### RL-01 — `IpRateLimiter` Complete but Marked `#![allow(dead_code)]` ℹ️

**Severity:** Medium
**Files:**
- `crates/aegis-security/src/rate_limit/ip_limiter.rs:29` (`#![allow(dead_code)]` directive)

**Description:**

`IpRateLimiter` is a fully-featured per-IP sliding-window rate limiter backed by `DashMap<IpAddr, VecDeque<Instant>>`. It supports hot-config-reload via `ArcSwap`, idle-IP sweep to bound memory, deterministic `consume_at()` for tests, and 12 unit tests covering boundary, concurrency, hot-reload, and recovery scenarios. The module is marked `#![allow(dead_code)]` and has zero call sites in the proxy hot path.

**Impact:** The per-IP flood guard described in the comment ("volumetric guard at the local node") provides no protection. High-RPS single-IP attacks are not throttled at the node level.

**What the code should do:** Wire `IpRateLimiter::consume(peer_ip)` early in the data-plane request handler, before heavy security checks. The limiter's design comment explicitly anticipates this: "added one for a single-IP volumetric guard would be premature — [but] a flooding source IP needs to be blocked at the *local* node anyway."

---

### RISK-01 — `RiskTracker` Complete but Marked `#![allow(dead_code)]` ℹ️

**Severity:** Medium
**Files:**
- `crates/aegis-security/src/risk/tracker.rs:29` (`#![allow(dead_code)]` directive)

**Description:**

`RiskTracker` provides lifetime strikes, trust recovery, adaptive mitigation thresholds, hot-swappable config, per-IP `level_with()` for per-tier overrides, and `top()` for forensics. All 20+ unit tests pass (by inspection). The module has `#![allow(dead_code)]` and no callers in the proxy data plane.

**Impact:** Malicious events are not accumulated. Strike-block, challenge escalation, and trust recovery do not apply to any live traffic. The `RiskEngine` (legacy engine) is also not visibly wired — risk scoring is effectively inactive for live requests.

**What the code should do:** After a detector signal above threshold, call `tracker.record_malicious(ip, delta)` and use `tracker.level(ip)` to gate the `Challenge` / `Block` decision. Wire `tracker.record_clean(ip)` for clean requests to enable trust recovery.

---

### DDOS-01 — `DdosRuntime::tick_rps()` Never Called by Any Timer ℹ️

**Severity:** Medium
**Files:**
- `crates/aegis-security/src/ddos.rs:147–149` (tick_rps on DdosRuntime)
- `crates/aegis-security/src/ddos.rs:255–271` (DdosDetector::tick_rps EWMA logic)

**Description:**

`DdosDetector::tick_rps()` is the EWMA update function: it reads the accumulated `rolling_rps` counter, computes a new baseline with a 0.9/0.1 exponential weight, and activates/deactivates `spike_active` based on the multiplier threshold. Without periodic calls, `baseline_rps` stays at its initial value of 100 and `spike_active` never fires (or fires incorrectly if `rolling_rps` is never reset).

A search of the codebase shows no timer task or background job that calls `tick_rps()`. The `DdosRuntime` wrapper exposes `tick_rps()` as a public method, indicating it was designed to be called externally, but no wiring exists.

**Impact:** Cluster-level spike detection is permanently inactive. The `tightened_per_ip_rps` behaviour during spike mode never engages. Baseline EWMA does not track actual traffic patterns.

**What the code should do:** Start a `tokio::spawn` background task that calls `runtime.tick_rps()` every second (or at a configurable interval). Recommended location: `aegis-proxy/src/main.rs` alongside the DDoS runtime initialization.

---

### THREAT-01 — Domain Threat Intel Uses Exact Match Only ℹ️

**Severity:** Medium
**Files:**
- `crates/aegis-security/src/threat_intel/mod.rs` (check_domain)

**Description:**

`check_domain()` performs a direct `HashMap::get(domain)` lookup on `exact_host_indicators`. A threat feed entry for `malware-c2.net` does not match `beacon.malware-c2.net` or `tier1.download.malware-c2.net`. Real-world C2 and malware domains almost always use subdomains for beacons; exact-only matching misses the vast majority of these.

```rust
pub fn check_domain(&self, domain: &str) -> Option<&Indicator> {
    self.exact_host_indicators.get(domain)   // ← exact only
}
```

**Impact:** Threat feed entries for known-malicious domains provide near-zero protection. A C2 operator using `beacon.evil.com` is not blocked even when `evil.com` is in the feed.

**What the code should do:** After the exact lookup, walk the domain hierarchy — for `a.b.evil.com`, also check `b.evil.com` and `evil.com`. A simple loop: `while let Some(idx) = domain.find('.') { domain = &domain[idx+1..]; if let Some(i) = check_exact(domain) { return Some(i); } }`.

---

### BOTS-01 — `BotClassifier` Trusts Caller-Supplied `reverse_dns` Without FCrDNS ℹ️

**Severity:** Medium
**Files:**
- `crates/aegis-security/src/bots.rs:84–89` (good-bot rDNS check)

**Description:**

`classify()` checks if `signals.reverse_dns.ends_with("googlebot.com")` to classify as `GoodBot`. The `BotSignals` struct is caller-populated; there is no internal DNS lookup or forward-confirmed reverse DNS (FCrDNS) validation. An attacker can supply `reverse_dns: Some("crawl-66-249-66-1.googlebot.com")` and receive `GoodBot` classification, bypassing any challenge tier applied to automated traffic.

**Impact:** Bot mitigation is bypassable by supplying a crafted `reverse_dns` value. This is only exploitable if the caller is supplied attacker-controlled input for this field (e.g., trusting a `Cf-Connecting-IP` or X-Forwarded-For header without verification).

**What the code should do:** FCrDNS validation: perform a DNS PTR lookup of the client IP to get the hostname, then perform a forward A/AAAA lookup of that hostname to confirm it resolves back to the same IP. Only then classify as GoodBot. Alternatively, document that the caller is responsible for performing FCrDNS and that the field must not be populated from request headers.

---

### SEC-19 — JA3 Uses blake3 Instead of MD5 ℹ️

**Severity:** Low
**Files:**
- `crates/aegis-security/src/fingerprint/ja3.rs` (hash_ja3_string)

**Description:**

JA3 is defined as MD5(canonical_string), producing a 32-char hex fingerprint. This implementation uses `blake3::hash()`, producing a 64-char hex fingerprint. The choice is documented ("We use blake3 instead of MD5 for security") and intentional, but it makes every fingerprint incompatible with external JA3 threat feeds, blocklists, and detection rules.

**Impact:** The JA3 field emitted in observability headers and audit events cannot be cross-referenced with any external feed. Threat hunters comparing against published JA3 hashes will find no matches.

**What the code should do:** If external feed compatibility is required, add an `md5_ja3()` variant for cross-referencing while keeping blake3 as the internal fingerprint. Alternatively, document explicitly that this deployment's JA3 is not interoperable.

---

### NOOP-01 — `NoopSecurityPipeline` Exported Without `#[deprecated]` ℹ️

**Severity:** Low
**Files:**
- `crates/aegis-security/src/noop.rs`
- `crates/aegis-security/src/lib.rs` (pub use noop::...)

**Description:**

`NoopSecurityPipeline` is exported at the crate root without a `#[deprecated]` attribute. It unconditionally returns `Action::Allow` from `inbound()` and `OutboundAction::PassThrough` from all response methods. The root cause of CTL-26 (Run 5) — `aegis-bin/src/main.rs` wiring the Noop instead of the real pipeline — persists partly because there is no compiler-level indication that this type should not be used in production.

**Impact:** Any engineer reaching for `aegis_security::NoopSecurityPipeline` in a new binary or test harness will get a silent security bypass with no warning.

**What the code should do:** Add `#[deprecated(note = "Use AegisSecurityPipeline for production. NoopSecurityPipeline bypasses all security checks.")]` to the struct declaration. Also add `#![allow(deprecated)]` internally where Noop is used in tests.

---

### DLP-FPE — `dlp/fpe.rs` Uses XOR-mod10, Not AES-FF1 ℹ️

**Severity:** Low
**Files:**
- `crates/aegis-security/src/dlp/fpe.rs` (entire module)

**Description:**

The format-preserving encryption module uses `(digit + key_byte) % 10` — a Caesar cipher over decimal digits. The module comment says "Stub: XORs with key bytes for demonstration. Real impl would use FF1." The `_reverse_xor_digits` function has an underscore prefix (dead-code marker). This is a documented stub.

**Impact:** PAN and other DLP-redacted values are not cryptographically protected; they are trivially reversible. However, `dlp::redact()` (which calls fpe) already replaces matched values with `[REDACTED:TYPE]` in the pipeline path — the FPE path is used only when an operator explicitly opts into tokenization rather than redaction.

**What the code should do:** Replace with an `aes-ff1` implementation (the `ff1` crate) before enabling the tokenization path in production.

---

### BASIC-01 — `auth/basic.rs` Hashes Passwords with blake3 (Not a KDF) ℹ️

**Severity:** Low
**Files:**
- `crates/aegis-security/src/auth/basic.rs:36` (add_user)

**Description:**

Passwords are stored as `blake3::hash(password.as_bytes())`. blake3 is extremely fast (~1 GB/s), making brute-force attacks trivial for short or dictionary passwords. The module is `#![allow(dead_code)]` (PR #9, zero callers). Filed as Low because it is deferred.

**Impact:** If ever wired, low-entropy passwords are vulnerable to offline brute-force if the password database is compromised.

**What the code should do:** Use argon2 (or bcrypt) for password hashing. The `argon2` crate is already commonly available in the Rust ecosystem.

---

### GQL-01 — GraphQL Complexity Uses Coarse Word-Count Formula ℹ️

**Severity:** Low
**Files:**
- `crates/aegis-security/src/api_security/graphql.rs:46–73` (analyze_query)

**Description:**

Complexity is computed as `max_depth * node_count` where `node_count` counts all non-keyword word tokens in the query string. This misses field aliases (which multiply execution cost without increasing apparent depth), fragments (which can be expanded many times at different call sites), and `@defer`/`@stream` directives. A sophisticated GraphQL abuse query can stay under the `max_complexity` threshold while generating O(N²) backend calls.

**Impact:** GraphQL query complexity limiting provides partial protection only. Determined attackers with knowledge of the formula can craft queries that bypass it.

**What the code should do:** Implement proper field cost accounting using a schema-aware complexity visitor. At minimum, count fragment spreads as their expansion cost and count aliases as separate fields.

---

## Cross-Crate Wiring Analysis

| Feature                  | Configured In             | Implemented In                        | Wired Into Pipeline            | Net Status              |
|--------------------------|---------------------------|---------------------------------------|--------------------------------|-------------------------|
| SQLi detector            | `detectors/mod.rs`        | `detectors/sqli.rs` ✓                | `pipeline.rs::inbound()` ✗     | **Dead — not called**   |
| XSS detector             | `detectors/mod.rs`        | `detectors/xss.rs` ✓                 | `pipeline.rs::inbound()` ✗     | **Dead — not called**   |
| SSRF detector            | `detectors/mod.rs`        | `detectors/ssrf.rs` ✓                | `pipeline.rs::inbound()` ✗     | **Dead — not called**   |
| PathTraversal detector   | `detectors/mod.rs`        | `detectors/path_traversal.rs` ✓      | `pipeline.rs::inbound()` ✗     | **Dead — not called**   |
| CommandInjection detector| `detectors/mod.rs`        | `detectors/command_injection.rs` ✓   | `pipeline.rs::inbound()` ✗     | **Dead — not called**   |
| Recon detector           | `detectors/mod.rs`        | `detectors/recon.rs` ✓               | `pipeline.rs::inbound()` ✗     | **Dead — not called**   |
| BruteForce detector      | `detectors/mod.rs`        | `detectors/brute_force.rs` ✓         | `pipeline.rs::inbound()` ✗     | **Dead — not called**   |
| NoSql/Template/Header/Body detectors | `detectors/mod.rs` | individual `detectors/*.rs` ✓  | `pipeline.rs::inbound()` ✗     | **Dead — not called**   |
| DLP response redaction   | `pipeline.rs`             | `dlp/mod.rs` ✓                       | `pipeline.rs::on_body_frame()` ✓| **Working** *(fixed PR #7)* |
| Stack trace scrubbing    | `pipeline.rs`             | `response_filter.rs` ✓               | `pipeline.rs::on_body_frame()` ✓| **Working** *(fixed PR #7)* |
| ICAP content scan        | `config`                  | `content/icap/tcp.rs` ✓              | `pipeline.rs::on_response_start()` ✗| **Dead — not called** |
| CIDR threat intel        | `config`                  | `threat_intel/mod.rs` ✓ (ipnet)      | `pipeline.rs::inbound()` ✗     | **Dead — not called** *(SEC-07)* |
| IpIn CIDR rule condition | `rules/eval.rs`           | `eval.rs:195` ✗ (prefix bug)         | rule evaluation ✓ (called)     | **Logic conflict**      |
| RateLimit rule action    | `rules/eval.rs`           | `eval.rs:107` ✗ (state ignored)      | rule evaluation ✓ (called)     | **Logic conflict**      |
| IpRateLimiter            | `rate_limit/ip_limiter.rs`| `ip_limiter.rs` ✓                    | hot path ✗                     | **Dead — not called**   |
| RiskTracker              | `risk/tracker.rs`         | `tracker.rs` ✓                       | hot path ✗                     | **Dead — not called**   |
| DDoS detection (per-IP)  | `ddos.rs`                 | `DdosDetector::check()` ✓            | needs wiring check             | **Partial** *(tick unwired)* |
| PoW challenge            | `challenge/pow.rs`        | `PowIssuer` ✓                        | challenge flow ✓               | **Working**             |
| JWT auth                 | `auth/jwt.rs`             | sig parsing only ✗                   | zero callers                   | **Stub — documented** *(PR #9)* |
| CAPTCHA                  | `challenge/captcha.rs`    | all providers return Ok(true) ✗      | zero callers                   | **Stub — documented** *(PR #9)* |
| OPA policy               | `auth/opa.rs`             | in-memory HashMap ✗                  | zero callers                   | **Stub — documented** *(PR #9)* |
| HMAC request signing     | `api_security/hmac_sign.rs`| `verify()` ✓                        | zero callers                   | **Dead — not called**   |
| GraphQL guard            | `api_security/graphql.rs` | `analyze_query()` ✓                  | zero callers                   | **Dead — not called**   |
| API key validation       | `api_security/api_keys.rs`| `ApiKeyStore::verify()` ✓            | zero callers                   | **Dead — not called**   |
| Bot classification       | `bots.rs`                 | `BotClassifier::classify()` ✓        | zero callers                   | **Dead — not called**   |
| Domain threat intel      | `threat_intel/mod.rs`     | exact-match only ✗                   | zero callers *(ICAP/pipeline)* | **Partial impl**        |

---

## Priority Fix Order

1. **SEC-07** — Wire `run_all_filtered_timed()` into `inbound()` and accumulate scores into Block/Challenge decisions. Every attack detection investment to date is blocked by this single missing call site. _(effort: medium)_

2. **EVAL-01** — Replace the `Condition::IpIn` string-prefix check with `ipnet::IpNet::contains()`. The `ipnet` crate is already in `Cargo.toml`. One-line fix, but silently voids all CIDR-based rules until addressed. _(effort: low)_

3. **EVAL-02** — Wire `StateBackend` into `evaluate_with_ctx()` and call `sliding::check()` in the `RateLimit` arm. Without this, any rule using `rate_limit:` unconditionally blocks all matching traffic. _(effort: medium)_

4. **SEC-20** — Invoke `IcapTcpClient::scan()` from `on_response_start()`. The TCP client is complete; the wiring is the only gap. _(effort: low)_

5. **DDOS-01** — Spawn a `tokio::interval` task calling `runtime.tick_rps()` every second in `aegis-proxy/src/main.rs`. Without this, the EWMA never tracks live traffic patterns. _(effort: low)_

6. **THREAT-01** — Add parent-domain walk to `check_domain()` to support wildcard subdomain matching. _(effort: low)_

7. **RL-01 + RISK-01** — Remove `#![allow(dead_code)]` and wire `IpRateLimiter` and `RiskTracker` into the data plane request handler. _(effort: medium each)_

8. **NOOP-01** — Add `#[deprecated]` to `NoopSecurityPipeline` to prevent accidental rewiring. _(effort: low)_

---

## Findings Deferred from Previous Run(s)

| Prior Run Finding | Status in This Run                                                             |
|-------------------|--------------------------------------------------------------------------------|
| SEC-07            | Still open — `run_all_filtered_timed()` still not called from `inbound()`     |
| SEC-02 (CAPTCHA)  | Reclassified — now documented stub via PR #9, zero callers, `#[allow(dead_code)]` |
| SEC-04 (JWT)      | Reclassified — now documented stub via PR #9, zero callers, `#[allow(dead_code)]` |
| SEC-16 (nonce race)| Still open in code — module is deferred/zero callers (PR #9)                 |
| SEC-18 (CIDR threat intel) | **Fixed** — `ipnet::IpNet::contains()` (PR #8)                     |
| SEC-19 (JA3/blake3) | Still open — intentional design decision, documented                        |
| SEC-20 (ICAP)     | Still open — `on_response_start()` still returns PassThrough unconditionally  |
| CTL-26 (Noop in main.rs) | Out of scope for this audit (aegis-bin, not aegis-security)             |
| RISK-OVERFLOW     | **Fixed** — `saturating_add` in `accumulated_risk`                            |
| BODY-DLP          | **Fixed** — `on_body_frame()` now calls DLP redact + scrub (PR #7)            |

---

## Test Suite

Test cases targeting each of the above findings are in:

```
crates/aegis-security/tests/lt_run6_audit_tests.rs
```

Run with:
```
cargo test -p aegis-security --test lt_run6_audit_tests
```

Key test groups:

| Module                          | Tests | What is proven                                           |
|---------------------------------|-------|----------------------------------------------------------|
| `sec07_detectors_disconnected`  | 5     | Pipeline allows SQLi, XSS, SSRF, PathTraversal; detectors catch them directly |
| `eval01_ipin_cidr_bug`          | 2     | CIDR `10.0.0.0/24` does not match `10.0.0.1` (BUG confirmed) |
| `eval02_ratelimit_no_backend`   | 2     | RateLimit fires on request #1; `limit=1` and `limit=1000000` behave identically |
| `sec16_nonce_race`              | 1     | Documents the race via code inspection                    |
| `sec20_icap_disconnected`       | 1     | `on_response_start()` always PassThrough                  |
| `sec19_ja3_blake3`              | 1     | JA3 output is 64 chars (blake3), not 32 (MD5)             |
| `ddos01_tick_rps_unwired`       | 2     | Baseline stale without tick_rps(); manual call works      |
| `threat01_domain_no_wildcard`   | 3     | Subdomain `c2.evil.com` not matched by parent `evil.com`  |
| `rl01_ip_limiter_dead_code`     | 1     | IpRateLimiter functional in isolation but not hot-path wired |
| `risk01_tracker_dead_code`      | 1     | RiskTracker computes Block but pipeline never consults it |

---

*Report generated by master-waf-tester skill — Run 6 (2026-05-13).
Next action: engineer fix planning per priority order above.
Top priority: SEC-07 (wire `run_all_filtered_timed`) + EVAL-01 (fix IpIn CIDR).*
