# Live Test Suite Audit — Run 7 Findings

| Field                | Value                                                                              |
|----------------------|------------------------------------------------------------------------------------|
| Run ID               | LT-RUN-7                                                                           |
| Date                 | 2026-05-13                                                                         |
| Approach             | Static review of live integration test files — correctness, coverage, false-signal analysis |
| Scope                | `tests/lt_run6_live_tests.py` (v1, ~1,000 lines) + `tests/lt_run6_extended_tests.py` (v2, ~700+ lines) |
| Source files reviewed | 2 Python test files, cross-checked against 4 Rust source files                  |
| Total findings       | **9**                                                                              |
| Critical             | **0**                                                                              |
| High                 | **2**                                                                              |
| Medium               | **3**                                                                              |
| Low                  | **4**                                                                              |
| Logic conflicts      | **2 confirmed** (TS-01 tests wrong path; TS-02 wrong hash + difficulty)           |
| Stubs / unimpl       | **0**                                                                              |
| Partial impl         | **3 confirmed** (TS-03 BOTS-01 wrong layer; TS-05 smuggling not deliverable; TS-06 thread hazard) |
| Contract violations  | **0**                                                                              |
| Test suite           | ⚠ Cannot run in sandbox — tests target `localhost:8080 / 9443` on user's machine |
| Status               | ⚠ OPEN — 2 High findings must be fixed before test results can be trusted        |

---

## Executive Summary

This run audits the live integration test suite generated in Run 6 rather than the source code itself. Two **High** defects render specific test groups misleading:

**TS-01** — The SEC-16 nonce-race test (`test_sec16_nonce_race_concurrent`, `test_sec16_nonce_sequential_timing`) polls `/__waf_control/challenge_issue`, which is served by `challenge/pow.rs`. That issuer uses an `AtomicU64` counter and will never produce duplicate nonces regardless of concurrency. The actual SEC-16 race lives in `challenge/token.rs:generate_nonce()` (timestamp_ms-based, no counter), which is reached via the JS-challenge verification flow — a completely different endpoint. The concurrent nonce test will always report zero collisions and silently pass, giving false confidence that SEC-16 is not exploitable.

**TS-02** — The `test_pow_full_flow` function attempts to solve the PoW challenge using the wrong hash algorithm (`hashlib.sha256` instead of `blake3`), missing the `:` separator between nonce and counter, and interpreting `difficulty` as hex-char count instead of leading zero bits. For the server's default `difficulty=16`, the test checks for 16 leading zero hex characters (= 64 zero bits) when the server only requires 16 zero bits. The solver will exhaust all 10,000,000 iterations without finding a solution and always report `solution=None`, making the PoW end-to-end flow, double-submit replay check, and invalid-MAC rejection tests unreachable.

Three **Medium** findings describe test logic that either targets the wrong architectural layer (TS-03 BOTS-01 headers), cannot accurately represent smuggling attacks via `urllib` (TS-05), or produces an inverted pass/fail signal that confuses developers reading results (TS-04). Four **Low** findings cover thread safety of the shared `opener`, URL-encoding inconsistencies in payloads, and missing explicit test documentation for the assertion-inversion convention.

The good news: **SEC-07, EVAL-01, EVAL-02, RL-01, RISK-01, DDOS-01, GQL-01, SEC-20**, and all admin API tests are correctly structured. Their assertion logic faithfully models the expected buggy behaviour as a ✓ and a fix landing as a ✗, and will produce actionable output when run against the live server.

---

## Finding Index

### Test Suite Logic Errors (TS-*)

| ID     | Severity     | Category       | Short Description                                                            |
|--------|--------------|----------------|------------------------------------------------------------------------------|
| TS-01  | **High**     | Logic Conflict  | SEC-16 nonce tests poll the safe PoW path, never the timestamp_ms race in `token.rs` |
| TS-02  | **High**     | Logic Conflict  | PoW solve uses SHA-256 not blake3, no `:` separator, difficulty × 4 too strict |
| TS-03  | **Medium**   | Partial Impl    | BOTS-01 test injects HTTP header; BotClassifier reads Rust struct field — wrong layer |
| TS-04  | **Medium**   | Logic Conflict  | Assertion-inversion (✓ = bug present, ✗ = bug fixed) undocumented, misleads triage |
| TS-05  | **Medium**   | Partial Impl    | HTTP smuggling payloads not deliverable via `urllib` (auto-injects Content-Length) |
| TS-06  | **Low**      | Partial Impl    | Concurrent tests share one `Client.opener` — CookieJar not thread-safe for parallel mutation |
| TS-07  | **Low**      | Partial Impl    | Mass-flood URL contains literal `<>` chars — may be auto-escaped, masking intent |
| TS-08  | **Low**      | Partial Impl    | `test_pow_full_flow` uses `str(counter)` in format string; server also uses counter as string → this part is actually correct, but the solve never runs due to TS-02 |
| TS-09  | **Low**      | Coverage Gap    | DLP-FPE (XOR-mod10 stub), SEC-19 (JA3 md5 vs blake3), BASIC-01 not covered — correct omission, but not documented |

---

## Detailed Findings

---

### TS-01 — SEC-16 Nonce Race Test Targets Wrong Endpoint ⚠

**Severity:** High  
**Files:**
- `tests/lt_run6_extended_tests.py:478–528` (`test_sec16_nonce_race_concurrent`, `test_sec16_nonce_sequential_timing`)
- `crates/aegis-security/src/challenge/pow.rs:200–211` (safe AtomicU64 nonce generator)
- `crates/aegis-security/src/challenge/token.rs:98–101` (timestamp_ms race — what SEC-16 actually describes)

**Description:**

The two SEC-16 tests send 50 concurrent requests to `/__waf_control/challenge_issue` and check for duplicate nonces. However, this endpoint is served by `PowIssuer::issue()` in `pow.rs`, which uses an `AtomicU64` counter:

```rust
// pow.rs:203–210 — SAFE: counter is monotonic across threads
fn generate_nonce() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let pid = std::process::id();
    let h = blake3::hash(format!("{ts_ns}:{pid}:{n}").as_bytes());
    h.to_hex().as_str()[..32].to_string()
}
```

The actual SEC-16 race is in `challenge/token.rs:98–101`, where `store_nonce()` (line 74) and `issue()` (line 23) each call `generate_nonce(key)` independently — and `generate_nonce` uses only `timestamp_ms()` + the RiskKey fields, with no counter:

```rust
// token.rs:98–101 — RACE: two calls in same millisecond produce same nonce
fn generate_nonce(key: &RiskKey) -> String {
    let input = format!("{}:{:?}:{:?}:{}", key.ip, key.device_fp, key.session, timestamp_ms());
    let hash = blake3::hash(input.as_bytes());
    hash.to_hex()[..24].to_string()
}
```

This path is reached only via the JS-challenge flow, which is a different endpoint (the browser-side JS challenge submit → `challenge_verify`). The concurrent PoW-issue test will **always** show zero collisions regardless of load, masking whether the SEC-16 race is actually testable in the current server build.

**Impact:** SEC-16 appears green in every test run; the actual race condition (which affects JS challenge flows once that path is wired) goes untested.

**What the test should do:** Either (a) probe the JS-challenge issue endpoint directly (if it exists and is reachable), or (b) document clearly that SEC-16 is untestable via HTTP because `challenge/token.rs` has zero callers in the current binary, and skip the test explicitly with a note.

---

### TS-02 — PoW Solve Uses Wrong Hash Algorithm, Separator, and Difficulty Interpretation ⚠

**Severity:** High  
**Files:**
- `tests/lt_run6_extended_tests.py:567–605` (`test_pow_full_flow`)
- `crates/aegis-security/src/challenge/pow.rs:174–181` (`pow_solution_valid`)

**Description:**

`pow.rs` defines the solve rule as:

```rust
// pow.rs:174–181
pub fn pow_solution_valid(nonce: &str, counter: &str, difficulty: u8) -> bool {
    let mut hasher = Hasher::new();
    hasher.update(nonce.as_bytes());
    hasher.update(b":");          // ← colon separator
    hasher.update(counter.as_bytes());
    let h = hasher.finalize();
    leading_zero_bits(h.as_bytes()) >= difficulty   // ← counts leading ZERO BITS
}
```

The test implements three errors simultaneously:

```python
# tests/lt_run6_extended_tests.py:583–593
prefix = "0" * difficulty   # BUG-C: difficulty=16 → "0000000000000000" (64 zero bits, not 16)
counter = 0
for counter in range(10_000_000):
    candidate = hashlib.sha256(            # BUG-A: sha256 not blake3
        f"{nonce}{counter}".encode()       # BUG-B: no ":" separator
    ).hexdigest()
    if candidate.startswith(prefix):       # BUG-C: hex prefix ≠ bit count
        solution = counter
        break
```

Consequences:
- **BUG-A** (wrong hash): The server computes `blake3(nonce + ":" + counter)`; the test computes `sha256(nonce + counter)`. Even a correct counter from the test will be rejected by the server.
- **BUG-B** (no separator): The colon separator is part of the canonical input; missing it produces a different hash even if the algorithm were correct.
- **BUG-C** (difficulty × 4): For `difficulty=16`, the server requires 16 leading zero bits (≈ 2 leading zero hex chars, expected ~65k iterations). The test checks for 16 leading zero hex characters (= 64 zero bits, expected ~1.8×10¹⁹ iterations). The solver will never complete within 10,000,000 iterations.

All subsequent tests (`double-submit replay check`, `invalid MAC rejection`) are unreachable because they depend on `solution is not None`.

**Impact:** The PoW end-to-end flow, replay protection (single-use nonce), and MAC tamper-detection tests all silently skip. `test_pow_invalid_mac` is the only surviving PoW test, but it too depends on getting a fresh challenge issue.

**What the test should do:**

```python
# Correct solver — requires: pip install pyblake3 OR use the ctypes wrapper
import blake3 as b3

def pow_solve(nonce: str, difficulty: int, max_iter=10_000_000):
    required_zero_bits = difficulty
    for counter in range(max_iter):
        counter_str = str(counter)
        h = b3.blake3((nonce + ":" + counter_str).encode()).digest()
        # Count leading zero bits
        bits = 0
        for byte in h:
            if byte == 0:
                bits += 8
            else:
                bits += (byte).bit_length() ^ 8  # leading zeros in byte
                break
            if bits >= required_zero_bits:
                break
        if bits >= required_zero_bits:
            return counter_str
    return None
```

Note: `pyblake3` is available via `pip install blake3`. Alternatively, a subprocess call to a small Rust binary (already compiled) can compute the solution.

---

### TS-03 — BOTS-01 Test Injects HTTP Headers; BotClassifier Reads Rust Struct Field ℹ️

**Severity:** Medium  
**Files:**
- `tests/lt_run6_extended_tests.py:365–404` (`test_bots01_reverse_dns_spoof`, `test_bots01_googlebot_ua_no_rdns`)
- `crates/aegis-security/src/bots.rs:16–23` (`BotSignals.reverse_dns`)
- `crates/aegis-security/src/bots.rs:83–91` (`classify()` — reads `signals.reverse_dns`)

**Description:**

The BOTS-01 tests send HTTP requests with `X-Reverse-DNS: googlebot.com` and check whether the proxy classifies the request as `GoodBot`. However, `BotClassifier::classify()` accepts a `BotSignals` struct:

```rust
// bots.rs:16–23
pub struct BotSignals {
    pub user_agent: Option<String>,
    pub reverse_dns: Option<String>,   // ← populated by aegis-proxy, not from HTTP header
    // ...
}
```

There is no evidence in any source file that the proxy crates (`aegis-proxy` or `aegis-bin`) read `X-Reverse-DNS` from the incoming request and map it to `BotSignals.reverse_dns`. The `reverse_dns` field is populated via OS-level rDNS lookup (or a pre-resolved value from infrastructure), not from untrusted request headers.

The tests therefore:
1. Do **not** test the actual BOTS-01 vulnerability (trusting caller-supplied `reverse_dns` in the struct — which is a code-level concern, not an HTTP header concern).
2. May **not** exercise the BotClassifier at all if the proxy ignores `X-Reverse-DNS`.
3. Produce misleading ✓ results ("no FCrDNS check") that cannot distinguish between "header is ignored" and "header is trusted and bypasses classification."

**Impact:** BOTS-01 reads as tested and green, but the actual trust boundary in `BotSignals.reverse_dns` population is untested.

**What the test should do:** Add a comment documenting that BOTS-01 is a code-path trust issue (how the proxy populates `BotSignals.reverse_dns`), not an HTTP header injection issue. The correct test is a code review of `aegis-proxy/src` to confirm whether rDNS is sourced from PTR records (correct) or from a request header (vulnerable). If the proxy is found to trust `X-Reverse-DNS`, then the HTTP test becomes valid.

---

### TS-04 — Assertion-Inversion Convention Undocumented and Misleading ℹ️

**Severity:** Medium  
**Files:**
- `tests/lt_run6_live_tests.py:296–317` (EVAL-01 CIDR test — `True` = bug confirmed)
- `tests/lt_run6_extended_tests.py:441–475` (EVAL-01 v2 — same inversion)
- Multiple other SEC-07 groups in both files

**Description:**

Both test files use a convention where `R.record(..., passed=True)` means *the expected buggy behaviour was observed* (i.e., the attack passed through, confirming SEC-07). When the bug is fixed and the attack is blocked, the test records `passed=False`. The terminal output therefore shows:

```
  ✓ [SEC-07] SQLi OR bypass — HTTP 200 — not blocked ✓ (confirms SEC-07)
  ✗ [SEC-07] SQLi OR bypass — HTTP 403 — attack blocked! SEC-07 may be fixed
```

Green checkmarks mean "the WAF is broken." Red crosses mean "the WAF is working." This inversion is intentional for the purpose of confirming known bugs, but it is undocumented within the files themselves. An engineer running the suite for the first time (after a partial fix lands) will see red crosses and believe something is broken, when in fact those are the first signs of progress.

The `R.summary()` function also uses the pass count as a quality metric, which will *decrease* as bugs are fixed.

**Impact:** Developer confusion during fix validation; potential for a CI gate that fails the suite when the WAF improves.

**What the test should do:** Add a header comment block explaining the inversion convention, and optionally add a separate `R.bug_confirmed(fid, name, note)` / `R.bug_fixed(fid, name, note)` method that separates "confirmed bug" outcomes from "test failure" outcomes in the summary table.

---

### TS-05 — HTTP Smuggling Tests Not Deliverable via `urllib` ℹ️

**Severity:** Medium  
**Files:**
- `tests/lt_run6_extended_tests.py:426–457` (`test_http_smuggling_variants`)

**Description:**

Python's `urllib.request` automatically adds a `Content-Length` header equal to `len(data)` for any request with a body. This is enforced at the socket level and cannot be overridden by passing a conflicting `Content-Length` in the headers dict. Additionally, `urllib` does not support raw Transfer-Encoding: chunked bodies — it encodes chunked framing at the HTTP/1.1 socket layer, not from raw bytes.

The test payloads:
```python
({
    "Content-Length": "6",
    "Transfer-Encoding": "chunked",
}, b"3\r\nGET\r\n0\r\n\r\n", "CL.TE smuggling (basic)")
```

When sent via `urllib`, the actual wire frame will have `Content-Length` overwritten by Python to `len(b"3\r\nGET\r\n0\r\n\r\n") == 14`, not `6`. The server will not see the CL/TE ambiguity that defines the smuggling attack.

**Impact:** All 5 smuggling test cases will return 200 or 400 based on how the proxy handles a normal request with a TE header — not because a smuggling attempt was made. Results are meaningless with respect to smuggling detection.

**What the test should do:** Use raw TCP sockets (`socket.socket`) to send crafted HTTP/1.1 requests with exact byte control. A minimal raw-socket helper can be added to the test file and used only for the smuggling group, leaving the rest of the suite on `urllib`.

---

### TS-06 — Concurrent Tests Share Non-Thread-Safe `Client.opener` ℹ️

**Severity:** Low  
**Files:**
- `tests/lt_run6_extended_tests.py:180–200` (`Client` class, single shared opener)
- `tests/lt_run6_extended_tests.py:215–237` (`test_rl01_burst_concurrent`)
- `tests/lt_run6_extended_tests.py:512–529` (`test_admin_concurrent_rule_write`)

**Description:**

The `Client` class creates a single `urllib.request.build_opener` instance at construction time. All concurrent threads in `test_rl01_burst_concurrent` (50 threads) and `test_admin_concurrent_rule_write` (20 threads) share this opener, including its shared `CookieJar`. `http.cookiejar.CookieJar` uses an internal `_cookies_lock`, but the opener itself (`AbstractHTTPHandler`, connection pools) is not designed for concurrent use.

In practice, intermittent connection errors or corrupt session state may occur under the 50-thread burst test — making failures ambiguous (bug or race in test framework?).

**Impact:** Flaky test results under high concurrency; incorrect attribution of failures.

**What the test should do:** Create a fresh `Client` per thread for concurrent tests:

```python
def burst():
    tc = c.clone()  # fresh opener + cookie jar
    tc.login()
    for _ in range(4):
        s, _, _ = tc.get("/burst_probe")
```

---

### TS-07 — Mass-Flood URL Contains Literal `<>` Characters ℹ️

**Severity:** Low  
**Files:**
- `tests/lt_run6_live_tests.py:823` (mass flood payload list)

**Description:**

The v1 `test_sec07_mass_flood` payload list contains:

```python
("/search?x=<script>eval(atob('YWxlcnQoMSk='))</script>", "XSS mass 1"),
("/search?x=<img%20src=1%20onerror=eval(name)>", "XSS mass 2"),
```

The first path has literal `<>` characters in the URL before they are passed to `urllib.request`. `urllib` will percent-encode these to `%3C` and `%3E` automatically on some Python versions — or it may raise `ValueError: Invalid URL` on others (Python 3.11+ with stricter URL parsing).

The second uses mixed raw/percent-encoded characters, which may be double-encoded by `urllib`.

**Impact:** XSS mass test payloads may silently differ from the intended raw bytes, masking the test intent and making payload-level debugging difficult.

**What the test should do:** Pre-encode all non-ASCII and reserved characters explicitly using `urllib.parse.quote()` before constructing the URL:

```python
path = "/search?x=" + urllib.parse.quote("<script>eval(atob('YWxlcnQoMSk='))</script>",
                                          safe="")
```

---

### TS-08 — `test_pow_full_flow` Counter Format is Accidentally Correct ℹ️

**Severity:** Low  
**Files:**
- `tests/lt_run6_extended_tests.py:583–593`

**Description:**

Despite the three errors in TS-02, one aspect is accidentally correct: `pow.rs` accepts `counter` as an arbitrary string (`counter: &str`), and the test passes `str(counter)` (Python integer → decimal string). The server's `pow_solution_valid(nonce, counter, difficulty)` also treats `counter` as a string. So the serialization format for `counter` — decimal string — would match the server if the other two bugs (wrong hash, wrong difficulty check) were fixed.

This is noted here to avoid over-correcting it as a bug during a fix attempt.

**Impact:** No independent impact. Documenting to prevent regression when TS-02 is fixed.

**What the test should do:** No change needed for counter serialization. Fix only the hash algorithm and difficulty check per TS-02.

---

### TS-09 — DLP-FPE, SEC-19, BASIC-01 Coverage Gaps (Intentional) ℹ️

**Severity:** Low  
**Files:**
- `tests/lt_run6_live_tests.py` — no DLP/JA3/basic-auth tests
- `tests/lt_run6_extended_tests.py` — no DLP/JA3/basic-auth tests

**Description:**

Three Run-6 findings are not covered by either test file:
- **DLP-FPE**: XOR-mod10 stub instead of AES-FF1. Testing would require an upstream that returns PAN/SSN data and checking the WAF's redaction of those values in the response body — requires a controllable upstream.
- **SEC-19**: JA3 fingerprint uses blake3 (64-char hex) not MD5 (32-char hex). This is a TLS-layer fingerprint only observable if the admin API exposes the computed JA3 hash, which no endpoint currently does.
- **BASIC-01**: `auth/basic.rs` is `#![allow(dead_code)]` with zero callers — cannot be exercised at all via HTTP.

These omissions are correct and expected given the current server topology.

**Impact:** None. Documenting to confirm intentional exclusion rather than oversight.

**What the test should do:** Add a comment block at the top of both test files listing these three findings as "untestable via HTTP — intentionally omitted."

---

## Cross-Crate Wiring Analysis

This wiring table maps each Run-6 security finding to its test coverage status after the Run-6 + Run-7 audit pair.

| Feature / Finding | Implemented In | Test Coverage | Correctness | Net Status |
|---|---|---|---|---|
| SEC-07: all 12 detectors disconnected | `pipeline.rs:147` | `lt_run6_live_tests.py` + `lt_run6_extended_tests.py` ✓ | Assertions correctly model pass-through as ✓ | **Covered** |
| EVAL-01: CIDR IpIn string-prefix bug | `rules/eval.rs` | v1 + v2 `test_eval01_*` ✓ | Correctly expects HTTP 200 (not 403) for /8 CIDR | **Covered** |
| EVAL-02: RateLimit fires on req #1 | `rules/eval.rs` | v1 + v2 `test_eval02_*` ✓ | Correctly expects 429 on first request | **Covered** |
| SEC-16: nonce race in token.rs | `challenge/token.rs:98` | v2 `test_sec16_*` ✗ wrong path | Tests poll PoW endpoint (safe) not JS challenge | **UNTESTED — TS-01** |
| SEC-20: on_response_start PassThrough | `pipeline.rs` | v1 + v2 `test_sec20_*` ✓ | Correctly checks for absence of ICAP headers | **Covered** |
| RL-01: IpRateLimiter not wired | `rate_limit/ip_limiter.rs` | v2 `test_rl01_*` ✓ | 200-req flood + thread burst, correct assertion | **Covered** |
| RISK-01: RiskTracker not wired | `risk/tracker.rs` | v2 `test_risk01_*` ✓ | Before/after score comparison, correct | **Covered** |
| DDOS-01: tick_rps never called | `ddos.rs` | v2 `test_ddos01_*` ✓ | 150-req burst + gate API, correct | **Covered** |
| BOTS-01: trusts reverse_dns struct | `bots.rs:84–91` | v2 `test_bots01_*` ✗ wrong layer | Tests HTTP header, not struct field | **UNTESTED — TS-03** |
| GQL-01: alias/fragment complexity | `api_security/graphql.rs` | v2 `test_gql01_*` ✓ | Correctly observes pass-through for alias flood | **Covered** |
| THREAT-01: exact domain match only | `ip_rep/mod.rs` | v2 `test_threat01_*` ✓ | Tests subdomain bypass via Host header | **Covered** |
| SEC-19: JA3 blake3 vs MD5 | `fingerprint/mod.rs` | — | Untestable via HTTP — intentional gap | **Not testable** |
| NOOP-01: NoopPipeline exported | `pipeline.rs` | v1 + v2 `test_noop01_*` ✓ | Canary block-rule test, correct | **Covered** |
| DLP-FPE: XOR stub | `dlp/fpe.rs` | — | Requires upstream control — intentional gap | **Not testable** |
| BASIC-01: blake3 password hash | `auth/basic.rs` | — | Zero callers, deferred — intentional gap | **Not testable** |
| PoW full flow end-to-end | `challenge/pow.rs` | v2 `test_pow_full_flow` ✗ wrong hash | SHA-256 / no separator / wrong difficulty | **BROKEN — TS-02** |

---

## Priority Fix Order

1. **TS-02** — Fix PoW solve algorithm (`blake3` + `:` separator + bit-count difficulty). Requires `pip install blake3` in the test environment. *(effort: low — 15 lines of code)*

2. **TS-01** — Mark SEC-16 nonce tests as explicitly skipped with a comment explaining that `challenge/token.rs` has zero callers. If the JS-challenge endpoint is ever wired, update the test to target it. *(effort: low — add a `skip()` guard and comment)*

3. **TS-03** — Add a code-review comment to BOTS-01 tests explaining that the trust boundary is in the struct-population code (aegis-proxy), not in HTTP headers. Audit `aegis-proxy/src` for how `BotSignals.reverse_dns` is populated. *(effort: medium — requires reading aegis-proxy source)*

4. **TS-04** — Add an assertion-inversion convention block at the top of both test files. Consider adding `R.confirms_bug()`/`R.bug_fixed()` helpers for cleaner CI output. *(effort: low — documentation + minor refactor)*

5. **TS-05** — Replace `test_http_smuggling_variants` with a raw-socket implementation. *(effort: medium — ~50 lines for a minimal socket sender)*

6. **TS-06** — Update concurrent test helpers to call `c.clone()` and `login()` per thread. *(effort: low — 5-line change per test)*

7. **TS-07** — Pre-encode all raw `<>` characters in mass-flood URL payloads. *(effort: low — one-pass search-and-replace)*

---

## Findings Deferred from Previous Runs

| Prior Run Finding | Status in This Run |
|-------------------|--------------------|
| SEC-07  | Still open — detectors confirmed disconnected. Live test coverage added (v1 + v2). |
| SEC-16  | Still open — now flagged TS-01: nonce test targets wrong path. Actual race untested. |
| SEC-20  | Still open — correctly tested via ICAP header absence checks. |
| EVAL-01 | Still open — extensively tested in v1 + v2. CIDR prefix bug correctly modelled. |
| EVAL-02 | Still open — multiple limit/key variants tested, all confirm immediate 429. |
| RL-01   | Still open — added 200-req + 50-thread burst tests in v2. |
| RISK-01 | Still open — added before/after score comparison in v2. |
| DDOS-01 | Still open — added 150-req burst + gate API read in v2. |
| BOTS-01 | Still open — TS-03 flags that HTTP header test does not validate the actual trust boundary. |
| GQL-01  | Still open — alias/fragment/nested tests added in v2. |
| THREAT-01 | Still open — subdomain bypass test added in v2. |
| PR #7 (body scrubbing fix) | Confirmed fixed in Run 6 — response filter tests in v1 remain to verify ongoing. |
| PR #8 (CIDR threat intel fix) | Confirmed fixed in Run 6 — ip_rep correctly uses `ipnet::IpNet::contains()`. |

---

*Report generated by master-waf-tester skill — Run 7 (2026-05-13).
Scope: Live integration test suite (lt_run6_live_tests.py + lt_run6_extended_tests.py).
Next action: fix TS-02 (PoW hash), then TS-01 (SEC-16 skip guard), then re-run full suite.*
