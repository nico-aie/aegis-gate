# WAF Interop Contract v2.3 — l-tester Run 3: Hacker Bypass Findings

| Field             | Value                                        |
|-------------------|----------------------------------------------|
| Run ID            | LT-RUN-3                                     |
| Date              | 2026-05-09                                   |
| Approach          | Attacker perspective — bypass testing        |
| Mock WAF version  | **v2 (unpatched)** — bugs NOT yet fixed      |
| Total scripts     | 25 (LT-01 – LT-25)                           |
| New bypass scripts| 5 (LT-21 – LT-25)                            |
| Bypasses confirmed| **12 individual bypass cases**               |
| Bug categories    | **5 distinct vulnerability classes**         |
| Status            | Closed               |

---

## Executive Summary

Testing was conducted from an attacker's perspective: each payload was crafted to slip through the WAF while carrying a real attack.  Twelve confirmed bypasses were found across five vulnerability classes.  **All twelve produce `X-WAF-Action: allow` with `X-WAF-Rule-Id: none` on an unpatched mock WAF v2**, meaning the threat goes completely undetected.

The most critical finding is **BYPASS-02**: the WAF's data-plane handler only inspects the URL path and query string.  Any attack payload placed in a POST request body — form-encoded or JSON — is invisible to every detector.  This is a complete blind spot that applies to all attack types (SQLi, XSS, CMDi, SSRF, template injection, NoSQL injection, path traversal).

---

## Test Scripts Added

| Script | Checks | What It Tests |
|--------|--------|---------------|
| `lt-21-hack-sqli-evasion.sh` | 11 | SQL keyword comment splitting, newline between keywords, tab whitespace, MySQL version comments, stacked queries, double-URL-encoding |
| `lt-22-hack-body-injection.sh` | 11 | POST body: SQLi / XSS / CMDi / path traversal / template injection / NoSQL / SSRF in form fields and JSON body |
| `lt-23-hack-ssrf-alt-ip.sh` | 11 | SSRF via decimal, hex, octal, IPv6, 0.0.0.0, IPv4-mapped IPv6, cloud-metadata decimal; detector-order sanity |
| `lt-24-hack-pattern-evasion.sh` | 13 | Template injection with spaces, backtick CMDi, mixed-case NoSQL, SVG/img XSS, `javascript:` URI, path traversal variants |
| `lt-25-hack-control-plane-abuse.sh` | 16 | Wrong JSON types for `mode`/`scope`, `features`/`policies` as strings, `feature` as array (server crash), unknown scope, mode injection |

---

## Confirmed Bypass Vulnerabilities

### BYPASS-01 — SQLi Newline Keyword Split

**Severity:** High  
**Test:** LT-21 checks 4 & 6  
**Payloads that bypass:**
```
?id=SELECT%0A1%0AFROM%0Ausers        → X-WAF-Action: allow
?q=UNION%0ASELECT%0A1%0AFROM%0Ausers → X-WAF-Action: allow
```
**Root cause:** The primary SQLi pattern uses Python `re` without `re.DOTALL`.  The `.` metacharacter does not match `\n` by default.  Inserting a newline (`%0A`) between SQL keywords breaks the `SELECT.{0,30}FROM` match.  The `UNION.{0,30}FROM` match fails for the same reason.

**Not bypassed by:** tab (`%09`), SQL comment (`/**/`), MySQL version comment (`/*!...*/`) — all caught by other patterns.

---

### BYPASS-02 — POST Body Completely Uninspected (Critical)

**Severity:** Critical  
**Test:** LT-22 all checks  
**Payloads that bypass:**
```
POST /search   body: id=1' OR '1'='1                        → X-WAF-Action: allow
POST /comment  body: comment=<script>alert(document.cookie)</script> → allow
POST /api/q    body: {"id":"1' OR '1'='1"}                  → allow
POST /execute  body: cmd=;cat%20/etc/passwd                 → allow
POST /render   body: tpl={{7*7}}                            → allow
POST /api/auth body: {"password":{"$ne":"wrong"}}           → allow
POST /fetch    body: url=http://127.0.0.1/internal          → allow
```
**Root cause:** `detect_threat(path, headers)` receives only `self.path` (URL path + query string).  The request body is read in `_proxy_upstream`, **after** the threat decision is final.  No body data ever reaches any detector.

This is a complete bypass for all attack types when the attacker moves the payload from the URL to the POST body.  A clean URL path is sufficient to pass the WAF, regardless of what is in the body.

---

### BYPASS-03 — SSRF via Alternate IP Representations

**Severity:** High  
**Test:** LT-23 checks 2–9  
**Payloads that bypass** (parameter `ssrf_fetch=` used to isolate SSRF detector):
```
?ssrf_fetch=http://2130706433/         (127.0.0.1 as decimal)   → allow
?ssrf_fetch=http://0x7f000001/         (127.0.0.1 as hex)       → allow
?ssrf_fetch=http://0177.0.0.1/         (127.0.0.1 as octal)     → allow
?ssrf_fetch=http://[::1]/              (IPv6 loopback)           → allow
?ssrf_fetch=http://0.0.0.0/            (all-interface bind)      → allow
?ssrf_fetch=http://[::ffff:127.0.0.1]/ (IPv4-mapped IPv6)       → allow
?ssrf_fetch=http://2852039166/         (169.254.169.254 decimal) → allow
```
**Root cause:** `SSRF_PATTERNS` only matches dotted-decimal notation (`127.`, `10.`, `192.168.`, etc.) and the literal string `localhost`.  All alternate but equally valid IP representations are unrecognised.

**Note on test design:** LT-23 resets WAF state before each individual check and verifies `X-WAF-Rule-Id: ssrf` (not just `action != allow`).  This prevents false-positive passes caused by elevated risk scores from previous requests.

---

### BYPASS-04 — Template Injection Whitespace (`{ { 7*7 } }`)

**Severity:** Medium  
**Test:** LT-24 check 2  
**Payload that bypasses:**
```
?q=%7B%20%7B%207%2A7%20%7D%20%7D  (decodes to: { { 7*7 } })  → allow
```
**Root cause:** Pattern `\{\{.+?\}\}` requires the two opening braces to be adjacent (`{{`).  Adding a space between them — `{ {` — causes the pattern to miss the match.

**Not bypassed by:** `${ 7*7 }` (Spring EL with space after `{`) — detected because `\$\{` matches the adjacent `${` and the space is inside the expression, not between delimiters.

---

### BYPASS-05 — CMDi via Backtick Subshell (`` `id` ``)

**Severity:** Medium  
**Test:** LT-24 check 12  
**Payload that bypasses:**
```
?cmd=%60id%60  (decodes to: `id`)  → allow
```
**Root cause:** `CMDI_PATTERNS` covers `$(...)` subshell and pipe/semicolon-prefixed commands but has no pattern for the backtick subshell syntax, which is equally valid in Bash/sh.

---

### BYPASS-06 — Control Plane: `features` / `policies` as String (Type Confusion)

**Severity:** Medium  
**Test:** LT-25 checks 10 & 11  
**Payloads:**
```json
{"scope":"features","mode":"log_only","features":"rules_engine"}
→ HTTP 200  (expected 400)

{"scope":"policies","mode":"log_only","feature":"rules_engine","policies":"sqli"}
→ HTTP 200  (expected 400)
```
**Root cause:** There is no `isinstance(..., list)` check for `features` or `policies`.  Python's `for feat in feats` iterates over a string character by character (`'r'`, `'u'`, `'l'`, `'e'`, …).  All single-character strings fail the `feat in FEATURES` lookup and are silently added to `unsupported`.  The request returns `{"ok": true, "unsupported": ["r","u","l","e","s","_","e","n","g","i","n","e"]}` — the mode change is not applied but the response is 200 instead of 400.

---

### BYPASS-07 — Control Plane: `feature` as Array → Server Crash

**Severity:** High  
**Test:** LT-25 check 12  
**Payload:**
```json
{"scope":"policies","mode":"log_only","feature":["rules_engine"],"policies":["sqli"]}
→ HTTP 000  (connection closed — server crash)
```
**Root cause:** `feature` is expected to be a string. Passing a list causes `["rules_engine"] not in FEATURES` to raise `TypeError: unhashable type: 'list'` inside the `with _lock` critical section.  The unhandled exception crashes the HTTP handler thread without sending any response — `curl` receives exit code 52 (empty reply from server).

**Impact:** A single malformed request kills the request-handling thread.  Depending on the thread pool configuration, repeated requests could exhaust available handler threads, causing a denial of service.

---

## Run Summary — LT-21 through LT-25 vs Unpatched WAF v2

| Script | Total checks | Passed | Failed | First failure |
|--------|-------------|--------|--------|---------------|
| lt-21-hack-sqli-evasion | 11 | 4 | 1+ | Newline SELECT\\nFROM bypass |
| lt-22-hack-body-injection | 11 | 2 | 1+ | SQLi in POST body bypass |
| lt-23-hack-ssrf-alt-ip | 11 | 1 | 1+ | SSRF decimal IP bypass |
| lt-24-hack-pattern-evasion | 13 | 2 | 1+ | Template `{ { 7*7 } }` bypass |
| lt-25-hack-control-plane-abuse | 16 | 9 | 1+ | `features` string type bypass |

> Tests use `set -euo pipefail` and exit at first failure.  "1+" means at least 1 fail was observed; the full probe run (shown above) confirmed additional failures in each category.

---

## All Confirmed Individual Bypass Cases (12 total)

| # | Category | Payload summary | Expected | Actual |
|---|----------|-----------------|----------|--------|
| 1 | SQLi | `SELECT\nFROM users` | block | **allow** |
| 2 | SQLi | `UNION\nSELECT\n1\nFROM users` | block | **allow** |
| 3 | Body | SQLi in POST form field | block | **allow** |
| 4 | Body | XSS in POST form field | block | **allow** |
| 5 | Body | SQLi in JSON POST body | block | **allow** |
| 6 | SSRF | `http://2130706433/` (decimal 127.0.0.1) | block | **allow** |
| 7 | SSRF | `http://0x7f000001/` (hex) | block | **allow** |
| 8 | SSRF | `http://0177.0.0.1/` (octal) | block | **allow** |
| 9 | SSRF | `http://[::1]/` (IPv6) | block | **allow** |
| 10 | SSRF | `http://0.0.0.0/` | block | **allow** |
| 11 | SSRF | `http://[::ffff:127.0.0.1]/` (IPv4-mapped) | block | **allow** |
| 12 | SSRF | `http://2852039166/` (decimal 169.254.169.254) | block | **allow** |
| 13 | Template | `{ { 7*7 } }` (spaces in braces) | block | **allow** |
| 14 | CMDi | `` `id` `` (backtick subshell) | block | **allow** |
| 15 | Control plane | `features: "rules_engine"` (string) | 400 | **200** |
| 16 | Control plane | `policies: "sqli"` (string) | 400 | **200** |
| 17 | Control plane | `feature: ["rules_engine"]` (array) | 400 | **crash** |

---

## Suggested Fix Areas (for planning)

| Bug | File / Location | What to change |
|-----|-----------------|----------------|
| BYPASS-01 (newline SQLi) | `detect_threat()` — `SQLI_PATTERNS[0]` | Add `re.DOTALL`; use `[\s\S]{0,40}` instead of `.{0,30}` |
| BYPASS-02 (POST body) | `DataHandler.handle_request()` | Read `Content-Length` body early; pass to `detect_threat()`; update `detect_threat` signature |
| BYPASS-03 (SSRF alt IP) | `SSRF_PATTERNS` list | Add patterns for `\d{7,10}`, `0x[0-9a-f]+`, `0\d+\.`, `\[::1`, `0\.0\.0\.0` |
| BYPASS-04 (template spaces) | `TEMPLATE_INJECTION_PATTERNS[0]` | Change `\{\{` to `\{[\s]*\{` |
| BYPASS-05 (backtick CMDi) | `CMDI_PATTERNS` | Add `r"\`[^\`]+\`"` |
| BYPASS-06 (type confusion) | `_handle_set_profile()` | `isinstance(feats, list)` / `isinstance(polices, list)` checks |
| BYPASS-07 (crash) | `_handle_set_profile()` | `isinstance(feat, str)` check **before** acquiring `_lock` |
