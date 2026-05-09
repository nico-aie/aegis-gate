# QA Run 5 — Security & Load Test Report (v2 — Extended)

**Date:** 2026-05-08  
**WAF version:** `make bench-dev` build (post Run-4 fixes)  
**Contract:** EN_waf_interop_contract_v2.3  
**Dataset:** v1 (57), v2 (87 evasion), v3 (220 new — 14 classes)  
**Tester:** QA automation via Claude in Chrome + bash  

---

## Executive Summary

All 18 interop contract requirements pass. Under concurrent load the WAF sustains **5,000 RPS peak** with p50 overhead of 0.208 ms on clean traffic and 0.061 ms on attack traffic (early short-circuit). The expanded v3 dataset (220 cases, 14 attack classes) surfaces **5 new coverage gaps** beyond the previously known 5, bringing the total known gaps to 10. Core OWASP Top-10 classes (SQLi, XSS, SSRF, CMDi, path traversal, XXE) are well covered. Newer attack classes (SSTI, NoSQL injection, Log4Shell obfuscation, open redirect, prototype pollution) have zero or partial coverage.

---

## 1. Overhead Latency — Full Percentile Breakdown

High-sample measurements (500–1,000 requests per profile):

| Profile | Samples | p50 | p75 | p90 | p95 | p99 | p99.9 | Max |
|---|---|---|---|---|---|---|---|---|
| **Clean traffic** | 500 | 0.208 ms | 0.253 ms | 0.343 ms | 0.418 ms | **2.155 ms** | 2.703 ms | 2.703 ms |
| **Attack traffic** | 500 | 0.061 ms | 0.118 ms | 0.248 ms | 0.365 ms | **0.813 ms** | 10.381 ms | 10.381 ms |
| **Mixed (1,000 req)** | 1,000 | 0.122 ms | 0.193 ms | 0.302 ms | 0.442 ms | **0.983 ms** | 4.550 ms | 4.550 ms |
| **Burst (300 req)** | 300 | 0.145 ms | 0.204 ms | 0.319 ms | 0.404 ms | **0.776 ms** | 0.890 ms | 0.890 ms |
| **v3 security probes** | 86 | 0.615 ms | — | 2.324 ms | 2.876 ms | **3.383 ms** | — | 3.383 ms |

**Key observations:**
- Clean traffic p99 = **2.155 ms** — occasional upstream connect jitter at tail; WAF processing itself is sub-ms
- Attack traffic p99 = **0.813 ms** — significantly lower than clean because the WAF rejects at the detector stage, never proxying to upstream
- Mixed traffic p99 = **0.983 ms** — good balance; tail dominated by clean requests that reach upstream
- No errors at any concurrency level tested (up to 1,000 concurrent)

---

## 2. Load Test — Full Results

### Throughput by concurrency

| Concurrency | Throughput | p50 | p95 | p99 | Errors |
|---|---|---|---|---|---|
| 100 | 3,984 RPS | 0.229 ms | 0.577 ms | 5.322 ms | 0 |
| **300 (peak)** | **5,000 RPS** | **0.218 ms** | **0.406 ms** | **0.538 ms** | **0** |
| 500 | 3,222 RPS | 0.184 ms | 1.401 ms | 2.818 ms | 0 |
| 1,000 (mixed) | 4,390 RPS | 0.122 ms | 0.442 ms | 0.983 ms | 0 |

**Peak throughput: 5,000 RPS at 300 concurrent. Graceful degradation beyond that — no cliff, no errors.**

### Detection under load (Phase B + C combined, 700 requests)

| Metric | Value |
|---|---|
| Clean requests sent | 210 |
| Clean blocked (FP) | 0 → **0.0% FP rate** |
| Attack requests sent | 490 |
| Attack requests blocked | 490 → **100% detection** |
| Overall throughput | 3,672–4,241 RPS |

---

## 3. Security Coverage — v3 Dataset (86 tested cases)

### Detection rate by class

| Attack Class | Cases Tested | Blocked | Rate | Notes |
|---|---|---|---|---|
| SQLi | 16 | 16 | **100%** ✅ | All variants: blind, time-based, stacked, evasion |
| XXE | 2 | 2 | **100%** ✅ | File-read and SSRF via XXE |
| SSRF | 10 | 9 | **90%** | Missed: URL credentials `http://user:pass@host/` |
| XSS | 10 | 9 | **90%** | Missed: XSS in arbitrary custom header value |
| CMDi | 8 | 7 | **88%** | Missed: blind `sleep` (no shell keyword like `id`/`cat`) |
| Path Traversal | 8 | 7 | **88%** | Missed: overlong UTF-8 `%c0%ae` encoding |
| Recon (classic) | 7 | 7 | **100%** ✅ | `.env`, `.git`, `.aws`, `.ssh`, wp-admin, etc. |
| Recon (framework) | 9 | 0 | **0%** ❌ | Spring actuator, Swagger, GraphQL, Prometheus, CGI-bin |
| Log4Shell | 5 | 2 | **40%** ⚠️ | Caught: URL-param + basic UA; Missed: RMI, nested obfuscation, UA header variants |
| SSTI | 3 | 0 | **0%** ❌ | No template injection detection (Jinja2 `{{7*7}}`, `${7*7}`) |
| NoSQL Injection | 3 | 0 | **0%** ❌ | No MongoDB operator detection (`$ne`, `$gt`, `$where`) |
| Open Redirect | 3 | 0 | **0%** ❌ | No redirect chain detection |
| Prototype Pollution | 2 | 0 | **0%** ❌ | `__proto__`, `constructor.prototype` in JSON |
| **Total** | **86** | **59** | **68.6%** | |

---

## 4. New Gaps Found (v3 Dataset)

### GAP-006 — SSTI not detected (High severity)

**Status:** New — confirmed in v3 run  
**Evidence:** `GET /search?q={{7*7}}` → allow; `GET /search?q=${7*7}` → allow  
**Impact:** Server-side template injection can lead to full RCE in templated applications (Flask/Jinja2, PHP Twig, Java Freemarker, Velocity).  
**Missed vectors:** `{{7*7}}`, `{{config}}`, `${7*7}`, Freemarker `<#assign ex=...>`, Handlebars `{{#with}}`  
**Recommendation:** Add SSTI pattern matching for `{{`, `}}`, `${`, `#set`, `#assign`, `<#`, and engine-specific function calls (`__class__.__mro__`, `freemarker.template`).

### GAP-007 — NoSQL injection not detected (High severity)

**Status:** New — confirmed in v3 run  
**Evidence:** `GET /api/users?username[$ne]=invalid` → allow; JSON `{"$ne":"x"}` body → allow  
**Impact:** MongoDB operator injection can bypass authentication entirely with `{$ne: null}` or dump all documents with `{$regex: ".*"}`.  
**Missed vectors:** `[$ne]`, `[$gt]`, `[$regex]`, `[$where]`, JSON body with `$`-prefixed keys  
**Recommendation:** Detect `[$op]` query string pattern and `"$operator"` keys in JSON bodies.

### GAP-008 — Log4Shell obfuscation variants not detected (High severity — CVE-2021-44228)

**Status:** New — partial coverage confirmed  
**Detected:** Basic `${jndi:ldap://...}` in URL param and `log4j-006` JSON body  
**Missed:** `${jndi:rmi://...}` in header, `${${::-j}${::-n}...}` nested obfuscation, `${${lower:j}ndi:...}` lower-case obfuscation, UA header with JNDI  
**Impact:** Log4Shell is critical RCE (CVSS 10.0). Obfuscated variants are common in active exploitation.  
**Recommendation:** Extend Log4Shell pattern to match `${jndi:` in ALL headers (not just URL), and add regex for nested/obfuscated forms: `\$\{[^}]*j[^}]*n[^}]*d[^}]*i[^}]*:`.

### GAP-009 — Open redirect not detected (Medium severity)

**Status:** New — confirmed in v3 run  
**Evidence:** `GET /redirect?next=http://evil.com` → allow  
**Impact:** Open redirects enable phishing, OAuth token theft, and bypass referrer-based CSRF protections.  
**Missed vectors:** `?url=`, `?next=`, `?to=`, `?redirect=` with external HTTP URLs; protocol-relative `//evil.com`  
**Recommendation:** Detect `(url|next|to|redirect|return|goto)=https?://` with an external domain allowlist OR flag any external-domain URL in redirect parameters.

### GAP-010 — Prototype pollution not detected (Medium severity)

**Status:** New — confirmed in v3 run  
**Evidence:** `POST /api/config {"__proto__":{"exec":"id"}}` → allow  
**Impact:** JavaScript prototype pollution can corrupt application state, leading to RCE in Node.js apps via `child_process.exec` or unsafe merge functions.  
**Missed vectors:** `__proto__`, `constructor.prototype`, `Object.prototype` in JSON request bodies  
**Recommendation:** Scan JSON bodies for `"__proto__"`, `"constructor"` keys with nested objects; reject or sanitize.

---

## 5. Previously Known Gaps (Run-4) — Status Update

| Gap | Description | Status |
|---|---|---|
| GAP-001 | Framework recon (Spring, Swagger, GraphQL, K8s) | ❌ Still open |
| GAP-002 | Path traversal evasion (Unicode, Windows, double-encode) | ⚠️ 1/4 still missed |
| GAP-003 | `waf.yaml` stale AI config | ❌ Still open |
| GAP-004 | SSRF URL credentials | ❌ Still open |
| GAP-005 | X-Forwarded-Host injection | ❌ Still open |

---

## 6. Contract Compliance Summary (unchanged — all pass)

| Requirement | Result |
|---|---|
| §2 Control plane (4 endpoints) | ✅ PASS |
| §5 Mandatory headers (6 + overhead) | ✅ PASS |
| §6 Audit log (8 fields, append-only, correlation) | ✅ PASS |
| §7 log_only semantics | ✅ PASS |

---

## 7. Dataset Inventory

| File | Version | Cases | Classes | Purpose |
|---|---|---|---|---|
| `attacks.json` | v1.0 | 57 | 8 | Core OWASP Top-10 baseline |
| `attacks_v2.json` | v2.0 | 87 | 8 + evasion | Evasion variants, extended coverage |
| `attacks_v3.json` | v3.0 | 220 | 14 | Broad coverage incl. XXE, SSTI, NoSQL, Log4Shell, GraphQL, LDAP, Redirect, Smuggling, Deserialization |
| `clean_baselines.json` | v1.0 | 33 | — | FP regression baseline |
| `contract_tests.json` | v1.0 | 30 | — | §2/§5/§6/§7 contract cases |
| **Total** | | **427** | **14** | |

---

## 8. Prioritized Recommendations

Ranked by exploitability × coverage gap:

1. **Log4Shell obfuscation (GAP-008)** — Critical RCE, active in the wild, partial coverage leaves bypass vectors open. Fix: extend JNDI pattern to all headers + obfuscation regex.
2. **SSTI detection (GAP-006)** — RCE class. Template injection is trivially exploitable in Flask/Jinja2/Twig/Freemarker stacks. Fix: add `{{`, `}}`, `${...}` pattern rules.
3. **NoSQL injection (GAP-007)** — Auth bypass class. Easy to exploit against MongoDB-backed APIs. Fix: flag `[$op]` query params and `$`-operator JSON keys.
4. **Framework recon paths (GAP-001)** — Actuator heapdump, Swagger API-docs, and Prometheus metrics leak sensitive runtime info. Fix: extend recon rule list.
5. **Open redirect (GAP-009)** — Phishing / OAuth token theft enabler. Fix: detect external-domain values in common redirect params.
6. **Prototype pollution (GAP-010)** — Node.js RCE vector. Fix: scan JSON for `__proto__`/`constructor` keys.
7. **Path traversal evasion (GAP-002)** — Overlong UTF-8, Windows backslash. Fix: normalize before matching.
8. **SSRF URL credentials (GAP-004)** — Credential smuggling to internal services. Fix: flag `://[^@]+@` pattern in URL params.

---

*Report generated by QA Run 5 (extended) — 2026-05-08*  
*Previous version: QA-RUN-5-SECURITY-LOAD.md*
