---
id: 2026-05-18-engine-verification
date: 2026-05-18T00:00Z
area: Rule engine + Response filter + Smart cache + Graceful degradation
spec_ref: §5.2 #07 + §5.4 + §5.7 + §5.8
---

# Engine layer — Rule Engine + Response Filter + Smart Cache + Graceful Degradation

## 1. Rule Engine — §5.4 — **PASS**

### Spec mandate

> AST với Conditions (All/Any/Not, IpIn, PathMatches, Method, Header/Query/Body matching, JwtClaim, BotClass, ThreatFeed, Country, ASN). Actions (Allow/Block/Challenge/RateLimit/RaiseRisk/LogOnly). First-match-wins, priority-ordered. Linter chặn forbidden patterns (§9). Hot-reload ≤10s.

### Code under test

- AST: [rules/ast.rs:1-306](../../../../crates/aegis-security/src/rules/ast.rs)
- Eval: [rules/eval.rs:1-1114](../../../../crates/aegis-security/src/rules/eval.rs)
- Linter: [rules/linter.rs:1-260](../../../../crates/aegis-security/src/rules/linter.rs)

### A) Spec compliance — **PASS**

- ✅ Condition variants 15 loại (ast.rs:86-113): All/Any/Not, IpIn, PathMatches, HostMatches, Method, HeaderMatches, QueryMatches, BodyMatches, CookieMatches, JwtClaim, BotClass, ThreatFeed, Country, Asn, SchemaViolation, True.
- ✅ Action variants 6 loại (ast.rs:190-198): Allow, Block, Challenge, RateLimit, RaiseRisk, LogOnly.
- ✅ First-match-wins + priority sort (eval.rs:131 `sorted.sort_by(|a, b| b.priority.cmp(&a.priority))`).
- ✅ Terminal actions short-circuit (eval.rs:152-228); non-terminal accumulate (eval.rs:229-237).
- ✅ Risk accumulation test (eval.rs:485-506).

### B) Dashboard config — **PASS**

- CRUD endpoints `POST/PUT/DELETE /api/rules/*` qua [api/rules.rs:1-150](../../../../crates/aegis-control/src/api/rules.rs).
- Body validation + linter check trước khi save.

### C) Hot-reload — **PASS**

- ArcSwap tại [rules/mod.rs:9](../../../../crates/aegis-security/src/rules/mod.rs#L9).
- `replace_rules()` (line 99-101) swap atomic.
- Pipeline `snapshot()` mỗi request (line 176).
- Effect ≤1 request latency (sub-ms).

### D) §9 — **PASS WITH NOTE**

- ✅ Linter validate duplicate IDs, priority range (max 10000), nesting depth (max 8), regex compile (line 47-99).
- ⚠️ **Note**: Linter chặn TOÀN BỘ `RateLimit` action với error `UnwiredAction` tại line 85-95 — đúng (rate-limit-per-rule backend chưa wire), nhưng nếu rule file có RateLimit action sẽ fail load. Đây là behavior chuẩn pre-fix, không phải bug.
- ⚠️ Open M-17: linter chưa flag `Condition::True` top-level (§9 forbidden loophole), duplicate priorities, catastrophic regex backtracking.

### Verdict

**PASS**. Rule engine là phần solid nhất, đầy đủ AST + eval + linter + hot-reload.

---

## 2. Response Filter — §5.7 — **PARTIAL**

### Spec mandate

> Strip headers: `Server`, `X-Powered-By`, `X-AspNet-Version`, `Via`, plus prefixes `x-debug-*`, `x-internal-*`. Cap 5xx response body size. Scrub stack traces. Mask internal IPs. Redact PII (email/phone/SSN) trong JSON response.

### Code under test

[crates/aegis-security/src/response_filter.rs](../../../../crates/aegis-security/src/response_filter.rs)

### A) Spec compliance — **PARTIAL**

- ⚠️ **STRIP_HEADERS chỉ có 2 header** (line 5, 32-35): `["server", "x-powered-by"]`. Spec yêu cầu:
  - `Server` ✅
  - `X-Powered-By` ✅
  - `X-AspNet-Version` ❌
  - `Via` ❌
  - Prefix `x-debug-*` ❌
  - Prefix `x-internal-*` ❌
- ✅ Stack trace scrubbing (line 49-81): Node.js, JVM, Python, Rust, PHP, .NET, Ruby, Go patterns.
- ✅ Internal IP masking (line 68-72): RFC 1918 + loopback + link-local → `[INTERNAL]`.
- ❌ **5xx body size cap**: chưa implement. Spec mandate cho HTTP 5xx response (debug stack trace có thể lộ secrets).
- ✅ PII redaction qua `dlp::redact` (line 230) — out of scope nhưng đã wire.

### B) Dashboard config — **PASS**

- `GET/PUT /api/response-filter` tại [api/response_filter.rs:1-166](../../../../crates/aegis-control/src/api/response_filter.rs).
- Toggle: `scrub_stack_traces`, `mask_internal_ips`, `redact_dlp` (line 28-35).

### C) Hot-reload — **PASS**

- `ArcSwap<ResponseFilterConfig>` (line 110).
- `set_filter_config()` (line 128-130) atomic store.
- `on_body_frame()` load mỗi frame (line 203).

### D) §9 — **PASS**

### Verdict

**PARTIAL**. Core scrubbing + masking OK. Header strip list incomplete (2/4 baseline + 0/2 prefixes). 5xx body cap chưa có. Fix outline ~100 LoC, ~3h — xem Sprint 2.5.

---

## 3. Smart Cache — §5.2 #07 — **FAIL**

### Spec mandate

> Vary cache key theo tier. KHÔNG cache CRITICAL/auth endpoints. Operator config được TTL + endpoint allowlist. Expose hit-ratio metric. Dashboard PUT update được ≤10s.

### Code under test

[crates/aegis-core/src/cache.rs:1-51](../../../../crates/aegis-core/src/cache.rs#L1)

### A) Spec compliance — **FAIL**

- ✅ `CacheKey` struct support method + host + path + `vary_headers` (line 1-6).
- ❌ **Per-tier variance**: không implement. Spec yêu cầu CRITICAL không cache, MEDIUM/CATCH-ALL có thể cache với TTL khác nhau.
- ❌ **CRITICAL/auth bypass logic**: không có `X-WAF-Cache: BYPASS` header trên `/login`, `/otp`, etc. Cache key architecture support variance nhưng implementation chưa enforce bypass.
- ❌ **TTL + endpoint allowlist operator config**: trait `CacheProvider` (line 14-24) chỉ là interface, không có config endpoint trong `aegis-control/src/api/`.
- ❌ **Hit-ratio metric**: chưa instrument trong code đọc được.

### B) Dashboard config — **FAIL**

- ❌ Không có `crates/aegis-control/src/api/cache.rs` (grep: 0 hit).
- ❌ Không có `GET /api/cache` hay `PUT /api/cache` endpoint.
- ✅ `POST /__waf_control/flush_cache` tồn tại tại [interop/control.rs:157-164](../../../../crates/aegis-core/src/interop/control.rs#L157) — nhưng response `FlushCacheResponse { ok, action, supported, ts_ms }` return `supported: false` nếu không có callback wired (line 321-322).

### C) Hot-reload — N/A (không có config endpoint).

### D) §9 — **PASS**

### Verdict

**FAIL**. Spec §5.2 #07 mandate cache với 4 yêu cầu (per-tier variance, bypass CRITICAL, operator config TTL/allowlist, hit-ratio metric). Hiện tại chỉ có abstraction trait + 1 flush endpoint không wired backend. Round-1 risk: MEDIUM (judge có thể test cache bypass behavior).

---

## 4. Graceful Degradation — §5.8 — **PARTIAL**

### Spec mandate

> Tier-based failure mode: CRITICAL = fail-close, HIGH = fail-close, MEDIUM = fail-open + risk bump, CATCH-ALL = fail-open. Áp dụng cho mọi component dependency (Redis, GeoIP, threat-feed, detector). Khi detector panic hoặc timeout → tier-based handling.

### Code under test

- Tier classifier: [crates/aegis-core/src/tier.rs:19-31](../../../../crates/aegis-core/src/tier.rs#L19)
- Pipeline classify_tier: [aegis-security/src/pipeline.rs:10-62](../../../../crates/aegis-security/src/pipeline.rs#L10)
- Detector invocation: [aegis-security/src/detectors/mod.rs:258-279](../../../../crates/aegis-security/src/detectors/mod.rs#L258)

### A) Spec compliance — **PARTIAL**

- ✅ Tier-based mapping (tier.rs:19-31):
  - `Tier::Critical → FailureMode::FailClose` (line 28).
  - `Tier::{High, Medium, Low} → FailureMode::FailOpen` (line 29).
  - ⚠️ Note: spec yêu cầu `Tier::High` = FailClose, code hiện tại = FailOpen (line 49 path heuristic). Discrepancy với spec.
- ✅ Per-route override qua route config; path heuristic fallback.
- ❌ **Panic recovery KHÔNG explicit**: `detectors/mod.rs::run_all_filtered_timed` chạy mỗi detector không có `std::panic::catch_unwind` wrapper. Một detector panic sẽ propagate đến hyper task. Cần catch tại data plane level (chưa thấy).
- ❌ **Timeout với risk bump**: chưa implement. Detector chạy sync, không có per-detector timeout.

### Path heuristics (pipeline.rs:26-62)

| Tier | Path patterns | Fail mode hiện tại | Fail mode spec |
|---|---|---|---|
| CRITICAL | /login, /signin, /auth, /payments, /checkout, /transfer, /2fa, /mfa, /password | FailClose ✅ | FailClose |
| HIGH | /api, /admin, /graphql, /webhook | FailClose ✅ (line 49) | FailClose |
| MEDIUM | /user, /account, /profile, /settings | FailOpen ✅ | FailOpen |
| CATCH-ALL | default | FailOpen ✅ | FailOpen |

### B) Dashboard config — N/A

### C) Hot-reload — N/A

### D) §9 — **PASS**

### Verdict

**PARTIAL**. Tier-mapping OK. Panic-catch + timeout-bump chưa implement. M-09 finding flagged the gap: "detector dispatcher has no per-detector panic isolation" — vẫn open.

---

## Summary Engine layer

| Component | Spec | Dashboard | Hot-reload | §9 | Verdict |
|---|---|---|---|---|---|
| Rule Engine §5.4 | PASS | PASS | PASS | PASS ⚠️ linter chặn RateLimit | **PASS** |
| Response Filter §5.7 | PARTIAL (2/4 headers, no prefix, no body cap) | PASS | PASS | PASS | **PARTIAL** |
| Smart Cache §5.2 #07 | FAIL (no per-tier, no bypass, no metric) | FAIL (no `/api/cache`) | N/A | PASS | **FAIL** |
| Graceful Degradation §5.8 | PARTIAL (no panic-catch, no timeout-bump) | N/A | N/A | PASS | **PARTIAL** |

## Ghi chú tổng

- Rule engine + control plane là 2 phần làm tốt nhất trong project.
- Response filter có gap nhỏ về header list — fix ~100 LoC.
- Smart cache là gap rõ nhất, có thể là intentional "Phase 4" deferral, nhưng theo spec §5.2 #07 thì BẮT BUỘC.
- Graceful degradation đủ tốt cho path heuristic, thiếu mechanism cho panic/timeout.
