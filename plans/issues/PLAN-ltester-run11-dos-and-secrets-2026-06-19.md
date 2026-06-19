# PLAN — LT-RUN-11 infra/DoS/secrets hardening + functional QC residue (2026-06-19)

- **Type:** PLAN (fix register, verified against current `develop` + v2.6 contract)
- **Status:** 🔴 OPEN (2026-06-19)
- **Sources:**
  - `tests/l-tester/reports/2026-06-19-run11/LT-RUN-11-INFRA-SECURITY-AUDIT.md` (16 findings, static source audit)
  - `skills/aegis-waf-tester/reports/findings/2026-06-19/functional-access-lists-and-rules.md` (1 MEDIUM + 2 LOW)
- **Relationship to existing plans:**
  - `PLAN-security-consolidated-2026-06-19.md` already shipped **R-1 / R-1b / R-2 / R-6**. This plan does
    **not** re-open those. It picks up the *code-side* gaps Run 11 found that the consolidated plan only
    half-covered (Redis schema/boot guard, read-only reconcile, csrf boot guard) plus the entirely-new
    DoS/secret findings.
  - Consolidated-plan **R-3** (csrf_secret boot hard-fail) == Run 11 **CTL-02**. Folded here as item **C2**.

---

## 0. Verification against current code (what's real)

All line refs verified on `develop` 2026-06-19. Prior session fixes are excluded.

| Run 11 ID | Verified status | Note |
|-----------|-----------------|------|
| STATE-01 | **OPEN** | `config_source/config_store.rs:67` — `ConfigDoc` carries no signature/MAC |
| STATE-02 | **OPEN (code half)** | `config.rs:3269` `RedisConfig` has no `password/username/tls`; no boot guard. `deploy/redis/redis.conf` hardening already shipped (R-2) but schema can't express auth/TLS and won't refuse a plaintext/unauth URL |
| STATE-03 | **OPEN** | `reconcile.rs:105,243` — every `WafError::State` (incl. READONLY) → `enter_partition` → empty in-mem fallback for rate-limit/risk/nonce. **Distinct from R-1**, which only fixed the admin-session write path |
| STATE-04 | **OPEN** (low) | stale module doc in `state/redis.rs` |
| PROXY-01 | **OPEN** | `data_plane.rs:731` `body.collect()` then cap check at `:745` |
| PROXY-02 | **OPEN** | `risk/tracker.rs:56` `IDLE_TTL=3600`; sweep is TTL-only (`:180`), no cardinality ceiling |
| PROXY-03 | **OPEN** | `listener/http3.rs` body drained with no cap; `proxy::handle_request` never reads `max_body_bytes` |
| PROXY-04 | **OPEN** | `accept.rs` hyper builders use defaults — no `header_read_timeout`, no conn cap |
| PROXY-05 | **OPEN** | `rate_limit/ip_limiter.rs` `DEFAULT_LIMIT=1_000_000`; unbounded map (same RiskKey cardinality) |
| PROXY-07 | **OPEN** (low) | `proto/ws_inspect.rs` bridge has no idle timeout |
| CTL-01 | **OPEN** | `interop/mod.rs:34` `DEFAULT_CONTROL_SECRET`; `prod-balanced.yaml:290` literal; `run.rs:2576` fallback |
| CTL-02 | **OPEN** | `accept.rs:413` warns & continues on empty csrf_secret (== R-3) |
| CTL-03 | **OPEN** (med) | `api/config.rs` `scrub_secrets` returns input unchanged |
| SEC-01 | **OPEN** | `run.rs:2304` `derive_pow_key(&rt.control.secret)` — PoW/challenge-pass key is a fn of control_secret |
| SEC-02 | **OPEN** (low) | `admin_auth/totp.rs:91` non-constant-time `==` |
| SEC-03 | **OPEN** (low, latent) | `auth/jwt.rs` validate() skips signature; `challenge/captcha.rs` verify() → Ok(true); **zero callers** |

### Functional report — re-scoped against the v2.6 contract
- **MEDIUM "XFF not honored / one upstream IP" → NOT A BUG.** v2.6 **§587** mandates `ip` = TCP `peer_addr`,
  **not** X-Forwarded-For; **§681–682** classify XFF/X-Real-IP as *supplementary, spoofable* signals, never
  identity. The WAF attributing to the peer IP is *contract-correct*. The tester's "parse XFF from the front
  proxy" recommendation would **violate** the contract. Residue is two non-code items:
  - **GeoIP DB not loaded** on the box → country/ASN access-list entries are silently inert (deploy/operator;
    document the load step + add a boot warning when country/ASN rules exist but no DB is loaded — item **D2**).
  - Per-IP access lists are inert behind the shared exam front proxy *by design of the exam topology*; document
    it. `trusted_proxies` (`config.rs:694`, with `is_unsafe_trusted_proxy` guard) already exists for real
    multi-tier deployments.
- **LOW "Rules view doesn't auto-refresh after mutate"** → real dashboard polish (item **D1**).
- **LOW "disabled-rule propagation lag"** → expected (interval-based rule-table refresh); document only.

---

## 1. Fix register (this plan)

Priority follows Run 11's recommended order, adjusted for "what's still open in code."

| ID | Sev | Item | Files | Effort |
|----|-----|------|-------|--------|
| **A1** ✅ | CRIT | Bound request body **before** buffering — H1 (`Limited` + Content-Length pre-check) | `data_plane.rs` `declared_content_length_over_cap` + `Limited::new` | **DONE 2026-06-19** (4 tests) |
| **A2** ✅ | HIGH | Bound request body — H3 (Content-Length pre-check + in-loop cap → 413) | `listener/http3.rs` (reuses A1 helper) | **DONE 2026-06-19** |
| **A3** ✅ | CRIT | Cardinality cap on RiskTracker + short TTL for zero-value slots | `risk/tracker.rs` (`MAX_TRACKED_KEYS`, `ZERO_VALUE_IDLE_TTL`) | **DONE 2026-06-19** (2 tests) |
| **A4** ✅ | HIGH | Same cardinality cap on per-IP limiter | `rate_limit/ip_limiter.rs` (`MAX_TRACKED_KEYS`) | **DONE 2026-06-19** (1 test). `DEFAULT_LIMIT=1M` left as-is — it is a documented benchmark decision; lowering it risks throttling the OC harness. Set a strict per-IP cap via profile, not the code default. |
| **A5** ✅ | HIGH | Slowloris: `header_read_timeout` (10s) + `TokioTimer` on all four serve sites | `accept.rs` (admin h1 ×2, data `auto::Builder` + plain h1) | **DONE 2026-06-19**. Conn-count semaphore + slow-**body** read timeout DEFERRED (benchmark-sensitive; needs a config knob; must not break SSE/WS lifetimes). |
| ~~**B1**~~ | ~~CRIT~~ **ACCEPTED** | Hardcoded control secret — **re-scoped, NOT a code change.** v2.6 §55/§768 *mandate* the public fixed value `X-Benchmark-Secret: waf-hackathon-2026-ctrl`; the OC harness sends exactly it. The control plane is **loopback-gated regardless of bind** (`config.rs:1221-1240`, audit L-9), so the public secret is not externally reachable. Same posture as the accepted public-HTTP admin plane. The genuinely exploitable part (the *public* secret seeding the data-plane challenge key) is fixed by **B2**. | accepted | — |
| **B2** ✅ | CRIT | Derive PoW/challenge key from an **independent** secret (`interop.challenge_secret`), random per-process when unset — never the contract-public control_secret | `run.rs` `resolve_challenge_key`, `config.rs` InteropConfig, `prod-balanced.yaml` | **DONE 2026-06-19** |
| **C1** | CRIT | Sign `ConfigDoc` (Ed25519 or HMAC w/ non-Redis boot key); reject unsigned before `apply_and_swap` | `config_store.rs`, `redis_source.rs:189,317` | med |
| **C2** ✅ | HIGH | **Fail boot** on empty csrf_secret when admin login enabled (was R-3 / CTL-02) — empty ⇒ publicly-computable `blake3("")` cookie key | `config.rs` `validate_admin_csrf_secret` | **DONE 2026-06-19** (short-secret stays a `warn!`; `session_key_fp` deferred to R-3) | 
| **C3** | MED | Make `scrub_secrets` actually redact; gate config-export to write scope | `api/config.rs` | low |
| **A6** | MED | READONLY/MISCONF/NOAUTH classified distinctly from connectivity; no fail-open-reset on read-only primary | `state/reconcile.rs:105`, error classifier | med |
| **A7** | LOW | RedisConfig gains `username/password_ref/tls`; boot warns (or fails) on plaintext+unauth `redis://` | `config.rs:3269`, `state/redis.rs:275` | med |
| **D1** | LOW | Re-fetch Rules (and access-list counter) on mutation success | dashboard front-end | low |
| **D2** | LOW | Boot warning when country/ASN access-list entries exist but GeoIP DB unloaded; document DB load | geoip wiring + `HACKATHON-DEPLOY.md` | low |
| **E1** | LOW | WS bridge idle timeout | `proto/ws_inspect.rs:384` | low |
| **E2** | LOW | Constant-time TOTP compare | `admin_auth/totp.rs:91` | low |
| **E3** | LOW | Stub doc fix + CI guard that JWT/CAPTCHA stay uncalled (or default fail-closed) | `state/redis.rs` doc, `auth/jwt.rs`, `challenge/captcha.rs`, CI | low |

---

## 2. Phasing (TDD per item; each phase is its own PR)

**P0 — Secrets (smallest, highest blast-radius): B2 + C2. ✅ DONE 2026-06-19.**
- **B2** — challenge/PoW MAC key decoupled from the contract-public control secret (`resolve_challenge_key`
  in `run.rs`; new `interop.challenge_secret`; random per-process key when unset). 6 unit tests
  (`challenge_key_tests`). This closes the real SEC-01 data-plane bypass.
- **C2** — `WafConfig::validate()` now hard-fails when admin login is enabled and `csrf_secret` is empty
  (`validate_admin_csrf_secret`). 4 unit tests. Also fixed the R-1-fallout compile break in
  `tests/admin_session_shared.rs`.
- **B1** — re-scoped to ACCEPTED (see register): the default control secret is the v2.6-mandated public
  benchmark value and the control plane is loopback-gated, so it is not forbidden. No code change.

> Test evidence: `cargo test -p aegis-core admin_csrf_secret_tests` (4/4), `cargo test -p aegis-proxy --lib
> challenge_key_tests` (6/6), `cargo test -p aegis-proxy --test admin_session_shared` (1/1); full
> `aegis-core` suite 310/310.

**P1 — Remote-OOM / DoS: A1 + A2 + A3 + A4 + A5. ✅ DONE 2026-06-19.**
The "make my WAF die" class. A1/A2 reuse the existing `Limited` pattern + a Content-Length pre-check; A3/A4
share one cardinality ceiling (`MAX_TRACKED_KEYS`, `cfg(test)`-overridable) with a short TTL for zero-value
slots; A5 sets `header_read_timeout` + `TokioTimer` on all four serve sites.

> Test evidence: `aegis-proxy --lib content_length_cap_tests` (4/4), `aegis-security risk::tracker` (+2 new,
> 37/37), `aegis-security rate_limit::ip_limiter` (+1 new, 18/18), full `aegis-security` lib 1822/1822,
> `aegis-core` 310/310. Full `aegis-proxy` lib: **914 passed, 9 failed** — the 9 failures are the
> `supervisor::tests::*` file-watch hot-reload tests, which **fail identically on clean `develop`**
> (pre-existing, unrelated to this work; the `run_binds_and_serves_200` timer panic was introduced and then
> fixed by adding `TokioTimer`). See `project_supervisor_tests_filewatch_flake` memory (now stale — they no
> longer pass even pre-built on this box; tracked separately).

> Deferred from P1 (documented in the register): the connection-count **semaphore** and the slow-**body**
> read timeout. Both are benchmark-sensitive (need a generous config knob) and must not truncate long-lived
> SSE / WebSocket streams — `header_read_timeout` already closes the classic slow-header slowloris.

**P2 — Config-from-Redis trust: C1 (+ depends-on B-class key material).**
Sign config docs with a boot-held key; reject unsigned/invalid before apply. Closes the "Redis attacker
rewrites the fleet" path. Pairs naturally with A6/A7 (Redis trust boundary).

**P3 — Redis trust-boundary depth + disclosure: A6 + A7 + C3.**
Classify READONLY distinctly (the operator's exact symptom, state-plane half that R-1 didn't cover); add
auth/TLS schema fields + boot guard; make `scrub_secrets` redact.

**P4 — Polish: D1 + D2 + E1 + E2 + E3.**

---

## 3. Test plan (per phase)

- **B1:** boot with `interop.enabled` + unset secret → hard error; set secret → boots. Assert no
  `DEFAULT_CONTROL_SECRET` reachable from prod profiles (grep guard in CI).
- **B2:** PoW key changes when `pow_key_ref` rotates independent of control_secret; pass minted under old
  key rejected after rotation.
- **C2:** empty/short csrf + admin reachable → boot `Err`; valid secret → `Ok`; `session_key_fp` stable per
  secret, differs across secrets (mirror R-3 fixtures).
- **A1/A2:** body 1 byte over cap → 413 on both H1 and H3 *before* full buffering (assert peak alloc bounded);
  `Content-Length` over cap short-circuits.
- **A3/A4:** flood unique session cookies → map `len()` plateaus at ceiling (LRU evicts); zero-score slot TTL
  shortened.
- **A5:** slow-header client hits `header_read_timeout`; N+1 concurrent conns rejected by semaphore.
- **C1:** doc with valid sig applies; tampered/absent sig rejected, `applied_version` unchanged.
- **A6:** READONLY error → distinct degraded metric, not silent empty fallback for security writes.
- **A7:** plaintext+unauth `redis://` + `state.backend=redis` → loud warn (or boot fail per chosen policy);
  `rediss://` + AUTH → clean.

---

## 4. Exit criteria
- No source-committed control secret; boot fails on missing/empty critical secrets (control, csrf).
- Challenge-pass key independent of control_secret.
- Oversized body → 413 with bounded memory on **both** H1 and H3; unique-cookie flood does not grow maps
  unbounded; slowloris connections time out.
- Config docs from Redis verified before apply; READONLY Redis no longer silently resets shared state.
- `cargo test` green for `aegis-proxy` / `aegis-security` / `aegis-control` with new fixtures.

## 5. Boundaries / non-goals
- **Do NOT** make the WAF trust `X-Forwarded-For` as client identity — v2.6 §587/§681 forbid it. The
  functional MEDIUM is contract-correct behavior; only GeoIP-load + docs are actionable (D2).
- Admin-plane public-HTTP posture stays as the committee contract (see `PLAN-security-consolidated`); not
  re-litigated here.
- SEC-03 stays latent — implement real verification only *before* any wiring; meanwhile CI-guard zero callers.
