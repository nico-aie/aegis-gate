---
id: 2026-06-17-section-04-rate-limit-challenge
contract_section: "§4 — Detection via HTTP Response (rate-limit + PoW challenge)"
checklist_ids: C-4-*
verdict: PASS (1 LOW edge — F-V26-005)
test_mode: source-review
---

# §4 — HTTP Behaviour, Rate-limit & Challenge

Primary code: rate-limit `crates/aegis-security/src/rate_limit/*`,
issuance `crates/aegis-proxy/src/data_plane.rs`, challenge
`crates/aegis-security/src/challenge.rs` + verify
`crates/aegis-proxy/src/admin_dispatch.rs:1096`.

## §4 recommended HTTP behavior — ✅ PASS

| Action | Expected | Aegis | Evidence |
|---|---|---|---|
| allow | proxy upstream | ✅ | forward path |
| block | 403 | ✅ | blocked_response |
| challenge | 429 | ✅ | `data_plane.rs:1388` |
| rate_limit | 429 | ✅ | `data_plane.rs:706` |
| timeout | 504 | ✅ | timeout tag wired |
| circuit_breaker | 503 | ✅ | breaker path; reset window 503+Retry-After:0 `data_plane.rs:257` |

C-4-03: bodies are JSON (any format permitted as long as headers accurate). ✅

## Basic rate-limit (mandatory, self-built) — ✅ PASS

| ID | Requirement | Result | Evidence |
|----|-------------|--------|----------|
| C-4-05 | self-built, no 3rd-party | ✅ | `rate_limit/{sliding,bucket,ip_limiter}.rs` — own sliding-window + token-bucket impls |
| C-4-06 | per-client count vs threshold → 429 + `X-WAF-Action: rate_limit` | ✅ | `data_plane.rs:706` status 429; `DecisionTag::rate_limit` |
| C-4-07 | deterministic | ✅ | window math is pure; backend-keyed counters |
| C-4-08 | `Retry-After` header AND/OR `retry_after_seconds` body | ✅ | `data_plane.rs:708` `retry-after` header + `:713` `retry_after_seconds` body field — **both** present |

## Basic challenge (mandatory, self-built PoW) — ✅ PASS

| ID | Requirement | Result | Evidence |
|----|-------------|--------|----------|
| C-4-10 | self-built PoW, no 3rd-party CAPTCHA | ✅ | `aegis_security::challenge::PowIssuer` — own SHA-256 PoW with HMAC-tagged token |
| C-4-11 | token+difficulty → client nonce → WAF verify | ✅ | `issue()` packs (nonce, difficulty, expires_at_ms, mac); client finds nonce; `verify()` checks |
| C-4-12 | correct + deterministic verify (accept valid / reject invalid) | ✅ | `verify()` returns `Ok(())` / `InvalidMac` / `Expired` / `InsufficientDifficulty` / `Replay` (`admin_dispatch.rs:1182`) |
| C-4-13/14 | Format A JSON fields | ✅ | `data_plane.rs:1371` emits `challenge`, `challenge_type:"proof_of_work"`, `challenge_token`, `difficulty`, `submit_url:"/challenge/verify"`, `submit_method:"POST"` |
| C-4-16 | submit `POST <submit_url>` `{challenge_token,nonce}` → 200 | ✅ | `handle_challenge_verify` parses exactly that body, returns 200 on success |
| C-4-17 | unsolvable challenge = FAILED | ⚠️ edge | see F-V26-005 (only the unwired-issuer fallback path) |

Replay protection: verify consumes a nonce via the StateBackend
(`consume_nonce`) → C-4-12 robustness. Stateless token (HMAC) means no
server-side issuance storage needed.

## Findings
- **F-V26-005 (LOW):** when `pow_issuer` is not wired (test bundles that skip
  the interop runtime), the challenge body falls back to a
  `challenge_type`-only JSON with **no** `challenge_token`/`difficulty`/
  `submit_url` (`data_plane.rs:1381`). That challenge is unsolvable → §4
  records FAILED. Production boot wires the issuer, so this only bites if a
  submission ships without the interop runtime. **Confirm the graded binary
  wires `pow_issuer`.** See F-V26-LOW file.

- **VERIFY-LIVE-2:** §4 says a verified challenge returns 200 "with a session
  cookie or token that allows the original request to proceed." The verify
  handler returns `200 {ok,action:"challenge_verified"}` but the
  session-cookie / risk-bucket-clear that lets the *replayed original
  request* pass is described as "wired by the data-plane risk-bucket clear
  (separate concern)" (`admin_dispatch.rs:1186`). **Confirm end-to-end that
  after verify, the same client's next request is allowed** (not re-challenged).

## Net
Rate-limit and challenge are both genuinely self-built and contract-shaped.
One edge (unwired fallback) and one live confirmation needed.
