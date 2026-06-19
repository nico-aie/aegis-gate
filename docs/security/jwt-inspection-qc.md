# JWT attack-shape detection — QC Feature Description & Verification Guide

> **Audience:** QC / testers. Describes what the JWT detector does, how to drive
> it, and a step-by-step checklist to verify every rule and its safety
> boundaries. **Status:** Phases A1–A3 shipped
> (`aegis-security/src/detectors/jwt_inspection.rs`). Engineering reference:
> [`detectors/jwt-inspection.md`](./detectors/jwt-inspection.md).

---

## 1. What the feature does (plain language)

The WAF now **decodes JWTs** carried in `Authorization: Bearer <jwt>` and in
`Cookie:` values, and flags tokens whose **structure** matches a known attack.
It looks at the token's first two parts (header + payload), which are just
Base64URL-encoded JSON — no secret required.

Key properties a tester must keep in mind:

- **Detection only — never validation.** The WAF does **not** check the
  signature, does not know your signing secret, and does not decide whether a
  token is "authentic". It only flags malicious *shapes*. A token with a
  perfectly valid signature but an attack shape (e.g. `alg:none`) is flagged; a
  token with a bad signature but a normal shape is **not** flagged here (your
  gateway rejects that).
- **Two report techniques are intentionally NOT covered** — weak-secret brute
  force (the token is validly signed) and RS256→HS256 confusion (needs your key
  + expected algorithm). These are gateway/app concerns, not WAF.
- **Where it reads the token:** `Authorization: Bearer …` first, then every
  `Cookie` value that *looks like* a JWT (three dot-separated Base64URL
  segments). It is **not** tied to the cookie being named `sid`.
- **Structural rules block; the role heuristic only observes.** alg:none, inline
  keys, kid-injection, external jku, and forged time claims score 70–80 (block).
  The privileged-role heuristic scores 20 and is **off by default**.

### The headers/fields to watch

- HTTP status: a blocked request returns **403** (in `enforce`) — see §4 on the
  enforce-vs-log_only distinction.
- `X-WAF-Action` is the **would-be** decision; the actual outcome is the HTTP
  status + `X-WAF-Mode`. In `log_only` the request is **allowed** even though
  `X-WAF-Action` shows the block — verify the real outcome, not just the header.
- Audit log `fields.detectors[]` carries the tag (`jwt_alg_none`,
  `jwt_jku_external`, …). The dashboard "Detector breakdown" shows
  `jwt_inspection`.

---

## 2. How to enable / configure it (setup for testing)

The detector is **on by default**. Config lives under `detectors.jwt_inspection`:

```yaml
detectors:
  jwt_inspection:
    enabled: true                 # class on/off (hot-toggle via /api/detectors)
    jku_allowed_domains:          # hosts a jku/x5u URL may reference
      - "auth.example.com"        #   exact host
      - "*.example.com"           #   subdomain glob (NOT the bare apex)
    flag_privileged_roles: false  # opt-in role heuristic (observe-only)
```

- `jku_allowed_domains` **empty = strict**: any external `jku`/`x5u` URL flags.
  This is the right first-deployment default — you see the surface before tuning.
- `flag_privileged_roles` defaults `false`. Turn it on only when you want to
  *observe* privileged-token traffic (§3.6).

Toggle the whole class at runtime with `PUT /api/detectors` (the
`jwt_inspection` mask bit) or `set_profile { policies: ["jwt_inspection"],
mode: "log_only" }`.

### Building test tokens

A JWT is `base64url(headerJSON).base64url(payloadJSON).signature`. The WAF never
checks the signature, so for QC you can use any placeholder signature (even
empty). Quick recipe:

```bash
b64url() { printf '%s' "$1" | base64 | tr '+/' '-_' | tr -d '='; }
H=$(b64url '{"alg":"none","typ":"JWT"}')
P=$(b64url '{"user":"admin","role":"admin"}')
TOKEN="$H.$P."           # alg:none → trailing dot, empty signature
curl -ki https://<waf>/api/profile -H "Cookie: sid=$TOKEN"
```

---

## 3. Verification checklist (per rule)

> **Dev-environment caution** (read before running): the dev listener does not
> trust `X-Forwarded-For`, so all local traffic is attributed to `127.0.0.1`.
> Repeated attack requests poison that single IP's cumulative risk, which can
> make *later* clean requests block for reasons unrelated to the token under
> test. Between cases, reset the IP: `PUT /api/risk/127.0.0.1/reset` (CSRF
> token required), use a realistic `User-Agent`, and space requests out. Verify
> each rule on a **fresh** state so you're testing the JWT rule, not accumulated
> IP risk.

For each case below: send the request, expect **403** (enforce) with the named
tag in the audit `fields.detectors[]`.

### 3.1 `jwt_alg_none` (blocks)
- Header `{"alg":"none"}` → 403. Also test `None`, `NONE`, `nOnE`, `null`, and
  empty `""` — **all** must flag (case-insensitive).
- Negative: `{"alg":"HS256"}` / `{"alg":"RS256"}` → not flagged by this rule.

### 3.2 `jwt_x5c_inline` (blocks)
- Header `{"alg":"RS256","x5c":["MIIC…"]}` → 403.
- Header with inline `{"jwk":{…}}` → 403.
- Negative: header with no `x5c`/`jwk` → not flagged.

### 3.3 `jwt_kid_injection` (blocks)
- `{"kid":"/dev/null"}`, `{"kid":"../../etc/passwd"}`,
  `{"kid":"k' OR '1'='1"}`, `{"kid":"http://attacker/key"}` → 403.
- Negative: `{"kid":"550e8400-e29b"}`, `{"kid":"keys/active"}`,
  `{"kid":"android-2024"}` → not flagged (a single `/` is fine; only `../`,
  absolute system roots, schemes, and SQL metachars flag).

### 3.4 `jwt_jku_external` (blocks)
- Strict (empty allowlist): `{"jku":"https://attacker.evil.com/jwks.json"}` →
  403. Same for `x5u`.
- With `jku_allowed_domains: ["auth.example.com"]`:
  `{"jku":"https://auth.example.com/jwks"}` → **allowed** (not flagged);
  `{"jku":"https://evil.com/jwks"}` → 403.
- With `["*.example.com"]`: `https://keys.example.com/…` allowed;
  `https://example.com/…` (bare apex) → still flags.
- Sneaky host: `{"jku":"https://auth.example.com@evil.com/jwks"}` → the real
  host is `evil.com` (after `@`) → 403 even with `auth.example.com` allowlisted.

### 3.5 `jwt_time_forged` (blocks)
- Payload `{"exp":9999999999}` (year 2286) → 403.
- Payload `{"iat":0,"nbf":0}` → 403.
- Negative: payload with `iat` ≈ now and `exp` ≈ now + 1 h → not flagged.

### 3.6 `jwt_role_priv` (observe-only, opt-in)
- With `flag_privileged_roles: false` (default): payload `{"role":"admin"}` →
  **no** `jwt_role_priv` signal (this is the default and must stay quiet).
- Set `flag_privileged_roles: true`, restart, resend → the signal appears in
  the audit `fields.detectors[]`, but the request is **still allowed** (score 20
  never single-blocks). Verify the HTTP status is **not** 403 for a token whose
  *only* issue is `role:admin`.
- Negative even when enabled: `{"role":"user"}`, `{"role":"admin-readonly"}`
  (whole-value match) → not flagged.

### 3.7 Transport + non-JWT negatives
- Same `alg:none` token via `Authorization: Bearer <token>` → 403.
- `Authorization: Basic dXNlcjpwYXNz` → not flagged (not a JWT).
- A normal session cookie `sid=abc123sessionid` (not JWT-shaped) → not flagged.
- A well-formed, normal token (`{"alg":"HS256"}` + sane claims) → **allowed**.
  This is the most important negative: legitimate traffic must pass clean.

---

## 4. Enforce vs. log_only (don't be fooled by the header)

In **enforce** mode a flagged structural rule returns 403. In **log_only** the
same request is **allowed (200/upstream status)** but the audit log records the
detection and `X-WAF-Action` shows the would-be block. To confirm which mode is
active, check `X-WAF-Mode` and the actual HTTP status — not `X-WAF-Action`
alone. You can scope just this detector to log_only with
`set_profile { policies: ["jwt_inspection"], mode: "log_only" }`.

---

## 5. What "pass" looks like

- All §3.1–3.5 structural cases return 403 (enforce) with the right tag.
- §3.6 role cases never 403 on the role alone; off by default, observe-only when
  enabled.
- All §3.7 negatives — and any of your real production tokens — pass clean.
- No regression: a request the WAF used to allow/deny for non-JWT reasons
  behaves the same (the detector only *adds* JWT signals; it changes nothing
  else).

If a real production token is flagged, capture it (redact the signature) and
file it — that's a false positive to tune, and the structural rules are designed
to have effectively none on well-formed tokens.

---

## 6. Cross-refs

- [`detectors/jwt-inspection.md`](./detectors/jwt-inspection.md) — engineering reference (rules, scores, config).
- [`../../plans/issues/archived/JWT_ATTACK_REPORT.md`](../../plans/issues/archived/JWT_ATTACK_REPORT.md) — the source report + technique catalogue.
- [`risk-scoring.md`](./risk-scoring.md) — how 80 / 70 / 20 interact with thresholds.
