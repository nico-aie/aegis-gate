# JWT attack-shape detection

> **Status:** Implemented — `aegis-security/src/detectors/jwt_inspection.rs`.
> Phases A1–A3 (2026-06-12), in response to
> [`../../../plans/issues/JWT_ATTACK_REPORT.md`](../../../plans/issues/JWT_ATTACK_REPORT.md).
> Plan: [`../../../plans/future/jwt-and-smuggling-detection.md`](../../../plans/future/jwt-and-smuggling-detection.md).

## Purpose

Decode JWTs carried in `Authorization: Bearer <jwt>` and `Cookie:` values
and flag **malicious structure** — the JWT analogue of the sqli / xss
detectors. Before this detector the WAF did no Base64URL decoding of tokens,
so alg-confusion, key-injection, and `kid`-traversal payloads passed straight
through (the report measured ~0% effective detection on 600 samples).

## Scope boundary — detection only, never validation

**This detector never verifies the signature, never handles a secret or key,
and makes no authenticity decision.** Signature verification, expected-alg
enforcement, and business-auth all belong in the router/gateway, not the WAF
(see [`zero-trust-mtls.md`](../zero-trust-mtls.md) and the project's
WAF-vs-gateway boundary). It pattern-matches attack *shapes* in
attacker-controlled input, exactly like every other detector here.

Two report techniques are therefore **out of scope by design** — they require
a key the WAF doesn't (and shouldn't) hold:

- **Weak-secret brute force** — the forged token has a *valid* signature; it is
  cryptographically indistinguishable from a real one. Mitigation is app-side
  secret entropy + rotation.
- **RS256 → HS256 confusion** — needs the app's expected algorithm and its
  public key. This is gateway/auth territory.

## What it inspects

For each request, in order (decoding at most the first 2 JWT-shaped tokens,
each header part capped at 16 KB):

1. `Authorization: Bearer <jwt>` (a bare JWT value is also accepted).
2. Every `Cookie` value matching the JWT shape
   `[A-Za-z0-9_-]+.[A-Za-z0-9_-]+.[A-Za-z0-9_-]*` — **any cookie name**, not a
   hardcoded `sid`. Matching on the token *shape* rather than a corpus cookie
   name avoids fixture-coupling.

The JWT **header** (part 0) and **payload** (part 1) are Base64URL-decoded
(no padding) and parsed as JSON objects. Any decode/parse failure is silent —
a token the WAF can't read is the gateway's problem, not a signal to raise.

## Rules + tags

| Tag (`fields.detectors[]`) | Fires when | Score | Action |
|---|---|---|---|
| `jwt_alg_none` | header `alg` is `none` / `null` / empty, **any case** (`None`, `NONE`, `nOnE`, …) | 80 | block |
| `jwt_x5c_inline` | header embeds inline key material — `x5c` cert chain or `jwk` | 80 | block |
| `jwt_kid_injection` | `kid` contains `../`, an absolute system path (`/etc/ /dev/ /proc/ /sys/`), a URL/file scheme (`http(s)://`, `file://`), or SQL metacharacters (`'`, `"`, `;`, `--`, space-delimited `OR`/`AND`/`UNION`/`SELECT`) | 80 | block |
| `jwt_jku_external` | header `jku` / `x5u` URL's host is outside `jku_allowed_domains` (empty allowlist = any external URL) | 80 | block |
| `jwt_time_forged` | payload `exp` > 10y out, `iat` > 10y old, or `iat == 0 && nbf == 0` (epoch-forged) | 70 | block |
| `jwt_role_priv` | payload `role` / `scope` claims a privileged value (`admin`, `administrator`, `superadmin`, `superuser`, `root`, `system`) | 20 | **observe** (opt-in) |

The structural rules (80 / 70) block on a single hit at the protective tiers.
The role heuristic is deliberately observe-only — see below.

### Coverage vs. the report

| Report technique | Outcome |
|---|---|
| `alg_none_no_signature`, `alg_none_capital_bypass` | **blocked** (`jwt_alg_none`) |
| `jku_ssrf_attacker_controlled_jwks` (+ `x5u`) | **blocked** (`jwt_jku_external`) |
| `x5c_cert_injection` (+ inline `jwk`) | **blocked** (`jwt_x5c_inline`) |
| `kid_header_path_traversal_or_sqli` | **blocked** (`jwt_kid_injection`) |
| `token_claim_manipulation` (time) | **blocked** (`jwt_time_forged`) |
| `token_claim_manipulation` (role) | **observed** (`jwt_role_priv`, opt-in) |
| `weak_secret_brute_forced` | out of scope (valid signature → app-side) |
| `rs256_to_hs256_confusion` | out of scope (needs key/expected-alg → gateway) |

## Why `jwt_role_priv` is observe-only and off by default

A legitimate admin carries `role: admin` on **every** request, so flagging it
is noisy by nature and carries real false-positive risk. It ships:

- **opt-in** — `cfg.detectors.jwt_inspection.flag_privileged_roles` defaults to
  `false`. Operators turn it on to *observe* the privileged-token surface, then
  decide whether to promote it.
- **observe-by-construction** — score **20** is below every per-request tier
  gate (critical 50 / high 60 / medium 70 / low 80), so it never single-blocks.
  Because cumulative IP-risk is **max-per-request + decay** (not a running sum),
  a steady-state admin sits at ~20 and never escalates to a block.

`role` is matched as a *whole* value (case-insensitive), so a distinct role
like `admin-readonly` does not match `admin`. `scope` is split on whitespace
(OAuth scope lists) and each token matched.

Promotion path (future): gate the signal on a second factor (e.g. new IP +
`role:admin`) and/or raise the score after traffic review — see the plan's §2.5.

## Configuration

```yaml
detectors:
  jwt_inspection:
    enabled: true                 # toggle the detector class on/off
    jku_allowed_domains: []       # hosts a jku/x5u URL may reference
    flag_privileged_roles: false  # opt-in role heuristic (observe-only)
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | Hot-toggleable via `PUT /api/detectors` (the `jwt_inspection` mask bit) or `set_profile { policies: ["jwt_inspection"], mode: "log_only" }`. |
| `jku_allowed_domains` | list of strings | `[]` (strict) | Literal host (`auth.example.com`) or `*.example.com` glob. Empty = any external `jku`/`x5u` flags. Boot-time only. |
| `flag_privileged_roles` | bool | `false` | Opt-in privileged-role heuristic. Boot-time only. |

`jku_allowed_domains` wildcard semantics match the open-redirect allowlist:
`*.example.com` matches `foo.example.com` and `a.b.example.com` but **not** the
bare apex `example.com`; list both to cover both.

Per-tier overrides apply via `cfg.detectors.per_tier.<tier>.jwt_inspection`
(`true`/`false`/omit-to-inherit), like every other class.

## Test corpus

Positive (should flag), all decoded from a header/payload:

- `{"alg":"none"}` / `{"alg":"None"}` / `{"alg":""}` → `jwt_alg_none`
- `{"alg":"RS256","x5c":["…"]}` / `{"jwk":{…}}` → `jwt_x5c_inline`
- `{"kid":"/dev/null"}`, `{"kid":"../../etc/passwd"}`, `{"kid":"k' OR '1'='1"}`,
  `{"kid":"http://attacker/key"}` → `jwt_kid_injection`
- `{"jku":"https://attacker.evil.com/jwks.json"}` (strict) → `jwt_jku_external`
- payload `{"exp":9999999999}` / `{"iat":0,"nbf":0}` → `jwt_time_forged`
- payload `{"role":"admin"}` with `flag_privileged_roles: true` → `jwt_role_priv`

Negative (must not flag):

- `{"alg":"HS256"}` / `{"alg":"RS256"}` / `{"alg":"ES256"}`
- `{"kid":"550e8400-e29b"}`, `{"kid":"keys/active"}`, `{"kid":"android-2024"}`
- `{"jku":"https://auth.example.com/jwks"}` with allowlist `["auth.example.com"]`
- payload with `iat`/`exp` within a sane window
- payload `{"role":"user"}` / `{"role":"admin-readonly"}` (whole-value match)
- non-JWT cookies, `Authorization: Basic …`, malformed Base64URL

See the `tests` module in
[`jwt_inspection.rs`](../../../crates/aegis-security/src/detectors/jwt_inspection.rs)
for the full table (71 cases) and
[`jwt-inspection-qc.md`](../jwt-inspection-qc.md) for the live QC plan.

## Cross-refs

- [`security-engine.md`](../security-engine.md) — risk-weight ladder + tag table.
- [`detectors/README.md`](./README.md) — detector index + tag catalogue.
- [`risk-scoring.md`](../risk-scoring.md) — how the 80 / 70 / 20 scores interact with `challenge_at` / `block_at`.
- [`tiered-protection.md`](../tiered-protection.md) — per-tier enforcement.
