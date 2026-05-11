# Unwired-stubs catalogue (2026-05-11)

> **Status:** Drafted 2026-05-11 as Phase 4 of the
> `plans/issue-fix/2026-05-11-policy-qa-and-audits` triage.
>
> The crate audits (LT-RUN-4 / LT-RUN-5) flagged a long tail of
> "this trait/struct exists in the source but isn't called from
> the data plane" findings. Most of them are not security
> incidents today — the trait shape ships against a deferred
> feature. They become real bugs the day someone wires them in.
>
> This file is the reference: every stub with a confirmed-zero
> caller in `aegis-proxy/src/` + `aegis-bin/src/` as of 2026-05-11,
> plus the contract status (required / not required / Phase-C
> deferred) so the person who wires each one in knows whether
> it's a contract obligation or a roadmap aspiration.

## Confirmation method

For each entry, `grep -rln '<symbol>' crates/aegis-proxy/src/
crates/aegis-bin/src/` returns zero hits as of commit
`3b01ade...` (PR #8 land). The stub still compiles + has unit
tests, but nothing in the live request path or the binary boot
sequence calls it.

---

## Challenge providers — CAPTCHA stubs

**File:** `crates/aegis-security/src/challenge/captcha.rs`

| Stub | Lines | Contract status |
|---|---|---|
| `CaptchaProvider` trait | 1-8 | **Not required.** Contract v2.3 §3 challenge: "client must solve a JS challenge OR proof-of-work." PoW alone satisfies the spec. |
| `Turnstile` | 11-30 | Not required. Always returns `Ok(true)`. |
| `HCaptcha` | 33-49 | Not required. Always returns `Ok(true)`. |
| `ReCaptchaV3` | 52-… | Not required. Always returns `Ok(true)`. |

**Why deferred:** PoW (`crates/aegis-security/src/challenge/pow.rs`)
is the production-shipped challenge path and satisfies the
contract. Vendor CAPTCHA integration is roadmap work that
requires (a) HTTP client + secret-manager plumbing to call the
vendor verify endpoints, and (b) an audit-mutated config
surface for the per-tenant secret + min-score knobs.

**Action if you wire it:** call sites would be the
challenge-escalation ladder
(`crates/aegis-security/src/challenge/ladder.rs`) and the
`Decision::Challenge { level: ChallengeLevel::Captcha }` arm
in `data_plane.rs`. Today `ChallengeLevel::Captcha` parses but
never fires because the ladder never escalates beyond PoW.

---

## Auth — JWT validator

**File:** `crates/aegis-security/src/auth/jwt.rs`

| Stub | Lines | Contract status |
|---|---|---|
| `JwtConfig` / `JwtClaims` / `JwtError` | 4-31 | **Not required.** Contract v2.3 §2.2 only requires *some* auth on control endpoints. The admin plane already uses argon2 + session cookie + CSRF (contract-conformant). |
| `validate(token, config, now)` | 37-… | Not required. Parses the base64 payload but never verifies the signature — `// In production, use jsonwebtoken crate with JWKS`. |

**Why deferred:** Admin auth ships via `aegis-control::api::login`
(argon2 + session cookie + CSRF) which the contract accepts.
JWT auth would be needed only if operators want a stateless
control-plane (no session store) — a roadmap item, not a gap.

**Action if you wire it:** swap the stubbed `validate` for a
`jsonwebtoken`-based implementation, plumb a JWKS fetcher with a
per-issuer cache, and add a config surface for `cfg.admin.
jwt_issuers[]`. Audit-mutated PUT path for the JWKS URL list.

---

## Auth — OPA client

**File:** `crates/aegis-security/src/auth/opa.rs`

**Contract status:** Not required. Rego-based external policy
evaluation is a roadmap feature; today's policy is expressed
through rules + tier config which the contract accepts.

**Action if you wire it:** add a `cfg.policy.opa.endpoint` config
surface, an HTTP client (reuse the `reqwest` secret-manager
client), and a call site in the request pipeline (most
likely between rule eval and detector eval). Note that the
contract doesn't accommodate OPA decision types like "deny
unless X" — you'd need to map them to `allow / block /
challenge / rate_limit / timeout / circuit_breaker`.

---

## Content scanning — ICAP

**Files:**
- `crates/aegis-security/src/content/icap/mod.rs`
- `crates/aegis-security/src/content/icap/codec.rs`
- `crates/aegis-security/src/content/icap/tcp.rs`

**Contract status:** Not required (Phase-C feature per module
doc). The contract calls out malware scanning as an optional
content-inspection layer, not a wire-required check.

**Why deferred:** ICAP RESPMOD/REQMOD scans add a network
round-trip per response — the latency budget needs an explicit
operator opt-in. The shipped response filter (PR #7) already
covers stack-trace + DLP + internal-IP scrubbing; ICAP would
add AV / payload reputation on top.

**Action if you wire it:**
- Add `cfg.response_filter.icap.{endpoint, timeout_ms,
  failure_mode}` config surface.
- Add an ICAP rung between the existing rungs in
  `Pipeline::on_body_frame` (after DLP, before pass-through).
- Per-content-type gate (don't ICAP-scan plain text, do scan
  octet-stream / multipart / archive types).
- New `OutboundAction::Abort { reason: "icap_quarantined" }`
  variant is already in place from PR #7.

---

## Audit sinks — SIEM exporters (Splunk HEC, Kafka, QRadar,
ArcSight)

**Status:** Symbols not present in the workspace as of
2026-05-11. The LT-RUN-5 finding referenced module names that
never landed; the audit fan-out today goes to:
- the in-memory `AuditRing` (dashboard live feed)
- the JSON audit log file (operator-configured path)
- the alert-receivers (Slack / Alertmanager / PagerDuty —
  these **are** shipped via `crates/aegis-control/src/api/
  alert_receivers.rs`)

**Contract status:** Not required. The contract specifies
audit-chain *shape* and accepts any sink that preserves the
shape.

**Action if added:** new sink crates under `crates/aegis-
control/src/audit/sinks/` consuming the `AuditBus`.

---

## License validator

**Status:** No `license` module in `aegis-security` or
`aegis-control` as of 2026-05-11. The LT-RUN-5 finding may
have been against a different repo or a deleted branch.

**Contract status:** Not relevant (the contract is silent on
licensing).

---

## Jaeger / OTLP tracing

**File reference:** Comment in `crates/aegis-proxy/src/
data_plane.rs:33` only — the OTLP exporter actually ships
through `crates/aegis-bin/src/otel.rs::init_or_default` (see
the `--features otel` build).

**Contract status:** Not required. The contract is silent on
tracing.

---

## Redis rate-limit backend

**Status:** The Redis dependency (`aegis-proxy/redis` feature)
ships and is used by the state backend (`StateBackend`
implementation against deadpool-redis). There is no separate
"Redis rate-limit backend" — the in-memory `IpRateLimiter` reads
from the state backend (which may be Redis-backed) when running
in a multi-node deployment.

**Contract status:** Working as designed.

---

## ACME auto-renew (PROXY-04 / 23)

**Status:** ACME is **shipped** — `instant-acme`-backed cert
issuance + the challenge store live in
`crates/aegis-proxy/src/acme_instant.rs` and are wired into
`run.rs:978`. The LT-RUN-5 finding for `PROXY-04 / 23` was
probably about a sub-feature of ACME (e.g. wildcard cert via
DNS-01 challenge, which uses HTTP-01 today).

**Action if extending:** add DNS-01 challenge solver behind a
feature flag; current HTTP-01 covers the common case.

---

## Network secret providers (Vault / AWS / GCP / Azure)

**Status:** All four ship behind feature flags
(`aegis-proxy/vault`, `aws`, `gcp`, `azure`). Default builds
don't pull them; deployments opt-in via Cargo features. The
LT-RUN-5 finding flagged these as "stubs" but they are real
working integrations — the gap was that the dashboard doesn't
have a config-surface for choosing one.

**Contract status:** Not required (the contract leaves secret
management to the operator).

**Action if surfacing:** add an audit-mutated PUT on
`/api/secrets/provider` that swaps the active backend without
restart. Today the choice is boot-time (env-driven).

---

## Network service-discovery (Consul / etcd / k8s)

**Status:** Three feature-gated implementations
(`aegis-proxy/consul`, `etcd`, `k8s`) ship and are wired into
`crates/aegis-proxy/src/sd/`. Default builds don't pull them.

**Contract status:** Not required.

---

## How this list will change

- **Trimmed** when a stub gets deleted (Phase 4 will remove
  truly-dead CAPTCHA + JWT modules).
- **Trimmed** when a stub gets wired (the entry moves into
  Architecture.md or a per-feature operator doc).
- **Grown** if a future audit catches a new "trait without
  callers" finding — same shape: file path + grep-confirmed
  zero-callers + contract status.

The principle behind the list: **a real stub is not the same as
a real bug.** A stub on a non-required code path is technical
debt to clean up at leisure. A stub on a contract-mandated
code path would be a critical bug — none of the entries above
fall into that bucket today.
