# Brute Force & Credential Stuffing Detection

> **Status:** Implemented — `detectors/brute_force.rs` runs per-IP, per-user
> (password-spraying), and per-device axes on login paths, plus **OTP-spray** and
> **OTP-grind** axes on second-factor paths (BF-OTP, 2026-07-06). Counts are
> per-node by default and fleet-aggregable via `detectors.brute_force.count_scope: fleet`.
>
> See [`../../../plans/plan.md`](../../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

## Purpose

Detect attempts to guess credentials — either by trying many passwords against one account (brute force) or trying one password against many accounts (credential stuffing). These are the most common attacks on login endpoints, and the most effective mitigation is at the WAF layer where the attacker can be stopped before the backend authentication system is even touched.

## Signals

### Per-IP / per-device / per-session failure count

Count failed authentication attempts (detected by response status or body) within a sliding window. If the count exceeds a threshold, escalate.

### Per-account failure count

Count failures targeting a specific username, regardless of source. This catches distributed brute force (one IP per attempt).

### Username enumeration

Requests with many different usernames from the same source indicate credential stuffing. Track unique usernames seen per IP in a sliding window.

### Password spray

One password, many usernames — typical of credential spraying. Track unique (password, username) pairs per IP; a fixed password across many usernames is a signal.

### Velocity and distribution

- Attempts faster than a human can type (<500ms apart) are bot-like
- Attempts spread evenly across accounts suggest automation

### OTP / second-factor brute force (BF-OTP)

Two request-path axes gate the OTP verify step (`/otp`, `/api/otp`, `/2fa/verify`,
`/mfa/verify`, `/challenge/verify`, `/totp`, … — exact-path allowlist). The identity is the
pre-auth `login_token` (→ `sid`/`session` cookie → `Bearer`); the `otp_code` is the guess
and is **never** used as the identity.

- **OTP spray (primary, IP-independent)** — many distinct sessions submitting the *same*
  `otp_code`. This is the fixed-code spray shape (bet that some account's code is `X`) that
  survives IP rotation: it keys on the code and counts **distinct identities**. Fires above
  **20** distinct identities / window → `brute_force_otp_spray`.
- **OTP grind** — one session (`login_token`) trying many distinct codes. Keys on the
  identity, counts **distinct codes**. Fires above **10** / window → `brute_force_otp`.

Both emit **score 40**, dedupe repeats to distinct-count semantics (killing retry/typo
false positives), hash the `otp_code` before use (never logged in plaintext), and aggregate
fleet-wide under `count_scope: fleet`. Thresholds are hardcoded constants (no per-detector
config). Design + evidence: `plans/issues/FEAT-otp-token-bruteforce-detection-2026-07.md`.

## Identifying failed auth

The WAF identifies a failed login without needing backend integration:

- Response status **401, 403** in response to `/login`, `/otp/verify`, or other CRITICAL-tier auth routes
- Response body containing configurable **failure markers**: `"invalid credentials"`, `"incorrect password"`, `"authentication failed"`, etc.
- Configurable per-site tuning

Successful logins are similarly identified by response status **2xx** with a `Set-Cookie` matching the configured session cookie name.

## Storage

`DashMap<BruteForceKey, FailureRecord>`:

```rust
enum BruteForceKey {
    Ip(IpAddr),
    Device(DeviceFingerprint),
    Account(String),               // hashed username
    IpAndAccount(IpAddr, String),
}

struct FailureRecord {
    attempts: VecDeque<Instant>,
    unique_accounts: HashSet<AccountHash>,
    last_reset: Instant,
}
```

Usernames are hashed before storage (SHA-256) so raw credentials never appear in WAF state.

## Escalation

Thresholds and actions (all configurable):

| Condition | Action |
|---|---|
| 5 failures from one IP in 5 min | Challenge (PoW) on next login attempt |
| 10 failures from one IP in 5 min | Block IP for 30 min |
| 3 different usernames failing from one IP in 1 min | Flag credential stuffing, block |
| 20 failures against one account in 10 min | Lock account (notify backend), alert |
| Per-account lockout triggered by multiple IPs | Network-wide incident flag, dashboard alert |

## Configuration

```yaml
detection:
  brute_force:
    enabled: true
    failed_markers:
      - "invalid credentials"
      - "incorrect password"
    auth_routes:
      - "/login"
      - "/otp/verify"
    success_cookie_name: "session_id"
    thresholds:
      per_ip:
        failures: 5
        window_s: 300
        action: challenge
      per_ip_aggressive:
        failures: 10
        window_s: 300
        action: block
        block_ttl_s: 1800
      per_account:
        failures: 20
        window_s: 600
        action: lock_account
      stuffing:
        unique_accounts: 3
        window_s: 60
        action: block
```

## Integration with velocity tracking

Brute force detection complements [transaction velocity](../transaction-velocity.md). Velocity enforces "you cannot call /login more than 5 times per 5 minutes"; brute force detection adds "... and if those 5 calls **fail**, we treat you as hostile."

## Implementation

- `src/detection/brute_force.rs` — per-IP / per-device / per-account counters + detection logic

## Design notes

- Usernames are hashed in WAF state to avoid storing credentials in-memory
- The WAF never sees passwords — by design, it classifies failures by response, not by request content
- Account lockout signals the backend via an audit event, not a direct API call (keeps the WAF passive)
- Challenge-before-block gives real users with a forgotten password a way to recover, while escalating on persistent attackers
