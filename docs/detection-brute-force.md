# Brute Force & Credential Stuffing Detection

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

Brute force detection complements [transaction velocity](./transaction-velocity.md). Velocity enforces "you cannot call /login more than 5 times per 5 minutes"; brute force detection adds "... and if those 5 calls **fail**, we treat you as hostile."

## Implementation

- `src/detection/brute_force.rs` — per-IP / per-device / per-account counters + detection logic

## Design notes

- Usernames are hashed in WAF state to avoid storing credentials in-memory
- The WAF never sees passwords — by design, it classifies failures by response, not by request content
- Account lockout signals the backend via an audit event, not a direct API call (keeps the WAF passive)
- Challenge-before-block gives real users with a forgotten password a way to recover, while escalating on persistent attackers
