---
id: 2026-05-17-brute-force-per-ip-post-only
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · brute force / credential stuffing
component: crates/aegis-security/src/detectors/brute_force.rs
interop_contract: official rules §5.3 (Brute Force / Credential Stuffing) · Attack Battle scenario 02
status: open
test_mode: source-review
---

# F-CRITICAL-014 · `brute_force.rs` tracks per-IP only, POST only — official rules require detection of distinct password-spraying AND credential-stuffing patterns

## Summary

Official rules §5.3 (Attack Detection Coverage — BẮT BUỘC) for
brute-force:

> *Brute Force / Credential Stuffing: Per-user failed login counter,
> password spraying pattern (nhiều user khác nhau từ cùng IP)*

Two distinct signals named:

1. **Per-user failed-login counter** (`one user, many attempts` — classic brute-force lockout).
2. **Password spraying** (`many users, one IP` — modern distributed attack pattern).

Plus the Attack Battle (§7) scenario 02:

> *Bot Login & Credential Stuffing: Brute force login, password
> spraying từ nhiều IP khác nhau, **distributed credential stuffing
> với IP rotation***.

Three distinct attack shapes, each requiring a different key:

- Per-user count (key: `username`).
- Per-IP count of distinct users (key: `IP`).
- Distributed (no single-axis key works; need device fingerprint or
  behavior).

Shipped `brute_force.rs` implements ONLY per-IP timestamp-list
counting, and ONLY for POST requests:

- [brute_force.rs:39](../../../../crates/aegis-security/src/detectors/brute_force.rs#L39) — `Mutex<HashMap<IpAddr, Vec<Instant>>>` — IP-only.
- [brute_force.rs:91](../../../../crates/aegis-security/src/detectors/brute_force.rs#L91) — method filter is `POST` only.
- No username parsing from body.
- No password-spraying axis (distinct usernames per IP).
- No credential-stuffing detection (distributed via fingerprint).

## Impact

### Per-user brute-force missing

Modern auth APIs use a mix of `POST /login`, `PUT /password`,
`PATCH /credentials`, `GET /api/auth?token=...` (Basic auth in
header), `POST /oauth/token` (grant_type=password). Restricting to
POST misses several legitimate auth surfaces.

### Password-spraying missing

Spraying = same password against many usernames from one IP. Without
parsing the body's `username` field, the detector cannot count
distinct usernames per IP → spraying passes.

### Credential stuffing (distributed) missing

Distributed credential stuffing rotates IPs. Per-IP counter never
accumulates because each new IP gets a fresh bucket. Same root cause
as F-CRITICAL-002 (rate-limit per-IP only). Detection requires
device fingerprint (per F-CRITICAL-010 + F-CRITICAL-011) keying.

### Compounding bugs (filed in F-HIGH-detectors but worth noting here)

- Global `Mutex<HashMap>` on the request hot path — serializes
  every login attempt.
- HashMap has NO eviction — idle IPs stay forever; map grows
  unbounded under any sustained scan.
- Cap `(threshold * 2).max(20)` per IP drained from the front via
  `drain(0..drop_n)` under the same Mutex.

## Suggested fix

### Three-axis tracker

```rust
pub struct BruteForceTracker {
    per_user: DashMap<String, FailedAttempts>,         // username key
    per_ip_users: DashMap<IpAddr, HashSet<String>>,    // IP → distinct usernames (spraying)
    per_device: DashMap<String, FailedAttempts>,       // device_fp key (distributed)
    cfg: BruteForceConfig,
}

pub struct BruteForceConfig {
    pub per_user_max_failures: u32,                    // e.g. 5 in 15min
    pub per_user_window: Duration,
    pub per_ip_distinct_users_max: u32,                // e.g. 10 distinct users in 5min → spraying
    pub per_ip_window: Duration,
    pub per_device_max_failures: u32,
    pub per_device_window: Duration,
}

impl BruteForceTracker {
    pub fn record_failure(
        &self,
        ip: IpAddr,
        device_fp: Option<&str>,
        username: Option<&str>,
        now: Instant,
    ) -> Vec<BruteForceSignal> {
        let mut signals = vec![];

        // Axis 1: per-user counter (classic brute force).
        if let Some(user) = username {
            if self.bump_per_user(user, now) >= self.cfg.per_user_max_failures {
                signals.push(BruteForceSignal::UserLockedOut(user.to_string()));
            }
        }

        // Axis 2: per-IP distinct usernames (password spraying).
        if let Some(user) = username {
            let count = self.bump_distinct_users(ip, user.to_string(), now);
            if count >= self.cfg.per_ip_distinct_users_max {
                signals.push(BruteForceSignal::PasswordSpraying { ip, distinct_users: count });
            }
        }

        // Axis 3: per-device counter (distributed credential stuffing).
        if let Some(dev) = device_fp {
            if self.bump_per_device(dev, now) >= self.cfg.per_device_max_failures {
                signals.push(BruteForceSignal::CredentialStuffing(dev.to_string()));
            }
        }

        signals
    }
}
```

### Body parsing for `username`

Pull `username` (or `email`, `login`, configurable) from:
- JSON body (`{"username": "..."}`).
- Form body (`username=...`).
- Basic auth header (`Authorization: Basic <base64(user:pass)>`).
- OAuth token body (`grant_type=password&username=...`).

Bounded to first 4 KiB of body. Fall back to "unknown" if not found.

### Method filter expansion

Match `POST | PUT | PATCH` and the route's auth-action classification
(see F-CRITICAL-003 fix). Not just POST.

### Replace `Mutex<HashMap>` with `DashMap`

Trivial. Also eliminates the eviction/cap issue (DashMap supports
`retain()`).

### Add background eviction

```rust
tokio::spawn(async move {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        tracker.evict_expired();
    }
});
```

## Verification

```sh
HOST="http://127.0.0.1:8080"

# Test 1: classic brute force (one user, many attempts).
for i in $(seq 1 20); do
    curl -ski -X POST "$HOST/login" -d "username=alice&password=wrong$i"
done
# Expect: 429/403 after per_user_max_failures attempts.

# Test 2: password spraying (many users, one IP, one password).
for u in alice bob carol dave eve frank grace heidi ivan jack; do
    curl -ski -X POST "$HOST/login" -d "username=$u&password=Spring2026!"
done
# Expect: 429/403 after per_ip_distinct_users_max.

# Test 3: distributed credential stuffing (many IPs, same device).
for i in $(seq 1 20); do
    curl -ski --interface 127.0.0.$i -X POST "$HOST/login" \
        -H "User-Agent: SameUA/1.0" \
        -d "username=user$i&password=Spring2026!"
done
# Expect: 429/403 once per-device counter trips (assumes F-CRITICAL-010 fingerprint stable).
```

Regression cases per axis in `tests/security/brute_force/`.

## Severity rationale

CRITICAL. Two distinct §5.3 sub-requirements unimplemented;
Attack Battle scenario 02 explicitly probes the third (distributed).
Implementation is ~200 LoC of three-axis tracker + body parsing.
