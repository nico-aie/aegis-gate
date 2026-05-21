---
id: 2026-05-17-rate-limit-keyed-by-ip-only
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · rate limit
component: crates/aegis-security/src/rate_limit/ip_limiter.rs · sliding.rs · bucket.rs
interop_contract: official rules §5.2 #02 (per IP AND per user-session) · Security 40/120
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-002 · Rate limiter keys on `IpAddr` only — §5.2 demands per-IP **AND** per-user-session; distributed credential stuffing trivially evades

## Summary

Official rules §5.2 #02 are explicit:

> *"Sliding window per IP **VÀ** per user-session — không chỉ per IP.
> Token bucket cho burst control"*

The shipped `IpRateLimiter` is per-IP only. Its `consume(ip: IpAddr)`
signature admits no session or user discriminator, and the underlying
`DashMap<IpAddr, VecDeque<Instant>>` only buckets by IP.

The Attack Battle (§7) explicitly lists "Distributed credential
stuffing với IP rotation" as a mandatory scenario. With per-IP-only
rate limiting, an attacker who rotates IPs (cheap on IPv6, doable on
IPv4 via residential proxy networks — exactly the scenario the
"per-user-session" requirement is designed to defeat) bypasses the
rate limit on EVERY request because each new IP gets a fresh bucket.

## Observed code path

[rate_limit/ip_limiter.rs:77-90](../../../../crates/aegis-security/src/rate_limit/ip_limiter.rs#L77-L90):

```rust
pub struct IpRateLimiter {
    ...
    map: DashMap<IpAddr, VecDeque<Instant>>,
    ...
}
```

[rate_limit/ip_limiter.rs:123](../../../../crates/aegis-security/src/rate_limit/ip_limiter.rs#L123) (paraphrased):

```rust
pub fn consume(&self, ip: IpAddr) -> Decision {
    let mut entry = self.map.entry(ip).or_default();
    ...
}
```

The underlying `sliding::check(state, key, ...)` at
[sliding.rs:18](../../../../crates/aegis-security/src/rate_limit/sliding.rs#L18) takes a generic `&str` key — so the
infrastructure supports session-keyed rate limiting. The bug is that
no caller wires it that way; every call site passes an IP-derived
string.

The token-bucket path (`bucket.rs:9-16`) delegates to
`StateBackend::token_bucket` — and per F-CRITICAL-007 from the
previous data-plane audit, the in-memory backend's token bucket is
mathematically broken (never refills). So even per-IP burst control
is degraded.

## Impact

- **Attack Battle scenario 02** (Distributed credential stuffing) —
  unavoidable evasion. Rotate one IP per request → every request
  passes rate limit → brute-force succeeds.
- **Security Effectiveness rubric (40 / 120)** — graders test this
  scenario explicitly. Failure on a headline vector.
- **Compounding with F-CRITICAL-001** (risk per-IP only) means
  the WAF has effectively NO per-session / per-user defense at all
  — every defense layer collapses to per-IP, exactly the failure
  mode the spec is designed to prevent.

## Suggested fix

**Option A — Run two parallel limiters and OR the deny decisions:**

```rust
pub struct CompositeLimiter {
    ip_limiter:      IpRateLimiter,
    session_limiter: KeyedRateLimiter,    // generic key type
    user_limiter:    KeyedRateLimiter,
}

impl CompositeLimiter {
    pub fn check(&self, ctx: &RequestCtx) -> Decision {
        let ip_dec      = self.ip_limiter.consume(ctx.peer.ip());
        let session_dec = ctx.session_id.as_ref()
            .map(|s| self.session_limiter.consume(s))
            .unwrap_or(Decision::Allow);
        let user_dec    = ctx.user_id.as_ref()
            .map(|u| self.user_limiter.consume(u))
            .unwrap_or(Decision::Allow);
        deny_wins(ip_dec, session_dec, user_dec)
    }
}
```

**Option B — Generic `RateKey` enum and one limiter map:**

```rust
pub enum RateKey {
    Ip(IpAddr),
    Session(String),
    User(String),
}

pub struct RateLimiter {
    map: DashMap<RateKey, VecDeque<Instant>>,
}
```

Caller checks against EACH applicable key — typically all three at
once. Cheaper than Option A in the common case (one map). Tier-aware
thresholds per `RateKey` shape (per-user limit lower than per-IP) are
trivial to add.

Wire session/user identity from:

- `ctx.session_id` — issued by the WAF (anonymous session cookie at
  first request).
- `ctx.user_id` — extracted from a JWT or session lookup if
  authenticated.

Cross-fix: `bucket.rs` MUST be fixed (or replaced) per F-HIGH-rate-limit-ddos
before the token-bucket burst control is usable at all. The
state-backend token-bucket bug from the proxy audit (F-CRITICAL-007)
also affects rate limit here.

## Verification

```sh
HOST="http://127.0.0.1:8080"

# Rotating IP, same session cookie — should rate-limit after threshold:
for i in $(seq 1 200); do
    SRC_PORT=$((20000 + i))                # forces curl to fresh tuple
    curl -ski --local-port $SRC_PORT "$HOST/login" \
        -H "Cookie: session=stable-session-id" \
        -d "user=alice&pass=guess$i" -o /dev/null -w "%{http_code} "
done; echo
# Expect: 200 (×N) then 429 ... — session-keyed rate-limit kicks in.
# Today (per-IP-only): 200 200 200 ... forever (each src port = new IP-bucket from kernel side; but actually each src port shares IP — let me clarify the repro)

# Better repro: use distinct loopback aliases (per §10 sandbox):
for i in $(seq 1 254); do
    curl -ski --interface 127.0.0.$i "$HOST/login" \
        -H "Cookie: session=stable" -d "user=alice&pass=p$i" \
        -o /dev/null -w "%{http_code} "
done
# Expect: after per-session threshold, all subsequent return 429.
# Actual today: all 200, session-keyed rate-limit not implemented.
```

Regression case in `tests/api/`: assert that 100 requests from 100
distinct source IPs but the same session cookie trigger rate limit
on the 101st.

## Severity rationale

CRITICAL. Explicit §5.2 requirement, explicit Attack Battle scenario,
explicit "loại ngay" framing of the per-IP-only failure in the rules.
Trivial to verify (any judge can test it in 30 seconds). Compounds
with F-CRITICAL-001 to make the WAF defenseless against distributed
attacks.
