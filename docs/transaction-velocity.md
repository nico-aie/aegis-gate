# Transaction Velocity Tracking

## Purpose

Limit how often a specific user can perform sensitive actions. Where [rate limiting](./rate-limiting.md) controls overall request frequency, velocity tracking controls **transaction frequency** — withdrawals, deposits, password changes, address updates. This is the core defense against account takeover and fraudulent transactions on CRITICAL tier routes.

## What's a transaction

A transaction is any request to a CRITICAL tier endpoint that represents a **business action**:

- `POST /login` (credential verification)
- `POST /deposit` (account funding)
- `POST /withdrawal` (funds out)
- `POST /transfer` (funds between accounts)
- `POST /otp/request` (OTP issuance)
- `POST /otp/verify`
- `POST /password/change`

Each transaction type has its own velocity budget.

## Velocity budgets

Configured per route (or route pattern) and per identity scope:

```yaml
velocity:
  - route: "/login"
    scope: user_id       # user | ip | device | session
    max_per_window:
      - count: 5
        window_s: 300    # 5 login attempts per 5 minutes
      - count: 20
        window_s: 3600   # 20 per hour
    on_exceed: block

  - route: "/withdrawal"
    scope: user_id
    max_per_window:
      - count: 3
        window_s: 3600   # 3 withdrawals per hour
      - count: 10
        window_s: 86400  # 10 per day
    on_exceed: challenge

  - route: "/otp/request"
    scope: [user_id, device]
    max_per_window:
      - count: 3
        window_s: 60     # 3 OTP requests per minute
    on_exceed: block
```

Each route can have **multiple windows** — short-term burst prevention AND long-term caps. All windows must be below their limit; exceeding any window triggers the action.

## Scope

Transaction velocity can be scoped by:

- `user_id` — the authenticated user (default for CRITICAL)
- `ip` — source IP (catches attackers rotating accounts from one IP)
- `device` — device fingerprint (catches attackers using VPN rotation)
- `session`
- Composite: e.g., `[user_id, device]` tracks per-user-per-device velocity

## Storage

`DashMap<VelocityKey, SlidingWindowCounter>` where `VelocityKey` is `(route, scope_value)`. The sliding window is identical to the one used by [rate limiting](./rate-limiting.md) but keyed differently.

Counters expire after the longest configured window for that route (so a `24h` window keeps its data for 24 hours).

## Actions on exceed

- `block` — return 403, add 30 to risk score
- `challenge` — require PoW before the transaction proceeds
- `log_only` — passive mode, emit warning but allow (for tuning)

## Integration with user ID

`user_id` scope requires knowing who is making the request. The WAF extracts this from:

1. A signed session cookie (if the backend uses one, the WAF parses it via a configured secret)
2. The `Authorization` header (e.g., JWT — the WAF verifies the signature without validating claims, to prevent forgery)
3. A configured request body field (for unauthenticated endpoints like `/login`, the `user_id` comes from the submitted form)

If no user ID can be extracted, velocity tracking falls back to IP or device scope.

## Canary on velocity breach

A user exceeding velocity limits gets their **risk score set to 100** immediately. Any subsequent request from that user — even to non-CRITICAL endpoints — is blocked. This is a deliberate escalation: if someone is hitting `/withdrawal` 100 times in an hour, they should not be allowed to browse `/game/*` unmolested.

## Implementation

- `src/behavior/velocity.rs` — velocity counters, per-route budgets, action dispatch

## Design notes

- Velocity is enforced **before** the backend sees the request — the backend never even processes fraudulent transactions
- Configuration is hot-reloadable — operators can tighten limits during an active incident
- Windows are sliding (not fixed buckets) to prevent boundary-gaming attacks
