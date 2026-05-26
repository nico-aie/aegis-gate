# Tiered Protection Policy (v2)

> **Status:** Implemented — `aegis-core/src/tier.rs` + per-tier detector mask overrides (P2/P3).
>
> See [`../../plans/plan.md`](../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

> **v1 → v2:** tiers are now **resolved after route matching** (see
> [`routing-ingress.md`](../data-plane/routing-ingress.md)). CRITICAL
> tier is also hard-wired to PCI/HIPAA response validation
> ([`api-security.md`](./api-security.md)).

## Purpose

Not every route needs the same level of defense. A static image and a
login endpoint have wildly different threat profiles and latency budgets.
The tier policy applies fine-grained pipelines per route pattern,
balancing security against performance.

## The four tiers

| Tier | Example routes | Policy | Failure mode |
|---|---|---|---|
| **CRITICAL** | `/login`, `/otp`, `/deposit`, `/withdrawal`, `/payments/*` | Per-user rate limit, device FP, behavioral check, transaction velocity, challenge, response-schema validation | **Fail-close** |
| **HIGH** | `/api/*`, `/user/*`, `/game/*` | DDoS, IP+session rate limit, OWASP detection, smart caching, bot filter | Fail-open |
| **MEDIUM** | `/static/*`, `/assets/*`, `/public/*` | Basic rate limit, path-traversal detection, aggressive caching | Fail-open |
| **LOW** (default) | `/**` (catch-all routing role) | Baseline SQLi/XSS, rate limit, known-bad IP blocking, full logging | Fail-open |

> The "Example routes" column is **illustrative of what an operator
> assigns to each tier via route config** — it is NOT an automatic
> mapping. As of 2026-05-21 the WAF has **no built-in path→tier
> heuristic**: a request's tier comes solely from its route's
> `tier_override`, and traffic with no override defaults to **Low**.
> (The old hardcoded heuristic that auto-classified `/login`→critical,
> `/api`→high, etc. was removed — it blocked traffic at stricter
> thresholds based on paths the operator never configured, and is not
> part of the interop contract. Mark sensitive paths explicitly via
> `tier_override` and/or the canary honeypot detector.)

## Resolution order

Tiers are resolved **after** the route table match:

1. Route table (host + path) → `route_id`
2. `route.tier_override` wins if present
3. Else **default to Low** (no path heuristic)

Route patterns are pre-compiled at config load and stored in an
`ArcSwap`, so route resolution is a tight loop on pre-built automata.

## Fail-close vs fail-open

The critical distinction of the tier system.

- **Fail-close (CRITICAL):** if any subsystem errors, times out, or
  panics, the request is blocked with 503. Better to refuse a login
  than let one through an unchecked pipeline.
- **Fail-open (other tiers):** failing subsystems are skipped with a
  warning log. A broken anomaly detector should not knock the
  static-asset endpoint offline.

See [`graceful-degradation.md`](../data-plane/graceful-degradation.md) for the
per-layer timeout machinery that enforces this.

## Global rules (all tiers)

Regardless of tier, every request gets:

- Inbound + outbound inspection
- Audit logging (hash-chained, see [`audit-logging.md`](../observability/audit-logging.md))
- Risk score calculation
- Global blacklist enforcement
- Response header hardening (see [`response-filtering.md`](./response-filtering.md))

## Configuration

> **2026-05-25:** the old "tiers carry their own routes/detectors/rate
> limits" schema is gone. Tier membership is now a property of the
> **route** (`tier_override`), not the tier. The `tiers:` block only seeds
> per-tier *scoring knobs*; routing, detector masks, and rate limits are
> configured separately.

### `tiers:` block — per-tier scoring knobs

A map keyed by canonical tier name. Each entry is optional; omitted tiers
fall back to the code defaults (`TiersConfig` / `TierThresholdConfig` in
`aegis-core/src/config.rs`).

```yaml
tiers:
  # risk_threshold: per-request block score — a request blocks when its
  #   summed detector score reaches this value on the matched tier.
  # challenges_enabled: when true, a *cumulative* IP-risk score landing in
  #   the challenge band (risk.thresholds challenge_at..block_at) issues a
  #   429 PoW challenge instead of passing through as allow.
  critical: { risk_threshold: 50, challenges_enabled: true }
  high:     { risk_threshold: 60, challenges_enabled: true }
  medium:   { risk_threshold: 70, challenges_enabled: true }
  low:      { risk_threshold: 80, challenges_enabled: true }
```

### Assigning a route to a tier

Tier comes from the route's `tier_override`; a route with no override
falls back to the **code default, Low**. Routes live in the top-level
`routes:` table, not inside the tier block:

```yaml
routes:
  - id: login
    path: "/login"
    match_type: prefix
    upstream: app-pool
    tier_override: critical
  - id: catch-all          # fallback for every unmatched request
    path: "/"
    match_type: prefix
    upstream: stub-pool
    tier_override: high     # makes HIGH the *effective* default tier
```

> Note: the code default for an override-less route is **Low**, but the
> shipped configs pin the catch-all route to `tier_override: high`, so the
> *effective* default in practice is HIGH (per-request threshold 60, not
> Low's 80).

### Per-tier detector overrides

Detector class enable/disable is a separate block. The global toggles are
the baseline; `per_tier` overrides them for requests classified to that
tier (`Some(true)` force-on, `Some(false)` force-off, absent = inherit):

```yaml
detectors:
  sqli: { enabled: true }
  per_tier:
    critical:
      command_injection: true
      brute_force: true
    low:
      recon: false
```

## Implementation

- `crates/aegis-core/src/tier.rs` — the `Tier` enum + per-tier `default_failure_mode`
- `crates/aegis-proxy/src/route/mod.rs` — route → tier resolution (`tier_override`, default `Tier::Low`)
- `crates/aegis-core/src/config.rs` — `TiersConfig` / `TierThresholdConfig` (per-tier `risk_threshold` + `challenges_enabled`); `DetectorsConfig.per_tier` / `TierDetectorMask` for per-tier detector overrides

## Performance notes

- Tier resolution is O(number_of_tiers), not O(number_of_routes)
- Patterns compiled once at config load; hot path walks `ArcSwap`
- CATCH-ALL guarantees no per-request allocation for the "no match" path
