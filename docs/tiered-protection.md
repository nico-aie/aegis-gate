# Tiered Protection Policy (v2)

> **v1 → v2:** tiers are now **resolved after route matching** (see
> [`routing-ingress.md`](./routing-ingress.md)) and can be **overridden
> per tenant** ([`multi-tenancy.md`](./multi-tenancy.md)). CRITICAL tier
> is also hard-wired to PCI/HIPAA response validation
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
| **CATCH-ALL** | `/**` | Baseline SQLi/XSS, rate limit, known-bad IP blocking, full logging | Fail-open |

## Resolution order

Tiers are resolved **after** the route table match:

1. Route table (host + path) → `route_id`
2. `route.tier_override` wins if present
3. Else tenant tier overrides
4. Else cluster-wide tier table (first-match wins)
5. CATCH-ALL guarantees a match

Patterns are pre-compiled at config load and stored in an `ArcSwap`,
so classification is a tight loop on pre-built automata.

## Fail-close vs fail-open

The critical distinction of the tier system.

- **Fail-close (CRITICAL):** if any subsystem errors, times out, or
  panics, the request is blocked with 503. Better to refuse a login
  than let one through an unchecked pipeline.
- **Fail-open (other tiers):** failing subsystems are skipped with a
  warning log. A broken anomaly detector should not knock the
  static-asset endpoint offline.

See [`graceful-degradation.md`](./graceful-degradation.md) for the
per-layer timeout machinery that enforces this.

## Per-tenant overrides

Tenants can:

- Add routes to an existing tier
- Create tenant-local tiers with stricter settings
- Not **weaken** cluster-wide CRITICAL guarantees — admin API refuses

## Global rules (all tiers)

Regardless of tier, every request gets:

- Inbound + outbound inspection
- Audit logging (hash-chained, see [`audit-logging.md`](./audit-logging.md))
- Risk score calculation
- Global blacklist enforcement
- Response header hardening (see [`response-filtering.md`](./response-filtering.md))

## Configuration

```yaml
tiers:
  - name: critical
    routes: ["/login", "/otp", "/deposit", "/withdrawal", "/payments/*"]
    match_type: wildcard
    failure_mode: fail_close
    detectors: [sqli, xss, ssrf, brute_force, header_injection, body_abuse]
    rate_limit:
      requests: 10
      window_s: 60
      scope: [ip, session, device]
    challenge:
      enabled: true
      initial: js
      escalate_to: captcha
    response_schema: strict
    cache: disabled

  - name: high
    routes: ["/api/*", "/user/*", "/game/*"]
    match_type: wildcard
    failure_mode: fail_open
    # …

  - name: medium
    routes: ["/static/*", "/assets/*", "/public/*"]
    match_type: wildcard
    failure_mode: fail_open
    # …

  - name: catchall
    routes: ["/**"]
    match_type: wildcard
    failure_mode: fail_open

per_tenant_tiers:
  acme:
    - name: critical
      routes_add: ["/acme/wire-transfer"]
```

## Implementation

- `src/pipeline/tier.rs` — tier resolver + compiled pattern cache
- `src/config/schema.rs::TierConfig` — schema
- `src/pipeline/tenant_tier.rs` — per-tenant override merge

## Performance notes

- Tier resolution is O(number_of_tiers), not O(number_of_routes)
- Patterns compiled once at config load; hot path walks `ArcSwap`
- CATCH-ALL guarantees no per-request allocation for the "no match" path
