# Risk Scoring (v2)

> **v1 → v2:** scores are now distributed via the `StateBackend` abstraction
> so a client's risk follows them across cluster nodes. The decision logic
> (Allow / Challenge / Block) is unchanged. Bot classification and JWT
> identity can now contribute to the composite key.

## Purpose

Every request contributes to a numeric risk score tied to a composite
identity. Thresholds drive the decision: low score → allow, medium →
challenge, high → block. Canary routes instantly max the score.

## Composite identity

```
RiskKey = (tenant_id, client_ip, device_fp, session, authenticated_user)
```

- `tenant_id` — v2; forces per-tenant isolation of scores
- `device_fp` — JA3/JA4 + UA hash (see [`device-fingerprinting.md`](./device-fingerprinting.md))
- `session` — session cookie or bearer-derived id
- `authenticated_user` — optional, present when JWT / OIDC validated

Any missing field collapses to `_`. The key hashes to a single state-backend
entry.

## Score accumulation

Sources (each contributes a configurable delta):

| Source | Typical delta |
|--------|--------------:|
| Attack detection hit (SQLi, XSS, path traversal, SSRF, header injection, recon) | 20 – 40 |
| Rate-limit rejection | +10 |
| Auto-block trip | +50 |
| Canary route touch | `max_score` |
| Rule engine `AddRisk` | rule-defined |
| Bot class `Known` / `Likely` | 30 / 15 (v2) |
| Schema violation (OpenAPI / GraphQL) | 25 (v2) |
| DLP pattern match in request | 30 (v2) |
| Threat-intel IP / domain feed hit | 40 (v2) |

Scores are capped at `max_score` (default 100) and persisted via the state
backend on every update.

## Decay

A background tokio task applies linear decay every minute:

```
score = max(0, score - decay_per_minute * elapsed_min)
```

Decay is computed on read in Redis-backed deployments (`GET + time_delta`
Lua script) to avoid a sweeping decay pass across millions of keys.

## Decision

```
score < allow_threshold  (default 30)  → Allow
score < challenge_thresh (default 70)  → Challenge
otherwise                              → Block
```

Thresholds are per-tier overridable; CRITICAL can drop `allow` to 10 and
`challenge` to 30.

## Canary honeypots

Canary routes are paths never advertised to legitimate users. Any touch
immediately sets the score to `max_score`. Canary paths are also recorded
with full request context for forensics.

```yaml
risk:
  thresholds: { allow: 30, challenge: 70 }
  decay_per_minute: 5
  max_score: 100
  canary_routes: [ "/admin/backup", "/.git/config", "/wp-admin" ]
```

## State backend

Identical pluggability to rate limiting:

- `in_memory` — DashMap<RiskKey, RiskScore>
- `redis` — keys `risk:{hash}` with TTL reset on update
- `raft` — (bonus) strongly consistent

**Split-brain safety**: on reconcile, take `max(local, remote)` so a
partition can only make the WAF stricter, never looser.

## Challenge escalation

When the score is in the challenge band, the request is routed to the
challenge engine (see [`challenge-engine.md`](./challenge-engine.md)).
Successful completion lowers the effective score for a configurable grace
period (cookie-bound), but the persisted score is unchanged.

## Configuration

```yaml
risk:
  thresholds: { allow: 30, challenge: 70 }
  decay_per_minute: 5
  max_score: 100
  canary_routes: ["/admin/backup", "/.git/config"]
  per_tier:
    critical: { thresholds: { allow: 10, challenge: 30 } }
```

## Implementation

- `src/risk/score.rs` — `RiskScore` with decay
- `src/risk/store.rs` — `RiskStore` + `RiskKey`
- `src/risk/engine.rs` — `RiskEngine::decide`, canary check
- `src/risk/backend_redis.rs` — Redis-backed impl (v2)

## Performance notes

- Composite key hashed once per request
- Decay amortized via lazy read (no global sweep loop)
- Single atomic add on the write path (`INCRBY` in Redis, fetch_add in memory)
