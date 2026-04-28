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
  thresholds:
    challenge_at: 40         # Allow → Challenge boundary
    block_at:     80         # Challenge → Block boundary
    max:          100
  decay_half_life: 5m        # legacy half-life decay (P6 trust
                             # recovery applies in addition)
  trust_recovery:            # P6: clean-traffic claw-back
    per_hour: 30             # cap on score reduction per hour
  strikes:                   # P6: lifetime malicious-event count
    block_at: 50             # permanent block at this many strikes
```

## P6 — strikes + trust recovery + adaptive mitigation

The legacy half-life decay is supplemented by two new policies:

- **Trust recovery** — a clean request claws back score capped at
  `trust_recovery.per_hour` per hour of elapsed clean traffic. One
  benign request can never reset a flagged client.
- **Strikes** — every malicious detection bumps a lifetime counter
  that *never decays*. Once `strikes.block_at` is reached, the IP
  is permanently blocked at the data plane until an operator runs
  `PUT /api/risk/{ip}/reset` (the request flows through the
  `AuditedMutate` pipeline so every reset lands an admin chain
  entry).
- **Adaptive mitigation** — the hot path classifier returns
  `Allow / Challenge / Block` based on `RiskThresholds`. Strike-
  blocked IPs short-circuit to `Block` regardless of how much the
  score has decayed.

### `/api/risk*` endpoints

```
GET /api/risk?limit=N        — top-N risk clients (sorted by strikes desc, score desc)
GET /api/risk/{ip}           — full snapshot for one client
PUT /api/risk/{ip}/reset     — operator override, audit-mutated
```

See [`dashboard-enterprise/api.md`](./dashboard-enterprise/api.md)
for response shapes.

## Implementation

- `aegis-security::risk::RiskEngine` — legacy half-life accumulator
- `aegis-security::risk::tracker::RiskTracker` — **P6** in-memory
  per-IP store with strikes + trust recovery; DashMap-backed; cheap
  to clone (Arc-shared). Hot path = one map lookup + bitfield AND.
- `aegis-control::api::risk` — `/api/risk*` HTTP surface
- `aegis-proxy::handle_risk_reset` — audit-mutated reset path

## Performance notes

- Composite key hashed once per request
- Decay amortized via lazy read (no global sweep loop)
- Single atomic add on the write path (`INCRBY` in Redis, fetch_add in memory)
- P6 strike check is one DashMap read + `u32` compare on the hot path
