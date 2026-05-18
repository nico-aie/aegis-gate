# Risk Scoring (v2)

> **Status:** Implemented — `risk/{tracker,mod}.rs` + `aegis-core::RiskKey`. P6 strikes + trust recovery.
>
> See [`../../plans/plan.md`](../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

> **v1 → v2:** scores are now distributed via the `StateBackend` abstraction
> so a client's risk follows them across cluster nodes. The decision logic
> (Allow / Challenge / Block) is unchanged. Bot classification and JWT
> identity can now contribute to the composite key.

> **2026-05-18 Phase E (F-CRITICAL-001):** the `RiskTracker` map key
> upgraded from bare `IpAddr` to `RiskKey` (composite). The legacy IP-
> only methods (`record_malicious(ip, …)`, `level(ip)`, `snapshot(ip)`,
> `reset(ip)`, `is_strike_blocked(ip)`) keep working and internally
> construct `RiskKey::from_ip(ip)`. New `*_with_key` / `*_for_key`
> variants take the full composite — two sessions on the same NAT'd
> IP get independent buckets. IP-only and composite calls populate
> different buckets even at the same IP, which is exactly the
> auditor's intent: don't conflate sessions.

## Purpose

Every request contributes to a numeric risk score tied to a composite
identity. Thresholds drive the decision: low score → allow, medium →
challenge, high → block. Canary routes instantly max the score.

## Composite identity

```
RiskKey = (client_ip, device_fp, session, authenticated_user)
```

- `device_fp` — JA3/JA4 + UA hash (see [`device-fingerprinting.md`](./device-fingerprinting.md))
- `session` — session cookie or bearer-derived id
- `authenticated_user` — optional, present when JWT / OIDC validated

Any missing field collapses to `_`. The key hashes to a single state-backend
entry.

## Score reference

The risk score is the **sum of every signal** that fired on a request,
capped at `max_score` (default 100) and persisted per-IP via the state
backend on every update. Two kinds of contributors:

### A. Detector signals (hardcoded per-class)

These come straight from `crates/aegis-security/src/detectors/*.rs`. A
single detector hit emits a `Signal { tag, score }`; the engine sums
all signals from the chain.

| Detector | Tag | Score | Source |
|---|---|---:|---|
| SQL injection | `sqli` | **40** | `detectors/sqli.rs:80` |
| XSS | `xss` | **35** | `detectors/xss.rs:77` |
| Path traversal | `path_traversal` | **45** | `detectors/path_traversal.rs:61` |
| SSRF | `ssrf` | **50** | `detectors/ssrf.rs:74` |
| Header injection / CRLF / smuggling | `header_injection` | **40** | `detectors/header_injection.rs:62` (each variant) |
| Recon — common probe path | `recon` | **25** | `detectors/recon.rs:88` |
| Recon — canary path | `recon` | **30** | `detectors/recon.rs:101` |
| Body abuse — oversize | `body_abuse` | **30** | `detectors/body_abuse.rs:67` |
| Body abuse — nesting depth 1 | `body_abuse` | **35** | `detectors/body_abuse.rs:85` |
| Body abuse — nesting depth 2 | `body_abuse` | **50** | `detectors/body_abuse.rs:93` |
| Body abuse — nesting depth 3 | `body_abuse` | **60** | `detectors/body_abuse.rs:109` |
| Brute force | `brute_force` | configurable in YAML | `detectors/brute_force.rs:97` (default off; set per-route) |
| **AI classifier** (verdict = attack) | `ai` | **60** | `detectors/ai/mod.rs:130` — fires whenever the ONNX model returns `attack` with confidence ≥ `ai.confidence_threshold` |

### B. Identity / behaviour signals (configurable in YAML)

These come from `cfg.risk.weights.*`; default is **10 each**. Tune to
shift the balance between content-based detectors and identity-based
heuristics.

| Source | YAML key | Default delta |
|---|---|---:|
| ASN reputation (hosting / VPN / Tor exit) | `risk.weights.bad_asn` | **10** |
| Bad TLS / HTTP fingerprint (JA4) | `risk.weights.bad_ja4` | **10** |
| Failed authentication | `risk.weights.failed_auth` | **10** |
| Generic detector hit modifier | `risk.weights.detector_hit` | **10** |
| Unknown bot class | `risk.weights.bot_unknown` | **10** |
| Repeat offender (history bonus) | `risk.weights.repeat_offender` | **10** |

### C. Rule engine + special

| Source | Score |
|---|---|
| Rule engine `RaiseRisk(delta)` action | rule-defined |
| Canary route touch | `max_score` (immediate cap) |
| Threat-intel feed hit (STIX/TAXII) | varies by feed config |

## Worked example: SQLi probe lifecycle

Tracing one IP through three requests on a default `prod-balanced`
config (`challenge_at: 40`, `block_at: 80`, `max: 100`,
`decay_half_life: 5m`).

```
T=0s   GET /api/users?q=1' OR '1'='1
       ─ detector chain fires: sqli (40)
       ─ per-request score = 40
       ─ tier_threshold for /api routes = 70 (high tier) → ALLOW the
         request through (40 < 70) — but the IP's CUMULATIVE risk
         is now 40, just at the challenge boundary.
       ─ strikes(IP) = 1

T=10s  GET /search?q=<script>alert(1)</script>
       ─ detector chain fires: xss (35)
       ─ per-request score = 35
       ─ tier_threshold for / catch-all = 90 (low tier) → ALLOW
       ─ cumulative score after decay (~negligible after 10s)
                         = 40 + 35 = 75 — past challenge_at (40),
         next request from this IP gets a 429 challenge.
       ─ strikes(IP) = 2

T=30s  GET /static/../../../etc/passwd
       ─ detector chain fires: path_traversal (45)
       ─ per-request score = 45 → THIS request is blocked at the
         tier gate (45 < 90, so per-request gate doesn't fire on
         catch-all; on /api with threshold 70, 45 < 70 still allows
         — but the IP's cumulative score is now 75 + 45 = 120,
         saturated to max=100).
       ─ Score 100 ≥ block_at (80) → access gate blocks every
         subsequent request from this IP, no matter how clean.
       ─ strikes(IP) = 3 (still well below strikes.block_at=50, so
         decay can still recover this IP eventually).

T=5m+  Score has decayed from 100 to 50 (half-life 5 min):
       ─ Above challenge_at (40) but below block_at (80) — IP gets
         a JS challenge instead of a block. Solving lowers score
         in the cookie-bound grace period.
```

**Key thing to internalize**: the per-request score (one request's
detector signals summed) and the per-IP cumulative risk score are
*two different numbers*. The first decides if THIS request gets
blocked at the route's tier gate. The second decides if SUBSEQUENT
requests from this IP get the challenge / access-gate-block
treatment. See
[security-engine.md § Risk model](./security-engine.md#risk-model)
for the full per-request vs per-IP separation.

## Worked example: AI detector chain

When `cfg.ai.enabled: true` and the binary is built `--features ai`,
the AI detector runs **after** the regex detectors as a tiebreaker.

```
GET /search?q=<obfuscated SQLi payload that regex misses>
  ─ regex chain: no signal (heuristic miss)
  ─ AI detector runs: model verdict = attack, confidence 0.94
  ─ AI signal = 60
  ─ per-request score = 60 → exceeds tier threshold for /api (70)?
    No (60 < 70) → ALLOW with strike + cumulative bump
  ─ score after this single request: 60 → past challenge_at (40)
  ─ strikes(IP) = 1
```

Mean AI inference 694 µs, +1.1 ms p95 / +2.3 ms p99 — see
[`detectors/ai-detector.md`](./detectors/ai-detector.md) for perf
profile and the 26-feature extractor list.

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

See [`control-plane/enterprise/api.md`](../control-plane/enterprise/api.md)
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
