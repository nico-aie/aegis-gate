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
> IP get independent buckets.
>
> **2026-05-19 — data-plane wire-up shipped.** `build_risk_key(peer_ip,
> headers, tls_fp)` populates the `session` axis from cookies and
> the `device_fp` axis from `blake3-16hex(JA4 ‖ User-Agent)` on the
> TLS path; the production data plane now calls the `*_with_key`
> variants. Plain HTTP still buckets by IP only (no TLS fingerprint
> available). The `tenant_id` axis was removed the same day —
> multi-tenancy was deprecated upstream and the field was
> hard-coded to `None` everywhere. New surgical reset endpoint
> `POST /api/risk/reset_key` wipes one bucket without disturbing
> siblings on the same IP; legacy `POST /api/risk/<ip>/reset`
> remains for IP-wide resets.

## Purpose

Every request contributes to a numeric risk score tied to a composite
identity. Thresholds drive the decision: low score → allow, medium →
challenge, high → block. Canary routes instantly max the score.

## Composite identity

```rust
pub struct RiskKey {
    pub ip: IpAddr,
    pub device_fp: Option<String>,
    pub session: Option<String>,
}
```

- `ip` — TCP peer IP (post-XFF). Always present. On a listener with
  `accept_proxy` on, "TCP peer" means the address asserted by a trusted
  PROXY-protocol header (the real client behind an L4 LB), not the LB's
  transport address — the real LB hop is recorded separately as the
  `proxy_via` audit field. See
  [`ip-reputation.md`](./ip-reputation.md#proxy-protocol-l4-real-client-ip).
- `device_fp` — `Some(blake3-16hex(JA4 ‖ UA))` on the TLS path;
  `None` on plain HTTP. See [`device-fingerprinting.md`](./device-fingerprinting.md).
- `session` — session-cookie value from the request; `None` when
  no recognised session cookie is sent.

The `authenticated_user` axis is **not on the current `RiskKey`** —
JWT/OIDC identity flows through a separate `ClientIdentity` channel
and contributes to risk via detector signals, not the bucket key.
The `tenant_id` axis was removed 2026-05-19 (deprecated upstream).

Any missing optional field stays `None` and buckets together with
other requests in that same state — e.g. plain-HTTP traffic without
a session cookie shares the IP-only bucket.

## Score reference

The risk score is the **sum of every signal** that fired on a request,
capped at `max_score` (default 100) and persisted per-RiskKey-bucket
via the state backend on every update. Two kinds of contributors:

### A. Detector signals (hardcoded per-class)

These come straight from `crates/aegis-security/src/detectors/*.rs`. A
single detector hit emits a `Signal { tag, score }`; the engine sums
all signals from the chain.

> **2026-05-20 recalibration (Option B), amended 2026-05-23.** The
> per-request block gate sums this request's signals and compares to
> the matched tier's `risk_threshold`. Defaults are a clean 10-apart
> ladder — **critical 50 / high 60 / medium 70 / low 80** — settable
> per profile via the `tiers:` config block (`tiers.<name>.risk_threshold`),
> or live via the dashboard *Edit Tier* modal. A single clear exploit
> (score 70 — sqli, xss, ssrf, path_traversal, cmdi, ssti, nosql, CRLF)
> blocks on critical/high/medium but **not** on `low` (2026-05-23 `low`
> was raised 70→80 so only the strongest single signals auto-block
> low-tier static-asset traffic). The detector ceiling is **80** (canary
> excepted): definitive-RCE — **Log4Shell, XXE = 80** — plus the
> **canary honeypot (100)** are the only detectors that block a lone
> request at `low`; a clear exploit there must stack (70 + any ≥10) or
> accumulate via the cumulative gate. At **high=60**, the score-60
> signals (AI, mass_assignment, velocity) block on a single hit at
> `high`. Weaker / probing signals (recon 25/50, oversize 30, …) stay
> below 60 and accumulate before blocking, so the FP guard holds. The
> **cumulative** bucket, by contrast, adds `max(signal)` per request
> (SEC-M003), not the sum. Values below are the single-source-of-truth
> scores from `crates/aegis-security/src/detectors/scores.rs`.
>
> When a detector fires but the summed score stays under the tier
> threshold, the request is forwarded as `allow` and labelled with the
> fired detectors in BOTH `X-WAF-Rule-Id` and the audit `rule_id` (they
> stay in lock-step), so the detection is never silent in the log.

| Detector | Tag | Score | Source |
|---|---|---:|---|
| SQL injection | `sqli` | **70** | `scores::sqli::SQLI` |
| XSS | `xss` | **70** | `scores::xss::XSS` |
| CSS injection | `css_injection` | **70** | `scores::xss::XSS` (emitted by `xss.rs`) — `@import`/resource-property `url(http…)`/attribute-selector exfil/`<style>` breakout, with control-byte deobfuscation |
| Path traversal | `path_traversal` | **70** | `scores::path_traversal::PATH_TRAVERSAL` |
| SSRF | `ssrf` | **70** | `scores::ssrf::SSRF` |
| Command injection (baseline) | `command_injection` | **70** | `scores::command_injection::BASELINE` |
| Log4Shell / JNDI | `command_injection` | **80** | `scores::command_injection::LOG4SHELL` — definitive-RCE ceiling; blocks at every tier incl. `low` |
| Template injection (SSTI) | `template_injection` | **70** | `scores::template_injection::TEMPLATE_INJECTION` |
| NoSQL injection | `nosql_injection` | **70** | `scores::nosql_injection::NOSQL_INJECTION` |
| Header injection — CRLF | `header_injection` | **70** | `scores::header_injection::CRLF` |
| Header injection — XFH poisoning | `header_injection` | **50** | `scores::header_injection::XFH` |
| Body abuse — XXE | `body_abuse` | **80** | `scores::body_abuse::XXE` — definitive-RCE ceiling; blocks at every tier incl. `low` |
| Body abuse — mass assignment | `body_abuse` | **60** | `scores::body_abuse::MASS_ASSIGNMENT` |
| Body abuse — proto pollution | `body_abuse` | **50** | `scores::body_abuse::PROTO_POLLUTION` |
| Body abuse — deep nesting | `body_abuse` | **35** | `scores::body_abuse::DEEP_NESTING` |
| Body abuse — oversize | `body_abuse` | **30** | `scores::body_abuse::OVERSIZE` |
| Open redirect | `open_redirect` | **50** | `scores::open_redirect::OPEN_REDIRECT` |
| Recon — scanner UA | `recon` | **50** | `scores::recon::TOOL` |
| Recon — probe path | `recon` | **25** | `scores::recon::PATH` |
| Brute force | `brute_force` | **50** (default) | `scores::brute_force::DEFAULT` (off by default; set per-route) |
| **Canary honeypot** (path hit) | `canary` | **100** | `detectors::canary` — operator-curated honeypot paths (`risk.canary_paths`); ~0 FP → max confidence, single-hit block at every tier. Default OFF. |
| **AI classifier** (verdict = attack) | `ai` | **50** | `scores::ai::AI` — runs ONLY when no Base detector matched (short-circuit). 2026-06-16: demoted 60→50 so a lone AI verdict no longer single-blocks on the catch-all `high` tier (60); it must stack with a rule detector except on `critical` (50) |

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

> Tier note (2026-05-21): there is **no automatic path→tier
> heuristic** anymore. Every request defaults to the **Low** tier
> unless a route sets `tier_override`. This example assumes the
> default (Low, per-request `risk_threshold` 80). Clear-exploit
> detector scores are 70 (see the table above).

```
T=0s   GET /api/users?q=1' OR '1'='1
       ─ detector chain fires: sqli (70)
       ─ per-request score = 70
       ─ Low tier per-request threshold = 80 → 70 < 80 → ALLOW the
         request (detected, forwarded). The IP's CUMULATIVE risk is
         now 70 (max(signal) per SEC-M003), past challenge_at (40).
       ─ strikes(IP) = 1

T=10s  GET /search?q=<script>alert(1)</script>
       ─ detector chain fires: xss (70)
       ─ per-request score = 70 → 70 < 80 → ALLOW (detected)
       ─ cumulative score (decay negligible after 10s)
                         = 70 + 70 = 140, saturated to max=100.
       ─ strikes(IP) = 2

T=30s  GET /etc/passwd via ../../../ traversal
       ─ detector chain fires: path_traversal (70)
       ─ per-request score = 70 → 70 < 80 → still ALLOW per-request
         on Low; but the IP's cumulative score is already at max=100.
       ─ Score 100 ≥ block_at (80) → access gate blocks every
         subsequent request from this IP, no matter how clean.
       ─ strikes(IP) = 3 (still below strikes.block_at=50, so decay
         can still recover this IP eventually).

T=5m+  Score has decayed from 100 to 50 (half-life 5 min):
       ─ Above challenge_at (40) but below block_at (80) — IP gets
         a JS challenge instead of a block. Solving lowers score
         in the cookie-bound grace period.
```

**Key thing to internalize**: the per-request score (one request's
detector signals summed) and the per-bucket cumulative risk score are
*two different numbers*. The first decides if THIS request gets
blocked at the route's tier gate. The second decides if SUBSEQUENT
requests from this IP get the challenge / access-gate-block
treatment. See
[security-engine.md § Risk model](./security-engine.md#risk-model)
for the full per-request vs per-bucket separation.

### Reading the two scores in the dashboard / audit

The Live Feed and the Investigation → Request detail drawer surface
**both** numbers under deliberately distinct labels. They are computed
differently and will often disagree — that is expected, not a bug:

| Label (UI) | Audit field | What it measures | Formula |
|---|---|---|---|
| **Request score (detectors)** | `fields.request_score` | how malicious *this one request* is | **sum** of this request's detector signals, capped at 100 |
| **IP risk (cumulative)** | `risk_score` | how malicious *the source* is over time | running per-`RiskKey` total; adds **`max(signal)`** per request (SEC-M003), capped at 100, then decays |

**Why a request can score 100 yet IP risk shows 70.** A request that
trips `sqli` (70) + `path_traversal` (70) has a *per-request* score of
`70 + 70 = 140 → capped 100`. But the cumulative bucket only ever adds
the **strongest single signal** (`max = 70`), never the sum — this is
SEC-M003, so one multi-detector request can't slam an IP straight to
100. On a fresh bucket (`strikes: 1` in the drawer) the cumulative is
therefore `0 + 70 = 70`. The displayed cumulative is the value **after**
this request was recorded, not before — send the same attack twice on
one session and the IP risk goes `70 → 100` (`70 + 70`, capped).

**Which number actually blocked the request** — read `Reason` / `rule_id`:
- `rule_id` = a **detector** (e.g. `sqli`, `sqli,path_traversal`) → the
  **per-request** gate fired (this request's summed score ≥ the tier's
  `risk_threshold`). The IP-risk value shown is just context.
- `rule_id` = `risk-score` / `risk-challenge` → the **cumulative** gate
  fired (the source's running score crossed `block_at` / `challenge_at`).
  The contributing detector rides in `fields.detectors`; the feed renders
  it as `risk-challenge · recon_path`, or `· cumulative` when this request
  itself scored 0 and was actioned purely on the IP's accumulated history.

## Worked example: AI detector chain

When `cfg.ai.enabled: true` and the binary is built `--features ai`,
the AI detector runs **after** the regex detectors as a tiebreaker.

```
GET /search?q=<obfuscated SQLi payload that regex misses>
  ─ regex chain: no signal (heuristic miss)
  ─ AI detector runs: model verdict = attack, confidence 0.94
  ─ AI signal = 50
  ─ per-request score = 50 → exceeds tier threshold for /api (70)?
    No (50 < 70) → ALLOW with strike + cumulative bump
  ─ score after this single request: 50 → past challenge_at (40)
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
  per-RiskKey-bucket store with strikes + trust recovery; DashMap-backed; cheap
  to clone (Arc-shared). Hot path = one map lookup + bitfield AND.
- `aegis-control::api::risk` — `/api/risk*` HTTP surface
- `aegis-proxy::handle_risk_reset` — audit-mutated reset path

## Performance notes

- Composite key hashed once per request
- Decay amortized via lazy read (no global sweep loop)
- Single atomic add on the write path (`INCRBY` in Redis, fetch_add in memory)
- P6 strike check is one DashMap read + `u32` compare on the hot path
