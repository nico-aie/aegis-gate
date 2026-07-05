# EG-1 design — egress & internal-traffic visibility

> Deliverable of [FEAT-egress-internal-observability](../../issues/FEAT-egress-internal-observability-2026-07.md)
> (committee round-2 🟡4). Drafted 2026-07-05. **This document gates EG-2/EG-3 —
> no code until the owner signs off on the scope, the detector set, and the
> perf budget below.**

## 1. The honest boundary (read this first)

Aegis is an inline reverse proxy. It sees **inbound edge traffic and the
responses to it** — nothing else. Three traffic classes, three different
answers:

| Class | Visibility | This plan |
|---|---|---|
| Responses flowing origin → client **through the WAF** | Full (headers + body, already terminated here) | **EG-2** — the real, in-path win |
| The WAF's **own** internal flows (fleet channel, Redis/etcd, upstream dials, config plane) | Full (we originate them) | **EG-3** — presentation of existing signals |
| **Origin-initiated egress** (direct sockets from backends, DNS tunneling, lateral movement between services that never traverse the WAF) | **None. Physically out of path.** | Out of scope — declared, not hand-waved |

Claiming more than row 1+2 would be the letter-vs-intent trap the committee
itself flagged (🟡6). The committee story: *"the WAF inspects everything that
crosses it — in both directions — and tells you plainly what it cannot see;
for origin-initiated egress, deploy an egress gateway/NDR and here is the
integration point."* Integration guidance (not build): audit-bus SIEM sinks
already ship 9 formats — an external NDR can correlate on `request_id`.

## 2. Threat model for the response path

What exfiltration/leakage actually looks like in traffic we DO see:

- **T1 — Bulk data in responses to a compromised session.** SQLi/IDOR that got
  past request-side detection returns 10⁴ rows where the endpoint normally
  returns 10¹. Signature: response size / row-shape anomaly per (route,
  client-risk) pair.
- **T2 — Secret material leaving.** Private-key PEM markers, cloud credential
  shapes (`AKIA…`, `-----BEGIN`), bearer tokens in bodies that should carry
  none.
- **T3 — Cardholder/PII sweeps.** Many Luhn-valid PANs or many email/phone/id
  shapes in one response — density is the signal, single occurrences are
  normal business.
- **T4 — Error-page information leaks.** Stack traces, framework debug pages,
  internal IPs/banners on 5xx bodies. Cheap to detect, high committee value,
  and `response_filter` already scrubs the header half.
- **T5 — Slow-drip exfil.** Sustained elevated bytes-out to one high-risk
  client across many small responses. Signature: per-risk-key egress-volume
  accounting, not per-response inspection.

Non-goals: TLS-in-TLS covert channels, timing channels, exfil via request
path (already covered), anything in class 3 above.

## 3. What already exists (verified 2026-07-05; re-verify at EG-2 kickoff)

| Building block | State | Reuse |
|---|---|---|
| Response-outcome hook (AC-P3-b) — `enumeration.observe_outcome` / `behavior_analyzer.observe_outcome` run in the data-plane wrapper with upstream status | **Live** | The attachment point for every EG-2 signal; extend the hook payload (status → +size, +content-type, +sampled body handle) |
| `response_filter` — header strip-list, stack-trace scrub flags | **Live** (header strip wired AC-P1-d) | T4 detection is the *observability* twin of the existing scrub: count + audit what was scrubbed instead of silently removing |
| `dlp` config (`patterns`, `fpe`, `max_scan_bytes`) | **Config shell, defaults empty/0** | T2/T3 pattern set lives here; `max_scan_bytes` is the natural body-scan cap knob |
| Per-IP risk model (`RiskTracker`, composite keys) | **Live** | EG-2 detectors **score, never block**: response signals feed `record_malicious` deltas exactly like `behavior_analyzer` does for requests |
| Bench gate (LT-P1 release profile) | **Live** | Every EG-2 PR ships with before/after bench numbers |
| SLO producers, passive health, `/api/upstreams`, zone routing, config-plane versions, fleet channel | **Live** | EG-3 aggregates these — presentation, not collection |

## 4. EG-2 — response-path detectors (proposed set, log-only v1)

Ordered by value/cost; each independently shippable:

1. **T4 error-leak detector** (S): on status ≥ 500 (+ content-type text/html|json,
   first `max_scan_bytes` only): stack-trace/debug-banner regexes (reuse the
   scrub list). Emits Detection-class audit event + risk delta. No new config.
2. **T5 egress-volume accounting** (S–M): bytes-out per risk-key sliding
   window via the outcome hook (size is already known — no body access).
   Anomaly = window volume > percentile-of-route baseline AND client risk >
   threshold. Feeds risk score.
3. **T2/T3 sensitive-data sampling** (M–L): content-type-gated
   (json/html/csv/text), size-capped (`dlp.max_scan_bytes`, default e.g.
   64 KiB), **sampled** (e.g. 1-in-N per route, always-on for
   challenge/block-band clients). Luhn-validated PANs, entropy-checked secret
   markers, PII-shape density thresholds. FP corpus from the l-tester harness
   before default-on.

Hard rules for all three:
- **Log/score only in v1.** Blocking a response mid-stream truncates bodies
  and corrupts client state; enforcement is a separate, explicit decision
  after FP data exists.
- **Streaming responses (SSE, websocket, tunnels) are exempt** from body
  inspection — outcome-hook metadata only.
- **Detectors default OFF** (same posture as `enumeration`/`behavior_analyzer`)
  until the FP-tuning track clears them.

### Perf budget (gate for every EG-2 PR)

- T4/T5 (no body copies beyond what's in memory): **≤ 1 % p99 latency, ≤ 2 %
  throughput** on the LT-P1 bench baseline.
- T1/T2/T3 body sampling at default rates: **≤ 3 % p99 / ≤ 5 % throughput**;
  body scan bounded by `max_scan_bytes`; zero allocations on the non-sampled
  path.
- Any PR that misses the budget ships sampling-rate reductions, not budget
  raises.

## 5. EG-3 — "Internal Flows" dashboard page (aggregation only)

One page, four cards, all from existing signals — **no new collectors in v1**:
fleet-channel health/latency (fleet snapshots: per-node `last_seen_ms` staleness +
latency histograms); Redis/etcd round-trip + error rate + writability
(`waf_state_backend_ops_total{op,outcome}` via `MeteredStateBackend` + readiness
signals — etcd has no dedicated health surface, it rides the same metric);
upstream dial outcomes by zone (passive-health `MemberHealth` + `/api/upstreams`
zone rollup + `waf_upstream_zone_routing_total`); config-plane propagation lag.

**Re-verification correction (2026-07-05):** the propagation-lag card is the one
place "data exists" was overstated — there is **no per-node applied-config-version
signal today** (`/api/about` is global build info; fleet snapshots carry no config
epoch). Options: (a) piggyback the active config version onto the existing fleet
snapshot each node already publishes (one field, not a new collector — preferred),
or (b) drop the card from v1. Owner picks at EG-3 kickoff. mTLS card note: the
`/api/mtls/*` identity tracker is **downstream** (client) identity; upstream
zero_trust status is thin — surface it via member health, don't promise more.

## 6. Decision points for the owner

1. **Detector order** — proposal: T4 → T5 → T2/T3 (value/cost). Veto/reorder?
2. **T2/T3 scope** — PAN+secret-markers only in v1, or full PII-shape set?
   (FP risk concentrates in the PII shapes.)
3. **EG-3 page name/placement** — "Internal Flows" as its own page vs a
   section on Health & SLOs.
4. **Committee wording** — sign off on the §1 boundary statement before it
   goes in the round-2 response.

## 7. Acceptance (mirrors the plan file)

- [ ] This doc reviewed by owner; §1 framing agreed → unlocks EG-2/EG-3.
- [ ] EG-2 detectors live log-only with bench evidence + risk-model wiring.
- [ ] EG-3 page live from existing signals.
- [ ] Out-of-scope boundary documented with integration guidance (§1).
