# FEAT — Egress & internal-traffic visibility (design-first)

> **Type:** FEAT (committee round-2 🟡4) · **Status:** ☐ Not started — planned 2026-07-04, **design-first**
> **Track ID prefix:** `EG-<1–3>` · Largest and least-defined round-2 item — do last; EG-1 is a
> design doc, not code.

**Objective (intent, not letter):** detect suspicious activity *leaving* the environment, not just
attacks entering it — and make traffic between system components observable.

---

## 1. Honest scoping (what a reverse proxy can and cannot see)

Aegis sits inline on **inbound edge traffic + its responses**. It does *not* see:
- origin-initiated outbound connections (exfil over a direct socket, DNS tunneling from the origin);
- traffic between backend services that doesn't traverse the WAF.

Claiming "egress inspection" beyond the response path would be exactly the letter-vs-intent trap
(round-2 🟡6). The honest decomposition:

| Layer | Visibility today | Opportunity |
|---|---|---|
| **Response path** (origin → client through WAF) | Response-outcome channel shipped (AC track); AI response filter exists (`response_filter_put`, `admin_mutate.rs:5726`); response-header strip | **EG-2: response/exfil inspection** — the real, in-path win |
| **WAF's own internal flows** (fleet channel, Redis, etcd, upstream dials) | Health signals, SLO producers, zero_trust upstream identity | **EG-3: internal observability** — mostly wiring existing signals into one surface |
| **Origin-initiated egress** | None (out of path) | Out of scope; document the boundary + integration point (e.g. export to a NDR/egress proxy) — do not build |

## 2. Staging

### EG-1 — design doc + committee expectation-setting · **S** · START HERE
- One design doc: threat model (what exfil through the response path looks like), the honest
  boundary above, perf budget (response-path inspection is hot-path — body scanning cost must be
  bounded/sampled), and the intended committee story. Owner review before any code.

### EG-2 — response-path exfil/anomaly detection · **L**
Candidate detectors (final set per EG-1; all content-type-gated, size-capped, log-only first):
- **Sensitive-data patterns in responses**: card PANs (Luhn-checked), private-key/secret markers,
  bulk-PII shapes — sampled, never full-body on large streams.
- **Response-size/rate anomalies per client**: sudden large transfers to a high-risk IP (feeds
  the existing per-IP risk model — a risk-scored *response* signal, mirroring how
  `behavior_analyzer` scores requests).
- **Error-page information leaks**: stack traces / debug banners leaving the origin (cheap,
  high committee value).
- Actions: log/score only initially; blocking a response mid-stream has UX + correctness traps —
  enforcement is a later, explicit decision.
- Reuse: response-outcome channel plumbing (AC-P2 work) is the natural attachment point.

### EG-3 — internal observability surface · **M**
- One dashboard page ("Internal Flows"): fleet-channel health/latency, Redis/etcd round-trip +
  error rates, upstream dial outcomes by zone (data exists — zone-aware LB + passive health),
  zero_trust identity status for upstream mTLS, config-plane propagation lag.
- Mostly aggregation of existing signals (SLO producers, passive-health, `/api/upstreams`,
  telemetry) — the gap is presentation, not collection.
- Alert hooks into the existing multi-burn alerting rather than a new system.

## 3. Risks

| Sev | Risk | Mitigation |
|---|---|---|
| HIGH | Response-body scanning wrecks hot-path perf | content-type gate + size cap + sampling; release-profile bench gate per PR (LT-P1 profile); log-only default |
| MEDIUM | Over-promising "egress" to the committee | EG-1 states the boundary explicitly; ship the honest subset |
| MEDIUM | FP-prone PII patterns (Luhn on random digits) | validators (Luhn, entropy), score-don't-block, corpus from the FP-tuning harness |
| LOW | EG-3 dashboard scope creep | aggregation of existing signals only; no new collectors in v1 |

## 4. Acceptance

- [ ] EG-1 design doc reviewed by owner; committee framing agreed.
- [ ] EG-2: response-path detectors live in log-only with bench evidence; risk-model integration.
- [ ] EG-3: internal-flows page live from existing signals.
- [ ] Documented boundary: origin-initiated egress explicitly out of scope with integration guidance.
