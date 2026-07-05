# FEAT — Egress & internal-traffic visibility (design-first)

> **Type:** FEAT (committee round-2 🟡4) · **Status:** ✅ COMPLETE 2026-07-05 — EG-1 signed off; EG-2
> T4/T5/T2/T3 detectors shipped on `feat/eg2-egress-observability` as **default-OFF, observability-only**
> (audit rows, no risk-score impact — owner call). EG-3 Internal Flows page **dropped** (duplicated
> Scaling/Upstreams). Open thread: EG-2 detectors default-OFF pending FP tuning.
> **Track ID prefix:** `EG-<1–3>` · Largest and least-defined round-2 item — do last; EG-1 is a
> design doc, not code → [`DESIGN-EG1-egress-response-inspection-2026-07.md`](../future/round-2-improvement/DESIGN-EG1-egress-response-inspection-2026-07.md).

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
| **Response path** (origin → client through WAF) | Response-outcome channel shipped (AC track — status-only payload today); response filter exists (regex scrub, 4 runtime rungs incl. body-frame pass — `handle_response_filter_put`, `admin_mutate.rs:5620`); response-header strip wired (buffered path only) | **EG-2: response/exfil inspection** — the real, in-path win |
| **WAF's own internal flows** (fleet channel, Redis, etcd, upstream dials) | Health signals, SLO producers, zero_trust upstream identity | **EG-3: internal observability** — mostly wiring existing signals into one surface |
| **Origin-initiated egress** | None (out of path) | Out of scope; document the boundary + integration point (e.g. export to a NDR/egress proxy) — do not build |

## 2. Staging

### EG-1 — design doc + committee expectation-setting · **S** · ✅ DELIVERED 2026-07-05 → [`DESIGN-EG1-egress-response-inspection-2026-07.md`](../future/round-2-improvement/DESIGN-EG1-egress-response-inspection-2026-07.md)
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

#### ⚠️ Coordination with the shipped Response Filtering surface (Settings page — verify at EG-2 kickoff)
The existing **Response Filtering** card (`ResponseFilterCard`, `pages.jsx:8141`; `Pipeline::on_body_frame`,
`aegis-security/src/pipeline.rs:223`) already runs EG-2's T2/T3/T4 scans — but in *mitigate-and-discard* mode.
EG-2 must converge with it, not build a second scanner:
- **Shared scan, not a second pass.** `redact_dlp` → `dlp::redact()` already sweeps every T2/T3 pattern
  (Luhn PANs, PEM keys, AWS/GitHub/Stripe/Slack/JWT/env-secret markers). `dlp::scan()` (`dlp/mod.rs:112`)
  already returns a structured `Vec<DlpMatch>` — the exact observability primitive T2/T3 needs; today
  `on_body_frame` discards it and keeps only the redacted string. EG-2 T2/T3 = surface that match set (audit
  + risk delta) from **one** `dlp::scan()` call. A separate EG-2 body pass would scan the body twice and
  blow the §4 perf budget (which assumes T2/T3 is the only body scan).
- **T4 twin already runs.** `scrub_stack_traces` / `mask_internal_ips` (same `on_body_frame`) are exactly
  T4's targets; T4 = count/audit what these scrub instead of silently rewriting (design §3).
- **Observe-before-redact (correctness).** `redact_dlp` is **default-ON** and rewrites PANs→`[REDACTED]`
  in `on_body_frame`. An EG-2 detector attached after redaction sees `[REDACTED]` and never fires — the
  observation point must precede the redact rewrite.
- **`max_scan_bytes` is a behavior change to a shipped feature.** The redact path ignores
  `dlp.max_scan_bytes` (2 MiB default is an unused config shell) and scans the full body with **no
  content-type gate**. EG-2's mandated content-type gate + size cap, applied to the shared scan, silently
  changes the default-ON redact rung (stops redacting past the cap). Decision needed: gate both together
  (accept the redact behavior change, document it) or keep redact full-body and cap only the EG-2 read.
- **Settings-page UX.** Response Filtering = *remove/mitigate* (default-ON, silent); EG-2 detectors =
  *observe/score/attribute* (default-OFF until FP-tuning). Two surfaces over the same patterns — state the
  relationship on the settings surface (e.g. a cross-link/sub-line) so operators don't read them as
  redundant or conflicting. No new rung on the Response Filtering card; EG-2 observability is its own
  detector config + the EG-3 "Internal Flows"/audit surface.

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

- [x] EG-1 design doc reviewed by owner (2026-07-05); committee framing agreed; decisions:
      T4→T5→T2/T3 order, T2/T3 v1 = PAN+secret markers only, own "Internal Flows" page,
      propagation-lag via config-version field on fleet snapshot.
- [x] EG-2: response-path detectors live — ✅ 2026-07-05 (branch `feat/eg2-egress-observability`).
      **Owner override (2026-07-05): observability-only — the detectors emit Detection audit rows
      (visible in Live Feed / Audit) but do NOT feed the risk score** (a response-side detector
      bumping risk that then blocks a *future* request was "hard to explain"). All three default-OFF:
      - **T4 error-leak** (`detectors::egress_leak`): 5xx text/json stack-trace / debug-banner /
        internal-IP detection, reusing the exact `response_filter` scrub patterns via new
        `has_stack_trace`/`has_internal_ip` oracles (observe + redact can't drift). Observe-before-
        redact at the buffered body-scrub site; stateless `scan()` → per-leak Detection audit only.
      - **T5 egress-volume** (`detectors::egress_volume`): per-IP sliding-window bytes-out (size-only,
        no body access) with a **read-only** volume-AND-elevated-risk FP guard (never raises risk);
        Allow-gated outcome hook (Content-Length size); audit only.
      - **T2/T3 sensitive-data** (`detectors::egress_sensitive`): content-type-gated, size-capped,
        1-in-N-sampled `dlp::scan()` (v1 scope PAN-density + secret markers; PII deferred); audit only.
- [x] EG-2: converged with the shipped Response Filtering path — observe-before-redact ordering
      confirmed; `max_scan_bytes` decision recorded → **cap only the EG-2 read, leave the shipped
      `redact_dlp` rung full-body and unchanged** (no behavior change to the default-ON scrubber).
      Content-type gate applies to the EG-2 read only. NB: v1 runs T2/T3 as its own capped+sampled
      `dlp::scan()` (the shipped path calls `dlp::redact()`, not `scan()`, so there is no existing
      `scan()` to piggyback yet); the double body pass is bounded by the cap + sampling. A future
      refactor can fold redact to reuse the scan match set for a single pass.
- [~] EG-3: internal-flows page — **DROPPED (owner decision 2026-07-05).** Built then reverted: the 4
      cards duplicated the existing **Scaling** (L2 cluster + L3 state backend) and **Upstreams**
      (zone health) pages; only the config-plane propagation-lag view was net-new, not enough to
      justify a page. The `/api/config/applied` endpoint was reverted with it. Revisit only if a
      propagation-lag view is specifically wanted (candidate: fold into the Scaling page).
- [x] Documented boundary: origin-initiated egress explicitly out of scope with integration guidance
      (EG-1 §1; `docs/security/egress-observability.md`).
