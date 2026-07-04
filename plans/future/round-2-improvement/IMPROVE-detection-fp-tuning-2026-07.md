# IMPROVE — Detection accuracy: FP tuning & default-ON graduation

> **Type:** IMPROVE (committee round-2 🟡1) · **Status:** ☐ Not started — planned 2026-07-04
> **Track ID prefix:** `FP-<1–3>` · Formalizes the previously-untracked loose thread from the
> attack-coverage track: `enumeration` + `behavior_analyzer` shipped **default-OFF pending FP
> tuning** (FEAT-attack-coverage-wiring, archived 2026-07-04).

**Objective (intent, not letter):** raise real-world precision on the existing detection
foundation — fewer false positives on benign traffic, no regression on true positives — and
graduate the two dormant detectors to default-ON with measured evidence, not vibes.

---

## 1. Current state

- Detection foundation is mature: content-type-gated body scans and XSS exec-sink gating already
  shipped as FP-reduction passes (`[[feedback_test_suite_green_baseline]]` — old detection tests
  going stale on FP-reduction commits is a known, *intended* pattern).
- `enumeration` (404-gated, off-chain) and `behavior_analyzer` are wired but **default-OFF**
  awaiting FP evidence.
- Two measurement traps to respect:
  - `[[project_ltester_decodes_dataplane_raw]]` — the l-tester harness double-decodes URIs; the
    real data plane feeds detectors **raw percent-encoded** forms. Validate with Rust unit tests
    on raw forms, never the Python recon report alone.
  - `[[project_hyper_normalizes_framing]]` — framing-level rules can't be exercised through
    normalizing clients.

## 2. Staging

### FP-1 — measurement harness + benign corpus · **M** · START HERE
- Build a versioned **benign-traffic corpus** (checked into `tests/` or fetched fixture):
  realistic browser sessions, API clients, static-asset paths, search queries with SQL-ish/HTML-ish
  benign payloads, percent-encoded redirect params (the known l-tester artifact class), webhook
  bodies (JSON/XML), file uploads.
- Attack corpus: reuse the l-tester vectors, replayed **raw** through the Rust path (unit-level
  `EvalContext` construction, not the Python harness).
- Deliverable: `cargo test`-runnable precision/recall report per detector (FP rate on benign
  corpus, TP rate on attack corpus), with a baseline snapshot committed so drift is diffable.

### FP-2 — tune the noisiest detectors · **M**
- Rank detectors by corpus FP contribution; tune top offenders (thresholds, gating, context
  requirements) one PR per detector, each PR showing before/after corpus numbers.
- Known candidates from history: redirect-param encodings, generic keyword rules on benign query
  strings. Do **not** re-attempt RegexSet consolidation (`[[project_regexset_slower_than_vec]]`).
- Guard: every tuning PR keeps the attack-corpus TP rate flat or better; perf budget respected
  (bench before/after on the release profile).

### FP-3 — graduate `enumeration` + `behavior_analyzer` to default-ON · **S–M**
- Entry criteria: corpus FP rate under an agreed budget (owner sets; suggest <0.1% of benign
  requests scoring, 0 blocks at default thresholds) + a soak in log-only on the dev/bench stack.
- Flip defaults + release-note the change; keep per-detector kill switches.

## 3. Tests / evidence

- FP-1 report is itself the test artifact; committed baselines make regressions RED.
- Detector unit tests updated alongside tuning (stale-test pattern is expected — confirm intended
  FP-reduction before "fixing" a detector to satisfy an old test).
- Log-only soak evidence attached before FP-3 default flips.

## 4. Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | Tuning quietly drops real TPs | attack corpus gate in every PR; log-only soak before default flips |
| MEDIUM | Corpus unrepresentative → false confidence | seed from real bench traffic + known FP reports; version and grow it |
| LOW | Perf regression from added gating | release-profile bench per PR (LT-P1 profile) |

## 5. Acceptance

- [ ] Reproducible precision/recall harness in `cargo test`, baseline committed.
- [ ] Top-N noisy detectors tuned with before/after numbers.
- [ ] `enumeration` + `behavior_analyzer` default-ON (or an evidence-backed decision not to).
- [ ] Committee-facing summary: measured FP reduction, foundation unchanged.
