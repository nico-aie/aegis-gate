# PLAN — Measure the current false-positive metric (baseline)

> **Type:** PLAN (committee round-2 🟡1) · **Status:** ☐ Not started — planned 2026-07-05 · **Owner: S-Tester member**
> **Track ID prefix:** `FPM-<1–3>` · **Feeds:** [IMPROVE-detection-fp-tuning-2026-07.md](IMPROVE-detection-fp-tuning-2026-07.md)
> (FP-2/FP-3 consume this baseline) and [IMPROVE-recon-detection-and-canary-2026-07.md](IMPROVE-recon-detection-and-canary-2026-07.md)
> (RC-2/RC-3 gate on the same corpus). **Build the harness once here; both improvement plans use it.**

**Objective (intent, not letter):** before we claim any FP improvement, know the *current* number.
Produce a reproducible, committed baseline of false-positive and true-positive rates per detector,
so every later tuning PR shows a real before/after — not vibes. This is the measurement deliverable;
the *reducing* is `IMPROVE-detection-fp-tuning`.

---

## 1. Why a separate plan

The improvement plans both assumed "build a corpus + harness" as their first step (FP-1 / shared
corpus). Pulling it into its own owned deliverable means:
- the S-Tester can land the measurement infrastructure and the **current baseline number** without
  waiting on any detector change;
- "get the current FP metric" becomes a checkable artifact the committee can see, distinct from
  "we improved it";
- the two improvement plans stop duplicating harness scope — they import the baseline.

## 2. Measurement traps to respect (non-negotiable)

- **`[[project_ltester_decodes_dataplane_raw]]`** — the l-tester Python harness double-decodes URIs;
  the real data plane feeds detectors **raw percent-encoded** forms. The baseline must be measured
  at the **Rust `EvalContext` level on raw forms**, not by scraping the Python report. A number
  taken from the Python harness alone is wrong and will misdirect tuning.
- **`[[project_hyper_normalizes_framing]]`** — framing-level rules can't be exercised through a
  normalizing HTTP client; don't score them via black-box replay.
- **`[[feedback_two_score_model]]` / `[[feedback_dev_xff_single_ip_gates]]`** — per-request detector
  SUM vs cumulative IP-risk are different numbers; the FP baseline is about **per-request detector
  firing on benign input**, measured with a fresh key each request (no cumulative bleed).

## 3. Staging

### FPM-1 — benign + attack corpora · **M** · START HERE
- **Benign corpus** (checked into `tests/` or a fetched fixture, versioned): realistic browser
  sessions, API clients, static-asset paths, search queries carrying SQL-ish / HTML-ish *benign*
  payloads, percent-encoded redirect params (the known l-tester FP artifact class), webhook bodies
  (JSON/XML), file uploads, and — seed from **real bench traffic** where available so it's
  representative, not synthetic-only.
- **Attack corpus:** reuse the l-tester vectors, replayed **raw** through unit-level `EvalContext`
  construction (not the Python harness). Label each with the detector(s) it *should* trip.
- Version both; a committed manifest (counts, provenance) so growth is diffable.

### FPM-2 — per-detector precision/recall harness · **M**
- A `cargo test`-runnable report: for each detector, **FP rate on the benign corpus** (benign
  requests that fire it) and **TP rate on the attack corpus** (attacks it catches), plus overall
  precision/recall. Constructed at the raw-`EvalContext` boundary so it measures what the data plane
  actually sees.
- **Commit the baseline snapshot** (a checked-in expected-numbers file). This is the artifact "the
  current FP metric" — and it makes any later regression **RED** in CI.
- Include the two dormant detectors (`enumeration`, `behavior_analyzer`) so FP-3's default-ON
  decision has a number.

### FPM-3 — baseline report + handoff · **S**
- One short doc: the current FP/TP numbers per detector, the noisiest detectors ranked by benign-FP
  contribution, and the corpus manifest. This is the committee-facing "here is where we started."
- Handoff: `IMPROVE-detection-fp-tuning` FP-2 picks the ranked top offenders; `IMPROVE-recon` RC-2/3
  gate their scoring/signature changes against this same corpus. Update those plans' FP-1 / corpus
  sections to **reference this baseline** instead of rebuilding it.

## 4. Tests / evidence

- The harness *is* the test: `cargo test` runs it; the committed baseline makes drift RED.
- Raw-form assertions only for detector firing ([[project_ltester_decodes_dataplane_raw]]).
- Corpus manifest committed; re-running the harness on the same corpus is deterministic.

## 5. Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | Corpus unrepresentative → false confidence in the baseline | seed from real bench traffic + known FP reports; version and grow; document provenance |
| MEDIUM | Baseline measured through the Python harness (double-decode) → wrong number | measure at raw `EvalContext`; the trap is memory-documented for a reason |
| LOW | Baseline churn as the corpus grows | snapshot is versioned; a corpus bump is an explicit, reviewed commit with a re-baseline |

## 6. Acceptance

- [ ] Benign + attack corpora committed with a provenance manifest.
- [ ] `cargo test`-runnable per-detector precision/recall harness; **baseline snapshot committed**.
- [ ] Baseline report: current FP/TP per detector + ranked noisiest detectors.
- [ ] `IMPROVE-detection-fp-tuning` and `IMPROVE-recon` updated to consume this baseline (no
      duplicate harness).
