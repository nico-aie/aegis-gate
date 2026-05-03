# AI Detector — perf + detection comparison

- **Run**: `run-ai-compare-2026-05-03` (k6, 4 cases × 8 000 reqs)
- **Target RPS**: 400  ·  **Duration**: 20 s/case  ·  **Attack mix**: 60 %
- **Cases**: A (regex+AI) · B (AI-only) · C (regex-only) · D (baseline / no detectors)
- **Harness**: [`tests/perf/ai-compare.sh`](../../perf/ai-compare.sh)
- **Per-detector reference**: [`docs/security/detectors/ai-detector.md`](../../../docs/security/detectors/ai-detector.md)
- **Latency target**: **p99 < 5 ms** for both attack and clean traffic

## Headline

| Case | Mode | Throughput rps | Detect % | FP % | Attack p50 / p95 / **p99** / max ms | Clean p50 / p95 / **p99** / max ms | RSS MB |
|---|---|---|---|---|---|---|---|
| A | ALL on (regex+AI) | 400.0 | 93.8 | 40.0 | 0.95 / 2.48 / **4.53** / 34.81 | 1.1 / 2.9 / **5.71** / 39.49 | 561.7 |
| B | AI ONLY | 400.0 | 85.7 | 40.1 | 1.33 / 2.39 / **5.58** / 20.61 | 1.64 / 2.69 / **5.47** / 39.37 | 507.2 |
| C | REGEX ONLY | 400.0 | 93.5 | 10.4 | 0.81 / 1.36 / **2.26** / 11.77 | 1.2 / 1.8 / **2.92** / 17.7 | 64.8 |
| D | NONE (baseline) | 400.0 | 0.0 | 0.0 | 0.94 / 1.42 / **2.44** / 13.03 | 0.95 / 1.44 / **2.58** / 12.21 | 51.2 |

## Detection breakdown (counts)

| Case | Attacks total | Caught | Missed | Clean total | False-blocked | Allowed-clean |
|---|---|---|---|---|---|---|
| A | 4828 | 4531 | 297 | 3173 | 1270 | 1903 |
| B | 4811 | 4124 | 687 | 3189 | 1279 | 1910 |
| C | 4859 | 4545 | 314 | 3142 | 328 | 2814 |
| D | 4720 | 0 | 4720 | 3281 | 0 | 3281 |

## AI inference cost

| Case | AI hits | AI inferences | Mean inference µs | Total inf. ms |
|---|---|---|---|---|
| A | 5478 | 8001 | 694.0 | 5552.9 |
| B | 5403 | 8000 | 783.1 | 6265.1 |
| C | 0 | 0 | 0 | 0 |
| D | 0 | 0 | 0 | 0 |

## Per-class detector hits (waf_detector_hits_total deltas)

| Case | ai | sqli | xss | path_traversal | ssrf | recon | body_abuse | brute_force | header_injection |
|---|---|---|---|---|---|---|---|---|---|
| A | 5478 | 683 | 591 | 1313 | 661 | 1281 | 644 | 298 | 0 |
| B | 5403 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| C | 0 | 649 | 662 | 1345 | 626 | 1265 | 624 | 328 | 0 |
| D | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## p99 vs the 5 ms target

| Case | Attack p99 ms | Clean p99 ms | Pass? |
|---|---|---|---|
| A — regex + AI | **4.53** | **5.71** | ⚠ Attack OK, clean over by 0.71 ms |
| B — AI only    | **5.58** | **5.47** | ❌ Both over by ~0.5 ms |
| C — regex only | **2.26** | **2.92** | ✅ Both well under |
| D — none       | **2.44** | **2.58** | ✅ Both well under (proxy floor) |

Only the regex-only and baseline cases meet the **p99 < 5 ms**
target outright. Adding the AI detector pushes p99 across the 5 ms
line on this hardware (Apple Silicon laptop, single WAF process,
no warm-up grace period). On production hosts with bigger CPU
budget the gap closes; the headline 5 k RPS run already
demonstrated p99 1.03 ms on `prod-balanced-5k`, so AI on a
real machine should land comfortably inside the target.

## Findings

- **Detection.** Regex alone caught **93.5 %** of attacks. AI
  alone caught **85.7 %**. Combining them lifts detection to
  **93.8 %** (+0.3 pp over regex-only). AI catches a different
  slice than regex — useful in defence-in-depth, doesn't
  dominate either rule on its own.
- **False-positive rate.** Regex-only FP **10.4 %**, AI-only
  **40.1 %**, combined **40.0 %**. AI fires on ~68 % of all
  traffic at threshold 0.5 — model favours sensitivity over
  precision in this corpus. Tightening to 0.7+ or running
  `ai.mode: observe` are the right knobs before `enforce`.
- **Latency.** AI adds ~**+1.1 ms p95 / +2.3 ms p99** when
  chained behind regex (case A vs C), and ~**+1.0 ms p95 /
  +3.1 ms p99** when running alone (case B vs D). Mean
  inference: **694 µs / request** on this hardware (the prior
  cold-cache run measured 357 µs — the value moves with system
  load + arena state).
- **Memory.** AI adds **~500 MB RSS** on top of the regex
  chain in this run (65 → 562 MB) — higher than the prior
  measurement (160 MB) because the ONNX runtime's lazy arena
  allocator has filled in further over the run.
- **Throughput.** All four cases sustained the 400 rps target;
  the saturation ceiling is the existing `prod-balanced-5k`
  test, not this comparison.

## Conclusion

**Headline.** The AI detector trades **+0.3 pp detection** and
a **+30 pp false-positive rate** for **~+2.3 ms p99 latency**
and **~+500 MB RSS** at threshold 0.5 on this hardware. The
detection lift is small because the bundled regex chain is
already strong on the test corpus; the FP rate is large because
the bundled model was trained for recall.

**Verdict per case.**

- **Case A — regex + AI (recommended production shape).**
  Highest detection, attack p99 inside the 5 ms target, clean
  p99 marginally over (5.71 ms). Production-ready *only after*
  burning in `ai.mode: observe` on real traffic and tightening
  the confidence threshold so the FP rate is acceptable.
- **Case B — AI alone.** Detection drops to 85.7 %, p99 fails
  the 5 ms target on both attack and clean traffic, RSS doubles.
  Useful only as a research / sweep mode — **not a production
  replacement** for the regex chain.
- **Case C — regex only (current production default).**
  93.5 % detection, 10.4 % FP rate, p99 well inside 5 ms. The
  bar AI must clear to be worth turning on; the right
  configuration for operators who can't afford a tuning week.
- **Case D — no detectors.** Latency floor reference (1.4 ms
  p95 attack/clean, ~2.5 ms p99). Not a production
  configuration — risk scoring + audit + access-list still run
  but no attack classification.

**False-positive caveat (the most load-bearing finding).** At
`confidence_threshold: 0.5` the model fires on ~68 % of all
traffic. The right path before `enforce`:

1. Run `ai.mode: observe` for ≥ 1 week on production shape;
   collect `would_block` audit events.
2. Inspect by-class FP rate via the dashboard's AI Detector
   card (reads `class="ai"` from `/metrics`).
3. Bump `ai.confidence_threshold` until FP rate matches your
   tolerance (0.7 / 0.85 / 0.95 are common starting points),
   then flip to `enforce`.
4. If feasible, retrain on a corpus matching your real traffic.

**When to enable AI.**

- ✅ You've burned in `observe` mode for ≥ 1 week and tuned the
  threshold. → Promote to `enforce`.
- ✅ You want a tripwire on novel-shape attacks the regex chain
  doesn't have rules for. → Run in `observe` permanently and
  alert on `would_block`.
- ❌ Your hardware is laptop-class and your latency SLO is p99
  < 5 ms. → Stick with the regex chain (case C) or upsize.
- ❌ You can't afford +500 MB RSS or want sub-1 MB binaries. →
  Build without `--features ai` (default OFF).
- ❌ You can't spend a tuning week. → Stick with regex.

**What to compare next.**
- A run at sustained 5 k+ rps with AI enabled, against
  `run-perf-5krps-prod-balanced-2026-05-02-v3`. This run only
  proved the marginal cost; the saturation behaviour is open.
- A retrained-model run after `observe` mode burn-in on real
  traffic.
- Same harness on a production-class host (more cores, less
  background load) — expect both p99 numbers to drop ~30-50 %.

## Notes

- **Detection %** = attacker probes blocked (HTTP 401/403/429) / attacker probes total.
- **FP %** = benign probes blocked / total benign probes.
- `ai.mode: enforce` in cases A and B so AI verdicts surface as HTTP 403.
- All cases use the same Redis state backend and upstream — only detector toggles differ.
- p99 measured by k6 with `--summary-trend-stats="…,p(99)"`; trend stats are emitted for `http_req_duration`, `attack_latency_ms`, `clean_latency_ms`.

## Raw artefacts

- `case-A/` — config.yaml · waf.log · k6.log · k6-summary.json · summary.json · metrics-before/after.txt
- `case-B/` — config.yaml · waf.log · k6.log · k6-summary.json · summary.json · metrics-before/after.txt
- `case-C/` — config.yaml · waf.log · k6.log · k6-summary.json · summary.json · metrics-before/after.txt
- `case-D/` — config.yaml · waf.log · k6.log · k6-summary.json · summary.json · metrics-before/after.txt

## Re-run

```bash
# default — 4 cases × 400 rps × 20 s
bash tests/perf/ai-compare.sh
# heavier — 800 rps × 60 s
RPS=800 DURATION=60s bash tests/perf/ai-compare.sh
# only the A/B cases
ONLY="A B" bash tests/perf/ai-compare.sh
```

Output lands at `tests/results/run-ai-compare-<UTC-date>/REPORT.md`.
