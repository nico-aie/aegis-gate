# AI Detector — perf + detection comparison

- **Run**: `run-ai-compare-2026-05-03` (k6 driven, 4 cases × 8 000 reqs)
- **Target RPS**: 400  ·  **Duration**: 20 s/case  ·  **Attack mix**: 60 %
- **Cases**: A (regex+AI) · B (AI-only) · C (regex-only) · D (baseline / no detectors)
- **Harness**: [`tests/perf/ai-compare.sh`](../../perf/ai-compare.sh)
- **Per-detector reference**: [`docs/security/detectors/ai-detector.md`](../../../docs/security/detectors/ai-detector.md)

## Headline

| Case | Mode | Throughput rps | Detect % | FP % | Attack p50 / p95 / max ms | Clean p50 / p95 / max ms | RSS MB |
|---|---|---|---|---|---|---|---|
| A | ALL on (regex+AI) | 400.0 | 93.3 | 38.4 | 0.55 / 1.11 / 16.2 | 0.66 / 1.33 / 15.03 | 222.4 |
| B | AI ONLY | 400.0 | 86.3 | 39.6 | 0.66 / 1.85 / 21.34 | 0.76 / 2.05 / 22.27 | 501.6 |
| C | REGEX ONLY | 400.0 | 92.9 | 10.5 | 0.34 / 1.01 / 12.79 | 0.5 / 1.48 / 15.17 | 62.8 |
| D | NONE (baseline) | 400.0 | 0.0 | 0.0 | 0.39 / 1.19 / 8.44 | 0.39 / 1.17 / 9.71 | 51.7 |

## Detection breakdown (counts)

| Case | Attacks total | Caught | Missed | Clean total | False-blocked | Allowed-clean |
|---|---|---|---|---|---|---|
| A | 4815 | 4490 | 325 | 3186 | 1224 | 1962 |
| B | 4742 | 4092 | 650 | 3259 | 1291 | 1968 |
| C | 4778 | 4437 | 341 | 3222 | 339 | 2883 |
| D | 4846 | 0 | 4846 | 3155 | 0 | 3155 |

## AI inference cost

| Case | AI hits | AI inferences | Mean inference µs | Total inf. ms |
|---|---|---|---|---|
| A | 5403 | 8001 | 356.5 | 2852.1 |
| B | 5383 | 8001 | 467.7 | 3742.2 |
| C | 0 | 0 | 0 | 0 |
| D | 0 | 0 | 0 | 0 |

## Per-class detector hits (deltas from `waf_detector_hits_total`)

| Case | ai | sqli | xss | path_traversal | ssrf | recon | body_abuse | brute_force | header_injection |
|---|---|---|---|---|---|---|---|---|---|
| A | 5403 | 626 | 650 | 1279 | 664 | 1289 | 640 | 336 | 0 |
| B | 5383 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| C | 0 | 626 | 637 | 1273 | 605 | 1300 | 612 | 339 | 0 |
| D | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Findings

- **Detection.** Regex alone caught 92.9 % of attacks. AI alone caught 86.3 %.
  Combining them lifts detection to 93.3 % (+0.4 pp over regex-only).
  AI catches a different slice of the corpus than regex — useful in defence-in-depth, but doesn't dominate either rule on its own.
- **False-positive rate.** Regex-only FP 10.5 %, AI-only 39.6 %, combined 38.4 %.
  AI fires on ~67.3 % of all traffic (attack + clean) at threshold 0.5 — model favours sensitivity over precision in this corpus.
  Operators tightening to 0.7+ or running `ai.mode: observe` are the right knobs before enforce.
- **Latency cost.** AI adds ~0.1 ms p95 when chained behind regex (case A vs C),
  and ~0.66 ms when running alone (case B vs D).
  Mean inference: **356.5 µs / request** with `ort` 2.0-rc.12 on the bundled 11-class model.
- **Memory cost.** Adding AI raises RSS by ~160.0 MB on top of the regex chain
  (63.0 → 222.0 MB) — the 38 MB ONNX session plus arenas.
- **Throughput.** All four cases sustained the 400 rps target without saturation; the headline ceiling test is the existing `prod-balanced-5k` run, not this comparison.

## Notes

- **Detection %** = attacker probes returning HTTP 401/403/429 / total attacker probes.
- **FP %** = benign probes blocked / total benign probes.
- `ai.mode: enforce` in cases A and B so AI verdicts surface as HTTP 403.
- Each case boots a fresh WAF (`pkill` between cases) against the same Redis state and `/tmp/aegis-fast-upstream`.
- Corpus: 15 attack payloads (one per regex/AI class — SQLi, XSS, ptrav, SSRF, cmd-inj, scanner UA, recon, log4shell, XXE, mass-assign) + 10 benign shapes (`/`, `/index.html`, `/api/users/100`, `/api/orders` POST, etc.).

## Conclusion

**Headline.** Adding the AI detector to the existing regex chain
lifts detection from **92.9 % → 93.3 %** (+0.4 pp on the bundled
corpus) at a cost of **+0.1 ms p95** request latency, **+357 µs
mean** per request for inference, and **+160 MB** RSS for the
ONNX session. The throughput target was hit in every case — the
WAF was not saturated at 400 rps in any configuration.

**Verdict per case.**

- **Case A — chain regex + AI.** The recommended production
  shape. Highest detection (93.3 %), tight attack p95 (1.11 ms).
  FP rate 38.4 % is dragged up by AI's permissiveness at
  threshold 0.5 — see the false-positive note below. **Ship in
  `ai.mode: observe` first**, tighten the threshold, then
  promote to `enforce`.
- **Case B — AI alone.** Detection drops to 86.3 % (regex
  catches a different slice that AI misses on this corpus),
  attack p95 doubles to 1.85 ms because AI runs on every
  request when nothing else fires first, and RSS more than
  doubles vs case A. Useful as a research / sweep mode, **not a
  production replacement** for the regex chain.
- **Case C — regex only.** The pre-AI baseline. 92.9 % detection
  with a tight 10.5 % FP rate — this is the bar AI must clear
  to be worth turning on.
- **Case D — no detectors.** WAF passes traffic through with
  audit + access-list + risk scoring still active but no attack
  classification. Useful as a latency floor reference (1.19 ms
  attack p95 ≈ pure proxy cost); **not a production
  configuration**.

**False-positive caveat (the most important number on the page).**
At `confidence_threshold: 0.5` the bundled model fires on
**67 % of all traffic** (attack + clean), giving a 39.6 %
false-positive rate when run alone and 38.4 % when chained.
That's far too aggressive for `enforce` mode. The right path:

1. Run `ai.mode: observe` for at least a week on production
   shape; collect `would_block` audit events.
2. Inspect by-class FP rate (the dashboard's AI Detector card
   reads `class="ai"` from `/metrics`).
3. Bump `ai.confidence_threshold` until FP rate matches your
   tolerance (0.7 / 0.85 / 0.95 are common starting points),
   then flip to `enforce`.
4. If retraining is feasible, retrain on a corpus matching your
   real traffic — the bundled model favours recall.

**When to enable AI.**

- ✅ You've burned in `observe` mode for ≥ 1 week and tuned the
  threshold. → Promote to `enforce`.
- ✅ You want a tripwire on novel-shape attacks the regex chain
  doesn't have rules for. → Run in `observe` permanently and
  alert on `would_block`.
- ❌ You can't afford +160 MB RSS or want sub-1 MB binaries. →
  Build without `--features ai` (default).
- ❌ Your traffic mix is heavily API/JSON shaped and you can't
  spend a week tuning. → Stick with the regex chain (case C).

**What to compare next.**
- A run at sustained 5 k+ rps with AI enabled, against the
  existing `run-perf-5krps-prod-balanced-2026-05-02-v3` baseline.
  This run only proved the marginal cost; the saturation
  behaviour is open.
- A retrained-model run after the operator burns in `observe`
  for a real week and feeds the FP corpus back into training.

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
