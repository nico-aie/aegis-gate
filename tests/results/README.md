# `tests/results/` — current reference runs

Each subdirectory is a recorded test run with its own
`README.md` describing the run context, headline numbers,
deltas vs prior runs, and reproducer commands.

This directory holds the **current reference baselines**.
Older runs live in [`archive/`](./archive/) — useful for
historical comparison but not needed for everyday work.

## Current baselines

| Dir | Date | What it's the baseline for |
|---|---|---|
| [`run-perf-5krps-prod-balanced-2026-05-02-v3/`](./run-perf-5krps-prod-balanced-2026-05-02-v3/) | 2026-05-02 | **Sustained throughput baseline** — `prod-balanced` profile @ 5 k+ RPS for 2 min, k6 4 891 RPS / WAF-internal 6 392 RPS, legit p99 1.03 ms / median 0.13 ms / 100 % OK, 80 % attack detection. All three k6 thresholds passed. Compare new perf runs against this. |
| [`run-perf-15min-2026-05-02-v2/`](./run-perf-15min-2026-05-02-v2/) | 2026-05-02 | **Detection-coverage baseline** — 15-min mixed-traffic harness post detector-coverage sprint. Detection rose 33 % → 80 % from the v1 result. Use to verify regression coverage when adding / changing detectors. |
| [`run-ai-compare-2026-05-03/`](./run-ai-compare-2026-05-03/) | 2026-05-03 | **AI Detector A/B/C/D baseline** — side-by-side regex+AI / AI-only / regex-only / none, 4 × 8 000 reqs at 400 rps. Headline: AI lifts detection 93.5 % → 93.8 % at +1.1 ms p95 / +2.3 ms p99 / +500 MB RSS. **p99 vs 5 ms target**: regex-only ✅ (2.92 ms), regex+AI ⚠ (clean 5.71 ms over by 0.71 ms on laptop hardware), AI-only ❌ (5.58 ms). Reproduces with `bash tests/perf/ai-compare.sh`. |
| [`run-cqa-round3-20260502/`](./run-cqa-round3-20260502/) | 2026-05-02 | **Dashboard CQA baseline** — Round-3 control-panel acceptance after the SOC-UX pass. 12 fresh screenshots, every page renders, OpenAPI shape green. |
| [`run-soc-sweep-202605030612/`](./run-soc-sweep-202605030612/) | 2026-05-03 | **SOC sweep baseline** — most recent multi-tester SOC walkthrough. Use as the comparison row for the next AI-assistant sweep. |

## Reading a run

Open the per-run `README.md` first. Each one is structured:

1. **Run context** — what build / config / runner
2. **Summary table** — pass / fail per script
3. **Comparison vs previous run** — deltas with direction
4. **What got better** — concrete improvements
5. **What needs improvement** — carry-overs surfaced
6. **Reproducing** — exact commands

## Adding a new run

```sh
mkdir tests/results/run-NN-YYYY-MM-DD-<theme>
# … run the suite, redirecting logs into it …
# Copy the README template from one of the current baselines.
# Update this index when the new run becomes a reference.
# Reference the run from Implement-Progress.md's Verification block.
```

When a new run supersedes a current baseline (e.g. a fresh
prod-balanced perf run that beats the 5krps-v3 numbers), move
the old one into `archive/` and update this table.

## Archive

[`archive/`](./archive/) — 28 older runs from the build-up
sprint (run-01 through run-17 plus the cqa / soc / profile
sweeps and the older perf-5krps v1+v2 + 15-min v1 trials).
Browse them when you need historical context (e.g. when did
HA cluster perf land, what did we measure for TLS recheck).
The archive's own README has the full historical timeline.
