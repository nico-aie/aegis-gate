# `tests/results/` — perf + integration run history

Index of every recorded perf run, newest at the top. Each
run is its own subdirectory with the raw k6 logs and a
`README.md` that describes:

- Run context (commit / build features / config / k6 args).
- Headline numbers vs the previous run.
- What changed in the codebase between this run and the
  prior one.
- Carry-overs surfaced or closed.
- Reproducer commands.

Subdirectories are named `run-NN-YYYY-MM-DD-<theme>` where
`NN` is monotonic. Older runs are kept untouched so any
read-back is reproducible.

## Run history

| # | Dir | Date | Focus | Headline | Status |
|---|---|---|---|---|---|
| 04 | [`run-04-2026-04-29-cluster-https/`](./run-04-2026-04-29-cluster-https/) | 2026-04-29 | Cluster smoke + HTTPS data-plane perf, post carry-over 3/4/5 closure | 31.7 k RPS plain (cluster), 31.8 k RPS over TLS, p95 ≤ 1.04 ms | ✅ all carry-overs closed |
| 03 | [`run-03-2026-04-29-carryovers/`](./run-03-2026-04-29-carryovers/) | 2026-04-29 | Carry-over A (data-plane Allow forward) + B (rate-limit 429) closures + first cluster smoke | 31.5 k RPS w/ real upstream, 429 wire confirmed | A + B closed; 3/4/5 still open at run end |
| 02 | [`run-02-2026-04-29-phase-b/`](./run-02-2026-04-29-phase-b/) | 2026-04-29 | First whole-system run after Phase B B3 + B4 + B5 closed | 42.3 k RPS, allow-path p95 877 µs (was 7.21 ms) | surfaced 5 carry-overs |
| 01 | [`run-01-2026-04-28-baseline/`](./run-01-2026-04-28-baseline/) | 2026-04-28 | Baseline after F-T1..F-T10 + dashboard track | 37.5 k RPS, 100 % allow_success (anomaly — rate-limit not yet enforced) | reference snapshot |

## Reading a run

Open the per-run `README.md` first. Each one structures the
content the same way:

1. **Run context** — what build / config / runner.
2. **Summary table** — pass/fail per script.
3. **Comparison vs previous run** — deltas with direction
   (improvement / regression).
4. **What got better** — concrete improvements.
5. **What needs improvement** — carry-overs surfaced.
6. **Reproducing** — exact commands.

## Index of carry-overs

Carry-overs are real gaps the perf benchmarks expose. Each
one is tracked in
[`Implement-Progress.md`](../../Implement-Progress.md). Their
state at run-04 (the latest run):

| ID | Topic | State | Closing run |
|---|---|---|---|
| A | data-plane Allow forwarding stub | ✅ closed | run-03 |
| B | rate-limit returns 403 not 429 (test calibration) | ✅ closed | run-03 |
| 3 | leader-state admin endpoint missing | ✅ closed | run-04 |
| 4 | per-node rate-limit bucket vs cluster-shared | ✅ closed (doc clarification) | run-04 |
| 5 | data-plane TLS loader missing | ✅ closed | run-04 |
| 6 | HA perf test routes per-port, no LB / single VIP | **open** — see [`tests/cluster/HA-TEST-METHODOLOGY.md`](../cluster/HA-TEST-METHODOLOGY.md) | — |

After run-04, carry-overs A / B / 3 / 4 / 5 are all closed.
A **new** carry-over (#6) was surfaced *by* run-04 —
the cluster perf harness drives traffic per-port instead
of through a single LB. That's a test-infra gap, not a
runtime bug; the recommended fix is HAProxy in front of
the cluster (option 2 in `HA-TEST-METHODOLOGY.md`).
Treat carry-over 6 as the gating task for the *next*
cluster perf publication; B6-T1 (production Dockerfile)
can land in parallel.

## Adding a new run

```sh
# 1. Create the next directory.
mkdir tests/results/run-NN-YYYY-MM-DD-<theme>

# 2. Run the suite, redirecting logs into it.
docker exec aegis-k6 k6 run …  > tests/results/run-NN-…/baseline.log

# 3. Copy in the per-run README template (see existing dirs).

# 4. Update *this* README.md's run-history table + the
#    carry-overs index at the bottom.

# 5. Reference the run from Implement-Progress.md's
#    Verification block.
```
