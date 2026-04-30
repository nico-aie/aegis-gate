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
| 11 | [`run-11-2026-04-30-control-panel-acceptance/`](./run-11-2026-04-30-control-panel-acceptance/) | 2026-04-30 | Full control-panel acceptance after CI-T1..T10 — every dashboard page on live API, OpenAPI contract, multi-protocol smoke (h1+h2+WS+gRPC), 12 fresh screenshots. | 22/22 endpoints serve real JSON; 25/25 OpenAPI shape checks; 8/8 Round-1 contract checks (RT 61 ms / hot-reload 52 ms); SLO engine fired 3 real alerts mid-run. | ✅ Full acceptance green |
| 10 | [`run-10-2026-04-30-dashboard-redesign/`](./run-10-2026-04-30-dashboard-redesign/) | 2026-04-30 | Dashboard redesign DD-T0..T7 — Aegis WAF Console; pre-compiled JSX bundle, no CDN, Rule CRUD endpoints, hot-reload version visibility. | All 12 pages render; CRUD wired end-to-end; CSP `script-src 'self'`; bundle 165 KB; +0 / −60+ files net (cleanup). | ✅ Round-1 functional bar met |
| 09 | [`run-09-2026-04-30-tls-recheck/`](./run-09-2026-04-30-tls-recheck/) | 2026-04-30 | TLS-T1 clean-host re-measure. Closes the run-05 handshake-latency carry-over. | Handshake p95 5.23 ms (run-04: 2.12, run-05: 9.08); post-handshake p95 1.04 ms unchanged. **Verdict: run-05 was host noise.** | ✅ run-05 carry-over closed |
| 08 | [`run-08-2026-04-30-interop/`](./run-08-2026-04-30-interop/) | 2026-04-30 | Interop contract self-driven dry-run (DR-T1..T7). Validates §2/§3/§5/§6 of v2.3 + perf delta with X-WAF-* + audit always-on. | **27/27 contract checks green**, perf delta ~30 µs at p95 (4 % overhead at 4 k RPS), 100 % success both modes. | ✅ Round-2 self-gate green |
| 07 | [`run-07-2026-04-30-upstream-pool/`](./run-07-2026-04-30-upstream-pool/) | 2026-04-30 | UP-T1 — pooled HTTP/1.1 keep-alive vs pre-UP-T1 baseline, swept over `runtime.workers` and offered RPS. | **Throughput ceiling 525 → 7 964 RPS (15×)**; p95 0.94 ms at 1 k RPS / 100 % success. Unpooled flatlines at ~525 RPS regardless of workers. | ✅ post-run-06 top item closed |
| 06 | [`run-06-2026-04-30-workers-perf/`](./run-06-2026-04-30-workers-perf/) | 2026-04-30 | Single-node sweep across `runtime.workers` ∈ {2, 4, 8, 12, auto} on a 12-core host. Proxied path + pure /healthz/ready path. | Worker count above 2 doesn't move RPS/latency on the current code base — bottleneck is upstream pool (proxied) or accept loop (pure). `auto` correctly = 12. | ℹ️ feature wiring verified; UP-T1 (now run-07) closed the upstream-pool gap |
| 05 | [`run-05-2026-04-30-ha-implementation/`](./run-05-2026-04-30-ha-implementation/) | 2026-04-30 | Full HA-T1..HA-T5 track landed: HAProxy reference deploy, single-VIP load tests, mid-burst failover (hard + graceful), peers visibility, drain endpoint | 9.5 k RPS via VIP, **99.93 % hard / 100 % graceful** failover budget, peers converge in 12 s | ✅ carry-over 6 closed |
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
state at run-05 (the latest run):

| ID | Topic | State | Closing run |
|---|---|---|---|
| A | data-plane Allow forwarding stub | ✅ closed | run-03 |
| B | rate-limit returns 403 not 429 (test calibration) | ✅ closed | run-03 |
| 3 | leader-state admin endpoint missing | ✅ closed | run-04 |
| 4 | per-node rate-limit bucket vs cluster-shared | ✅ closed (doc clarification) | run-04 |
| 5 | data-plane TLS loader missing | ✅ closed | run-04 |
| 6 | HA perf test routes per-port, no LB / single VIP | ✅ closed | **run-05** |

After run-05, **all six carry-overs surfaced by perf are closed**.
The recommended fix from `HA-TEST-METHODOLOGY.md` (option 2 —
HAProxy in front of the cluster) shipped as
[`deploy/haproxy/haproxy.cfg`](../../deploy/haproxy/haproxy.cfg)
plus the new `aegis-lb` compose service. The cluster smoke
expanded from 4 scripts to 6 (single-VIP baseline + mid-burst
failover); both `tests/cluster/05-single-vip-baseline.sh` and
`06-mid-burst-failover.sh` are green on the current branch.
Run-05 also wired HA-T5 (LB-friendly readiness): `POST
/admin/drain` flips `readiness.draining`, `?strict=1` on
`/healthz/ready` returns 503 unless the node holds the cluster
leader lease, and SIGTERM auto-drains for 5 s before aborting
listeners. The graceful-drain failover path produces zero 5xx.

The next gating tracks are **B6-T1** (production Dockerfile)
and an upstream connection pool (the 4–5 k RPS measured for
fully-forwarded cluster traffic comes from new TCP per request
on the upstream side; both can land independently).

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
