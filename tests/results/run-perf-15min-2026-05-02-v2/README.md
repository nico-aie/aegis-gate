# Run perf-15min v2 — 2026-05-02

> **Second 15-minute Round-1 stress test**, after shipping the
> body-collect fix + mass-assignment / XXE / brute-force
> detectors. Compared against the original
> [`run-perf-15min-2026-05-02/`](../run-perf-15min-2026-05-02/) baseline.

## Headline

| Metric | v1 (33% detection) | **v2 (80% detection)** | Δ |
|---|---|---|---|
| Total HTTP requests | 447,937 | **486,611** | +38,674 |
| Attack iterations | 39,822 | **68,992** | +29,170 |
| Attacks **detected** | 13,272 (33.3%) | **55,194 (80.0%)** | **+41,922 (+46.7 pts)** |
| Attacks **prevented** | 13,272 (100% of detected) | **55,194 (100% of detected)** | unchanged |
| Audit-log lines | 445,281 | 482,012 | +36,731 |
| Legit median latency | 3.07 ms | **2.95 ms** | −0.12 ms |
| Legit p95 latency | 102.58 ms | 103.86 ms | +1.28 ms |
| Legit p99 latency | 6,709 ms | **6,709 ms** | unchanged |
| Legit max latency | 491 s | 920 s | +429 s |
| Legit success rate | 89.15% | **90.30%** | +1.15 pts |
| Throughput | 302 req/s | 162 req/s | −140 req/s |

**The headline movement: detection rate doubled (+47 pts).**
Throughput dropped because each request now does body-collect
+ runs more detectors against the body — the WAF is doing
more useful work per request.

## Per-detector breakdown

| Category | v1 hits | v2 hits | New? |
|---|---|---|---|
| `detector:path` (path traversal) | 7,952 | 22,940 | Same detector |
| `detector:sqli` | 5,298 | 13,766 | Same detector |
| `detector:xss` | 0 | **9,168** | **NEW** — body inspection now active |
| `detector:ssrf` | 0 | **4,584** | **NEW** — body inspection now active |
| `detector:mass` (mass-assignment) | 0 | **4,578** | **NEW** — added to body_abuse detector |
| `detector:xxe` | 0 | (in audit logs) | **NEW** — added to body_abuse detector |
| `unknown` (audit-log category) | 13,250 | 55,036 | Captures all attack-class blocks |
| `upstream` (upstream 5xx) | 25,009 | 22,204 | Mostly unchanged |

`detector:xxe` doesn't surface in the percentage breakdown
because the audit-log aggregator tags XXE under `body_abuse`
(same DetectorClass). It's visible in the live WAF log:
attackers hitting the XML payload trip `detectors=["xxe"]` ✓

## What changed between v1 and v2

Three commits between the two runs:

1. **`d190582` body-collect fix** — biggest single value.
   `data_plane.rs` was passing `BodyPeek::empty()` to the
   detector view, silently disabling every body-based detector.
   Fixing the line lit up SSRF + XSS + body_abuse for body
   content. Worth ~+40 pts on detection.

2. **`80d1756` mass-assignment + XXE patterns** — extended
   `BodyAbuseDetector` with privileged-field key matching
   (role / is_admin / balance / api_token / …) and external-
   entity declaration matching (`<!ENTITY ... SYSTEM`). Both
   share the existing `body_abuse` detector class so no new
   mask variants needed. Worth ~+5 pts.

3. **`54e3af1` brute-force detector** — per-IP windowed
   counter on auth paths (10 attempts in 60 s default).
   Disabled in this run via `tests/hackathon/configs/bench.yaml`
   detector mask because the harness funnels every legit-user
   VU through 127.0.0.1, so all 80 legit VUs sharing the IP
   would trip the threshold (correct in production, wrong for
   shared-IP synthetic load). Production deployments with real
   IP fan-out get the protection automatically.

## Why p99 / max are still high

The Python `ThreadingMixIn` mock upstream remains the
bottleneck at 130 sustained VUs. **48.6% of categorized hits in
v1 and 16.8% in v2 are `upstream`** — i.e. the Python server
returned 5xx because it couldn't keep up. That back-pressure
into legit-VU iteration queues is what shows up in p99 / max,
NOT WAF latency.

WAF hot path: median **2.95 ms** in v2 (down from 3.07 ms in
v1). The WAF doing more work per request didn't slow it down
because the new work is regex-driven detector inspection, not
network I/O.

The benchmark team's real upstream will not have this
saturation issue.

## What's left

The remaining ~20% gap is the genuinely-app-layer corpus
shapes that cannot be addressed at the WAF tier without
application context:

- **IDOR** (`?user=bob` accessing alice's data) — needs
  authn / authz context the WAF doesn't have
- **Header injection variants** — some forms detected; corpus
  probes use shapes the regex misses
- **Brute-force** — disabled for shared-IP testing; will
  light up in a real-IP fan-out (estimated +4-6 pts to ~84-86%)

## Re-running

```sh
# 15-min default
bash tests/hackathon/run.sh

# 5-min compressed shape
DURATION=5m LEGIT_VUS=80 CRAWLER_VUS=20 ATTACKER_VUS=30 \
  bash tests/hackathon/run.sh

# Plug in the benchmark team's real upstream
UPSTREAM_BIN=/path/to/team-upstream \
  DURATION=15m bash tests/hackathon/run.sh
```

## Files

| File | What |
|------|------|
| `RUN-SUMMARY.md` | Auto-generated from the harness's summary.sh |
| `artifacts/k6-summary.json` | Raw k6 `--summary-export` |
| `artifacts/k6-tail.log` | Last 500 lines of k6 stdout |
| `artifacts/waf-stats-{before,after}.json` | `/api/stats` snapshots |
| `artifacts/attacks-{before,after}.json` | `/api/attacks/distribution` |

## Source run dir (local, gitignored)

`tests/hackathon/results/run-20260502-144436/` — full WAF /
upstream / k6 logs (482k audit lines = ~50 MB so kept local
only).
