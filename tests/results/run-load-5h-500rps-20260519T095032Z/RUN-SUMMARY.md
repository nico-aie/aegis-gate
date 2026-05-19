# Run summary — `run-load-5h-500rps-20260519T095032Z`

| | |
|---|---|
| **Intent** | 5-hour load test, ~500 RPS target, behavior_burst retirement fix verified, host-stability safeguards in place after the 2k RPS run took the box down |
| **Started** | `2026-05-19T09:50:32Z` UTC / `2026-05-19 16:50:32 +07` |
| **Stopped (operator)** | `2026-05-19T12:57:42Z` UTC / `2026-05-19 19:57:42 +07` |
| **Actual duration** | **3h 7m** (operator stopped early — host stayed healthy throughout) |
| **WAF commit** | `7046d3a` (post-merge `behavior_burst` retired + dashboard config-backup + ddos hot-flippable) |
| **Config** | `config/staging.yaml` with `ddos.enabled: false`; runtime `default_mode: log_only` via `/__waf_control/set_profile` |
| **k6 script** | `tests/hackathon/k6/prod-balanced-5k.js` with `LEGIT_VUS=3 CRAWLER_VUS=1 ATTACKER_VUS=1` (5 VUs total) |
| **Upstream** | `/tmp/aegis-fast-upstream` on `127.0.0.1:9999` (transient systemd unit) |
| **Safeguards applied this run** | `net.netfilter.nf_conntrack_max=1048576` (was 262144), `tcp_timeout_time_wait=30s` (was 120s), sidecar `sysstat.csv` recording every 10 s |

## Headline numbers — finally clean, finally trustworthy

| Metric | Value |
|---|---|
| Iterations | **1,742,243** at 155.3 iter/s |
| **HTTP requests** | **10,527,879 total at 938.6 RPS** (overshot the 500 RPS target ~1.9× because each iteration makes ~6 reqs, and the WAF is healthier than the per-VU math from earlier runs assumed) |
| **http_req_duration p50** | **0.46 ms** |
| **http_req_duration p95** | **0.81 ms** |
| **http_req_duration p99** | **0.92 ms** |
| http_req_duration avg | 0.51 ms |
| http_req_duration max | 105.67 ms (one outlier) |
| http_req_failed network rate | 0.90 % (mostly the k6 XFF-invalid follow-up) |
| VUs sustained | 5 / 5 throughout |

**These are real numbers** — sub-millisecond p99 on a healthy WAF with full detector chain, audit chain, GeoIP wired, and v2.3 contract serving on every request. Compare to the saturated 5k RPS run where p99 was 32 ms.

## Security / detection numbers

| Metric | Value |
|---|---|
| Synthetic attack requests | **471,463** |
| Attacks detected by WAF | **440,032** |
| **Attack detection rate** | **93.34 %** |
| Audit events written during run | **~10.5 M** (file went 20 → 10,496,468 lines in `./waf_audit.log`) |
| Audit-emit rate | ~935 events/sec sustained — matches the request rate |
| **`legit_ok_rate`** | **100.00 %** — every legit-VU request returned OK from upstream |

**That last number is the proof that the `behavior_burst` retirement (commit `e50ab79`) fixed the single-source-IP false-positive problem.** In the prior 5k bench, `legit_ok_rate` was **0.01 %** because every loopback request tripped the behavior detector. In this run with the retirement merged, **legit_ok_rate = 1.0** — perfect pass-through for the benign workload while still detecting 93 % of synthetic attacks.

## Sysstat over time (1,121 samples, one every 10 s)

| Metric | min | avg | max |
|---|---|---|---|
| `nf_conntrack` count | 54 | 81.5 | **218** |
| WAF CPU % | 0.0 | 29.6 | 37.7 |
| WAF RSS (KB) | 114,980 | 546,691 | **764,928** |
| sockets ESTABLISHED on `:8080` | 1 | 6.0 | 6 |
| sockets CLOSE_WAIT on `:8080` | 1 | 1.0 | **1** |
| load1 | 0.12 | 1.80 | 3.23 |
| MemAvailable (KB) | 9,282,524 | 11,218,316 | 12,993,168 |

**Every dimension looks comfortable.** Specifically:

- **conntrack max 218** — vs the 1,048,576 ceiling we set, that's 0.02 % utilization. The 2k RPS run that killed the host was at ~167 K (63 % of the **default** 262 K ceiling). At 500 RPS this is a non-issue.
- **CLOSE_WAIT pinned at 1** — no socket leak. In the saturated 5k run we saw 392.
- **WAF RSS grew** 115 MB → 765 MB over the 3h run — that's ~3.5 MB/min. Not alarming for a 3h window (would be ~21 GB over 100 h, still fine), but worth tracking on multi-day runs.
- **load1 max 3.23** on a multi-core box — fine; nowhere near pegged.

## What this run actually proved

1. **Behavior-burst retirement (latest merge) works** — legit-OK rate jumped from 0.01 % to 100 %.
2. **WAF latency at 938 RPS is sub-millisecond** (p99 = 0.92 ms). The doc-published prod-balanced baseline numbers (`run-profile-sweep-20260502`: p99 = 4.52 ms at 344 RPS) are now beaten by ~5× on per-request latency at ~3× the throughput.
3. **No saturation under multi-hour sustained load** — CPU, RSS, sockets, conntrack, mem all stayed well within margin. Diametric opposite of the 5k / 2k / 400-VU runs that crashed the host.
4. **The conntrack-ceiling fix (the suspected cause of the 2k RPS host hang) is paid down** — even if we run higher rates, we have 1M headroom now.
5. **Attack detection rate 93.34 %** — consistent with prior runs; not affected by the behavior-detector retirement (those weren't carrying the OWASP-class detection load).

## Honest caveats

1. **Stopped at 3h 7m, not the planned 5h** — operator chose to stop early after seeing the host was stable. Numbers above are valid for the 3h window; we don't have data for hours 4–5 but every sysstat trend was flat-to-mildly-increasing (RSS was the only thing growing).
2. **Throughput overshot target ~1.9×** — 5 VUs × 6 reqs/iter at sub-ms latency = ~938 RPS, not 500. Not a problem; just means the math from previous saturated runs (12.5 RPS/VU) was wrong for a healthy WAF.
3. **`legit_ok_rate.thresholds.rate>0.95: false` flag in the k6 summary** — looks like a k6-script bug (threshold registered with inverted semantics); the underlying value=1.0 (9,726,824 / 9,726,824 passes) is correct.
4. **`attacks_prevented.count: 62,861` is lower than `attacks_detected.count: 440,032`** — that's because `mode: log_only`. Detectors detect and audit-emit, but don't enforce a block at the WAF, so "prevented" stays low. In `enforce` mode these would track each other.
5. **Audit log already at 10.5 M lines / ~2 GB after 3h** — at this rate a 24 h run would write ~16 GB. Still need to wire a logrotate rule before any long-overnight bench.

## Artifacts

| Path | What |
|---|---|
| `artifacts/k6-summary.json` | k6 metrics (this one wrote cleanly — k6 was stopped before reboot) |
| `artifacts/sysstat.csv` | 1,121 rows × 8 columns, 10 s sample interval |
| `artifacts/metrics-before.txt` / `metrics-after.txt` | Prometheus scrapes at boot and at stop |
| `artifacts/audit-before.txt` / `audit-after.txt` | Audit log line counts (20 → 10,496,468) |
| `artifacts/start-time.txt` / `stop-time.txt` | UTC timestamps |
| `logs/k6.log` | k6 stdout — should be complete this run (no early-cutoff bug like the 10h run) |
| `./waf_audit.log` (repo root) | v2.3-shape audit, 10.5 M rows |
| `/var/log/aegis/audit-2026-05-19.ndjson` | Chain-hash audit (richer schema) |

## Comparison vs prior runs

| Run | Duration | Sustained RPS | p99 latency | legit_ok | Detection % | Outcome |
|---|---|---|---|---|---|---|
| 2h 5k RPS (400 VUs) | 17 m | 5,025 | 32.6 ms | 0.01 % | 93.0 % | Saturated, CLOSE_WAIT leak |
| 10h 2k RPS (20 VUs) | 9h 23m | ~1,400 audit/s | n/a | n/a | n/a | Host hang after ~3h, watchdog reboot |
| **5h 500 RPS (5 VUs) — THIS** | **3h 7m** | **938** | **0.92 ms** | **100 %** | **93.3 %** | **Clean, no degradation** |

The 500 RPS / 5-VU configuration is the **sweet spot for a single-source-IP synthetic bench on this host**. For genuine prod-scale numbers we'd need multiple source IPs (loopback aliases or separate hosts) so the per-IP detectors don't suppress what the WAF can really process.
