### CQA-T4 · Analytics (HACK-T1 watch-list: SLO pills + cert freshness)

**Audit method:** Static source analysis (Bash blocked — no live server probing)

| Item | Type | Verified | Notes |
|---|---|---|---|
| `useTimeseriesApi(cfg.window, cfg.step)` → `/api/stats/timeseries` | data load | ✅ | Dynamic window/step driven by `range` state |
| `useSloApi()` → `/api/slo` | data load | ✅ | Live hook — not static fixture |
| `useCertsApi()` → `/api/certs` | data load | ✅ | Live hook — not static fixture |
| `Math.random()` in render path | code | ✅ | Retired. `reqOverTime` and `blockRatioPct` computed from API `points[]`. |
| Time-range selector (1h/6h/24h/7d/30d) chips | mutation | ✅ | `setRange` → re-parameterises `useTimeseriesApi`; hooks `cfg.window` and `cfg.step` update |
| Refresh button | mutation | ✅ | Calls `ts.reload` |
| "Requests over time" empty state | render | ✅ | "No traffic recorded in the last {range}." when `!hasSeries` |
| "Block ratio" empty state | render | ✅ | "No block decisions in the last {range}." |
| "Latency p50/p95/p99" widget | render | ⚠️ PLACEHOLDER | Explicitly states "Latency percentiles ship via Prometheus." — correctly documented but renders no live data. |
| "Error rate by route" widget | render | ⚠️ PLACEHOLDER | "Per-route aggregation ships in a follow-up." — correctly documented but no data. |
| SLO budget bars | render | ✅ | `sloApi.data?.slis ?? []` with proper empty state "SLO engine warming up". `budget_remaining` progress bar logic correct. |
| Cert freshness pills | render | ✅ | `certsApi.data?.certs ?? []` with empty state "No certificates configured". Correctly uses `days_to_expiry ?? days` to normalize field name. |
| SLO pill tone logic | render | ✅ | `remainPct < 30 → down`, `< 60 → warn`, else no override — visually correct |
| Cert pill tone logic | render | ✅ | `days < 7 → down`, `< 30 → warn`, else `up` |
| `avgReqPerSecond` division guard | render | ✅ | `points.length > 0` guard prevents div-by-zero |
| `peakBlockPct` when array empty | render | ✅ | Guard `blockRatioPct.length > 0` before `Math.max(...blockRatioPct)` |
| Static `window.CERTS` fixture | code | ✅ | PageAnalytics uses `certsApi.data?.certs` only — never reads `window.CERTS` |
| Static `window.ALERTS` / `window.CLUSTER` | code | ✅ | Not referenced |

**Findings:**

- **FINDING-T4-A (LOW):** "Latency p50/p95/p99" and "Error rate by route" cards render static placeholder text. They are clearly labeled as follow-ups in the UI, so operators can distinguish live data from pending features. This is an honest placeholder, not a stale fixture.

**Console errors:** None expected from static analysis.
**Network 4xx/5xx:** Cannot verify live (Bash blocked).
**Audit chain:** Not applicable (read-only page).
**Verdict:** ✅ PASS (with acknowledged placeholder gaps per FINDING-T4-A — these are documented in the UI)
