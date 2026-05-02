### CQA-T1 · Overview

**Audit method:** Static source analysis (Bash blocked — no live server probing)

| Item | Type | Verified | Notes |
|---|---|---|---|
| `useStatsApi` → `/api/stats` | data load | ✅ | Hook wired; `request_rate`, `blocks_total`, `block_rate_pct`, `active_threats`, `upstream` consumed |
| `useTimeseriesApi(60,1)` → `/api/stats/timeseries` | data load | ✅ | Sparklines + TrafficChart fed from API points |
| `useAttacksDistributionApi(900)` → `/api/attacks/distribution` | data load | ✅ | Donut slices built from `categories[]` array |
| `useAttacksTopApi(900,5)` → `/api/attacks/top` | data load | ✅ | Top-attacker table from `attackers[]` |
| KPI tiles (`requestRate`, `blocksTotal`, `blockRate`, `activeThreats`) | render | ✅ | All fed from `stats.data`; `?? 0` fallback appropriate |
| Empty state — top attackers table | render | ✅ | Explicit `length === 0` row: "No attackers observed in the last 15 minutes." |
| World map geo pill: "geo DB not loaded" | render | ✅ | Shows honest warning when `blips.length === 0` |
| Risk heatmap widget | render | ❌ STATIC | `RiskHeatmap` receives hardcoded rows (8 named paths with hardcoded intensity values) — not fed from any API. See FINDING-T1-A. |
| `Refresh` button | mutation | ❌ NO-OP | `onClick` not connected — button has no handler. See FINDING-T1-B. |
| `Export` button | mutation | ❌ NO-OP | `onClick` not connected. |
| `Open Grafana` button | mutation | ❌ NO-OP | Opens no URL; no handler. |
| `Block` button (top-attacker rows) | mutation | ❌ NO-OP | No `onClick` handler — `<button className="btn sm danger">Block</button>` is inert. See FINDING-T1-C. |
| `Inspect` button (top-attacker rows) | mutation | ✅ | Opens Drawer via `setDrawerEvent(a)`. |
| `AI INSIGHTS` "Notify me →" button | render | ✅ | Correctly `disabled` — decorative placeholder, labeled "Coming soon". |
| Window controls (1m/5m/15m/1h chips) | mutation | ❌ NO-OP | Chips have no `onClick` to change the API window. See FINDING-T1-D. |
| `RequestDetail` drawer — hardcoded fields | render | ❌ STATIC | Drawer hard-codes `AS14061 (DigitalOcean)`, `t13d_1516h2...` JA4, `req_8a1f2c4d9e0b` request_id, `a4f2e9c1b3d7` chain_hash, "splunk ✓ · datadog ✓ · s3-archive ✓" sinks. These values never change regardless of which attacker is clicked. |
| `Math.random()` in rendering code | code | ✅ | Not present in pages.jsx. The `Math.random` calls are in `data.jsx::makeLiveEvent` / `useLiveFeed` / `useTrafficSeries` (simulation helpers). |
| Static fixture globals (`window.RULES`, etc.) | code | ✅ | Overview page does NOT use RULES/BLACKLIST/WHITELIST/UPSTREAMS/CLUSTER/CERTS/ALERTS/ADMIN_LOG |
| Console errors (static) | code | ✅ | No obvious error-throw paths on initial render |
| Network 4xx/5xx | code | ✅ | `useApi` catches HTTP errors; fallback = null; no 4xx expected on GET |

**Findings:**

- **FINDING-T1-A (HIGH):** `RiskHeatmap` receives 8 static rows hardcoded in JSX (lines 225-234). There is no API hook wiring for the heatmap. The cell intensities (`0.95`, `0.85`, etc.) are fabricated. No `/api/*` endpoint backs this widget.
- **FINDING-T1-B (MEDIUM):** "Refresh" button (page-actions) has no `onClick` handler — clicking it does nothing. Same for "Export".
- **FINDING-T1-C (HIGH):** "Block" button in the Top Attackers table has no `onClick`. It renders as a danger-colored button but is completely inert — clicking it performs no action, emits no toast, adds no blacklist entry.
- **FINDING-T1-D (LOW):** Time-window chips (1m/5m/15m/1h) are decorative; clicking them does not change the API query window. The chart always uses the hardcoded 60s/1s parameters.
- **FINDING-T1-E (HIGH):** `RequestDetail` drawer contains fully hardcoded network fields (ASN, JA4, xff chain, request_id, chain_hash, sinks list) that never reflect the actual selected attacker's data.

**Console errors:** Likely none at static load. FINDING-T1-E may cause confusion but not JS errors.
**Network 4xx/5xx:** Cannot verify live (Bash blocked).
**Audit chain:** Not applicable for read-only Overview page.
**Verdict:** ❌ FAIL — FINDING-T1-A (static heatmap), FINDING-T1-C (inert Block button), FINDING-T1-E (static drawer fields)
