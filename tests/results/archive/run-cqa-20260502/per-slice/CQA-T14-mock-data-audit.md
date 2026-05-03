### CQA-T14 · Mock-data audit (Math.random + static fixture sweep)

**Audit method:** Static source analysis of all 5 source files (pages.jsx 4181 lines, data.jsx 740 lines, app.jsx 228 lines, widgets.jsx 446 lines, help.jsx not counted). Bash blocked — no grep execution.

---

#### Part A: Math.random() locations

| Location | File | Line(s) | In rendering code? | Notes |
|---|---|---|---|---|
| `makeLiveEvent` | data.jsx | 152-163 | NO — simulation helper | Used by `useLiveFeed` (mock feed, now superseded by `useRealLiveFeed`) |
| `useLiveFeed` | data.jsx | 202 | NO — simulation helper | Only used if SSE is unavailable; `PageLiveFeed` calls `useRealLiveFeed` |
| `useTrafficSeries` | data.jsx | 219-233 | ⚠️ PARTIAL | `useTrafficSeries` is exported to `window` and declared in data.jsx. However PageOverview now uses `useTimeseriesApi` (real API), not `useTrafficSeries`. BUT — `useTrafficSeries` is still exported via `window.useTrafficSeries` and still contains `Math.random()`. If any page accidentally calls `window.useTrafficSeries` instead of `window.useTimeseriesApi`, it would render fake data. |
| In-comment `Math.random` mentions | data.jsx / pages.jsx | n/a | NO | Plan §9 notes "2 grep matches are inside comments" — confirmed: the comment at line 459 of pages.jsx (`// HACK-T1 — Math.random retired`) references the word in comment text only. |

**Verdict Part A:** ✅ No `Math.random()` in any active rendering path. The two simulation helpers (`makeLiveFeed`, `useTrafficSeries`) remain in the codebase but are not called by any page component. `useRealLiveFeed` replaces `useLiveFeed`. `useTimeseriesApi` replaces `useTrafficSeries`.

**Recommendation:** Remove `useLiveFeed` and `useTrafficSeries` from the codebase entirely to prevent accidental reuse.

---

#### Part B: Static fixture globals — which ones still render on pages?

| Fixture | Defined in | Exported to `window` | Referenced in page render? | Verdict |
|---|---|---|---|---|
| `window.RULES` | data.jsx | ✅ | PageRuleManager: ❌ No | ✅ CLEAN |
| `window.TIERS` | data.jsx | ✅ | PageTierConfig: ❌ No | ✅ CLEAN |
| `window.BLACKLIST` | data.jsx | ✅ | ListPage: ❌ No | ✅ CLEAN |
| `window.WHITELIST` | data.jsx | ✅ | ListPage: ❌ No | ✅ CLEAN |
| `window.UPSTREAMS` | data.jsx | ✅ | PageUpstreams / PageTracking: ❌ No | ✅ CLEAN |
| `window.CLUSTER` | data.jsx | ✅ | PageTracking / PageScaling: ❌ No | ✅ CLEAN |
| `window.CERTS` | data.jsx | ✅ | PageTracking / PageAnalytics: ❌ No | ✅ CLEAN |
| `window.ALERTS` | data.jsx | ✅ | PageTracking: ❌ No | ✅ CLEAN |
| `window.ADMIN_LOG` | data.jsx | ✅ | PageAuditLog: ❌ No | ✅ CLEAN |
| `window.ATTACK_CATS` | data.jsx | ✅ | Not used in page render directly | ✅ CLEAN — label definitions only |
| `window.ATTACKER_GEO` | data.jsx | ✅ | makeLiveEvent only | ✅ CLEAN — simulation helper only |
| `window.ROUTES` / `REGIONS` / `METHODS` / `ORIGIN` | data.jsx | ✅ | makeLiveEvent only | ✅ CLEAN — simulation helper only |

---

#### Part C: Hardcoded static values still rendering as live data (not fixtures from data.jsx)

These are hardcoded in JSX in pages.jsx and are NOT from the static fixture globals, but still violate the "no static data" criterion:

| Location | Content | File:Line | Severity |
|---|---|---|---|
| `RiskHeatmap rows` in PageOverview | 8 hardcoded path/intensity pairs | pages.jsx:225-234 | HIGH |
| `RequestDetail` ASN field | `"AS14061 (DigitalOcean)"` hardcoded | pages.jsx:307 | HIGH |
| `RequestDetail` JA4 field | `"t13d_1516h2_8daaf6152771_e5627efa2ab1"` hardcoded | pages.jsx:308 | HIGH |
| `RequestDetail` xff field | `"10.32.4.11 → 10.99.0.1"` hardcoded | pages.jsx:309 | HIGH |
| `RequestDetail` request_id | `"req_8a1f2c4d9e0b"` hardcoded | pages.jsx:312 | HIGH |
| `RequestDetail` chain_hash | `"a4f2e9c1b3d7…"` hardcoded | pages.jsx:313 | HIGH |
| `RequestDetail` prev hash | `"a4f2e9c1b3d6"` hardcoded | pages.jsx:314 | HIGH |
| `RequestDetail` sinks list | `"splunk ✓ · datadog ✓ · s3-archive ✓"` hardcoded | pages.jsx:315 | HIGH |
| `RequestDetail` request body | `{"url": "http://169.254.169.254/..."}` hardcoded | pages.jsx:319-320 | MEDIUM |
| Sidebar footer BUILD / UPTIME | `"1.4.2-3a8f"` and `"14d 22h"` hardcoded | app.jsx:121-122 | MEDIUM |
| Cache management card stats | 6 rows with hardcoded sizes/ages/counts | pages.jsx:2146-2152 | HIGH |
| Help page subtitle | `"last updated 2026-04-28 · v1.4.2"` hardcoded | help.jsx:12 | LOW |

---

#### Part D: "Coming soon" or disabled buttons that should be functional

| Element | Page | Issue |
|---|---|---|
| "AI INSIGHTS / Notify me →" | Overview | `disabled` — acceptable placeholder, clearly labeled |
| "Open Grafana" | Overview | No URL wired |
| "Full docs" | Help | No URL wired |
| "Contact on-call" | Help | No URL wired |
| Risk threshold sliders | Settings | Local state only; labeled "not wired" |
| Challenge Engine select | Settings | Local state only; labeled "not wired" |
| Honeypot paths add | Settings | Not wired; labeled "not wired" |
| Response filtering toggles | Settings | Not wired; labeled "not wired" |

---

**Overall Verdict Part C/D:** ❌ FAIL on "zero static-fixture fallbacks rendering anywhere" — 8 fields in `RequestDetail` are hardcoded; RiskHeatmap rows are hardcoded; Cache management card stats are hardcoded.

**Overall CQA-T14 Verdict:** ❌ FAIL — Math.random retirement is complete (✅) and window fixture globals are not read in page render (✅), but JSX-level hardcoded values in RequestDetail, RiskHeatmap, and CacheManagement card fail the "zero fake numbers" requirement.
