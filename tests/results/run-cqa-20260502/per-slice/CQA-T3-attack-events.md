### CQA-T3 · Attack Events (HACK-T1 watch-list)

**Audit method:** Static source analysis (Bash blocked — no live server probing)

| Item | Type | Verified | Notes |
|---|---|---|---|
| `useAttacksByDetectorApi(windowSeconds)` → `/api/attacks/by-detector` | data load | ✅ | Hook correctly parameterised; re-fetches on window change |
| `useBotMixApi(windowSeconds)` → `/api/bots/mix` | data load | ✅ | Hook correctly parameterised |
| `useThreatIntelApi(windowSeconds, 20)` → `/api/threat-intel/hits` | data load | ✅ | Hook correctly parameterised |
| `Math.random()` in render path | code | ✅ | Confirmed retired — HACK-T1 complete. No `Math.random` call in PageAttackEvents. |
| Detector breakdown empty state | render | ✅ | "No detections in the last {win}." message when `detectorBars.length === 0` |
| Bot mix empty state | render | ✅ | "No bot classifications recorded in the last {win}." message |
| Threat-intel empty state | render | ✅ | "No threat-intel matches in the last {win}." message |
| Window selector (5m/15m/1h/6h/24h) | mutation | ✅ | `setWin` triggers state update, which re-parameterises all three hooks via `windowSeconds` |
| Refresh button | mutation | ✅ | Calls `byDetector.reload`, `botMix.reload`, `tiApi.reload` |
| `malicious.pct` field rendering | render | ⚠️ RISKY | Code calls `malicious.pct.toFixed(1)` — if `/api/bots/mix` returns a category without a `pct` field, this throws. Backend must include `pct` on each category object. See FINDING-T3-A. |
| Threat-intel `last_seen` date parse | render | ✅ | `new Date(t.last_seen).toLocaleTimeString()` — handles ISO strings; silently shows "Invalid Date" if field is missing |
| Static fixtures (`ATTACK_CATS`, `ATTACKER_GEO`) | code | ✅ | `ATTACK_CATS` used only for label definitions in data.jsx; `ATTACKER_GEO` only used in simulation helpers. PageAttackEvents does not reference them. |
| ADMIN_LOG, CLUSTER, CERTS, UPSTREAMS fixtures | code | ✅ | Not referenced in PageAttackEvents |

**Findings:**

- **FINDING-T3-A (MEDIUM):** `malicious.pct.toFixed(1)` at line 581 — if the `pct` field is absent or null from the `/api/bots/mix` response, this throws a TypeError and crashes the bot mix card. Should guard with `(malicious.pct ?? 0).toFixed(1)`.

**Console errors:** Potential TypeError if `pct` is missing (FINDING-T3-A).
**Network 4xx/5xx:** Cannot verify live (Bash blocked).
**Audit chain:** Not applicable (read-only page).
**Verdict:** ⚠️ CONDITIONAL PASS — HACK-T1 retirement is clean. FINDING-T3-A is a crash risk if backend omits `pct`.
