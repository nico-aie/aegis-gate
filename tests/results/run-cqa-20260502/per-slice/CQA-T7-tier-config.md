### CQA-T7 · Tier Config

**Audit method:** Static source analysis (Bash blocked — no live server probing)

| Item | Type | Verified | Notes |
|---|---|---|---|
| `useTiersApi()` → `/api/tiers` | data load | ✅ | `fallback: { tiers: [] }` — honest empty state |
| `useRoutesApi()` → `/api/routes` | data load | ✅ | `fallback: { routes: [] }` |
| HACK-T1 retirement | code | ✅ | PageTierConfig uses `tiersApi.data?.tiers` and `routesApi.data?.routes` — no reference to `window.TIERS` fixture |
| Empty state — tiers list | render | ✅ | "No tiers configured." when `tiers.length === 0` |
| Empty state — routes for tier | render | ✅ | "No routes assigned to this tier." when `routesForSelected.length === 0` |
| Live / fetch-failed pill | render | ✅ | `tiersApi.error || routesApi.error ? 'fetch failed' : 'live'` |
| Auto-select first tier | render | ✅ | `useEffectP` sets `selectedName` when `tiers.length > 0` |
| Refresh button | mutation | ✅ | Calls both `tiersApi.reload` and `routesApi.reload` |
| Pipeline stages display | render | ✅ | Maps `selected.pipeline[]` to pills |
| Routes table columns | render | ✅ | id, host, path, match_type, methods, upstream — all from live data |
| Detector count badge | render | ✅ | `(t.pipeline || []).filter(p => !['rate','rules','risk','challenge'].includes(p)).length` — reasonable but excludes these 4 infra stages from the count |
| Edit tier button / save | mutation | ❌ MISSING | No "Edit" or "Save" button exists on this page. Tier config is view-only. The audit-mutated PUT per the plan description is not surfaced in the UI. See FINDING-T7-A. |
| Detector mask toggle per tier | mutation | ❌ MISSING | Plan §3 says "detector mask audit-mutated PUT + per-tier override" — not implemented in the UI. |
| `window.TIERS` fixture | code | ✅ | Not used in PageTierConfig |

**Findings:**

- **FINDING-T7-A (HIGH):** PageTierConfig is fully read-only. There is no Edit button, no mutation form, and no audit-mutated PUT for modifying tier pipeline / detector masks. The plan description for CQA-T7 explicitly requires "detector mask audit-mutated PUT + per-tier override". This functionality is missing from the UI entirely.

**Console errors:** None expected.
**Network 4xx/5xx:** Cannot verify live (Bash blocked).
**Audit chain:** No mutations possible from this page.
**Verdict:** ❌ FAIL — FINDING-T7-A: tier editing is not implemented. Page is read-only display only.
