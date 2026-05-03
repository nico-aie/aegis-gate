### CQA-T6 · Rule Manager (HACK-T3 watch-list: simulator card)

**Audit method:** Static source analysis (Bash blocked — no live server probing)

| Item | Type | Verified | Notes |
|---|---|---|---|
| `useRulesApi()` → `/api/rules` | data load | ✅ | `fallback: { rules: [] }` — honest empty state when API returns nothing |
| HACK-T1 retirement | code | ✅ | `merged` built entirely from `rulesApi.data.rules`. No reference to `window.RULES` fixture in PageRuleManager. |
| Empty state when no rules | render | ✅ | "No rules match." shown when `filtered.length === 0` |
| "No rule selected" state | render | ✅ | Right panel shows "No rule selected. Use + New rule to create one." |
| Reload button | mutation | ✅ | Calls `rulesApi.reload` |
| New rule button → modal | mutation | ✅ | `setShowNew(true)` opens `NewRuleModal` |
| Rule list click → select | mutation | ✅ | `setSelectedId(r.id)` on row click |
| Edit button → edit mode | mutation | ✅ | `startEdit()` sets `editing=true`, copies body to `editBody` |
| Save & deploy → `rulesPut(id, {body, enabled})` | mutation | ✅ | Calls `window.rulesPut`, then `waitForVersion` → toast on apply |
| Cancel edit | mutation | ✅ | `cancelEdit()` clears state |
| Toggle enable/disable → `rulesToggle(id)` | mutation | ✅ | Calls `window.rulesToggle`, waits for version, toasts |
| Delete rule → `rulesDelete(id)` | mutation | ✅ | `window.confirm()` guard, then `rulesDelete`, version wait, toast |
| Create new rule → `rulesPost({id, body, enabled})` | mutation | ✅ | `NewRuleModal` gated by `newId.trim()` non-empty; calls `rulesPost` |
| CSRF token extraction | code | ✅ | All mutations read `aegis_csrf` cookie via `document.cookie` (in data.jsx helpers) |
| Version increment verification | code | ✅ | `waitForVersion(before + 1, 10000)` polls `/api/config/version` — correct |
| Toast on successful mutation | render | ✅ | `window.aegisToast(label, 'ok'/'warn'/'err')` called in all paths |
| Audit chain (via PUT/POST/DELETE) | mutation | ✅ | All three helpers in data.jsx include CSRF header — will hit audit-mutated backend handlers |
| **HACK-T3 — Rule Simulator card** | | | |
| Simulator: method select | mutation | ✅ | 6 methods available (GET/POST/PUT/DELETE/PATCH/HEAD) |
| Simulator: path input pre-seeded | render | ✅ | Default `"/api/users?id=1' OR '1'='1"` — a SQLi probe, good for regression |
| Simulator: Simulate button → `rulesSimulate(payload)` | mutation | ✅ | POST `/api/rules/simulate` with CSRF header |
| Simulator: disabled when path empty | render | ✅ | `disabled={busy || !path}` — validation present |
| Simulator: shows `decision_action` pill | render | ✅ | `ok && decision` → pill with tone |
| Simulator: shows `detectors_fired[]` | render | ✅ | List of fired detector IDs |
| Simulator: shows `muted_detectors[]` | render | ✅ | "Muted (disabled by mask)" section |
| Simulator: shows `signals[]` | render | ✅ | Table of class/detail rows |
| Simulator: HTTP error display | render | ✅ | `result.status !== 200 → pill down with status code` |
| Per-rule stats tab | render | ⚠️ PLACEHOLDER | "Per-rule statistics ship in a follow-up." — honest placeholder, correctly redirects to Audit Log. |
| `window.RULES` fixture not used | code | ✅ | Confirmed — `PageRuleManager` reads only `rulesApi.data.rules` |
| `merged[0]?.id` initialisation race | code | ⚠️ RISKY | `useState(merged[0]?.id || null)` — `merged` is computed from `apiRules` at render time; on first render `apiRules` is always `[]` so `selectedId` initialises to `null`. The `useEffectP` re-anchor picks it up correctly once data lands. Low risk but worth noting. |

**Findings:**

- **FINDING-T6-A (LOW):** Per-rule statistics tab is a placeholder. Operators must navigate to Audit Log and filter by rule_id manually. This is correctly flagged in the UI.
- **FINDING-T6-B (LOW):** Rule list rows show `hits1h: 0` universally because the API-shape normalisation at lines 1079-1093 hard-sets `hits1h: 0`. The backend `/api/rules` response may carry hits but the adapter discards it.

**Console errors:** None expected.
**Network 4xx/5xx:** Cannot verify live (Bash blocked). CSRF-missing test not runnable.
**Audit chain:** PUT/POST/DELETE all routed through CSRF-gated handlers — expected to produce audit entries.
**Verdict:** ✅ PASS — HACK-T3 simulator is fully wired. Mutations have complete CSRF + version-wait + toast logic. Only minor gaps (stats placeholder, hits1h discarded).
