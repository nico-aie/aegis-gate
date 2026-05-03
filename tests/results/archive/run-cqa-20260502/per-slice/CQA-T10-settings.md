### CQA-T10 · Settings (HACK-T4 watch-list: ConfigVersionsCard rollback; MTLS-T7 watch-list: MtlsSansCard)

**Audit method:** Static source analysis (Bash blocked — no live server probing)

| Item | Type | Verified | Notes |
|---|---|---|---|
| `useModeApi()` → `/api/mode` | data load | ✅ | Live hook; `isShadow` derived from `mode === 'log_only'` |
| Shadow mode toggle → `settingsModePut(next)` | mutation | ✅ | CSRF-gated; version-wait; toast; `modeApi.reload` after |
| Shadow mode banner | render | ✅ | Shows banner + ACTIVE pill when `isShadow` is true |
| **HACK-T4 — ConfigVersionsCard** | | | |
| `useConfigVersionsApi(50)` → `/api/config/versions` | data load | ✅ | Live hook; `fallback: null` |
| Empty state for versions | render | ✅ | "No config changes recorded yet…" when `versions.length === 0` |
| Row expand (▶/▼ toggle) | mutation | ✅ | `setExpanded(isOpen ? null : v.seq)` on row click |
| Request ID cross-link to Audit Log | render | ✅ | `<a href="#/audit?request_id=...">View in Audit Log →</a>` |
| Rollback button visibility | render | ✅ | Only shown when `rollbackable.includes(v.action)` — currently `['mode_set']` |
| Two-step rollback confirm | mutation | ✅ | `confirmSeq → Yes, rollback → onRollback(seq)` flow |
| Rollback → `configRollback(seq)` → POST `/api/config/versions/{seq}/rollback` | mutation | ✅ | CSRF-gated; success pill / fail pill |
| Rollback only on `mode_set` action | render | ✅ | "rollback unavailable" hint for other action types with tooltip explaining |
| **MTLS-T7 — MtlsSansCard** | | | |
| `useMtlsSansApi()` → `/api/mtls/sans` | data load | ✅ | Live hook; `fallback: { allowed: [] }` |
| Empty list state | render | ✅ | "No patterns configured — every cert-presenting peer is admitted." when `empty` |
| "open (any SAN)" pill when empty | render | ✅ | Correct pill shown |
| Add SAN → `mtlsSansPut([...list, next])` → PUT `/api/mtls/sans` | mutation | ✅ | CSRF-gated; checks for duplicate; toasts on ok/err |
| Remove SAN → `mtlsSansDelete(san)` → DELETE `/api/mtls/sans/{san}` | mutation | ✅ | `window.confirm` guard; CSRF-gated; reloads list |
| Test admit → `mtlsSansTest(target)` → POST `/api/mtls/sans/{target}/test` | mutation | ✅ | Shows admitted / rejected / error result pill |
| Enter key submits Add SAN | render | ✅ | `onKeyDown={e => { if (e.key === 'Enter') addOne(); }}` |
| **Risk Thresholds card** | | | |
| Risk sliders (allow/challenge) | mutation | ⚠️ NOT WIRED | Clearly labeled `pill warn "not wired"` in UI. Sliders update local state only — no PUT to `/api/risk/thresholds`. See FINDING-T10-A. |
| **Challenge Engine card** | | | |
| Challenge type select | mutation | ⚠️ NOT WIRED | Labeled "not wired" — local state only. |
| **Honeypot Paths card** | | | |
| Honeypot chip removal | mutation | ⚠️ NOT WIRED | Labeled "not wired" — local state only. |
| Add path button | mutation | ⚠️ NOT WIRED | Input + plus-button have no submit logic and card is labeled "not wired". |
| **Response Filtering card** | | | |
| Stack traces toggle | mutation | ⚠️ NOT WIRED | Labeled "not wired" — local state only. |
| Redact JSON toggle | mutation | ⚠️ NOT WIRED | Labeled "not wired" — local state only. |
| **Cache management card** | | | |
| Cache stats (size, age, n) | render | ❌ STATIC DEMO | Explicitly labeled `pill warn "demo data"`. 6 cache cards have hardcoded sizes/ages/entry counts. See FINDING-T10-B. |
| "Reset all caches" button | mutation | ❌ DISABLED | `disabled` attribute — no-op. |
| Individual "Flush" buttons | mutation | ❌ NO-OP | Each cache card has a "Flush" button with no `onClick`. See FINDING-T10-C. |
| Runtime sizing hint | render | ✅ | Shows when `/api/runtime` responds; links to Scaling page |
| `window.CLUSTER` / `window.CERTS` / etc. | code | ✅ | Not referenced in PageSettings |

**Findings:**

- **FINDING-T10-A (MEDIUM):** Risk threshold sliders are local state only. The backend endpoint `PUT /api/risk/thresholds` (CI-T12) is implemented in data.jsx as `settingsRiskThresholdsPut` and exported to `window`, but the Settings page does not call it. The "not wired" label is honest but the mutation pathway exists and could be wired.
- **FINDING-T10-B (HIGH):** Cache management card has 6 hardcoded demo entries (sizes, ages, counts are static strings in the JSX). The card is labeled "demo data" which is honest, but renders fake operational data.
- **FINDING-T10-C (HIGH):** Individual "Flush" buttons per cache type have no `onClick`. They appear clickable but do nothing.

**Console errors:** None expected.
**Network 4xx/5xx:** Cannot verify live (Bash blocked).
**Audit chain:** Mode toggle and SAN mutations are CSRF-gated and audit-chained. Rollback is also CSRF-gated.
**Verdict:** ⚠️ PARTIAL PASS — ConfigVersionsCard (HACK-T4) and MtlsSansCard (MTLS-T7) are fully wired and meet their acceptance criteria. Shadow mode toggle works. Multiple "not wired" cards are explicitly labeled. Critical gap: FINDING-T10-B/C (demo cache data + inert flush buttons).
