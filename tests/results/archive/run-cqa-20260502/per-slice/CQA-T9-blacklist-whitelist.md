### CQA-T9 · Blacklist + Whitelist

**Audit method:** Static source analysis (Bash blocked — no live server probing)

| Item | Type | Verified | Notes |
|---|---|---|---|
| `useBlacklistApi()` → `/api/blacklist` | data load | ✅ | `fallback: { entries: [] }` — honest empty state |
| `useWhitelistApi()` → `/api/whitelist` | data load | ✅ | `fallback: { entries: [] }` |
| HACK-T1 retirement | code | ✅ | Neither `window.BLACKLIST` nor `window.WHITELIST` referenced in `ListPage` |
| Data shape normalisation | code | ✅ | `const raw = api.data?.entries ?? api.data ?? []; const data = Array.isArray(raw) ? raw : [];` — handles both `{entries:[]}` and flat array |
| Empty state | render | ✅ | "No entries." row when `data.length === 0` |
| Live / fetch-failed pill | render | ✅ | `api.error ? 'fetch failed' : 'live'` |
| `expires_at` / `created_at` field normalisation | render | ✅ | Uses `.expires_at` and `.created_at` (server field names); mock data uses `expires` / `created` (old names). The current code looks for `e.expires_at` — if backend returns old names this shows "never" / "—" for all rows. See FINDING-T9-A. |
| Action pill (blacklist) | render | ✅ | `<ActionPill value={e.action || 'block'} />` |
| Bypass pills (whitelist) | render | ✅ | `e.bypass || []` — renders "all · high-trust" or individual bypasses |
| Refresh button | mutation | ✅ | `api.reload` called |
| `+ Add entry` button | mutation | ❌ NO-OP | Button has no `onClick` handler — `<button className="btn primary"><window.I.Plus /> Add entry</button>`. See FINDING-T9-B. |
| Delete entry | mutation | ❌ MISSING | No delete button per row. |
| Edit entry | mutation | ❌ MISSING | No edit action per row. |
| Search / filter | mutation | ❌ MISSING | No search input. |
| `window.BLACKLIST` / `window.WHITELIST` | code | ✅ | Not used in ListPage |

**Findings:**

- **FINDING-T9-A (MEDIUM):** The `ListPage` renders `e.expires_at` and `e.created_at` but the static `BLACKLIST` / `WHITELIST` fixtures in data.jsx use `expires` and `created`. If the live backend returns the same old field names, all dates render as "never" / "—". Need to confirm API field names match what the UI reads.
- **FINDING-T9-B (HIGH):** "Add entry" button has no `onClick` handler. Clicking it does nothing. There is no modal, no form, no POST path. Both blacklist and whitelist are read-only displays with no mutation capability beyond what was already in the backend config file. This is the most critical gap for the blacklist/whitelist pages.
- **FINDING-T9-C (HIGH):** No delete or edit action per row. Operators cannot remove entries from the UI.

**Console errors:** None expected.
**Network 4xx/5xx:** Cannot verify live (Bash blocked).
**Audit chain:** No mutations possible.
**Verdict:** ❌ FAIL — FINDING-T9-B and FINDING-T9-C: no CRUD mutations at all. Page is read-only display.
