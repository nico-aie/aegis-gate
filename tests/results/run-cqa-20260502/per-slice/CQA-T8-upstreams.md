### CQA-T8 · Upstreams

**Audit method:** Static source analysis (Bash blocked — no live server probing)

| Item | Type | Verified | Notes |
|---|---|---|---|
| `useUpstreamsConfigApi()` → `/api/upstreams/config` | data load | ✅ | `fallback: { pools: {} }` |
| `useUpstreamsApi()` → `/api/upstreams` | data load | ✅ | `fallback: { pools: [] }` — live health summary |
| HACK-T1 retirement | code | ✅ | PageUpstreams does not reference `window.UPSTREAMS` fixture |
| Empty state — no pools | render | ✅ | "No upstream pools configured. Click + Add pool…" |
| "Select a pool to inspect" state | render | ✅ | `PoolDetail` renders placeholder when `pool` is null |
| Live vs config health cross-reference | render | ✅ | `PoolListRow` reads healthy count from `summaryApi` live data, not config |
| + Add pool button → `PoolEditModal` | mutation | ✅ | `openAdd()` sets `editor = { mode: 'add' }` |
| Edit pool → `PoolEditModal` | mutation | ✅ | `openEdit(name, pool)` pre-seeds form from existing PoolView |
| Save pool → `poolUpsert(name, body)` → PUT `/api/upstreams/pool/{name}` | mutation | ✅ | CSRF-gated; status 200+ok on success; error toast otherwise |
| Delete pool → `DeletePoolModal` → `poolDelete(name)` | mutation | ✅ | Modal shows blocked/unblocked state; 409 route-reference guard shown |
| Form validation | render | ✅ | `canSave` gated by trimmedName, memberOk, healthOk, cbOk — mirrors backend validators |
| `humanTimeFromMs` conversion | code | ✅ | Correctly converts ms → humantime strings (e.g. "30s", "1m") for wire format |
| `poolFormFromView` / `poolConfigFromForm` symmetry | code | ✅ | Round-trip shape conversion appears correct |
| 409 route-reference guard display | render | ✅ | `DeletePoolModal` shows `refs` list and blocks Confirm when refs.length > 0 |
| Referenced-by-routes pill in PoolDetail | render | ✅ | "unreferenced" pill when `refs.length === 0`; route count otherwise |
| Health check toggle | render | ✅ | `d.health_enabled` checkbox controls whether health block is sent to API |
| Circuit breaker toggle | render | ✅ | `d.cb_enabled` controls whether `circuit_breaker` block is sent |
| Member add / remove rows | mutation | ✅ | `addMember()` / `removeMember(i)` modify `d.members` array immutably |
| Audit chain | mutation | ✅ | `poolUpsert` / `poolDelete` go through CSRF-gated handlers tagged in audit ring |
| Refresh button | mutation | ✅ | Calls both `cfgApi.reload` and `summaryApi.reload` |
| `window.UPSTREAMS` fixture | code | ✅ | Not used in PageUpstreams |
| Pool per-member drain | mutation | ❌ MISSING | No per-member drain or disable action within the edit modal or pool detail. |

**Findings:**

- **FINDING-T8-A (LOW):** No per-member health override or drain control in the UI. Operators can edit the pool (which hot-applies), but cannot mark a single member as drained / disabled without removing it from the config. Likely a follow-up item.

**Console errors:** None expected.
**Network 4xx/5xx:** Cannot verify live (Bash blocked). 409 handling is correctly coded client-side.
**Audit chain:** `poolUpsert` → `pool_upsert` audit action; `poolDelete` → `pool_delete` — both CSRF-gated.
**Verdict:** ✅ PASS — Full CRUD with proper 409 handling, form validation, and audit wiring. Only FINDING-T8-A (per-member drain) is a gap.
