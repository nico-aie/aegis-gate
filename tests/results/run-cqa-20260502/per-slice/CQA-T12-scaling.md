### CQA-T12 · Scaling

**Audit method:** Static source analysis (Bash blocked — no live server probing)

| Item | Type | Verified | Notes |
|---|---|---|---|
| `useRuntimeApi()` → `/api/runtime` | data load | ✅ | Live hook; `fallback: null` |
| `useClusterApi()` → `/api/cluster` | data load | ✅ | Live hook; `fallback: null` |
| `useStateApi()` → `/api/state` | data load | ✅ | Live hook; `fallback: null`; 5s poll interval |
| **L1 — ScalingL1Card** | | | |
| L1 empty state | render | ✅ | "Runtime info not available — endpoint may be loading." when `!hasData` |
| Workers / mode / blocking-pool / CPU affinity stats | render | ✅ | All from `/api/runtime`; none are hardcoded |
| CPU affinity state logic | render | ✅ | Three-way `active / requested-inactive / off` with tones |
| Restart-only hint | render | ✅ | Banner shown when hasData is true |
| **L2 — ScalingL2Card** | | | |
| Cluster peers table | render | ✅ | Shown when `peers.length > 0`; "No cluster peers — running standalone." when empty |
| "Drain this node" button → two-step confirm | mutation | ✅ | Step 0 → Step 1 (confirm) → `onConfirmFinal` |
| `onDrain` → `adminDrainPost()` → POST `/admin/drain` | mutation | ✅ | CSRF-gated; outcome pill shown |
| Drain result pill (success/fail) | render | ✅ | `status >= 200 && < 300 → "Drained — readiness now 503"` |
| **L3 — ScalingL3Card** | | | |
| L3 empty state | render | ✅ | "State endpoint loading…" when `!hasData` |
| Backend type display | render | ✅ | `data.backend` — "in_memory" on dev config |
| Connected / circuit state | render | ✅ | Connected bool + circuit state with correct tones |
| Keys count (DBSIZE) | render | ✅ | `data?.key_count` — null-safe with "—" fallback |
| Replica lag | render | ✅ | `data?.replica_lag_ms` with warn tone if > 1000ms |
| Latency chips (p50/p95/p99) | render | ✅ | `data?.latency?.p50_us` etc. — µs to ms/s conversion |
| Refresh button | mutation | ✅ | Calls `runtime.reload`, `cluster.reload`, `state.reload` |
| `window.CLUSTER` fixture | code | ✅ | Not used in PageScaling |
| TopBar drain button | mutation | ❌ MISSING | No drain button exists in TopBar (app.jsx). TopBar shows env pill, cluster health, notifications, user chip — no drain. See FINDING-T12-A. |

**Findings:**

- **FINDING-T12-A (MEDIUM):** The QA plan §1.2 cross-cutting list mentions "TopBar drain button". The TopBar (app.jsx lines 40-97) has no drain button. The drain action exists only on the Scaling page (L2 card). If the plan intended a global drain shortcut in the TopBar, it is missing.

**Console errors:** None expected.
**Network 4xx/5xx:** Cannot verify live (Bash blocked). `/admin/drain` POST with no CSRF expected to return 403.
**Audit chain:** `adminDrainPost` is CSRF-gated — should produce an audit entry on success.
**Verdict:** ✅ PASS — All three scaling layers are properly wired to live APIs. Drain button has two-step confirm and CSRF. FINDING-T12-A (missing TopBar drain) is noted for cross-cutting slice.
