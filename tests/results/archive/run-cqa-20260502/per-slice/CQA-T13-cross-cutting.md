### CQA-T13 · Cross-cutting (TopBar, Sidebar, Toast, StatusBar)

**Audit method:** Static source analysis (Bash blocked — no live server probing)

| Item | Type | Verified | Notes |
|---|---|---|---|
| **TopBar** | | | |
| `useStatusApi()` → `/api/about` | data load | ✅ | Version, environment, build_sha from live API |
| `useClusterApi()` → `/api/cluster` | data load | ✅ | Peer count from live API |
| Version display | render | ✅ | `status.data?.version || '—'` |
| Environment pill | render | ✅ | `(status.data?.environment || 'unknown').toLowerCase()` |
| Health LED + label | render | ✅ | `healthTone` logic: `status.error → 'err'`, `peerCount === 0 → 'warn'`, else `'ok'` |
| `Standalone` vs `Cluster N nodes` label | render | ✅ | Correct |
| Notifications bell button | mutation | ❌ NO-OP | `<button className="icon-btn" title="Notifications">` — no `onClick` handler. See FINDING-T13-A. |
| **Drain button in TopBar** | mutation | ❌ MISSING | Not present in TopBar (confirmed in app.jsx lines 58-97). FINDING-T12-A confirmed here too. |
| Logout button / mechanism | mutation | ❌ MISSING | No logout button anywhere in TopBar or anywhere in the codebase. User chip shows "admin / SUPER · TOTP" but there is no logout action. See FINDING-T13-B. |
| **Sidebar** | | | |
| Active highlight | render | ✅ | `className={nav-item ${active === it.id ? 'active' : ''}}` |
| All 14 nav items present | render | ✅ | Matches plan §1.1 inventory |
| Live badge on Feed | render | ✅ | `badge: 'LIVE', tone: 'live'` |
| SLO badge on Tracking | render | ✅ | `badge: 'SLO', tone: 'warn'` |
| Sidebar footer build info | render | ❌ STATIC | Shows hardcoded "BUILD 1.4.2-3a8f" and "UPTIME 14d 22h" — never updates from API. See FINDING-T13-C. |
| **StatusBar** | | | |
| Session tick (clock) | render | ✅ | `tick` from `useTicking(2000)` — increments every 2s; "session {tick}s" shown |
| Cluster N/M from `/api/cluster` | render | ✅ | Live `healthy/total` from API |
| GitOps state from `/api/gitops/status` | render | ✅ | Live `gitopsState` pill |
| Build label from `/api/about` | render | ✅ | `buildSha ? "${version}-${sha.slice(0,4)}" : version` |
| SSE indicator | render | ⚠️ DEMO | Explicitly labeled "SSE (demo)" with `title` explaining it's not observed at topbar level |
| Audit chain indicator | render | ⚠️ DEMO | Explicitly labeled "demo" with `title` explaining CLI-only verification |
| **Toast container** | | | |
| Toast system (`window.aegisToast`) | render | ✅ | Called consistently across all mutations |
| Toast lifetime | render | ❓ CANNOT VERIFY | `window.ToastContainer` defined in widgets.jsx; cannot verify timeout without live test |
| **Hash routing** | | | |
| All 14 routes wired in App switch | render | ✅ | All pages render correctly per route |
| `hashchange` listener | render | ✅ | `window.addEventListener('hashchange', onHash)` with cleanup |
| Default route to `overview` | render | ✅ | `location.hash.slice(2) || 'overview'` |

**Findings:**

- **FINDING-T13-A (MEDIUM):** Notifications bell button in TopBar has no `onClick`. It renders with a red dot (suggesting unread notifications) but clicking does nothing.
- **FINDING-T13-B (HIGH):** There is no logout button anywhere in the application. The user chip displays role/TOTP info but provides no logout action. This is a critical gap for any multi-operator deployment — operators cannot sign out from the UI.
- **FINDING-T13-C (MEDIUM):** Sidebar footer shows hardcoded "BUILD 1.4.2-3a8f" and "UPTIME 14d 22h" that never reflect live data. The TopBar and StatusBar correctly show live version/uptime, but the sidebar duplicates these with static strings.

**Console errors:** None expected from static analysis.
**Network 4xx/5xx:** Cannot verify live (Bash blocked).
**Verdict:** ❌ FAIL — FINDING-T13-B: no logout mechanism is a critical cross-cutting issue.
