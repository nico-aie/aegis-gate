### CQA-T2 · Live Feed

**Audit method:** Static source analysis (Bash blocked — no live server probing)

| Item | Type | Verified | Notes |
|---|---|---|---|
| `useRealLiveFeed` → `/dashboard/sse` | data load | ✅ | EventSource with `withCredentials: true`; maps SSE payload to row shape |
| SSE connected pill | render | ✅ | Shows 'connected' / 'disconnected' from `connected` state; logic correct |
| Pause / Resume button | mutation | ✅ | Toggles `paused` state; EventSource subscription respects it |
| Filter by action (select) | mutation | ✅ | Client-side filter on `filterAction` state |
| Filter by risk tier (select) | mutation | ✅ | Client-side filter on `filterTier` state |
| Search by IP / path | mutation | ✅ | Client-side filter on `search` state |
| Table empty state | render | ✅ | No explicit empty-state row; table renders 0 rows silently (acceptable for streaming) |
| Row click → Drawer | mutation | ✅ | `onClick={() => setSelected(e)}` wired |
| Drawer `Copy as cURL` button | mutation | ❌ NO-OP | Button in drawer footer has no `onClick` handler. See FINDING-T2-A. |
| Drawer `Block IP` button | mutation | ❌ NO-OP | No `onClick` handler. See FINDING-T2-A. |
| Drawer `Whitelist` button | mutation | ❌ NO-OP | No `onClick` handler. See FINDING-T2-A. |
| `Inspect` icon-btn | mutation | ❌ NO-OP | `<button className="icon-btn">` with no onClick. |
| CSV Download button | mutation | ❌ NO-OP | No `onClick` handler. |
| `RequestDetail` drawer — static fields | render | ❌ STATIC | Same issue as T1-E: ASN, JA4, xff, request_id, chain_hash, sinks are hardcoded strings (lines 306-336). |
| SSE fallback when disconnected | render | ✅ | `events` stays at `[]` when EventSource fails; page shows 0 rows + 'disconnected' pill — honest empty state |
| `Math.random()` in rendering path | code | ✅ | Not in PageLiveFeed. `useRealLiveFeed` is pure SSE, not simulation. |
| Static fixtures used | code | ✅ | Page does not reference window.RULES / window.BLACKLIST / etc. |

**Findings:**

- **FINDING-T2-A (HIGH):** Three drawer footer buttons ("Copy as cURL", "Block IP", "Whitelist") have no `onClick` handlers. They are cosmetically rendered but non-functional. Block IP in the live feed context is the primary incident-response action — it must route to blacklist POST.
- **FINDING-T2-B (MEDIUM):** The `RequestDetail` component shared between Overview and Live Feed contains hardcoded network fields (see FINDING-T1-E). The `data` prop only carries `{ ip, geo, risk, cats }` — the drawer body cannot display accurate ASN, JA4, xff, request_id, or audit chain details.
- **FINDING-T2-C (LOW):** CSV Download button is a no-op.

**Console errors:** No obvious static-load errors.
**Network 4xx/5xx:** Cannot verify live (Bash blocked). SSE endpoint may return 401 if session not established.
**Audit chain:** Not applicable (read-only feed page).
**Verdict:** ❌ FAIL — FINDING-T2-A (all three action buttons are no-ops)
