### CQA-T5 · Audit Log

**Audit method:** Static source analysis (Bash blocked — no live server probing)

| Item | Type | Verified | Notes |
|---|---|---|---|
| `useAuditLogApi({ip, ruleId, requestId, limit:200})` → `/api/audit/since` | data load | ✅ | Parameterised by filter state; 250ms debounce prevents keystroke-per-request |
| Filter by client IP | mutation | ✅ | `setIpFilter` → debounce → `debouncedQ.ip` → `useAuditLogApi` param |
| Filter by rule_id | mutation | ✅ | `setRuleIdFilter` → debounce → `useAuditLogApi` |
| Filter by request_id | mutation | ✅ | `setRequestIdFilter` → debounce → `useAuditLogApi` |
| Empty state (no events) | render | ✅ | "No audit events match the current filters." row when `events.length === 0` |
| Live / fetch-failed pill | render | ✅ | Shows `audit.error ? 'fetch failed' : 'live'` |
| Stream gap pill | render | ✅ | `{gap && <span className="pill warn">stream gap</span>}` |
| Refresh button | mutation | ✅ | Calls `audit.reload` |
| Cursor display | render | ✅ | `audit.data?.cursor` and `next_cursor` shown in filter bar |
| Row data extraction | render | ✅ | `const e = row.event || row` — handles both wrapped and flat event shapes |
| Class pill coloring | render | ✅ | `admin→warn`, `system→info`, `access→neutral`, `detection→block` |
| `from`/`to` time filter | mutation | ⚠️ NOT WIRED | `useAuditLogApi` accepts `from`/`to` params but the UI exposes no date-range inputs. Operators can only filter by IP, rule_id, or request_id. See FINDING-T5-A. |
| Verify chain button | mutation | ❌ MISSING | No UI to trigger chain verification from the Audit Log page. StatusBar shows "Audit chain (demo)". Chain is hash-chained server-side but no per-entry "Verify" action is exposed to the operator from this page. See FINDING-T5-B. |
| Pagination / load-more | mutation | ⚠️ LIMITED | Cursor is displayed but there is no "Load more" button to fetch the next page. Hard limit of 200 events. |
| Static `window.ADMIN_LOG` fixture | code | ✅ | PageAuditLog does NOT reference `window.ADMIN_LOG`. Uses live API. |

**Findings:**

- **FINDING-T5-A (MEDIUM):** The `useAuditLogApi` hook accepts `from` / `to` unix-timestamp parameters but the page UI provides no date/time range picker. Operators cannot query audit events by time range from the dashboard; they must know a specific IP, rule_id, or request_id to filter.
- **FINDING-T5-B (MEDIUM):** The acceptance criteria require "verify" chain verification from the Audit Log page. No verify button exists. The StatusBar marks audit chain as "(demo)" which is accurate but the page itself offers no operator-facing verification flow.
- **FINDING-T5-C (LOW):** Hard limit of 200 events with no pagination; only cursor display. For a busy system this may miss recent events.

**Console errors:** None expected from static analysis.
**Network 4xx/5xx:** Cannot verify live (Bash blocked).
**Audit chain:** Read-only page — no mutations to trace.
**Verdict:** ⚠️ PARTIAL PASS — Core data fetch and filter wiring are clean. FINDING-T5-A (no time-range UI) and FINDING-T5-B (no verify action) are functional gaps against the acceptance criteria.
