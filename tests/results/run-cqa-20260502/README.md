# CQA Run — 2026-05-02

## Audit Method

**Static source analysis only.** Bash execution was denied in this runtime, which means:
- No live server was probed (curl unavailable)
- No Playwright or Agent Browser screenshots were taken
- No mutation round-trips were verified against a running WAF
- No network logs were captured

All findings are derived from reading the full source of:
- `crates/aegis-control/assets/dashboard/src/pages.jsx` (4181 lines)
- `crates/aegis-control/assets/dashboard/src/data.jsx` (740 lines)
- `crates/aegis-control/assets/dashboard/src/app.jsx` (228 lines)
- `crates/aegis-control/assets/dashboard/src/widgets.jsx` (446 lines)
- `crates/aegis-control/assets/dashboard/src/help.jsx`
- `plans/console-qa.md`

Items marked "Cannot verify live" require a follow-up pass with a running WAF instance and Bash access (or Playwright).

---

## Consolidated Verdict Table

| Slice | Page | Verdict | Critical Findings |
|---|---|---|---|
| CQA-T1 | Overview | ❌ FAIL | RiskHeatmap rows hardcoded; Block button no-op; RequestDetail 8 hardcoded fields; time-window chips decorative |
| CQA-T2 | Live Feed | ❌ FAIL | 3 drawer action buttons no-op (Block IP / Copy cURL / Whitelist); RequestDetail static fields |
| CQA-T3 | Attack Events | ⚠️ CONDITIONAL | `malicious.pct.toFixed(1)` crash risk if field absent; HACK-T1 retirement otherwise clean |
| CQA-T4 | Analytics | ✅ PASS | Latency + per-route cards are honest placeholders; SLO + cert pills correctly wired |
| CQA-T5 | Audit Log | ⚠️ PARTIAL | No time-range filter UI; no verify button; pagination limited to 200 with no load-more |
| CQA-T6 | Rule Manager | ✅ PASS | Full CRUD + HACK-T3 simulator all wired; CSRF + version-wait + toast throughout |
| CQA-T7 | Tier Config | ❌ FAIL | Page is fully read-only; no Edit/Save; detector mask mutation not implemented |
| CQA-T8 | Upstreams | ✅ PASS | Full CRUD + 409 guard + form validation; no per-member drain (minor gap) |
| CQA-T9 | Blacklist / Whitelist | ❌ FAIL | "Add entry" no-op; no delete/edit per row; page is display-only |
| CQA-T10 | Settings | ⚠️ PARTIAL | HACK-T4 rollback + MTLS-T7 SAN allowlist fully wired; cache card shows demo data; flush buttons no-op; 4 settings cards "not wired" (labeled) |
| CQA-T11 | Tracking | ✅ PASS | All alert receiver CRUD + test button wired; `useAlertReceiversApi` calls `window.useApi` (code smell) |
| CQA-T12 | Scaling | ✅ PASS | All 3 layers live; drain two-step confirm + CSRF correct |
| CQA-T13 | Cross-cutting | ❌ FAIL | No logout button anywhere; sidebar footer hardcoded; notifications bell no-op; no TopBar drain button |
| CQA-T14 | Mock-data audit | ❌ FAIL | Math.random retired (✅); window fixture globals not used in render (✅); but RequestDetail (8 fields), RiskHeatmap (8 rows), cache card stats are all hardcoded JSX |

**Overall: 5 PASS, 3 PARTIAL, 6 FAIL**

---

## Issues Needing Fixes (Sprint Backlog)

### CRITICAL / HIGH

| ID | Slice | Description |
|---|---|---|
| FINDING-T13-B | CQA-T13 | No logout button anywhere in the application |
| FINDING-T1-C | CQA-T1 | "Block" button in Top Attackers table has no onClick |
| FINDING-T1-A | CQA-T1 | RiskHeatmap receives 8 hardcoded JSX rows — no API |
| FINDING-T2-A | CQA-T2 | Drawer "Block IP", "Copy as cURL", "Whitelist" buttons all no-op |
| FINDING-T1-E | CQA-T1, T2 | RequestDetail: ASN, JA4, xff, request_id, chain_hash, sinks all hardcoded |
| FINDING-T7-A | CQA-T7 | PageTierConfig has zero mutation capability — no edit/save at all |
| FINDING-T9-B | CQA-T9 | "Add entry" button no-op on both Blacklist and Whitelist |
| FINDING-T9-C | CQA-T9 | No delete/edit per row on Blacklist/Whitelist |
| FINDING-T10-C | CQA-T10 | Individual cache "Flush" buttons have no onClick |
| FINDING-T10-B | CQA-T10 | Cache management card shows 6 hardcoded demo stats |
| FINDING-T14 | CQA-T14 | 8 fields in RequestDetail + RiskHeatmap + cache stats are hardcoded JSX values |

### MEDIUM

| ID | Slice | Description |
|---|---|---|
| FINDING-T3-A | CQA-T3 | `malicious.pct.toFixed(1)` crashes if `pct` field absent |
| FINDING-T5-A | CQA-T5 | No time-range filter UI on Audit Log page |
| FINDING-T5-B | CQA-T5 | No chain-verify action on Audit Log page |
| FINDING-T10-A | CQA-T10 | Risk threshold sliders not wired to `PUT /api/risk/thresholds` |
| FINDING-T11-A | CQA-T11 | `useAlertReceiversApi` calls `window.useApi` instead of local `useApi` |
| FINDING-T13-A | CQA-T13 | Notifications bell button no-op |
| FINDING-T13-C | CQA-T13 | Sidebar footer BUILD/UPTIME are hardcoded static strings |
| FINDING-T1-D | CQA-T1 | Time-window chips (1m/5m/15m/1h) are decorative |
| FINDING-T9-A | CQA-T9 | Blacklist/Whitelist use `e.expires_at`/`e.created_at` — check backend field names |
| FINDING-T12-A | CQA-T12 | No TopBar drain button (plan §1.2 mentions one) |

### LOW

| ID | Slice | Description |
|---|---|---|
| FINDING-T4-A | CQA-T4 | Latency/per-route cards are documented placeholders |
| FINDING-T6-A | CQA-T6 | Per-rule stats tab is a placeholder |
| FINDING-T6-B | CQA-T6 | Rule hits1h always shows 0 (adapter discards backend value) |
| FINDING-T8-A | CQA-T8 | No per-member drain control |
| FINDING-T14-orphan | CQA-T14 | `useLiveFeed` + `useTrafficSeries` (Math.random) still exported to window — should be removed |

---

## Notes on Live Verification Gaps

The following acceptance criteria from plan §2 could NOT be verified without a running server:

- §2.1 — All API calls return 200 with real data (not mock shapes)
- §2.3 — Every button produces visible feedback (toast / row change)
- §2.4 — Audit-chain entries visible within 2s after mutations
- §2.5 — CSRF gate: mutation without x-csrf-token returns 403
- §2.6 — `/api/config/version` increments after mutations
- §2.8 — No 4xx/5xx leaks in Network tab

These must be re-verified in a second pass with Bash/Playwright access and the WAF running.

---

## Definition of Done Status

- [x] All 14 slices have a row in the run report
- [ ] No slice marked Fail without an open ticket — **6 slices are FAIL; tickets needed for all**
- [x] Zero `Math.random()` in rendering paths (simulation helpers remain but are not called)
- [ ] Zero static-fixture fallbacks rendering anywhere — **FAIL: RequestDetail (8 fields), RiskHeatmap rows, cache card stats**
- [ ] All audit-mutated buttons round-trip through `/api/config/versions` — **unverified (no live run)**
- [ ] Run report committed under `tests/results/run-cqa-*` — **this file**
