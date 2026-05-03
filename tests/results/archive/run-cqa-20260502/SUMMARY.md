# CQA — Final consolidated summary (2026-05-02)

> Combines the two parallel passes:
> - **(a) Live API + JSX-grep** (driven by the parent session) —
>   verified every read endpoint + CSRF gate + audit chain on a
>   running WAF.
> - **(b) Static source analysis** (delegated to the
>   `e2e-runner` agent) — read every page in `pages.jsx` line
>   by line and pinpointed dead `onClick`s and hardcoded JSX.

The two passes are complementary: (a) confirmed the **backend
is healthy** (41/41 read endpoints 200, CSRF 403/200, audit
+1 per mutation); (b) showed **the dashboard front end is
where the gaps live**.

## Headline

| Layer | Verdict |
|---|---|
| Backend (read APIs + CSRF + audit chain) | ✅ all green |
| Dashboard pages | **5 PASS / 3 PARTIAL / 6 FAIL** |
| Mock-data audit (`Math.random` + window fixtures) | Partial — random retired, but **3 hardcoded JSX clusters remain** |

## Per-slice verdict

| Slice | Page | Verdict | Top issue |
|---|---|---|---|
| CQA-T1 | Overview | ❌ FAIL | Block-button no-op, 8 hardcoded fields in RequestDetail, RiskHeatmap rows hardcoded |
| CQA-T2 | Live Feed | ❌ FAIL | 3 drawer action buttons no-op (Block IP / Copy cURL / Whitelist) |
| CQA-T3 | Attack Events | ⚠️ COND | `pct.toFixed(1)` crashes when field absent |
| CQA-T4 | Analytics | ✅ PASS | Latency / per-route are documented placeholders |
| CQA-T5 | Audit Log | ⚠️ PARTIAL | No time-range filter, no chain-verify button, pagination cap 200 |
| CQA-T6 | Rule Manager | ✅ PASS | Full CRUD + simulator wired correctly |
| CQA-T7 | Tier Config | ❌ FAIL | Page is read-only — detector-mask mutation not wired |
| CQA-T8 | Upstreams | ✅ PASS | Full CRUD + 409 route-ref guard |
| CQA-T9 | Blacklist + Whitelist | ❌ FAIL | "Add entry" no-op, no delete/edit per row |
| CQA-T10 | Settings | ⚠️ PARTIAL | Rollback + SAN allowlist great; risk-threshold sliders + cache flush still no-op |
| CQA-T11 | Tracking | ✅ PASS | Alert receiver CRUD + test wired |
| CQA-T12 | Scaling | ✅ PASS | All 3 layers live; drain confirm + CSRF correct |
| CQA-T13 | Cross-cutting | ❌ FAIL | **No logout button** anywhere; sidebar BUILD/UPTIME hardcoded; notifications bell no-op |
| CQA-T14 | Mock-data audit | ❌ FAIL | `Math.random` retired ✅; window fixtures not used ✅; **but RequestDetail / RiskHeatmap / cache stats remain hardcoded JSX** |

Detailed per-slice findings: `per-slice/CQA-T<n>-*.md`.

## Aggregate sprint backlog

### Critical / High (Round-1 risk if shown to OC)

| ID | Where | Fix |
|---|---|---|
| **F-T13-LOGOUT** | TopBar | Add logout button → `POST /admin/logout`; wire alongside the existing session pill |
| **F-T9-CRUD** | Blacklist + Whitelist | Wire "Add entry" + per-row Delete on `ListPage` (uses already-existing audit-mutated endpoints if present, otherwise add them) |
| **F-T7-MASK** | Tier Config | Add Edit / Save UI on `PageTierConfig`; calls already-shipped `PUT /api/detectors` |
| **F-T1-NOOP** | Overview Top Attackers | Wire "Block" → `POST /api/blacklist` |
| **F-T2-DRAWER** | Live Feed drawer | Wire "Block IP" / "Copy as cURL" (clipboard) / "Whitelist" (calls `POST /api/whitelist`) |
| **F-T1-DETAIL** | Overview + Live Feed `RequestDetail` | Replace 8 hardcoded fields with live values from `/api/audit/since` lookup by `request_id` |
| **F-T1-HEAT** | Overview RiskHeatmap | Replace hardcoded row JSX with `/api/attacks/by-detector` or new `/api/risk/heatmap` |
| **F-T10-CACHE** | Settings cache card | Either remove the card or wire the flush buttons + show real cache stats |

### Medium (worth fixing before Round-1; visible polish)

| ID | Where | Fix |
|---|---|---|
| **F-T10-RISK** | Settings risk-threshold sliders | Wire to `PUT /api/risk/thresholds` (endpoint already shipped — UI just doesn't call it yet) |
| **F-T13-BELL** | TopBar notifications bell | Either remove or wire to `/api/alerts` |
| **F-T13-FOOTER** | Sidebar footer | Replace hardcoded BUILD / UPTIME with `/api/about` values |
| **F-T5-FILTER** | Audit Log | Add time-range filter UI |
| **F-T5-VERIFY** | Audit Log | Add chain-verify button |
| **F-T5-LOAD** | Audit Log | Replace hard 200-row cap with paginated load-more |
| **F-T3-NPE** | Attack Events | Defensive `.toFixed(1)` against missing `pct` |
| **F-T11-SMELL** | Tracking | `useAlertReceiversApi` should call local `useApi`, not `window.useApi` |
| **F-T12-DRAIN** | TopBar | Add a drain button (plan §1.2 mentions one) |

### Low (dust; not Round-1 blocking)

| ID | Where | Fix |
|---|---|---|
| F-T4-PLACEHOLDER | Analytics | Wire latency/per-route once Prometheus aggregator lands |
| F-T6-STATS | Rule Manager per-rule stats tab | Placeholder; wire after a per-rule hit counter exists |
| F-T6-HITS1H | Rule Manager rules table | Adapter discards backend `hits1h` value; preserve it |
| F-T8-MEMBER-DRAIN | Upstreams | Per-member drain control |
| F-T14-EXPORTS | data.jsx | Stop exporting `useLiveFeed` + `useTrafficSeries` (they still use Math.random for sim) |

## Backend status (no changes needed)

The live verification (`run-cqa-20260502-api/findings/`)
confirms:

- ✅ 41 / 41 read endpoints return 200
- ✅ CSRF gate: 403 without, 200 with
- ✅ `/api/config/version` increments by 1 per mutation
- ✅ Audit chain captures every mutation (verified with `mode_set`)

**Every issue in this report is a front-end fix or a trivial
defensive guard.** Backend is solid.

## Replan — proposed sprint shape

A two-day sprint clears the entire HIGH bucket. Suggested
order (lowest-risk → highest-value):

### Day 1 — Frontend mutation wiring (~4 hours)
1. **F-T9-CRUD** — Blacklist + Whitelist add/delete wired
2. **F-T7-MASK** — Tier Config Edit/Save form
3. **F-T10-RISK** — Risk-threshold sliders → PUT
4. **F-T13-LOGOUT** — TopBar logout button
5. **F-T13-FOOTER** — Sidebar footer wired

### Day 2 — Replace hardcoded JSX clusters (~3 hours)
6. **F-T1-DETAIL** — RequestDetail backed by `/api/audit/since`
7. **F-T1-HEAT** — RiskHeatmap backed by an API (existing or new)
8. **F-T10-CACHE** — decide: remove card OR wire it
9. **F-T1-NOOP / F-T2-DRAWER** — Overview + Live Feed action buttons
10. **F-T13-BELL** — notifications bell (decision: remove vs wire)

### Cleanup pass (~1 hour)
11. F-T3-NPE / F-T5-* / F-T11-SMELL / F-T12-DRAIN
12. F-T6-HITS1H, F-T14-EXPORTS

After the sprint, a second CQA pass (CQA round-2) re-runs both
(a) live + (b) source to flip every Fail / Partial → Pass.

## Files

| File | Source |
|---|---|
| `README.md` | e2e-runner agent — source-only verdict table |
| `per-slice/*.md` | e2e-runner agent — one file per slice |
| `../run-cqa-20260502-api/findings/read-endpoints.md` | parent session — 41-row HTTP probe |
| `../run-cqa-20260502-api/findings/live-verification.md` | parent session — CSRF / version-increment / audit-chain proofs |
| **this file** | merged conclusion + sprint plan |
