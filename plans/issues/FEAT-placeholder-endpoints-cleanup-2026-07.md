# FEAT — Placeholder endpoints: complete or remove

> **Type:** FEAT/chore (committee round-2 🔴3) · **Status:** ☐ Not started — planned 2026-07-04
> **Track ID prefix:** `PE-<1–3>` · Sweep verified 2026-07-04 against the full admin route table
> (`admin_dispatch.rs:59-617`, `admin_get.rs:111-1443`) + control plane (`interop/control.rs`).

**Objective (intent, not letter):** every auth-gated endpoint either does real work or does not
exist. No "coming soon" JSON behind a login, no dead registered routes, no fields that lie.

---

## 1. Verified inventory (the complete list — nothing else qualified)

| # | Endpoint | Today | Disposition (proposed) |
|---|---|---|---|
| 1 | `GET /api/threat-intel/feeds` (`admin_get.rs:620-627`) | Hardcoded `{"feeds":[],"configured_in_yaml":false,...}`; comment claims it reads `cfg.threat_intel` — **no such config field exists** | **REMOVE** endpoint + its dashboard tile. Re-add only when a real threat-intel feature ships. |
| 2 | `GET /api/gitops/status` (`admin_get.rs:1218` → `tracking.rs:535-541`) | Always `GitopsStatusResponse::placeholder()`; gitops module deleted | **REMOVE** endpoint, drop the gitops fold-in from `/api/tracking/snapshot` (`tracking.rs:594`), drop UI. |
| 3 | `GET /api/analytics/query` (`admin_get.rs:702-711` → `analytics.rs:140-186`) | 503 unconfigured; **empty shells even when `admin.prometheus_url` set** ("upstream-proxy call lands in a follow-up") | **COMPLETE** — implement the Prometheus proxy call (small, the plumbing + response types exist). Feeds the `security-analytics-and-reporting.md` track. If declined: honest 501 + hide UI. |
| 4 | `GET /api/audit/witness` (`admin_get.rs:679-681`) | Schema-only; HMAC sign/verify deleted (`witness.rs:1-22`); nothing ever calls `WitnessState::update` | **REMOVE** endpoint + UI. Real witness/anchoring is a `security-analytics` / audit-durability follow-up, not a stub. |
| 5 | `GET /api/cold-tier` (`admin_get.rs:984-988` → `logging.rs:60-90`) | Sink list real; `delivery:"unknown"` hardcoded per sink | **COMPLETE** — wire per-sink delivery counters (ok/error/last-success from the sink tasks). Cheap and genuinely useful ops signal. Fallback: drop the field. |
| 6 | `render_cert_renew` (`tracking.rs:623-631`) | Always `405`; **registered on no route** — dead code | **DELETE** function + its unit test. |
| 7 | `GET /api/geoip/status` (`admin_get.rs:634-660`) | Real except `indicator_count: 0` hardcoded (line 651) | **COMPLETE** (wire the real count) or drop the field. One-liner either way. |

**Verified NOT placeholders (leave alone):** copilot endpoints (real, honest 503 when `llm`
feature absent), the conditional `::placeholder()` fallbacks for `/api/slo|cluster|certs|alerts`
(live data when wired; empty only in single-node/test bundles), `/api/analytics/latency*`
`/route-activity` `/routes` (empty only when the window isn't installed), all `/__waf_control/*`
(real). Do not "fix" these.

## 2. Staging

### PE-1 — removals (#1, #2, #4, #6) · **S** · ✅ shipped 2026-07-04 (`feat/pe1-placeholder-removals`)
One PR. Endpoint + route registration + dashboard tile/panel per item, together (`[[project_dashboard_js_hook_safety]]`:
rebuild binary to see JSX changes; run the acorn hooks guard). Note removals in the response doc
for the committee ("removed unfinished surface" is an acceptable — and honest — resolution).

### PE-2 — completions (#3, #5, #7) · **S–M** · ✅ shipped 2026-07-04 (`feat/pe2-placeholder-completions`)
- #3 analytics/query: implement the Prometheus HTTP call (respect `admin.prometheus_url`,
  timeout, error → honest 502/503 envelope). Range + instant queries.
- #5 cold-tier: per-sink delivery status from sink task state (delivered/error counters + last
  success ts). Surfaces the audit-durability story from `FEAT-audit-coverage-gaps-2026-07.md`.
- #7 geoip: wire `indicator_count` from the loaded DB/country list.

### PE-3 — regression guard · **S** · ✅ shipped 2026-07-05 (`feat/au3-decay-caveats-pe3-guard`)
- `pe3_route_guard` tests in `admin_get.rs` (run in CI via `cargo test`): every `/api/*` route
  literal in the dispatch layer must appear in the documented surface (enterprise api.md /
  openapi / usage.md / ops docs) or the dashboard sources; banned-marker scan
  ("coming soon" / "ships in phase" / `placeholder()`) on the comment-stripped route layer.
  First run caught 4 real doc gaps (`/api/config/rollback`, 3 × zero-trust downstream) — fixed.

## 3. Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | Wire-format consumers (external scripts) hit removed endpoints | endpoints are admin-session-gated + undocumented externally; note in CHANGELOG; 404 is correct for removed |
| LOW | Dashboard blank-page from JSX edits | binary rebuild + `lint-hooks.mjs` guard + manual smoke of each touched page |
| LOW | #3 scope creep into full analytics tier | proxy call only; Tier-2 store stays in `security-analytics-and-reporting.md` |

## 4. Acceptance

- [ ] The 7 items dispositioned (removed or genuinely functional) — none returns static/lying data.
- [ ] Dashboard has no tile backed by a removed endpoint.
- [ ] Guard from PE-3 in CI.
- [ ] `plans/archive/unwired-stubs-catalog.md` staleness note updated to reference this sweep.
