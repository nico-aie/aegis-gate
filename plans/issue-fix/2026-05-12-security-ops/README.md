# Fix plan — 2026-05-12 Security Ops QA

> **Status:** Drafted 2026-05-12, awaiting confirmation.
> **Input:** `tests/n-tester/reports/2026-05-12-security-ops/`
> (run summary + HIGH-SO-01 + MED-SO-02..06 + LOW bundle +
> INFO bundle + 10 UX proposals).
> **QA verdict:** 0 CRITICAL · 1 HIGH · 5 MEDIUM · 4 LOW · 6 INFO ·
> 10 UX proposals. Previous-sprint verification: all 5 batches from
> `plans/issue-fix/2026-05-11-policy-and-dns-verification` confirmed
> shipped + operational.

## TL;DR — what hurts most

**HIGH-SO-01** breaks the SOC's primary incident-response workflow:
the operator clicks Block on a Top Attackers row (or the Live Feed
drawer, or the Overview preview), gets a confirm prompt, sees a
toast, but the POST body is missing `bypass: []` and the server
rejects it with 400. Three surfaces, one root cause. Trivial
dashboard fix — ship in next dashboard rebuild.

**MED-SO-04** is the next worst — Ack POST returns 200, toast says
success, but the lifecycle UI doesn't transition because the
server has no "incidents overlay" store. The audit chain captures
the ack; the page state machine doesn't see it. Server-side work.

Everything else is column-mapping bugs (MED-SO-03, MED-SO-05,
MED-SO-06) or a misnamed-filter bug (MED-SO-02) — all
dashboard-only.

## Phase 0 — HIGH-SO-01 (urgent, ship first)

**Scope.** Three call sites in `pages.jsx` post to
`/api/blacklist` without a `bypass` field. The server's
`AccessListEntry` deserializer rejects missing fields with 400.

**Fix shape (dashboard-side, ~30 LoC total):**

```js
// applies to TopAttackers Block button, Live Feed drawer
// "Block IP" button, Overview preview Block chip
const body = {
  id: `top-${identifier.replace(/[^\w.:-]/g, '-')}`,
  kind: identifier.includes('/') ? 'cidr' : 'ip',
  value: identifier,
  note: `Blocked from <surface> · risk ${risk}`,
  bypass: [],                             // ← the missing line
  created_at: new Date().toISOString(),
};
```

Three identical edits in `crates/aegis-control/assets/dashboard/
src/pages.jsx`.

**Belt-and-braces server-side relaxation (queued separately).**
Make `bypass` optional in the deserializer so future callers
don't trip the same wire:

```rust
#[serde(default)]
pub bypass: Vec<String>,
```

This is one line in `crates/aegis-control/src/api/blacklist.rs::
AccessListEntry`. Ship after the dashboard fix unblocks operators
today — the dashboard fix is the urgent bit; the server relax is
hygiene for the contract.

**Effort:** ~30 min dashboard + ~15 min server + ~30 min tests.

## Phase 1 — MEDIUM fixes (5 findings, ~1.5 days)

Bundle into one or two dashboard PRs + one server PR (MED-SO-04).

### MED-SO-02 — Investigation pivot doesn't actually filter

The four KPI cards + Audit timeline read raw `/api/audit/since`
without pivot filter. The "Attacker context" card does honor the
pivot, so the page half-works.

**Fix (option A — client-side filter, ships today).** In the
Investigation page component, after fetching the audit events,
filter by the pivot before rendering. Reuses the
`extractResourceId(event)` helper from MED-01 in the previous
sprint so `rule_id` pivots match events where the rule lives in
`fields.resource` / `fields.diff`. ~20 LoC.

**Fix (option B — server-side filter, next sprint).** Add
`?client_ip=<>` / `?request_id=<>` / `?rule_id=<>` query params
to `/api/audit/since`. Dashboard drops the client-side filter.
Lets the page work past the 200-event ring overflow. Estimated
~3 h server + ~30 min dashboard.

**Recommendation:** ship **A** in this Phase 1; file **B** as the
follow-up (it's also SO-P3 in the UX proposals, same fix at a
higher polish level).

### MED-SO-03 — Incidents table columns (SLI / FIRED / BUDGET / ACKED BY / NOTE) show placeholders

API gives `name`, `severity`, `since`, `runbook_url`. Dashboard
shows `unknown` / `—` for all of them.

**Fix.** ~30 LoC in the Incidents row renderer:

```js
function sliFromAlertName(name) {
  // "DataPlaneAvailability-1h" → { sli, window }
  const m = /^(.+)-([0-9]+[hm])$/.exec(name);
  return m ? { sli: m[1], window: m[2] } : { sli: name, window: '' };
}
// SLI cell: <sli> + <Chip>{window}</Chip>
// FIRED cell: formatRelative(alert.since) with title=absolute
// BUDGET: compute_budget(alert) or '—' fallback
// ACKED BY / NOTE: from the (currently empty) /api/incidents.incidents
//   overlay — wired but lights up once MED-SO-04 lands.
```

`formatRelative` already exists in `widgets.jsx` (used by the
alert-channels card). Reuse it.

### MED-SO-04 — Incident Ack ok but no lifecycle reflection

Server-side gap. The ack handler writes to the audit chain but
no "incidents overlay" store records the new state, so
`/api/incidents.incidents` stays `[]`.

**Fix shape.**

1. **Server-side overlay store** in `crates/aegis-control/src/
   api/incidents.rs`:
   - `IncidentOverlay { acked_by, acked_at, snoozed_until,
     resolved_at, note }` keyed by `alert_name`
   - In-memory + audit-chained, mirroring the
     `AccessListStore` overlay pattern
   - Three mutation handlers: `ack` / `snooze` / `resolve`
     write to the overlay AND the audit chain
2. **`/api/incidents` GET** joins `raw_alerts.firing` with the
   overlay by name and returns the combined shape:
   ```json
   {
     "alert_name": "DataPlaneAvailability-1h",
     "state": "acknowledged",
     "acked_by": "admin",
     "acked_at": "2026-05-12T00:14:00Z",
     "note": null
   }
   ```
3. **Dashboard** is already wired to read `incidents` from this
   shape — once the API surfaces the overlay rows, the page
   lights up automatically. No JSX changes required.

**Effort:** ~1 day server (store + 3 handlers + tests) + ~0
dashboard. **Recommendation:** ship as its own focused PR.

**Stop-gap until A lands:** change the toast copy from "Incident
ack ok" (claim of success) to "Ack recorded to audit chain
(lifecycle UI pending)". Avoids the green-toast-on-no-op
confusion. ~5 min dashboard.

### MED-SO-05 — Investigation Detector breakdown reports 0

Card reads from the wrong endpoint (or filters its response to
nothing). The Overview's identical card uses
`/api/attacks/by-detector?window=3600` correctly.

**Fix.** Point the Investigation card at the same endpoint
(`/api/attacks/by-detector`). If the card is meant to filter by
pivot, update the empty-state copy to "No detections in the last
1h for `<pivot>`" so the operator can tell "card is broken" from
"card is empty by design". ~10 LoC.

### MED-SO-06 — Investigation audit-timeline METHOD/PATH/RULE_ID empty

Same data path Live Feed uses (`/api/audit/since`), same fields
(`event.fields.{method, path}`, `event.rule_id` /
`event.fields.detectors[]`). Investigation reads placeholder
fields.

**Fix.** Wire the cells to the actual field paths:

```js
const method = event.fields?.method || '—';
const path   = event.fields?.path || '/';
const ruleId = extractResourceId(event)
            || event.fields?.detectors?.join(',')
            || '—';
```

Gate the placeholders on `event.class === 'detection'` so
non-request events (`rule_create`, `pool_upsert`) still render
sensibly. ~15 LoC.

## Phase 2 — LOW polish bundle (~1 h, single dashboard PR)

| ID | Fix |
|---|---|
| **LOW-SO-01** | Chart subtitle template — `${window} window · ${bucketSize} buckets` instead of hard-coded "Realtime · 60s window · 1s buckets". ~5 LoC. |
| **LOW-SO-02** | Add `#/live-feed` as an alias for `#/live` in the router. ~3 LoC. Audit other "compact route name vs. sidebar long name" pairs while we're there. |
| **LOW-SO-03** | Top Attackers IP column: either make the underlined IP click pivot to Investigation (preferred — saves a click) or drop the underline. Preferred fix is ~10 LoC. |
| **LOW-SO-04** | Bot classifier empty-state copy. Quick code read to determine which of the three causes (recon-positive only / missing DB / wired-but-not-read) is true; update the empty-state copy to match. ~15 min investigation + ~10 LoC copy. |

## Phase 3 — UX proposals (triage)

10 proposals; recommended split:

### Phase 3a (immediate, bundled with bug fixes)

These are dashboard-only, small, and operator-impactful:

| # | Proposal | Effort | Why now |
|---|---|---|---|
| **SO-P1** | Sec Ops posture cheat-card across 5 pages | S | Mirrors the Policy posture pattern (INFO-SO-06 explicitly calls it a win); operator orientation drops from ~10s to ~2s |
| **SO-P3** | Real Investigation pivot filter | M | Closes MED-SO-02 properly with the server-side filter option |
| **SO-P5** | Incidents lifecycle overlay | M | Closes MED-SO-04 properly |
| **SO-P8** | Live Feed keyboard shortcuts (J/K/P/B/W/Esc/`/`) | S | Power-user 3-4× speed-up on triage |
| **SO-P10** | Incidents "Suggested action" column | S | Cuts SOC onboarding tax; copy lives in `cfg.alerts` |

### Phase 3b (deferred — needs design or backend)

| # | Proposal | Reason to defer |
|---|---|---|
| **SO-P2** | Live Feed pin-an-attacker | Needs a focused UX prototype before commit; medium-high impact when it lands |
| **SO-P6** | Map 5m retention + scrubber | Backend has the per-IP ring; UI scrubber needs design |
| **SO-P4** | Top Attackers per-IP mini-sparkline | Reuses Phase 3b's `RouteActivityWindow` pattern keyed by IP — backend extension |
| **SO-P7** | Audit timeline payload excerpts | Audit emitter needs to ship the excerpt; redaction policy decision |
| **SO-P9** | Top Attackers AS-level grouping | Needs `/api/attacks/top-by-asn` endpoint + CIDR-block-from-ASN resolution |

## Suggested PR sequence

1. **PR-HIGH** — Phase 0 dashboard fix for HIGH-SO-01 (`bypass: []`
   on three Block call sites) + server-side `#[serde(default)]`
   relaxation. ~1 h. Independent.
2. **PR-MED-DASH** — Phase 1 dashboard-only fixes (MED-SO-02
   client-side filter, MED-SO-03 column mapping, MED-SO-05
   endpoint, MED-SO-06 column mapping). Also the MED-SO-04
   toast-copy stop-gap. ~4 h.
3. **PR-MED-SRV** — Phase 1 server-side: incidents overlay store
   + 3 handlers + `/api/incidents` GET join (MED-SO-04 proper).
   ~1 day. Closes SO-P5 by the same hand.
4. **PR-LOW** — Phase 2 polish bundle. ~1 h.
5. **PR-UX-A1** — SO-P1 Sec Ops posture cheat-card across 5
   pages. ~2 h.
6. **PR-UX-A2** — SO-P3 server-side pivot filter on
   `/api/audit/since` (closes the MED-SO-02 follow-up; SO-P3 is
   the same work). ~3 h server + 30 min dashboard.
7. **PR-UX-A3** — SO-P8 keyboard shortcuts + SO-P10 suggested-
   action column. ~3 h.
8. **PR-UX-B** — Phase 3b items each get their own focused PR
   after design discussion.

## Decisions to lock in before starting

1. **HIGH-SO-01 fix surface.** Dashboard-side only (ship today)
   vs. dashboard + server-side schema relaxation (recommended,
   both small)?
2. **MED-SO-02 fix shape.** Client-side filter now (ships today)
   vs. wait for the server-side `?client_ip=` query param
   (Phase 3a SO-P3)?
   - **Recommendation:** ship both. Client-side filter is the
     same 20 LoC operator unblocker; the server-side filter
     ships next sprint and the dashboard switches over without
     a visible operator change.
3. **MED-SO-04 stop-gap.** Change the toast copy in the
   dashboard PR (while the server overlay store ships
   separately), or hold the change until the proper fix is
   ready and ship them together?
   - **Recommendation:** ship the toast-copy stop-gap now — the
     green-toast-on-no-op is operator-misleading, the corrected
     copy is honest until the overlay lands.
4. **Phase 3a scope.** SO-P1 + SO-P3 + SO-P5 + SO-P8 + SO-P10,
   or trim?

## Effort summary

| Phase | Effort | Operator-visible impact |
|---|---|---|
| 0 — HIGH-SO-01 | ~1 h | Primary SOC "block this attacker" workflow unblocked end-to-end |
| 1 — MEDIUM (dashboard) | ~4 h | Investigation pivot actually filters; Incidents columns light up; detector breakdown not always-zero; METHOD/PATH/RULE_ID render |
| 1 — MEDIUM (server, MED-SO-04) | ~1 day | Incidents lifecycle becomes a real state machine; Ack/Snooze/Resolve work end-to-end |
| 2 — LOW | ~1 h | Chart subtitle accurate; `#/live-feed` works; IP links pivot; bot-mix copy honest |
| 3a — UX (immediate) | ~8 h | Sec Ops posture card on 5 pages; server-side pivot filter; keyboard shortcuts; suggested-action column |
| 3b — UX (deferred) | TBD | Pin-an-attacker, map scrubber, sparkline, payload excerpts, AS grouping |

**Total verified-bug effort (Phases 0 + 1 + 2):** ~10 h
(~1 h urgent + ~5 h dashboard + ~1 day server).
With Phase 3a: ~18 h. Phase 3b TBD.

## What this plan does NOT change

- **The audit chain.** It's already correct end-to-end —
  INFO-SO-05 confirmed the chain captures the ack mutation even
  though the lifecycle UI doesn't reflect it.
- **Top Attackers + Investigation pivot URLs.** INFO-SO-03 calls
  out that the navigation + URL design are right; the wart is
  the filter wiring, not the URL contract.
- **The Live Feed drawer.** INFO-SO-02 calls it "excellent"; the
  only fix touching it is the `Block IP` button POST body
  (HIGH-SO-01).
- **The Overview map.** INFO-SO-01 calls it "the single best
  operator-orientation surface in the product". Phase 3b's P6
  proposes extending its retention window; not a fix.

## Out of scope (intentionally)

- Re-running the QA harness — operators do that after PRs ship.
- Audit-chain schema changes — every MED fix uses the existing
  event shape; the only emitter change is for SO-P7 (payload
  excerpts) which is deferred.
- New SLO definitions — MED-SO-03 reads existing alert names.
- Cross-page navigation refactors beyond the `#/live-feed`
  alias.
