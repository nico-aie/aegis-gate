---
id: 2026-05-13-final-release-readiness-fix-plan
date: 2026-05-13
status: ready
source_report: tests/n-tester/reports/2026-05-13-FINAL-release-readiness/
prior_sprint: plans/issue-fix/2026-05-12-routing-upstreams-ux/README.md
verdict: SHIP IT (after Phase 1)
---

# Fix plan — 2026-05-13 FINAL release-readiness

## Headline

The release-readiness QC pass is **SHIP IT**:

```
0 CRITICAL · 0 HIGH · 0 MEDIUM · 2 LOW · 12 INFO
```

Every issue raised across the previous six sprints is closed.
SOC scenarios S1–S8 all score 5/5 (up from 1–3 on the first
run). Detector chain p99 = **0.88 ms** (beats the 1.03 ms
published baseline). 17/17 dashboard pages mount cleanly. 10/10
security regression battery green. Zero `console.error` over a
60-second idle.

Two LOW findings remain — one is a 5-line cleanup, the other is
a deferred-by-design persistence-layer limitation.

## Findings recap

| ID | Sev | Area | One-line |
|---|---|---|---|
| LOW-FINAL-01 | LOW | dashboard · incidents toast | Stale "lifecycle UI pending (server overlay not yet wired)" fallback copy at `pages.jsx:8273` — unreachable since MED-ADM-01 closed the round-trip |
| LOW-FINAL-02 | LOW | audit · cold-tier | Audit ring capped at 200 events; no long-window export. Deferred by design (cold-tier persistence is out of scope for any near-term sprint). |

## Root-cause analysis

### LOW-FINAL-01 — dead `else` branch in incidents toast

Verified by reading the code:

`crates/aegis-control/assets/dashboard/src/pages.jsx:8262-8276`:

```js
if (r && r.status >= 200 && r.status < 300) {
    const reflected = !!(incidents.data?.incidents || []).length;
    const tone = reflected ? 'ok' : 'warn';
    const msg = reflected
        ? `Incident ${action} ok`
        : `${action} recorded to audit chain · lifecycle UI pending (server overlay not yet wired)`;
    window.aegisToast(msg, tone);
    ...
}
```

This branch was introduced during the MED-SO-04 / MED-OBS-01
investigation when the server-side overlay write was broken.
Three sprints later:

- `e6b307c` — `alert_id` format alignment (Observability sprint)
- `cadd01b` — percent-decode incident path segments (Admin
  sprint)

…closed the round-trip end-to-end. The QA pass confirmed:
*"Verified by clicking Ack on row 1 in this run — toast read
'Incident ack ok' (the success path), not the fallback."*

The fallback branch fires only when `r.status` is 2xx but
`incidents.data?.incidents` is empty — which can't happen once
the server overlay reliably reflects the just-acked state. The
copy implies the overlay isn't wired (false) and confuses
operators reading the source.

**Fix.** Collapse the ternary. Keep the success copy; replace
the dead-branch copy with an honest "we got a 2xx but the
overlay didn't update — refresh to retry" message that mentions
the actual failure mode (overlay refetch race), not the
phantom-server-overlay one.

### LOW-FINAL-02 — audit ring capped at 200 events

Verified by reading the code:

- `crates/aegis-control/src/api/audit.rs:108` declares
  `DEFAULT_CAP = 200`.
- `/api/cold-tier` endpoint returns
  `{"feature_present": false, "note": "cold-tier export not wired"}`.
- The Reports card title already says "Audit trail (full ring ·
  last 200 events)" — the 2026-05-12-admin LOW-ADM-02 fix
  shipped the honest copy.

So the operator-visible surface is already honest. The
underlying limitation: process restart loses the chain
(contradicts the "tamper-evident audit" framing in the
contract). The QA report explicitly classifies this as
*deferred limitation, not a regression*.

**Fix.** Out of scope for this sprint. Document the limitation
explicitly in `plans/future/` so it's tracked alongside the
multi-node metrics aggregation plan, and add an explicit
"future" stub at the v1 cold-tier feature gate.

## Phases & ship order

### Phase 1 — LOW-FINAL-01 (dead `else` branch) ★ ship before release

Dashboard-only. ~5 min.

**Files**
- `crates/aegis-control/assets/dashboard/src/pages.jsx:8262-8276`:
  - Drop the `reflected` check (it was a stand-in for "did the
    overlay write reflect?", which is now always true after a
    2xx response).
  - Toast on 2xx → green "Incident <action> ok". The fallback
    path was only reachable when the server-side write
    succeeded but the read-back didn't surface state — a
    contract violation. With the round-trip closed, the
    surviving non-success path is the existing `else` block
    that handles status ≥ 300.
  - Optional: add a defensive read-modify check that toasts
    `warn` if `incidents.reload()` doesn't return the new
    state within 1 polling cycle — but that's a UX nicety, not
    a correctness fix. Defer.

**Verify**
- Rebundle.
- Manual: drive 3 alerts, click Ack on row 1 — toast reads
  "Incident ack ok" (green); next GET shows
  `status: acknowledged`. (Same flow QA already verified in
  the FINAL run.)
- `grep -n "lifecycle UI pending" crates/aegis-control/assets/dashboard/` returns no matches.

### Phase 2 — LOW-FINAL-02 (cold-tier audit limitation)

Documentation-only. ~15 min.

**Files**
- New file: `plans/future/audit-cold-tier-export.md` — design
  notes for the cold-tier audit feature. Two design shapes
  (JSONL append vs embedded sqlite per the QA report), trade-
  offs, and a v1 recommendation (JSONL append for cost-of-
  carry).
- Cross-link from `plans/future/README.md` if it exists; create
  if it doesn't.
- Optional: add a `// TODO(cold-tier):` comment in
  `crates/aegis-control/src/api/audit.rs` near `DEFAULT_CAP`
  pointing at the future plan.

**No code change.** This phase keeps the limitation in the
operator-visible knowledge graph instead of relying on a single
QC report capturing it.

### Phase 3 — deferred (not in scope here)

Items already deferred per their original plans, called out by
the FINAL QC for completeness:

| Item | Plan ref |
|---|---|
| Admin sessions DELETE handler | 2026-05-12-admin Phase 3 |
| Break-glass POST handler | 2026-05-12-admin Phase 3 |
| External integrations PUT handler | 2026-05-12-admin Phase 3 |
| Reports top-attackers.csv / compliance.json endpoints | 2026-05-12-admin Phase 3 |
| Challenge Engine CAPTCHA / Strict PoW rungs | 2026-05-11 fix plan §4.0.3 |
| Honeypot Paths runtime mutation | YAML-only today |
| Per-IP cumulative risk multi-node aggregation | `plans/future/multi-node-metrics-aggregation.md` |
| Audit cold-tier export | Phase 2 above |
| Routing & Upstreams UX proposals RU-P1..P8 | 2026-05-12-routing-upstreams-ux Phase 3 |
| Admin UX proposals ADM-P1..P8 | 2026-05-12-admin Phase 3 |
| Observability UX proposals OBS-P1..P8 | 2026-05-12-observability Phase 3 |
| Security Ops UX proposals (deferred 5 of 10 P-items) | 2026-05-12-security-ops Phase 3 |

## Risk register

- **Phase 1 might re-introduce a different failure mode.** The
  current `else` branch fires `warn` toast on a 2xx response —
  not a hard error, just operator confusion. After Phase 1 the
  same 2xx-but-empty-overlay path would silently render `ok`
  toast. If the overlay store ever regresses again (re-opening
  MED-ADM-01 class of bugs), operators wouldn't see the
  warning. Mitigation: the regression test
  `ack_then_enrich_returns_acknowledged_status` (`e6b307c`)
  guards against that exact class. As long as that test stays
  green, the fallback is dead code.

- **Phase 2 is documentation.** No risk.

## Out of scope

- All Phase 3 items above.
- Any feature work — six sprints is a wrap.

## Recommendation

Ship Phase 1 today (5-line cleanup, zero blast-radius). Phase 2
this week as a doc-only follow-up. Then **cut the release**.
The FINAL QC has already endorsed `SHIP IT` modulo this
polish.
