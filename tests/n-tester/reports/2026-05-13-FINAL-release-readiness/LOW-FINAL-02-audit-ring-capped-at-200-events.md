---
id: 2026-05-13-audit-ring-capped-at-200-events
date: 2026-05-13T09:30Z
severity: LOW
area: admin-api · audit
component: audit ring / cold-tier export
status: documented-limitation
test_mode: full-qc
---

# Audit ring capped at 200 events — second Reports card title now honest, but "audit last 1000 events" feature gap remains

## Summary

`crates/aegis-control/src/api/audit.rs:108` documents
`DEFAULT_CAP = 200`. The Reports page's first card ("Audit
trail · last 200 events · full ring") now matches the cap — the
2026-05-12-admin LOW-ADM-02 fix already shipped this honesty.

The follow-up gap: there's no way to export a longer audit
window than the in-memory ring. The `/api/cold-tier` endpoint
exists as a placeholder (returns
`{"feature_present": false, "note": "cold-tier export not wired"}`).
This is a deferred limitation, not a regression.

## Repro

```bash
curl -s -b /tmp/jar 'http://127.0.0.1:9443/api/reports/audit.csv?limit=10000' | wc -l
# 201 lines (200 events + header)
# limit=10000 is silently clamped to the ring's cap
```

## Expected

For weekly compliance reviews (the audit chain's primary
use-case), operators want at least 7 days of audit retention.
That requires:
- A cold-tier persistent store (sqlite / parquet / etc.) that
  the audit ring spills into on overflow.
- An export endpoint that reads from the cold-tier.
- A date-range picker on the Reports page (per the ADM-P2
  proposal).

## Actual

In-memory ring only. Process restart loses the chain (which
contradicts the "tamper-evident audit" framing in the
contract).

## Suggested fix

Out of scope for any near-term sprint. Documented limitation.

Two design shapes to consider when this becomes priority:

1. **Append to disk** — every audit event line-appends to a
   JSONL file at `data/audit/chain-<date>.jsonl`. Cheap. No
   query primitive, but `grep` / `jq` work fine for export.

2. **Embedded sqlite** — `data/audit/chain.db` with one row per
   event. Adds `?from=<ts>&to=<ts>` query support to
   `/api/audit/since` and `/api/reports/audit.csv`. ~1 day +
   migration story.

Pick (1) for v1 if time-budget is small.

## Severity rationale

LOW + documented-limitation. The current shape is honest about
its cap (Reports card title says "full ring, last 200 events").
No operator surprise; no security issue (the audit chain is
still tamper-evident *within* the ring). Compliance teams
operating Aegis-Gate in regulated industries will hit this
limitation but the gap is clear in `Implement-Progress.md` and
the operator-facing copy.

