---
id: 2026-05-12-admin-low-findings-bundle
date: 2026-05-12T08:32Z
severity: LOW
area: dashboard · admin-api
component: various
status: open
test_mode: full-qc
---

# LOW-severity findings (Admin polish)

## LOW-ADM-01 — Multiple "not yet wired" mutation handlers on Settings give operators a read-only UI for several surfaces

Several cards on Settings include "(audit-mutated DELETE / POST /
PUT handler not yet wired)" subtitle notes:

- **Active admin sessions**: "terminate via direct API
  (audit-mutated DELETE handler not yet wired)"
- **Break-glass**: "toggle via direct API (audit-mutated POST
  handler not yet wired)"
- **External integrations**: "edit via waf.yaml + restart
  (audit-mutated PUT handler not yet wired)"

Honest copy, but it leaves a SOC operator looking at the
dashboard with three surfaces they can't actually mutate from
the UI:
- Can't terminate a hostile session — has to find the session
  ID and DELETE via curl
- Can't enable break-glass during an incident — has to POST via
  curl, defeating the "break-glass during incident" UX
- Can't reconfigure Grafana/Alertmanager URLs without a config
  reload + restart

**Suggested fix:** ship these three mutation handlers. They're
the standard "small server endpoint + audit-mutated emit +
dashboard form wire-up" pattern; each is ~half a day.

Until they ship, the subtitle copy could surface a concrete
shell snippet (`curl -X DELETE -H 'x-csrf-token: <csrf>'
http://127.0.0.1:9443/api/admin/sessions/<id>`) so operators
don't have to read the source to figure out the API shape.

## LOW-ADM-02 — Reports "Audit trail (last 1000 events)" returns the same content as "(last 200 events)"

The audit ring is sized to 200 events (verified via the same
endpoint at `?limit=1000` returning the same 10910 bytes as
`?limit=200`). The "last 1000 events" card title is therefore
misleading — operators will assume they're getting a wider
window than they actually are.

```
GET /api/reports/audit.csv?limit=200   → 10910 bytes
GET /api/reports/audit.csv?limit=1000  → 10910 bytes (same)
```

**Suggested fix:** either expand the audit ring to support a
larger window for export, or change the card title to honestly
reflect the cap. Either:
- "Audit trail (last 200 events, full ring)" — honest about the
  cap
- "Audit trail (last 7 days, sourced from cold-tier)" — if the
  cold-tier `/api/cold-tier` is the path to larger exports

Currently the second card simply duplicates the first.

## LOW-ADM-03 — Reports mixes two different download patterns (Link href vs Button onClick blob)

The four export cards on Reports use two different download
mechanisms:

| Card | Element | Mechanism |
|---|---|---|
| Audit trail (200) | `<a href=".../api/reports/audit.csv?limit=200">` | Server endpoint |
| Audit trail (1000) | `<a href=".../api/reports/audit.csv?limit=1000">` | Server endpoint |
| Top attackers (7d) | `<button onClick={...}>` | Client-side Blob from `/api/attacks/top` |
| Compliance snapshot | `<button onClick={...}>` | Client-side Blob from `/api/config + /api/detectors` |

Direct probes of `/api/reports/top-attackers.csv` and
`/api/reports/compliance.json` both return 404. So those URLs
don't exist server-side — the buttons assemble the CSV/JSON
client-side from the same APIs the dashboard already uses.

Two issues:
1. **Inconsistent UI affordance.** The `<a>` link gets the
   browser's native "open or save" behaviour + download history;
   the `<button>` triggers a JS-controlled blob URL. Operators
   can't right-click the buttons to "Copy link" or "Save link as"
   — those work for the audit links but not the others.
2. **No server endpoint contract.** If a future caller (e.g. a
   nightly ops cron) wants to fetch the top-attackers CSV, there's
   no URL to hit — they'd have to assemble it from
   `/api/attacks/top` themselves.

**Suggested fix:** add the two missing server endpoints
(`/api/reports/top-attackers.csv` and
`/api/reports/compliance.json`) and convert the buttons to anchor
links with `href` pointing at them. Saves the JS code, makes
the operator experience consistent, and gives the contract a
stable URL.

## LOW-ADM-04 — Audit CSV header includes `method` + `path` but the values are empty for every detection row

```csv
seq,ts,class,action,client_ip,method,path,rule_id,reason,request_id
1,2026-05-12T08:26:03.424337Z,detection,block,5.195.235.51,,,,blocked by detectors: recon_path (score: 25),a5bdb494...
```

Method + path are blank even though the API source has them in
`event.fields.{method,path}`. Same issue as the previous-sprint
MED-SO-06 / LOW-OBS-04 patterns — different code path needs the
same `fields.method` / `fields.path` fallback.

**Suggested fix:** in
`crates/aegis-control/src/api/reports.rs` (or wherever the CSV
serializer lives), pull `fields.method` and `fields.path` instead
of the top-level fields (which are null for detection rows). Same
pattern that lit up the Investigation Audit timeline columns and
the Audit Trail RULE column.

## LOW-ADM-05 — Config history TIME column uses 12-hour AM/PM while the rest of the dashboard uses 24h or ISO

```
#62  May 12, 12:28:45 PM  INCIDENT_ACK
#61  May 12, 12:27:00 PM  INCIDENT_ACK
```

The Audit Trail page on this same install shows 24-hour `12:28:45`
without AM/PM. Settings → Config history uses `.toLocaleString()`
which renders AM/PM under en-US locale. Inconsistent.

Same root cause as previous-sprint LOW-OBS-05 (also un-fixed on
this run — Performance card subtitle still shows AM/PM,
Health & SLOs HEARTBEAT column shows `12:25:30 PM`). The fix
applied per the Observability plan was narrow ("only the
Block-ratio peak time"); a broader sweep across all `Date`
renders in `pages.jsx` would close the consistency.

**Suggested fix:** introduce a `formatTimestamp(d)` helper that
calls `d.toLocaleString(undefined, { hour12: false })` and use it
everywhere a wall-clock string appears.

## LOW-ADM-06 — Help & Guide "How it works" says "four binary short-circuits" but Traffic Gates page lists five items

The "Request flow" step 3 reads: *"Traffic gates — four binary
short-circuits fire in cheapest-first order before the detector
chain: access list, strike-block, rate limit, DDoS gate. All
four configurable from the Traffic Gates page; …"*

But the Traffic Gates page itself lists FIVE items: Access List,
Strike-Block, Cumulative IP risk thresholds, Rate Limit, DDoS
gate.

The discrepancy is technically right (cumulative IP risk
thresholds is a *tuner* not a *binary gate*) but the visual
numbering on the Traffic Gates page goes 1 → 5 with the
cumulative IP risk thresholds card labeled "3.", so an operator
reading "four gates" then opening the page and seeing "5." will
flag it as a doc bug.

**Suggested fix:** either:
- Update Help & Guide to say "five surfaces (four binary
  short-circuits + one IP-risk tuner)"
- Renumber the Traffic Gates page so the four binary gates are 1
  → 4 and the cumulative IP risk tuner is called out as a separate
  "tuner" panel

The first is the smaller diff.

