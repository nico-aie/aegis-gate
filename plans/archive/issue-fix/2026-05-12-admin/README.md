---
id: 2026-05-12-admin-fix-plan
date: 2026-05-12
status: ready
source_report: tests/n-tester/reports/2026-05-12-admin/
prior_sprint: plans/issue-fix/2026-05-12-observability/README.md
---

# Fix plan — 2026-05-12 Admin pages QC findings

## Headline

The Observability sprint's MED-OBS-01 was **only partially fixed**:
the `alert_id()` format alignment landed correctly (commit
`e6b307c`) but a second, latent URL-encoding bug masquerades as
the same operator-visible failure mode. The admin-dispatch layer
passes the raw URL-encoded path segment (`%3A`) as the overlay
key, so the ack handler writes `"DataPlaneAvailability-1h%3A<ts>"`
while `enrich()` looks up `"DataPlaneAvailability-1h:<ts>"` —
they still don't match.

This is the same MEDIUM bug, third sprint in a row, with a
different cause each time. The fix is a 2-line change in the
dispatcher + a test that exercises the **HTTP layer** (not just
the `IncidentTracker` unit) so we don't ship a third partial.

Plus six small LOW polish items.

## Findings recap

| ID | Sev | Area | One-line |
|---|---|---|---|
| MED-ADM-01 | MEDIUM | admin-api · incidents | Ack overlay still doesn't round-trip — dispatcher doesn't URL-decode the path segment, so `%3A` ≠ `:` between write and read |
| LOW-ADM-01 | LOW | settings | Three "not yet wired" mutation handlers (sessions DELETE, break-glass POST, integrations PUT) — copy honest but operator can't act |
| LOW-ADM-02 | LOW | reports | "Audit trail last 1000 events" returns same payload as "last 200" — ring is capped at 200 |
| LOW-ADM-03 | LOW | reports | Two cards use server-URL `<a>` href; two cards use client-side Blob `onClick` — inconsistent affordance + missing server endpoints |
| LOW-ADM-04 | LOW | reports · audit.csv | CSV header carries `method` + `path` but values empty on every detection row (same MED-SO-06 fallback gap) |
| LOW-ADM-05 | LOW | settings · audit-trail | Config history TIME column uses 12h AM/PM while rest of dashboard uses 24h |
| LOW-ADM-06 | LOW | help & guide | "How it works" says "four binary short-circuits" but Traffic Gates page lists 5 numbered items |

## Verified-fine (from previous sprint)

- **LOW-OBS-02** `#/health-slos` alias — ✅ resolves.
- **LOW-OBS-04** Audit Trail RULE column — ✅ detection rows show
  the detector class.
- **MED-OBS-01** alert_id format alignment — ⚠️ landed at the
  string level (verified via API probe) but doesn't close the
  round-trip because of LOW-ADM-01's URL-decode gap.

## Root-cause analysis

### MED-ADM-01 — URL-encoded id reaches the overlay store as-is

Verified by reading the code:

- `crates/aegis-proxy/src/admin_dispatch.rs:177-194` — the
  incidents-mutation router:
  ```rust
  if path.starts_with("/api/incidents/") {
      let suffix = &path["/api/incidents/".len()..];
      if let Some(id) = suffix.strip_suffix("/ack") {
          if !id.is_empty() && !id.contains('/') {
              return handle_incident_ack(req, id, services).await;
          }
      }
      // … same shape for /snooze and /resolve
  }
  ```
  `path` is `req.uri().path()` — **percent-encoded**. So `id` is
  literally `"DataPlaneAvailability-1h%3A1778574385"`.
- `crates/aegis-proxy/src/admin_mutate.rs:1184` (incident_ack
  handler) passes `&alert_id_owned` (= the raw `%3A`-encoded id)
  to `incidents.ack(...)`.
- `crates/aegis-control/src/api/incidents.rs:94` writes to the
  overlay store under that key.
- `crates/aegis-control/src/api/incidents.rs:153` (enrich) calls
  `alert_id(&a)` → returns `"DataPlaneAvailability-1h:<ts>"`
  (literal `:`).
- Lookup miss → overlay never surfaces.

**Why the previous regression test passed.** Phase 1's
`ack_then_enrich_returns_acknowledged_status` exercised
`IncidentTracker::ack(&id, ...)` directly with the value
`alert_id(&a)` returns — i.e. the already-decoded form. It never
ran the HTTP path that introduces the `%3A`. Three sprints of
fixing this bug have all stopped one layer above the actual
mismatch.

**Fix.** URL-decode the path segment in the dispatcher before
handing it to the handler. The `percent_decode` helper added in
PR-UX-A2 already does this; make it crate-public and use it
here:

```rust
// admin_dispatch.rs around line 177
if path.starts_with("/api/incidents/") {
    let suffix = &path["/api/incidents/".len()..];
    if let Some(raw_id) = suffix.strip_suffix("/ack") {
        if !raw_id.is_empty() && !raw_id.contains('/') {
            let id = crate::admin_get::percent_decode(raw_id);
            return handle_incident_ack(req, &id, services).await;
        }
    }
    // … same for /snooze and /resolve
}
```

**Regression test that exercises the right layer.** Phase 1's
unit test stays. Add an integration-shaped test that simulates
the dispatcher's decode + writes via the encoded path and reads
back via the decoded key. The test must use the URL form the
dashboard actually sends.

### LOW-ADM-02 — Audit ring capped at 200 events

Verified: `crates/aegis-control/src/api/audit.rs:108` documents
`DEFAULT_CAP = 200`. The `/api/reports/audit.csv` handler at
`admin_get.rs:199-232` calls `services.audit.render_since(0,
limit)` which clamps via the ring's `since(cursor, limit)` —
limit doesn't grow the ring, it only requests up to that many
events.

**Fix.** Rename the second Reports card to honestly reflect the
ring cap. Adding a wider ring is out of scope (would require
tiered storage). Card title becomes "Audit trail (full ring,
last 200 events)" with subtitle copy explaining the cap and
where to find historical data.

### LOW-ADM-04 — Audit CSV method+path empty

Same pattern as MED-SO-06 / LOW-OBS-04 but in
`crates/aegis-proxy/src/admin_get.rs:204-224`. The CSV serializer
pulls `getter("method")` / `getter("path")` from the top-level
event object — those are null for detection rows. The actual
values live under `event.fields.{method,path}`.

**Fix.** Same fallback: try the top-level, then fall through to
`event.fields.method` / `event.fields.path`.

### LOW-ADM-05 — Mixed 12h/AM-PM time format

Same root cause as previous-sprint LOW-OBS-05, only the
Block-ratio peak time got the targeted fix. The QA recommends a
project-wide `formatTimestamp(d)` helper.

**Fix.** Introduce `fmtClockTime(d)` and `fmtAbsoluteTimestamp(d)`
helpers in `pages.jsx` (top of file, near the existing `fmtTs`
helper). Audit the file for `toLocaleTimeString` / `toLocaleString`
calls; replace those that render dashboard timestamps with the
new helpers. Skip `last_seen` / `last_heartbeat` style fields
that already use 24h-by-default in the locales we care about
(they're locale-dependent but consistent within a session).

Target the two QA-flagged sites at minimum:
- Config history TIME column (Settings)
- Performance card subtitle (already done in LOW-OBS-05 — verify
  no regression)
- Health & SLOs HEARTBEAT column

### LOW-ADM-01 / LOW-ADM-03 / LOW-ADM-06 — copy + endpoint gaps

- **LOW-ADM-01**: "not yet wired" cards. Out of scope for this
  sprint (each handler is ~half a day). Document as deferred in
  the plan. Surface a concrete `curl` snippet in the subtitle
  copy so operators have a path during the gap.
- **LOW-ADM-03**: inconsistent download affordance. Same shape:
  add `/api/reports/top-attackers.csv` and
  `/api/reports/compliance.json` server endpoints, convert
  buttons to anchor links. Larger than Phase 2 budget — defer
  to a follow-up PR.
- **LOW-ADM-06**: Help & Guide "four binary short-circuits" copy.
  One-line fix: "five surfaces (four binary short-circuits + one
  IP-risk tuner)" — keeps the existing 1→5 numbering on Traffic
  Gates.

## Phases & ship order

### Phase 1 — MED-ADM-01 (URL-decode in dispatcher) ★ ship first

Server-only. ~30 min including tests.

**Files**
- `crates/aegis-proxy/src/admin_get.rs` — make `percent_decode`
  visible to other modules in the crate (`pub(crate) fn`).
- `crates/aegis-proxy/src/admin_dispatch.rs` — call `percent_decode`
  on the incident id before passing to the handler. Apply to all
  three lifecycle paths (`/ack`, `/snooze`, `/resolve`). Do the
  same for the alert-ack path at line 165 (`/api/alerts/{id}/ack`)
  in case it has the same shape.
- `crates/aegis-control/src/api/incidents.rs` — extend tests with
  a layer-aware regression test that simulates an encoded id
  passed in (e.g. `ack_accepts_decoded_id_after_url_decode`).

**Verify**
- `cargo test -p aegis-control --lib -- api::incidents`
- `cargo test -p aegis-proxy --lib` (if dispatcher has tests).
- Manual: drive 3 alerts, click Ack on row 1, refresh — row
  transitions to ACKED.

### Phase 2 — LOW polish bundle ★ ship together

Mix of dashboard + small server. ~1.5h total.

**LOW-ADM-02 — Reports card title is honest**
- `crates/aegis-control/assets/dashboard/src/pages.jsx::PageReports`
  card 2 title and subtitle.

**LOW-ADM-04 — audit.csv method+path fallback**
- `crates/aegis-proxy/src/admin_get.rs::audit.csv` handler:
  prefer `event.fields.method` over `event.method`; same for
  `path`. Add a unit test if the CSV renderer has one.

**LOW-ADM-05 — Time format consistency**
- `crates/aegis-control/assets/dashboard/src/pages.jsx`: add
  `fmtClockTime(d)` + `fmtAbsoluteTimestamp(d)` helpers; replace
  Settings Config history + Health & SLOs HEARTBEAT call sites.

**LOW-ADM-06 — Help & Guide copy fix**
- `crates/aegis-control/assets/dashboard/src/help.jsx`: "How it
  works" → "Request flow" → step 3: rewrite "four binary
  short-circuits" to "five surfaces (four binary short-circuits
  + one IP-risk tuner)".

**Verify**
- Rebundle, navigate to Reports → card 2 title reflects ring cap;
  download `audit.csv` → method/path columns populated; Settings
  Config history → 24h; Help → "How it works" reads consistently
  with Traffic Gates.

### Phase 3 — Deferred (next sprint)

- LOW-ADM-01: ship the three missing mutation handlers (sessions
  DELETE, break-glass POST, integrations PUT). ~1 day.
- LOW-ADM-03: add `/api/reports/top-attackers.csv` +
  `/api/reports/compliance.json` server endpoints; convert
  dashboard buttons to anchors. ~half a day.
- ADM-P1..P8 UX proposals (priority order in the QA report's
  UX-PROPOSALS-admin.md): each its own PR.

## Risk register

- **URL-decode might over-decode.** `percent_decode` is the
  minimal `%XX` → byte mapper added in PR-UX-A2. It leaves `+`
  alone (correct for query strings; correct here too — path
  segments don't use `+` for space). Confirm no path segment we
  care about contains a literal `%` that isn't a percent escape.
  None do today; the only IDs in `/api/incidents/{id}/` are
  `alert_id()` output which is `<SliKind>-<Nh>:<ts>` (no `%`).
- **Hyper URI path semantics.** `req.uri().path()` returns the
  percent-encoded form, so the decode is correct exactly once at
  the dispatch layer. Don't apply decode again inside the
  handlers — that would double-decode any `%25` (escaped `%`).
- **LOW-ADM-05 time helper rollout.** The QA recommends a
  project-wide sweep. Scope this fix to the two flagged sites +
  the Block-ratio peak time (already done). A broader sweep
  belongs in a follow-up.

## Out of scope

- Witness signing rotation.
- LOW-ADM-01 / LOW-ADM-03 server-side handler work (deferred).
- ADM-P1..P8 UX proposals.
- Audit ring expansion past 200 events.
