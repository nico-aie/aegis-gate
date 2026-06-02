---
id: audit-cold-tier-export
status: deferred
opened: 2026-05-13
source_qc: tests/n-tester/reports/2026-05-13-FINAL-release-readiness/LOW-FINAL-02-audit-ring-capped-at-200-events.md
related: plans/future/unwired-stubs-catalog.md
---

# Audit cold-tier export

## Problem statement

The audit chain lives in an in-memory `AuditRing` capped at 200
events (`crates/aegis-control/src/api/audit.rs::DEFAULT_CAP`).
Two consequences fall out:

1. **No long-window export.** The dashboard's Reports page
   (`/api/reports/audit.csv?limit=N`) silently clamps `N` to the
   ring's cap. The card title was made honest in the
   2026-05-12-admin LOW-ADM-02 fix ("Audit trail · full ring ·
   last 200 events") but the underlying limitation remains.

2. **Process restart loses the chain.** This contradicts the
   "tamper-evident audit" framing in the v2.3 hackathon contract
   — a restart-erased chain isn't actually tamper-evident across
   the restart boundary. Operators in regulated industries
   (PCI / HIPAA / SOC2 — covered by `compliance-profiles.md`)
   will need persistence before a real deployment.

A stub exists at `GET /api/cold-tier` that returns
`{"feature_present": false, "note": "cold-tier export not wired"}`
— a deliberate placeholder so the dashboard can branch on the
flag.

## Design shapes

Two candidate v1 implementations. Pick (1) for cost-of-carry,
(2) for query power.

### Option 1 — JSONL append (recommended for v1)

Every event the audit ring records also `line-appends` to
`data/audit/chain-<UTC-date>.jsonl`. One file per day; rotation
is by filename so no in-band rotation logic.

**Pros**
- ~30 LoC.  `std::fs::OpenOptions::new().append(true).create(true)`
  + a `tokio::sync::Mutex` for the writer handle.
- File format is identical to the existing
  `/tmp/audit-YYYY-MM-DD.ndjson` sink the WAF already writes —
  reuse the serializer.
- `grep` / `jq` / `gzip` work for export. Spreadsheet import via
  `jq -r '. | [.ts, .action, .client_ip] | @csv'`.
- Trivial backup story: rsync the directory.
- Zero migration story (just start appending).

**Cons**
- No range queries. `/api/audit/since?from=<ts>&to=<ts>` would
  have to scan the file (cheap enough for typical SOC review
  windows — 7d * 100rps * 200 bytes = ~120 MB).
- No transactional commit guarantee on power-loss — appended
  bytes between `fsync()`s can be torn. Mitigated by adding the
  audit-chain hash in each row (a torn-tail row breaks the hash
  link and is detectable on replay).

### Option 2 — Embedded sqlite

`data/audit/chain.db` with one row per event. Schema:

```sql
CREATE TABLE events (
    seq          INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,  -- unix_ms
    request_id   TEXT NOT NULL,
    class        TEXT NOT NULL,
    action       TEXT NOT NULL,
    client_ip    TEXT,
    rule_id      TEXT,
    fields       TEXT NOT NULL,     -- json blob
    prev_hash    BLOB,
    self_hash    BLOB NOT NULL
);
CREATE INDEX events_ts ON events(ts);
CREATE INDEX events_client_ip ON events(client_ip);
```

**Pros**
- Real `from`/`to` query support without a file scan.
- Per-IP filter (Investigation pivot) can hit the index directly
  instead of walking the in-memory ring.
- Transactional. Power-loss tolerant.
- Bundled file is operator-friendly (one file to back up).

**Cons**
- ~1 day work. Schema, migration story, embedded sqlite crate
  (rusqlite + bundled feature), connection pool.
- Adds a dependency (rusqlite ~ 250 KB binary growth).
- A real migration path needed when the schema evolves
  (`ALTER TABLE` or auto-migrate on boot).

## Recommendation

**Ship Option 1 first.** It closes the operator-visible
limitation (persistence across restart, weekly compliance
exports) in <1 day with no schema/migration story. If real
query power becomes the bottleneck, layer Option 2 on top
later — the JSONL files become the cold archive and sqlite
becomes the hot index.

## Wire-up notes when this lands

- Promote `/api/cold-tier` from stub to real endpoint:
  ```json
  {
    "feature_present": true,
    "format": "jsonl",
    "directory": "data/audit",
    "current_file": "chain-2026-05-13.jsonl",
    "size_bytes": 12345678,
    "oldest_event_ts": "2026-05-06T00:00:00Z"
  }
  ```
- Update `/api/reports/audit.csv?from=<ts>&to=<ts>` to read from
  cold-tier when the requested window predates the ring's
  oldest entry.
- Add a Reports card: "Audit archive (last 7 days · cold tier)"
  using the new endpoint.
- Update `Implement-Progress.md` to mark the "cold-tier audit"
  row as shipped.

## Out of scope here

- Retention policy (when to delete old JSONL files). Operators
  decide via cron / external rotation. The WAF doesn't
  garbage-collect its own audit by design — that's a compliance
  decision, not a runtime one.
- S3 / object-storage sink. Filesystem first; remote storage is
  a follow-up.
- Audit-chain hash verification tooling (separate `aegis-bin
  audit verify` subcommand). The hash links are already there;
  only the verifier is missing.
