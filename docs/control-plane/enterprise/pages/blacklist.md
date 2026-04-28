# Page — Blacklist

> Deny lists for IPs, CIDRs, and ASNs. Mirrors the existing
> `geoip-filtering` and `ip-reputation` modules but exposes a
> dedicated CRUD UI.

## Route

`GET /dashboard/blacklist`

## Data sources

| Widget | Source |
|--------|--------|
| List | `GET /api/blacklist?type=&q=&cursor=` (new) |
| Detail | `GET /api/blacklist/{id}` |
| Add entry | `POST /api/blacklist` (session + CSRF) |
| Update entry | `PUT /api/blacklist/{id}` |
| Remove entry | `DELETE /api/blacklist/{id}` |
| Bulk import | `POST /api/blacklist/bulk` (NDJSON or CIDR list) |
| Hits | `GET /api/blacklist/{id}/hits?window=24h` |

The data store is the existing CIDR list / threat-intel store in
`aegis-security` — see [`../../ip-reputation.md`](../../ip-reputation.md)
and [`../../geoip-filtering.md`](../../geoip-filtering.md). The new
endpoints are thin wrappers; the business logic doesn't change.

## Entry shape

```jsonc
{
  "id": "uuid",
  "type": "ip" | "cidr" | "asn" | "fingerprint",
  "value": "1.2.3.4" | "10.0.0.0/8" | "AS13335" | "fp:abcd…",
  "scope": "global" | "route:<id>" | "tier:<name>",
  "action": "block" | "challenge",
  "reason": "operator-supplied free text",
  "expires_at": "2026-05-04T12:00:00Z" | null,
  "created_by": "admin",
  "created_at": "...",
  "hits_24h": 0,
  "last_hit_at": "..." | null
}
```

## Layout

```
┌──────────────────────────────────────────────────────────────┐
│ Blacklist                              [+ Add] [Bulk import] │
├──────────────────────────────────────────────────────────────┤
│ [type▾] [scope▾] [active/expired▾] [search…]                 │
├──────────────────────────────────────────────────────────────┤
│ Type · Value · Scope · Action · Reason · Expires · Hits 24h  │
│ … rows ↓                                                     │
└──────────────────────────────────────────────────────────────┘
```

- Sortable by hits, expiry, created.
- Row kebab: Edit, Extend (sets new expires_at), Remove.
- Empty state: "No deny rules. Add one or import a list."

## Add modal

- Single form with type radio, value input (validated client-side
  for IP/CIDR/ASN format), scope dropdown, action select, reason
  textarea, expiry datetime input (optional, with "Never" pill).
- Submit: `POST /api/blacklist` with CSRF.
- Server validation echoed inline if `400`.

## Bulk import

- Modal with a `<textarea>` accepting CIDR per line, plus a "Use
  same scope/action/reason for all" form.
- Server applies them transactionally; on partial failure returns
  per-line outcomes; UI shows a result table.

## Expiry sweep

- Server sweeps expired entries every 5 minutes (existing job in
  `residency.rs`). The UI doesn't need to poll; entries simply
  drop off.

## Hits drill-in

- Click a row → drawer with last 50 detection events that matched
  this entry.
- "Promote to allowlist" if the operator decides this was a
  mistake — opens a confirm modal that performs the move
  transactionally.

## Audit

Every mutation writes an `AuditClass::Admin` entry with the diff:

```
{ "blacklist": { "removed": [...], "added": [...], "modified": [...] } }
```
