# Page — Whitelist

> Allow lists for IPs, CIDRs, ASNs, and fingerprints. Mirror image
> of [`blacklist.md`](blacklist.md) — same shape, opposite action,
> separate auditable surface.

## Route

`GET /dashboard/whitelist`

## Data sources

| Widget | Source |
|--------|--------|
| List | `GET /api/whitelist?type=&q=&cursor=` |
| Detail | `GET /api/whitelist/{id}` |
| Add | `POST /api/whitelist` (session + CSRF) |
| Update | `PUT /api/whitelist/{id}` |
| Remove | `DELETE /api/whitelist/{id}` |
| Bulk | `POST /api/whitelist/bulk` |
| Bypasses | `GET /api/whitelist/{id}/bypasses?window=24h` |

## Entry shape

```jsonc
{
  "id": "uuid",
  "type": "ip" | "cidr" | "asn" | "fingerprint",
  "value": "...",
  "scope": "global" | "route:<id>" | "tier:<name>",
  "bypass": ["rate-limit", "challenge", "detector:sqli", "all"],
  "reason": "operator-supplied",
  "expires_at": "..." | null,
  "created_by": "admin",
  "created_at": "...",
  "bypasses_24h": 0,
  "last_bypass_at": "..." | null
}
```

The `bypass` array is the differentiator from blacklist: it lists
which gates the entry skips. `all` is a privileged option that
fires a confirm dialog with extra warnings.

## Layout

Same shell as Blacklist. Columns:

```
Type · Value · Scope · Bypass · Reason · Expires · Bypasses 24h
```

A "high-trust" pill highlights any `bypass: ["all"]` entries to
make them obvious during reviews.

## Safety

- `bypass: ["all"]` requires:
  1. A reason length ≥ 20 chars.
  2. An expiry within 30 days (configurable per
     `admin.whitelist.max_all_bypass_ttl`).
  3. A second-factor re-prompt (TOTP) at submit time when TOTP is
     enabled.
- Entries with `bypass: ["all"]` and no expiry are forbidden by
  the validator — server returns 400.

## Audit

Same admin-class entries as Blacklist, with an extra
`bypass_summary` field summarising the bypass list change.

## Compliance interaction

- HIPAA / PCI profiles enforce a max TTL on all whitelist entries
  (typically 30 days). The validator surfaces this inline at
  Save time — the operator sees "Compliance profile PCI requires
  expiry ≤ 30d" if they leave the field blank.
