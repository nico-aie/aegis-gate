# Page — Tier Config

> Tier definitions and pipeline assignment. The tier classifier in
> `aegis-security` decides which pipeline (basic / enhanced /
> strict) a request runs through. This page exposes that mapping.

## Route

`GET /dashboard/tiers`

## Data sources

| Widget | Source |
|--------|--------|
| Tier list | `GET /api/tiers` (new — wraps `WafConfig.tiers`) |
| Tier detail | `GET /api/tiers/{name}` |
| Save tier | `PUT /api/tiers/{name}` (session + CSRF) |
| Route assignment | `GET /api/routes` (already exists) + per-route `tier` field |
| Match counts | `GET /api/tiers/{name}/stats?window=1h` |

`GET /api/tiers` returns the existing `WafConfig.tiers` slice as
JSON. No new server logic — the data already exists in
`aegis-core`.

## Layout

```
┌──────────────────────────────────────────────────────────────┐
│ Tier Config                                  [+ New tier]    │
├────────────┬─────────────────────────────────────────────────┤
│ tier list  │   tier detail                                    │
│ basic      │                                                  │
│ enhanced   │   ┌─ tabs: Pipeline | Routes | Stats ─┐         │
│ strict     │   │                                    │         │
│            │   │  pipeline editor                   │         │
│            │   │  - rate-limit profile              │         │
│            │   │  - detector set                    │         │
│            │   │  - challenge ladder                │         │
│            │   │  - tls profile                     │         │
│            │   └────────────────────────────────────┘         │
│            │                                                  │
│            │   [Save]   [Cancel]                              │
└────────────┴─────────────────────────────────────────────────┘
```

## Pipeline editor

The tier's pipeline is a small struct: a list of named stages with
toggles and parameters. The editor renders one card per stage:

```
┌──────────────────────────────────┐
│ ⚙ Rate limiting        [enabled] │
│   profile:  [strict ▾]           │
│   override: per-route allowed     │
└──────────────────────────────────┘
```

Stages exposed in v1:
- TLS profile (FIPS / modern / compat)
- Rate limit profile (lenient / standard / strict)
- Detector set (`[sqli, xss, path_traversal, ssrf, header_injection,
  body_abuse, recon]` — multi-select)
- Challenge ladder (none / js-only / js+captcha / strict)
- DLP action (`audit_only` / `mask` / `block`)

## Routes tab

- Lists routes whose `tier` field matches this tier.
- Inline edit: change `tier` per route via `PUT /api/routes/{id}`.
- Bulk reassign: select rows + apply.

## Stats tab

- Bar chart of decisions by route within the tier (1h window).
- Top 5 firing rules within the tier.

## Validation

- Saving a tier runs through the same validator as `/api/config`.
  Conflicts with compliance profiles (e.g. PCI-DSS forbids TLS <
  1.2) are surfaced inline before save.
- Read-only mode if compliance profiles forbid editing this tier
  (e.g. FIPS lockdown).
