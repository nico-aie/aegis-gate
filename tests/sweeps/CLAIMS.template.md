# Claims — `<sweep-id>`

Each tester appends a row when they start. Edit-when-you-claim,
not-when-you-finish. Helps everyone else avoid trampling.

| Tester | AI model | Slice | Started (UTC) | Finished | Notes |
|---|---|---|---|---|---|
| _example: alice_ | _claude-sonnet-4.6_ | _control.dashboard.soc_ | _2026-05-10T14:00Z_ | _—_ | _focus on Investigation page_ |

## Available slices (claim by editing the row above)

- `data-plane.security` — detector mask, rules, tier overrides
- `data-plane.routing` — upstream pools, health, failover
- `data-plane.tls` — listener cert hot-swap, ACME, HTTP/3
- `data-plane.mtls` — client auth, allowed SANs, CA bundle hot-swap
- `control.api` — REST + WebSocket admin endpoints
- `control.dashboard.config` — Detectors/Rules/Routes/Upstreams pages
- `control.dashboard.soc` — Investigation/Compliance/Reports/Threat Intel/Incidents
- `cluster.ha` — leader election, partition fallback, reconciliation

## Conflict rules

- One claim per slice per sweep window. If two testers want the
  same slice, the second tester picks a different slice or pairs
  with the first.
- A slice with no claim 24h before the sweep window opens rolls
  into the shared "unowned" pool — anyone can pick it up
  ad-hoc.
- A finished slice frees up; the tester may claim a second.
