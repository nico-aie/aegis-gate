# Page — Attack Events

> Curated view focused on detections and rule firings — quieter than
> Live Feed (which includes access logs and admin events).

## Route

`GET /dashboard/attacks`

## Data sources

| Widget | Source |
|--------|--------|
| Detector breakdown chart | `GET /api/attacks/by-detector?window=1h` |
| Top firing rules | `GET /api/rules/top?window=1h&limit=10` |
| Threat-intel hits | `GET /api/threat-intel/hits?window=1h&limit=20` |
| Bot mix | `GET /api/bots/mix?window=1h` |
| Recent detections table | SSE from `/dashboard/sse?class=detection` |

## Layout

```
┌──────────────────────────────────────────────────────────────┐
│ Attack Events — last 1h                  [1h ▾] [Export CSV] │
├──────────────────────────┬───────────────────────────────────┤
│ Detector breakdown       │ Bot classification mix            │
│ horizontal bar chart     │ stacked bar (verified / suspect / │
│                          │ malicious / unknown)              │
├──────────────────────────┴───────────────────────────────────┤
│ Top firing rules                                              │
│ table: rule id · scope · action · count · last fired          │
├───────────────────────────────────────────────────────────────┤
│ Threat-intel hits                                             │
│ table: source · indicator · category · count · first/last     │
├───────────────────────────────────────────────────────────────┤
│ Recent detections (live tail)                                 │
│ same row anatomy as Live Feed but pre-filtered to `detection` │
└───────────────────────────────────────────────────────────────┘
```

- Window selector: 5m, 15m, 1h (default), 6h, 24h. Updates all
  widgets in unison.
- Export CSV: server-side stream of the rule and detection rows
  for the selected window.

## Detector breakdown

- Horizontal bar chart, one bar per OWASP detector
  (`sqli`, `xss`, `path_traversal`, `ssrf`, `header_injection`,
  `body_abuse`, `recon`).
- Bar colour matches the attack-distribution palette in
  [`../theme.md`](../theme.md).
- Click a bar → filters the recent detections tail to that
  detector.

## Top firing rules

- Sorted by count desc.
- Columns: Rule ID (link to Rule Manager), Scope (`route` /
  `global`), Action (`block`/`challenge`/`audit`), Count, Last
  Fired (relative time).
- Row action: "Disable for 1h" (writes to rule overrides; CSRF +
  confirm modal).

## Threat-intel hits

- Columns: Source (e.g. `spamhaus_drop`, `tor`, `firehol`),
  Indicator (IP/CIDR), Category, Hits, First/Last seen.
- Click a row → drawer with the matching detections list.

## Bot classification mix

- Stacked bar of bot categories from the bot classifier.
- Categories: `verified` (Googlebot etc.), `suspect`, `malicious`,
  `unknown`. Same window as the page.
- Click a category → filters the live tail.

## States

- Empty: large centred message "Quiet on the wire — no detections
  in this window." with a link to widen the window.
- Error per widget: localised retry, page keeps working.

## Performance

The aggregate endpoints precompute once per second on the server
(see [`../api.md`](../api.md) §caching). Each tab triggers at most
one fetch per refresh interval per endpoint.
