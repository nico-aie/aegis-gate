---
id: 2026-05-12-block-button-broken
date: 2026-05-12T00:23Z
severity: HIGH
area: dashboard · admin-api contract
component: top-attackers · live-feed-drawer · overview preview
status: open
test_mode: full-qc
---

# `Block` button on Top Attackers (and the Live Feed drawer "Block IP" action) sends an incomplete POST body — server returns 400 `missing field bypass`

## Summary

Three operator surfaces share the same "block this attacker in one
click" affordance: the `Block` action chip in the Top Attackers
table, the `Block IP` button in the Live Feed request-detail
drawer, and the small `Block` action on the Overview page's "Top
attacker IPs · 15m" preview. All three POST to `/api/blacklist`.

All three fail today with HTTP 400:

```
Block failed: invalid blacklist entry: missing field `bypass`
at line 1 column 123
```

The Access Lists page's own `Submit` button (Blacklist tab) works
fine, so the schema is satisfiable — the difference is that the
Access-Lists path sends `bypass: []` (an empty array) while the
one-click Block path omits the field entirely. The server's
`MemberConfig` deserializer flags any missing field as a hard
400.

This breaks **S6 "Block this attacker"** end-to-end — the primary
incident-response workflow in the dashboard. The confirm prompt
copy is good (`"Block 104.21.14.6? Adds to /api/blacklist ·
audit-chained."`), the toast on failure is clear, and the
operator's only manual workaround is to navigate to Access Lists
and re-type the IP. That defeats the entire purpose of the chip.

## Repro

1. Sign in to `:9443`, drive any attack traffic (e.g.
   `make mock-load-attacks` or curl from a second tab with
   `X-Forwarded-For` spoofed).
2. Navigate to **Top Attackers**. Wait for the table to
   populate (window: 1h).
3. Click `Block` on any row.
4. Confirm the native prompt: *"Block <IP>? Adds to
   /api/blacklist · audit-chained."*
5. Observe the bottom-right red toast:
   `"Block failed: invalid blacklist entry: missing field `bypass`
   at line 1 column 123"`
6. `fetch("/api/blacklist", {credentials:"include"})` returns
   `entries: []` — nothing was persisted.

Same repro for the **Live Feed** → row click → drawer →
`Block IP` button and the **Overview** Top attackers preview
row's `Block` chip.

For comparison, the working Access-Lists Blacklist `Submit` flow
sends:
```json
{
  "id":"qa-test",
  "kind":"ip",
  "value":"203.0.113.99",
  "note":"qa",
  "bypass":[],
  "created_at":"2026-05-12T00:20:00Z"
}
```
and the server accepts it.

## Expected

Top Attackers `Block` button (and its siblings) constructs the
same shape Access Lists uses — including `bypass: []` — and the
POST succeeds. The row should optimistically show a `BLOCKED`
pill or vanish from the Top Attackers list; the next request from
that IP returns 403 with the `blacklist` rule tag.

## Actual

Server rejects the POST with `missing field bypass`. No state
change. The operator's clicked-Block intent is silently dropped
besides the toast.

## Suggested fix

Single dashboard-side edit. In the Top Attackers / Live Feed
drawer / Overview-preview Block handler, build the POST body as:

```js
{
  id: `top-${identifier.replace(/[^\w.:-]/g, '-')}`,
  kind: identifier.includes(':') ? 'cidr' : 'ip',
  value: identifier,
  note: `Blocked from Top Attackers · risk ${risk}`,
  bypass: [],                                  // ← THIS LINE
  created_at: new Date().toISOString(),
}
```

(The `kind: 'cidr'` branch is for the SOC analyst who Pivots on a
network range — Top Attackers can also surface AS-level
identifiers via the same affordance later.)

Same one-line fix in:
- `crates/aegis-control/assets/dashboard/src/pages.jsx` —
  TopAttackers handler (`Block` button onClick)
- Same file — Live Feed drawer (`Block IP` button onClick)
- Same file — Overview preview table (`Block` chip onClick)

Run `make dashboard` after, hard-reload the SPA (per the existing
LOW finding about `max-age=3600`), retest.

### Tighter alternative — make `bypass` optional server-side

`bypass: []` is the no-bypass case (the entry blocks **all**
detectors, no allow-list per detector). It's also the most common
case — only operators with surgical detector-bypass rules need to
populate it. The server schema would be friendlier with:

```rust
#[serde(default)]
pub bypass: Vec<DetectorClass>,
```

— making the field optional and defaulting to `vec![]`. Existing
clients keep working; future callers can omit the field.

I'd ship the dashboard fix first (it's a one-line patch and
unblocks operators today) and queue the server-side
schema-relaxation as a follow-up.

## Severity rationale

HIGH. It's not CRITICAL because:
- The Block-button-broken state is recoverable via Access Lists.
- The toast tells the operator the action failed (no silent
  data-loss, no false sense of security).

But it's also strictly worse than "the feature isn't shipped" —
operators will click Block, see the green confirm, and walk away
believing the IP is blocked. Then the next attack lands.

The fix is < 30 lines of dashboard JS + a bundle rebuild + a
hard-reload. Ship in the next dashboard PR.

