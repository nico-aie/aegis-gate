---
id: 2026-05-19-info-risk-composite-key-data-plane-works
date: 2026-05-19T12:35Z
severity: INFO
area: data-plane
component: risk-composite-key
status: open
test_mode: functional
---

# Risk-composite-key data plane: end-to-end correct on the HTTP path

## Summary

The data-plane half of `plans/future/risk-composite-key-data-plane.md`
is live and behaves as documented. Two TLS-less requests from the
same TCP peer (127.0.0.1 in dev) with different `Cookie:
sessionid=…` values bucket into independent `RiskKey { ip,
device_fp, session }` entries — the central audit claim of the
phase (don't conflate two sessions on the same NAT'd IP) holds on
the HTTP path. The dashboard's `/api/risk` endpoint surfaces the
new `session` field per row, the `Top risk buckets` card renders
one row per bucket with 8-char-truncated device_fp/session columns,
and the "Group by IP" toggle correctly collapses the composite
view back into the legacy IP-keyed shape.

## Repro

After login at `http://127.0.0.1:9443/`:

1. From the data-plane tab (`http://127.0.0.1:8080`), drive
   distinct session cookies:
   - `sessionid=alice-session-1234567890` → 5 SQLi probes.
   - `sessionid=bob-session-aaaaaaaaaa` → 8 XSS probes.
   - no cookie → 3 path-traversal probes.
2. `GET /api/risk?limit=50` from the admin origin.

## Expected

Three buckets sharing `ip=127.0.0.1`, distinguished by `session`:
alice → 5 strikes, bob → 8 strikes, IP-only floor → 3 strikes.

## Actual

```json
{
  "total_tracked": 3,
  "returned": 3,
  "clients": [
    { "ip": "127.0.0.1", "session": "bob-session-aaaaaaaaaa",   "score": 100, "strikes": 8, "level": "allow" },
    { "ip": "127.0.0.1", "session": "alice-session-1234567890", "score": 100, "strikes": 5, "level": "allow" },
    { "ip": "127.0.0.1",                                        "score": 100, "strikes": 3, "level": "allow" }
  ]
}
```

(`device_fp` is `null` on the HTTP path and `serde` omits it — no
TLS handshake means `build_risk_key` has no JA4 to feed
`device_fp_hash`. That's the documented behavior.)

The `Top risk buckets` card on `/#/traffic-gates` renders all three
rows. The card's "Group by IP" toggle collapses them into a single
summary row showing `max(score)=100`, `max(strikes)=8`, "3 buckets"
in the action column. Both behaviors match the implementation in
`pages.jsx::TopRiskBucketsCard`.

Audit rows for the blocking events carry a `fields.session` axis
(populated) and `fields.device_fp` axis (null on HTTP). 16 attack
requests produced exactly 16 `block` audit events (no double-write
regression).

## Suggested fix

None — this is a confirmation of correct behavior. Two follow-ups
worth tracking:

- The HTTPS data plane (`:8443`) was not exercised in this run; the
  device_fp axis only populates on the TLS path. Worth a Smoke
  re-run with curl to `https://127.0.0.1:8443` once a self-signed
  cert is in the dev profile, to confirm the JA4 → `device_fp_hash`
  → `RiskKey.device_fp` plumbing surfaces the third axis in
  `/api/risk` and on the card.
- Consider adding a one-line tooltip on the device_fp/session column
  headers explaining "—" means "no TLS fingerprint" / "no
  recognized session cookie" — today the dim-em-dash is the only
  signal and an operator unfamiliar with the model may read it as a
  bug.

## Severity rationale

INFO — proof the data-plane wire-up shipped correctly. Filed so the
run record shows what was exercised, not just what broke.
