---
id: 2026-05-12-info-bundle
date: 2026-05-12T00:22Z
severity: INFO
area: various
component: pass-observations
status: documented
test_mode: full-qc
---

# INFO — passing observations from the Security Ops run

## INFO-SO-01 — Overview page Live attack origins map is excellent

After 100 attacks from 10 spoofed source IPs, the world map
showed 4 country pins (US / DE / CN / AE — `5.195.235.51` carries
country=AE / AS5384), with dotted lines converging to the SG-1
edge marker. The legend says `5 ACTIVE SOURCES · 4 GEO-TAGGED`
which is honest — the 5th source (`203.0.113.7`) is TEST-NET-3
documentation space and correctly has no country pin. Top right
of the map carries `5 ACTIVE SOURCES · 4 GEO-TAGGED` chips that
double as a count.

This is the single best operator-orientation surface in the
product. A SOC analyst opening Overview at 3am can answer
"where's this coming from?" in <2 seconds.

## INFO-SO-02 — Live Feed Request-detail drawer is excellent

Click any row → side drawer with:

- **Summary**: Action chip / Reason / Risk bar / Tier chip
- **Network**: client_ip / ts
- **Request**: method/path, status, class
- **Detection**: human-readable reason
- **Extra fields**: detectors[], load_mode, strikes, verbosity,
  …
- Bottom actions: `Copy as cURL` / `Block IP` / `Whitelist`

`Copy as cURL` is the standout — operators can paste the exact
attack to a colleague or replay it against a fix. Other WAFs
make you reconstruct the headers manually.

(Caveat: the `Block IP` button hits HIGH-SO-01 today.)

## INFO-SO-03 — Top Attackers + Investigation pivot are well-coupled

Clicking `Pivot` on a Top Attackers row navigates to
`#/investigation?pivot=104.21.14.6&kind=ip` — the URL is shareable
and the page mounts with the pivot pre-filled and the kind
selector switched away from auto-detect. The Attacker context
card reads from `/api/attacks/top` and surfaces hits + country +
ASN + categories.

The fact that the rest of the page doesn't filter to the pivot
(MED-SO-02) is the wart, but the navigation + URL design are
right.

## INFO-SO-04 — Investigation page's Pivot input is shape-aware

Typing `104.21.14.6` and clicking Pivot auto-classifies as `ip`.
The `auto-detect` dropdown also offers `request_id` and
`rule_id` as explicit kinds. Underneath the input the confirmation
reads `"Pivoting on 104.21.14.6 · type: ip"`. Operator confidence
in the classification is high.

## INFO-SO-05 — Audit chain integrity visible in Action breakdown

On a pivot, Investigation's Action breakdown card surfaced rows
including `INCIDENT_ACK · 1 · 0.5%`. The ack mutation I clicked
earlier on the Incidents page **did** land in the audit chain —
even though the Incidents lifecycle UI didn't reflect it
(MED-SO-04). So the chain itself is honest; the lifecycle overlay
is the gap.

## INFO-SO-06 — Policy posture cheat-card is a clear win

Shipped in the previous sprint (`594235c`). Every Policy page
now opens with a single-line chip row:
`POSTURE ENFORCE · 4 TIERS · AI OFF · 0 RULES · 0 BLACKLIST · 0
WHITELIST · DDOS ENFORCE`. Each chip is clickable. Operator
orientation cost dropped from "read the whole page" to "read
the one line". Worth keeping as the canonical pattern for any
future Policy-adjacent page.

