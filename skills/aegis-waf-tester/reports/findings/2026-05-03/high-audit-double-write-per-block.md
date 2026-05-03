---
id: 2026-05-03-high-audit-double-write-per-block
date: 2026-05-03T17:40Z
severity: HIGH
area: data-plane
component: audit-chain
status: fixed
test_mode: full-qc
---

# Every block produces two audit events (peer IP + XFF IP) — counts double

## Summary
Each blocked request lands two rows in the audit chain instead of
one. The first row is keyed by the connection's actual peer IP
(`127.0.0.1` in dev) and carries the full detector metadata
(`fields.detectors`, `rule_id`, `load_mode`, `strikes`,
`verbosity`). The second row is keyed by the resolved client IP
from `X-Forwarded-For` (`8.8.8.8`) but the rule field is `—` and
the only useful field is `reason: "blocked by detectors: …
(score: 100)"`.

Visible everywhere downstream:

- `/api/audit/since?limit=80` returned 80 events for what should
  have been 40 attack probes (10 × 4 classes).
- Audit Trail UI shows two rows per block, alternating
  `127.0.0.1` / `8.8.8.8`, same timestamp to the second.
- `/api/attacks/top` — the connection-IP rows pile up under
  `127.0.0.1`, the XFF-IP rows pile up under the spoofed IP.
  In a single-host dev session the loopback IP outranks every
  real attacker.
- `/api/attacks/by-detector` count totals are 2× the truth (and
  also mis-bucketed; see related finding).

## Repro
```bash
# 1 attack request
curl -s -o /dev/null -H "X-Forwarded-For: 8.8.8.8" \
  "http://127.0.0.1:8080/?q=<script>alert(1)</script>"

# Inspect: 2 audit rows for this single request
curl -s -b $JAR "http://127.0.0.1:9443/api/audit/since?limit=4" | jq '.events[] | {ts, action, client_ip, rule: .fields.rule_id, detectors: .fields.detectors}'
```

Sample output (paths_per_action from the live run):
```
{ "a":"block", "p":"/?q=<script>...", "client_ip":"127.0.0.1", "d":["xss","ssrf"] }
{ "a":"block", "p":"/",               "client_ip":"8.8.8.8",   "d":null }
```

The second row has the URL truncated at `/` (no query string)
and `detectors: null`, so it can't even reproduce the original
request — yet it's the row Top Attackers uses to credit hits to
the resolved client IP.

## Expected
One audit event per request, carrying both the connection peer
IP (e.g. `peer_ip: 127.0.0.1`) AND the resolved client IP
(`client_ip: 8.8.8.8`) as separate fields, plus the full
`fields.detectors` array. Aggregate metrics keyed by
`client_ip`.

## Actual
Two events per request, with mutually exclusive metadata. Either
record alone is incomplete; the dashboard joins by timestamp +
URL prefix and ends up double-counting.

## Suggested fix
Pick one of:

1. **Single-write, two IPs.** Have the data-plane handler emit
   one event with `peer_ip` + `client_ip` populated, and pick
   `client_ip` (XFF-resolved) as the join key everywhere
   downstream. Smallest change.
2. **Two writes, two roles.** Tag the events explicitly so they
   can be filtered: `kind: "decision"` for the detector-rich
   record, `kind: "request_log"` for the request-keyed one. Then
   make `/api/attacks/top` and `/api/attacks/by-detector` only
   read `kind: decision`. Bigger change but preserves whatever
   reason the two writes exist today.

Whichever path you take, the audit-chain hash linkage needs to
stay valid (one fewer or two fewer events both rebreak the chain
unless the chain is recomputed).

## Severity rationale
HIGH. Inflates every operator-facing count by 2× and pollutes
Top Attackers with a phantom #1 (the loopback IP). Not CRITICAL
because the data is *more* not less — once the join is fixed,
no record needs to be reconstructed.
