---
id: 2026-05-30-response-filter-not-rollbackable
date: 2026-05-30T20:30Z
severity: MEDIUM
area: admin-api
component: rollback-handler / response-filter PUT path
status: open
test_mode: full-qc
---

# Rollback rejects `response_filter_put` — operator can't undo a fold change

## Summary

NT-04 publishes a response_filter change, then asks the server to
roll back. The server responds:

```json
{"error": "action `response_filter_put` is not rollback-able in this build"}
```

So a folded toggle change is one-way. An operator who flipped
`scrub_stack_traces` by mistake cannot use the rollback API — they
must remember the prior value and PUT it again manually.

## Repro

```sh
# Cluster up, logged in, CSRF in $CSRF, cookies in $J.
curl -s -b "$J" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -X PUT -d '{"scrub_stack_traces": false}' \
  http://127.0.0.1:9443/api/response-filter
# → 200 {"version": N, ...}

curl -s -b "$J" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -X POST -d "{\"target_version\": $((N - 1))}" \
  http://127.0.0.1:9443/api/config/rollback
# → 400 {"error": "action `response_filter_put` is not rollback-able in this build"}
```

## Expected

Rollback should re-activate the snapshot at the target version
(which already exists at `config:waf:v:<N-1>` — we can see this
key in Redis). Rollback uses `ConfigStore::rollback` which calls
`activate(cur, blob, …)` with the old YAML blob — the activate
path doesn't care which action originally produced the blob.

## Actual

A whitelist somewhere in the rollback handler refuses folded
actions. The folded-toggle work (commit `e77d379` and subsequent)
added several new actions (`ai_confidence_put`, `ai_enabled_put`,
`response_filter_put`, `tier_put`, `rule_put`, `upstream_put`); the
rollback whitelist appears not to have been updated in lockstep.

## Suggested fix

Either:

- A: extend the rollback action whitelist to include every folded
  PUT action. The snapshot is just bytes; rollback re-activates the
  blob regardless of which kind of PUT produced it. Test-coverage
  add: nt-04 should also try `ai_confidence_put` rollback once this
  lands.
- B: explicitly document the limitation in `docs/operator/rollback.md`
  + change nt-04 to use a rollback-able action (e.g. a routes
  change). This is the cheap path if the dev team decided folded
  PUTs deliberately aren't rollback-able for some reason — but if
  so the response should say *why*, not just "not rollback-able in
  this build".

## Severity rationale

MEDIUM. Operators have a workaround (PUT the old value back), so
it's not blocking. But the rollback API is one of the dashboard's
safety nets and silently not supporting half the writeable surface
is a real gap. CRITICAL if any production runbook references
"rollback your last change" — which the architecture doc
(`docs/architecture/storage-and-contract.md` line 65) implies it
does.
