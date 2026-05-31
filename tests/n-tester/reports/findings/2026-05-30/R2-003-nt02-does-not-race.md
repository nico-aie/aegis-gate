---
id: 2026-05-30-nt02-does-not-race
date: 2026-05-30T20:30Z
severity: HIGH
area: docs
component: tests/n-tester/nt-02-clu-version-conflict
status: open
test_mode: full-qc
---

# NT-02 doesn't actually race the two PUTs — CAS conflict never fires

## Summary

NT-02 wants to prove the CAS-versioned config-plane returns exactly
one 200 + one 409 when two writers race. It builds the race like this:

```sh
( http_status "$NODE_A_ADMIN" PUT ... ) & pid_a=$!
(
  COOKIE_BAK="$COOKIE"; CSRF_BAK="$CSRF"
  login "$NODE_B_ADMIN"                # ← serializes ~200 ms
  http_status "$NODE_B_ADMIN" PUT ...
  ...
) & pid_b=$!
wait "$pid_a" "$pid_b"
```

The B-side subshell does a full `login "$NODE_B_ADMIN"` *before* its
PUT — that's a request, response, cookie parse — usually 100-300 ms.
PUT-A almost always completes (and activates v=1 on a fresh cluster)
before PUT-B even *reads* `config:waf:doc`. PUT-B then reads v=1 and
writes v=2 cleanly. No conflict.

Empirically: every run reports `ok=2 conflict=0`.

## Repro

Run nt-02 as-is — fails every time on a clean cluster.

## Expected

Both PUTs hit `ConfigStore::activate` with the same
`expected_version`, exactly one wins CAS, the loser returns 409 with
`error: version_conflict` and `current: <new>`.

## Actual

Serial execution, both win, no conflict surfaces.

## Suggested fix

Pre-login both nodes BEFORE the race, then fork only the PUTs:

```sh
login "$NODE_A_ADMIN"
A_COOKIE="$COOKIE"; A_CSRF="$CSRF"
login "$NODE_B_ADMIN"
B_COOKIE="$COOKIE"; B_CSRF="$CSRF"

(
  COOKIE="$A_COOKIE"; CSRF="$A_CSRF"
  http_status "$NODE_A_ADMIN" PUT "/api/response-filter" \
    '{"scrub_stack_traces": false}'  > "$race_log_a" 2>&1
) &
pid_a=$!
(
  COOKIE="$B_COOKIE"; CSRF="$B_CSRF"
  http_status "$NODE_B_ADMIN" PUT "/api/response-filter" \
    '{"scrub_stack_traces": true, "mask_internal_ips": false}'  > "$race_log_b" 2>&1
) &
pid_b=$!
wait "$pid_a" "$pid_b"
```

Note `COOKIE`/`CSRF` are subshell-local so no `BAK` dance needed.

For extra reliability, add a `sleep 0.05` synchronization barrier
before both PUTs and use a single shared FIFO to gate them.

## Severity rationale

HIGH because version_conflict / CAS is a load-bearing invariant of
the cluster config plane; this is the only test that proves it
end-to-end. The product looks broken when it isn't.
