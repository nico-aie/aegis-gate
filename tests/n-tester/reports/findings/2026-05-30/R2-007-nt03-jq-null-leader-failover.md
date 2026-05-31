---
id: 2026-05-30-nt03-jq-null-leader-failover
date: 2026-05-30T20:30Z
severity: LOW
area: docs
component: tests/n-tester/nt-03-clu-leader-failover
status: open
test_mode: full-qc
---

# NT-03 fails with `jq: error … Cannot iterate over null`

## Summary

NT-03 produces no FAIL line and no test-specific error; its
stderr_tail in the JSON report contains only:

```
jq: error (at <stdin>:0): Cannot iterate over null (null)
```

`rc=5` (jq's exit code for runtime error). That points at one of
the script's `jq` invocations getting fed `null` and trying to
iterate. Most likely a missing array field (`.members`, `.peers`,
`.leaders` or similar) on a `/api/cluster/*` response — either the
endpoint shape changed under the test, or a response branch returns
`null` instead of `[]` in some condition.

I haven't read the full script yet — flagging this so the dev who
owns the leader-lease layer can pin down which endpoint changed.

## Repro

```sh
cd /Users/nico/waf-code/aegis-gate
bash -x tests/n-tester/nt-03-clu-leader-failover.sh 2>&1 \
  | tee /tmp/nt-03-x.log
# Look for the `+ … | jq …` line that emits the error.
```

## Expected

Test passes, or fails with a meaningful message explaining what
the cluster did wrong.

## Actual

jq runtime error escapes through `set -e` with no QC-readable
context. Same diagnostic-loss class as the silent fails (nt-05,
nt-09), just with one stray line.

## Suggested fix

Wrap suspect `jq` calls in either:

- `jq -r '.field // empty'` to tolerate null, OR
- a guard `if [[ "$(echo "$resp" | jq -r '.field // "null"')" == "null" ]]; then fail "endpoint X returned no .field: $resp"; fi`.

Both make the failure mode legible without changing the test's
intent.

## Severity rationale

LOW — a single test failing with an ugly message, easy fix.
Doesn't block any release path, but worth fixing because right now
nt-03 contributes zero information to the suite.
