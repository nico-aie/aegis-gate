---
id: 2026-05-30-nt05-nt09-silent-fails
date: 2026-05-30T20:30Z
severity: HIGH
area: docs
component: tests/n-tester/nt-05, tests/n-tester/nt-09, possibly _common.sh
status: open
test_mode: full-qc
---

# NT-05 and NT-09 fail with empty stderr_tail — possible regression of L-fail-message-stderr fix

## Summary

In the run report, both tests have `rc=1` but `stderr_tail=""`:

```json
{ "name": "nt-05-clu-restart-rejoin", "status": "fail", "rc": 1, "stderr_tail": "" }
{ "name": "nt-09-ai-confidence-default-from-config", "status": "fail", "rc": 1, "stderr_tail": "" }
```

The prior Round-1 finding `L-fail-message-stderr-vs-stdout` was
fixed in `_common.sh` L88-90 (verified at source level — `fail()`
writes via `_red "FAIL: $*" >&2`). Other tests in this same run
emit proper FAIL lines through that path. So the question is
whether nt-05 and nt-09 are hitting a different exit path that
*doesn't* go through `fail()`.

Both scripts use `set -euo pipefail`. The most likely culprit is
an unguarded pipeline that pipefails (e.g., `admin_get | jq …`
inside a `local v="$(...)"` capture, where the curl times out
non-zero), causing the script to exit 1 with no message.

## Repro

```sh
cd /Users/nico/waf-code/aegis-gate
bash -x tests/n-tester/nt-05-clu-restart-rejoin.sh 2>&1 | tee /tmp/nt-05-x.log
# Look for the last line before exit. That's where set -e fired.

bash -x tests/n-tester/nt-09-ai-confidence-default-from-config.sh 2>&1 | tee /tmp/nt-09-x.log
```

## Expected

A FAIL line on stderr describing what went wrong — the same way
every other failing test in this run reported `FAIL: <message>`.

## Actual

Silent rc=1. Nothing on stderr. The harness fall-back
(`stderr_tail=""`) is the only signal we have, and it's useless.

## Suggested fix

Step 1 — run the two scripts with `bash -x` to find where they
exit. Step 2 — depending on what you find:

- If a pipeline pipefails: refactor `local v=$(curl … | jq …)`
  into two lines (capture body, then jq it; check curl exit
  separately).
- If a function exits via `return 1` instead of `fail`: wrap the
  call sites in `|| fail "…"`.
- If a third path exists (e.g. `start_node` returning 77 inside a
  test that doesn't treat it as skip): handle the skip exit in the
  caller.

Also worth considering: trap a `ERR` handler in `_common.sh` that
prints the failing line number and last command before exiting,
so future silent fails surface their location automatically.

## Severity rationale

HIGH. Silent failures destroy the harness's diagnostic value. Even
if the underlying tests are exercising bugs we *want* to find,
without a message we can't act. This is also one rebuild away from
masking a real product regression.
