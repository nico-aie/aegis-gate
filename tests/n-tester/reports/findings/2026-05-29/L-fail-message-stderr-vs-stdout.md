---
id: 2026-05-29-fail-message-stderr-vs-stdout
date: 2026-05-29T19:50Z
severity: LOW
area: docs
component: tests/n-tester/_common.sh, tests/n-tester/run-all.sh
status: open
test_mode: functional
---

# `fail()` writes to stdout but runner captures only stderr — `stderr_tail` is empty for every failure

## Summary
`tests/n-tester/_common.sh:83`:
```sh
fail() { _red "FAIL: $*"; exit 1; }
```
`_red()` is `printf '\033[…m%s\033[…m\n' "$*"`, which defaults
to stdout. But `tests/n-tester/run-all.sh:69` runs each test
with `bash "$script" 2>"$err_log"` — only stderr is captured.
So when a test calls `fail "…explanation…"`, the explanation goes
to the controlling terminal but is **not** captured in the JSON
report; `stderr_tail` ends up `""` for every failure. The same
applies to silent `set -e` aborts (no message at all reaches
either stream).

This makes post-mortem of CI failures significantly harder than
it has to be — see the 2026-05-29 run where 11 failures all
appeared as `rc=1, stderr_tail=""` and I had to manually rerun
nt-01 + stitch tools together to figure out the actual cause.

## Repro
1. `cd /Users/nico/waf-code/aegis-gate`
2. Force a failure: any nt-* in current state already does — see
   `H-cluster-yaml-missing-dashboard-auth`. Or hand-construct:
   `bash -c 'source tests/n-tester/_common.sh; fail "synthetic"'`.
3. `tests/n-tester/run-all.sh --filter 'nt-01*'`
4. `jq '.results[0].stderr_tail' tests/n-tester/reports/run-*.json | tail -1`

## Expected
`stderr_tail` contains the `FAIL: <reason>` line from the test.

## Actual
`""` — the FAIL line went to stdout (visible in your terminal,
discarded by the runner).

## Suggested fix
Single-line change in `_common.sh`:
```sh
fail() { _red "FAIL: $*" >&2; exit 1; }
```
Optionally also change `_red`/`_yellow` to write to fd 2 directly
since both are diagnostic, not data. After that, every captured
FAIL appears in the report and `stderr_tail` becomes immediately
useful.

Bonus: combine with the related `login-silent-on-no-cookie`
finding — together they remove the "silent abort" failure mode
the suite currently has.

## Severity rationale
LOW. No behavioural defect — only diagnostic quality. Fixing it
makes future regression investigation cheaper but doesn't change
correctness of the suite or the WAF.
