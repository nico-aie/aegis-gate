---
id: 2026-05-29-run-all-skip-bookkeeping
date: 2026-05-29T19:50Z
severity: LOW
area: docs
component: tests/n-tester/run-all.sh
status: open
test_mode: functional
---

# `run-all.sh` never increments `skip`; SKIPped tests get counted as `pass`

## Summary
`tests/n-tester/run-all.sh` reports `pass=1 fail=11 skip=0`
even though nt-11 emitted a `SKIP:` line and exited 0. There is
no `skip=…` increment anywhere in the runner — it only has the
`pass` branch and the `fail` branch. So any test that uses the
`skip()` helper (which calls `exit 0`) gets folded into `pass`,
hiding the fact that environment-gated tests didn't actually run.

## Repro
1. `cd /Users/nico/waf-code/aegis-gate`
2. `tests/n-tester/run-all.sh` (with `AEGIS_AI_E2E` unset — the default)
3. Note nt-11 prints `SKIP: AEGIS_AI_E2E=1 not set; the live-effect
   test needs a real ONNX model`.
4. After completion, check report: `jq '.summary' tests/n-tester/reports/run-*.json | tail -10`.

## Expected
```
{ "total": 12, "pass": 0 or 1 depending on other state, "fail": …, "skip": 1 }
```
and the per-test `nt-11` entry has `"status": "skip"` with a
`"reason"` field (matches the `README.md` shape "A `skip` entry
includes `reason`.").

## Actual
```
{ "total": 12, "pass": 1, "fail": 11, "skip": 0 }
```
nt-11 entry in the JSON:
```json
{ "name": "nt-11-ai-confidence-live-effect", "status": "pass", "duration_s": 0 }
```
No `reason`, no `skip` status.

## Suggested fix
Two reasonable options:

a) **Detect the prefix** in `run-all.sh` after the script exits
   successfully — if the captured stdout's last line starts with
   `SKIP:`, write a `skip` row and bump `skip` instead of `pass`.

b) **Reserve an exit code.** Have `skip()` exit with e.g. `77`
   (the autotools convention) and have `run-all.sh` branch on
   `if [ "$rc" -eq 77 ]; then skip=$((skip+1)); …`. This is the
   cleaner path because it doesn't depend on stdout parsing, and
   it composes with `bash -e` inside individual scripts cleanly.

Either way, also update the per-test JSON to write `{"status": "skip",
"reason": "<captured>"}` so the README's documented shape is honest.

## Severity rationale
LOW. The misclassification doesn't change a release decision on
its own (nt-11 is gated on AEGIS_AI_E2E and that's documented), but
it produces a misleading summary that can mask "skipped because of
a config issue" failures in CI. Easy fix.
