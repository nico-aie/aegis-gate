#!/usr/bin/env bash
# tests/n-tester/run-all.sh
#
# Runs every nt-*.sh sequentially. Each test boots + stops its own
# cluster (Redis container stays warm across tests for speed; the
# config-plane keyspace is wiped at the start of each cluster boot).
#
# Usage:
#   tests/n-tester/run-all.sh [--filter <pattern>]
#
# Options:
#   --filter <pattern>   Run only nt-* files matching the glob.
#                        Example: --filter 'nt-0[6-9]*'
#
# Env:
#   AEGIS_AI_E2E=1       Run the AI live-effect test (NT-11). Default 0
#                        (skipped) — needs an ONNX model linked.
#
# Exit codes:
#   0  — every test passed (skips don't fail the run)
#   1  — one or more tests failed
#
# Output:
#   - Human-readable PASS/FAIL/SKIP lines on stdout
#   - Machine-readable summary at reports/run-<UTC-timestamp>.json

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

FILTER="${FILTER:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --filter) FILTER="$2"; shift 2;;
    -h|--help)
      sed -n '3,28p' "$0"; exit 0;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT_DIR="$HERE/reports"
REPORT_JSON="$REPORT_DIR/run-$TIMESTAMP.json"
mkdir -p "$REPORT_DIR"

# Discover.
shopt -s nullglob
if [[ -n "$FILTER" ]]; then
  # shellcheck disable=SC2206  — glob expansion is the point
  TESTS=( "$HERE"/$FILTER )
else
  TESTS=( "$HERE"/nt-*.sh )
fi
shopt -u nullglob

if (( ${#TESTS[@]} == 0 )); then
  echo "no tests matched ${FILTER:-nt-*.sh}" >&2
  exit 1
fi

pass=0; fail=0; skip=0; total=0
results_jsonl="$(mktemp)"

for script in "${TESTS[@]}"; do
  name="$(basename "$script" .sh)"
  total=$((total + 1))
  printf '── %s ──\n' "$name"
  out_log="$(mktemp)"
  err_log="$(mktemp)"
  start=$SECONDS
  # 2026-05-29 (QC L-run-all-skip-bookkeeping): capture exit code
  # without disabling errexit in this loop, and distinguish 77 (skip,
  # autotools convention used by _common.sh::skip()) from a real fail.
  rc=0
  bash "$script" >"$out_log" 2>"$err_log" || rc=$?
  dur=$((SECONDS - start))
  case "$rc" in
    0)
      pass=$((pass + 1))
      printf '{"name":"%s","status":"pass","duration_s":%d}\n' \
        "$name" "$dur" >>"$results_jsonl"
      ;;
    77)
      skip=$((skip + 1))
      # `skip()` writes "SKIP: <reason>" to stderr through `_yellow`,
      # which prefixes/suffixes ANSI colour codes — strip those first
      # so the anchor matches. (Caught 2026-05-29: skip reasons were
      # silently logged as "no reason captured".)
      reason="$(cat "$err_log" "$out_log" 2>/dev/null \
                | sed -E 's/\x1B\[[0-9;]*[mK]//g' \
                | grep -h '^SKIP:' \
                | head -1 | sed -E 's/^[^:]+: *//' || true)"
      reason_json="$(printf '%s' "${reason:-no reason captured}" | jq -Rs .)"
      printf '{"name":"%s","status":"skip","duration_s":%d,"reason":%s}\n' \
        "$name" "$dur" "$reason_json" >>"$results_jsonl"
      echo "  → SKIP: ${reason:-no reason captured}"
      ;;
    *)
      tail_text="$(tail -20 "$err_log" | jq -Rs . 2>/dev/null || echo '""')"
      fail=$((fail + 1))
      printf '{"name":"%s","status":"fail","duration_s":%d,"rc":%d,"stderr_tail":%s}\n' \
        "$name" "$dur" "$rc" "$tail_text" >>"$results_jsonl"
      echo "--- stderr tail for $name ---"
      tail -20 "$err_log"
      ;;
  esac
  rm -f "$out_log" "$err_log"
done

# Compose JSON report.
results_array="$(jq -s '.' "$results_jsonl")"
jq -n \
  --arg ts "$TIMESTAMP" \
  --argjson results "$results_array" \
  --argjson total "$total" --argjson pass "$pass" \
  --argjson fail "$fail"  --argjson skip "$skip" \
  '{timestamp:$ts, results:$results, summary:{total:$total,pass:$pass,fail:$fail,skip:$skip}}' \
  >"$REPORT_JSON"
rm -f "$results_jsonl"

printf '\n=== summary ===\n'
printf 'total=%d  pass=%d  fail=%d  skip=%d\n' "$total" "$pass" "$fail" "$skip"
printf 'report: %s\n' "$REPORT_JSON"

(( fail == 0 ))
