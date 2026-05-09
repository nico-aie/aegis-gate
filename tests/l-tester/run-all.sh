#!/usr/bin/env bash
# tests/l-tester/run-all.sh
#
# Runs every LT-* test sequentially.  Each test boots + stops the WAF
# independently so they never share state.
#
# Usage:
#   tests/l-tester/run-all.sh [--filter <pattern>]
#
# Options:
#   --filter <pattern>   Run only test files matching the glob pattern
#                        (e.g. --filter "lt-0[12]*")
#
# Exit codes:
#   0  — every test passed
#   1  — one or more tests failed
#
# Output:
#   Human-readable summary + writes machine-readable results to
#   tests/l-tester/reports/run-<timestamp>.json

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

FILTER="${FILTER:-}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT_DIR="$HERE/reports"
REPORT_JSON="$REPORT_DIR/run-$TIMESTAMP.json"

mkdir -p "$REPORT_DIR"

# Parse arguments.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --filter) FILTER="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

# Discover test scripts.
if [[ -n "$FILTER" ]]; then
  # shellcheck disable=SC2207
  scripts=( $(ls "$HERE"/lt-*.sh 2>/dev/null | grep -E "$FILTER" | sort || true) )
else
  scripts=( "$HERE"/lt-*.sh )
fi

if [[ ${#scripts[@]} -eq 0 || ! -f "${scripts[0]}" ]]; then
  echo "No test scripts found in $HERE matching filter='$FILTER'" >&2
  exit 1
fi

echo
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           WAF Interop Contract v2.3 — l-tester              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
printf "  timestamp : %s\n" "$TIMESTAMP"
printf "  scripts   : %d\n" "${#scripts[@]}"
echo

# Tracking vars.
pass=0
fail=0
skip=0
declare -a results=()

for script in "${scripts[@]}"; do
  name="$(basename "$script" .sh)"
  printf "  ┌─ %-52s\n" "$name"

  set +e
  output=$(bash "$script" 2>&1)
  exit_code=$?
  set -e

  if [[ $exit_code -eq 0 ]]; then
    pass=$((pass + 1))
    status="PASS"
    colour="\033[0;32m"
  elif printf '%s' "$output" | grep -q '^SKIP:'; then
    skip=$((skip + 1))
    status="SKIP"
    colour="\033[0;33m"
  else
    fail=$((fail + 1))
    status="FAIL"
    colour="\033[0;31m"
  fi

  # Print indented output.
  printf '%s' "$output" | sed 's/^/  │  /'
  printf "  └─ %b%s\033[0m — %s\n\n" "$colour" "$status" "$name"

  # Accumulate for JSON report.
  # Escape output for JSON embedding (simple approach).
  escaped_output=$(printf '%s' "$output" | \
    python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))" 2>/dev/null \
    || printf '"%s"' "$(printf '%s' "$output" | tr -d '"')")
  results+=("{\"name\":\"$name\",\"status\":\"$status\",\"exit_code\":$exit_code,\"output\":$escaped_output}")
done

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
total=$((pass + fail + skip))
echo "══════════════════════════════════════════════════════════════════"
printf "  TOTAL: %d   PASS: %d   FAIL: %d   SKIP: %d\n" \
  "$total" "$pass" "$fail" "$skip"
echo "══════════════════════════════════════════════════════════════════"
echo

# ------------------------------------------------------------------
# Write JSON report
# ------------------------------------------------------------------
{
  printf '{\n'
  printf '  "timestamp": "%s",\n' "$TIMESTAMP"
  printf '  "total": %d,\n' "$total"
  printf '  "pass":  %d,\n' "$pass"
  printf '  "fail":  %d,\n' "$fail"
  printf '  "skip":  %d,\n' "$skip"
  printf '  "results": [\n'
  for i in "${!results[@]}"; do
    if [[ $i -lt $(( ${#results[@]} - 1 )) ]]; then
      printf '    %s,\n' "${results[$i]}"
    else
      printf '    %s\n'  "${results[$i]}"
    fi
  done
  printf '  ]\n'
  printf '}\n'
} > "$REPORT_JSON"

printf "  Report written: %s\n\n" "$REPORT_JSON"

# Link the latest report for convenience.
ln -sf "$REPORT_JSON" "$REPORT_DIR/latest.json"

if [[ $fail -gt 0 ]]; then
  exit 1
fi
exit 0
