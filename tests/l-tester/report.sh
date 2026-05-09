#!/usr/bin/env bash
# tests/l-tester/report.sh
#
# Reads the latest (or a named) run-*.json report and prints a
# human-readable summary with per-test status and a coverage matrix
# mapping each test to its v2.3 contract section.
#
# Usage:
#   tests/l-tester/report.sh                  # reads reports/latest.json
#   tests/l-tester/report.sh <path-to.json>   # reads a named report

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
require() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }; }
require jq

REPORT="${1:-$HERE/reports/latest.json}"

if [[ ! -f "$REPORT" ]]; then
  echo "Report not found: $REPORT" >&2
  echo "Run: tests/l-tester/run-all.sh   to generate one." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Coverage matrix — maps each script to the v2.3 sections it exercises.
# ---------------------------------------------------------------------------
declare -A SECTIONS
SECTIONS["lt-01-sec-control-auth"]="§2.2 Control-plane authentication"
SECTIONS["lt-02-sec-capabilities"]="§2.3 Capabilities response shape"
SECTIONS["lt-03-sec-reset-state"]="§2.4 reset_state atomicity + audit preservation"
SECTIONS["lt-04-sec-set-profile"]="§2.5 set_profile scopes + unsupported handling"
SECTIONS["lt-05-sec-flush-cache"]="§2.6 flush_cache"
SECTIONS["lt-06-func-obs-headers"]="§5.1/§5.3 Observability headers on every response"
SECTIONS["lt-07-func-mode-semantics"]="§2.5/§2.7/§5.3 enforce vs log_only semantics"
SECTIONS["lt-08-func-decision-classes"]="§3.1 Threat category → action mapping"
SECTIONS["lt-09-func-audit-log"]="§6 Audit log schema, JSONL, IP semantics"
SECTIONS["lt-10-func-correlation"]="§5.3/§4 X-WAF-Request-Id ↔ audit correlation"
SECTIONS["lt-11-func-caching"]="§9 Caching observability (BYPASS/MISS/HIT)"
SECTIONS["lt-12-func-source-ip"]="§10 Source IP trust model"
SECTIONS["lt-13-func-log-only-passthrough"]="§7 log_only passthrough + decision normalization"

# ---------------------------------------------------------------------------
# Print header
# ---------------------------------------------------------------------------
ts=$(jq -r '.timestamp' "$REPORT")
total=$(jq -r '.total' "$REPORT")
pass=$(jq -r '.pass'  "$REPORT")
fail=$(jq -r '.fail'  "$REPORT")
skips=$(jq -r '.skip'  "$REPORT")

echo
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║         WAF Interop Contract v2.3 — l-tester Test Report            ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
printf "  Run timestamp : %s\n" "$ts"
printf "  Report file   : %s\n" "$REPORT"
printf "  Total: %-4d   PASS: %-4d   FAIL: %-4d   SKIP: %-4d\n" \
  "$total" "$pass" "$fail" "$skips"
echo

# ---------------------------------------------------------------------------
# Per-test table
# ---------------------------------------------------------------------------
printf "  %-42s  %-6s  %s\n" "Test" "Status" "Contract section"
printf "  %s  %s  %s\n" "$(printf '%.0s─' {1..42})" "──────" "$(printf '%.0s─' {1..50})"

while IFS= read -r name; do
  status=$(jq -r --arg n "$name" '.results[] | select(.name==$n) | .status' "$REPORT")
  section="${SECTIONS[$name]:-—}"
  case "$status" in
    PASS) marker="\033[0;32m✓\033[0m";;
    FAIL) marker="\033[0;31m✗\033[0m";;
    SKIP) marker="\033[0;33m~\033[0m";;
    *)    marker=" ";;
  esac
  printf "  %b %-40s  %-6s  %s\n" "$marker" "$name" "$status" "$section"
done < <(jq -r '.results[].name' "$REPORT")

echo
echo "──────────────────────────────────────────────────────────────────────"

# ---------------------------------------------------------------------------
# Print FAIL details
# ---------------------------------------------------------------------------
fail_count=$(jq '[.results[] | select(.status=="FAIL")] | length' "$REPORT")
if [[ "$fail_count" -gt 0 ]]; then
  echo
  echo "  FAILED TEST DETAILS:"
  echo
  while IFS= read -r name; do
    echo "  ┌─ $name"
    jq -r --arg n "$name" \
      '.results[] | select(.name==$n) | .output' "$REPORT" \
      | sed 's/^/  │  /'
    echo "  └─ FAIL"
    echo
  done < <(jq -r '.results[] | select(.status=="FAIL") | .name' "$REPORT")
fi

# ---------------------------------------------------------------------------
# Exit code mirrors the run result
# ---------------------------------------------------------------------------
if [[ "$fail" -gt 0 ]]; then
  printf "\n  \033[0;31mRESULT: FAIL (%d test(s) failed)\033[0m\n\n" "$fail"
  exit 1
else
  printf "\n  \033[0;32mRESULT: ALL PASS\033[0m\n\n"
  exit 0
fi
