#!/usr/bin/env bash
# tests/l-tester/_common.sh
#
# Shared helpers for every tests/l-tester/lt-*.sh script.
#
# Exports:
#   $REPO        — repository root
#   $WAF_BIN     — path to release binary  (./target/release/waf)
#   $CONFIG      — WAF config file          (config/dev.yaml)
#   $DATA        — data-plane base URL      (http://127.0.0.1:8080)
#   $ADMIN       — admin-plane base URL     (http://127.0.0.1:9443)
#   $SECRET      — X-Benchmark-Secret value
#   $AUDIT_LOG   — audit log path           (./waf_audit.log)
#
# Functions:
#   require <bin>         — abort if a CLI is missing
#   ok  <msg>             — green PASS line
#   fail <msg>            — red FAIL line + exit 1
#   skip <msg>            — yellow SKIP line + exit 0
#   start_waf             — boot WAF + wait for /healthz/ready
#   stop_waf              — SIGTERM + wait
#   trap_cleanup          — registered via `trap trap_cleanup EXIT`
#   count_audit_lines     — wc -l $AUDIT_LOG (0 if absent)
#   ctrl_post <path> [body] — authenticated POST to admin control plane
#   ctrl_get  <path>        — authenticated GET to admin control plane
#   header_value <raw> <name>           — extract header value (case-insensitive)
#   assert_header_present <raw> <name>  — non-empty header → 0
#   assert_header_in_set  <raw> <name> <val...> — value in set → 0
#   assert_header_matches <raw> <name> <regex>  — value matches ERE → 0
#   assert_json_eq    <body> <jq-path> <expected> — jq -r path == expected → 0
#   assert_json_present <body> <jq-path>           — type != null → 0
#   uuid_valid <val>  — UUID v4 shape check → 0

set -euo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
WAF_BIN="${WAF_BIN:-$REPO/target/release/waf}"
CONFIG="${CONFIG:-$REPO/config/dev.yaml}"
DATA="${DATA:-http://127.0.0.1:8080}"
ADMIN="${ADMIN:-http://127.0.0.1:9443}"
SECRET="${SECRET:-waf-hackathon-2026-ctrl}"
AUDIT_LOG="${AUDIT_LOG:-$REPO/waf_audit.log}"

WAF_PID=""
WAF_LOG=""

# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------
_red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
_green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
_yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }

require() {
  command -v "$1" >/dev/null 2>&1 \
    || { echo "FAIL: missing tool: $1" >&2; exit 1; }
}

ok()   { _green "PASS: $*"; }
fail() { _red   "FAIL: $*"; exit 1; }
skip() { _yellow "SKIP: $*"; exit 0; }

# ---------------------------------------------------------------------------
# WAF lifecycle
#
# Set SKIP_WAF_BOOT=1 to skip starting/stopping the WAF binary when a
# WAF (or mock-waf) is already running externally.  The test scripts
# will still call start_waf / stop_waf; this flag makes them no-ops so
# the external instance is used instead.
# ---------------------------------------------------------------------------
SKIP_WAF_BOOT="${SKIP_WAF_BOOT:-0}"

start_waf() {
  # If SKIP_WAF_BOOT is set, just verify the WAF is reachable.
  if [[ "$SKIP_WAF_BOOT" == "1" ]]; then
    local attempts=0
    while (( attempts++ < 25 )); do
      if curl --silent --max-time 1 "$ADMIN/healthz/ready" \
           | grep -q '"status":"ok"'; then
        return 0
      fi
      sleep 0.2
    done
    fail "WAF at $ADMIN does not respond to /healthz/ready (SKIP_WAF_BOOT=1 but WAF not running)"
  fi

  [[ -x "$WAF_BIN" ]] \
    || fail "WAF binary not found at $WAF_BIN — run: cargo build -p aegis-bin --release --features redis"
  rm -f "$AUDIT_LOG"
  WAF_LOG="$(mktemp -t l-tester-waf.XXXXXX)"
  cd "$REPO"
  "$WAF_BIN" run --config "$CONFIG" > "$WAF_LOG" 2>&1 &
  WAF_PID=$!
  local attempts=0
  while (( attempts++ < 50 )); do
    if curl --silent --max-time 1 "$ADMIN/healthz/ready" \
         | grep -q '"status":"ok"'; then
      return 0
    fi
    sleep 0.2
  done
  echo "--- WAF stderr (last 40 lines) ---" >&2
  tail -40 "$WAF_LOG" >&2 || true
  fail "WAF did not become ready within 10 s"
}

stop_waf() {
  [[ "$SKIP_WAF_BOOT" == "1" ]] && return 0
  [[ -n "$WAF_PID" ]] || return 0
  kill -TERM "$WAF_PID" 2>/dev/null || true
  wait "$WAF_PID" 2>/dev/null || true
  WAF_PID=""
}

trap_cleanup() {
  [[ "$SKIP_WAF_BOOT" == "1" ]] && return 0
  stop_waf
  pkill -9 -f 'target/release/waf' 2>/dev/null || true
}

count_audit_lines() {
  if [[ -f "$AUDIT_LOG" ]]; then
    wc -l < "$AUDIT_LOG" | tr -d ' '
  else
    echo 0
  fi
}

# ---------------------------------------------------------------------------
# Control-plane helpers
# ---------------------------------------------------------------------------
ctrl_post() {
  local path="$1"
  local body="${2:-}"
  if [[ -n "$body" ]]; then
    curl -s --max-time 5 -X POST \
         -H "X-Benchmark-Secret: $SECRET" \
         -H "content-type: application/json" \
         -d "$body" \
         "$ADMIN$path"
  else
    curl -s --max-time 5 -X POST \
         -H "X-Benchmark-Secret: $SECRET" \
         "$ADMIN$path"
  fi
}

ctrl_get() {
  local path="$1"
  curl -s --max-time 5 \
       -H "X-Benchmark-Secret: $SECRET" \
       "$ADMIN$path"
}

# Status-only variants (no body capture).
ctrl_post_status() {
  local path="$1"
  local body="${2:-}"
  local extra_headers=()
  if [[ -n "$body" ]]; then
    extra_headers+=(-H "content-type: application/json" -d "$body")
  fi
  curl -s --max-time 5 -X POST \
       "${extra_headers[@]:-}" \
       -o /dev/null -w '%{http_code}' \
       "$ADMIN$path"
}

ctrl_get_status() {
  local path="$1"
  local extra_secret="${2:-$SECRET}"
  curl -s --max-time 5 \
       -H "X-Benchmark-Secret: $extra_secret" \
       -o /dev/null -w '%{http_code}' \
       "$ADMIN$path"
}

ctrl_get_status_no_auth() {
  curl -s --max-time 5 \
       -o /dev/null -w '%{http_code}' \
       "$ADMIN/__waf_control/capabilities"
}

# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------
# Extract header value from raw `curl -sI` output, case-insensitive.
header_value() {
  local raw="$1" name="$2"
  printf '%s' "$raw" | awk -v h="$name" '
    BEGIN { IGNORECASE=1 }
    tolower($1) == tolower(h) ":" {
      sub(/^[^:]+:[ \t]*/, "")
      sub(/\r$/, "")
      print
      exit
    }'
}

assert_header_present() {
  local raw="$1" name="$2"
  local v
  v=$(header_value "$raw" "$name")
  [[ -n "$v" ]]
}

assert_header_in_set() {
  local raw="$1" name="$2"
  shift 2
  local v
  v=$(header_value "$raw" "$name")
  for allowed in "$@"; do
    [[ "$v" == "$allowed" ]] && return 0
  done
  echo "  header $name = '$v'; allowed: $*" >&2
  return 1
}

assert_header_matches() {
  local raw="$1" name="$2" regex="$3"
  local v
  v=$(header_value "$raw" "$name")
  [[ "$v" =~ $regex ]]
}

# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------
assert_json_eq() {
  local body="$1" path="$2" expected="$3"
  local got
  got=$(printf '%s' "$body" | jq -r "$path" 2>/dev/null || echo '__JQ_ERR__')
  if [[ "$got" != "$expected" ]]; then
    echo "  jq $path → '$got'; expected '$expected'" >&2
    return 1
  fi
}

assert_json_present() {
  local body="$1" path="$2"
  local got
  got=$(printf '%s' "$body" | jq "$path | type" 2>/dev/null || echo 'null')
  [[ "$got" != 'null' && -n "$got" ]]
}

# ---------------------------------------------------------------------------
# UUID v4 shape validator
# ---------------------------------------------------------------------------
uuid_valid() {
  local v="$1"
  [[ "$v" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
}

# ---------------------------------------------------------------------------
# Convenience: reset WAF to a known clean enforce state.
# ---------------------------------------------------------------------------
reset_to_enforce() {
  ctrl_post /__waf_control/reset_state >/dev/null
  ctrl_post /__waf_control/set_profile '{"scope":"all","mode":"enforce"}' >/dev/null
}
