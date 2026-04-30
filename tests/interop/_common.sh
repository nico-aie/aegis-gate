#!/usr/bin/env bash
# Shared helpers for tests/interop/*.sh.
#
# Brings up the WAF release binary against a test config, waits
# for `/healthz/ready`, and exposes:
#   - $DATA, $ADMIN — base URLs for the data + admin planes
#   - $SECRET       — the X-Benchmark-Secret value
#   - $AUDIT_LOG    — path to the minimal-schema audit log
#   - require <bin> — abort if a CLI is missing
#   - ok / fail / skip — coloured status lines
#   - start_waf / stop_waf — boot + drain the gateway
#   - count_audit_lines — wc -l "$AUDIT_LOG"

set -euo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
WAF_BIN="${WAF_BIN:-$REPO/target/release/waf}"
CONFIG="${CONFIG:-$REPO/config/dev.yaml}"
DATA="${DATA:-http://127.0.0.1:8080}"
ADMIN="${ADMIN:-http://127.0.0.1:9443}"
SECRET="${SECRET:-waf-hackathon-2026-ctrl}"
AUDIT_LOG="${AUDIT_LOG:-$REPO/waf_audit.log}"

# Per-test scratch dir.
WAF_PID=""
WAF_LOG=""

require() {
  command -v "$1" >/dev/null 2>&1 \
    || { echo "FAIL: missing tool: $1" >&2; exit 1; }
}

ok()   { printf "PASS: %s\n" "$*"; }
fail() { printf "FAIL: %s\n" "$*"; exit 1; }
skip() { printf "SKIP: %s\n" "$*"; exit 0; }

start_waf() {
  [[ -x "$WAF_BIN" ]] || fail "missing $WAF_BIN — build with 'cargo build -p aegis-bin --release --features redis'"
  rm -f "$AUDIT_LOG"
  WAF_LOG="$(mktemp -t waf-interop.XXXXXX)"
  cd "$REPO"
  "$WAF_BIN" run --config "$CONFIG" > "$WAF_LOG" 2>&1 &
  WAF_PID=$!
  for _ in $(seq 1 50); do
    if curl --silent --max-time 1 \
        "$ADMIN/healthz/ready" \
        | grep -q '"status":"ok"'; then
      return 0
    fi
    sleep 0.2
  done
  echo "--- waf log ---"
  tail -40 "$WAF_LOG" >&2 || true
  fail "WAF didn't become ready within 10 s"
}

stop_waf() {
  [[ -n "$WAF_PID" ]] || return 0
  kill -TERM "$WAF_PID" 2>/dev/null || true
  wait "$WAF_PID" 2>/dev/null || true
  WAF_PID=""
}

trap_cleanup() {
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

# Convenience: send a request, capture status + a named header.
# Usage: read_header_status URL HEADER  → echoes "<status>\t<value>"
read_header_status() {
  local url="$1" header="$2"
  local out
  out=$(curl -sI --max-time 3 -o /dev/null \
              -w "%{http_code}" "$url"; \
        echo "X-WAF-PLACEHOLDER")
  # Need the raw headers — re-fetch to read the value.
  local raw
  raw=$(curl -sI --max-time 3 "$url" 2>/dev/null)
  local val
  val=$(printf '%s' "$raw" | awk -v h="$header" '
    BEGIN{ IGNORECASE=1 }
    tolower($1) == tolower(h":") {
      sub(/^[^ ]+ /, ""); sub(/\r$/, ""); print; exit
    }')
  printf '%s\t%s\n' "${out%X-WAF-PLACEHOLDER}" "$val"
}
