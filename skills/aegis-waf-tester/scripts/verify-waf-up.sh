#!/usr/bin/env bash
# skills/aegis-waf-tester/scripts/verify-waf-up.sh
#
# Pre-flight checks before any test run.  Exits 0 when the WAF is
# ready to accept traffic, non-zero with a diagnostic message
# otherwise.

set -uo pipefail

ADMIN="${AEGIS_ADMIN:-http://127.0.0.1:9443}"
DATA="${AEGIS_DATA:-http://127.0.0.1:8080}"
REDIS_HOST="${AEGIS_REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${AEGIS_REDIS_PORT:-6379}"

ok=0
fail=0

check() {
  local label="$1" cmd="$2"
  if eval "$cmd" >/dev/null 2>&1; then
    printf "  ok   %s\n" "$label"
    ok=$((ok + 1))
  else
    printf "  FAIL %s\n" "$label"
    fail=$((fail + 1))
  fi
}

echo "==> Aegis-Gate pre-flight ($(date -u +%FT%TZ))"

check "data plane TCP open ($DATA)" \
  "curl -fsS -o /dev/null --max-time 3 '$DATA/' || [ \$? -eq 56 ] || [ \$? -eq 22 ]"
# 22 = HTTP non-2xx, 56 = receive failure.  Both still mean "WAF is
# accepting TCP connections" — the data plane returns 502 when no
# upstream is wired, which is fine for liveness.

check "admin healthz/live" \
  "curl -fsS --max-time 3 '$ADMIN/healthz/live'"

check "admin healthz/ready" \
  "curl -fsS --max-time 3 '$ADMIN/healthz/ready'"

check "admin /metrics endpoint" \
  "curl -fsS --max-time 3 '$ADMIN/metrics' | grep -q '^waf_'"

check "GET /admin/login renders the login page" \
  "curl -fsS --max-time 3 '$ADMIN/admin/login' | grep -qi '<form id=.login-form'"

check "Redis listening at $REDIS_HOST:$REDIS_PORT" \
  "(echo PING; sleep 0.2) | nc -w 2 $REDIS_HOST $REDIS_PORT 2>/dev/null | grep -q PONG"

echo
echo "==> Result: $ok ok · $fail failed"

if [[ $fail -ne 0 ]]; then
  cat <<EOF >&2

Pre-flight failed.  Common fixes:

  - WAF not running:           make run-dev   (in another terminal)
  - Redis container down:       make redis-up
  - Stale binary:               make build && make run-dev
  - Port collision (8080/9443): lsof -i :8080,:9443

Re-run this script after fixing.
EOF
  exit 1
fi
