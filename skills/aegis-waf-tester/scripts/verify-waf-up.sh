#!/usr/bin/env bash
# skills/aegis-waf-tester/scripts/verify-waf-up.sh
#
# Pre-flight checks before any test run.  Exits 0 when the WAF is
# ready to accept traffic, exits 2 with a per-failure guidance
# block otherwise.
#
# Goal: never refuse to help.  When something's down, point at the
# exact command that brings it up — never just "FAIL".

set -uo pipefail

ADMIN="${AEGIS_ADMIN:-http://127.0.0.1:9443}"
DATA="${AEGIS_DATA:-http://127.0.0.1:8080}"
REDIS_HOST="${AEGIS_REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${AEGIS_REDIS_PORT:-6379}"

ok=0
fail=0
fail_data=0
fail_admin=0
fail_redis=0

check() {
  local label="$1" cmd="$2"
  if eval "$cmd" >/dev/null 2>&1; then
    printf "  ok   %s\n" "$label"
    ok=$((ok + 1))
  else
    printf "  FAIL %s\n" "$label"
    fail=$((fail + 1))
    case "$label" in
      *data\ plane*)   fail_data=1 ;;
      *admin*)         fail_admin=1 ;;
      *Redis*)         fail_redis=1 ;;
    esac
  fi
}

echo "==> Aegis-Gate pre-flight ($(date -u +%FT%TZ))"

check "data plane TCP open ($DATA)" \
  "curl -fsS -o /dev/null --max-time 3 '$DATA/' || [ \$? -eq 56 ] || [ \$? -eq 22 ]"

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

if [[ $fail -eq 0 ]]; then
  exit 0
fi

# Emit targeted next-steps, not just a wall of text.
echo
echo "==> Next steps"

if [[ $fail_data -eq 1 || $fail_admin -eq 1 ]]; then
  cat <<'EOF'
  WAF is not running.  Boot it:

      bash skills/aegis-waf-tester/scripts/start-waf.sh

  (or, equivalently, in the repo root:)

      make redis-up      # starts the dev Redis if it's not running
      make run-dev &     # boots the WAF in the background
      sleep 5
      bash skills/aegis-waf-tester/scripts/verify-waf-up.sh

EOF
fi

if [[ $fail_redis -eq 1 && $fail_data -eq 0 ]]; then
  cat <<'EOF'
  Redis is not listening.  Bring it up:

      make redis-up

  The data-plane health checks pass without Redis on default
  builds (Redis is the cluster state backend; standalone runs
  fall back to in-memory), but every `make run-*` target wires
  Redis by default.  If you really want a Redis-less smoke,
  run `cargo run --release -p aegis-bin -- run --config
  config/profiles/standalone.yaml` instead — but that's not the
  shipped path.

EOF
fi

if [[ $fail_data -eq 0 && $fail_admin -eq 0 && $fail_redis -eq 0 ]]; then
  cat <<'EOF'
  All ports up but a check still failed — usually a stale binary
  or a config drift.  Rebuild + restart:

      pkill -f 'target/release/waf' 2>/dev/null
      make build
      make run-dev &
      sleep 5
      bash skills/aegis-waf-tester/scripts/verify-waf-up.sh

EOF
fi

cat <<'EOF'
  After fixing, re-run this script.  The skill will pick up where
  it left off.
EOF

exit 2
