#!/usr/bin/env bash
# skills/aegis-waf-tester/scripts/start-waf.sh
#
# Boot the WAF in the background ready for the skill's pre-flight.
# Idempotent: if a WAF is already running, this is a no-op.
#
# Steps:
#   1. Ensure the dev Redis is up (cluster state backend).
#   2. Ensure a release binary exists.
#   3. Boot ./target/release/waf with the dev config; redirect logs
#      to /tmp/aegis-waf.log.
#   4. Wait up to 15 s for /healthz/ready to return 200.
#   5. Print the URL trio + log path.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

ADMIN_URL="${AEGIS_ADMIN:-http://127.0.0.1:9443}"
LOG="${AEGIS_WAF_LOG:-/tmp/aegis-waf.log}"

# 1. Already running?  Don't double-boot.
if curl -fsS --max-time 2 "$ADMIN_URL/healthz/live" >/dev/null 2>&1; then
  echo "==> WAF already running (admin healthz/live OK).  Logs: $LOG"
  exit 0
fi

# 2. Redis up.
if ! (echo PING; sleep 0.2) | nc -w 2 127.0.0.1 6379 2>/dev/null | grep -q PONG; then
  echo "==> Starting dev Redis"
  make redis-up >>"$LOG" 2>&1 || {
    echo "FAIL: make redis-up returned non-zero.  Check Docker is running."
    exit 1
  }
fi

# 3. Release binary present?  If not, build it (with the features
#    the dev config expects: redis + geoip).
if [[ ! -x ./target/release/waf ]]; then
  echo "==> No release binary at target/release/waf — building (this takes a couple minutes cold)"
  cargo build --release -p aegis-bin --features "redis geoip" >>"$LOG" 2>&1 || {
    echo "FAIL: cargo build returned non-zero.  Tail:"
    tail -20 "$LOG"
    exit 1
  }
fi

# 4. Boot.  AEGIS_INSECURE_COOKIES=1 so the dev session cookie
#    works on plain HTTP (the run-dev profile serves admin
#    plain-HTTP for first-light convenience).
echo "==> Booting WAF (logs: $LOG)"
AEGIS_INSECURE_COOKIES=1 \
  ./target/release/waf run --config config/dev.yaml \
  >>"$LOG" 2>&1 &

# 5. Wait for ready.
ready=0
for _ in $(seq 1 15); do
  sleep 1
  if curl -fsS --max-time 2 "$ADMIN_URL/healthz/ready" >/dev/null 2>&1; then
    ready=1
    break
  fi
done

if [[ $ready -eq 0 ]]; then
  echo "FAIL: WAF didn't reach /healthz/ready within 15 s.  Tail of log:"
  tail -20 "$LOG"
  exit 1
fi

cat <<EOF
==> WAF live.

  Data plane (HTTP)   http://127.0.0.1:8080/
  Data plane (HTTPS)  https://127.0.0.1:8443/   (-k for self-signed)
  Admin / dashboard   $ADMIN_URL/
  Login               admin / aegis-test-1234
  Logs                $LOG

Re-run pre-flight if you want:

  bash skills/aegis-waf-tester/scripts/verify-waf-up.sh
EOF
