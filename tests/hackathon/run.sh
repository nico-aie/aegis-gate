#!/usr/bin/env bash
# tests/hackathon/run.sh — orchestrate a 15-min Round-1 stress test.
#
# 1. Boot the upstream (mock or operator-supplied UPSTREAM_BIN).
# 2. Boot the WAF on the bench config (or AEGIS_BIN override).
# 3. Capture before-stats from the WAF.
# 4. Run k6 mixed-traffic for $DURATION.
# 5. Capture after-stats.
# 6. Stop everything.
# 7. Render a summary.md report into the run dir.
#
# Env knobs:
#   DURATION=15m                          k6 run length
#   AEGIS_BIN=./target/release/waf        WAF binary path
#   UPSTREAM_BIN=                          operator-supplied upstream;
#                                          if unset, we run the bundled mock
#   WAF_CONFIG=tests/hackathon/configs/bench.yaml
#   ADMIN=http://127.0.0.1:9443
#   DATA=http://127.0.0.1:8080
#   K6_SCRIPT=tests/hackathon/k6/mixed-15min.js

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"

DURATION="${DURATION:-15m}"
AEGIS_BIN="${AEGIS_BIN:-$REPO/target/release/waf}"
UPSTREAM_BIN="${UPSTREAM_BIN:-}"
WAF_CONFIG="${WAF_CONFIG:-$HERE/configs/bench.yaml}"
ADMIN="${ADMIN:-http://127.0.0.1:9443}"
DATA="${DATA:-http://127.0.0.1:8080}"
K6_SCRIPT="${K6_SCRIPT:-$HERE/k6/mixed-15min.js}"
SECRET="${BENCHMARK_SECRET:-waf-hackathon-2026-ctrl}"

ts="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$HERE/results/run-$ts"
mkdir -p "$RUN_DIR/logs" "$RUN_DIR/artifacts"
echo "run dir: $RUN_DIR"

UPSTREAM_PID=""
WAF_PID=""

cleanup() {
  echo
  echo "==> cleanup"
  [[ -n "$WAF_PID" ]]      && kill "$WAF_PID"      2>/dev/null || true
  [[ -n "$UPSTREAM_PID" ]] && kill "$UPSTREAM_PID" 2>/dev/null || true
  pkill -f "$AEGIS_BIN" 2>/dev/null || true
  if [[ -z "$UPSTREAM_BIN" ]]; then
    pkill -f "tests/hackathon/upstream/server.py" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Sanity: AEGIS_BIN exists
if [[ ! -x "$AEGIS_BIN" ]]; then
  echo "FAIL: $AEGIS_BIN not executable. Build with: cargo build --release -p aegis-bin" >&2
  exit 1
fi

# 1. Upstream
echo "==> starting upstream"
if [[ -n "$UPSTREAM_BIN" ]]; then
  if [[ ! -x "$UPSTREAM_BIN" ]]; then
    echo "FAIL: UPSTREAM_BIN=$UPSTREAM_BIN not executable" >&2
    exit 1
  fi
  "$UPSTREAM_BIN" > "$RUN_DIR/logs/upstream.log" 2>&1 &
  UPSTREAM_PID=$!
else
  python3 "$HERE/upstream/server.py" --bind 127.0.0.1 --port 9999 \
    > "$RUN_DIR/logs/upstream.log" 2>&1 &
  UPSTREAM_PID=$!
fi

# Wait for upstream
for _ in $(seq 1 25); do
  if curl --silent --max-time 1 http://127.0.0.1:9999/health -o /dev/null; then
    break
  fi
  sleep 0.2
done
echo "    upstream pid=$UPSTREAM_PID"

# 2. WAF
echo "==> starting WAF"
"$AEGIS_BIN" run --config "$WAF_CONFIG" \
  > "$RUN_DIR/logs/waf.log" 2>&1 &
WAF_PID=$!
for _ in $(seq 1 50); do
  if curl --silent --max-time 1 "$ADMIN/healthz/ready" \
       | grep -q '"status":"ok"'; then
    break
  fi
  sleep 0.2
done
echo "    waf pid=$WAF_PID"

# Quick sanity: a benign request should succeed
sanity=$(curl --silent --max-time 3 -o /dev/null -w "%{http_code}" "$DATA/health")
if [[ "$sanity" != "200" ]]; then
  echo "FAIL: sanity GET $DATA/health returned $sanity (expected 200)" >&2
  tail -30 "$RUN_DIR/logs/waf.log" >&2 || true
  exit 1
fi

# 3. Before-stats
echo "==> capturing before-stats"
curl -sS --max-time 3 "$ADMIN/api/stats"               -o "$RUN_DIR/artifacts/waf-stats-before.json" || true
curl -sS --max-time 3 "$ADMIN/api/attacks/distribution" -o "$RUN_DIR/artifacts/attacks-before.json"   || true
audit_before_lines=0
[[ -f "$REPO/waf_audit.log" ]] && audit_before_lines=$(wc -l < "$REPO/waf_audit.log" | tr -d ' ')
echo "    audit lines before: $audit_before_lines"
echo "$audit_before_lines" > "$RUN_DIR/artifacts/audit-before-lines.txt"

# 4. k6 — `set +e` so a threshold breach still produces a summary.
echo "==> running k6 ($DURATION)"
set +e
WAF_TARGET="$DATA" DURATION="$DURATION" \
  k6 run \
    --summary-export "$RUN_DIR/artifacts/k6-summary.json" \
    "$K6_SCRIPT" \
    2>&1 | tee "$RUN_DIR/logs/k6.log" | tail -50
k6_rc=$?
set -e
echo "    k6 exit: $k6_rc"

# 5. After-stats
echo "==> capturing after-stats"
curl -sS --max-time 3 "$ADMIN/api/stats"               -o "$RUN_DIR/artifacts/waf-stats-after.json" || true
curl -sS --max-time 3 "$ADMIN/api/attacks/distribution" -o "$RUN_DIR/artifacts/attacks-after.json"   || true
audit_after_lines=0
[[ -f "$REPO/waf_audit.log" ]] && audit_after_lines=$(wc -l < "$REPO/waf_audit.log" | tr -d ' ')
echo "    audit lines after:  $audit_after_lines"
echo "$audit_after_lines" > "$RUN_DIR/artifacts/audit-after-lines.txt"

# 6. Render summary
bash "$HERE/summary.sh" "$RUN_DIR" > "$RUN_DIR/summary.md"
echo
echo "==> done. summary at $RUN_DIR/summary.md"
echo
cat "$RUN_DIR/summary.md"
