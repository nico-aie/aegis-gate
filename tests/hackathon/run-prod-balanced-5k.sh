#!/usr/bin/env bash
# tests/hackathon/run-prod-balanced-5k.sh — sustained 5k+ RPS run on
# the prod-balanced semantic config.
#
# Differences vs run.sh:
#   - Upstream started with --latency-ms 0 (we want WAF cost, not the
#     Python upstream's synthetic latency)
#   - WAF_CONFIG defaults to tests/hackathon/configs/prod-balanced-5k.yaml
#   - K6_SCRIPT defaults to tests/hackathon/k6/prod-balanced-5k.js
#   - DURATION default 5m (faster iteration than 15m for tuning)
#   - LEGIT_VUS / CRAWLER_VUS / ATTACKER_VUS overridable; defaults
#     in the k6 script (240 / 60 / 100)

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"

DURATION="${DURATION:-5m}"
AEGIS_BIN="${AEGIS_BIN:-$REPO/target/release/waf}"
WAF_CONFIG="${WAF_CONFIG:-$HERE/configs/prod-balanced-5k.yaml}"
ADMIN="${ADMIN:-http://127.0.0.1:9443}"
DATA="${DATA:-http://127.0.0.1:8080}"
K6_SCRIPT="${K6_SCRIPT:-$HERE/k6/prod-balanced-5k.js}"
UPSTREAM_LATENCY_MS="${UPSTREAM_LATENCY_MS:-0}"
# UPSTREAM_BIN: optional path to a pre-built upstream binary. When unset,
# falls back to the bundled Python server.py (good enough for ≤1k RPS;
# becomes the bottleneck above that). Use /tmp/fast-upstream (Go) for
# 5k+ RPS testing.
UPSTREAM_BIN="${UPSTREAM_BIN:-}"

ts="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${RUN_DIR:-$REPO/tests/results/run-perf-5krps-prod-balanced-2026-05-02}"
mkdir -p "$RUN_DIR/logs" "$RUN_DIR/artifacts"
echo "run dir: $RUN_DIR"
echo "timestamp: $ts"

UPSTREAM_PID=""
WAF_PID=""

cleanup() {
  echo
  echo "==> cleanup"
  [[ -n "$WAF_PID"      ]] && kill "$WAF_PID"      2>/dev/null || true
  [[ -n "$UPSTREAM_PID" ]] && kill "$UPSTREAM_PID" 2>/dev/null || true
  pkill -f "$AEGIS_BIN" 2>/dev/null || true
  pkill -f "tests/hackathon/upstream/server.py" 2>/dev/null || true
  [[ -n "$UPSTREAM_BIN" ]] && pkill -f "$UPSTREAM_BIN" 2>/dev/null || true
}
trap cleanup EXIT

if [[ ! -x "$AEGIS_BIN" ]]; then
  echo "FAIL: $AEGIS_BIN not executable. Build with: cargo build --release -p aegis-bin --features redis" >&2
  exit 1
fi

if [[ -n "$UPSTREAM_BIN" ]]; then
  if [[ ! -x "$UPSTREAM_BIN" ]]; then
    echo "FAIL: UPSTREAM_BIN=$UPSTREAM_BIN not executable" >&2
    exit 1
  fi
  echo "==> starting upstream (UPSTREAM_BIN=$UPSTREAM_BIN)"
  "$UPSTREAM_BIN" > "$RUN_DIR/logs/upstream.log" 2>&1 &
  UPSTREAM_PID=$!
else
  echo "==> starting upstream (python3 server.py --latency-ms $UPSTREAM_LATENCY_MS)"
  python3 "$HERE/upstream/server.py" --bind 127.0.0.1 --port 9999 \
      --latency-ms "$UPSTREAM_LATENCY_MS" \
    > "$RUN_DIR/logs/upstream.log" 2>&1 &
  UPSTREAM_PID=$!
fi

for _ in $(seq 1 25); do
  if curl --silent --max-time 1 http://127.0.0.1:9999/health -o /dev/null; then
    break
  fi
  sleep 0.2
done
echo "    upstream pid=$UPSTREAM_PID"

echo "==> starting WAF ($WAF_CONFIG)"
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

sanity=$(curl --silent --max-time 3 -o /dev/null -w "%{http_code}" "$DATA/health")
if [[ "$sanity" != "200" ]]; then
  echo "FAIL: sanity GET $DATA/health returned $sanity (expected 200)" >&2
  tail -30 "$RUN_DIR/logs/waf.log" >&2 || true
  exit 1
fi

echo "==> capturing before-stats"
curl -sS --max-time 3 "$ADMIN/api/stats"               -o "$RUN_DIR/artifacts/waf-stats-before.json" || true
curl -sS --max-time 3 "$ADMIN/api/attacks/distribution" -o "$RUN_DIR/artifacts/attacks-before.json"   || true
curl -sS --max-time 3 "$ADMIN/metrics"                  -o "$RUN_DIR/artifacts/metrics-before.txt"   || true
audit_before_lines=0
[[ -f "$REPO/waf_audit.log" ]] && audit_before_lines=$(wc -l < "$REPO/waf_audit.log" | tr -d ' ')
echo "    audit lines before: $audit_before_lines"
echo "$audit_before_lines" > "$RUN_DIR/artifacts/audit-before-lines.txt"

echo "==> running k6 ($DURATION)"
set +e
# 2026-05-17: prior `${VAR:+VAR=$VAR}` indirection didn't survive bash
# tokenisation (expanded `VAR=val` becomes a positional arg, not an
# inline env-var assignment), so the orchestrator failed with
# `LEGIT_VUS=120: command not found`. Plain exports work — the k6
# script reads from the env regardless of how it got there.
export WAF_TARGET="$DATA" DURATION="$DURATION"
[[ -n "${LEGIT_VUS:-}"    ]] && export LEGIT_VUS
[[ -n "${CRAWLER_VUS:-}"  ]] && export CRAWLER_VUS
[[ -n "${ATTACKER_VUS:-}" ]] && export ATTACKER_VUS
k6 run \
    --summary-export "$RUN_DIR/artifacts/k6-summary.json" \
    "$K6_SCRIPT" \
    2>&1 | tee "$RUN_DIR/logs/k6.log" | tail -60
k6_rc=$?
set -e
echo "    k6 exit: $k6_rc"

echo "==> capturing after-stats"
curl -sS --max-time 3 "$ADMIN/api/stats"               -o "$RUN_DIR/artifacts/waf-stats-after.json" || true
curl -sS --max-time 3 "$ADMIN/api/attacks/distribution" -o "$RUN_DIR/artifacts/attacks-after.json"   || true
curl -sS --max-time 3 "$ADMIN/metrics"                  -o "$RUN_DIR/artifacts/metrics-after.txt"   || true
audit_after_lines=0
[[ -f "$REPO/waf_audit.log" ]] && audit_after_lines=$(wc -l < "$REPO/waf_audit.log" | tr -d ' ')
echo "    audit lines after:  $audit_after_lines"
echo "$audit_after_lines" > "$RUN_DIR/artifacts/audit-after-lines.txt"

# Re-use the existing summary.sh — it reads from $RUN_DIR/artifacts/.
bash "$HERE/summary.sh" "$RUN_DIR" > "$RUN_DIR/RUN-SUMMARY.md"
echo
echo "==> done. summary at $RUN_DIR/RUN-SUMMARY.md"
echo
cat "$RUN_DIR/RUN-SUMMARY.md"
