#!/usr/bin/env bash
# DR-T6 — perf re-measure with the always-on interop surface
# active. Reuses the run-07 sweep harness; key question is
# whether the X-WAF-* header stamping + waf_audit.log write per
# request regresses run-07's pooled baseline.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO"

WAF_BIN="${WAF_BIN:-$REPO/target/release/waf}"
OUT_DIR="$REPO/tests/results/run-08-2026-04-30-interop"
WORKER_COUNTS="${WORKER_COUNTS:-2 4 12 auto}"
RPS="${RPS:-1000}"
DURATION="${DURATION:-30s}"
DATA_PORT=18080
ADMIN_PORT=19443
COOLDOWN_S="${COOLDOWN_S:-20}"

[[ -x "$WAF_BIN" ]] || { echo "FAIL: $WAF_BIN missing"; exit 1; }

write_cfg() {
  local workers="$1" interop="$2" cfg="$3"
  local workers_yaml
  if [[ "$workers" == "auto" ]]; then
    workers_yaml='workers: auto'
  else
    workers_yaml="workers: $workers"
  fi
  cat > "$cfg" <<YAML
listeners:
  data: [{ bind: "127.0.0.1:$DATA_PORT", tls: false }]
  admin: { bind: "127.0.0.1:$ADMIN_PORT" }
routes:
  - { id: catch-all, path: "/", match_type: prefix, upstream: stub-pool }
upstreams:
  stub-pool:
    members: [{ addr: "127.0.0.1:8081" }]
state: { backend: in_memory }
runtime:
  $workers_yaml
  blocking_threads: 512
  cpu_affinity: false
  stack_size_kb: 2048
rate_limit:
  buckets:
    - { id: global-ip, scope: global, key: ip, algo: sliding_window, limit: 10000000, window: "1m" }
interop:
  enabled: $interop
  audit_path: "/tmp/waf-perf-audit-$workers-$interop.log"
YAML
}

wait_ready() {
  for _ in $(seq 1 50); do
    if curl -s --max-time 1 "http://127.0.0.1:$ADMIN_PORT/healthz/ready" \
        | grep -q '"status":"ok"'; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

run_one() {
  local workers="$1" interop="$2" label
  if [[ "$workers" == "auto" ]]; then label="auto"; else label="$workers"; fi
  local cfg="/tmp/waf-perf-${interop}-w-$label.yaml"
  local waflog="/tmp/waf-perf-${interop}-w-$label.log"
  local k6log="$OUT_DIR/k6-interop-${interop}-workers-$label.log"

  echo "==> interop=$interop workers=$label"
  write_cfg "$workers" "$interop" "$cfg"

  rm -f "/tmp/waf-perf-audit-$workers-$interop.log"
  "$WAF_BIN" run --config "$cfg" > "$waflog" 2>&1 &
  local pid=$!
  if ! wait_ready; then
    echo "FAIL: interop=$interop/workers=$label — never ready"
    kill -9 "$pid" 2>/dev/null || true
    return 1
  fi

  docker exec aegis-k6 k6 run \
      -e DURATION="$DURATION" \
      -e RPS="$RPS" \
      -e WAF_TARGET="http://host.docker.internal:$DATA_PORT" \
      /scripts/failover-burst.js \
      > "$k6log" 2>&1 || true

  kill -TERM "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  sleep "$COOLDOWN_S"

  local rps p50 p95 success
  rps=$(awk '/^.*http_reqs.*\/s/{ for(i=1;i<=NF;i++) if($i ~ /\/s$/){gsub("/s","",$i);print $i;exit} }' "$k6log")
  p50=$(awk '/^.*allow_latency_ms/{ for(i=1;i<=NF;i++) if($i ~ /^med=/){sub("med=","",$i);print $i;exit} }' "$k6log")
  p95=$(awk '/^.*allow_latency_ms/{ for(i=1;i<=NF;i++) if($i ~ /^p\(95\)=/){sub("p\\(95\\)=","",$i);print $i;exit} }' "$k6log")
  success=$(awk '/^.*allow_success/{ for(i=1;i<=NF;i++) if($i ~ /%$/){print $i;exit} }' "$k6log")

  printf '%-9s | %-8s | %-12s | %-9s | %-9s | %s\n' \
    "$interop" "$label" "${rps:-?}" "${p50:-?}" "${p95:-?}" "${success:-?}"
}

mkdir -p "$OUT_DIR"
{
  printf '%-9s | %-8s | %-12s | %-9s | %-9s | %s\n' \
    "interop" "workers" "RPS" "p50" "p95" "allow_success"
  printf '%-9s-+-%-8s-+-%-12s-+-%-9s-+-%-9s-+-%s\n' \
    "---------" "--------" "------------" "---------" "---------" "-------------"
  for mode in true false; do
    for w in $WORKER_COUNTS; do
      run_one "$w" "$mode"
    done
  done
} | tee "$OUT_DIR/summary.txt"
