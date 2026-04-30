#!/usr/bin/env bash
# UP-T1 perf — pooled vs unpooled vs worker count.
#
# Two sweeps:
#   - "pooled":   max_idle_per_host=32, keep_alive=true (UP-T1 default)
#   - "unpooled": max_idle_per_host=0   (pre-UP-T1 baseline, for diff)
#
# Each at workers ∈ {2, 4, 8, 12, auto} × constant 1000 RPS / 30 s
# of failover-burst.js. The pooled column should saturate the
# host's port budget MUCH later than the unpooled column.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO"

WAF_BIN="${WAF_BIN:-$REPO/target/release/waf}"
OUT_DIR="$REPO/tests/results/run-07-2026-04-30-upstream-pool"
WORKER_COUNTS="${WORKER_COUNTS:-2 4 8 12 auto}"
RPS="${RPS:-1000}"
DURATION="${DURATION:-30s}"
DATA_PORT=18080
ADMIN_PORT=19443
COOLDOWN_S="${COOLDOWN_S:-20}"

[[ -x "$WAF_BIN" ]] || { echo "FAIL: $WAF_BIN missing" >&2; exit 1; }

write_cfg() {
  local workers="$1" pool_mode="$2" cfg_path="$3" workers_yaml conn_yaml
  if [[ "$workers" == "auto" ]]; then
    workers_yaml='workers: auto'
  else
    workers_yaml="workers: $workers"
  fi
  if [[ "$pool_mode" == "pooled" ]]; then
    conn_yaml=$'    connection:\n      max_idle_per_host: 32\n      idle_timeout: 30s\n      keep_alive: true'
  else
    conn_yaml=$'    connection:\n      max_idle_per_host: 0\n      keep_alive: false'
  fi
  cat > "$cfg_path" <<YAML
listeners:
  data:
    - bind: "127.0.0.1:$DATA_PORT"
      tls: false
  admin:
    bind: "127.0.0.1:$ADMIN_PORT"
routes:
  - id: catch-all
    path: "/"
    match_type: prefix
    upstream: stub-pool
upstreams:
  stub-pool:
    members:
      - addr: "127.0.0.1:8081"
$conn_yaml
state:
  backend: in_memory
runtime:
  $workers_yaml
  blocking_threads: 512
  cpu_affinity: false
  stack_size_kb: 2048
rate_limit:
  buckets:
    - id: global-ip
      scope: global
      key: ip
      algo: sliding_window
      limit: 10000000
      window: "1m"
YAML
}

wait_ready() {
  for _ in $(seq 1 50); do
    if curl --silent --max-time 1 "http://127.0.0.1:$ADMIN_PORT/healthz/ready" \
        | grep -q '"status":"ok"'; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

run_one() {
  local workers="$1" pool_mode="$2" label
  if [[ "$workers" == "auto" ]]; then label="auto"; else label="$workers"; fi
  local cfg="/tmp/waf-up-${pool_mode}-w-$label.yaml"
  local waflog="/tmp/waf-up-${pool_mode}-w-$label.log"
  local k6log="$OUT_DIR/k6-${pool_mode}-workers-$label.log"

  echo "==> ${pool_mode} / workers=$label"
  write_cfg "$workers" "$pool_mode" "$cfg"

  "$WAF_BIN" run --config "$cfg" > "$waflog" 2>&1 &
  local pid=$!
  if ! wait_ready; then
    echo "FAIL: ${pool_mode}/workers=$label — never ready"
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

  printf '%-9s | %-10s | %-12s | %-9s | %-9s | %s\n' \
    "$pool_mode" "$label" "${rps:-?}" "${p50:-?}" "${p95:-?}" "${success:-?}"
}

mkdir -p "$OUT_DIR"
{
  printf '%-9s | %-10s | %-12s | %-9s | %-9s | %s\n' \
    "pool" "workers" "RPS" "p50" "p95" "allow_success"
  printf '%-9s-+-%-10s-+-%-12s-+-%-9s-+-%-9s-+-%s\n' \
    "---------" "----------" "------------" "---------" "---------" "-------------"
  for mode in pooled unpooled; do
    for w in $WORKER_COUNTS; do
      run_one "$w" "$mode"
    done
  done
} | tee "$OUT_DIR/summary.txt"
