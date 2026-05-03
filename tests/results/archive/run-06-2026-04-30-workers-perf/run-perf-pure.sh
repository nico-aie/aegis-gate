#!/usr/bin/env bash
# Pure-WAF throughput vs `runtime.workers`.
#
# Same boot-and-sweep harness as run-perf.sh but the load
# target is the admin /healthz/ready endpoint — no upstream
# forwarder, no per-request TCP connect to httpbin. Lets us
# measure how Layer-1 worker count scales the in-process
# pipeline without the upstream-pool ceiling masking the
# differences.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO"

WAF_BIN="${WAF_BIN:-$REPO/target/release/waf}"
OUT_DIR="$REPO/tests/results/run-06-2026-04-30-workers-perf"
WORKER_COUNTS="${WORKER_COUNTS:-2 4 8 12 auto}"
VUS="${VUS:-50}"
DURATION="${DURATION:-30s}"
DATA_PORT=18080
ADMIN_PORT=19443
COOLDOWN_S="${COOLDOWN_S:-10}"

[[ -x "$WAF_BIN" ]] || {
  echo "FAIL: $WAF_BIN missing" >&2; exit 1;
}

write_cfg() {
  local workers="$1" cfg_path="$2" workers_yaml
  if [[ "$workers" == "auto" ]]; then
    workers_yaml='workers: auto'
  else
    workers_yaml="workers: $workers"
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
    lb: round_robin
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
  local workers="$1" label
  if [[ "$workers" == "auto" ]]; then label="auto"; else label="$workers"; fi
  local cfg="/tmp/waf-perf-pure-w-$label.yaml"
  local waflog="/tmp/waf-perf-pure-w-$label.log"
  local k6log="$OUT_DIR/k6-pure-workers-$label.log"

  echo "==> workers=$label (pure /healthz/ready)"
  write_cfg "$workers" "$cfg"

  "$WAF_BIN" run --config "$cfg" > "$waflog" 2>&1 &
  local pid=$!
  if ! wait_ready; then
    echo "FAIL: workers=$label — never ready"
    kill -9 "$pid" 2>/dev/null || true
    return 1
  fi

  local effective
  effective=$(curl --silent --max-time 2 \
      "http://127.0.0.1:$ADMIN_PORT/api/runtime" \
      | sed -E 's/.*"workers":([0-9]+).*/\1/')

  docker exec aegis-k6 k6 run \
      -e DURATION="$DURATION" \
      -e VUS="$VUS" \
      -e WAF_ADMIN="http://host.docker.internal:$ADMIN_PORT" \
      /scripts/admin-healthz.js \
      > "$k6log" 2>&1 || true

  kill -TERM "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  sleep "$COOLDOWN_S"

  local rps p50 p95 success
  rps=$(awk '/^.*http_reqs.*\/s/{ for(i=1;i<=NF;i++) if($i ~ /\/s$/){gsub("/s","",$i);print $i;exit} }' "$k6log")
  p50=$(awk '/^.*ready_latency_ms/{ for(i=1;i<=NF;i++) if($i ~ /^med=/){sub("med=","",$i);print $i;exit} }' "$k6log")
  p95=$(awk '/^.*ready_latency_ms/{ for(i=1;i<=NF;i++) if($i ~ /^p\(95\)=/){sub("p\\(95\\)=","",$i);print $i;exit} }' "$k6log")
  success=$(awk '/^.*ready_success/{ for(i=1;i<=NF;i++) if($i ~ /%$/){print $i;exit} }' "$k6log")

  printf '%-10s | %-9s | %-12s | %-9s | %-9s | %s\n' \
    "$label" "${effective:-?}" "${rps:-?}" "${p50:-?}" "${p95:-?}" "${success:-?}"
}

mkdir -p "$OUT_DIR"
{
  printf '%-10s | %-9s | %-12s | %-9s | %-9s | %s\n' \
    "config" "effective" "RPS" "p50" "p95" "ready_success"
  printf '%-10s-+-%-9s-+-%-12s-+-%-9s-+-%-9s-+-%s\n' \
    "----------" "---------" "------------" "---------" "---------" "-------------"
  for w in $WORKER_COUNTS; do
    run_one "$w"
  done
} | tee "$OUT_DIR/summary-pure.txt"
