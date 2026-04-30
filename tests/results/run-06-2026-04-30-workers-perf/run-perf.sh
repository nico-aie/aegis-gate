#!/usr/bin/env bash
# Single-node throughput vs `runtime.workers`.
#
# For each worker count in `WORKER_COUNTS`:
#   1. Generate a config with that count.
#   2. Boot the WAF release binary against it.
#   3. Wait for /healthz/ready.
#   4. Drive 15s of `failover-burst.js` at 1000 RPS.
#   5. Record RPS, p50/p95 latency, allow_success.
#   6. Stop the WAF gracefully, wait for socket release.
#
# Why constant-arrival-rate:
#   constant-vus saturates the local TCP ephemeral-port budget
#   (see tests/cluster/06-mid-burst-failover.sh notes). We want
#   to measure WAF throughput, not host TCP behaviour.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO"

WAF_BIN="${WAF_BIN:-$REPO/target/release/waf}"
OUT_DIR="$REPO/tests/results/run-06-2026-04-30-workers-perf"
WORKER_COUNTS="${WORKER_COUNTS:-2 4 8 12 auto}"
# 200 RPS × 30 s = 6 000 reqs total — well under the host's
# ~270 RPS ephemeral-port ceiling per source IP (mac default
# 16 k ports × 60 s TIME_WAIT). The upstream forwarder still
# does new TCP per request until B6 lands a connection pool;
# higher rates here just measure host TCP, not WAF throughput.
RPS="${RPS:-200}"
DURATION="${DURATION:-30s}"
# Cooldown between iterations — gives TIME_WAIT time to drain
# so each run starts from a clean port budget.
COOLDOWN_S="${COOLDOWN_S:-30}"
DATA_PORT=18080
ADMIN_PORT=19443

if [[ ! -x "$WAF_BIN" ]]; then
  echo "FAIL: $WAF_BIN missing — build with: cargo build -p aegis-bin --release --features redis" >&2
  exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -q '^aegis-k6$'; then
  echo "FAIL: aegis-k6 container not running — bring up the test stack" >&2
  exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -q '^aegis-httpbin$'; then
  echo "FAIL: aegis-httpbin container not running — bring up the test stack" >&2
  exit 1
fi

write_cfg() {
  local workers="$1"
  local cfg_path="$2"
  local workers_yaml
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

# Layer-1 — the knob under test
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
      # High enough not to bottleneck the perf test.
      limit: 10000000
      window: "1m"
YAML
}

wait_ready() {
  local i
  for i in $(seq 1 50); do
    if curl --silent --max-time 1 "http://127.0.0.1:$ADMIN_PORT/healthz/ready" \
        | grep -q '"status":"ok"'; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

run_one() {
  local workers="$1"
  local label
  if [[ "$workers" == "auto" ]]; then
    label="auto"
  else
    label="$workers"
  fi
  local cfg="/tmp/waf-perf-w-$label.yaml"
  local waflog="/tmp/waf-perf-w-$label.log"
  local k6log="$OUT_DIR/k6-workers-$label.log"

  echo "==> workers=$label"
  write_cfg "$workers" "$cfg"

  "$WAF_BIN" run --config "$cfg" > "$waflog" 2>&1 &
  local pid=$!

  if ! wait_ready; then
    echo "FAIL: workers=$label — node never became ready"
    kill -9 "$pid" 2>/dev/null || true
    return 1
  fi

  # Pull the effective worker count back from the admin endpoint.
  local effective
  effective=$(curl --silent --max-time 2 \
                "http://127.0.0.1:$ADMIN_PORT/api/runtime" \
              | sed -E 's/.*"workers":([0-9]+).*/\1/')
  echo "    effective workers = $effective"

  docker exec aegis-k6 k6 run \
      -e DURATION="$DURATION" \
      -e RPS="$RPS" \
      -e WAF_TARGET="http://host.docker.internal:$DATA_PORT" \
      /scripts/failover-burst.js \
      > "$k6log" 2>&1 || true

  # Stop the WAF gracefully; wait long enough for the SIGTERM
  # drain (5s default) plus a little slack for sockets to close.
  kill -TERM "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  # Cooldown so TIME_WAIT'd ports from this run don't bleed
  # into the next iteration. Skipped on the last config.
  sleep "$COOLDOWN_S"

  # Extract the headline numbers.
  local rps p50 p95 success
  rps=$(awk '/^.*http_reqs.*\/s/{ for(i=1;i<=NF;i++) if($i ~ /\/s$/){gsub("/s","",$i);print $i;exit} }' "$k6log")
  p50=$(awk '/^.*allow_latency_ms/{ for(i=1;i<=NF;i++) if($i ~ /^med=/){sub("med=","",$i);print $i;exit} }' "$k6log")
  p95=$(awk '/^.*allow_latency_ms/{ for(i=1;i<=NF;i++) if($i ~ /^p\(95\)=/){sub("p\\(95\\)=","",$i);print $i;exit} }' "$k6log")
  success=$(awk '/^.*allow_success/{ for(i=1;i<=NF;i++) if($i ~ /%$/){print $i;exit} }' "$k6log")

  printf '%-10s | %-9s | %-9s | %-9s | %-9s | %s\n' \
    "$label" "${effective:-?}" "${rps:-?}" "${p50:-?}" "${p95:-?}" "${success:-?}"
}

mkdir -p "$OUT_DIR"
{
  printf '%-10s | %-9s | %-9s | %-9s | %-9s | %s\n' \
    "config" "effective" "RPS" "p50" "p95" "allow_success"
  printf '%-10s-+-%-9s-+-%-9s-+-%-9s-+-%-9s-+-%s\n' \
    "----------" "---------" "---------" "---------" "---------" "-------------"
  for w in $WORKER_COUNTS; do
    run_one "$w"
  done
} | tee "$OUT_DIR/summary.txt"
