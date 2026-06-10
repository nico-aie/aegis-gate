#!/usr/bin/env bash
# Common helpers for the HA cluster tests.
#
# Two-node fixture. Both nodes are the *same* binary started
# against `config/cluster-{a,b}.yaml`. They share a Redis
# primary on `127.0.0.1:6379` (the `aegis-cluster-redis`
# container the runner brings up).
#
# Public surface:
#   ensure_redis            — start the redis container if absent
#   stop_redis              — `docker rm -f aegis-cluster-redis`
#   start_node A|B [config] — boot a node, return PID via $LAST_NODE_PID
#   stop_node  <pid>        — kill + wait for the PID
#   wait_ready <admin_url>  — poll /healthz/ready until 200 (30s cap)
#   require    <tool>       — abort with FAIL if missing

set -euo pipefail

AEGIS_REPO="${AEGIS_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
AEGIS_BIN="${AEGIS_BIN:-$AEGIS_REPO/target/release/waf}"
AEGIS_REDIS_NAME="${AEGIS_REDIS_NAME:-aegis-cluster-redis}"

NODE_A_DATA="${NODE_A_DATA:-http://127.0.0.1:8080}"
# Admin is plain HTTP in the cluster fixture (cluster-{a,b}.yaml
# don't bind a TLS resolver). Override with `https://...` if you
# extend the fixture to terminate TLS on the admin plane.
NODE_A_ADMIN="${NODE_A_ADMIN:-http://127.0.0.1:9443}"
NODE_B_DATA="${NODE_B_DATA:-http://127.0.0.1:8090}"
NODE_B_ADMIN="${NODE_B_ADMIN:-http://127.0.0.1:9543}"

LAST_NODE_PID=""

require() {
  command -v "$1" >/dev/null \
    || { echo "FAIL: missing tool: $1" >&2; exit 1; }
}

ok() { echo "PASS: $*"; }
skip() { echo "SKIP: $*"; exit 0; }

# Admin creds — match the cluster-{a,b}.yaml dashboard_auth fixture
# (hash is for `aegis-test-1234`). Test-only; never production values.
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-aegis-test-1234}"
# Populated by `login`. The two nodes do NOT share session state, so
# re-`login` against whichever node you're about to query.
COOKIE=""
CSRF=""

# `login <admin_url>` → POST /admin/login, capturing the session +
# CSRF cookies into $COOKIE / $CSRF for subsequent authed /api calls.
# Aborts (FAIL) on a non-200 so a broken fixture doesn't masquerade as
# a test failure downstream.
login() {
  local admin_url="$1"
  local resp_headers body code
  resp_headers="$(mktemp)"
  body="$(curl --silent --insecure --max-time 5 \
       -D "$resp_headers" \
       -H "content-type: application/json" \
       --data "{\"user\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
       -o /dev/null -w '%{http_code}' \
       "$admin_url/admin/login" 2>/dev/null || echo "000")"
  code="$body"
  if [[ "$code" != "200" ]]; then
    rm -f "$resp_headers"
    echo "FAIL: login: HTTP $code from $admin_url/admin/login" >&2
    return 1
  fi
  COOKIE="$(grep -i '^set-cookie: aegis_session=' "$resp_headers" 2>/dev/null \
              | sed -E 's/.*aegis_session=([^;]+).*/\1/' | tr -d '\r' | head -1 || true)"
  CSRF="$(grep -i '^set-cookie: aegis_csrf=' "$resp_headers" 2>/dev/null \
              | sed -E 's/.*aegis_csrf=([^;]+).*/\1/' | tr -d '\r' | head -1 || true)"
  rm -f "$resp_headers"
  if [[ -z "$COOKIE" ]]; then
    echo "FAIL: login: HTTP 200 but no aegis_session cookie" >&2
    return 1
  fi
}

# `authed_get <admin_url> <path>` → GET with the session cookie from
# the most recent `login`. Echoes the response body.
authed_get() {
  curl --silent --insecure --max-time 3 \
       -H "Cookie: aegis_session=$COOKIE; aegis_csrf=$CSRF" \
       "$1$2" 2>/dev/null || echo ""
}

# Bring up the cluster Redis. Idempotent — exits 0 quickly when
# the container is already running.
ensure_redis() {
  require docker
  if docker ps --format '{{.Names}}' | grep -q "^${AEGIS_REDIS_NAME}$"; then
    return 0
  fi
  if docker ps -a --format '{{.Names}}' | grep -q "^${AEGIS_REDIS_NAME}$"; then
    docker start "$AEGIS_REDIS_NAME" >/dev/null
  else
    docker run -d --name "$AEGIS_REDIS_NAME" \
      -p 6379:6379 redis:7-alpine \
      redis-server --save "" --appendonly no >/dev/null
  fi
  # Wait for redis to accept TCP.
  for _ in $(seq 1 30); do
    if docker exec "$AEGIS_REDIS_NAME" redis-cli ping 2>/dev/null \
        | grep -q PONG; then
      return 0
    fi
    sleep 0.2
  done
  echo "FAIL: redis did not become ready" >&2
  return 1
}

stop_redis() {
  if docker ps -a --format '{{.Names}}' | grep -q "^${AEGIS_REDIS_NAME}$"; then
    docker rm -f "$AEGIS_REDIS_NAME" >/dev/null 2>&1 || true
  fi
}

# `start_node A` boots node A from `config/cluster-a.yaml`.
# Sets $LAST_NODE_PID. Caller is responsible for calling
# `stop_node "$LAST_NODE_PID"` later.
start_node() {
  local letter="$1"
  # `${var,,}` is bash 4+ — use tr for macOS bash 3 compatibility.
  local lower
  lower="$(printf '%s' "$letter" | tr '[:upper:]' '[:lower:]')"
  local config="${2:-$AEGIS_REPO/config/cluster-${lower}.yaml}"
  if [[ ! -x "$AEGIS_BIN" ]]; then
    skip "release binary $AEGIS_BIN not built — \`cargo build -p aegis-bin --release\` first"
  fi
  if [[ ! -f "$config" ]]; then
    skip "missing config: $config"
  fi
  "$AEGIS_BIN" run --config "$config" \
    > "/tmp/waf-cluster-${lower}.log" 2>&1 &
  LAST_NODE_PID=$!
  echo "started node $letter (pid $LAST_NODE_PID, log /tmp/waf-cluster-${lower}.log)"
}

stop_node() {
  local pid="$1"
  if [[ -z "$pid" ]]; then return 0; fi
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

# Poll `/healthz/ready` on the given admin URL until it answers
# 200, or 30 s elapse. Allows a 503 during the rehydrate window
# documented in B1-T5.
wait_ready() {
  local url="$1"
  local deadline=$((SECONDS + 30))
  local code
  while (( SECONDS < deadline )); do
    code=$(curl --silent --insecure --max-time 1 \
                -o /dev/null -w "%{http_code}" \
                "$url/healthz/ready" 2>/dev/null \
           || echo "000")
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    sleep 0.5
  done
  echo "FAIL: $url not ready within 30s" >&2
  return 1
}

# Convenience: spin up two nodes + redis, run "$@" inside the
# `with_two_nodes` body, then clean up. Sets NODE_A_PID and
# NODE_B_PID for the caller to inspect / kill mid-test.
NODE_A_PID=""
NODE_B_PID=""

with_two_nodes() {
  ensure_redis
  start_node A
  NODE_A_PID="$LAST_NODE_PID"
  start_node B
  NODE_B_PID="$LAST_NODE_PID"

  # Trap so any exit (success, fail, or signal) cleans up.
  trap 'stop_node "$NODE_A_PID"; stop_node "$NODE_B_PID"' EXIT

  wait_ready "$NODE_A_ADMIN" || return 1
  wait_ready "$NODE_B_ADMIN" || return 1
}
