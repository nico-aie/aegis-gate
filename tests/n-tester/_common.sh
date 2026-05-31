#!/usr/bin/env bash
# tests/n-tester/_common.sh
#
# Shared helpers for every tests/n-tester/nt-*.sh script.
#
# Builds on tests/cluster/_common.sh (Redis container + start_node)
# and adds the admin-login + CSRF + JSON helpers the new cluster
# config-plane / AI-confidence tests need.
#
# Exports (overridable via env):
#   $AEGIS_REPO          repo root
#   $AEGIS_BIN           release binary path
#   $CONFIG_A            config/cluster-a.yaml
#   $CONFIG_B            config/cluster-b.yaml
#   $NODE_A_DATA/ADMIN   http://127.0.0.1:{8080,9443}
#   $NODE_B_DATA/ADMIN   http://127.0.0.1:{8090,9543}
#   $ADMIN_USER          admin
#   $ADMIN_PASS          aegis-test-1234   (dev creds — cluster-a/b.yaml)
#
# Functions:
#   require <bin>                     abort if a CLI is missing
#   ok  <msg>                          green PASS line
#   fail <msg>                         red FAIL line + exit 1
#   skip <msg>                         yellow SKIP line + exit 0
#   ensure_redis / stop_redis          docker container lifecycle
#   start_node A|B                     boot a node (LAST_NODE_PID set)
#   stop_node <pid>                    kill + wait
#   wait_ready <admin_url>             /healthz/ready polling
#   start_cluster                      ensure_redis + start_node A + B + wait both
#   stop_cluster                       stop both, optionally stop redis
#   login <admin_url>                  POST /admin/login → sets $COOKIE / $CSRF
#   admin_get  <admin_url> <path>      authenticated GET, prints body
#   admin_put  <admin_url> <path> <json>  authenticated PUT, prints body
#   http_status <admin_url> <method> <path> [json]   prints "<code>\n<body>"
#   assert_json_eq <body> <jq-path> <expected>
#   assert_status <expected> <actual>
#   wait_for <fn> <timeout_s>          re-run until 0 or deadline
#   namespace_redis <test_name>        wipe redis keys under this test's prefix
#
# Usage in a test file:
#   set -euo pipefail
#   HERE="$(cd "$(dirname "$0")" && pwd)"
#   source "$HERE/_common.sh"
#   trap stop_cluster EXIT
#   require curl; require jq
#   start_cluster
#   login "$NODE_A_ADMIN"
#   ... assertions ...

set -euo pipefail

AEGIS_REPO="${AEGIS_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
AEGIS_BIN="${AEGIS_BIN:-$AEGIS_REPO/target/release/waf}"
AEGIS_REDIS_NAME="${AEGIS_REDIS_NAME:-aegis-cluster-redis}"

CONFIG_A="${CONFIG_A:-$AEGIS_REPO/config/cluster-a.yaml}"
CONFIG_B="${CONFIG_B:-$AEGIS_REPO/config/cluster-b.yaml}"

NODE_A_DATA="${NODE_A_DATA:-http://127.0.0.1:8080}"
NODE_A_ADMIN="${NODE_A_ADMIN:-http://127.0.0.1:9443}"
NODE_B_DATA="${NODE_B_DATA:-http://127.0.0.1:8090}"
NODE_B_ADMIN="${NODE_B_ADMIN:-http://127.0.0.1:9543}"

ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-aegis-test-1234}"

# Populated by login(). Re-login when you want to talk to a different
# admin URL; the two nodes do NOT share session state.
COOKIE=""
CSRF=""

NODE_A_PID=""
NODE_B_PID=""
LAST_NODE_PID=""

# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------
_red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
_green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
_yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
# 2026-05-29 (QC L-fail-message-stderr-vs-stdout):
# PASS lines stay on stdout (informational). FAIL + SKIP lines go to
# **stderr** so `run-all.sh` (which captures stderr) can show the
# post-mortem tail. SKIP uses exit code **77** (autotools convention)
# so `run-all.sh` counts it distinctly from pass — see
# L-run-all-skip-bookkeeping.md in the QC report.
ok()   { _green "PASS: $*"; }
fail() { _red   "FAIL: $*" >&2; exit 1; }
skip() { _yellow "SKIP: $*" >&2; exit 77; }

require() {
  command -v "$1" >/dev/null 2>&1 \
    || fail "missing tool: $1"
}

# 2026-05-30 (QC R2-007 / R2-009): float-tolerant equality check.
# YAML / JSON round-trip through `f32` widens 0.85 to
# 0.8500000238418579 (next f64 representable above the f32 cast).
# Strict `(a+0)==(b+0)` in awk treats those as different. Tests
# should call `floats_eq <a> <b> [epsilon]` instead.
floats_eq() {
  local a="$1" b="$2" eps="${3:-1e-5}"
  awk -v a="$a" -v b="$b" -v eps="$eps" \
    'BEGIN{ d = a - b; if (d < 0) d = -d; exit !(d <= eps) }'
}

# 2026-05-30 (QC R2-005): defensive ERR trap. Tests should still
# use `fail` for known error paths, but if `set -e` or a pipefail
# aborts a script silently, this trap prints the line + last
# command so the post-mortem isn't a guessing game.
on_err() {
  local rc=$?
  local line="${BASH_LINENO[0]:-?}"
  local cmd="${BASH_COMMAND:-?}"
  _red "FAIL (errexit @ line $line): \`$cmd\` exited $rc" >&2
  exit "$rc"
}
# Tests opt in by calling `enable_err_trap` after sourcing this file.
enable_err_trap() {
  trap on_err ERR
}

# ---------------------------------------------------------------------------
# Redis lifecycle (idempotent — safe to call from every test)
# ---------------------------------------------------------------------------
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
  for _ in $(seq 1 30); do
    if docker exec "$AEGIS_REDIS_NAME" redis-cli ping 2>/dev/null \
        | grep -q PONG; then
      return 0
    fi
    sleep 0.2
  done
  fail "redis did not become ready"
}

stop_redis() {
  docker rm -f "$AEGIS_REDIS_NAME" >/dev/null 2>&1 || true
}

# Wipe every config-plane key so a test starts from a clean cluster
# state. NOT a FLUSHALL — only the namespaces the config plane owns.
reset_redis_config_plane() {
  docker exec "$AEGIS_REDIS_NAME" sh -c '
    redis-cli --scan --pattern "config:waf:*" | xargs -r redis-cli DEL >/dev/null
  ' 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Node lifecycle
# ---------------------------------------------------------------------------
start_node() {
  local letter="$1"
  local lower
  lower="$(printf '%s' "$letter" | tr '[:upper:]' '[:lower:]')"
  local config
  if [[ "$lower" == "a" ]]; then config="$CONFIG_A"
  elif [[ "$lower" == "b" ]]; then config="$CONFIG_B"
  else fail "start_node: bad letter $letter (expected A or B)"
  fi
  [[ -x "$AEGIS_BIN" ]] \
    || skip "release binary not built — run: cargo build -p aegis-bin --release --features \"redis geoip alerts ai affinity\""
  [[ -f "$config" ]] \
    || fail "missing config: $config"
  local log="/tmp/n-tester-${lower}.log"
  "$AEGIS_BIN" run --config "$config" >"$log" 2>&1 &
  LAST_NODE_PID=$!
  echo "started node $letter (pid $LAST_NODE_PID, log $log)"
}

stop_node() {
  local pid="$1"
  [[ -z "$pid" ]] && return 0
  kill -TERM "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

wait_ready() {
  local url="$1"
  local deadline=$((SECONDS + 30))
  local code
  while (( SECONDS < deadline )); do
    code=$(curl --silent --insecure --max-time 1 \
                -o /dev/null -w "%{http_code}" \
                "$url/healthz/ready" 2>/dev/null \
           || echo "000")
    [[ "$code" == "200" ]] && return 0
    sleep 0.5
  done
  echo "--- last 30 lines of node log (best-effort) ---" >&2
  tail -30 /tmp/n-tester-a.log /tmp/n-tester-b.log 2>/dev/null >&2 || true
  fail "$url not ready within 30 s"
}

start_cluster() {
  # 2026-05-30 (QC R2-008): refuse to start if the test's ports are
  # already bound. Otherwise a stale `waf run` in another shell
  # silently steals the test — `start_node` spawns a binary that
  # immediately exits on bind failure, but `wait_ready` still gets
  # 200 from the squatter, so every assertion lies. Fail loudly
  # with a kill hint instead.
  for port in 8080 8090 9443 9543; do
    if lsof -i ":$port" -P -n 2>/dev/null | grep -q LISTEN; then
      fail "port $port already bound — stop the squatting process before starting the test cluster (try: pkill -f 'target/release/waf'; sleep 1)"
    fi
  done
  ensure_redis
  reset_redis_config_plane
  start_node A; NODE_A_PID="$LAST_NODE_PID"
  start_node B; NODE_B_PID="$LAST_NODE_PID"
  # Give each binary ~200 ms to either bind or fail-fast on bind
  # error. If a node died (bind clash, missing model file, panic on
  # boot) `wait_ready` would otherwise spin for 30 s with no signal.
  sleep 0.3
  if ! kill -0 "$NODE_A_PID" 2>/dev/null; then
    tail -20 /tmp/n-tester-a.log >&2 || true
    fail "node A (pid $NODE_A_PID) died during boot — see log above"
  fi
  if ! kill -0 "$NODE_B_PID" 2>/dev/null; then
    tail -20 /tmp/n-tester-b.log >&2 || true
    fail "node B (pid $NODE_B_PID) died during boot — see log above"
  fi
  wait_ready "$NODE_A_ADMIN"
  wait_ready "$NODE_B_ADMIN"
}

stop_cluster() {
  stop_node "$NODE_A_PID"; NODE_A_PID=""
  stop_node "$NODE_B_PID"; NODE_B_PID=""
  # Leave the redis container running between tests for speed; the
  # `reset_redis_config_plane` call on the next `start_cluster` wipes
  # what matters. Use `stop_redis` explicitly if you want it gone.
}

# ---------------------------------------------------------------------------
# Admin auth — cookie + CSRF
#
# /admin/login returns 200 with two cookies: `aegis_session` (the auth
# cookie) and `aegis_csrf` (a token to be echoed as `x-csrf-token` on
# mutations). Per-node — sessions DO NOT share across A and B.
# ---------------------------------------------------------------------------
login() {
  local admin_url="$1"
  local resp_headers out body code
  resp_headers="$(mktemp)"
  # 2026-05-29 (QC L-login-silent-on-no-cookie): capture the HTTP
  # status code FIRST and fail with the body if non-200 — before the
  # grep pipeline, which under `set -euo pipefail` silently aborts
  # the whole script when grep finds nothing (e.g. 401 response has
  # no `Set-Cookie: aegis_session=` line). The old shape masked
  # 401 invalid_credentials with an empty-stderr crash.
  out="$(curl --silent --insecure --max-time 5 \
       -D "$resp_headers" \
       -H 'content-type: application/json' \
       --data "{\"user\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
       -w '\n%{http_code}' \
       "$admin_url/admin/login")" || {
    rm -f "$resp_headers"
    fail "login: curl to $admin_url/admin/login failed"
  }
  code="$(printf '%s' "$out" | tail -1)"
  body="$(printf '%s' "$out" | sed '$d')"
  if [[ "$code" != "200" ]]; then
    rm -f "$resp_headers"
    fail "login: HTTP $code from $admin_url/admin/login (body: ${body:0:300})"
  fi
  # Now safe to grep for cookies — `|| true` neutralises pipefail if
  # the response is 200 but somehow missing a cookie (genuine bug we
  # want to surface as the explicit error below).
  COOKIE="$(grep -i '^set-cookie: aegis_session=' "$resp_headers" 2>/dev/null \
            | sed -E 's/.*aegis_session=([^;]+).*/\1/' | tr -d '\r' | head -1 || true)"
  CSRF="$(grep -i '^set-cookie: aegis_csrf=' "$resp_headers" 2>/dev/null \
            | sed -E 's/.*aegis_csrf=([^;]+).*/\1/' | tr -d '\r' | head -1 || true)"
  rm -f "$resp_headers"
  [[ -n "$COOKIE" && -n "$CSRF" ]] \
    || fail "login: HTTP 200 but missing cookies (COOKIE='${COOKIE:-<empty>}' CSRF='${CSRF:-<empty>}', body: ${body:0:200})"
}

# Authenticated GET — prints body to stdout, returns curl's exit status.
admin_get() {
  local admin_url="$1" path="$2"
  curl --silent --insecure --max-time 5 \
       -H "Cookie: aegis_session=$COOKIE; aegis_csrf=$CSRF" \
       "$admin_url$path"
}

# Authenticated PUT with JSON body — prints body to stdout.
admin_put() {
  local admin_url="$1" path="$2" body="$3"
  curl --silent --insecure --max-time 5 \
       -X PUT \
       -H "Cookie: aegis_session=$COOKIE; aegis_csrf=$CSRF" \
       -H "x-csrf-token: $CSRF" \
       -H 'content-type: application/json' \
       --data "$body" \
       "$admin_url$path"
}

# Authenticated POST with JSON body — prints body to stdout.
admin_post() {
  local admin_url="$1" path="$2" body="${3:-}"
  curl --silent --insecure --max-time 5 \
       -X POST \
       -H "Cookie: aegis_session=$COOKIE; aegis_csrf=$CSRF" \
       -H "x-csrf-token: $CSRF" \
       -H 'content-type: application/json' \
       --data "$body" \
       "$admin_url$path"
}

# Prints "<status_code>\n<body>" so callers can parse both.
http_status() {
  local admin_url="$1" method="$2" path="$3" body="${4:-}"
  local hdrs=()
  hdrs+=(-H "Cookie: aegis_session=$COOKIE; aegis_csrf=$CSRF")
  if [[ "$method" != "GET" ]]; then
    hdrs+=(-H "x-csrf-token: $CSRF" -H 'content-type: application/json')
  fi
  local args=(--silent --insecure --max-time 5 -X "$method" "${hdrs[@]}" -w '\n%{http_code}')
  if [[ -n "$body" ]]; then args+=(--data "$body"); fi
  curl "${args[@]}" "$admin_url$path"
}

# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------
assert_status() {
  local expected="$1" actual="$2" ctx="${3:-}"
  [[ "$actual" == "$expected" ]] \
    || fail "expected HTTP $expected, got $actual ${ctx:+— $ctx}"
}

# assert_json_eq <body> <jq-path> <expected>
assert_json_eq() {
  local body="$1" path="$2" expected="$3"
  local actual
  actual="$(printf '%s' "$body" | jq -r "$path" 2>/dev/null || true)"
  [[ "$actual" == "$expected" ]] \
    || fail "jq $path: expected '$expected', got '$actual' (body: ${body:0:200})"
}

# assert_json_present <body> <jq-path>
assert_json_present() {
  local body="$1" path="$2"
  local v
  v="$(printf '%s' "$body" | jq -r "$path" 2>/dev/null || true)"
  [[ "$v" != "null" && -n "$v" ]] \
    || fail "jq $path: missing or null (body: ${body:0:200})"
}

# Poll `fn` (a bash function name returning 0 = success) until it
# succeeds or `timeout_s` elapses. Used for "eventually converges".
wait_for() {
  local fn="$1" timeout_s="${2:-10}"
  local deadline=$((SECONDS + timeout_s))
  while (( SECONDS < deadline )); do
    if "$fn"; then return 0; fi
    sleep 0.25
  done
  return 1
}
