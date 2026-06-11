#!/usr/bin/env bash
# tests/l-tester/lt-26-upstream-mtls.sh
#
# Upstream mTLS integration test — WAF as TLS client presenting a
# client certificate to a backend that requires mutual TLS.
#
# Test matrix:
#   T1  upstream_mtls.enabled=true  → WAF presents client cert → backend
#       accepts → 200 proxied to client.
#   T2  upstream_mtls.enabled=false → WAF connects without client cert →
#       backend rejects TLS handshake → WAF returns 502.
#   T3  upstream_mtls.enabled=true  but trust CA does NOT match backend
#       server cert → WAF fails server-cert verification → 502 (fail-closed).
#
# Dependencies: openssl, python3 (stdlib ssl + http.server), curl
# WAF binary:   target/release/waf  (pre-built)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

require openssl
require python3
require curl

# ---------------------------------------------------------------------------
# Ports (chosen well away from default 8080/9443 to avoid conflicts)
# ---------------------------------------------------------------------------
BACKEND_PORT=18765
WAF_DATA_PORT=18780
WAF_ADMIN_PORT=18781

DATA="http://127.0.0.1:${WAF_DATA_PORT}"
ADMIN="http://127.0.0.1:${WAF_ADMIN_PORT}"

# ---------------------------------------------------------------------------
# Temp directory
# ---------------------------------------------------------------------------
WORK_DIR="$(mktemp -d -t lt-26-mtls.XXXXXX)"
BACKEND_LOG="${WORK_DIR}/backend.log"
BACKEND_READY="${WORK_DIR}/backend.ready"   # sentinel file written when listening

cleanup_all() {
  stop_waf     2>/dev/null || true
  stop_backend 2>/dev/null || true
  rm -rf "$WORK_DIR"
}
trap 'cleanup_all' EXIT

# ---------------------------------------------------------------------------
# Python backend — write once, reuse
# ---------------------------------------------------------------------------
cat > "${WORK_DIR}/backend.py" <<'PYEOF'
#!/usr/bin/env python3
"""
Minimal HTTPS backend for upstream mTLS testing.
Writes a sentinel file (argv[4]) when the socket is ready, then serves.

Usage: python3 backend.py <work_dir> <port> <mode> <ready_file>
  mode = mtls_required  — TLS server that requires client cert
  mode = tls_only       — TLS server, no client cert required
"""
import sys, ssl, http.server, os, pathlib

work_dir = sys.argv[1]
port     = int(sys.argv[2])
mode     = sys.argv[3]   # "mtls_required" | "tls_only"
ready    = sys.argv[4]   # path to sentinel file

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"upstream-ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Upstream-Mode", mode)
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        print(f"[backend] {fmt % args}", flush=True)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(
    os.path.join(work_dir, "backend.crt"),
    os.path.join(work_dir, "backend.key"),
)
ctx.load_verify_locations(os.path.join(work_dir, "ca.crt"))

if mode == "mtls_required":
    ctx.verify_mode = ssl.CERT_REQUIRED
elif mode == "tls_only":
    ctx.verify_mode = ssl.CERT_NONE
else:
    print(f"[backend] unknown mode: {mode}", file=sys.stderr, flush=True)
    sys.exit(1)

server = http.server.HTTPServer(("127.0.0.1", port), Handler)
server.socket = ctx.wrap_socket(server.socket, server_side=True)

# Signal that the port is bound and ready BEFORE entering serve_forever.
pathlib.Path(ready).write_text("ok")
print(f"[backend] {mode} listening on port {port}", flush=True)
server.serve_forever()
PYEOF

# ---------------------------------------------------------------------------
# Backend lifecycle
# ---------------------------------------------------------------------------
BACKEND_PID=""

stop_backend() {
  [[ -n "$BACKEND_PID" ]] || return 0
  kill -TERM "$BACKEND_PID" 2>/dev/null || true
  wait "$BACKEND_PID" 2>/dev/null || true
  BACKEND_PID=""
  rm -f "$BACKEND_READY"
}

start_backend() {
  local mode="$1"
  stop_backend 2>/dev/null || true

  rm -f "$BACKEND_READY"
  python3 "${WORK_DIR}/backend.py" \
      "$WORK_DIR" "$BACKEND_PORT" "$mode" "$BACKEND_READY" \
      > "$BACKEND_LOG" 2>&1 &
  BACKEND_PID=$!

  # Wait for the sentinel file (backend writes it after binding).
  local attempts=0
  while (( attempts++ < 50 )); do
    [[ -f "$BACKEND_READY" ]] && return 0
    kill -0 "$BACKEND_PID" 2>/dev/null || {
      echo "--- backend log ---" >&2; cat "$BACKEND_LOG" >&2 || true
      fail "Backend process ($BACKEND_PID) exited unexpectedly (mode=$mode)"
    }
    sleep 0.1
  done

  echo "--- backend log ---" >&2; cat "$BACKEND_LOG" >&2 || true
  fail "Backend did not write ready-sentinel within 5 s (mode=$mode)"
}

# ---------------------------------------------------------------------------
# PKI generation
# ---------------------------------------------------------------------------
gen_pki() {
  local dir="$1"
  echo "[pki] generating CA + backend cert + WAF client cert"

  # CA
  openssl req -x509 -newkey rsa:2048 \
    -keyout "$dir/ca.key" -out "$dir/ca.crt" \
    -days 1 -nodes -subj "/CN=test-ca" 2>/dev/null

  # Backend server cert (SAN covers 127.0.0.1 and localhost)
  openssl req -newkey rsa:2048 \
    -keyout "$dir/backend.key" -out "$dir/backend.csr" \
    -nodes -subj "/CN=localhost" 2>/dev/null
  openssl x509 -req \
    -in "$dir/backend.csr" \
    -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
    -out "$dir/backend.crt" -days 1 \
    -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost\n") \
    2>/dev/null

  # WAF client cert (used as zero_trust.upstream_identity)
  openssl req -newkey rsa:2048 \
    -keyout "$dir/waf-client.key" -out "$dir/waf-client.csr" \
    -nodes -subj "/CN=waf-client" 2>/dev/null
  openssl x509 -req \
    -in "$dir/waf-client.csr" \
    -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
    -out "$dir/waf-client.crt" -days 1 \
    2>/dev/null

  # A second, unrelated CA (T3 — wrong trust CA)
  openssl req -x509 -newkey rsa:2048 \
    -keyout "$dir/wrong-ca.key" -out "$dir/wrong-ca.crt" \
    -days 1 -nodes -subj "/CN=wrong-ca" 2>/dev/null

  echo "[pki] PKI generated OK"
}

# ---------------------------------------------------------------------------
# WAF config factory
# ---------------------------------------------------------------------------
write_waf_config() {
  local out="$1"
  local mtls_enabled="$2"     # "true" | "false"
  local trust_ca="$3"         # path to CA cert used for upstream trust

  if [[ "$mtls_enabled" == "true" ]]; then
    local mtls_block="    upstream_mtls:
      enabled: true
      trust: ${trust_ca}"
  else
    # enabled=false → WAF dials TLS but presents no client cert.
    # The backend (requiring mTLS) will reject → 502.
    local mtls_block="    upstream_mtls:
      enabled: false"
  fi

  cat > "$out" <<YAML
# Auto-generated by lt-26-upstream-mtls.sh

listeners:
  data:
    - bind: "127.0.0.1:${WAF_DATA_PORT}"
      tls: false
  admin:
    bind: "127.0.0.1:${WAF_ADMIN_PORT}"

zero_trust:
  upstream_identity:
    source: file
    cert_path: "${WORK_DIR}/waf-client.crt"
    key_ref:   "${WORK_DIR}/waf-client.key"

routes:
  - id: catch-all
    path: "/"
    match_type: prefix
    upstream: backend

upstreams:
  backend:
    members:
      - addr: "127.0.0.1:${BACKEND_PORT}"
    lb: round_robin
    connection:
      tls: true
${mtls_block}

state:
  backend: in_memory

risk:
  weights:
    bad_asn: 15
    bad_ja4: 10
    failed_auth: 20
    detector_hit: 25
    bot_unknown: 10
    repeat_offender: 15
  decay_half_life: "5m"
  thresholds:
    challenge_at: 40
    block_at:     80
    max:          100
  trust_recovery:
    per_hour: 30
  strikes:
    block_at: 1000000

audit:
  sinks:
    - jsonl:
        path: "${WORK_DIR}/audit.jsonl"
  chain:
    enabled: true
  retention: "7d"
  pseudonymize_ip: false

rate_limit:
  buckets: []

rules:
  paths: []
  max_rule_count: 10000
  strict_compile: false

detectors:
  sqli:             { enabled: false }
  xss:              { enabled: false }
  path_traversal:   { enabled: false }
  ssrf:             { enabled: false }
  header_injection: { enabled: false }
  body_abuse:       { enabled: false }
  recon:            { enabled: false }
  brute_force:      { enabled: false }

observability:
  prometheus:
    enabled: false

logging:
  verbosity: info

admin:
  bind: "127.0.0.1:${WAF_ADMIN_PORT}"
  identity:
    user: admin
    password_hash: "\$argon2id\$v=19\$m=19456,t=2,p=1\$dGVzdHRlc3R0ZXN0\$kxlR4dPmllB+IMOmw3hNW1Lv3qiI4xFC7FgTiM2wmiU"

interop:
  enabled: true
  audit_path: "${WORK_DIR}/waf_audit.log"
  control_secret: "waf-hackathon-2026-ctrl"
YAML
}

# ---------------------------------------------------------------------------
# WAF lifecycle (uses our custom ports)
# ---------------------------------------------------------------------------
boot_waf_with_config() {
  local cfg="$1"
  stop_waf 2>/dev/null || true

  [[ -x "$WAF_BIN" ]] \
    || fail "WAF binary not found at $WAF_BIN — run: cargo build -p aegis-bin --release"

  WAF_LOG="$(mktemp -t lt-26-waf.XXXXXX)"
  cd "$REPO"
  "$WAF_BIN" run --config "$cfg" >"$WAF_LOG" 2>&1 &
  WAF_PID=$!

  local attempts=0
  while (( attempts++ < 50 )); do
    if curl --silent --max-time 1 "$ADMIN/healthz/ready" \
         | grep -q '"status":"ok"'; then
      return 0
    fi
    sleep 0.2
  done
  echo "--- WAF log (last 40 lines) ---" >&2; tail -40 "$WAF_LOG" >&2 || true
  fail "WAF did not become ready (config: $cfg)"
}

# Single probe → returns HTTP status code (or 000 on connection failure)
probe_status() {
  curl --silent --max-time 5 \
       --output /dev/null \
       --write-out "%{http_code}" \
       "${DATA}/"
}

# ============================================================
# MAIN
# ============================================================
echo ""
echo "========================================"
echo "  LT-26  Upstream mTLS test"
echo "========================================"
echo ""

gen_pki "$WORK_DIR"

# ============================================================
# T1: mTLS ENABLED — WAF presents client cert → backend accepts → 200
# ============================================================
echo ""
echo "--- T1: upstream_mtls.enabled=true (expect 200) ---"

start_backend "mtls_required"
echo "[T1] backend started (pid=$BACKEND_PID, mode=mtls_required)"

CONFIG_T1="${WORK_DIR}/waf-mtls-enabled.yaml"
write_waf_config "$CONFIG_T1" "true" "${WORK_DIR}/ca.crt"
boot_waf_with_config "$CONFIG_T1"
echo "[T1] WAF started"

STATUS=$(probe_status)
echo "[T1] response status: $STATUS"

if [[ "$STATUS" == "200" ]]; then
  ok "T1: upstream mTLS enabled — proxy succeeded (200)"
else
  echo "--- WAF log (last 30 lines) ---" >&2; tail -30 "$WAF_LOG" >&2 || true
  echo "--- backend log ---" >&2; cat "$BACKEND_LOG" >&2 || true
  fail "T1: expected 200, got $STATUS"
fi

stop_waf
stop_backend

# ============================================================
# T2: mTLS DISABLED — WAF presents no client cert → backend rejects → 502
# ============================================================
echo ""
echo "--- T2: upstream_mtls.enabled=false (expect 502) ---"

start_backend "mtls_required"
echo "[T2] backend started (pid=$BACKEND_PID, mode=mtls_required)"

CONFIG_T2="${WORK_DIR}/waf-mtls-disabled.yaml"
write_waf_config "$CONFIG_T2" "false" "${WORK_DIR}/ca.crt"
boot_waf_with_config "$CONFIG_T2"
echo "[T2] WAF started"

STATUS=$(probe_status)
echo "[T2] response status: $STATUS"

if [[ "$STATUS" == "502" || "$STATUS" == "503" || "$STATUS" == "504" || "$STATUS" == "000" ]]; then
  ok "T2: upstream mTLS disabled — backend rejected no-cert connection (status $STATUS)"
else
  echo "--- WAF log (last 30 lines) ---" >&2; tail -30 "$WAF_LOG" >&2 || true
  echo "--- backend log ---" >&2; cat "$BACKEND_LOG" >&2 || true
  fail "T2: expected 502/503/504 (mTLS rejection), got $STATUS"
fi

stop_waf
stop_backend

# ============================================================
# T3: WRONG CA — trust CA does not sign backend cert → 502 (fail-closed)
# ============================================================
echo ""
echo "--- T3: wrong trust CA (expect 502) ---"

start_backend "mtls_required"
echo "[T3] backend started (pid=$BACKEND_PID, mode=mtls_required)"

CONFIG_T3="${WORK_DIR}/waf-wrong-ca.yaml"
write_waf_config "$CONFIG_T3" "true" "${WORK_DIR}/wrong-ca.crt"
boot_waf_with_config "$CONFIG_T3"
echo "[T3] WAF started"

STATUS=$(probe_status)
echo "[T3] response status: $STATUS"

if [[ "$STATUS" == "502" || "$STATUS" == "503" || "$STATUS" == "504" || "$STATUS" == "000" ]]; then
  ok "T3: wrong trust CA — WAF rejected untrusted backend cert (status $STATUS)"
else
  echo "--- WAF log (last 30 lines) ---" >&2; tail -30 "$WAF_LOG" >&2 || true
  echo "--- backend log ---" >&2; cat "$BACKEND_LOG" >&2 || true
  fail "T3: expected 502/503/504 (untrusted backend cert), got $STATUS"
fi

stop_waf
stop_backend

echo ""
echo "========================================"
echo "  LT-26 PASSED (3/3)"
echo "========================================"
echo ""
