#!/usr/bin/env bash
# tests/cluster/10-proxy-protocol-client-ip.sh — PROXY-protocol P4 gate.
#
# A single WAF node with a data listener in `accept_proxy: strict`,
# trusting loopback as the load balancer (config/cluster-proxy.yaml).
# This script *is* the trusted LB: it opens loopback TCP connections and
# prepends a PROXY v1 header asserting the real client IP, exactly as
# nginx `stream { proxy_protocol on; }` or HAProxy `send-proxy` does.
#
# Asserts:
#   1. Differential risk — attacks as client A drive A's per-IP risk up
#      while clean client B stays at 0 AND the LB hop (127.0.0.1) never
#      accrues risk. Proves per-IP buckets key on the *real client*, not
#      the collapsed LB IP — the exact bug PROXY protocol fixes.
#   2. Strict-missing — a header-less connection on a strict listener is
#      closed (no HTTP response served).
#   3. Malformed header — a bad PROXY line closes the connection.
#
# Self-contained: the fixture uses `state.backend: in_memory` and AI off,
# so the rig needs only `target/release/waf` + bash /dev/tcp + curl —
# no docker, no redis. Skips cleanly when the release binary is missing.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl

PROXY_CONFIG="$AEGIS_REPO/config/cluster-proxy.yaml"
DATA_HOST="127.0.0.1"
DATA_PORT="8080"
ATTACKER="203.0.113.7"
CLEAN="198.51.100.20"
# URL-encoded `1' OR '1'='1` — same SQLi probe as docs/FEATURES.md.
SQLI_PATH="/?q=1%27%20OR%20%271%27%3D%271"

# Boot the single proxy-protocol node (reuses node A's 8080/9443 ports).
start_node A "$PROXY_CONFIG"
NODE_PID="$LAST_NODE_PID"
trap 'stop_node "$NODE_PID"' EXIT
wait_ready "$NODE_A_ADMIN" || exit 1

# send_proxy <client_ip> <path> — open a loopback connection (the "LB"),
# prepend a PROXY v1 header asserting <client_ip>, then send a minimal
# HTTP/1.1 GET. The WAF (trusting 127.0.0.1) adopts <client_ip> as the
# effective peer. Response is drained + discarded.
send_proxy() {
  local client_ip="$1" path="$2"
  exec 3<>"/dev/tcp/$DATA_HOST/$DATA_PORT" || return 0
  printf 'PROXY TCP4 %s 127.0.0.1 40000 %s\r\nGET %s HTTP/1.1\r\nHost: rig\r\nUser-Agent: proxy-rig\r\nConnection: close\r\n\r\n' \
    "$client_ip" "$DATA_PORT" "$path" >&3 2>/dev/null || true
  cat <&3 >/dev/null 2>&1 || true
  exec 3>&- 3<&- 2>/dev/null || true
}

# send_raw <prefix> — open a loopback connection and write <prefix>
# (interpreted with %b for \r\n escapes) followed by an HTTP GET, with
# NO valid PROXY header. Echoes the response (empty when the WAF closed
# the connection before serving anything).
send_raw() {
  local prefix="$1" resp=""
  exec 3<>"/dev/tcp/$DATA_HOST/$DATA_PORT" || { echo ""; return 0; }
  printf '%bGET / HTTP/1.1\r\nHost: rig\r\nConnection: close\r\n\r\n' "$prefix" >&3 2>/dev/null || true
  resp="$(cat <&3 2>/dev/null || true)"
  exec 3>&- 3<&- 2>/dev/null || true
  printf '%s' "$resp"
}

# score_of <json> — pull the integer `score` from a /api/risk/<ip>
# detail body; 0 when the IP is unknown (404 not_found, no score field).
score_of() {
  local s
  s="$(printf '%s' "$1" | grep -o '"score"[: ]*[0-9]*' | head -1 | grep -o '[0-9]*$' || true)"
  echo "${s:-0}"
}

login "$NODE_A_ADMIN" || { echo "FAIL: admin login failed"; exit 1; }

# ---- 1. Differential risk -------------------------------------------
echo "==> driving 6 SQLi attacks as client A ($ATTACKER), 3 benign as B ($CLEAN)"
for _ in $(seq 1 6); do send_proxy "$ATTACKER" "$SQLI_PATH"; done
for _ in $(seq 1 3); do send_proxy "$CLEAN" "/"; done
sleep 1  # let the risk tracker settle

a_score="$(score_of "$(authed_get "$NODE_A_ADMIN" "/api/risk/$ATTACKER")")"
b_score="$(score_of "$(authed_get "$NODE_A_ADMIN" "/api/risk/$CLEAN")")"
lb_score="$(score_of "$(authed_get "$NODE_A_ADMIN" "/api/risk/127.0.0.1")")"
echo "risk scores: attacker=$a_score  clean=$b_score  lb(127.0.0.1)=$lb_score"

if (( a_score <= 0 )); then
  echo "FAIL: attacker risk did not climb (score=$a_score) — PROXY client IP not applied"
  exit 1
fi
if (( b_score != 0 )); then
  echo "FAIL: clean client accrued risk (score=$b_score) — per-IP buckets bleeding across clients"
  exit 1
fi
if (( lb_score != 0 )); then
  echo "FAIL: LB IP 127.0.0.1 accrued risk (score=$lb_score) — buckets collapsed onto the LB (the bug PROXY protocol fixes)"
  exit 1
fi
ok "differential risk: attacker=$a_score, clean=0, LB=0 — buckets key on the real client"

# ---- 2. Strict-missing closes ---------------------------------------
missing_resp="$(send_raw '')"
if printf '%s' "$missing_resp" | grep -q "HTTP/"; then
  echo "FAIL: strict listener served a header-less connection:"
  printf '%s\n' "$missing_resp" | head -1
  exit 1
fi
ok "strict-missing: header-less connection closed (no HTTP response)"

# ---- 3. Malformed header closes -------------------------------------
malformed_resp="$(send_raw 'PROXY GARBAGE NOT A VALID HEADER\r\n')"
if printf '%s' "$malformed_resp" | grep -q "HTTP/"; then
  echo "FAIL: malformed PROXY header was served:"
  printf '%s\n' "$malformed_resp" | head -1
  exit 1
fi
ok "malformed header: connection closed"

ok "proxy-protocol client-IP rig passed"
