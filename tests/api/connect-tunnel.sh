#!/usr/bin/env bash
# tests/api/connect-tunnel.sh — TCP-T5 smoke (data plane).
#
# Asserts that the data-plane CONNECT-method dispatch is wired
# in a brought-up gateway by exercising the *deny path* — no
# real upstream TCP server needed, just a route that exists
# and isn't `scheme: tcp`.
#
# Why deny-path-only:
# - Dev config (`config/dev.yaml`) ships with one HTTP catch-all
#   route, no `scheme: tcp` pool. A CONNECT to that route MUST
#   return 502 with `x-waf-rule-id: connect_to_non_tcp_route` —
#   that's the documented contract from
#   plans/tcp-forwarder-phase-4.md §3.
# - The admit path needs a real TCP echo upstream + a tcp route
#   in YAML; that combo is integration-tested in-process at
#   `aegis_proxy::data_plane::tcp_connect_tests` and at
#   `aegis_proxy::tcp_tunnel::bridge_tunnel_round_trips_*`.
#   Reproducing it in shell would duplicate the harness for
#   marginal extra signal.
#
# Run after `make run-dev`; the data-plane plaintext listener is
# expected at WAF_DATA (default 127.0.0.1:8080).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

WAF_DATA_HOST="${WAF_DATA_HOST:-127.0.0.1}"
WAF_DATA_PORT="${WAF_DATA_PORT:-8080}"

require curl

# Probe that the listener is actually up before we send malformed
# requests at it. A non-2xx GET is fine — we just need a TCP
# round-trip.
if ! curl -sk -o /dev/null -m 3 "http://$WAF_DATA_HOST:$WAF_DATA_PORT/" 2>/dev/null; then
  if ! curl -sk -o /dev/null -m 3 \
      -w "%{http_code}" "http://$WAF_DATA_HOST:$WAF_DATA_PORT/" \
      | grep -qE '^[0-9]{3}$'; then
    echo "SKIP: data-plane listener at $WAF_DATA_HOST:$WAF_DATA_PORT not reachable"
    echo "      (run 'make run-dev' first)"
    exit 0
  fi
fi

# Build the CONNECT request manually. curl's proxy mode would
# also work but adds noise (it negotiates the tunnel itself);
# raw bytes give a deterministic response we can grep.
issue_connect() {
  local target="$1"
  # Use bash's /dev/tcp for the round trip — avoids netcat
  # variant differences (BSD nc lacks -q on macOS, GNU nc has
  # different flags). Bash on macOS + Linux both ship /dev/tcp.
  exec 3<>"/dev/tcp/$WAF_DATA_HOST/$WAF_DATA_PORT"
  printf 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' "$target" "$target" >&3
  local response=""
  # Read up to 4 KB or until the connection closes; the WAF's
  # 502 response is a few hundred bytes, so 4 KB is a generous
  # ceiling.
  response=$(dd bs=1 count=4096 <&3 2>/dev/null || true)
  exec 3<&-
  echo "$response"
}

assert_status() {
  local response="$1"
  local want="$2"
  local what="$3"
  if echo "$response" | head -1 | grep -q "HTTP/1.1 $want "; then
    ok "$what -> $want"
  else
    echo "FAIL: $what — expected status $want, got:"
    echo "$response" | head -3
    exit 1
  fi
}

assert_rule_id() {
  local response="$1"
  local want="$2"
  local what="$3"
  if echo "$response" | grep -qi "^x-waf-rule-id:[[:space:]]*$want"; then
    ok "$what -> rule_id=$want"
  else
    echo "FAIL: $what — expected rule_id=$want, response headers:"
    echo "$response" | grep -i "^x-waf-" || echo "(no x-waf-* headers)"
    exit 1
  fi
}

# 1. CONNECT to a public-looking dest on the dev catch-all route.
#    The route exists (catch-all `/`) but its pool is HTTP (not
#    `scheme: tcp`), so the dispatcher returns 502 with
#    `connect_to_non_tcp_route`.
echo "→ CONNECT to dev catch-all (HTTP route, NOT tcp scheme)"
resp=$(issue_connect "203.0.113.5:443")
assert_status "$resp" 502 "CONNECT to non-tcp route"
assert_rule_id "$resp" "connect_to_non_tcp_route" "dispatch matrix"

# 2. CONNECT with a malformed authority (path-form) — must
#    NOT crash the listener; should return some 4xx.
echo "→ CONNECT with malformed authority"
resp=$(issue_connect "/")
status=$(echo "$resp" | head -1 | awk '{print $2}')
case "$status" in
  4??) ok "malformed authority -> $status (4xx)" ;;
  *)
    echo "FAIL: malformed authority — expected 4xx, got $status"
    echo "$resp" | head -3
    exit 1
    ;;
esac

echo "PASS: tests/api/connect-tunnel.sh"
