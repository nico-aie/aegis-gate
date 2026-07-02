#!/usr/bin/env bash
# Native (host) nginx LB control — no root, no Docker. See nginx-stream-native.conf
# for WHY (rootless Docker SNATs the client IP; native nginx sees the real source).
#
#   ./native-lb.sh start|stop|reload|test|status
set -euo pipefail
PFX="$(cd "$(dirname "${BASH_SOURCE[0]}")/native" && pwd)"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="$DIR/nginx-stream-native.conf"
POLLER="$DIR/drain-poller.sh"
NGINX=(conda run -n nginx-lb nginx -p "$PFX" -c "$CONF")

# Seed the drain-poller-generated upstream include so nginx -t / start never sees
# it missing (the file lives under the gitignored native/ runtime prefix).
seed() { [ -f "$PFX/conf.d/waf_upstream.conf" ] || "$POLLER" --once >/dev/null; }

case "${1:-status}" in
  test)   seed; "${NGINX[@]}" -t ;;
  start)  seed; "${NGINX[@]}" -t && "${NGINX[@]}" && echo "native nginx LB started (pid $(cat "$PFX/run/nginx.pid" 2>/dev/null||echo ?)) — also start the poller: aegis-drain-poller.service (or $POLLER)" ;;
  reload) "${NGINX[@]}" -t && "${NGINX[@]}" -s reload && echo "reloaded" ;;
  stop)   "${NGINX[@]}" -s quit && echo "stopped" ;;
  status) ss -ltn 2>/dev/null | grep -E ':(56208|56243|56244|56245)\b' || echo "(no LB ports listening)" ;;
  *) echo "usage: $0 start|stop|reload|test|status"; exit 1 ;;
esac
