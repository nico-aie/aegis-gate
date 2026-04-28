#!/usr/bin/env bash
# tests/api/cold-tier.sh — P8 smoke
#
# Asserts:
# 1. GET /api/cold-tier returns the documented shape.
# 2. Splunk HEC tokens are NEVER echoed in the response body
#    (defence-in-depth — even though the renderer only stores
#    the endpoint, scan the whole body to catch regressions).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

aegis_login

body=$(aegis_get /api/cold-tier)
echo "$body" | jq -e '.sinks, .fallback_buffer_bytes' >/dev/null \
  || { echo "FAIL: missing sinks/fallback_buffer_bytes" >&2; exit 1; }
ok "GET /api/cold-tier shape"

# Defence in depth: response body must not contain "secret:"
# substring (the splunk token_ref shape) nor any obvious
# token-like pattern.
if echo "$body" | grep -E 'secret:|token_ref|token=' >/dev/null; then
  echo "FAIL: cold-tier response leaked secret-like substring" >&2
  exit 1
fi
ok "no secret substrings in response"

# Each sink row has the documented keys.
echo "$body" | jq -e '
  (.sinks | length) >= 0 and
  ((.sinks // []) | all(has("id") and has("kind") and has("destination") and has("delivery")))
' >/dev/null || { echo "FAIL: sink row schema" >&2; exit 1; }
ok "every sink has id/kind/destination/delivery"
