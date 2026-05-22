#!/usr/bin/env bash
# DR-T6 — enforce vs log_only ENFORCEMENT behaviour (contract §2.7 / §"Enforcement semantics").
#
# DR-T3 only proves the `X-WAF-Mode` header flips on a benign request.
# DR-T6 proves the actual contract semantics with real attacks:
#
#   enforce  → the intended action is APPLIED   (block → 403, rate_limit → 429)
#              and X-WAF-Mode reads `enforce`.
#   log_only → the intended action is REPORTED  (X-WAF-Action + X-WAF-Rule-Id
#              + X-WAF-Mode: log_only) but NOT applied — the request is
#              forwarded upstream, so the status is the upstream's, never the
#              WAF's enforce code.
#
# Coverage: the `block` (detector gate) and `rate_limit` (per-IP gate) actions.
# Both ride the SAME `log_only_intent` → `final_tag` → stamper funnel as the
# `challenge` action, so this also guards the 2026-05-22 challenge log_only fix.
# (`challenge` itself needs per-tier `challenges_enabled`, which is admin-set
# only — not reachable from a self-contained, control-plane-only test.)

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl

# dev.yaml's per-IP rate-limit budget is 1,000,000 — far too high to trip in a
# short burst. Boot against a copy with a tiny limit so a 6-request burst
# crosses the gate. Everything else (detectors, routes, upstream, interop)
# stays identical to dev.
RL_CFG="$(mktemp -t waf-dt6.XXXXXX).yaml"
sed 's/limit: 1000000/limit: 4/' "$REPO/config/dev.yaml" > "$RL_CFG"
CONFIG="$RL_CFG"

cleanup6() {
  stop_waf
  pkill -9 -f 'target/release/waf' 2>/dev/null || true
  rm -f "$RL_CFG"
}
trap cleanup6 EXIT

start_waf

post_ctrl() {
  local path="$1" body="${2:-}"
  if [[ -n "$body" ]]; then
    curl -s --max-time 3 -X POST \
         -H "X-Benchmark-Secret: $SECRET" \
         -H "content-type: application/json" \
         -d "$body" "$ADMIN$path" >/dev/null
  else
    curl -s --max-time 3 -X POST \
         -H "X-Benchmark-Secret: $SECRET" "$ADMIN$path" >/dev/null
  fi
}

set_mode()     { post_ctrl /__waf_control/set_profile "{\"scope\":\"all\",\"mode\":\"$1\"}"; }
reset_state()  { post_ctrl /__waf_control/reset_state; }

# probe URL [curl-args...] — one request; sets P_STATUS / P_ACTION / P_MODE / P_RULE
# from the status line + the X-WAF-* response headers.
probe() {
  local url="$1"; shift
  local out
  out=$(curl -s -D - -o /dev/null -w 'HTTP_STATUS:%{http_code}' --max-time 5 "$url" "$@")
  P_STATUS=$(printf '%s' "$out" | sed -n 's/.*HTTP_STATUS:\([0-9]\{3\}\).*/\1/p' | tail -1)
  _hv() {
    printf '%s' "$out" | awk -v h="$1" '
      BEGIN { IGNORECASE = 1 }
      tolower($1) == tolower(h ":") { sub(/^[^ ]+ /, ""); sub(/\r$/, ""); print; exit }'
  }
  P_ACTION=$(_hv x-waf-action)
  P_MODE=$(_hv x-waf-mode)
  P_RULE=$(_hv x-waf-rule-id)
}

# A clear SQL-injection in the query string — the sqli detector scores it at
# the Low-tier block threshold, so it blocks in enforce mode.
SQLI="$DATA/?id=1%27%3BDROP%20TABLE%20users--%20OR%201=1"

# ───────────────────────────── block: enforce ─────────────────────────────
reset_state
set_mode enforce
probe "$SQLI"
[[ "$P_STATUS" == "403" ]]    || fail "block/enforce: expected 403, got $P_STATUS"
[[ "$P_ACTION" == "block" ]]  || fail "block/enforce: X-WAF-Action=$P_ACTION (expected block)"
[[ "$P_MODE" == "enforce" ]]  || fail "block/enforce: X-WAF-Mode=$P_MODE (expected enforce)"
[[ -n "$P_RULE" && "$P_RULE" != "none" ]] || fail "block/enforce: X-WAF-Rule-Id empty/none"
ok "block/enforce: 403 + action=block + mode=enforce + rule=$P_RULE"

# ───────────────────────────── block: log_only ────────────────────────────
set_mode log_only
probe "$SQLI"
[[ "$P_STATUS" != "403" ]]     || fail "block/log_only: still enforced (403) — must forward upstream"
[[ "$P_ACTION" == "block" ]]   || fail "block/log_only: X-WAF-Action=$P_ACTION (expected the intended 'block')"
[[ "$P_MODE" == "log_only" ]]  || fail "block/log_only: X-WAF-Mode=$P_MODE (expected log_only)"
[[ -n "$P_RULE" && "$P_RULE" != "none" ]] || fail "block/log_only: X-WAF-Rule-Id empty/none (evidence must match enforce)"
ok "block/log_only: status=$P_STATUS (forwarded) + action=block + mode=log_only + rule=$P_RULE"

# ─────────────────────────── rate_limit: enforce ──────────────────────────
reset_state
set_mode enforce
for n in 1 2 3 4 5 6; do probe "$DATA/rl-probe?n=$n"; done   # limit=4 → later requests trip
[[ "$P_STATUS" == "429" ]]        || fail "rate_limit/enforce: expected 429 after burst, got $P_STATUS"
[[ "$P_ACTION" == "rate_limit" ]] || fail "rate_limit/enforce: X-WAF-Action=$P_ACTION (expected rate_limit)"
[[ "$P_MODE" == "enforce" ]]      || fail "rate_limit/enforce: X-WAF-Mode=$P_MODE (expected enforce)"
ok "rate_limit/enforce: 429 + action=rate_limit + mode=enforce"

# ────────────────────────── rate_limit: log_only ──────────────────────────
reset_state           # contract §2.4 — clear the per-IP counter for a clean burst
set_mode log_only
for n in 1 2 3 4 5 6; do probe "$DATA/rl-probe?n=$n"; done
[[ "$P_STATUS" != "429" ]]        || fail "rate_limit/log_only: still enforced (429) — must forward upstream"
[[ "$P_ACTION" == "rate_limit" ]] || fail "rate_limit/log_only: X-WAF-Action=$P_ACTION (expected intended rate_limit)"
[[ "$P_MODE" == "log_only" ]]     || fail "rate_limit/log_only: X-WAF-Mode=$P_MODE (expected log_only)"
ok "rate_limit/log_only: status=$P_STATUS (forwarded) + action=rate_limit + mode=log_only"

# Restore enforce so the gateway is left in a secure-by-default state.
set_mode enforce

ok "DR-T6 mode enforcement: 4/4 cells green (block + rate_limit × enforce/log_only)"
