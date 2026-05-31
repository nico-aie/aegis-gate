#!/usr/bin/env bash
# NT-09 — GET /api/ai/confidence surfaces both `confidence_threshold`
# (LIVE) and `default` (cfg-loaded). The dashboard pre-fills the input
# with the live value AND labels the default — both must be in the
# payload so QC can render "current vs. config" without re-parsing
# YAML.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl; require jq; require docker

trap stop_cluster EXIT
start_cluster
login "$NODE_A_ADMIN"

# Read the cfg default straight from the YAML so we know what to
# expect. If the file doesn't set it explicitly, fall back to 0.85
# (the value of `default_ai_confidence_threshold()` in
# crates/aegis-core/src/config.rs).
yaml_default="$(grep -E '^\s*confidence_threshold:' "$CONFIG_A" \
                | head -1 | awk '{print $2}')"
yaml_default="${yaml_default:-0.85}"

# Baseline GET — before any operator change.
baseline="$(admin_get "$NODE_A_ADMIN" "/api/ai/confidence")"
echo "baseline: $baseline"

# Shape checks.
assert_json_present "$baseline" '.confidence_threshold'
assert_json_present "$baseline" '.default'
assert_json_present "$baseline" '.feature_present'

# Default must equal what's in cluster-a.yaml (or 0.85 fallback).
# 2026-05-30 (QC R2-005): use floats_eq — YAML `0.85` round-trips
# through f32 → JSON as 0.8500000238418579 (next f64 representable
# above the f32 cast). Strict awk equality would fail every time.
got_default="$(printf '%s' "$baseline" | jq -r '.default')"
floats_eq "$got_default" "$yaml_default" \
  || fail ".default ($got_default) ≠ cluster-a.yaml ($yaml_default)"
ok "default surfaces from cfg: $got_default"

# At boot, with no operator change yet, confidence_threshold == default.
got_live="$(printf '%s' "$baseline" | jq -r '.confidence_threshold')"
floats_eq "$got_live" "$got_default" \
  || fail ".confidence_threshold ($got_live) at boot should equal .default ($got_default)"
ok "live == default at boot ($got_live)"

# Mutate live; default must STAY the same; live must change.
target="0.42"
admin_put "$NODE_A_ADMIN" "/api/ai/confidence" \
  "{\"confidence_threshold\": $target}" >/dev/null
# Wait for the local atomic + GET surface to reflect the PUT — the
# AI confidence handler updates the atomic synchronously on the
# originator (see handle_ai_confidence_put), but the watcher tick
# can re-set on subsequent polls. 1 s is comfortable for the local
# read.
sleep 1
post="$(admin_get "$NODE_A_ADMIN" "/api/ai/confidence")"
echo "post-mutation: $post"
post_default="$(printf '%s' "$post" | jq -r '.default')"
post_live="$(printf '%s' "$post" | jq -r '.confidence_threshold')"
floats_eq "$post_default" "$yaml_default" \
  || fail ".default changed after PUT: was $yaml_default, now $post_default"
floats_eq "$post_live" "$target" \
  || fail ".confidence_threshold did not reflect PUT: got $post_live, want $target"
ok ".default stable ($post_default), .confidence_threshold updated ($post_live)"

echo "NT-09 PASS"
