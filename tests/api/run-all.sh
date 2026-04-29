#!/usr/bin/env bash
# tests/api/run-all.sh — drive every smoke test in sequence.
#
# Exits non-zero on the first failure. Useful as a CI gate after
# `cargo test --workspace` passes — this layer covers the live
# endpoint shapes that the per-crate tests can't reach.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

trap 'echo "tests/api/run-all.sh aborted"; exit 1' ERR

echo "==> tests/api/auth.sh"
"$HERE/auth.sh"
echo
echo "==> tests/api/tls.sh"
"$HERE/tls.sh"
echo
echo "==> tests/api/tls-ciphers.sh"
"$HERE/tls-ciphers.sh"
echo
echo "==> tests/api/tls-data.sh"
"$HERE/tls-data.sh"
echo
echo "==> tests/api/detectors.sh"
"$HERE/detectors.sh"
echo
echo "==> tests/api/risk.sh"
"$HERE/risk.sh"
echo
echo "==> tests/api/loadmode.sh"
"$HERE/loadmode.sh"
echo
echo "==> tests/api/logging.sh"
"$HERE/logging.sh"
echo
echo "==> tests/api/cold-tier.sh"
"$HERE/cold-tier.sh"
echo
echo "all admin-API smoke tests passed"
