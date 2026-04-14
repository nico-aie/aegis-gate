#!/usr/bin/env bash
# Run OWASP ZAP baseline scan against a live WAF instance.
#
# Usage:
#   ./tests/security/run-zap.sh [target-url]
#
# Default target: http://localhost:8080

set -euo pipefail

TARGET="${1:-http://localhost:8080}"
OUT_DIR="${OUT_DIR:-./.zap-out}"
mkdir -p "$OUT_DIR"

docker run --rm \
  -v "$PWD/$OUT_DIR:/zap/wrk:rw" \
  --add-host=host.docker.internal:host-gateway \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t "$TARGET" \
  -r "zap-baseline-$(date +%Y%m%d-%H%M%S).html" \
  -I
