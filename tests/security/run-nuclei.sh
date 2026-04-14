#!/usr/bin/env bash
# Run nuclei against a live WAF instance.
#
# Usage:
#   ./tests/security/run-nuclei.sh [target-url]
#
# Default target: http://host.docker.internal:8080

set -euo pipefail

TARGET="${1:-http://host.docker.internal:8080}"
OUT_DIR="${OUT_DIR:-./.nuclei-out}"
mkdir -p "$OUT_DIR"

nuclei \
  -u "$TARGET" \
  -severity critical,high,medium \
  -exclude-tags intrusive,dos \
  -rate-limit 100 \
  -stats \
  -o "$OUT_DIR/nuclei-$(date +%Y%m%d-%H%M%S).txt"
