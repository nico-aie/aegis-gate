#!/usr/bin/env bash
# B6-T1 — multi-arch build helper for the production image.
#
# Builds `aegis-gate:<version>` (and `:latest`) for both amd64
# and arm64. Loads the result into the local Docker daemon when
# the host arch matches; otherwise just leaves the multi-arch
# manifest in the buildx cache for `docker buildx build --push`.
#
# Usage:
#   bash deploy/docker-build.sh                    # default: tag from cargo + buildx multi-arch
#   AEGIS_TAG=1.4.2 bash deploy/docker-build.sh    # explicit tag
#   AEGIS_PUSH=1 bash deploy/docker-build.sh       # also push to the configured registry
#   AEGIS_PLATFORMS=linux/amd64 \
#       bash deploy/docker-build.sh                # single-arch build (faster on local Mac)
#
# Image-size budget: 100 MiB compressed (asserted via
# `tests/api/dockerfile.sh`).

set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

require() {
  command -v "$1" >/dev/null \
    || { echo "FAIL: missing tool: $1" >&2; exit 1; }
}
require docker

AEGIS_TAG="${AEGIS_TAG:-$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')}"
AEGIS_PLATFORMS="${AEGIS_PLATFORMS:-linux/amd64,linux/arm64}"
AEGIS_PUSH="${AEGIS_PUSH:-0}"
AEGIS_REGISTRY="${AEGIS_REGISTRY:-}"

# When pushing, prefix the registry. When loading locally,
# use the bare tag.
if [[ -n "$AEGIS_REGISTRY" ]]; then
  IMAGE="${AEGIS_REGISTRY%/}/aegis-gate:${AEGIS_TAG}"
  IMAGE_LATEST="${AEGIS_REGISTRY%/}/aegis-gate:latest"
else
  IMAGE="aegis-gate:${AEGIS_TAG}"
  IMAGE_LATEST="aegis-gate:latest"
fi

echo "Building $IMAGE for platforms: $AEGIS_PLATFORMS"

# Multi-arch builds need a buildx builder. Create one if absent.
if ! docker buildx inspect aegis-builder >/dev/null 2>&1; then
  docker buildx create --name aegis-builder --use >/dev/null
fi
docker buildx use aegis-builder

# Single-arch builds can `--load` straight into the local daemon;
# multi-arch needs `--push` (or `--output type=oci,...`).
LOAD_OR_PUSH=()
if [[ "$AEGIS_PUSH" == "1" ]]; then
  LOAD_OR_PUSH+=("--push")
elif [[ "$AEGIS_PLATFORMS" != *","* ]]; then
  LOAD_OR_PUSH+=("--load")
else
  echo "INFO: multi-arch build without push — image stays in buildx cache"
fi

docker buildx build \
  --platform "$AEGIS_PLATFORMS" \
  --tag "$IMAGE" \
  --tag "$IMAGE_LATEST" \
  --build-arg "BUILD_SHA=$(git rev-parse HEAD 2>/dev/null || echo unknown)" \
  --file deploy/Dockerfile \
  "${LOAD_OR_PUSH[@]}" \
  .

if [[ "$AEGIS_PUSH" != "1" && "$AEGIS_PLATFORMS" != *","* ]]; then
  echo
  echo "Built $IMAGE (loaded into local Docker daemon)"
  size_bytes=$(docker image inspect "$IMAGE" --format '{{.Size}}')
  size_mb=$(( size_bytes / 1024 / 1024 ))
  echo "Image size: ${size_mb} MiB"
  if (( size_mb > 100 )); then
    echo "WARN: image exceeds the 100 MiB budget" >&2
  fi
fi
